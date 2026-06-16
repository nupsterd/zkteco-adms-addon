"""
ZKTeco ADMS Server for Home Assistant
Raw TCP server with TLS support for ZKTeco devices.
"""

import asyncio
import logging
import json
import os
import ssl
import subprocess
from datetime import datetime
from urllib.parse import parse_qs

from audit import AuditLogger
from audit_schema import build_access_record, build_device_state_record
from forwarder import BackendForwarder

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

# Read config from HA add-on options
def load_options():
    options_file = "/data/options.json"
    if os.path.exists(options_file):
        with open(options_file) as f:
            return json.load(f)
    return {}

_options = load_options()
HA_TOKEN = _options.get("ha_token", os.environ.get("HA_TOKEN", ""))
ADMS_PORT = int(_options.get("adms_port", os.environ.get("ADMS_PORT", "8083")))
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")

# Fan-out OPT-IN al backend pv-backend (v1.7.0). Vacio = desactivado.
PV_BACKEND_URL = _options.get("pv_backend_url", "")
PV_BACKEND_TOKEN = _options.get("pv_backend_verify_token", "")
PV_BACKEND_QUEUE_MAXSIZE = int(_options.get("pv_backend_queue_maxsize", 1000))
PV_BACKEND_TIMEOUT = float(_options.get("pv_backend_timeout_seconds", 3))
# `or` (no solo el default de .get): el campo es opcional (str?), asi que puede
# venir ausente, null o "" desde la UI -> caemos siempre al default (§5.9.36).
AUDIT_LOG_PATH = _options.get("audit_log_path") or "/config/audit.log"

# Inicializados en main() antes de servir.
_audit = None
_forwarder = None

# Contador in-memory de lineas no-ATTLOG filtradas (§5.9.40). Solo observabilidad.
_skipped_attlog_count = 0

# Use Supervisor API if token available, otherwise direct HA connection
if SUPERVISOR_TOKEN:
    HA_URL = "http://supervisor/core"
else:
    HA_URL = "https://homeassistant:8123"

VERIFY_METHODS = {
    "0": "fingerprint",
    "1": "fingerprint",
    "2": "face",
    "3": "card",
    "4": "password",
    "15": "face",
}

connected_devices = {}

CERT_FILE = "/app/cert.pem"
KEY_FILE = "/app/key.pem"


def generate_self_signed_cert():
    """Generate a self-signed certificate for TLS."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        logger.info("SSL certificates already exist")
        return
    
    logger.info("Generating self-signed SSL certificate...")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", KEY_FILE, "-out", CERT_FILE,
        "-days", "3650", "-nodes",
        "-subj", "/CN=zkteco-adms-server"
    ], check=True, capture_output=True)
    logger.info("SSL certificate generated successfully")


async def fire_ha_event(event_type: str, event_data: dict):
    """Fire an event in Home Assistant."""
    # Use SUPERVISOR_TOKEN (auto-provided) or user token
    token = SUPERVISOR_TOKEN or HA_TOKEN
    if not token:
        logger.warning("No HA_TOKEN configured, skipping event")
        return

    try:
        import aiohttp
        url = f"{HA_URL}/api/events/{event_type}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=event_data, headers=headers, ssl=False) as resp:
                if resp.status == 200:
                    logger.info(f"HA event fired: {event_type} -> {event_data}")
                else:
                    text = await resp.text()
                    logger.error(f"Failed to fire event: {resp.status} {text}")
    except Exception as e:
        logger.error(f"Error firing HA event: {e}")


async def update_ha_sensor(entity_id: str, state: str, attributes: dict = None):
    """Update a sensor state in Home Assistant."""
    token = SUPERVISOR_TOKEN or HA_TOKEN
    if not token:
        return

    try:
        import aiohttp
        url = f"{HA_URL}/api/states/{entity_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        payload = {"state": state, "attributes": attributes or {}}
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, ssl=False) as resp:
                if resp.status not in (200, 201):
                    text = await resp.text()
                    logger.error(f"Failed to update sensor {entity_id}: {resp.status} {text}")
    except Exception as e:
        logger.error(f"Error updating HA sensor: {e}")


def parse_http_request(raw_data: bytes):
    """Parse raw HTTP request bytes."""
    try:
        text = raw_data.decode('utf-8', errors='replace')
    except:
        text = str(raw_data)
    
    lines = text.split('\r\n')
    if not lines:
        return None, None, None, None, ""
    
    request_line = lines[0]
    parts = request_line.split(' ')
    method = parts[0] if len(parts) >= 1 else "UNKNOWN"
    path = parts[1] if len(parts) >= 2 else "/"
    
    headers = {}
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        if line == '':
            body_start = i + 1
            break
        if ':' in line:
            key, val = line.split(':', 1)
            headers[key.strip()] = val.strip()
    
    body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ""
    
    query = {}
    if '?' in path:
        path_part, qs = path.split('?', 1)
        query = parse_qs(qs)
        query = {k: v[0] if len(v) == 1 else v for k, v in query.items()}
        path = path_part
    
    return method, path, headers, query, body.strip()


def build_response(status: str, body: str, content_type: str = "text/plain") -> str:
    """Build HTTP response."""
    return (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{body}"
    )


def build_cdata_response(sn: str) -> str:
    """Build ADMS registration response."""
    body = (
        f"GET OPTION FROM:{sn}\r\n"
        f"ATTLOGStamp=None\r\n"
        f"OPERLOGStamp=9999\r\n"
        f"ATTPHOTOStamp=None\r\n"
        f"ErrorDelay=30\r\n"
        f"Delay=10\r\n"
        f"TransTimes=00:00;14:05\r\n"
        f"TransInterval=1\r\n"
        f"TransFlag=TransData AttLog OpLog AttPhoto EnrollUser ChgUser EnrollFP ChgFP UserPic\r\n"
        f"TimeZone=-5\r\n"
        f"Realtime=1\r\n"
        f"Encrypt=None\r\n"
    )
    return build_response("200 OK", body)


def _is_valid_attlog_line(line: str) -> bool:
    """True si la linea es un ATTLOG real (evento de verificacion). Pura, sin side effects.

    El ADMS manda por /iclock/cdata con body cosas que NO son ATTLOG (OPLOG,
    dumps de la tabla USER, etc). Sin este filtro entran al audit/fan-out como
    basura (§5.9.40). Criterios (evidencia E2E v1.7.0):

    1. >= 4 campos tab-separated.
    2. parts[0] numerico (user_id).
    3. parts[1] datetime 'YYYY-MM-DD HH:MM:SS'.
    4. parts[2] numerico (status).
    5. parts[3] numerico (verify_method code).
    """
    parts = line.strip().split("\t")
    if len(parts) < 4:
        return False
    if not parts[0].isdigit():
        return False
    try:
        datetime.strptime(parts[1], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    if not parts[2].isdigit():
        return False
    return parts[3].isdigit()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handle each incoming TCP/TLS connection."""
    global _skipped_attlog_count
    addr = writer.get_extra_info('peername')
    
    try:
        raw_data = await asyncio.wait_for(reader.read(8192), timeout=15.0)
        
        if not raw_data:
            writer.close()
            return
        
        method, path, headers, query, body = parse_http_request(raw_data)
        logger.info(f"REQUEST {addr[0]}: {method} {path} query={query} body_len={len(body)}")
        
        response = build_response("200 OK", "OK")
        
        if path == "/status":
            status_data = json.dumps({
                "status": "running",
                "connected_devices": connected_devices,
                "timestamp": datetime.now().isoformat(),
            })
            response = build_response("200 OK", status_data, "application/json")
        
        elif "/iclock/cdata" in (path or ""):
            sn = query.get("SN", "unknown")
            
            if body and len(body) > 0:
                logger.info(f"ATTENDANCE DATA from {sn}: {body[:500]}")
                lines = body.split("\n")
                for line in lines:
                    # §5.9.40: solo ATTLOG reales pasan. OPLOG, dumps de USER, etc
                    # se saltean (no HA, no audit, no fan-out). Fail-silent.
                    if not _is_valid_attlog_line(line):
                        if line.strip():
                            _skipped_attlog_count += 1
                            logger.debug(f"SKIPPED non-ATTLOG line: {line.strip()[:120]}")
                            if _skipped_attlog_count % 50 == 1:
                                logger.warning(
                                    f"Filtered {_skipped_attlog_count} non-ATTLOG lines (cumulative)"
                                )
                        continue
                    parts = line.strip().split("\t")
                    if len(parts) >= 4:
                        event_data = {
                            "serial_number": sn,
                            "user_id": parts[0],
                            "timestamp": parts[1],
                            "status": parts[2],
                            "verify_method": VERIFY_METHODS.get(parts[3], "unknown"),
                        }
                        logger.info(f"ATTENDANCE EVENT: {event_data}")
                        await fire_ha_event("zkteco_attendance", event_data)
                        await update_ha_sensor(
                            f"sensor.zkteco_{sn.lower().replace('-','_')}_last_user",
                            parts[0],
                            {
                                "friendly_name": f"ZKTeco {sn} - Ultimo Usuario",
                                "timestamp": parts[1],
                                "verify_method": VERIFY_METHODS.get(parts[3], "unknown"),
                                "status": parts[2],
                            }
                        )
                        # Audit local + fan-out al backend (v1.7.0). Fail-silent
                        # total: nunca rompe el reenvio a HA ni la respuesta ADMS.
                        record = build_access_record(
                            sn=sn,
                            user_id=parts[0],
                            device_ts=parts[1],
                            status=parts[2],
                            verify_method=VERIFY_METHODS.get(parts[3], "unknown"),
                            raw_line=line.strip(),
                        )
                        if _audit is not None:
                            try:
                                await _audit.write(record)
                            except Exception:
                                logger.exception("audit.write failed (continuing)")
                        if _forwarder is not None:
                            try:
                                await _forwarder.enqueue(record)
                            except Exception:
                                logger.exception("forwarder.enqueue failed (continuing)")
                response = build_response("200 OK", "OK")
            else:
                logger.info(f"DEVICE REGISTERED: SN={sn}")
                connected_devices[sn] = datetime.now().isoformat()
                await update_ha_sensor(
                    f"sensor.zkteco_{sn.lower().replace('-','_')}_status",
                    "online",
                    {
                        "friendly_name": f"ZKTeco {sn}",
                        "serial_number": sn,
                        "last_seen": connected_devices[sn],
                    }
                )
                await fire_ha_event("zkteco_device_connected", {
                    "serial_number": sn,
                    "timestamp": connected_devices[sn],
                })
                # Audit local + fan-out al backend (v1.7.0). Fail-silent total.
                record = build_device_state_record(sn=sn, state="online")
                if _audit is not None:
                    try:
                        await _audit.write(record)
                    except Exception:
                        logger.exception("audit.write failed (continuing)")
                if _forwarder is not None:
                    try:
                        await _forwarder.enqueue(record)
                    except Exception:
                        logger.exception("forwarder.enqueue failed (continuing)")
                response = build_cdata_response(sn)
        
        elif "/iclock/getrequest" in (path or ""):
            sn = query.get("SN", "unknown")
            logger.debug(f"Command poll from: {sn}")
            response = build_response("200 OK", "OK")
        
        elif "/iclock/devicecmd" in (path or ""):
            sn = query.get("SN", "unknown")
            logger.info(f"Command result from {sn}: {body[:200]}")
            response = build_response("200 OK", "OK")
        
        else:
            logger.info(f"UNHANDLED: {method} {path} body={body[:200]}")
            response = build_response("200 OK", "OK")
        
        writer.write(response.encode('utf-8'))
        await writer.drain()
    
    except asyncio.TimeoutError:
        logger.debug(f"Timeout from {addr[0]}")
    except Exception as e:
        logger.error(f"Error from {addr[0]}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass


async def main():
    global _audit, _forwarder

    # Generate self-signed cert for TLS
    generate_self_signed_cert()

    # Audit local + fan-out OPT-IN al backend (v1.7.0). El audit se escribe
    # SIEMPRE (paridad Hikvision, ADR-004 Opcion C); el forwarder solo si hay
    # url + token configurados.
    _audit = AuditLogger(AUDIT_LOG_PATH)
    _forwarder = BackendForwarder(
        url=PV_BACKEND_URL,
        token=PV_BACKEND_TOKEN,
        queue_maxsize=PV_BACKEND_QUEUE_MAXSIZE,
        timeout_seconds=PV_BACKEND_TIMEOUT,
    )
    await _forwarder.start()

    # Create SSL context
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    
    # Start TLS server
    server = await asyncio.start_server(handle_client, '0.0.0.0', ADMS_PORT, ssl=ssl_ctx)
    logger.info(f"ZKTeco ADMS Server (TLS) running on port {ADMS_PORT}")
    logger.info(f"Home Assistant URL: {HA_URL}")
    logger.info(f"SUPERVISOR_TOKEN: {'configured' if SUPERVISOR_TOKEN else 'not found'}")
    logger.info(f"HA_TOKEN: {'configured' if HA_TOKEN else 'not found'}")
    
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
