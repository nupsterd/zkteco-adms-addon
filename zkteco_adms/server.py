"""
ZKTeco ADMS Server for Home Assistant
Raw TCP server with TLS support for ZKTeco devices.
"""

import asyncio
import logging
import json
import os
import re
import secrets
import ssl
import subprocess
from datetime import datetime
from urllib.parse import parse_qs

from audit import AuditLogger
from audit_schema import build_access_record, build_device_state_record
from command_queue import (
    CommandQueue,
    COMMAND_CLEANUP_INTERVAL_SECONDS,
)
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

# Endpoint local de control (PR A.1, ADR-076). Deshabilitado por defecto: el
# endpoint solo encola comandos ADMS hacia el device (drain en PR A.2). Sin
# token configurado + habilitado => el endpoint responde 503 (config insegura)
# pero el resto del flow ADMS sigue funcionando (no crashea el add-on).
CONTROL_ENDPOINT_ENABLED = bool(_options.get("control_endpoint_enabled", False))
CONTROL_ENDPOINT_TOKEN = _options.get("control_endpoint_token") or ""

# Regex de validacion del payload del comando ZK: alfanumerico + separadores
# comunes (`= , _ - : .` y espacio). Sin newlines ni caracteres de control para
# que el payload no rompa la respuesta HTTP cruda ni el protocolo ADMS.
_CONTROL_PAYLOAD_RE = re.compile(r"^[A-Za-z0-9 =,_\-:.]+$")

# Redaccion del campo Passwd= en texto logueado (§5.9.260). `+` (no `*`): un
# Passwd vacio (`Passwd=` seguido de tab) NO se toca porque no hay secreto que
# filtrar (decision de diseno del prompt PR A.1).
_PASSWD_RE = re.compile(r"Passwd=[^\t\s]+")

# Regex para extraer cmd_id del ACK del device en POST /iclock/devicecmd (PR A.3).
# El protocolo ZK ADMS estandar usa `ID=<cmd_id>` en el body (query-string style).
# Si el firmware del MB10-VL difiere, ajustar aca tras validacion empirica.
_DEVICECMD_ACK_RE = re.compile(r"ID=(\d+)")

# Inicializados en main() antes de servir.
_audit = None
_forwarder = None
_command_queue = None


def redact_passwd(text: str) -> str:
    """Reemplaza el valor del campo `Passwd=<valor>` por `Passwd=<REDACTED>`.

    El MB10-VL pushea un snapshot `USER PIN=... Passwd=<plain> ...` antes del
    OPLOG de USER ADD/MODIFY (§5.9.260). El flow ADR-068 v2 NO usa passwords,
    pero si el operador asigna uno localmente en el menu del device, queda en
    texto plano en los logs del add-on. Esta funcion lo redacta ANTES de loguear.

    Pura y fail-safe: un Passwd vacio se deja igual; texto sin Passwd no cambia.
    """
    if not text:
        return text
    return _PASSWD_RE.sub("Passwd=<REDACTED>", text)


def _header_get(headers: dict, name: str) -> str:
    """Lookup case-insensitive de un header (los HTTP headers no son case-sensitive)."""
    if not headers:
        return ""
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return ""


async def _handle_control_enqueue(method: str, headers: dict, body: str) -> str:
    """Maneja `POST /control/enqueue`: encola un comando ADMS para un device.

    Retorna la respuesta HTTP cruda ya construida (mismo patron raw-TCP que el
    resto de `handle_client`). PR A.1 SOLO encola; el drain en `getrequest` es
    PR A.2.
    """
    def _json(status: str, payload: dict) -> str:
        return build_response(status, json.dumps(payload), "application/json")

    # 1. Solo POST.
    if method != "POST":
        return _json("405 Method Not Allowed", {"error": "method_not_allowed"})

    # 2. Endpoint deshabilitado => 404 (no revela que existe).
    if not CONTROL_ENDPOINT_ENABLED:
        return _json("404 Not Found", {"error": "not_found"})

    # 3. Habilitado pero sin token configurado => config insegura => 503.
    if not CONTROL_ENDPOINT_TOKEN:
        logger.error(
            "control_endpoint_enabled=true pero control_endpoint_token vacio: "
            "endpoint /control/enqueue inseguro, respondiendo 503"
        )
        return _json("503 Service Unavailable", {"error": "endpoint_misconfigured"})

    # 4. Auth: token compartido en header X-Control-Token (comparacion constante).
    provided = _header_get(headers, "X-Control-Token")
    if not provided or not secrets.compare_digest(provided, CONTROL_ENDPOINT_TOKEN):
        return _json("401 Unauthorized", {"error": "unauthorized"})

    # 5. Body JSON valido.
    try:
        data = json.loads(body) if body else None
    except (ValueError, TypeError):
        return _json("400 Bad Request", {"error": "invalid_json"})
    if not isinstance(data, dict):
        return _json("400 Bad Request", {"error": "invalid_json"})

    # 6. Validacion de sn + payload.
    sn = data.get("sn")
    payload = data.get("payload")
    if not isinstance(sn, str) or not sn.strip():
        return _json("400 Bad Request", {"error": "invalid_sn"})
    if not isinstance(payload, str) or not payload.strip():
        return _json("400 Bad Request", {"error": "invalid_payload"})
    if not _CONTROL_PAYLOAD_RE.match(payload):
        return _json("400 Bad Request", {"error": "payload_has_forbidden_chars"})

    if _command_queue is None:
        logger.error("CommandQueue no inicializado, respondiendo 503")
        return _json("503 Service Unavailable", {"error": "queue_unavailable"})

    cmd = await _command_queue.enqueue(sn, payload)
    logger.info(f"Command enqueued cmd_id={cmd.cmd_id} for sn={sn} payload={payload}")
    return _json(
        "201 Created",
        {"cmd_id": cmd.cmd_id, "sn": cmd.sn, "enqueued_at": cmd.enqueued_at.isoformat()},
    )


async def _handle_control_status(method: str, headers: dict, query: dict) -> str:
    """Maneja `GET /control/status?cmd_id=<id>`: retorna estado de un comando.

    Misma auth que /control/enqueue (X-Control-Token). PR A.3.
    """
    def _json(status: str, payload: dict) -> str:
        return build_response(status, json.dumps(payload), "application/json")

    # 1. Solo GET.
    if method != "GET":
        return _json("405 Method Not Allowed", {"error": "method_not_allowed"})

    # 2. Endpoint deshabilitado => 404 (no revela que existe).
    if not CONTROL_ENDPOINT_ENABLED:
        return _json("404 Not Found", {"error": "not_found"})

    # 3. Habilitado pero sin token configurado => config insegura => 503.
    if not CONTROL_ENDPOINT_TOKEN:
        logger.error(
            "control_endpoint_enabled=true pero control_endpoint_token vacio: "
            "endpoint /control/status inseguro, respondiendo 503"
        )
        return _json("503 Service Unavailable", {"error": "endpoint_misconfigured"})

    # 4. Auth: token compartido en header X-Control-Token (comparacion constante).
    provided = _header_get(headers, "X-Control-Token")
    if not provided or not secrets.compare_digest(provided, CONTROL_ENDPOINT_TOKEN):
        return _json("401 Unauthorized", {"error": "unauthorized"})

    # 5. Query param cmd_id obligatorio + parseable a int.
    cmd_id_raw = query.get("cmd_id")
    if not cmd_id_raw:
        return _json("400 Bad Request", {"error": "missing_cmd_id"})
    try:
        cmd_id = int(cmd_id_raw)
    except (ValueError, TypeError):
        return _json("400 Bad Request", {"error": "invalid_cmd_id"})

    if _command_queue is None:
        logger.error("CommandQueue no inicializado, respondiendo 503")
        return _json("503 Service Unavailable", {"error": "queue_unavailable"})

    cmd = await _command_queue.get_status(cmd_id)
    if cmd is None:
        return _json("404 Not Found", {"error": "cmd_id_not_found"})

    return _json("200 OK", cmd.to_dict())

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
    "3": "password",  # §5.9.41: el MB10-VL emite "3" al teclear password (no card)
    "4": "card",      # §5.9.41: el MB10-VL emite "4" al pasar tarjeta RFID (no password)
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
    """Handle each incoming TCP/TLS connection.

    Lectura HTTP/1.1 compliant:
    1. Lee bytes hasta encontrar el separador headers/body (`\\r\\n\\r\\n`).
    2. Parsea `Content-Length` del header.
    3. Lee EXACTAMENTE Content-Length bytes del body despues de los headers.

    Defensa anti-DOS: maximo 65536 bytes de headers + Content-Length acotado.

    Fix bug §5.9.292: el read(8192) original retornaba el primer recv() del
    buffer TCP. Funcionaba con clientes que envian headers+body en un solo
    write (curl, MB10-VL firmware) pero fallaba con clientes que separan
    headers y body en writes distintos (httpx con json=, requests session
    persistente). Sintoma: 400 invalid_json aleatorio.
    """
    global _skipped_attlog_count
    addr = writer.get_extra_info('peername')

    try:
        # --- BEGIN FIX §5.9.292: Content-Length aware HTTP read ---
        HEADERS_MAX_BYTES = 65536          # cap anti-DOS de headers
        BODY_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB cap anti-DOS de body
        SEPARATOR = b"\r\n\r\n"

        # 1. Leer headers hasta encontrar el separador.
        buf = b""
        sep_idx = -1
        deadline = asyncio.get_event_loop().time() + 15.0
        while sep_idx < 0:
            remaining_time = deadline - asyncio.get_event_loop().time()
            if remaining_time <= 0:
                logger.warning(f"Header read timeout from {addr}")
                writer.close()
                return
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining_time)
            except asyncio.TimeoutError:
                logger.warning(f"Header read timeout from {addr}")
                writer.close()
                return
            if not chunk:
                # Conexion cerrada por el cliente.
                writer.close()
                return
            buf += chunk
            if len(buf) > HEADERS_MAX_BYTES:
                logger.warning(f"Headers too large from {addr} (>{HEADERS_MAX_BYTES} bytes)")
                writer.close()
                return
            sep_idx = buf.find(SEPARATOR)

        header_part = buf[:sep_idx]
        body_early = buf[sep_idx + len(SEPARATOR):]

        # 2. Parsear Content-Length del header (case-insensitive).
        content_length = 0
        try:
            header_lines = header_part.decode("utf-8", errors="replace").split("\r\n")
            for line in header_lines[1:]:  # skip request line
                if ":" not in line:
                    continue
                key, val = line.split(":", 1)
                if key.strip().lower() == "content-length":
                    try:
                        content_length = int(val.strip())
                    except ValueError:
                        content_length = 0
                    break
        except Exception as e:
            logger.warning(f"Failed parsing headers from {addr}: {e}")
            writer.close()
            return

        if content_length < 0 or content_length > BODY_MAX_BYTES:
            logger.warning(f"Content-Length out of bounds from {addr}: {content_length}")
            writer.close()
            return

        # 3. Leer el resto del body (lo que falta tras body_early).
        body_bytes = body_early
        remaining = content_length - len(body_early)
        while remaining > 0:
            remaining_time = deadline - asyncio.get_event_loop().time()
            if remaining_time <= 0:
                logger.warning(
                    f"Body read timeout from {addr} (read {len(body_bytes)}/{content_length})"
                )
                writer.close()
                return
            try:
                chunk = await asyncio.wait_for(reader.read(min(remaining, 65536)), timeout=remaining_time)
            except asyncio.TimeoutError:
                logger.warning(f"Body read timeout from {addr}")
                writer.close()
                return
            if not chunk:
                break
            body_bytes += chunk
            remaining -= len(chunk)

        raw_data = header_part + SEPARATOR + body_bytes
        # --- END FIX §5.9.292 ---

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

        elif path == "/control/enqueue":
            response = await _handle_control_enqueue(method, headers, body)

        elif path == "/control/status":
            response = await _handle_control_status(method, headers, query)

        elif "/iclock/cdata" in (path or ""):
            sn = query.get("SN", "unknown")
            
            if body and len(body) > 0:
                # §5.9.260: redactar Passwd= ANTES de loguear (anti-leak). El body
                # original NO se altera: el ATTLOG nunca contiene Passwd, asi que el
                # parsing aguas abajo sigue intacto (solo se redacta lo que se loguea).
                logger.info(f"ATTENDANCE DATA from {sn}: {redact_passwd(body)[:500]}")
                lines = body.split("\n")
                for line in lines:
                    # §5.9.40: solo ATTLOG reales pasan. OPLOG, dumps de USER, etc
                    # se saltean (no HA, no audit, no fan-out). Fail-silent.
                    if not _is_valid_attlog_line(line):
                        if line.strip():
                            _skipped_attlog_count += 1
                            logger.debug(f"SKIPPED non-ATTLOG line: {redact_passwd(line.strip())[:120]}")
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
            cmd = None
            if _command_queue is not None and sn and sn != "unknown":
                cmd = await _command_queue.pop_for_delivery(sn)
            if cmd is not None:
                body_response = f"C:{cmd.cmd_id}:{cmd.payload}"
                logger.info(
                    f"Command delivered cmd_id={cmd.cmd_id} sn={sn} payload={cmd.payload}"
                )
                response = build_response("200 OK", body_response)
            else:
                response = build_response("200 OK", "OK")

        elif "/iclock/devicecmd" in (path or ""):
            sn = query.get("SN", "unknown")
            logger.info(f"Command result from {sn}: {body[:200]}")
            if _command_queue is not None and body:
                match = _DEVICECMD_ACK_RE.search(body)
                if match:
                    try:
                        cmd_id = int(match.group(1))
                    except (ValueError, TypeError):
                        logger.warning(f"devicecmd con cmd_id no parseable: {body[:200]}")
                    else:
                        existing = await _command_queue.get_status(cmd_id)
                        if existing is None:
                            logger.warning(
                                f"devicecmd ACK para cmd_id={cmd_id} desconocido (no en queue)"
                            )
                        else:
                            await _command_queue.mark_acked(cmd_id, response=body[:500])
                            logger.info(f"Command ACKed cmd_id={cmd_id} sn={sn}")
                else:
                    logger.warning(f"devicecmd sin cmd_id reconocible: {body[:200]}")
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


async def _cleanup_loop(queue: CommandQueue):
    """Background task: cleanup periodico del CommandQueue (PR A.3).

    Fail-safe total: una iteracion rota no mata el loop. Sleep PRIMERO para no
    correr inmediatamente al startup (los Commands recien creados no van a estar
    vencidos de todas formas).
    """
    while True:
        await asyncio.sleep(COMMAND_CLEANUP_INTERVAL_SECONDS)
        try:
            evicted = await queue.cleanup_expired()
            if evicted > 0:
                size = await queue.size()
                logger.info(
                    f"CommandQueue cleanup: evicted={evicted} remaining={size}"
                )
        except Exception:
            logger.exception("cleanup_loop iteration failed (continuing)")


async def main():
    global _audit, _forwarder, _command_queue

    # Generate self-signed cert for TLS
    generate_self_signed_cert()

    # CommandQueue in-memory para el endpoint /control/enqueue (PR A.1, ADR-076).
    _command_queue = CommandQueue()
    if CONTROL_ENDPOINT_ENABLED and not CONTROL_ENDPOINT_TOKEN:
        logger.error(
            "control_endpoint_enabled=true pero control_endpoint_token vacio: "
            "el endpoint /control/enqueue respondera 503 hasta configurar un token"
        )
    logger.info(
        f"Control endpoint /control/enqueue: "
        f"{'enabled' if CONTROL_ENDPOINT_ENABLED else 'disabled'}"
    )

    asyncio.create_task(_cleanup_loop(_command_queue))
    logger.info(
        f"CommandQueue cleanup loop iniciado "
        f"(interval={COMMAND_CLEANUP_INTERVAL_SECONDS}s)"
    )

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
