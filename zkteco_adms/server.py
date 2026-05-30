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

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

HA_URL = os.environ.get("HA_URL", "http://homeassistant.local:8123")
HA_TOKEN = os.environ.get("HA_TOKEN", "")
ADMS_PORT = int(os.environ.get("ADMS_PORT", "8083"))

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
    if not HA_TOKEN:
        logger.warning("No HA_TOKEN configured, skipping event")
        return

    try:
        import aiohttp
        url = f"{HA_URL}/api/events/{event_type}"
        headers = {
            "Authorization": f"Bearer {HA_TOKEN}",
            "Content-Type": "application/json",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=event_data, headers=headers, ssl=False) as resp:
                if resp.status == 200:
                    logger.info(f"HA event fired: {event_type} -> {event_data}")
                else:
                    logger.error(f"Failed to fire event: {resp.status}")
    except Exception as e:
        logger.error(f"Error firing HA event: {e}")


async def update_ha_sensor(entity_id: str, state: str, attributes: dict = None):
    """Update a sensor state in Home Assistant."""
    if not HA_TOKEN:
        return

    try:
        import aiohttp
        url = f"{HA_URL}/api/states/{entity_id}"
        headers = {
            "Authorization": f"Bearer {HA_TOKEN}",
            "Content-Type": "application/json",
        }
        payload = {"state": state, "attributes": attributes or {}}
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, ssl=False) as resp:
                if resp.status not in (200, 201):
                    logger.error(f"Failed to update sensor {entity_id}: {resp.status}")
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


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handle each incoming TCP/TLS connection."""
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
    # Generate self-signed cert for TLS
    generate_self_signed_cert()
    
    # Create SSL context
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    
    # Start TLS server
    server = await asyncio.start_server(handle_client, '0.0.0.0', ADMS_PORT, ssl=ssl_ctx)
    logger.info(f"ZKTeco ADMS Server (TLS) running on port {ADMS_PORT}")
    logger.info(f"Home Assistant URL: {HA_URL}")
    
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
