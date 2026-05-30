"""
ZKTeco ADMS Server for Home Assistant
Uses raw TCP to handle non-standard HTTP from ZKTeco devices.
"""

import asyncio
import logging
import json
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
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
                    logger.info(f"Event fired: {event_type} -> {event_data}")
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
    
    # Parse request line
    request_line = lines[0]
    parts = request_line.split(' ')
    if len(parts) >= 2:
        method = parts[0]
        path = parts[1]
    else:
        method = "UNKNOWN"
        path = "/"
    
    # Parse headers
    headers = {}
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        if line == '':
            body_start = i + 1
            break
        if ':' in line:
            key, val = line.split(':', 1)
            headers[key.strip()] = val.strip()
    
    # Parse body
    body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ""
    
    # Parse query string
    query = {}
    if '?' in path:
        path_part, qs = path.split('?', 1)
        query = parse_qs(qs)
        # Flatten single values
        query = {k: v[0] if len(v) == 1 else v for k, v in query.items()}
        path = path_part
    
    return method, path, headers, query, body


def build_cdata_response(sn: str) -> str:
    """Build the ADMS response for device registration."""
    return (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: text/plain\r\n"
        f"Connection: close\r\n"
        f"\r\n"
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


def build_ok_response() -> str:
    return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK\r\n"


def build_status_response() -> str:
    data = json.dumps({
        "status": "running",
        "connected_devices": connected_devices,
        "timestamp": datetime.now().isoformat(),
    })
    return f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{data}\r\n"


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handle each incoming TCP connection."""
    addr = writer.get_extra_info('peername')
    
    try:
        # Read raw data with timeout
        raw_data = await asyncio.wait_for(reader.read(8192), timeout=10.0)
        
        if not raw_data:
            writer.close()
            return
        
        # Log raw bytes for debugging
        logger.info(f"RAW from {addr[0]}: hex={raw_data[:50].hex()} ascii={raw_data[:200].decode('utf-8', errors='replace')}")
        
        # Check if TLS/SSL handshake (starts with 0x16 0x03)
        if raw_data[0:1] == b'\x16':
            logger.warning(f"TLS handshake detected from {addr[0]} - device is trying HTTPS. Disable HTTPS on the device.")
            writer.close()
            return
        
        # Parse HTTP request
        method, path, headers, query, body = parse_http_request(raw_data)
        logger.info(f"REQUEST from {addr[0]}: method={method} path={path} query={query} body_len={len(body)}")
        
        # Route handling
        response = build_ok_response()
        
        if path == "/status":
            response = build_status_response()
        
        elif "/iclock/cdata" in path:
            sn = query.get("SN", "unknown")
            
            if body and len(body.strip()) > 0:
                # Attendance data
                logger.info(f"ATTENDANCE DATA from {sn}: {body[:500]}")
                lines = body.strip().split("\n")
                for line in lines:
                    parts = line.strip().split("\t")
                    if len(parts) >= 4:
                        user_id = parts[0]
                        timestamp_str = parts[1]
                        status = parts[2]
                        verify = parts[3]
                        verify_method = VERIFY_METHODS.get(verify, "unknown")
                        
                        event_data = {
                            "serial_number": sn,
                            "user_id": user_id,
                            "timestamp": timestamp_str,
                            "status": status,
                            "verify_method": verify_method,
                        }
                        logger.info(f"Attendance event: {event_data}")
                        await fire_ha_event("zkteco_attendance", event_data)
                        await update_ha_sensor(
                            f"sensor.zkteco_{sn.lower()}_last_user",
                            user_id,
                            {
                                "friendly_name": f"ZKTeco {sn} - Ultimo Usuario",
                                "timestamp": timestamp_str,
                                "verify_method": verify_method,
                                "status": status,
                            }
                        )
                response = build_ok_response()
            else:
                # Device registration / heartbeat
                logger.info(f"Device registered: SN={sn}")
                connected_devices[sn] = datetime.now().isoformat()
                await update_ha_sensor(
                    f"sensor.zkteco_{sn.lower()}_status",
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
        
        elif "/iclock/getrequest" in path:
            sn = query.get("SN", "unknown")
            logger.debug(f"Command poll from: {sn}")
            response = build_ok_response()
        
        elif "/iclock/devicecmd" in path:
            sn = query.get("SN", "unknown")
            logger.info(f"Command result from {sn}: {body[:200]}")
            response = build_ok_response()
        
        else:
            logger.info(f"UNHANDLED path={path} method={method}")
            response = build_ok_response()
        
        writer.write(response.encode('utf-8'))
        await writer.drain()
    
    except asyncio.TimeoutError:
        logger.debug(f"Timeout reading from {addr[0]}")
    except Exception as e:
        logger.error(f"Error handling client {addr[0]}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass


async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', ADMS_PORT)
    logger.info(f"ZKTeco ADMS Server running on port {ADMS_PORT}")
    logger.info(f"Home Assistant URL: {HA_URL}")
    
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
