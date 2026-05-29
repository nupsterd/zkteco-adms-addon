"""
ZKTeco ADMS Server for Home Assistant
Receives attendance events from ZKTeco devices via ADMS protocol
and publishes them to Home Assistant via the REST API.
"""

import asyncio
import logging
import json
import os
from datetime import datetime
from aiohttp import web
import aiohttp

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


async def fire_ha_event(event_type: str, event_data: dict):
    """Fire an event in Home Assistant."""
    if not HA_TOKEN:
        logger.warning("No HA_TOKEN configured, skipping event")
        return

    url = f"{HA_URL}/api/events/{event_type}"
    headers = {
        "Authorization": f"Bearer {HA_TOKEN}",
        "Content-Type": "application/json",
    }

    try:
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

    url = f"{HA_URL}/api/states/{entity_id}"
    headers = {
        "Authorization": f"Bearer {HA_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {"state": state, "attributes": attributes or {}}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, ssl=False) as resp:
                if resp.status not in (200, 201):
                    logger.error(f"Failed to update sensor {entity_id}: {resp.status}")
    except Exception as e:
        logger.error(f"Error updating HA sensor: {e}")


async def handle_cdata(request: web.Request) -> web.Response:
    """
    Handle /iclock/cdata - device registration and data push.
    ZKTeco devices send attendance records here.
    """
    sn = request.rel_url.query.get("SN", "unknown")
    options = request.rel_url.query.get("options", "")

    # Device registration / heartbeat
    if "all" in options or not await request.read():
        logger.info(f"Device registered/heartbeat: SN={sn}")
        connected_devices[sn] = datetime.now().isoformat()

        # Update device sensor in HA
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

        return web.Response(
            text=f"GET OPTION FROM:{sn}\nATTLOGStamp=None\nOPERLOGStamp=9999\nATTPHOTOStamp=None\nErrorDelay=30\nDelay=10\nTransTimes=00:00;14:05\nTransInterval=1\nTransFlag=TransData AttLog OpLog AttPhoto EnrollUser ChgUser EnrollFP ChgFP UserPic\nTimeZone=8\nRealtime=1\nEncrypt=None",
            content_type="text/plain"
        )

    # Attendance data push
    body = await request.text()
    logger.info(f"Data from {sn}: {body}")

    if body:
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

                logger.info(f"Attendance: {event_data}")

                # Fire HA event
                await fire_ha_event("zkteco_attendance", event_data)

                # Update last user sensor
                await update_ha_sensor(
                    f"sensor.zkteco_{sn.lower()}_last_user",
                    user_id,
                    {
                        "friendly_name": f"ZKTeco {sn} - Último Usuario",
                        "timestamp": timestamp_str,
                        "verify_method": verify_method,
                        "status": status,
                    }
                )

    return web.Response(text="OK", content_type="text/plain")


async def handle_getrequest(request: web.Request) -> web.Response:
    """
    Handle /iclock/getrequest - device polls for commands.
    We can send commands to the device here.
    """
    sn = request.rel_url.query.get("SN", "unknown")
    logger.debug(f"Command poll from: {sn}")
    return web.Response(text="OK", content_type="text/plain")


async def handle_devicecmd(request: web.Request) -> web.Response:
    """
    Handle /iclock/devicecmd - device reports command execution result.
    """
    body = await request.text()
    sn = request.rel_url.query.get("SN", "unknown")
    logger.info(f"Command result from {sn}: {body}")
    return web.Response(text="OK", content_type="text/plain")


async def handle_status(request: web.Request) -> web.Response:
    """Health check endpoint."""
    return web.json_response({
        "status": "running",
        "connected_devices": connected_devices,
        "timestamp": datetime.now().isoformat(),
    })


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_route("GET", "/iclock/cdata", handle_cdata)
    app.router.add_route("POST", "/iclock/cdata", handle_cdata)
    app.router.add_route("GET", "/iclock/getrequest", handle_getrequest)
    app.router.add_route("POST", "/iclock/devicecmd", handle_devicecmd)
    app.router.add_route("GET", "/status", handle_status)
    return app


if __name__ == "__main__":
    logger.info(f"Starting ZKTeco ADMS Server on port {ADMS_PORT}")
    logger.info(f"Home Assistant URL: {HA_URL}")
    app = create_app()
    web.run_app(app, host="0.0.0.0", port=ADMS_PORT)
