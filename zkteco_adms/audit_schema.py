"""Schema unificado del audit JSON Lines del add-on ZKTeco (v1.7.0).

El MISMO objeto se escribe al audit local y se manda como body del POST al
webhook ``/eventos/zkteco`` del backend (paridad con ADR-030 del Hikvision). El
adapter ``zkteco.mb10_vl`` del backend consume ``event.tipo`` + ``received_ts``.

``received_ts`` se genera con tz America/Bogota. ``device_mac`` siempre None: el
MB10-VL no expone MAC en ADMS push (la resolucion del backend sera por
``device_sn``).
"""

from datetime import datetime
from zoneinfo import ZoneInfo

_TZ = ZoneInfo("America/Bogota")

SCHEMA_VERSION = "1.0"
DEVICE_BRAND = "zkteco"
# El piloto usa el MB10-VL; el add-on hoy sirve un unico modelo ZKTeco.
DEVICE_MODEL = "MB10-VL"


def _received_ts() -> str:
    return datetime.now(tz=_TZ).isoformat()


def build_access_record(
    sn: str,
    user_id: str,
    device_ts: str,
    status: str,
    verify_method: str,
    raw_line: str,
) -> dict:
    """Record de un evento de acceso (verificacion biometrica/tarjeta/pin)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "received_ts": _received_ts(),
        "device_brand": DEVICE_BRAND,
        "device_model": DEVICE_MODEL,
        "device_sn": sn,
        "device_mac": None,
        "event": {
            "tipo": "access",
            "external_user_id": user_id,
            "verify_method": verify_method,
            "device_ts": device_ts,
            "raw_status": status,
            "raw_line": raw_line,
            "state": None,
        },
    }


def build_device_state_record(sn: str, state: str = "online") -> dict:
    """Record de registro/heartbeat del device (sin body de asistencia)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "received_ts": _received_ts(),
        "device_brand": DEVICE_BRAND,
        "device_model": DEVICE_MODEL,
        "device_sn": sn,
        "device_mac": None,
        "event": {
            "tipo": "device_state",
            "external_user_id": None,
            "verify_method": None,
            "device_ts": None,
            "raw_status": None,
            "raw_line": None,
            "state": state,
        },
    }
