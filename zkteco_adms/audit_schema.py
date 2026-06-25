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


def _envelope(sn: str, event: dict) -> dict:
    """Arma el sobre raiz comun del schema unificado alrededor de un ``event``."""
    return {
        "schema_version": SCHEMA_VERSION,
        "received_ts": _received_ts(),
        "device_brand": DEVICE_BRAND,
        "device_model": DEVICE_MODEL,
        "device_sn": sn,
        "device_mac": None,
        "event": event,
    }


def build_oplog_record(sn: str, parsed: dict, raw_line: str) -> dict:
    """Record de una operacion OPLOG (USER MODIFY/DELETE, post-FP commit) (PR A.4).

    ``parsed`` proviene de ``operlog_parser.parse_oplog_line``. El OPLOG trae su
    propio ``device_ts`` (estable entre reentregas del MB10-VL) => el flag
    ``inferred_timestamp`` queda False: B.3 debe usar ``device_ts`` como timestamp
    de idempotencia (constraint ``ux_eventos_idempotencia``, NULLS NOT DISTINCT)
    junto a ``codigo_mayor=oplog_code`` para no colisionar dos OPLOG del mismo
    segundo (p.ej. OPLOG 6 y OPLOG 30 comparten device_ts).
    """
    return _envelope(
        sn,
        {
            "tipo": parsed["tipo"],
            "oplog_code": parsed["oplog_code"],
            "param": parsed["param"],
            "device_ts": parsed["device_ts"],
            "pin": parsed["pin"],
            "raw_extra": parsed["raw_extra"],
            "raw_line": raw_line,
            "inferred_timestamp": False,
        },
    )


def build_user_snapshot_record(sn: str, parsed: dict, raw_line: str) -> dict:
    """Record de un snapshot USER (PR A.4).

    El USER snapshot NO trae ``device_ts`` propio => ``inferred_timestamp`` True:
    B.3 usa ``received_ts`` (wall clock con microsegundos) como timestamp y acepta
    el riesgo de duplicado en una reentrega rara (decision cerrada Chat 4a; la
    correlacion con el OPLOG vecino es scope B.3, no A.4). El ``passwd`` ya viene
    redactado por el caller (§5.9.260).
    """
    return _envelope(
        sn,
        {
            "tipo": "user_snapshot",
            "pin": parsed["pin"],
            "fields": parsed["fields"],
            "device_ts": None,
            "raw_line": raw_line,
            "inferred_timestamp": True,
        },
    )


def build_fp_template_record(sn: str, parsed: dict, raw_line: str) -> dict:
    """Record de un template biometrico FP (PR A.4).

    Sin ``device_ts`` propio => ``inferred_timestamp`` True (ver
    build_user_snapshot_record). ``tmp_b64`` se preserva completo.
    """
    return _envelope(
        sn,
        {
            "tipo": "fingerprint_template",
            "pin": parsed["pin"],
            "fid": parsed["fid"],
            "size": parsed["size"],
            "valid": parsed["valid"],
            "tmp_b64": parsed["tmp_b64"],
            "device_ts": None,
            "raw_line": raw_line,
            "inferred_timestamp": True,
        },
    )


def build_operlog_record(sn: str, parsed: dict, raw_line: str) -> dict:
    """Dispatcher: arma el record unificado segun ``parsed["tipo"]`` (PR A.4).

    Acepta la salida de ``operlog_parser.classify_operlog_line``. Levanta
    ``ValueError`` ante un tipo desconocido (defensivo; el caller solo pasa tipos
    ya clasificados).
    """
    tipo = parsed["tipo"]
    if tipo.startswith("oplog_"):
        return build_oplog_record(sn, parsed, raw_line)
    if tipo == "user_snapshot":
        return build_user_snapshot_record(sn, parsed, raw_line)
    if tipo == "fingerprint_template":
        return build_fp_template_record(sn, parsed, raw_line)
    raise ValueError(f"tipo OPERLOG desconocido: {tipo!r}")
