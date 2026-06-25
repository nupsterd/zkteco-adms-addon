"""Parsers puros de las lineas OPERLOG/USER/FP del MB10-VL (PR A.4, Chat 4a S8).

El MB10-VL, ademas de los ATTLOG de verificacion, pushea por la tabla OPERLOG
(via POST /iclock/cdata) lineas de auditoria de cambios de usuario que hoy el
add-on descarta (filtro `_is_valid_attlog_line`, §5.9.294). Este modulo las
parsea para forwardearlas al backend:

- ``OPLOG <code>\\t<param>\\t<device_ts>\\t<pin>\\t<x>\\t<y>\\t<z>`` -- operacion.
  Codigos canonicos (§5.9.259): 4=admin login, 6=post-FP commit (hipotesis
  §5.9.301), 7=USER ADD puro, 9=USER DELETE, 30=USER MODIFY, 70=pre-commit.
  Orden temporal tipico (§5.9.302): USER snapshot -> FP -> OPLOG.
- ``USER PIN=<n>\\tName=...\\tPasswd=<REDACTED>\\t...`` -- snapshot del usuario.
- ``FP PIN=<n>\\tFID=<n>\\tSize=<n>\\tValid=<n>\\tTMP=<base64>`` -- template FP.

Lista positiva de forward (decision D2 Chat 4a): OPLOG 6/9/30 + USER snapshot +
FP template. Se descartan OPLOG 4 (admin login, ruido), 7 (USER ADD puro, no
productivo) y 70 (pre-commit redundante con el 30/9 posterior).

Funciones puras (zero side-effects) para testeo trivial: ninguna loggea, redacta
ni forwardea. La redaccion del Passwd (§5.9.260) y el forward los hace el caller
(`server._maybe_forward_operlog`): estos parsers preservan el valor que reciben
(si el caller ya redacto, queda `Passwd=<REDACTED>`).

Samples literales (Chat 4a 2026-06-25):
    OPLOG 30\\t0\\t2026-06-25 16:28:28\\t4\\t0\\t0\\t0
    OPLOG 9\\t0\\t2026-06-25 16:29:14\\t4\\t0\\t0\\t0
    OPLOG 6\\t0\\t2026-06-25 16:28:28\\t4\\t0\\t0\\t0
    USER PIN=4\\tName=User3\\tPri=0\\tPasswd=<REDACTED>\\tCard=\\tGrp=1\\tTZ=0000000100000000\\tVerify=1\\tViceCard=\\tStartDatetime=0\\tEndDatetime=0
    FP PIN=4\\tFID=6\\tSize=1488\\tValid=1\\tTMP=<base64 ~1.4KB>
"""

# Codigos OPLOG que NO se forwardean (decision D2). parse_oplog_line los trata
# como linea no-match (retorna None) para que el filtro de arriba los descarte.
_OPLOG_DESCARTAR = frozenset({4, 7, 70})

# Campos del USER snapshot mapeados a claves snake_case del schema unificado.
# (clave del device, clave en `fields`).
_USER_FIELDS = (
    ("Name", "name"),
    ("Pri", "pri"),
    ("Passwd", "passwd"),
    ("Card", "card"),
    ("Grp", "grp"),
    ("TZ", "tz"),
    ("Verify", "verify"),
    ("ViceCard", "vice_card"),
    ("StartDatetime", "start_datetime"),
    ("EndDatetime", "end_datetime"),
)


def _parse_kv_fields(prefix: str, line: str) -> dict | None:
    """Parsea una linea ``<PREFIX> K1=V1\\tK2=V2\\t...`` a dict {K: V}.

    El primer campo viene pegado al prefijo (``USER PIN=4`` / ``FP PIN=4``), por
    eso se separa el prefijo antes de splitear por tab. Cada par se parte por el
    PRIMER ``=`` (el base64 del TMP puede llevar ``=`` de padding -> se preserva).
    Retorna None si la linea no arranca con el prefijo esperado.
    """
    if not line:
        return None
    stripped = line.strip()
    if not stripped.startswith(prefix):
        return None
    parts = stripped.split("\t")
    # Primer campo: quitar "PREFIX " dejando "PIN=<n>".
    first = parts[0][len(prefix):]
    items = [first] + parts[1:]
    kv: dict = {}
    for item in items:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        kv[key.strip()] = value
    return kv


def parse_oplog_line(line: str) -> dict | None:
    """Parsea una linea ``OPLOG <code>\\t<param>\\t<device_ts>\\t<pin>\\t...``.

    Retorna ``{tipo, oplog_code, param, device_ts, pin, raw_extra}`` si matchea y
    el codigo esta en la lista positiva; ``None`` si no matchea, esta malformado o
    el codigo esta en {4, 7, 70} (filtrado por D2).
    """
    if not line:
        return None
    stripped = line.strip()
    parts = stripped.split("\t")
    head = parts[0].split()
    if len(head) != 2 or head[0] != "OPLOG":
        return None
    try:
        oplog_code = int(head[1])
    except ValueError:
        return None
    if oplog_code in _OPLOG_DESCARTAR:
        return None
    # Shape esperado: OPLOG <code>\t<param>\t<device_ts>\t<pin>\t<x>\t<y>\t<z>.
    if len(parts) < 4:
        return None
    try:
        param = int(parts[1])
        pin = int(parts[3])
    except ValueError:
        return None
    return {
        "tipo": f"oplog_{oplog_code}",
        "oplog_code": oplog_code,
        "param": param,
        "device_ts": parts[2],
        "pin": pin,
        "raw_extra": parts[4:7],
    }


def parse_user_snapshot(line: str) -> dict | None:
    """Parsea ``USER PIN=<n>\\tName=...\\tPasswd=<...>\\t...`` a dict estructurado.

    Retorna ``{tipo: "user_snapshot", pin, fields: {...}}`` o ``None`` si no
    matchea. El ``passwd`` se preserva tal cual viene (el caller redacta antes,
    §5.9.260): si la entrada trae ``Passwd=<REDACTED>``, ``fields.passwd`` queda
    ``"<REDACTED>"``.
    """
    kv = _parse_kv_fields("USER ", line)
    if kv is None or "PIN" not in kv:
        return None
    try:
        pin = int(kv["PIN"])
    except ValueError:
        return None
    fields = {dest: kv.get(src) for src, dest in _USER_FIELDS}
    return {"tipo": "user_snapshot", "pin": pin, "fields": fields}


def parse_fp_template(line: str) -> dict | None:
    """Parsea ``FP PIN=<n>\\tFID=<n>\\tSize=<n>\\tValid=<n>\\tTMP=<base64>``.

    Retorna ``{tipo: "fingerprint_template", pin, fid, size, valid, tmp_b64}`` o
    ``None``. ``tmp_b64`` se preserva COMPLETO (no se trunca; el parser HTTP de
    §5.9.292 acota a 10 MiB, holgado para un FP de ~2 KB).
    """
    kv = _parse_kv_fields("FP ", line)
    if kv is None:
        return None
    try:
        pin = int(kv["PIN"])
        fid = int(kv["FID"])
        size = int(kv["Size"])
        valid = int(kv["Valid"])
    except (KeyError, ValueError):
        return None
    return {
        "tipo": "fingerprint_template",
        "pin": pin,
        "fid": fid,
        "size": size,
        "valid": valid,
        "tmp_b64": kv.get("TMP", ""),
    }


def classify_operlog_line(line: str) -> tuple[str, dict] | None:
    """Prueba los 3 parsers en orden y retorna el primer match.

    Retorna ``(tipo, parsed_dict)`` o ``None`` si ninguna variedad matchea (linea
    ATTLOG, OPLOG filtrado 4/7/70, o basura).
    """
    for parser in (parse_oplog_line, parse_user_snapshot, parse_fp_template):
        parsed = parser(line)
        if parsed is not None:
            return parsed["tipo"], parsed
    return None
