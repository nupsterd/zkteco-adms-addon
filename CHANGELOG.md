# Changelog

## v1.7.2 (2026-06-16)

Fix swap "3" ↔ "4" en VERIFY_METHODS (§5.9.41). Validado empíricamente con tráfico real del MB10-VL del piloto (UDP3260500207): la tarjeta RFID emite parts[3]="4" y el password tecleado emite parts[3]="3", inverso al mapping heredado. Sin cambios funcionales adicionales.

## 1.7.1

**Patch: bugfixes detectados en la validación E2E de v1.7.0 (sin nuevas features).**

- **§5.9.36 — `audit_log_path` opcional.** En v1.7.0 el campo estaba declarado
  `audit_log_path: str` (requerido) en el schema, así que guardar configuración
  en la UI sin ese campo fallaba con "Missing option 'audit_log_path' in root".
  Ahora es `str?` (opcional) y `server.py` cae al default `/config/audit.log`
  ante ausente / null / "".
- **§5.9.40 — Filtro estricto de ATTLOG.** La rama `/iclock/cdata` con body
  procesaba CUALQUIER línea con 4+ campos tab-separated como evento de acceso,
  dejando entrar al audit y al fan-out líneas que NO son ATTLOG (OPLOG, dumps de
  la tabla USER, etc.). Nuevo helper puro `_is_valid_attlog_line()` valida 5
  criterios (user_id numérico, timestamp `YYYY-MM-DD HH:MM:SS`, status y
  verify_method numéricos); las líneas inválidas se saltean a nivel `debug` (con
  contador acumulado a `warning` cada 50). La rama "sin body" (DEVICE REGISTERED
  → `device_state`) NO cambia. Bug heredado de v1.6.0.

## 1.7.0

**AuditLogger + BackendForwarder asyncio (paridad con Hikvision ISAPI Listener v1.2.0).**

- **Audit local JSON Lines** (`AuditLogger`, asyncio + `aiofiles`): TODOS los
  eventos (acceso + registro de device) se persisten en `audit_log_path`
  (default `/config/audit.log`) antes del fan-out. ADR-004 Opción C.
- **Fan-out OPT-IN al backend `pv-backend`** (`BackendForwarder`, asyncio-nativo:
  `asyncio.Queue` + task + `aiohttp.ClientSession`). POST al webhook
  `/eventos/zkteco` con header `X-PV-ZKTeco-Token`. Reintentos con backoff
  (0/0.5/1/2s), sin reintento en 4xx, drop si la cola se llena, fail-silent
  total (nunca rompe el reenvío a HA ni la respuesta ADMS).
- **Schema unificado** del record (`audit_schema.py`): mismo objeto en el audit
  local y en el body del POST (contrato compartido con el adapter
  `zkteco.mb10_vl` del backend).
- 4 opciones nuevas (todas opcionales, default deshabilitado): `pv_backend_url`,
  `pv_backend_verify_token`, `pv_backend_queue_maxsize`,
  `pv_backend_timeout_seconds`. Más `audit_log_path`.
- `map: [addon_config:rw]` para que `/config` (y el audit) sea visible desde
  core-ssh en `/addon_configs/<slug>/`.
- `aiofiles` agregado al `pip3 install` del Dockerfile.
- **Zero regression**: con `pv_backend_url` vacío el comportamiento es idéntico
  a v1.6.0 (solo se suma el audit local).
