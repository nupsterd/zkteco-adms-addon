# Changelog

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
