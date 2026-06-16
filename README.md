# ZKTeco ADMS Server - Home Assistant Add-on

Servidor ADMS para integrar dispositivos ZKTeco (MB10-VL y otros) con Home Assistant.

## ¿Cómo funciona?

El dispositivo ZKTeco se conecta como cliente ADMS a este servidor. Cada vez que alguien registra huella, rostro o tarjeta, el servidor recibe el evento y lo publica en Home Assistant.

## Eventos generados en HA

### `zkteco_attendance`
Se dispara cada vez que alguien es verificado.

```json
{
  "serial_number": "ABC123",
  "user_id": "1",
  "timestamp": "2026-01-01 08:00:00",
  "status": "0",
  "verify_method": "fingerprint"
}
```

### `zkteco_device_connected`
Se dispara cuando el dispositivo se conecta o envía heartbeat.

```json
{
  "serial_number": "ABC123",
  "timestamp": "2026-01-01 08:00:00"
}
```

## Sensores creados automáticamente

- `sensor.zkteco_{SN}_status` — Estado del dispositivo (online/offline)
- `sensor.zkteco_{SN}_last_user` — Último usuario verificado

## Configuración del dispositivo ZKTeco

En el menú del ZKTeco:
```
Comm → Cloud Server Setting
  Habilitar nombre de dominio: ON
  Dirección del servidor: [IP de la Raspberry]
  Puerto del servidor: 8083
```

## Configuración del add-on

| Parámetro | Descripción |
|---|---|
| `ha_token` | Long-lived access token de Home Assistant |
| `adms_port` | Puerto del servidor (default: 8083) |
| `audit_log_path` | Ruta del audit log JSON Lines (default: `/config/audit.log`) |
| `pv_backend_url` | URL del webhook del backend (vacío = fan-out desactivado) |
| `pv_backend_verify_token` | Shared secret del header `X-PV-ZKTeco-Token` |
| `pv_backend_queue_maxsize` | Tamaño máximo de la cola del forwarder (default: 1000) |
| `pv_backend_timeout_seconds` | Timeout del POST al backend (default: 3) |

## Automatización de ejemplo

Abrir puerta cuando alguien es verificado:

```yaml
automation:
  - alias: "Abrir puerta acceso peatonal"
    trigger:
      platform: event
      event_type: zkteco_attendance
    condition:
      condition: template
      value_template: "{{ trigger.event.data.verify_method in ['fingerprint', 'face', 'card'] }}"
    action:
      service: switch.turn_on
      entity_id: switch.rele_puerta
```

## Fan-out al backend pv-backend (v1.7.0+)

Desde v1.7.0 el add-on, además de emitir eventos a Home Assistant, puede:

1. **Auditar localmente** todos los eventos en JSON Lines (`audit_log_path`,
   default `/config/audit.log`, visible desde core-ssh en
   `/addon_configs/<slug>/audit.log`). Siempre activo (ADR-004 Opción C).
2. **Hacer fan-out** del mismo record al webhook `/eventos/zkteco` del backend
   `pv-backend`. **Opt-in**: si `pv_backend_url` está vacío, queda desactivado
   (zero regression respecto a v1.6.0).

Cada evento se manda con el header `X-PV-ZKTeco-Token: <pv_backend_verify_token>`,
que debe coincidir con el secret `zkteco_webhook_shared_secret` que el backend
lee de la tabla `secrets_aplicacion` al startup.

El forwarder es asyncio-nativo (`asyncio.Queue` + task + `aiohttp`): reintenta
con backoff (0/0.5/1/2s), no reintenta en 4xx, dropea si la cola se llena, y es
**fail-silent total** (jamás rompe el reenvío a HA ni la respuesta ADMS al
dispositivo).

Esquema del record (mismo objeto en el audit local y en el POST):

```json
{
  "schema_version": "1.0",
  "received_ts": "2026-06-16T15:34:01.123-05:00",
  "device_brand": "zkteco",
  "device_model": "MB10-VL",
  "device_sn": "UDP3260500207",
  "device_mac": null,
  "event": {
    "tipo": "access",
    "external_user_id": "1",
    "verify_method": "fingerprint",
    "device_ts": "2026-06-16 15:34:01",
    "raw_status": "255",
    "raw_line": "1\t2026-06-16 15:34:01\t255\t1\t0\t0\t0\t0\t0\t0",
    "state": null
  }
}
```

Para registros/heartbeats (sin body de asistencia) `event.tipo` es
`"device_state"` con `state: "online"`.

### Configuración de ejemplo

```yaml
pv_backend_url: "http://192.168.18.91:8000/api/v1/eventos/zkteco"
pv_backend_verify_token: "<igual al secret zkteco_webhook_shared_secret del backend>"
pv_backend_queue_maxsize: 1000
pv_backend_timeout_seconds: 3
```
