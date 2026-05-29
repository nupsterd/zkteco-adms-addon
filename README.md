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
