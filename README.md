# Hikvision Face Terminal Listener — Home Assistant Add-on

Add-on para Home Assistant que se conecta al endpoint
`/ISAPI/Event/notification/alertStream` del **terminal biométrico peatonal
Hikvision DS-K1T344MBFWX-E1** (firmware V4.31 build 250421), parsea los
eventos en tiempo real y los reenvía al backend del **Sistema de Portería
Virtual** de NupsterD.

Es un fork del add-on productivo `hikvision-isapi-addon` v1.2.0 (que atiende
al controlador de acceso DS-K2624X), con adaptaciones puntuales para el
firmware V4.31 del terminal facial.

## Arquitectura — IMPORTANTE

> **Este add-on NO abre puertas.** El DS-K1T344 es un *standalone reporter*:
> autentica localmente (rostro / huella / tarjeta / PIN) y **solo REPORTA**
> los eventos al backend.
>
> La apertura física del electroimán **MAG350NLED** la sigue liberando la
> controladora **DS-K2624X** vía *Remote Unlock* ISAPI. El backend evalúa la
> policy (Nivel B) y orquesta ese Remote Unlock a través de Home Assistant.
> Este add-on es **listener + parser + fan-out puro** hacia el backend.

```
  ┌──────────────┐  alertStream   ┌────────────────────┐  fan-out   ┌───────────┐
  │  DS-K1T344   │ ─────────────▶ │  este add-on       │ ─────────▶ │ pv-backend│
  │ (biométrico) │  eventos JSON  │ (listener+parser)  │  POST      │ (policy)  │
  └──────────────┘                └────────────────────┘            └─────┬─────┘
                                                                          │ Remote Unlock
                                                                    ┌─────▼─────┐   ┌──────────┐
                                                                    │ DS-K2624X │──▶│ MAG350NLED│
                                                                    └───────────┘   └──────────┘
```

## Cómo funciona

1. Mantiene una conexión HTTPS persistente al stream con autenticación Digest.
2. Parsea cada bloque MIME + JSON y normaliza el evento a un dict plano.
3. **Filtra** los eventos históricos (`currentEvent=false`) y los heartbeats
   `videoloss`.
4. **Loguea TODOS** los eventos vivos a `/config/face_audit.log` (JSON Lines)
   para auditoría completa.
5. Hace **fan-out** de cada record al backend (`POST` con header
   `X-PV-Hikvision-Face-Token`).
5.5. Si `ha_webhook_url` no es dummy/vacío y el evento es auth OK (face `(5,75)`
   o card `(5,1)` con `employee_no` poblado), emit HTTP POST síncrono al webhook
   HA con payload subset del record. Es un **side-effect defensivo** (fail-silent,
   sin re-raise ni rollback del fan-out backend, que es la fuente primaria).
6. Reconecta automáticamente si pierde la conexión.

## Adaptaciones del firmware V4.31 (hallazgos empíricos §5.9.426-451)

| # | Hallazgo | Adaptación |
|---|---|---|
| §5.9.426 | HTTP/1.1 keep-alive + Digest **cuelga** el request indefinidamente | Header explícito `Connection: close` en el `GET` del stream |
| §5.9.427 | ISAPI solo sobre **HTTPS** (443), cert self-signed regenerable | URL `https://…` + `verify=False` |
| §5.9.443 | El firmware empuja el **buffer histórico completo** (`currentEvent=false`) al abrir el stream, antes del streaming vivo | Filtro `if ace.get("currentEvent") is False: return None` |
| §5.9.444 | Payload con campos nuevos vs DS-K2624X (`cardType`, `FaceRect`, `mask`, `userType`, `frontSerialNo`, `label`, `purePwdVerifyEnable`) | Se extraen y preservan en el record del audit |

> **Nota de smoke E2E hardware (sub-chat 4d):** el comportamiento del firmware
> ante `Connection: close` + `stream=True` con `Transfer-Encoding: chunked`
> solo se confirma con hardware real. El fallback documentado (forzar HTTP/1.0
> vía monkeypatch de `http.client`) está en el comentario del `run()`.

## Tabla de eventos (19 EVENT_TYPES canonical v1.3)

`(majorEventType, subEventType) → descripción`

| Major | Sub | Descripción |
|---|---|---|
| 1 | 1028 | Tamper Restored |
| 1 | 1029 | Tamper Alarm |
| 1 | 1032 | Alarm Input Trigger |
| 2 | 39 | Unknown High-Frequency Event |
| 2 | 1024 | Device Boot/Init |
| 2 | 1031 | Internet Access Status |
| 3 | 112 | Admin Login Success |
| 3 | 123 | Unknown Admin Op 123 |
| 3 | 241 | Unknown Admin Op 241 |
| 3 | 1078 | Unknown Admin Op 1078 |
| 5 | 1 | Card Auth Passed |
| 5 | 21 | Door Unlocked (relé interno del terminal) |
| 5 | 22 | Door Locked (relé interno del terminal) |
| 5 | 23 | Exit Button Pressed |
| 5 | 25 | Door Closed (sensor) |
| 5 | 38 | Fingerprint Auth Passed |
| 5 | 39 | Auth Failed non-face |
| 5 | 75 | Face Auth Passed |
| 5 | 76 | Face Auth Failed |

## Configuración

| Opción | Tipo | Default | Descripción |
|---|---|---|---|
| `terminal_host` | str | `192.168.18.202` | IP o hostname del terminal DS-K1T344 |
| `terminal_user` | str | `admin` | Usuario del terminal |
| `terminal_password` | password | (vacío) | Contraseña del terminal |
| `ha_webhook_url` | url? | (vacío) | Webhook HA; emit POST post-auth OK. Vacío o dummy (`http://127.0.0.1:9999/unused`) = deshabilitado |
| `ha_webhook_timeout_seconds` | int | `3` | Timeout POST al webhook HA (1-30s) |
| `audit_log_path` | str | `/config/face_audit.log` | Ruta del log de auditoría |
| `edificio_slug` | str? | (vacío) | Metadata de ubicación para el backend |
| `puerta_slug` | str | `peatonal-principal` | Metadata de ubicación para el backend |
| `reconnect_delay` | int | `5` | Segundos entre intentos de reconexión |
| `stream_idle_timeout` | int | `30` | Timeout de stream zombie (sin datos) |
| `backend_url` | str? | (vacío) | Webhook del backend; vacío = fan-out deshabilitado |
| `backend_secret` | password? | (vacío) | Shared-secret del header `X-PV-Hikvision-Face-Token` |
| `backend_queue_maxsize` | int | `1000` | Tamaño máx. de la cola de fan-out |
| `backend_timeout_seconds` | int | `3` | Timeout de cada POST al backend |

## Estructura del record enviado al backend / audit

```json
{
  "received_ts": "2026-07-16T19:24:29-05:00",
  "kind": "access_controller_event",
  "major": 5,
  "sub": 75,
  "sub_name": "Face Auth Passed",
  "door": null,
  "serial": 201,
  "device_ts": "2026-07-16T19:24:29-05:00",
  "device_ip": "192.168.18.202",
  "device_mac": "a4:d5:c2:75:fd:64",
  "employee_no": "9001",
  "verify_mode": "faceOrFpOrCardOrPw",
  "card_type": null,
  "face_rect": { "height": 0.389, "width": 0.22, "x": 0.412, "y": 0.458 },
  "mask": "no",
  "user_type": "normal",
  "front_serial_no": 200,
  "label": "",
  "active_post_count": 1,
  "pure_pwd_verify_enable": true,
  "device_kind": "face_terminal",
  "raw": { "...evento original completo..." }
}
```

## Instalación

1. En Home Assistant: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**.
2. Agregar: `https://github.com/nupsterd/hikvision-face-terminal-addon`.
3. Instalar **Hikvision Face Terminal Listener** desde el listado.
4. Configurar `terminal_password`, `backend_url` y `backend_secret`, y arrancar.

## Limitaciones conocidas

- El terminal permite **un solo cliente simultáneo** en el stream. Si iVMS-4200
  está armado, este add-on no puede conectarse hasta que iVMS sea desarmado.
- El `face_audit.log` no rota automáticamente.
- El smoke de este add-on es **local** (replay de un `.raw` capturado). El smoke
  E2E contra el hardware real (`192.168.18.202`) queda para el sub-chat 4d.

## Desarrollo / tests

```bash
uv venv .venv && uv pip install --python .venv/bin/python pytest pytest-cov requests
./.venv/bin/python -m pytest tests/ -v --cov=hikvision_face_terminal --cov-report=term-missing
```

## Licencia

MIT. Ver [LICENSE](LICENSE).
