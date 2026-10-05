# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versionado siguiendo [SemVer](https://semver.org/lang/es/).

## v1.1.0-alpha (sin publicar)

### Added
- **Recuperación de eventos perdidos por ISAPI AcsEvent (#54, B6.2).** Después de cada
  conexión exitosa del stream (incluido el arranque), un hilo aparte pide al terminal
  `POST /ISAPI/AccessControl/AcsEvent?format=json` todo lo posterior al cursor
  (`beginSerialNo = cursor + 1`, `maxResults` 30, paginando mientras `MORE`), lo reordena
  por `serialNo` (AcsEvent ordena por hora), lo reconstruye con la forma del alertStream
  (`dateTime` = `time` tal cual) y lo pasa por el mismo parser y el mismo
  `build_audit_record` con `recuperado: true`. Va al audit y al backend; **nunca** al
  webhook de HA. Requiere pv-backend con el PR #74 (pre-chequeo de duplicados).
- Estado persistente `/config/face_state.json` (`cursor_serial`, `terminal_mac`,
  `updated_at`), escritura atómica y lectura tolerante. Cursor = mayor serial entregado con
  2xx sin ningún serial pendiente o fallido por debajo (3 intentos agotados, 4xx o cola
  llena lo frenan hasta que una recuperación lo entregue).
- Puerta única por serial antes de la cola (últimos 10 000): cada serial sale como máximo
  una vez por proceso, por stream o por recuperación.
- Primer arranque sin estado: el cursor se inicializa con el serial más reciente del
  terminal (`timeReverseOrder`, últimos 7 días) sin recuperar historia.
- `major=0` (todos) con caída a `major=5` si el equipo lo rechaza; reset de fábrica
  (serial en vivo < cursor − 1000) reinicia el cursor; tope por corrida de 1000 eventos y
  7 días; un 401 suspende la recuperación de esa conexión sin reintentar (§5.9.574); sin
  MAC del terminal no se recupera. Ninguna opción nueva.

### Fixed (prueba en hardware 2026-10-05)
- `deviceInfo`: el DS-K1T344 ignora `?format=json` y responde XML con namespace; la
  recuperación terminaba en "Sin MAC del terminal (deviceInfo HTTP 200)". Ahora se pide
  `GET /ISAPI/System/deviceInfo` sin formato, se intenta JSON y si no se parsea el XML
  (elemento cuyo tag termina en `macAddress`, sin importar el namespace).
- Techo por conexión del cursor: si la recuperación no se completaba (sin MAC, 401, error o
  corte por tope), las entregas en vivo subían el cursor por encima de seriales nunca vistos
  y se perdían en silencio. Cada corrida con cursor abre un techo en el cursor efectivo del
  momento; el cursor (y el persistido) no lo pasa. Corrida completa ⇒ se libera; cortada por
  tope ⇒ sube al mayor serial admitido; fallida ⇒ queda. Tras un reinicio se retoma desde el
  cursor persistido congelado (lo entregado en vivo en ese lapso se re-envía y el backend lo
  absorbe como duplicado). El primer arranque no abre techo; un reset de fábrica lo descarta.
- AcsEvent por serial: el DS-K1T344 exige `endSerialNo` junto con `beginSerialNo` (sin él
  responde 400 `errorMsg: "endSerialNo"`, que se tomaba como rechazo de `major=0` y la
  corrida abortaba). Toda consulta por serial manda `endSerialNo = 999999999` (`4294967295`
  también da 400). La consulta de inicialización es por tiempo y no cambia.
- Fallback a `major=5` solo si el 400 trae un `errorMsg` que menciona `major`; cualquier otro
  rechazo aborta la corrida (el techo protege) y el `errorMsg` del equipo se loguea.
- Corrida cortada sin ningún ítem admitido (todos con más de 7 días, ya vistos o sin
  record) dejaba el techo igual y la siguiente pedía el mismo rango: cursor congelado. Ahora
  el techo de una corrida cortada sube a lo procesado: con sobrantes, `min(sobrantes) − 1`;
  con la paginación cortada y sin sobrantes, el mayor serial obtenido; sin ítems, queda.
- Los abandonados por antigüedad y los ítems sin record no subían el cursor: sin entregas
  en vivo, cada reconexión volvía a pedir el mismo rango (también tras una corrida completa
  con todo abandonado). Ahora son estado final igual que un 2xx (`resolver_sin_envio`):
  suben el cursor hasta el mayor de ellos; un pendiente por debajo y el techo lo siguen
  limitando. Los sobrantes por tope no se resuelven.
- El techo se abre en `Recuperador.lanzar()`, en el hilo del stream y antes de leer
  eventos de la conexión (antes lo abría el hilo de recuperación: una 2xx en vivo que
  ganara la carrera saltaba el hueco). `abrir_techo` nunca sube un techo abierto
  (`min(techo, cursor efectivo)`); sin cursor no abre. `correr()` ya no lo abre.
- `lanzar()` con una corrida en curso ya no pierde la conexión nueva: marca "relanzar"
  (log INFO); la corrida en curso no libera el techo y al terminar se corre otra en el mismo
  hilo, repitiendo mientras se vuelva a marcar.

### Changed
- `BackendForwarder._post_with_retries` devuelve `True` (2xx) / `False` (4xx) para informar
  el resultado al cursor. `AuditLogger.write` con lock (escriben dos hilos).

## v1.0.1-alpha (2026-07-18)

### 2026-07-18 hotfix1
- Fixed: `_maybe_emit_ha_webhook` `requests.post` ahora usa `verify=False` (paridad con `forward_to_ha` línea 494 y fan-out DS-K1T344 línea 636). Sin este fix el emit HTTPS al HA banco con cert self-signed fallaba con `RemoteDisconnected` empírico (§5.9.510 canónico Chat 7 S10).

### 2026-07-18 hotfix2
- Fixed: `_maybe_emit_ha_webhook` discriminador `sub in (75, 1)` → `(75, 1, 38)` para incluir `(5,38)` Fingerprint Auth Passed. Sin este fix, gestos fingerprint OK del firmware V4.31 no emitían al webhook HA y no generaban aperturas (§5.9.512 canónico Chat 7 S10).

- **Added**: HA webhook emit post-auth OK (`(5,75)` face + `(5,1)` card empírico
  §5.9.507 Chat 7 S10) — skip legacy dummy URL para backward compat.
- **Added**: config setting `ha_webhook_timeout_seconds` (default 3s, range 1-30s).
- **Fixed**: §5.9.491 brecha empírica flow face → apertura DS-K1T344 → policy
  engine backend closed empíricamente.
- **Fixed**: `EVENT_TYPES` dict `(5,38)` description corregida a "Fingerprint
  Auth Passed" (era "Auth Passed non-face" mislabeled §14.35). Agregado `(5,1)`
  "Card Auth Passed" empíricamente confirmado en Chat 7 S10 3 gestos card
  (§5.9.507). Tabla de eventos v1.2 (18 entries) → v1.3 (19 entries).

## [1.0.0-alpha] - 2026-07-16

Fork greenfield del add-on productivo `hikvision-isapi-addon` v1.2.0 (que
atiende al controlador DS-K2624X) para dar soporte al terminal biométrico
peatonal **DS-K1T344MBFWX-E1** firmware V4.31 build 250421.

### Added
- Listener del Event Stream ISAPI del DS-K1T344 (HTTPS + Digest).
- **18 EVENT_TYPES canonical v1.2** (Major 1/2/3/5): tabla completa consolidada
  a partir de los eventos live F4 + el buffer histórico F3.4.
- Fan-out al backend `pv-backend` con header `X-PV-Hikvision-Face-Token` y
  field `device_kind=face_terminal` para el branching del webhook.
- Extracción y preservación de los campos nuevos del payload DS-K1T344
  (§5.9.444): `cardType`, `FaceRect`, `mask`, `userType`, `frontSerialNo`,
  `label`, `purePwdVerifyEnable`, `activePostCount` — para features forward
  (§5.9.430 duress, §5.9.448 multi-modal, §5.9.451 face quality).
- Nuevos campos de config: `edificio_slug`, `puerta_slug`, `stream_idle_timeout`.
- Suite de tests greenfield (el repo original no tenía tests): parser (18
  EVENT_TYPES + filtro `currentEvent` + shape §5.9.444), config, backend
  forwarder (retry/backoff/header/queue), y smoke de replay del `.raw`
  capturado empíricamente. Cobertura ≥85% en `listener.py`.

### Changed (adaptaciones firmware V4.31)
- **§5.9.426**: header `Connection: close` obligatorio en el `GET` del stream
  (HTTP/1.1 keep-alive + Digest cuelga el request indefinidamente).
- **§5.9.427**: URL del stream sobre **HTTPS** + `verify=False` (cert
  self-signed; el DS-K1T344 no expone HTTP a diferencia del DS-K2624X).
- **§5.9.443**: filtro `currentEvent=false` en el parser (descarta el buffer
  histórico que el firmware empuja al abrir el stream; evita connection storm
  y duplicados al reconectar).
- Renaming semántico: `controller_*` → `terminal_*`, `pv_backend_*` →
  `backend_*`.

### Notes
- **Divergencia empírica** (candidato §5.9.X): el diseño D9 asumía que
  `purePwdVerifyEnable` era un campo top-level del payload; verificado
  empíricamente que vive **dentro** de `AccessControllerEvent`. Se extrae de
  `ace`. `activePostCount` sí es top-level.
- Este add-on **NO abre puertas**: la apertura del electroimán la sigue
  liberando la DS-K2624X vía Remote Unlock orquestado por el backend.
- El smoke E2E contra el hardware real queda para el sub-chat 4d.
