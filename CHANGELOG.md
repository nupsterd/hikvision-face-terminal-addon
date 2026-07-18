# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versionado siguiendo [SemVer](https://semver.org/lang/es/).

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
