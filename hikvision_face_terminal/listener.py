#!/usr/bin/env python3
"""
Hikvision ISAPI Event Stream Listener para el terminal biométrico peatonal
DS-K1T344MBFWX-E1 (firmware V4.31 build 250421).

Mantiene una conexión HTTPS de larga duración al endpoint
/ISAPI/Event/notification/alertStream del terminal facial, parsea los
eventos multipart MIME + JSON, filtra los relevantes y los reenvía al
backend pv-backend. Loguea todo a archivo local para auditoría completa.

ARQUITECTURA (no confundir con el add-on del DS-K2624X):
El DS-K1T344 es un "standalone reporter" peatonal: autentica localmente
(rostro / huella / tarjeta / PIN) y SOLO REPORTA los eventos al backend.
La apertura física del electroimán MAG350NLED la sigue liberando la
controladora DS-K2624X vía Remote Unlock ISAPI, orquestado por el backend
(policy Nivel B) a través de Home Assistant. Este add-on NO abre puertas:
es listener + parser + fan-out puro.

Fork del add-on productivo `hikvision-isapi-addon` v1.2.0 (DS-K2624X).
Adaptaciones puntuales del firmware V4.31 documentadas en §5.9.426-451:
  - HTTP/1.0 requirement via header Connection: close (§5.9.426)
  - HTTPS + cert self-signed (§5.9.427)
  - Filter currentEvent=true en el parser (§5.9.443)
  - Shape del payload §5.9.444 (cardType/FaceRect/mask/userType/...)
"""

from __future__ import annotations

import json
import logging
import os
import queue
import shutil
import signal
import sys
import time
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from requests.auth import HTTPDigestAuth


# ---------------------------------------------------------------------------
# Configuración: leída desde variables de entorno (inyectadas por config.yaml)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Config:
    """Configuración del listener. Read-only tras inicialización (frozen)."""

    terminal_host: str
    terminal_user: str
    terminal_password: str
    ha_webhook_url: str
    audit_log_path: Path
    # Metadata que el backend usa para ubicar el evento (edificio/puerta).
    edificio_slug: str = ""
    puerta_slug: str = "peatonal-principal"
    reconnect_delay: int = 5
    # Timeout máximo sin recibir nada del stream (incluso heartbeats).
    # El DS-K1T344 emite videoloss heartbeats cada ~25s, así que 30s es
    # ajustado; parametrizable por si el firmware cambia el intervalo.
    stream_idle_timeout: int = 30
    # Fan-out al backend pv-backend. Todos opcionales: con backend_url vacío
    # el forwarder queda deshabilitado (no-op).
    backend_url: str = ""
    backend_secret: str = ""
    backend_queue_maxsize: int = 1000
    backend_timeout_seconds: int = 3

    @classmethod
    def from_options_json(cls, path: str = "/data/options.json") -> "Config":
        """Lee la config desde el archivo que inyecta el supervisor de HA."""
        with open(path, "r", encoding="utf-8") as f:
            opts = json.load(f)
        return cls(
            terminal_host=opts["terminal_host"],
            terminal_user=opts["terminal_user"],
            terminal_password=opts["terminal_password"],
            ha_webhook_url=opts.get("ha_webhook_url", ""),
            audit_log_path=Path(opts.get("audit_log_path", "/config/face_audit.log")),
            edificio_slug=opts.get("edificio_slug", ""),
            puerta_slug=opts.get("puerta_slug", "peatonal-principal"),
            reconnect_delay=int(opts.get("reconnect_delay", 5)),
            stream_idle_timeout=int(opts.get("stream_idle_timeout", 30)),
            backend_url=opts.get("backend_url", ""),
            backend_secret=opts.get("backend_secret", ""),
            backend_queue_maxsize=int(opts.get("backend_queue_maxsize", 1000)),
            backend_timeout_seconds=int(opts.get("backend_timeout_seconds", 3)),
        )


# ---------------------------------------------------------------------------
# Diccionario de eventos Hikvision del DS-K1T344 (18 EVENT_TYPES canonical v1.2)
# (major_event_type, sub_event_type) -> descripción humana
#
# 18 = tabla completa consolidada (§5.9.X sub-chat 4c). Los "14 EVENT_TYPES"
# del handoff §14.35 eran el conteo empírico de eventos live F4 (13 gestos +
# 1 tamper); los 18 incluyen los eventos del buffer histórico F3.4 (Major 2/3
# de boot, internet access y ops admin) capturados en dsk1t344_alertstream_first.
# ---------------------------------------------------------------------------

EVENT_TYPES: dict[tuple[int, int], str] = {
    # Major 1 (Alarm/Tamper Events)
    (1, 1028): "Tamper Restored",
    (1, 1029): "Tamper Alarm",
    (1, 1032): "Alarm Input Trigger",
    # Major 2 (Device/System Events)
    (2, 39): "Unknown High-Frequency Event",
    (2, 1024): "Device Boot/Init",
    (2, 1031): "Internet Access Status",
    # Major 3 (Operation/Admin Events)
    (3, 112): "Admin Login Success",
    (3, 123): "Unknown Admin Op 123",
    (3, 241): "Unknown Admin Op 241",
    (3, 1078): "Unknown Admin Op 1078",
    # Major 5 (Access Control Events)
    (5, 21): "Door Unlocked (relé interno del terminal)",
    (5, 22): "Door Locked (relé interno del terminal)",
    (5, 23): "Exit Button Pressed",
    (5, 25): "Door Closed (sensor)",
    (5, 38): "Auth Passed non-face (fp/card/PIN multi-modal)",
    (5, 39): "Auth Failed non-face",
    (5, 75): "Face Auth Passed",
    (5, 76): "Face Auth Failed",
}


def should_forward_to_ha(major: int, sub: int) -> bool:
    """Filtro forward-a-HA para el DS-K1T344.

    Sin eventos que forward a HA en el MVP del terminal facial: el backend
    recibe todo vía fan-out. HA interviene solo forward sobre la DS-K2624X
    (add-on productivo `hikvision-isapi-addon` v1.2.0), que es quien libera
    el electroimán. Cualquier necesidad de forward a HA se re-evalúa post-MVP;
    el field ha_webhook_url del config se preserva como placeholder.
    """
    return False


# ---------------------------------------------------------------------------
# Parser del stream multipart MIME
# ---------------------------------------------------------------------------

MIME_BOUNDARY = b"--MIME_boundary"


def parse_event_block(body: bytes, log: logging.Logger) -> Optional[dict]:
    """
    Parsea un bloque JSON del stream. Retorna dict normalizado o None.
    None significa: heartbeat (videoloss) o evento histórico (currentEvent
    False) — se ignoran silenciosamente.
    """
    try:
        text = body.decode("utf-8", errors="replace").strip()
        if not text:
            return None
        event = json.loads(text)
    except json.JSONDecodeError:
        log.warning("No se pudo parsear JSON del bloque: %r", body[:100])
        return None

    event_type = event.get("eventType")

    # Heartbeats — se ignoran
    if event_type == "videoloss":
        return None

    # Eventos de control de acceso (los más importantes)
    if event_type == "AccessControllerEvent":
        ace = event.get("AccessControllerEvent", {})
        # §5.9.443: el firmware V4.31 empuja el buffer histórico completo
        # (currentEvent=false) al abrir el alertStream ANTES del streaming
        # vivo. Sin este filtro, un reconnect tras crash reenvía decenas de
        # eventos viejos al backend (connection storm + duplicados masivos).
        # `is False` (no `== False`) para no descartar por None/missing.
        if ace.get("currentEvent") is False:
            log.debug("skip_historical_event serialNo=%s", ace.get("serialNo"))
            return None
        major = ace.get("majorEventType")
        sub = ace.get("subEventType")
        return {
            "kind": "access_controller_event",
            "timestamp": event.get("dateTime"),
            "device_ip": event.get("ipAddress"),
            "device_mac": event.get("macAddress"),
            "major": major,
            "sub": sub,
            "description": EVENT_TYPES.get((major, sub), f"Unknown ({major},{sub})"),
            "door_no": ace.get("doorNo"),
            "door_name": ace.get("doorName"),
            "serial_no": ace.get("serialNo"),
            "card_no": ace.get("cardNo"),
            "employee_no": ace.get("employeeNoString") or ace.get("employeeNo"),
            "verify_mode": ace.get("currentVerifyMode"),
            # Campos DS-K1T344 shape §5.9.444 (nuevos vs DS-K2624X). Se
            # preservan para features forward: §5.9.430 duress cards,
            # §5.9.448 multi-modal breakdown, §5.9.451 FaceRect quality.
            "card_type": ace.get("cardType"),          # §5.9.430 duress detection
            "face_rect": ace.get("FaceRect"),           # §5.9.451 quality heuristic
            "mask": ace.get("mask"),                    # face con/sin mascarilla
            "user_type": ace.get("userType"),           # normal/duress/patrol/visitor
            "front_serial_no": ace.get("frontSerialNo"),
            "label": ace.get("label"),                  # placeholder Hikvision futuro
            # DIVERGENCIA EMPÍRICA §5.9.X (sub-chat 4c): purePwdVerifyEnable
            # vive DENTRO de AccessControllerEvent, NO top-level. El diseño D9
            # asumía top-level; verificado en dsk1t344_f4_capture (top=None,
            # nested=True). Se extrae de `ace`.
            "pure_pwd_verify_enable": ace.get("purePwdVerifyEnable"),
            # activePostCount SÍ es top-level del payload (confirmado empírico).
            "active_post_count": event.get("activePostCount"),
            "raw": event,
        }

    # Cualquier otro tipo: lo dejamos crudo
    return {
        "kind": "other",
        "timestamp": event.get("dateTime"),
        "event_type": event_type,
        "raw": event,
    }


# ---------------------------------------------------------------------------
# Auditoría local: append a archivo, una línea por evento (JSON Lines)
# ---------------------------------------------------------------------------

# Path legacy del audit (heredado del add-on original). El terminal facial es
# greenfield, pero se preserva la migración para paridad estructural cross-repo.
LEGACY_AUDIT_PATH = Path("/data/face_audit.log")


class AuditLogger:
    """Escribe TODOS los eventos parseados a un archivo JSON Lines para auditoría.

    Mantiene un handle de archivo persistente en modo append y hace flush()
    explícito tras cada write: ~5x menos syscalls que open/close por evento,
    misma garantía de durabilidad ante crash.
    """

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("a", encoding="utf-8")

    def write(self, record: dict) -> None:
        try:
            self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._fh.flush()
        except OSError as exc:
            # Nunca bloqueamos el fan-out al backend (camino crítico M2);
            # reportamos a stderr y seguimos.
            logging.getLogger("audit").error("Falló escritura audit log: %s", exc)


def build_audit_record(event: dict) -> dict:
    """Proyecta el evento normalizado de parse_event_block() al schema JSON Lines
    del audit (superset acordado), preservando los campos §5.9.444 del DS-K1T344.

    Incluye `device_kind="face_terminal"` como field top-level requerido por el
    backend para el branching device_kind (webhook /eventos/hikvision-face).
    Para eventos kind=="other" los canónicos van en null (schema homogéneo).
    """
    received_ts = datetime.now().astimezone().isoformat()  # tz America/Bogota del container

    return {
        "received_ts": received_ts,
        "kind": event.get("kind"),
        "major": event.get("major"),
        "sub": event.get("sub"),
        "sub_name": event.get("description"),   # renombrado
        "door": event.get("door_no"),           # renombrado
        "serial": event.get("serial_no"),       # renombrado
        # extras útiles del parser (superset)
        "device_ts": event.get("timestamp"),    # dateTime reportado por el terminal
        "device_ip": event.get("device_ip"),
        "device_mac": event.get("device_mac"),
        "door_name": event.get("door_name"),
        "card_no": event.get("card_no"),
        "employee_no": event.get("employee_no"),
        "verify_mode": event.get("verify_mode"),
        "event_type": event.get("event_type"),  # presente en kind=="other"
        # Campos DS-K1T344 nuevos (§5.9.444), preservados para features futuras:
        "card_type": event.get("card_type"),
        "face_rect": event.get("face_rect"),
        "mask": event.get("mask"),
        "user_type": event.get("user_type"),
        "front_serial_no": event.get("front_serial_no"),
        "label": event.get("label"),
        "active_post_count": event.get("active_post_count"),
        "pure_pwd_verify_enable": event.get("pure_pwd_verify_enable"),
        # Field TOP-LEVEL nuevo requerido por el backend para branching device_kind:
        "device_kind": "face_terminal",
        "raw": event.get("raw"),
    }


def migrate_legacy_audit(legacy: Path, new: Path, log: logging.Logger) -> None:
    """Copia única del audit viejo (/data) al nuevo path (/config) en el arranque.

    No destructiva, no aborta el arranque si falla. Preservada del add-on
    original para paridad estructural cross-repo (backports triviales).
    """
    try:
        if legacy == new or not legacy.exists():
            return
        if new.exists():
            log.warning(
                "Audit nuevo ya existe en %s; NO se migra el legacy (%s). Continuando.",
                new, legacy,
            )
            return
        new.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(legacy, new)
        n = sum(1 for _ in new.open("r", encoding="utf-8", errors="replace"))
        log.info(
            "Migración audit: %d líneas copiadas de %s a %s. Legacy intacto.",
            n, legacy, new,
        )
    except OSError as exc:
        logging.getLogger("audit").error(
            "Falló migración del audit legacy (%s -> %s): %s. "
            "Continuando con el path nuevo.",
            legacy, new, exc,
        )


# ---------------------------------------------------------------------------
# Fan-out al backend pv-backend (canal primario del M2 face terminal)
# ---------------------------------------------------------------------------

class BackendForwarder:
    """Worker thread daemon que reenvía records al pv-backend.

    Fail-silent total: ningún error rompe el audit local. Si backend_url está
    vacío, el forwarder queda no-op (deshabilitado).

    Política:
    - Cola thread-safe con maxsize configurable. Si llena, drop el nuevo
      (put_nowait raisea queue.Full).
    - Reintentos: 3 intentos con backoff 0.5/1/2s.
    - 4xx (cliente) NO se reintenta. 5xx + RequestException SÍ.
    - El record es el mismo que se escribió al audit.log: schema unificado.
    - Header X-PV-Hikvision-Face-Token: el backend valida device_kind=
      face_terminal con este header específico (distinto del DS-K2624X).
    """

    _SENTINEL = object()  # marca de shutdown (no usado activamente hoy)

    def __init__(self, cfg: Config, log: logging.Logger):
        self.cfg = cfg
        self.log = log
        self.enabled = bool(cfg.backend_url.strip())
        self._queue: Optional[queue.Queue] = (
            queue.Queue(maxsize=cfg.backend_queue_maxsize) if self.enabled else None
        )
        self._thread: Optional[threading.Thread] = None
        self._dropped_count = 0

    def start(self) -> None:
        if not self.enabled:
            self.log.info("Fan-out al backend deshabilitado (backend_url vacío).")
            return
        if not self.cfg.backend_secret:
            self.log.warning(
                "Fan-out: backend_url configurada pero sin secret. El backend "
                "va a rechazar todo con 401."
            )
        self._thread = threading.Thread(
            target=self._worker, name="backend-forwarder", daemon=True
        )
        self._thread.start()
        self.log.info(
            "Fan-out al backend activo: url=%s queue_maxsize=%d timeout=%ds",
            self.cfg.backend_url,
            self.cfg.backend_queue_maxsize,
            self.cfg.backend_timeout_seconds,
        )

    def enqueue(self, record: dict) -> None:
        if not self.enabled:
            return
        assert self._queue is not None  # enabled => la cola existe
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            self._dropped_count += 1
            # Logueamos el primer drop y luego 1 de cada 50, con el total.
            if self._dropped_count % 50 == 1:
                self.log.warning(
                    "Cola de fan-out llena (maxsize=%d): record descartado. "
                    "Total descartados: %d.",
                    self.cfg.backend_queue_maxsize,
                    self._dropped_count,
                )

    def _worker(self) -> None:
        assert self._queue is not None
        # NUNCA salir del while por un fallo de envío: solo el sentinel rompe
        # el loop. Capturamos Exception (no BaseException) para preservar
        # KeyboardInterrupt / SystemExit.
        while True:
            record = self._queue.get()
            try:
                if record is self._SENTINEL:
                    break
                self._post_with_retries(record)
            except Exception as exc:
                self.log.error(
                    "Fan-out falló para record (kind=%s major=%s sub=%s): %s",
                    record.get("kind") if isinstance(record, dict) else "?",
                    record.get("major") if isinstance(record, dict) else "?",
                    record.get("sub") if isinstance(record, dict) else "?",
                    exc,
                )
            finally:
                self._queue.task_done()

    def _post_with_retries(self, record: dict) -> None:
        url = self.cfg.backend_url
        token = self.cfg.backend_secret
        timeout = self.cfg.backend_timeout_seconds
        # §F5.8: header renombrado. El backend valida device_kind=face_terminal
        # con este header; sin él responde 401.
        headers = {"X-PV-Hikvision-Face-Token": token} if token else {}
        delays = [0.5, 1.0, 2.0]
        last_exc: Optional[BaseException] = None
        for attempt, delay in enumerate(delays, start=1):
            try:
                resp = requests.post(
                    url, json=record, headers=headers, timeout=timeout
                )
                if 200 <= resp.status_code < 300:
                    return  # éxito
                if 400 <= resp.status_code < 500:
                    # error de cliente: no reintentable (token malo, payload, etc.)
                    self.log.warning(
                        "Fan-out no reintentable (HTTP %d): %s",
                        resp.status_code,
                        resp.text[:200],
                    )
                    return
                # 5xx -> reintentable
                last_exc = RuntimeError(f"HTTP {resp.status_code}")
                self.log.warning(
                    "Fan-out 5xx (HTTP %d), reintento %d/%d en %.1fs.",
                    resp.status_code,
                    attempt,
                    len(delays),
                    delay,
                )
            except requests.RequestException as exc:
                last_exc = exc
                self.log.warning(
                    "Fan-out request falló (%s), reintento %d/%d en %.1fs.",
                    exc,
                    attempt,
                    len(delays),
                    delay,
                )
            if attempt < len(delays):
                time.sleep(delay)
        raise RuntimeError("Fan-out agotó 3 intentos") from last_exc


# ---------------------------------------------------------------------------
# Reenvío a HA via webhook (preservado del original; hoy inactivo en el M2:
# should_forward_to_ha() devuelve False. Se mantiene para paridad estructural
# y para un eventual re-enable post-MVP sin re-implementar).
# ---------------------------------------------------------------------------

def forward_to_ha(webhook_url: str, event: dict, log: logging.Logger) -> None:
    """POST del evento al webhook de HA. No bloquea ante errores."""
    try:
        resp = requests.post(
            webhook_url,
            json=event,
            timeout=5,
            verify=False,  # HA con cert autofirmado en LAN
        )
        if resp.status_code >= 400:
            log.warning(
                "HA webhook respondió %s: %s",
                resp.status_code, resp.text[:200]
            )
    except requests.RequestException as exc:
        log.error("Falló envío al webhook de HA: %s", exc)


# ---------------------------------------------------------------------------
# Loop principal: conecta, escucha, reconecta
# ---------------------------------------------------------------------------

def run(cfg: Config, log: logging.Logger) -> None:
    """Loop principal del listener. Reconecta indefinidamente ante caídas
    y detecta streams zombie (conectado pero sin datos)."""
    migrate_legacy_audit(LEGACY_AUDIT_PATH, cfg.audit_log_path, log)
    audit = AuditLogger(cfg.audit_log_path)
    forwarder = BackendForwarder(cfg, log)
    forwarder.start()
    # §5.9.427/D8: el DS-K1T344 V4.31 solo expone ISAPI sobre HTTPS puerto 443
    # (a diferencia del DS-K2624X que expone HTTP 80).
    url = f"https://{cfg.terminal_host}/ISAPI/Event/notification/alertStream"

    STREAM_IDLE_TIMEOUT = cfg.stream_idle_timeout

    while True:
        try:
            log.info("Conectando al stream ISAPI: %s", url)
            # §5.9.426/D6: el firmware V4.31 cuelga request HTTP/1.1 con
            # keep-alive + Digest indefinidamente. El header Connection: close
            # fuerza el cierre por request y desbloquea el stream.
            # §5.9.427: HTTPS con cert self-signed regenerable -> verify=False.
            #
            # NOTA §5.9.426: si el firmware cierra el stream tras el primer chunk
            # con Connection: close + stream=True, el fallback documentado es
            # forzar HTTP/1.0 via monkeypatch en setup_logging():
            #   import http.client
            #   http.client.HTTPConnection._http_vsn = 10
            #   http.client.HTTPConnection._http_vsn_str = "HTTP/1.0"
            # Validar en smoke E2E hardware sub-chat 4d.
            response = requests.get(
                url,
                auth=HTTPDigestAuth(cfg.terminal_user, cfg.terminal_password),
                stream=True,
                timeout=(10, STREAM_IDLE_TIMEOUT),
                headers={"Connection": "close"},
                verify=False,  # DS-K1T344 usa HTTPS cert self-signed §5.9.427
            )
            response.raise_for_status()
            log.info("Conectado. Escuchando eventos.")

            last_data_at = time.monotonic()

            buffer = b""
            for chunk in response.iter_content(chunk_size=1024):
                # Watchdog: si pasó mucho tiempo sin chunks, asumir zombie
                if time.monotonic() - last_data_at > STREAM_IDLE_TIMEOUT:
                    log.warning(
                        "Stream sin datos durante %ds — asumiendo zombie, "
                        "reconectando.",
                        STREAM_IDLE_TIMEOUT,
                    )
                    break

                if not chunk:
                    continue

                last_data_at = time.monotonic()
                buffer += chunk

                while MIME_BOUNDARY in buffer:
                    part, _, buffer = buffer.partition(MIME_BOUNDARY)
                    if not part.strip():
                        continue

                    if b"\r\n\r\n" in part:
                        _, _, body = part.partition(b"\r\n\r\n")
                    elif b"\n\n" in part:
                        _, _, body = part.partition(b"\n\n")
                    else:
                        continue

                    event = parse_event_block(body, log)
                    if event is None:
                        continue

                    # Audit: siempre todos (el filtrado aplica solo a HA)
                    record = build_audit_record(event)
                    audit.write(record)
                    # Fan-out al backend (canal primario M2; no-op si deshabilitado).
                    forwarder.enqueue(record)

                    # Filtrado para HA (hoy siempre False en el M2 face terminal).
                    if event.get("kind") == "access_controller_event":
                        major = event.get("major")
                        sub = event.get("sub")
                        if should_forward_to_ha(major, sub):
                            log.info(
                                "→ HA: door=%s serial=%s %s",
                                event.get("door_no"),
                                event.get("serial_no"),
                                event.get("description"),
                            )
                            forward_to_ha(cfg.ha_webhook_url, event, log)
                        else:
                            log.debug(
                                "↓ audit+backend-only: %s",
                                event.get("description"),
                            )
                    else:
                        log.debug(
                            "↓ audit+backend-only (other): %s",
                            event.get("event_type"),
                        )

        except requests.exceptions.ReadTimeout:
            log.warning(
                "Read timeout del stream (%ds sin datos). Reconectando.",
                STREAM_IDLE_TIMEOUT,
            )

        except requests.exceptions.HTTPError as exc:
            log.error("HTTP error del terminal: %s", exc)
            if exc.response is not None:
                status = exc.response.status_code
                body = exc.response.text[:500]
                log.error("  Status: %s", status)
                log.error("  Headers WWW-Authenticate: %r",
                          exc.response.headers.get("WWW-Authenticate"))
                log.error("  Body: %r", body)

                if status == 401 and "lockStatus" in body and "lock" in body:
                    import re
                    m = re.search(r"<unlockTime>(\d+)</unlockTime>", body)
                    wait_s = int(m.group(1)) + 30 if m else 900
                    log.error(
                        "*** CUENTA BLOQUEADA por el terminal. "
                        "Esperando %ds antes de reintentar. ***",
                        wait_s,
                    )
                    time.sleep(wait_s)
                    continue

                if status == 401:
                    log.error(
                        "*** Autenticación fallida (401 sin lockout). "
                        "Esperando 5 minutos antes de reintentar. ***"
                    )
                    time.sleep(300)
                    continue

        except requests.exceptions.ConnectionError as exc:
            log.error("Conexión perdida: %s", exc)
        except requests.exceptions.RequestException as exc:
            log.error("Error de request: %s", exc)
        except Exception as exc:
            log.exception("Excepción no manejada en el loop: %s", exc)

        log.info("Reintentando conexión en %ds...", cfg.reconnect_delay)
        time.sleep(cfg.reconnect_delay)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def setup_logging() -> logging.Logger:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # Silenciar el warning de cert autofirmado al conectar por HTTPS
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return logging.getLogger("hikvision-face-terminal")


def install_signal_handlers(log: logging.Logger) -> None:
    def handler(signum, _frame):
        log.info("Señal %s recibida, saliendo limpiamente.", signum)
        sys.exit(0)
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)


def main() -> None:
    log = setup_logging()
    install_signal_handlers(log)

    try:
        cfg = Config.from_options_json()
    except FileNotFoundError:
        log.error("/data/options.json no existe. ¿Está corriendo dentro del add-on?")
        sys.exit(1)
    except KeyError as exc:
        log.error("Falta opción obligatoria en options.json: %s", exc)
        sys.exit(1)

    log.info(
        "Config fan-out backend: url=%r secret=%s queue_maxsize=%d timeout=%ds",
        cfg.backend_url or "(deshabilitado)",
        "configurado" if cfg.backend_secret else "(vacío)",
        cfg.backend_queue_maxsize,
        cfg.backend_timeout_seconds,
    )
    log.info(
        "Listener iniciado. Terminal=%s user=%s edificio=%s puerta=%s audit=%s",
        cfg.terminal_host,
        cfg.terminal_user,
        cfg.edificio_slug or "(vacío)",
        cfg.puerta_slug,
        cfg.audit_log_path,
    )
    run(cfg, log)


if __name__ == "__main__":
    main()
