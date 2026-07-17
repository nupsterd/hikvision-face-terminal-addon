"""Tests que ejercitan el loop run(), los entry points y los componentes de I/O.

Drivean el listener con un requests.get mockeado que reproduce el stream
capturado, sin tocar hardware ni red.
"""

from __future__ import annotations

import json
import logging
import queue
from dataclasses import replace
from pathlib import Path

import pytest

from hikvision_face_terminal import listener as mod
from hikvision_face_terminal.listener import (
    AuditLogger,
    BackendForwarder,
    Config,
    build_audit_record,
    forward_to_ha,
    install_signal_handlers,
    migrate_legacy_audit,
    parse_event_block,
    run,
    setup_logging,
)

LOG = logging.getLogger("test-run")


class _StopLoop(Exception):
    """Rompe el while True de run() de forma controlada en los tests."""


class FakeResponse:
    def __init__(self, chunks, status: int = 200):
        self._chunks = chunks
        self.status_code = status

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size=1024):
        yield from self._chunks


def cfg_for(tmp_path: Path, **overrides) -> Config:
    base = Config(
        terminal_host="192.168.18.202",
        terminal_user="admin",
        terminal_password="x",
        ha_webhook_url="",
        audit_log_path=tmp_path / "face_audit.log",
        backend_url="",
        backend_secret="",
        reconnect_delay=1,
    )
    return replace(base, **overrides)


def chunks_from_fixture(name: str, size: int = 1024):
    raw = (Path(__file__).parent / "fixtures" / name).read_bytes()
    return [raw[i:i + size] for i in range(0, len(raw), size)]


# --- run(): happy path completo con replay del stream ---

def test_run_replay_stream_escribe_audit_y_reconecta(tmp_path, monkeypatch):
    """run() conecta, parsea los 13 ACE live, los audita, y reconecta.

    Corta el while True vía time.sleep(reconnect_delay) -> _StopLoop.
    """
    chunks = chunks_from_fixture("dsk1t344_f4_capture.raw")
    resp = FakeResponse(chunks)

    def fake_get(url, **kwargs):
        # Verifica las adaptaciones DS-K1T344: HTTPS + Connection: close + verify=False
        assert url.startswith("https://")
        assert kwargs["headers"]["Connection"] == "close"
        assert kwargs["verify"] is False
        return resp

    monkeypatch.setattr(mod.requests, "get", fake_get)

    def fake_sleep(_s):
        raise _StopLoop()

    monkeypatch.setattr(mod.time, "sleep", fake_sleep)

    cfg = cfg_for(tmp_path)
    with pytest.raises(_StopLoop):
        run(cfg, LOG)

    # Se auditaron los 13 eventos ACE live (videoloss no se auditan).
    lines = (tmp_path / "face_audit.log").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 13
    records = [json.loads(x) for x in lines]
    assert all(r["device_kind"] == "face_terminal" for r in records)
    assert any((r["major"], r["sub"]) == (5, 75) for r in records)


def _stop_sleep(monkeypatch):
    monkeypatch.setattr(
        mod.time, "sleep", lambda _s: (_ for _ in ()).throw(_StopLoop())
    )


class HTTPErrResponse:
    def __init__(self, status, text, www=""):
        self.status_code = status
        self.text = text
        self.headers = {"WWW-Authenticate": www}


def test_run_maneja_read_timeout(tmp_path, monkeypatch):
    def fake_get(url, **kwargs):
        raise mod.requests.exceptions.ReadTimeout("idle")

    monkeypatch.setattr(mod.requests, "get", fake_get)
    _stop_sleep(monkeypatch)
    with pytest.raises(_StopLoop):
        run(cfg_for(tmp_path), LOG)


def test_run_maneja_401_lockout(tmp_path, monkeypatch):
    """401 con <lockStatus>lock</lockStatus> -> espera unlockTime (sleep)."""
    resp = HTTPErrResponse(
        401,
        "<lockStatus>lock</lockStatus><unlockTime>120</unlockTime>",
    )
    err = mod.requests.exceptions.HTTPError("401")
    err.response = resp

    def fake_get(url, **kwargs):
        raise err

    monkeypatch.setattr(mod.requests, "get", fake_get)
    _stop_sleep(monkeypatch)  # el sleep del lockout dispara _StopLoop
    with pytest.raises(_StopLoop):
        run(cfg_for(tmp_path), LOG)


def test_run_maneja_401_sin_lockout(tmp_path, monkeypatch):
    resp = HTTPErrResponse(401, "unauthorized")
    err = mod.requests.exceptions.HTTPError("401")
    err.response = resp
    monkeypatch.setattr(mod.requests, "get",
                        lambda url, **k: (_ for _ in ()).throw(err))
    _stop_sleep(monkeypatch)
    with pytest.raises(_StopLoop):
        run(cfg_for(tmp_path), LOG)


def test_run_maneja_request_exception_generica(tmp_path, monkeypatch):
    monkeypatch.setattr(
        mod.requests, "get",
        lambda url, **k: (_ for _ in ()).throw(
            mod.requests.exceptions.RequestException("weird")),
    )
    _stop_sleep(monkeypatch)
    with pytest.raises(_StopLoop):
        run(cfg_for(tmp_path), LOG)


def test_forwarder_start_avisa_si_no_hay_secret(tmp_path, caplog):
    cfg = cfg_for(tmp_path, backend_url="https://b.local/e", backend_secret="")
    fwd = BackendForwarder(cfg, LOG)
    with caplog.at_level(logging.WARNING):
        fwd.start()
    fwd.enqueue(BackendForwarder._SENTINEL)  # type: ignore[arg-type]
    fwd._thread.join(timeout=2)
    assert any("sin secret" in r.message for r in caplog.records)


def test_run_maneja_connection_error_y_reintenta(tmp_path, monkeypatch):
    """Un ConnectionError en la primera conexión se maneja y va al reconnect."""
    calls = {"n": 0}

    def fake_get(url, **kwargs):
        calls["n"] += 1
        raise mod.requests.exceptions.ConnectionError("no route to host")

    monkeypatch.setattr(mod.requests, "get", fake_get)
    monkeypatch.setattr(mod.time, "sleep", lambda _s: (_ for _ in ()).throw(_StopLoop()))

    cfg = cfg_for(tmp_path)
    with pytest.raises(_StopLoop):
        run(cfg, LOG)
    assert calls["n"] == 1


# --- AuditLogger ---

def test_audit_logger_escribe_json_lines(tmp_path):
    path = tmp_path / "sub" / "audit.log"
    audit = AuditLogger(path)
    audit.write({"a": 1, "ñ": "áéí"})
    audit.write({"b": 2})
    content = path.read_text(encoding="utf-8").splitlines()
    assert json.loads(content[0]) == {"a": 1, "ñ": "áéí"}
    assert json.loads(content[1]) == {"b": 2}


# --- migrate_legacy_audit ---

def test_migrate_legacy_copia_si_new_no_existe(tmp_path):
    legacy = tmp_path / "data" / "audit.log"
    legacy.parent.mkdir()
    legacy.write_text("line1\nline2\n", encoding="utf-8")
    new = tmp_path / "config" / "audit.log"
    migrate_legacy_audit(legacy, new, LOG)
    assert new.read_text(encoding="utf-8") == "line1\nline2\n"


def test_migrate_legacy_no_sobreescribe_si_new_existe(tmp_path):
    legacy = tmp_path / "data" / "audit.log"
    legacy.parent.mkdir()
    legacy.write_text("legacy\n", encoding="utf-8")
    new = tmp_path / "config" / "audit.log"
    new.parent.mkdir()
    new.write_text("nuevo\n", encoding="utf-8")
    migrate_legacy_audit(legacy, new, LOG)
    assert new.read_text(encoding="utf-8") == "nuevo\n"  # intacto


def test_migrate_legacy_noop_si_legacy_no_existe(tmp_path):
    legacy = tmp_path / "nope.log"
    new = tmp_path / "new.log"
    migrate_legacy_audit(legacy, new, LOG)
    assert not new.exists()


# --- forward_to_ha (preservado, inactivo en el MVP) ---

def test_forward_to_ha_ok(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None, verify=None):
        captured["url"] = url
        captured["verify"] = verify

        class R:
            status_code = 200
        return R()

    monkeypatch.setattr(mod.requests, "post", fake_post)
    forward_to_ha("https://ha.local/webhook", {"k": 1}, LOG)
    assert captured["verify"] is False


def test_forward_to_ha_maneja_status_error(monkeypatch):
    def fake_post(url, json=None, timeout=None, verify=None):
        class R:
            status_code = 500
            text = "boom"
        return R()

    monkeypatch.setattr(mod.requests, "post", fake_post)
    forward_to_ha("https://ha.local/webhook", {"k": 1}, LOG)  # no raise


def test_forward_to_ha_maneja_request_exception(monkeypatch):
    def fake_post(url, json=None, timeout=None, verify=None):
        raise mod.requests.RequestException("refused")

    monkeypatch.setattr(mod.requests, "post", fake_post)
    forward_to_ha("https://ha.local/webhook", {"k": 1}, LOG)  # no raise


# --- BackendForwarder worker end-to-end ---

def test_forwarder_worker_procesa_y_hace_post(tmp_path, monkeypatch):
    posts = []

    def fake_post(url, json=None, headers=None, timeout=None):
        posts.append(json)

        class R:
            status_code = 200
            text = ""
        return R()

    monkeypatch.setattr(mod.requests, "post", fake_post)
    cfg = cfg_for(tmp_path, backend_url="https://b.local/e", backend_secret="tok")
    fwd = BackendForwarder(cfg, LOG)
    fwd.start()
    fwd.enqueue({"kind": "access_controller_event", "major": 5, "sub": 75})
    fwd._queue.join()  # espera drenar la cola
    assert posts == [{"kind": "access_controller_event", "major": 5, "sub": 75}]


def test_forwarder_worker_captura_excepcion_de_post(tmp_path, monkeypatch):
    """Un fallo de _post_with_retries no mata el worker (fail-silent)."""
    def fake_post(url, json=None, headers=None, timeout=None):
        raise mod.requests.RequestException("down")

    monkeypatch.setattr(mod.requests, "post", fake_post)
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)
    cfg = cfg_for(tmp_path, backend_url="https://b.local/e", backend_secret="tok")
    fwd = BackendForwarder(cfg, LOG)
    fwd.start()
    fwd.enqueue({"kind": "x"})
    fwd._queue.join()  # el worker sigue vivo tras el fallo
    assert fwd._thread.is_alive()


def test_forwarder_worker_rompe_con_sentinel(tmp_path):
    cfg = cfg_for(tmp_path, backend_url="https://b.local/e", backend_secret="tok")
    fwd = BackendForwarder(cfg, LOG)
    fwd.start()
    fwd.enqueue(BackendForwarder._SENTINEL)  # type: ignore[arg-type]
    fwd._thread.join(timeout=2)
    assert not fwd._thread.is_alive()


# --- entry point helpers ---

def test_setup_logging_devuelve_logger():
    log = setup_logging()
    assert log.name == "hikvision-face-terminal"


def test_install_signal_handlers_no_rompe():
    install_signal_handlers(LOG)  # registra SIGTERM/SIGINT sin error


def test_main_sale_1_si_falta_options(monkeypatch, tmp_path):
    monkeypatch.setattr(
        mod.Config, "from_options_json",
        classmethod(lambda cls, *a, **k: (_ for _ in ()).throw(FileNotFoundError())),
    )
    with pytest.raises(SystemExit) as ei:
        mod.main()
    assert ei.value.code == 1


def test_main_sale_1_si_falta_campo(monkeypatch):
    monkeypatch.setattr(
        mod.Config, "from_options_json",
        classmethod(lambda cls, *a, **k: (_ for _ in ()).throw(KeyError("terminal_host"))),
    )
    with pytest.raises(SystemExit) as ei:
        mod.main()
    assert ei.value.code == 1


def test_main_happy_llama_run(monkeypatch, tmp_path):
    cfg = cfg_for(tmp_path)
    monkeypatch.setattr(mod.Config, "from_options_json",
                        classmethod(lambda cls, *a, **k: cfg))
    called = {}
    monkeypatch.setattr(mod, "run", lambda c, l: called.setdefault("ok", (c, l)))
    mod.main()
    assert called["ok"][0] is cfg
