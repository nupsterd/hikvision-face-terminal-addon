"""Tests del BackendForwarder: header, retry logic, backoff, queue behavior."""

from __future__ import annotations

import logging
from dataclasses import replace
from pathlib import Path

import pytest

from hikvision_face_terminal import listener as mod
from hikvision_face_terminal.listener import BackendForwarder, Config

LOG = logging.getLogger("test-forwarder")


def base_cfg(**overrides) -> Config:
    cfg = Config(
        terminal_host="192.168.18.202",
        terminal_user="admin",
        terminal_password="x",
        ha_webhook_url="",
        audit_log_path=Path("/tmp/test_face_audit.log"),
        backend_url="https://backend.local/eventos/hikvision-face",
        backend_secret="tok",
    )
    return replace(cfg, **overrides)


class FakeResponse:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


def test_forwarder_deshabilitado_si_backend_url_vacio():
    """Con backend_url vacío, el forwarder es no-op (enabled=False)."""
    cfg = base_cfg(backend_url="")
    fwd = BackendForwarder(cfg, LOG)
    assert fwd.enabled is False
    # enqueue no debe romper aunque no haya cola
    fwd.enqueue({"kind": "x"})


def test_forwarder_envia_header_x_pv_hikvision_face_token(monkeypatch):
    """El POST lleva el header X-PV-Hikvision-Face-Token con el secret."""
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        return FakeResponse(200)

    monkeypatch.setattr(mod.requests, "post", fake_post)
    fwd = BackendForwarder(base_cfg(backend_secret="mytoken"), LOG)
    fwd._post_with_retries({"kind": "access_controller_event"})

    assert captured["headers"] == {"X-PV-Hikvision-Face-Token": "mytoken"}
    assert captured["url"] == "https://backend.local/eventos/hikvision-face"


def test_forwarder_sin_secret_no_manda_header(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["headers"] = headers
        return FakeResponse(200)

    monkeypatch.setattr(mod.requests, "post", fake_post)
    fwd = BackendForwarder(base_cfg(backend_secret=""), LOG)
    fwd._post_with_retries({"kind": "x"})
    assert captured["headers"] == {}


def test_forwarder_reintenta_3_veces_con_backoff_0_5_1_2s(monkeypatch):
    """Ante 5xx persistente: 3 intentos, backoff 0.5/1.0s (no duerme tras el 3º)."""
    calls = {"n": 0}
    sleeps = []

    def fake_post(url, json=None, headers=None, timeout=None):
        calls["n"] += 1
        return FakeResponse(503, "upstream down")

    monkeypatch.setattr(mod.requests, "post", fake_post)
    monkeypatch.setattr(mod.time, "sleep", lambda s: sleeps.append(s))

    fwd = BackendForwarder(base_cfg(), LOG)
    with pytest.raises(RuntimeError, match="agotó 3 intentos"):
        fwd._post_with_retries({"kind": "x"})

    assert calls["n"] == 3
    # backoff entre intentos: 0.5 y 1.0 (el 2.0 no se duerme porque es el último)
    assert sleeps == [0.5, 1.0]


def test_forwarder_no_reintenta_4xx(monkeypatch):
    """Un 4xx (401/400) no se reintenta: 1 solo POST, sin excepción."""
    calls = {"n": 0}

    def fake_post(url, json=None, headers=None, timeout=None):
        calls["n"] += 1
        return FakeResponse(401, "unauthorized")

    monkeypatch.setattr(mod.requests, "post", fake_post)
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)

    fwd = BackendForwarder(base_cfg(), LOG)
    fwd._post_with_retries({"kind": "x"})  # no raise
    assert calls["n"] == 1


def test_forwarder_reintenta_ante_request_exception(monkeypatch):
    """RequestException (red caída) SÍ se reintenta hasta agotar."""
    calls = {"n": 0}

    def fake_post(url, json=None, headers=None, timeout=None):
        calls["n"] += 1
        raise mod.requests.RequestException("connection refused")

    monkeypatch.setattr(mod.requests, "post", fake_post)
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)

    fwd = BackendForwarder(base_cfg(), LOG)
    with pytest.raises(RuntimeError, match="agotó 3 intentos"):
        fwd._post_with_retries({"kind": "x"})
    assert calls["n"] == 3


def test_forwarder_dropea_records_si_queue_lleno():
    """maxsize=2 + enqueue 3 sin drenar la cola -> 1 record descartado."""
    # No arrancamos el worker: la cola no se drena, así el 3º cae por Full.
    fwd = BackendForwarder(base_cfg(backend_queue_maxsize=2), LOG)
    assert fwd.enabled is True
    fwd.enqueue({"i": 1})
    fwd.enqueue({"i": 2})
    fwd.enqueue({"i": 3})  # cola llena -> drop
    assert fwd._dropped_count == 1
