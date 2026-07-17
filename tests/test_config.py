"""Tests del Config: carga desde options.json, defaults, inmutabilidad."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from hikvision_face_terminal.listener import Config


def test_config_from_options_json_carga_campos_requeridos(tmp_path):
    opts = {
        "terminal_host": "192.168.18.202",
        "terminal_user": "admin",
        "terminal_password": "s3cr3t",
        "ha_webhook_url": "",
        "audit_log_path": "/config/face_audit.log",
        "edificio_slug": "torre-1",
        "puerta_slug": "peatonal-lateral",
        "reconnect_delay": 7,
        "stream_idle_timeout": 45,
        "backend_url": "https://backend.local/eventos/hikvision-face",
        "backend_secret": "token123",
        "backend_queue_maxsize": 500,
        "backend_timeout_seconds": 4,
    }
    p = tmp_path / "options.json"
    p.write_text(json.dumps(opts), encoding="utf-8")

    cfg = Config.from_options_json(str(p))

    assert cfg.terminal_host == "192.168.18.202"
    assert cfg.terminal_user == "admin"
    assert cfg.terminal_password == "s3cr3t"
    assert cfg.audit_log_path == Path("/config/face_audit.log")
    assert cfg.edificio_slug == "torre-1"
    assert cfg.puerta_slug == "peatonal-lateral"
    assert cfg.reconnect_delay == 7
    assert cfg.stream_idle_timeout == 45
    assert cfg.backend_url == "https://backend.local/eventos/hikvision-face"
    assert cfg.backend_secret == "token123"
    assert cfg.backend_queue_maxsize == 500
    assert cfg.backend_timeout_seconds == 4


def test_config_defaults_sensatos(tmp_path):
    """Con solo los campos obligatorios, los defaults son sensatos."""
    opts = {
        "terminal_host": "192.168.18.202",
        "terminal_user": "admin",
        "terminal_password": "x",
    }
    p = tmp_path / "options.json"
    p.write_text(json.dumps(opts), encoding="utf-8")

    cfg = Config.from_options_json(str(p))

    assert cfg.ha_webhook_url == ""
    assert cfg.audit_log_path == Path("/config/face_audit.log")
    assert cfg.edificio_slug == ""
    assert cfg.puerta_slug == "peatonal-principal"
    assert cfg.reconnect_delay == 5
    assert cfg.stream_idle_timeout == 30
    assert cfg.backend_url == ""
    assert cfg.backend_secret == ""
    assert cfg.backend_queue_maxsize == 1000
    assert cfg.backend_timeout_seconds == 3


def test_config_falta_campo_obligatorio_raisea_keyerror(tmp_path):
    opts = {"terminal_host": "192.168.18.202", "terminal_user": "admin"}
    p = tmp_path / "options.json"
    p.write_text(json.dumps(opts), encoding="utf-8")
    with pytest.raises(KeyError):
        Config.from_options_json(str(p))


def test_config_terminal_password_es_frozen_no_mutable():
    """El dataclass es frozen: no se puede mutar terminal_password."""
    cfg = Config(
        terminal_host="h",
        terminal_user="u",
        terminal_password="p",
        ha_webhook_url="",
        audit_log_path=Path("/tmp/a.log"),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.terminal_password = "otro"  # type: ignore[misc]
