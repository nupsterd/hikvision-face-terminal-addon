"""Tests del emit HTTP POST al webhook HA post-auth OK (§5.9.507 Chat 7 S10).

Ejercitan _maybe_emit_ha_webhook: discriminador (5,75)/(5,1) + employee_no,
skip dummy/vacío (backward compat §5.9.475), payload subset del record, y el
error handling defensivo (fail-silent, no re-raise).
"""

from __future__ import annotations

import logging

import pytest

from hikvision_face_terminal import listener as mod
from hikvision_face_terminal.listener import (
    DUMMY_HA_WEBHOOK_URL,
    EVENT_TYPES,
    _maybe_emit_ha_webhook,
)

LOG = logging.getLogger("test-ha-webhook")

HA_URL = "https://ha.local/api/webhook/inadivinable-secret-id"


def face_record(**overrides) -> dict:
    """Record de un gesto face auth OK (5,75) — shape de build_audit_record."""
    rec = {
        "kind": "access_controller_event",
        "major": 5,
        "sub": 75,
        "sub_name": "Face Auth Passed",
        "device_kind": "face_terminal",
        "employee_no": "9001",
        "card_no": None,
        "face_rect": {"x": 0.412, "y": 0.458, "width": 0.22, "height": 0.389},
        "verify_mode": "faceOrFpOrCardOrPw",
        "device_ip": "192.168.18.202",
        "device_mac": "a4:d5:c2:75:fd:64",
        "device_ts": "2026-07-18T18:05:59-05:00",
        "received_ts": "2026-07-18T18:06:02.096930-05:00",
        "raw": {"AccessControllerEvent": {"name": "DM"}},
    }
    rec.update(overrides)
    return rec


def card_record(**overrides) -> dict:
    """Record de un gesto card auth OK (5,1) — Card Auth Passed.

    `sub_name` se toma de EVENT_TYPES[(5,1)] canonical (§5.9.507), no fabricado
    ad-hoc: refleja exactamente lo que el parser real produce post v1.0.1-alpha.
    """
    return face_record(
        sub=1,
        sub_name=EVENT_TYPES[(5, 1)],
        card_no="2641394168",
        verify_mode="card",
        **overrides,
    )


class _Capture:
    """Captura los argumentos del requests.post monkeypatcheado."""

    def __init__(self):
        self.calls = []

    def __call__(self, url, json=None, timeout=None, **kwargs):
        self.calls.append(
            {"url": url, "json": json, "timeout": timeout, "kwargs": kwargs}
        )

        class R:
            status_code = 200
            text = ""

        return R()


# --- (a) emit exitoso con gesto face (5,75) ---

def test_emit_face_75_hace_post_con_payload_subset(monkeypatch):
    cap = _Capture()
    monkeypatch.setattr(mod.requests, "post", cap)

    _maybe_emit_ha_webhook(
        face_record(), HA_URL, 3,
        edificio_slug="conjunto-piloto", puerta_slug="peatonal-principal",
    )

    assert len(cap.calls) == 1
    call = cap.calls[0]
    assert call["url"] == HA_URL
    assert call["timeout"] == 3
    # Cero header auth custom: HA valida por webhook_id en la URL.
    assert "headers" not in call["kwargs"] or call["kwargs"]["headers"] is None
    payload = call["json"]
    assert payload["major"] == 5
    assert payload["sub"] == 75
    assert payload["sub_name"] == "Face Auth Passed"
    assert payload["device_kind"] == "face_terminal"
    assert payload["employee_no"] == "9001"
    assert payload["name"] == "DM"            # leído del raw.AccessControllerEvent
    assert payload["card_no"] is None
    assert payload["face_rect"] == {"x": 0.412, "y": 0.458, "width": 0.22, "height": 0.389}
    assert payload["verify_mode"] == "faceOrFpOrCardOrPw"
    assert payload["edificio_slug"] == "conjunto-piloto"
    assert payload["puerta_slug"] == "peatonal-principal"


# --- (b) emit exitoso con gesto card (5,1) ---

def test_emit_card_1_hace_post(monkeypatch):
    cap = _Capture()
    monkeypatch.setattr(mod.requests, "post", cap)

    _maybe_emit_ha_webhook(
        card_record(), HA_URL, 5,
        edificio_slug="conjunto-piloto", puerta_slug="peatonal-principal",
    )

    assert len(cap.calls) == 1
    payload = cap.calls[0]["json"]
    assert payload["sub"] == 1
    # sub_name canonical del parser real (§5.9.507), no fabricado ad-hoc.
    assert payload["sub_name"] == EVENT_TYPES[(5, 1)] == "Card Auth Passed"
    assert payload["card_no"] == "2641394168"
    assert cap.calls[0]["timeout"] == 5


# --- (c) skip cuando ha_webhook_url es la dummy legacy §5.9.475 ---

def test_skip_cuando_url_dummy(monkeypatch):
    cap = _Capture()
    monkeypatch.setattr(mod.requests, "post", cap)
    _maybe_emit_ha_webhook(face_record(), DUMMY_HA_WEBHOOK_URL, 3)
    assert cap.calls == []


# --- (d) skip cuando ha_webhook_url vacío ---

def test_skip_cuando_url_vacia(monkeypatch):
    cap = _Capture()
    monkeypatch.setattr(mod.requests, "post", cap)
    _maybe_emit_ha_webhook(face_record(), "", 3)
    _maybe_emit_ha_webhook(face_record(), "   ", 3)  # whitespace-only también
    assert cap.calls == []


# --- (e) skip evento non-auth (5,21) Door Unlocked (major 5 pero sub != 75/1) ---

def test_skip_evento_non_auth_5_21(monkeypatch):
    cap = _Capture()
    monkeypatch.setattr(mod.requests, "post", cap)
    rec = face_record(sub=21, sub_name="Door Unlocked (relé interno del terminal)")
    _maybe_emit_ha_webhook(rec, HA_URL, 3)
    assert cap.calls == []


# --- (f) skip cuando employee_no es NULL ---

def test_skip_cuando_employee_no_null(monkeypatch):
    cap = _Capture()
    monkeypatch.setattr(mod.requests, "post", cap)
    _maybe_emit_ha_webhook(face_record(employee_no=None), HA_URL, 3)
    assert cap.calls == []


# --- (g) error handling: timeout del webhook HA no re-raisea + warning ---

def test_timeout_no_reraise_y_loguea_warning(monkeypatch, caplog):
    def fake_post(url, json=None, timeout=None, **kwargs):
        raise mod.requests.exceptions.Timeout("read timed out")

    monkeypatch.setattr(mod.requests, "post", fake_post)

    with caplog.at_level(logging.WARNING, logger="hikvision-face-terminal"):
        # No debe propagar la excepción (fail-silent, sin rollback del fan-out).
        _maybe_emit_ha_webhook(face_record(), HA_URL, 3)

    assert any(
        "ha_webhook_emit_falla" in r.message for r in caplog.records
    )


# --- extra: skip evento kind != access_controller_event (defensivo) ---

def test_skip_kind_other(monkeypatch):
    cap = _Capture()
    monkeypatch.setattr(mod.requests, "post", cap)
    rec = face_record(kind="other")
    _maybe_emit_ha_webhook(rec, HA_URL, 3)
    assert cap.calls == []


# --- startup log: rama URL activa vs skip dummy/vacío ---

def _cfg_with_ha(url: str):
    from pathlib import Path
    return mod.Config(
        terminal_host="192.168.18.202",
        terminal_user="admin",
        terminal_password="x",
        ha_webhook_url=url,
        audit_log_path=Path("/tmp/test_face_audit.log"),
    )


def test_startup_log_url_activa(monkeypatch, caplog):
    monkeypatch.setattr(mod.Config, "from_options_json",
                        classmethod(lambda cls, *a, **k: _cfg_with_ha(HA_URL)))
    monkeypatch.setattr(mod, "run", lambda c, l: None)
    with caplog.at_level(logging.INFO, logger="hikvision-face-terminal"):
        mod.main()
    assert any("Config HA webhook: url=" in r.message for r in caplog.records)


def test_startup_log_skip_dummy(monkeypatch, caplog):
    monkeypatch.setattr(mod.Config, "from_options_json",
                        classmethod(lambda cls, *a, **k: _cfg_with_ha(DUMMY_HA_WEBHOOK_URL)))
    monkeypatch.setattr(mod, "run", lambda c, l: None)
    with caplog.at_level(logging.INFO, logger="hikvision-face-terminal"):
        mod.main()
    assert any("skip razon=dummy_url_o_vacio" in r.message for r in caplog.records)
