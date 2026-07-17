"""Tests unitarios del parser: 18 EVENT_TYPES canonical + casos especiales."""

from __future__ import annotations

import json

import pytest

from hikvision_face_terminal.listener import (
    EVENT_TYPES,
    build_audit_record,
    parse_event_block,
)


def make_ace_body(
    major: int,
    sub: int,
    *,
    current_event: bool = True,
    extra_ace: dict | None = None,
    extra_top: dict | None = None,
) -> bytes:
    """Construye el body JSON de un bloque AccessControllerEvent del DS-K1T344."""
    ace = {
        "deviceName": "Terminal Facial Torre 1",
        "majorEventType": major,
        "subEventType": sub,
        "serialNo": 201,
        "currentEvent": current_event,
    }
    if extra_ace:
        ace.update(extra_ace)
    event = {
        "ipAddress": "192.168.18.202",
        "portNo": 443,
        "protocol": "HTTPS",
        "macAddress": "a4:d5:c2:75:fd:64",
        "channelID": 1,
        "dateTime": "2026-07-16T19:24:29-05:00",
        "activePostCount": 1,
        "eventType": "AccessControllerEvent",
        "eventState": "active",
        "eventDescription": "Access Controller Event",
        "AccessControllerEvent": ace,
    }
    if extra_top:
        event.update(extra_top)
    return json.dumps(event).encode("utf-8")


# --- 18 tests: uno por cada EVENT_TYPE canonical v1.2 ---

@pytest.mark.parametrize(("major", "sub", "description"), sorted(
    (m, s, d) for (m, s), d in EVENT_TYPES.items()
))
def test_event_type_canonical_parsea_con_descripcion(major, sub, description, log):
    """Cada uno de los 18 (major, sub) canonical parsea con su descripción."""
    body = make_ace_body(major, sub)
    event = parse_event_block(body, log)
    assert event is not None
    assert event["kind"] == "access_controller_event"
    assert event["major"] == major
    assert event["sub"] == sub
    assert event["description"] == description


def test_hay_exactamente_18_event_types():
    """Consolidación §5.9.X: la tabla canonical v1.2 tiene 18 entradas."""
    assert len(EVENT_TYPES) == 18


# --- Casos especiales ---

def test_filter_current_event_false_skippea_evento_historico(log):
    """§5.9.443: evento histórico (currentEvent=false) se descarta -> None."""
    body = make_ace_body(5, 75, current_event=False)
    assert parse_event_block(body, log) is None


def test_current_event_missing_no_se_descarta(log):
    """`is False` (no `== False`): sin el campo, el evento NO se descarta."""
    event = {
        "eventType": "AccessControllerEvent",
        "dateTime": "2026-07-16T19:24:29-05:00",
        "AccessControllerEvent": {"majorEventType": 5, "subEventType": 75},
    }
    parsed = parse_event_block(json.dumps(event).encode("utf-8"), log)
    assert parsed is not None
    assert parsed["major"] == 5


def test_parse_event_extrae_campos_ds_k1t344_completos(log):
    """§5.9.444: todos los campos nuevos del DS-K1T344 se extraen correctamente.

    Incluye la DIVERGENCIA empírica: purePwdVerifyEnable vive DENTRO de
    AccessControllerEvent (nested), y activePostCount es top-level.
    """
    face_rect = {"height": 0.389, "width": 0.22, "x": 0.412, "y": 0.458}
    body = make_ace_body(
        5, 75,
        extra_ace={
            "cardType": "duress",
            "FaceRect": face_rect,
            "mask": "no",
            "userType": "normal",
            "frontSerialNo": 200,
            "label": "",
            "currentVerifyMode": "faceOrFpOrCardOrPw",
            "employeeNoString": "9001",
            "purePwdVerifyEnable": True,   # nested -> se extrae de ace
            "doorNo": 1,
        },
        extra_top={"activePostCount": 7},   # top-level -> se extrae de event
    )
    event = parse_event_block(body, log)
    assert event is not None
    assert event["card_type"] == "duress"
    assert event["face_rect"] == face_rect
    assert event["mask"] == "no"
    assert event["user_type"] == "normal"
    assert event["front_serial_no"] == 200
    assert event["label"] == ""
    assert event["verify_mode"] == "faceOrFpOrCardOrPw"
    assert event["employee_no"] == "9001"
    assert event["door_no"] == 1
    # DIVERGENCIA §5.9.X: purePwdVerifyEnable nested (no top-level como decía D9)
    assert event["pure_pwd_verify_enable"] is True
    # activePostCount SÍ top-level
    assert event["active_post_count"] == 7


def test_parse_event_desconocido_devuelve_description_generica(log):
    """(major, sub) fuera de la tabla -> descripción genérica 'Unknown (m,s)'."""
    body = make_ace_body(9, 999)
    event = parse_event_block(body, log)
    assert event is not None
    assert event["description"] == "Unknown (9,999)"


def test_videoloss_heartbeat_se_ignora(log):
    """Los heartbeats videoloss se descartan silenciosamente (-> None)."""
    body = json.dumps({
        "eventType": "videoloss",
        "eventState": "inactive",
        "dateTime": "2026-07-16T19:23:13-05:00",
    }).encode("utf-8")
    assert parse_event_block(body, log) is None


def test_evento_no_ace_devuelve_kind_other(log):
    """Un eventType desconocido no-ACE devuelve kind='other' crudo."""
    body = json.dumps({
        "eventType": "somethingElse",
        "dateTime": "2026-07-16T19:23:13-05:00",
    }).encode("utf-8")
    event = parse_event_block(body, log)
    assert event is not None
    assert event["kind"] == "other"
    assert event["event_type"] == "somethingElse"


def test_json_invalido_devuelve_none(log):
    """Un body con JSON corrupto no rompe: devuelve None con warning."""
    assert parse_event_block(b"{not json", log) is None


def test_body_vacio_devuelve_none(log):
    assert parse_event_block(b"   ", log) is None


def test_build_audit_record_incluye_device_kind_face_terminal(log):
    """El record del audit lleva device_kind='face_terminal' (branching backend)."""
    body = make_ace_body(5, 75, extra_ace={"mask": "no", "userType": "normal"})
    event = parse_event_block(body, log)
    record = build_audit_record(event)
    assert record["device_kind"] == "face_terminal"
    assert record["mask"] == "no"
    assert record["user_type"] == "normal"
    assert record["sub_name"] == "Face Auth Passed"
    assert record["serial"] == 201
