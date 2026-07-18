"""Smoke test local: replay del stream capturado empíricamente vía MockStream.

Reemplaza el smoke E2E hardware (sub-chat 4d) por un replay determinístico del
`.raw` capturado contra el DS-K1T344 real, sin tocar el terminal 192.168.18.202.
"""

from __future__ import annotations

import logging

from hikvision_face_terminal.listener import (
    MIME_BOUNDARY,
    build_audit_record,
    parse_event_block,
)

from .conftest import MockStream

LOG = logging.getLogger("smoke")


def replay_stream(raw: bytes):
    """Reproduce la lógica de buffer/boundary de run() sobre un MockStream.

    Devuelve (parsed_events, skipped_none_count) recorriendo el stream por
    chunks igual que el loop productivo, pero acumulando en memoria.
    """
    stream = MockStream(raw, chunk_size=1024)
    parsed = []
    skipped = 0
    buffer = b""
    for chunk in stream.iter_content(chunk_size=1024):
        if not chunk:
            continue
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
            event = parse_event_block(body, LOG)
            if event is None:
                skipped += 1
            else:
                parsed.append(event)
    return parsed, skipped


def test_smoke_replay_dsk1t344_f4_capture(dsk1t344_f4_capture_bytes):
    """Replay de la captura F4 empírica: 13 ACE live + 6 videoloss skippeados.

    NOTA DIVERGENCIA §5.9.X (sub-chat 4c): el diseño D13 decía "6 eventos
    históricos skippeados", pero empíricamente los 6 skippeados de esta captura
    son heartbeats videoloss (return None), NO eventos históricos ACE
    (currentEvent=false). El filtro histórico se ejercita en el fixture
    dsk1t344_alertstream_first (ver test dedicado abajo).
    """
    parsed, skipped = replay_stream(dsk1t344_f4_capture_bytes)

    # 13 eventos ACE live pasan; 6 videoloss heartbeats se descartan (None).
    assert len(parsed) == 13
    assert skipped == 6
    assert all(e["kind"] == "access_controller_event" for e in parsed)
    # Todos live: currentEvent=true (ninguno histórico).
    assert all(e["raw"]["AccessControllerEvent"].get("currentEvent") is True
               for e in parsed)

    # Correlación de gestos empíricos: los 4 gestos + tamper alarm + restore.
    combos = [(e["major"], e["sub"]) for e in parsed]
    assert (5, 75) in combos   # Face Auth Passed
    assert (5, 38) in combos   # Fingerprint Auth Passed (§14.35 rectificado: el
                               # gesto (5,38) de F4 era fingerprint OK, no card;
                               # card es (5,1), no capturado en F4 §5.9.447/§5.9.507)
    assert (5, 39) in combos   # Auth Failed non-face
    assert (5, 76) in combos   # Face Auth Failed
    assert (1, 1029) in combos  # Tamper Alarm
    assert (1, 1028) in combos  # Tamper Restored

    # El (5,76) Face Auth Failed trae mask="no" (§5.9.444).
    face_fail = next(e for e in parsed if (e["major"], e["sub"]) == (5, 76))
    assert face_fail["mask"] == "no"
    assert face_fail["description"] == "Face Auth Failed"
    # El (5,38) del fixture F4 mapea a la description canónica v1.3 rectificada.
    fp_pass = next(e for e in parsed if (e["major"], e["sub"]) == (5, 38))
    assert fp_pass["description"] == "Fingerprint Auth Passed"

    # Descripciones legibles para todos (ninguno "Unknown").
    assert all(not e["description"].startswith("Unknown") for e in parsed)


def test_smoke_replay_build_audit_preserva_campos_ds_k1t344(dsk1t344_f4_capture_bytes):
    """Todo record del audit incluye device_kind + campos §5.9.444 preservados."""
    parsed, _ = replay_stream(dsk1t344_f4_capture_bytes)
    records = [build_audit_record(e) for e in parsed]
    assert len(records) == 13

    required_keys = {
        "device_kind", "card_type", "face_rect", "mask", "user_type",
        "front_serial_no", "label", "active_post_count", "pure_pwd_verify_enable",
    }
    for r in records:
        assert required_keys.issubset(r.keys())
        assert r["device_kind"] == "face_terminal"

    # El gesto face-passed (5,75) tiene employee_no y purePwdVerifyEnable nested.
    face_ok = next(r for r in records if (r["major"], r["sub"]) == (5, 75))
    assert face_ok["employee_no"] == "9001"
    assert face_ok["pure_pwd_verify_enable"] is True   # DIV: nested, no top-level
    assert face_ok["active_post_count"] == 1            # top-level


def test_smoke_replay_alertstream_first_skippea_todo_historico(
    dsk1t344_alertstream_first_bytes,
):
    """§5.9.443: el buffer histórico (41 ACE currentEvent=false) se skippea entero.

    Esto es lo que previene el connection storm al reconectar tras crash/restart.
    """
    parsed, skipped = replay_stream(dsk1t344_alertstream_first_bytes)
    assert len(parsed) == 0     # ningún evento histórico pasa el filtro
    assert skipped == 41        # los 41 se descartan (currentEvent is False)
