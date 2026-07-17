"""Fixtures compartidas para la suite del hikvision-face-terminal-addon."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"

MIME_BOUNDARY = b"--MIME_boundary"


@pytest.fixture
def log() -> logging.Logger:
    return logging.getLogger("test-hikvision-face-terminal")


@pytest.fixture
def dsk1t344_f4_capture_bytes() -> bytes:
    """Captura empírica F4: 19 eventos (13 ACE live + 6 videoloss heartbeats)."""
    return (FIXTURES_DIR / "dsk1t344_f4_capture.raw").read_bytes()


@pytest.fixture
def dsk1t344_alertstream_first_bytes() -> bytes:
    """Buffer histórico F3.4: 41 eventos ACE, TODOS currentEvent=false."""
    return (FIXTURES_DIR / "dsk1t344_alertstream_first.raw").read_bytes()


@pytest.fixture
def mock_config():
    from hikvision_face_terminal.listener import Config

    return Config(
        terminal_host="192.168.18.202",
        terminal_user="admin",
        terminal_password="dummy",
        ha_webhook_url="",
        audit_log_path=Path("/tmp/test_face_audit.log"),
        edificio_slug="test-edificio",
        puerta_slug="peatonal-principal",
        backend_url="",
        backend_secret="",
    )


# ---------------------------------------------------------------------------
# Helpers de parsing del stream multipart para los tests de replay
# ---------------------------------------------------------------------------

def split_mime_blocks(raw: bytes):
    """Genera los bodies JSON de cada bloque MIME del stream crudo."""
    for part in raw.split(MIME_BOUNDARY):
        if b"\r\n\r\n" in part:
            _, _, body = part.partition(b"\r\n\r\n")
        elif b"\n\n" in part:
            _, _, body = part.partition(b"\n\n")
        else:
            continue
        body = body.strip()
        if body:
            yield body


def load_raw_events(raw: bytes):
    """Devuelve la lista de dicts JSON parseados de un stream crudo."""
    events = []
    for body in split_mime_blocks(raw):
        try:
            events.append(json.loads(body.decode("utf-8", "replace")))
        except json.JSONDecodeError:
            pass
    return events


class MockStream:
    """Emula requests.Response.iter_content() troceando el .raw en chunks.

    Permite el replay del stream capturado empíricamente sin hardware real.
    """

    def __init__(self, raw: bytes, chunk_size: int = 1024):
        self._raw = raw
        self._chunk_size = chunk_size

    def iter_content(self, chunk_size: int = 1024):
        size = chunk_size or self._chunk_size
        for i in range(0, len(self._raw), size):
            yield self._raw[i:i + size]
