"""Recuperación de eventos por ISAPI AcsEvent (#54, B6.2).

Todo con mocks: ``requests.request`` (AcsEvent / deviceInfo), ``requests.get`` (stream) y
``requests.post`` (backend). ``tmp_path`` reemplaza /config. Datos inventados: los números de
empleado y nombres son sintéticos; la fixture F4 se usa solo para comparar formas.
"""

from __future__ import annotations

import copy
import json
import logging
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hikvision_face_terminal import listener as mod
from hikvision_face_terminal import recuperacion as rec
from hikvision_face_terminal.listener import (
    BackendForwarder,
    Config,
    build_audit_record,
    parse_event_block,
    record_desde_evento,
    run,
)
from hikvision_face_terminal.recuperacion import (
    EstadoPersistente,
    Recuperador,
    SeguimientoEntregas,
    normalizar_mac,
    reconstruir_evento,
)
from tests.conftest import FIXTURES_DIR, load_raw_events

LOG = logging.getLogger("test-recuperacion")
TZ = timezone(timedelta(hours=-5))
AHORA = datetime(2030, 3, 4, 11, 0, 0, tzinfo=TZ)
MAC = "a4:d5:c2:00:00:01"
HOST = "192.0.2.10"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeResp:
    def __init__(self, status: int = 200, data=None, content: bytes = b""):
        self.status_code = status
        self._data = data
        self.content = content

    def json(self):
        if self._data is None:
            raise ValueError("sin json")
        return self._data


def _rechazo(error_msg: str) -> dict:
    return {"statusCode": 6, "statusString": "Invalid Content", "subStatusCode": "badJsonContent",
            "errorCode": 1610612737, "errorMsg": error_msg}


class FakeISAPI:
    """Fake de requests.request para AcsEvent + deviceInfo. Registra cada llamada."""

    def __init__(self, *, paginas=None, mac=MAC, rechaza_major0=False, status_acs=200,
                 status_info=200, reciente=None, info_xml=False, error_400=None):
        self.paginas = list(paginas or [])  # lista de (estado, items)
        self.mac = mac
        self.rechaza_major0 = rechaza_major0
        self.status_acs = status_acs
        self.status_info = status_info
        self.reciente = reciente  # items para la consulta timeReverseOrder
        self.info_xml = info_xml  # deviceInfo como el DS-K1T344 real: XML aunque se pida JSON
        self.error_400 = error_400  # errorMsg de un 400 forzado en toda consulta AcsEvent
        self.llamadas: list[tuple[str, str, dict | None, dict]] = []

    def __call__(self, metodo, url, json=None, **kwargs):  # noqa: A002 (firma de requests)
        self.llamadas.append((metodo, url, copy.deepcopy(json), kwargs))
        if "deviceInfo" in url:
            if self.status_info != 200:
                return FakeResp(self.status_info)
            if self.info_xml:
                mac = "" if self.mac is None else f"<macAddress>{self.mac}</macAddress>"
                xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                       '<DeviceInfo version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema">'
                       f'<deviceName>Terminal</deviceName>{mac}<model>X</model></DeviceInfo>')
                return FakeResp(200, None, xml.encode("utf-8"))
            info = {} if self.mac is None else {"macAddress": self.mac}
            return FakeResp(200, {"DeviceInfo": info})
        cond = json["AcsEventCond"]
        if self.status_acs != 200:
            return FakeResp(self.status_acs)
        if self.error_400 is not None:
            return FakeResp(400, _rechazo(self.error_400))
        # Como el DS-K1T344 real (sondeo 2026-10-05): beginSerialNo exige endSerialNo.
        if "beginSerialNo" in cond and "endSerialNo" not in cond:
            return FakeResp(400, _rechazo("endSerialNo"))
        if self.rechaza_major0 and cond["major"] == 0:
            return FakeResp(400, _rechazo("major"))
        if cond.get("timeReverseOrder"):
            items = self.reciente or []
            return FakeResp(200, {"AcsEvent": {"responseStatusStrg": "OK" if items else "NO MATCH",
                                               "numOfMatches": len(items), "InfoList": items}})
        idx = cond["searchResultPosition"] // rec.MAX_RESULTS
        if idx >= len(self.paginas):
            return FakeResp(200, {"AcsEvent": {"responseStatusStrg": "NO MATCH", "numOfMatches": 0}})
        estado, items = self.paginas[idx]
        return FakeResp(200, {"AcsEvent": {"responseStatusStrg": estado,
                                           "numOfMatches": len(items), "InfoList": items}})

    def acs(self):
        return [c for c in self.llamadas if "AcsEvent" in c[1]]


def item(serial: int, *, minor: int = 75, time: str | None = None, emp: str = "5001") -> dict:
    return {
        "major": 5,
        "minor": minor,
        "time": time or (AHORA - timedelta(minutes=30) + timedelta(seconds=serial % 600)).isoformat(),
        "serialNo": serial,
        "employeeNoString": emp,
        "name": "PERSONA PRUEBA",
        "attendanceStatus": "checkIn",
        "currentVerifyMode": "faceOrFpOrCardOrPw",
        "mask": "no",
        "userType": "normal",
        "label": "",
        "doorNo": 1,
        "cardReaderNo": 1,
    }


def seguimiento(tmp_path: Path, *, cursor=None, mac=MAC) -> SeguimientoEntregas:
    path = tmp_path / "face_state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if cursor is not None or mac is not None:
        path.write_text(json.dumps({"cursor_serial": cursor, "terminal_mac": mac, "updated_at": "x"}))
    return SeguimientoEntregas(EstadoPersistente(path, LOG), LOG)


def recuperador(seg: SeguimientoEntregas, destino) -> Recuperador:
    return Recuperador(
        terminal_host=HOST,
        terminal_user="admin",
        terminal_password="x",
        seguimiento=seg,
        construir_record=lambda ev: record_desde_evento(ev, LOG),
        destino=destino,
        log=LOG,
        ahora=lambda: AHORA,
    )


@pytest.fixture
def isapi(monkeypatch):
    def _instalar(**kwargs) -> FakeISAPI:
        fake = FakeISAPI(**kwargs)
        monkeypatch.setattr(rec.requests, "request", fake)
        return fake
    return _instalar


def leer_estado(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "face_state.json").read_text())


# ---------------------------------------------------------------------------
# (a) estado persistente
# ---------------------------------------------------------------------------

def test_estado_escritura_atomica_y_relectura(tmp_path):
    path = tmp_path / "sub" / "face_state.json"
    est = EstadoPersistente(path, LOG)
    assert est.guardar(cursor_serial=42, terminal_mac=MAC) is True
    datos = json.loads(path.read_text())
    assert (datos["cursor_serial"], datos["terminal_mac"]) == (42, MAC)
    assert datos["updated_at"]
    assert [p.name for p in path.parent.iterdir()] == ["face_state.json"]  # sin temporales
    otra = EstadoPersistente(path, LOG)
    assert (otra.cursor_serial, otra.terminal_mac) == (42, MAC)


def test_estado_fallo_al_escribir_no_toca_el_anterior(tmp_path, monkeypatch, caplog):
    path = tmp_path / "face_state.json"
    est = EstadoPersistente(path, LOG)
    est.guardar(cursor_serial=10, terminal_mac=MAC)

    def falla(_fd):
        raise OSError("disco lleno")

    monkeypatch.setattr(rec.os, "fsync", falla)
    with caplog.at_level(logging.WARNING):
        assert est.guardar(cursor_serial=11, terminal_mac=MAC) is False
    assert json.loads(path.read_text())["cursor_serial"] == 10
    assert [p.name for p in tmp_path.iterdir()] == ["face_state.json"]
    assert "No se pudo guardar" in caplog.text


@pytest.mark.parametrize("contenido", ["{no es json", "[1, 2]", '{"cursor_serial": "x"}', ""])
def test_estado_corrupto_es_vacio_con_warning(tmp_path, caplog, contenido):
    path = tmp_path / "face_state.json"
    path.write_text(contenido)
    with caplog.at_level(logging.WARNING):
        est = EstadoPersistente(path, LOG)
    assert est.cursor_serial is None
    assert caplog.records and caplog.records[0].levelno == logging.WARNING


def test_estado_ausente_es_vacio_con_warning(tmp_path, caplog):
    with caplog.at_level(logging.WARNING):
        est = EstadoPersistente(tmp_path / "face_state.json", LOG)
    assert (est.cursor_serial, est.terminal_mac) == (None, None)
    assert "ausente" in caplog.text


# ---------------------------------------------------------------------------
# (b) cursor
# ---------------------------------------------------------------------------

def test_cursor_avanza_con_2xx_y_se_frena_en_el_fallido(tmp_path):
    seg = seguimiento(tmp_path, cursor=100)
    recs = {s: {"serial": s} for s in (101, 102, 103)}
    assert all(seg.admitir(r) for r in recs.values())
    assert seg.cursor == 100  # pendientes: nada confirmado todavía
    seg.entregado(recs[101])
    assert seg.cursor == 101
    seg.entregado(recs[103])
    assert seg.cursor == 101  # 102 sigue pendiente por debajo
    seg.fallido(recs[102])
    assert seg.cursor == 101  # min(fallido) - 1
    assert leer_estado(tmp_path)["cursor_serial"] == 101
    assert seg.admitir(recs[102]) is True  # el fallido salió de la puerta
    seg.entregado(recs[102])
    assert seg.cursor == 103
    assert leer_estado(tmp_path)["cursor_serial"] == 103


def test_records_sin_serial_no_mueven_el_cursor(tmp_path):
    seg = seguimiento(tmp_path, cursor=100)
    otro = {"kind": "other", "serial": None}
    assert seg.admitir(otro) is True
    assert seg.admitir(otro) is True  # sin serial no hay puerta
    seg.entregado(otro)
    seg.fallido(otro)
    assert seg.cursor == 100


def _esperar(fwd: BackendForwarder) -> None:
    assert fwd._queue is not None
    fwd._queue.join()


def test_forwarder_informa_entregado_fallido_y_cola_llena(tmp_path, monkeypatch):
    seg = seguimiento(tmp_path, cursor=100)
    cfg = Config(terminal_host=HOST, terminal_user="a", terminal_password="x", ha_webhook_url="",
                 audit_log_path=tmp_path / "a.log", backend_url="https://b/x", backend_secret="s")
    fwd = BackendForwarder(cfg, LOG)
    fwd.seguimiento = seg
    respuestas = {101: 200, 102: 400, 103: 503}

    def fake_post(url, json, headers, timeout):  # noqa: A002
        return FakeResp(respuestas[json["serial"]])

    monkeypatch.setattr(mod.requests, "post", fake_post)
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)
    fwd.start()
    for s in (101, 102, 103):
        r = {"serial": s}
        assert seg.admitir(r)
        fwd.enqueue(r)
    _esperar(fwd)
    assert seg.cursor == 101  # 102 (4xx) y 103 (3 intentos 5xx) no confirmados

    # Cola llena ⇒ fallido (no se pierde: el cursor no lo pasa).
    lleno = BackendForwarder(replace(cfg, backend_queue_maxsize=1), LOG)
    seg2 = seguimiento(tmp_path / "otro", cursor=200)
    lleno.seguimiento = seg2
    for s in (201, 202):
        r = {"serial": s}
        seg2.admitir(r)
        lleno.enqueue(r)  # sin start(): la segunda no entra
    assert lleno._dropped_count == 1
    assert seg2.admitir({"serial": 202}) is True  # salió de la puerta


# ---------------------------------------------------------------------------
# (c) paginación y orden
# ---------------------------------------------------------------------------

def test_paginacion_more_y_reorden_por_serial(tmp_path, isapi):
    # AcsEvent ordena por hora: en la misma página el serial mayor puede venir antes.
    pag1 = [item(s) for s in (101, 103, 102)] + [item(s) for s in range(104, 131)]
    pag2 = [item(s) for s in (132, 131)] + [item(s) for s in range(133, 161)]
    pag3 = [item(s) for s in (165, 161, 162, 163, 164)]
    fake = isapi(paginas=[("MORE", pag1), ("MORE", pag2), ("OK", pag3)])
    seg = seguimiento(tmp_path, cursor=100)
    enviados: list[dict] = []
    resumen = recuperador(seg, enviados.append).correr()
    conds = [c[2]["AcsEventCond"] for c in fake.acs()]
    assert [c["searchResultPosition"] for c in conds] == [0, 30, 60]
    assert {c["beginSerialNo"] for c in conds} == {101}
    assert all(c["endSerialNo"] == rec.SERIAL_FIN for c in conds)  # el DS-K1T344 lo exige
    assert len({c["searchID"] for c in conds}) == 1
    assert all(c["maxResults"] == 30 for c in conds)
    assert [r["serial"] for r in enviados] == list(range(101, 166))
    assert all(r["recuperado"] is True for r in enviados)
    assert (resumen["paginas"], resumen["encolados"], resumen["ya_vistos"]) == (3, 65, 0)
    _, _, _, kwargs = fake.acs()[0]
    assert kwargs["headers"] == {"Connection": "close"} and kwargs["verify"] is False


# ---------------------------------------------------------------------------
# (d) puerta por serial: un solo POST en los dos órdenes
# ---------------------------------------------------------------------------

def test_puerta_stream_primero_luego_recuperacion(tmp_path, isapi):
    isapi(paginas=[("OK", [item(101), item(102)])])
    seg = seguimiento(tmp_path, cursor=100)
    assert seg.admitir({"serial": 101})  # llegó por el stream
    enviados: list[dict] = []
    resumen = recuperador(seg, enviados.append).correr()
    assert [r["serial"] for r in enviados] == [102]
    assert resumen["ya_vistos"] == 1


def test_puerta_recuperacion_primero_luego_stream(tmp_path, isapi):
    isapi(paginas=[("OK", [item(101)])])
    seg = seguimiento(tmp_path, cursor=100)
    enviados: list[dict] = []
    recuperador(seg, enviados.append).correr()
    assert [r["serial"] for r in enviados] == [101]
    assert seg.admitir({"serial": 101, "device_mac": MAC}) is False  # el stream no lo repite


class FakeStream:
    def __init__(self, chunks):
        self._chunks = chunks
        self.status_code = 200

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size=1024):
        yield from self._chunks


class _Stop(Exception):
    pass


def _f4_ace() -> list[dict]:
    raw = (FIXTURES_DIR / "dsk1t344_f4_capture.raw").read_bytes()
    return [e for e in load_raw_events(raw) if e.get("eventType") == "AccessControllerEvent"]


def _como_stream(eventos: list[dict]) -> list[bytes]:
    partes = b""
    for ev in eventos:
        body = json.dumps(ev).encode()
        partes += b"--MIME_boundary\r\nContent-Type: application/json\r\n\r\n" + body + b"\r\n"
    partes += b"--MIME_boundary\r\n"
    return [partes]


def _item_desde_vivo(ev: dict) -> dict:
    """Ítem de AcsEvent equivalente a un evento del stream (sin los campos que AcsEvent no
    trae: currentEvent, frontSerialNo, purePwdVerifyEnable, activePostCount, ip/mac)."""
    ace = ev["AccessControllerEvent"]
    it = {"major": ace["majorEventType"], "minor": ace["subEventType"], "time": ev["dateTime"]}
    for campo in ("serialNo", "employeeNoString", "name", "attendanceStatus", "currentVerifyMode",
                  "cardType", "FaceRect", "mask", "userType", "label", "doorNo", "cardReaderNo"):
        if campo in ace:
            it[campo] = ace[campo]
    return it


@pytest.mark.parametrize("orden", ["recuperacion_primero", "stream_primero"])
def test_run_un_solo_post_por_serial_y_sin_ha_para_recuperados(tmp_path, monkeypatch, orden):
    """(d)+(f) con run() real: dos conexiones; la recuperación devuelve los MISMOS seriales del
    stream. Cada serial llega al backend UNA vez y ningún recuperado toca HA."""
    eventos = _f4_ace()[:4]  # seriales 201-204
    host = eventos[0]["ipAddress"]
    mac = eventos[0]["macAddress"]
    (tmp_path / "face_state.json").write_text(json.dumps({"cursor_serial": 200, "terminal_mac": mac}))
    cfg = Config(terminal_host=host, terminal_user="admin", terminal_password="x",
                 ha_webhook_url="https://ha.local/api/webhook/x", audit_log_path=tmp_path / "a.log",
                 backend_url="https://backend/x", backend_secret="s", reconnect_delay=1,
                 state_path=tmp_path / "face_state.json")

    # La fixture F4 es de julio: sin esto el tope de 7 días (contra el reloj real) la descarta.
    monkeypatch.setattr(rec, "TOPE_ANTIGUEDAD", timedelta(days=36500))
    acs = FakeISAPI(paginas=[("OK", [_item_desde_vivo(e) for e in eventos])], mac=mac)
    monkeypatch.setattr(rec.requests, "request", acs)

    conexiones = {"n": 0}

    def fake_get(url, **kwargs):
        conexiones["n"] += 1
        primera = conexiones["n"] == 1
        # El stream trae los eventos en la conexión que corresponde al orden pedido.
        con_eventos = primera if orden == "stream_primero" else not primera
        return FakeStream(_como_stream(eventos) if con_eventos else [])

    monkeypatch.setattr(mod.requests, "get", fake_get)

    corrida = {"n": 0}
    def lanzar_sincronico(self):
        # Determinismo: la recuperación corre en la PRIMERA conexión si va primero, en la
        # SEGUNDA si va después del stream.
        corrida["n"] += 1
        if (orden == "recuperacion_primero") == (corrida["n"] == 1):
            self.correr()
        return True

    monkeypatch.setattr(Recuperador, "lanzar", lanzar_sincronico)

    posts: list[dict] = []
    lock = threading.Lock()

    def fake_post(url, json, headers=None, timeout=None, **kw):  # noqa: A002
        with lock:
            posts.append(json)
        return FakeResp(200)

    monkeypatch.setattr(mod.requests, "post", fake_post)
    ha_emit: list[dict] = []
    monkeypatch.setattr(mod, "_maybe_emit_ha_webhook", lambda record, *a, **k: ha_emit.append(record))
    fwd_ha: list[dict] = []
    monkeypatch.setattr(mod, "forward_to_ha", lambda url, ev, log: fwd_ha.append(ev))

    sleeps = {"n": 0}

    def fake_sleep(_s):
        sleeps["n"] += 1
        if sleeps["n"] >= 2:
            raise _Stop()

    monkeypatch.setattr(mod.time, "sleep", fake_sleep)
    with pytest.raises(_Stop):
        run(cfg, LOG)

    # Esperar a que el forwarder drene (hilo daemon).
    for _ in range(200):
        with lock:
            if len(posts) >= 4:
                break
        threading.Event().wait(0.01)
    threading.Event().wait(0.05)
    seriales = sorted(p["serial"] for p in posts)
    assert seriales == [201, 202, 203, 204]
    recuperados = [p for p in posts if p.get("recuperado") is True]
    assert len(recuperados) == (4 if orden == "recuperacion_primero" else 0)
    # (f) ningún recuperado pasa por HA; los en vivo sí (comportamiento previo).
    assert not any(r.get("recuperado") for r in ha_emit)
    assert fwd_ha == []
    if orden == "stream_primero":
        assert len(ha_emit) == 4


# ---------------------------------------------------------------------------
# (e) record recuperado == record en vivo
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("con_asistencia", [False, True])
def test_record_recuperado_igual_al_en_vivo(tmp_path, isapi, con_asistencia):
    vivo_ev = copy.deepcopy(_f4_ace()[0])  # (5,75) serial 201
    if con_asistencia:
        vivo_ev["AccessControllerEvent"]["attendanceStatus"] = "checkIn"
    vivo = build_audit_record(parse_event_block(json.dumps(vivo_ev).encode(), LOG))

    isapi(paginas=[("OK", [_item_desde_vivo(vivo_ev)])], mac=vivo_ev["macAddress"])
    seg = seguimiento(tmp_path, cursor=200, mac=vivo_ev["macAddress"])
    enviados: list[dict] = []
    r = Recuperador(terminal_host=vivo_ev["ipAddress"], terminal_user="a", terminal_password="x",
                    seguimiento=seg, construir_record=lambda ev: record_desde_evento(ev, LOG),
                    destino=enviados.append, log=LOG, ahora=lambda: datetime(2026, 7, 17, tzinfo=TZ))
    r.correr()
    (recuperado,) = enviados

    for campo in ("device_ts", "device_mac", "device_ip", "major", "sub", "employee_no", "serial",
                  "device_kind", "kind", "sub_name", "verify_mode", "mask", "user_type", "label",
                  "face_rect"):
        assert recuperado[campo] == vivo[campo], campo
    for campo in ("attendanceStatus", "name", "serialNo", "employeeNoString"):
        assert (recuperado["raw"]["AccessControllerEvent"].get(campo)
                == vivo["raw"]["AccessControllerEvent"].get(campo)), campo
    assert isinstance(recuperado["major"], int) and isinstance(recuperado["sub"], int)
    assert recuperado["recuperado"] is True and "recuperado" not in vivo
    # received_ts: ambos son el "ahora" de su construcción (no se compara).


def test_reconstruccion_copia_time_tal_cual_y_normaliza_mac():
    it = item(7, time="2026-10-04T18:18:42-05:00")
    ev = reconstruir_evento(it, HOST, MAC)
    assert ev["dateTime"] == "2026-10-04T18:18:42-05:00"
    assert ev["eventType"] == "AccessControllerEvent"
    assert ev["AccessControllerEvent"]["majorEventType"] == 5
    assert ev["AccessControllerEvent"]["subEventType"] == 75
    assert "cardReaderNo" not in ev["AccessControllerEvent"]
    assert normalizar_mac("A4-D5-C2-00-00-01") == MAC
    assert normalizar_mac("A4D5C2000001") == MAC
    assert normalizar_mac("no-mac") is None


# ---------------------------------------------------------------------------
# (g) primer arranque sin estado
# ---------------------------------------------------------------------------

def test_sin_estado_inicializa_cursor_desde_el_terminal_sin_recuperar(tmp_path, isapi):
    fake = isapi(reciente=[item(5432)])
    seg = SeguimientoEntregas(EstadoPersistente(tmp_path / "face_state.json", LOG), LOG)
    enviados: list[dict] = []
    resumen = recuperador(seg, enviados.append).correr()
    (llamada,) = fake.acs()
    cond = llamada[2]["AcsEventCond"]
    assert cond["timeReverseOrder"] is True and cond["maxResults"] == 1
    assert cond["startTime"] == (AHORA - timedelta(days=7)).isoformat(timespec="seconds")
    assert cond["endTime"] == (AHORA + timedelta(days=1)).isoformat(timespec="seconds")
    assert enviados == [] and resumen["encolados"] == 0
    assert seg.cursor == 5432
    assert leer_estado(tmp_path)["cursor_serial"] == 5432
    # La conexión siguiente ya recupera desde ahí.
    fake.paginas = [("OK", [item(5433)])]
    recuperador(seg, enviados.append).correr()
    assert fake.acs()[-1][2]["AcsEventCond"]["beginSerialNo"] == 5433
    assert [r["serial"] for r in enviados] == [5433]


@pytest.mark.parametrize("caso", ["sin_eventos", "falla"])
def test_sin_estado_y_sin_respuesta_util_espera_al_primer_entregado(tmp_path, isapi, caplog, caso):
    isapi(reciente=[]) if caso == "sin_eventos" else isapi(status_acs=500)
    seg = SeguimientoEntregas(EstadoPersistente(tmp_path / "face_state.json", LOG), LOG)
    with caplog.at_level(logging.WARNING):
        recuperador(seg, lambda r: None).correr()
    assert seg.cursor is None
    assert "primer record entregado" in caplog.text
    r = {"serial": 77}
    seg.admitir(r)
    seg.entregado(r)
    assert seg.cursor == 77


def test_inicializacion_no_pisa_un_cursor_fijado_en_vivo(tmp_path, isapi):
    isapi(reciente=[item(5432)])
    seg = SeguimientoEntregas(EstadoPersistente(tmp_path / "face_state.json", LOG), LOG)
    r = {"serial": 9000}
    seg.admitir(r)
    seg.entregado(r)
    recuperador(seg, lambda r: None).correr()  # ya hay cursor ⇒ recupera desde 9001
    assert seg.cursor == 9000


# ---------------------------------------------------------------------------
# (h) reset de fábrica
# ---------------------------------------------------------------------------

def test_reset_de_fabrica_reinicia_el_cursor(tmp_path, caplog):
    seg = seguimiento(tmp_path, cursor=5000)
    seg.admitir({"serial": 4999})  # basura de la numeración vieja en la puerta
    with caplog.at_level(logging.WARNING):
        seg.observar_vivo({"serial": 12, "device_mac": MAC})
    assert seg.cursor == 12
    assert "reset de fábrica" in caplog.text
    assert leer_estado(tmp_path)["cursor_serial"] == 12
    assert seg.admitir({"serial": 4999}) is True  # puerta limpia
    # Un serial normal (dentro del umbral) no reinicia nada.
    seg2 = seguimiento(tmp_path / "b", cursor=5000)
    seg2.observar_vivo({"serial": 4500, "device_mac": MAC})
    assert seg2.cursor == 5000


# ---------------------------------------------------------------------------
# (i) tope por corrida
# ---------------------------------------------------------------------------

def test_tope_1000_eventos_y_7_dias(tmp_path, isapi, caplog):
    viejos = [item(s, time=(AHORA - timedelta(days=8)).isoformat()) for s in range(1, 4)]
    nuevos = [item(s) for s in range(4, 1009)]  # 1005 recientes
    isapi(paginas=[("OK", viejos + nuevos)])
    seg = seguimiento(tmp_path, cursor=0)
    # Un viejo había fallado antes: frenaba el cursor; el tope lo abandona.
    seg.admitir({"serial": 2})
    seg.fallido({"serial": 2})
    enviados: list[dict] = []
    with caplog.at_level(logging.WARNING):
        resumen = recuperador(seg, enviados.append).correr()
    assert resumen["encolados"] == 1000
    assert resumen["descartados"] == 3 + 5
    assert [r["serial"] for r in enviados][:2] == [4, 5]
    assert enviados[-1]["serial"] == 1003
    assert "tope" in caplog.text and "3 con más de 7 días" in caplog.text
    for r in enviados:
        seg.entregado(r)
    assert seg.cursor == 1003  # avanza por lo entregado; los sobrantes quedan para la próxima


# ---------------------------------------------------------------------------
# (j) 401
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("donde", ["acs", "device_info"])
def test_401_sin_reintento_en_la_conexion(tmp_path, isapi, caplog, donde):
    if donde == "acs":
        fake = isapi(status_acs=401)
        seg = seguimiento(tmp_path, cursor=100)
    else:
        fake = isapi(status_info=401)
        seg = seguimiento(tmp_path, cursor=100, mac=None)
    with caplog.at_level(logging.ERROR):
        resumen = recuperador(seg, lambda r: None).correr()
    assert len(fake.llamadas) == 1  # ni reintento ni fallback de major
    assert resumen["encolados"] == 0
    assert "401" in caplog.text


def test_fallo_de_la_recuperacion_no_corta_el_stream(tmp_path, monkeypatch):
    """La recuperación corre en su hilo: un 401 ahí no toca el loop del stream."""
    (tmp_path / "face_state.json").write_text(json.dumps({"cursor_serial": 200, "terminal_mac": MAC}))
    cfg = Config(terminal_host=HOST, terminal_user="a", terminal_password="x", ha_webhook_url="",
                 audit_log_path=tmp_path / "a.log", backend_url="https://b/x", backend_secret="s",
                 state_path=tmp_path / "face_state.json")
    fake = FakeISAPI(status_acs=401)
    monkeypatch.setattr(rec.requests, "request", fake)
    eventos = _f4_ace()[:2]
    monkeypatch.setattr(mod.requests, "get", lambda url, **k: FakeStream(_como_stream(eventos)))
    monkeypatch.setattr(mod.requests, "post", lambda *a, **k: FakeResp(200))
    hilos: list[threading.Thread] = []
    lanzar_real = Recuperador.lanzar

    def lanzar_y_guardar(self):
        ok = lanzar_real(self)
        hilos.append(self._hilo)
        return ok

    monkeypatch.setattr(Recuperador, "lanzar", lanzar_y_guardar)
    monkeypatch.setattr(mod.time, "sleep", lambda _s: (_ for _ in ()).throw(_Stop()))
    with pytest.raises(_Stop):
        run(cfg, LOG)
    for h in hilos:
        h.join(timeout=5)
    lineas = (tmp_path / "a.log").read_text().splitlines()
    assert len(lineas) == 2  # el stream auditó sus dos eventos
    assert len(fake.acs()) == 1


# ---------------------------------------------------------------------------
# (k) sin MAC
# ---------------------------------------------------------------------------

def test_sin_mac_no_recupera(tmp_path, isapi, caplog):
    fake = isapi(mac=None, paginas=[("OK", [item(101)])])
    seg = seguimiento(tmp_path, cursor=100, mac=None)
    with caplog.at_level(logging.WARNING):
        resumen = recuperador(seg, lambda r: None).correr()
    assert fake.acs() == []
    assert resumen["encolados"] == 0
    assert "Sin MAC" in caplog.text


def test_mac_desde_device_info_normalizada_y_persistida(tmp_path, isapi):
    isapi(mac="A4-D5-C2-00-00-01", paginas=[("OK", [item(101)])])
    seg = seguimiento(tmp_path, cursor=100, mac=None)
    enviados: list[dict] = []
    recuperador(seg, enviados.append).correr()
    assert enviados[0]["device_mac"] == MAC
    assert leer_estado(tmp_path)["terminal_mac"] == MAC


# ---------------------------------------------------------------------------
# (l) major=0 rechazado
# ---------------------------------------------------------------------------

def test_major0_rechazado_cae_a_major5_y_lo_recuerda(tmp_path, isapi, caplog):
    fake = isapi(rechaza_major0=True, paginas=[("OK", [item(101)])])
    seg = seguimiento(tmp_path, cursor=100)
    r = recuperador(seg, lambda rec_: None)
    with caplog.at_level(logging.WARNING):
        resumen = r.correr()
    majors = [c[2]["AcsEventCond"]["major"] for c in fake.acs()]
    assert majors == [0, 5]
    assert resumen["encolados"] == 1
    assert caplog.text.count("rechazó major=0") == 1
    r.correr()  # segunda corrida: directo con major=5, sin volver a probar 0
    assert [c[2]["AcsEventCond"]["major"] for c in fake.acs()] == [0, 5, 5]


def test_major0_aceptado_se_usa(tmp_path, isapi):
    fake = isapi(paginas=[("OK", [item(101)])])
    seg = seguimiento(tmp_path, cursor=100)
    recuperador(seg, lambda r: None).correr()
    assert [c[2]["AcsEventCond"]["major"] for c in fake.acs()] == [0]
    assert fake.acs()[0][2]["AcsEventCond"]["minor"] == 0


# ---------------------------------------------------------------------------
# Logs sin datos personales
# ---------------------------------------------------------------------------

def test_logs_de_recuperacion_sin_employee_no_ni_nombre(tmp_path, isapi, caplog):
    isapi(paginas=[("OK", [item(101, emp="5099")])])
    seg = seguimiento(tmp_path, cursor=100)
    with caplog.at_level(logging.DEBUG, logger=LOG.name):
        recuperador(seg, lambda r: None).correr()
    assert "5099" not in caplog.text
    assert "PERSONA PRUEBA" not in caplog.text
    assert "desde serial 101, 1 encolados" in caplog.text


# ---------------------------------------------------------------------------
# (m) deviceInfo XML (prueba en hardware 5-oct: el terminal ignora ?format=json)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("info_xml", [True, False], ids=["xml", "json"])
def test_mac_desde_device_info_xml_o_json(tmp_path, isapi, info_xml):
    fake = isapi(mac="A4:D5:C2:00:00:01", info_xml=info_xml, paginas=[("OK", [item(101)])])
    seg = seguimiento(tmp_path, cursor=100, mac=None)
    enviados: list[dict] = []
    recuperador(seg, enviados.append).correr()
    url_info = [c[1] for c in fake.llamadas if "deviceInfo" in c[1]]
    assert url_info == [f"https://{HOST}/ISAPI/System/deviceInfo"]
    assert enviados[0]["device_mac"] == MAC
    assert leer_estado(tmp_path)["terminal_mac"] == MAC


def test_device_info_xml_sin_mac_no_recupera(tmp_path, isapi, caplog):
    fake = isapi(mac=None, info_xml=True, paginas=[("OK", [item(101)])])
    seg = seguimiento(tmp_path, cursor=100, mac=None)
    with caplog.at_level(logging.WARNING):
        recuperador(seg, lambda r: None).correr()
    assert fake.acs() == []
    assert "Sin MAC del terminal (deviceInfo HTTP 200)" in caplog.text


# ---------------------------------------------------------------------------
# (n)-(q) techo por conexión: una recuperación incompleta congela el cursor
# ---------------------------------------------------------------------------

def _entregar_en_vivo(seg: SeguimientoEntregas, seriales) -> None:
    for s in seriales:
        r = {"serial": s}
        assert seg.admitir(r)
        seg.entregado(r)


def _desde(fake: FakeISAPI) -> list[int]:
    return [c[2]["AcsEventCond"]["beginSerialNo"] for c in fake.acs()
            if c[2]["AcsEventCond"]["searchResultPosition"] == 0]


def test_sin_mac_el_cursor_no_pasa_el_techo_y_la_corrida_siguiente_libera(tmp_path, isapi):
    fake = isapi(mac=None, info_xml=True)
    seg = seguimiento(tmp_path, cursor=100, mac=None)
    recuperador(seg, lambda r: None).correr()
    assert seg.techo == 100
    _entregar_en_vivo(seg, [105, 106, 107])  # 101..104 nunca vistos
    assert seg.cursor == 100
    assert leer_estado(tmp_path)["cursor_serial"] == 100

    fake.mac = MAC
    fake.paginas = [("OK", [item(s) for s in range(101, 108)])]
    enviados: list[dict] = []
    resumen = recuperador(seg, enviados.append).correr()
    assert _desde(fake) == [101]
    assert [r["serial"] for r in enviados] == [101, 102, 103, 104]
    assert resumen["ya_vistos"] == 3
    assert seg.techo is None
    assert seg.cursor == 100  # liberado, pero los admitidos frenan hasta entregarse
    for r in enviados:
        seg.entregado(r)
    assert seg.cursor == 107
    assert leer_estado(tmp_path)["cursor_serial"] == 107


def test_sin_mac_con_reinicio_retoma_desde_el_cursor_congelado(tmp_path, isapi):
    fake = isapi(mac=None, info_xml=True)
    seg = seguimiento(tmp_path, cursor=100, mac=None)
    recuperador(seg, lambda r: None).correr()
    _entregar_en_vivo(seg, [105, 106])

    reiniciado = SeguimientoEntregas(EstadoPersistente(tmp_path / "face_state.json", LOG), LOG)
    assert reiniciado.cursor == 100 and reiniciado.techo is None
    fake.mac = MAC
    fake.paginas = [("OK", [item(s) for s in range(101, 107)])]
    enviados: list[dict] = []
    recuperador(reiniciado, enviados.append).correr()
    assert _desde(fake) == [101]
    # Lo entregado en vivo antes del reinicio se re-envía: el backend lo absorbe como duplicado.
    assert [r["serial"] for r in enviados] == [101, 102, 103, 104, 105, 106]


@pytest.mark.parametrize("status", [401, 500], ids=["401", "respuesta_invalida"])
def test_abortada_el_cursor_no_pasa_el_techo_y_la_corrida_siguiente_libera(tmp_path, isapi, status):
    fake = isapi(status_acs=status)
    seg = seguimiento(tmp_path, cursor=100)
    r = recuperador(seg, lambda rec_: None)
    resumen = r.correr()
    assert resumen["encolados"] == 0
    assert seg.techo == 100
    _entregar_en_vivo(seg, [104, 105])
    assert seg.cursor == 100
    assert leer_estado(tmp_path)["cursor_serial"] == 100

    fake.status_acs = 200
    fake.paginas = [("OK", [item(s) for s in range(101, 106)])]
    enviados: list[dict] = []
    r.destino = enviados.append
    r.correr()
    assert _desde(fake)[-1] == 101
    assert [x["serial"] for x in enviados] == [101, 102, 103]
    assert seg.techo is None
    for x in enviados:
        seg.entregado(x)
    assert seg.cursor == 105
    assert leer_estado(tmp_path)["cursor_serial"] == 105


def test_tope_1000_con_1500_el_techo_queda_en_el_milesimo(tmp_path, isapi):
    fake = isapi(paginas=[("OK", [item(s) for s in range(1, 1501)])])
    seg = seguimiento(tmp_path, cursor=0)
    enviados: list[dict] = []
    resumen = recuperador(seg, enviados.append).correr()
    assert resumen["encolados"] == 1000
    assert seg.techo == 1000
    for r in enviados:
        seg.entregado(r)
    _entregar_en_vivo(seg, [1600])
    assert seg.cursor == 1000
    assert leer_estado(tmp_path)["cursor_serial"] == 1000

    fake.paginas = [("OK", [item(s) for s in range(1001, 1501)] + [item(1600)])]
    enviados.clear()
    resumen = recuperador(seg, enviados.append).correr()
    assert _desde(fake) == [1, 1001]
    assert enviados[0]["serial"] == 1001 and enviados[-1]["serial"] == 1500
    assert resumen["encolados"] == 500 and resumen["ya_vistos"] == 1
    assert seg.techo is None
    for r in enviados:
        seg.entregado(r)
    assert seg.cursor == 1600
    assert leer_estado(tmp_path)["cursor_serial"] == 1600


def test_paginacion_cortada_sube_el_techo_al_mayor_admitido(tmp_path, isapi, monkeypatch):
    monkeypatch.setattr(rec, "MAX_PAGINAS", 2)
    pagina = rec.MAX_RESULTS
    fake = isapi(paginas=[("MORE", [item(s) for s in range(101 + i * pagina, 101 + (i + 1) * pagina)])
                          for i in range(3)])
    seg = seguimiento(tmp_path, cursor=100)
    enviados: list[dict] = []
    recuperador(seg, enviados.append).correr()
    ultimo = 100 + 2 * pagina
    assert enviados[-1]["serial"] == ultimo
    assert seg.techo == ultimo
    for r in enviados:
        seg.entregado(r)
    _entregar_en_vivo(seg, [ultimo + 50])
    assert seg.cursor == ultimo


def test_corrida_completa_sin_items_libera_y_el_cursor_sigue_al_vivo(tmp_path, isapi):
    isapi(paginas=[])
    seg = seguimiento(tmp_path, cursor=100)
    resumen = recuperador(seg, lambda r: None).correr()
    assert resumen["encolados"] == 0
    assert seg.techo is None
    _entregar_en_vivo(seg, [101, 102])
    assert seg.cursor == 102
    assert leer_estado(tmp_path)["cursor_serial"] == 102


def test_primer_arranque_no_abre_techo(tmp_path, isapi):
    isapi(reciente=[item(500)])
    seg = seguimiento(tmp_path, cursor=None, mac=None)
    recuperador(seg, lambda r: None).correr()
    assert seg.techo is None
    _entregar_en_vivo(seg, [501])
    assert seg.cursor == 501


# ---------------------------------------------------------------------------
# (r)-(t) endSerialNo obligatorio y fallback de major solo por errorMsg "major"
# ---------------------------------------------------------------------------

def test_consulta_por_serial_manda_begin_y_end_serial(tmp_path, isapi):
    pagina = rec.MAX_RESULTS
    fake = isapi(paginas=[("MORE", [item(s) for s in range(101, 101 + pagina)]),
                          ("OK", [item(101 + pagina)])])
    seg = seguimiento(tmp_path, cursor=100)
    resumen = recuperador(seg, lambda r: None).correr()
    conds = [c[2]["AcsEventCond"] for c in fake.acs()]
    assert len(conds) == 2
    assert all(c["beginSerialNo"] == 101 and c["endSerialNo"] == 999999999 for c in conds)
    assert rec.SERIAL_FIN == 999999999
    assert resumen["encolados"] == pagina + 1


def test_inicializacion_por_tiempo_sin_campos_de_serial(tmp_path, isapi):
    fake = isapi(reciente=[item(500)])
    seg = seguimiento(tmp_path, cursor=None, mac=None)
    recuperador(seg, lambda r: None).correr()
    cond = fake.acs()[0][2]["AcsEventCond"]
    assert cond["timeReverseOrder"] is True
    assert "beginSerialNo" not in cond and "endSerialNo" not in cond
    assert seg.cursor == 500


def test_400_end_serial_aborta_sin_fallback_a_major5(tmp_path, isapi, caplog):
    fake = isapi(error_400="endSerialNo", paginas=[("OK", [item(101)])])
    seg = seguimiento(tmp_path, cursor=100)
    r = recuperador(seg, lambda rec_: None)
    with caplog.at_level(logging.WARNING):
        resumen = r.correr()
    assert [c[2]["AcsEventCond"]["major"] for c in fake.acs()] == [0]
    assert resumen["encolados"] == 0
    assert r._major is None  # no se fijó major=5
    assert "rechazó major=0" not in caplog.text
    assert "HTTP 400, errorMsg 'endSerialNo'" in caplog.text
    assert seg.techo == 100  # fallida: el techo protege


def test_400_major_cae_a_major5_y_loguea_el_error_msg(tmp_path, isapi, caplog):
    fake = isapi(rechaza_major0=True, paginas=[("OK", [item(101)])])
    seg = seguimiento(tmp_path, cursor=100)
    with caplog.at_level(logging.WARNING):
        resumen = recuperador(seg, lambda r: None).correr()
    assert [c[2]["AcsEventCond"]["major"] for c in fake.acs()] == [0, 5]
    assert resumen["encolados"] == 1
    assert "errorMsg 'major'" in caplog.text


def test_400_sin_error_msg_aborta_sin_fallback(tmp_path, isapi):
    fake = isapi(status_acs=400, paginas=[("OK", [item(101)])])
    seg = seguimiento(tmp_path, cursor=100)
    recuperador(seg, lambda r: None).correr()
    assert [c[2]["AcsEventCond"]["major"] for c in fake.acs()] == [0]
