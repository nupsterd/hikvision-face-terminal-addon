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
        self.text = content.decode("utf-8", errors="replace")

    def json(self):
        if self._data is None:
            raise ValueError("sin json")
        return self._data


def _rechazo(error_msg: str) -> dict:
    return {"statusCode": 6, "statusString": "Invalid Content", "subStatusCode": "badJsonContent",
            "errorCode": 1610612737, "errorMsg": error_msg}


class FakeISAPI:
    """Fake de requests.request para AcsEvent + deviceInfo. Registra cada llamada.

    Se comporta como el terminal: las consultas por serial filtran por
    ``[beginSerialNo, endSerialNo]`` y paginan con ``searchResultPosition``/``maxResults``
    (MORE mientras queden). ``paginas`` es la lista de eventos que el equipo devuelve, en su
    orden (por hora); el estado de cada página que trae el test se ignora. La consulta de un
    serial exacto (ancla) busca también entre los eventos de listas anteriores: el equipo
    los conserva.
    """

    def __init__(self, *, paginas=None, mac=MAC, rechaza_major0=False, status_acs=200,
                 status_info=200, reciente=None, info_xml=False, error_400=None,
                 estado_forzado=None):
        self.conocidos: dict[int, dict] = {}
        self.estado_forzado = estado_forzado  # responseStatusStrg fijo en las consultas por serial
        self.paginas = list(paginas or [])  # lista de (estado, items)
        self.mac = mac
        self.rechaza_major0 = rechaza_major0
        self.status_acs = status_acs
        self.status_info = status_info
        self.reciente = reciente  # items para la consulta timeReverseOrder
        self.info_xml = info_xml  # deviceInfo como el DS-K1T344 real: XML aunque se pida JSON
        self.error_400 = error_400  # errorMsg de un 400 forzado en toda consulta AcsEvent
        self.llamadas: list[tuple[str, str, dict | None, dict]] = []

    @property
    def paginas(self):
        return self._paginas

    @paginas.setter
    def paginas(self, valor):
        self._paginas = list(valor)
        for _estado, items in self._paginas:
            for i in items:
                if isinstance(i.get("serialNo"), int):
                    self.conocidos[i["serialNo"]] = i

    def eventos(self) -> list[dict]:
        return [i for _estado, items in self._paginas for i in items]

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
        desde, hasta = cond["beginSerialNo"], cond["endSerialNo"]
        if desde == hasta:
            base = [self.conocidos[desde]] if desde in self.conocidos else []
        else:
            base = self.eventos()
        sel = [i for i in base if isinstance(i.get("serialNo"), int) and desde <= i["serialNo"] <= hasta]
        if not sel:
            return FakeResp(200, {"AcsEvent": {"responseStatusStrg": "NO MATCH", "numOfMatches": 0}})
        pos, n = cond["searchResultPosition"], cond["maxResults"]
        pagina = sel[pos:pos + n]
        estado = "MORE" if pos + n < len(sel) else "OK"
        if self.estado_forzado is not None:
            estado = self.estado_forzado
            if estado == "MORE vacío":
                estado, pagina = "MORE", []
            if estado == "ausente":
                return FakeResp(200, {"AcsEvent": {"numOfMatches": len(pagina), "InfoList": pagina}})
        return FakeResp(200, {"AcsEvent": {"responseStatusStrg": estado,
                                           "numOfMatches": len(pagina), "InfoList": pagina}})

    def ventanas(self) -> list[tuple[int, int]]:
        """(begin, end) de la primera página de cada consulta por ventana (no sondeos)."""
        return [(c[2]["AcsEventCond"]["beginSerialNo"], c[2]["AcsEventCond"]["endSerialNo"])
                for c in self.acs()
                if "beginSerialNo" in c[2]["AcsEventCond"]
                and c[2]["AcsEventCond"]["endSerialNo"] != rec.SERIAL_FIN
                and c[2]["AcsEventCond"]["beginSerialNo"] != c[2]["AcsEventCond"]["endSerialNo"]
                and c[2]["AcsEventCond"]["searchResultPosition"] == 0]

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


@pytest.fixture(autouse=True)
def _sin_reintentos_de_fondo(monkeypatch):
    """Un hilo de recuperación que quedó esperando un reintento no vuelve a correr durante
    la sesión (los tests de reintento bajan estos valores a propósito)."""
    monkeypatch.setattr(rec, "REINTENTO_BASE", 3600.0, raising=False)
    monkeypatch.setattr(rec, "REINTENTO_MAX", 3600.0, raising=False)


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
    ventana, sondeo = conds[:-1], conds[-1]
    assert [c["searchResultPosition"] for c in ventana] == [0, 30, 60]
    assert {(c["beginSerialNo"], c["endSerialNo"]) for c in ventana} == {(101, 1100)}
    assert len({c["searchID"] for c in ventana}) == 1
    assert all(c["maxResults"] == 30 for c in ventana)
    # Sondeo: ¿hay algo después de la ventana? (endSerialNo obligatorio en el DS-K1T344)
    assert (sondeo["beginSerialNo"], sondeo["endSerialNo"], sondeo["maxResults"]) == (1101, rec.SERIAL_FIN, 1)
    assert [r["serial"] for r in enviados] == list(range(101, 166))
    assert (resumen["paginas"], resumen["encolados"], resumen["ya_vistos"]) == (3, 65, 0)


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
    assert _desde(fake)[-1] == 5433
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
        assert seg.observar_vivo({"serial": 12, "device_mac": MAC}) is True
    # Cierre completo: cursor y techo en 0 (se recupera la numeración nueva desde 1).
    assert seg.cursor == 0 and seg.techo == 0
    assert "reset de fábrica" in caplog.text
    assert leer_estado(tmp_path)["cursor_serial"] == 0
    assert seg.admitir({"serial": 4999}) is True  # puerta limpia
    # Un serial normal (dentro del umbral) no reinicia nada.
    seg2 = seguimiento(tmp_path / "b", cursor=5000)
    assert seg2.observar_vivo({"serial": 4500, "device_mac": MAC}) is False
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
    # Ventana de 1000 seriales: 1..3 abandonados, 4..1000 encolados, 1001..1008 la próxima.
    assert resumen["encolados"] == 997
    assert resumen["descartados"] == 3
    assert resumen["resultado"] == rec.CORTADA
    assert [r["serial"] for r in enviados][:2] == [4, 5]
    assert enviados[-1]["serial"] == 1000
    assert "tope" in caplog.text and "3 con más de 7 días" in caplog.text
    assert "después de 1000" in caplog.text
    for r in enviados:
        seg.entregado(r)
    assert seg.cursor == 1000  # avanza por lo entregado; lo de después, la próxima corrida


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
    assert majors == [0, 5, 5]  # ventana (0 rechazado, 5) + sondeo con 5
    assert resumen["encolados"] == 1
    assert caplog.text.count("rechazó major=0") == 1
    r.correr()  # segunda corrida: directo con major=5, sin volver a probar 0
    assert [c[2]["AcsEventCond"]["major"] for c in fake.acs()] == [0, 5, 5, 5, 5]


def test_major0_aceptado_se_usa(tmp_path, isapi):
    fake = isapi(paginas=[("OK", [item(101)])])
    seg = seguimiento(tmp_path, cursor=100)
    recuperador(seg, lambda r: None).correr()
    assert [c[2]["AcsEventCond"]["major"] for c in fake.acs()] == [0, 0]  # ventana + sondeo
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
    # Solo las consultas por ventana: no la inicialización (por tiempo) ni los sondeos.
    return [desde for desde, _hasta in fake.ventanas()]


def conexion(r: Recuperador) -> dict:
    """Lo que hace ``lanzar`` por cada conexión del stream, sin hilo: abrir el techo y correr."""
    r.seguimiento.abrir_techo()
    return r.correr()


def test_sin_mac_el_cursor_no_pasa_el_techo_y_la_corrida_siguiente_libera(tmp_path, isapi):
    fake = isapi(mac=None, info_xml=True)
    seg = seguimiento(tmp_path, cursor=100, mac=None)
    conexion(recuperador(seg, lambda r: None))
    assert seg.techo == 100
    _entregar_en_vivo(seg, [105, 106, 107])  # 101..104 nunca vistos
    assert seg.cursor == 100
    assert leer_estado(tmp_path)["cursor_serial"] == 100

    fake.mac = MAC
    fake.paginas = [("OK", [item(s) for s in range(101, 108)])]
    enviados: list[dict] = []
    resumen = conexion(recuperador(seg, enviados.append))
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
    conexion(recuperador(seg, lambda r: None))
    _entregar_en_vivo(seg, [105, 106])

    reiniciado = SeguimientoEntregas(EstadoPersistente(tmp_path / "face_state.json", LOG), LOG)
    assert reiniciado.cursor == 100 and reiniciado.techo is None
    fake.mac = MAC
    fake.paginas = [("OK", [item(s) for s in range(101, 107)])]
    enviados: list[dict] = []
    conexion(recuperador(reiniciado, enviados.append))
    assert _desde(fake) == [101]
    # Lo entregado en vivo antes del reinicio se re-envía: el backend lo absorbe como duplicado.
    assert [r["serial"] for r in enviados] == [101, 102, 103, 104, 105, 106]


@pytest.mark.parametrize("status", [401, 500], ids=["401", "respuesta_invalida"])
def test_abortada_el_cursor_no_pasa_el_techo_y_la_corrida_siguiente_libera(tmp_path, isapi, status):
    fake = isapi(status_acs=status)
    seg = seguimiento(tmp_path, cursor=100)
    r = recuperador(seg, lambda rec_: None)
    resumen = conexion(r)
    assert resumen["encolados"] == 0
    assert seg.techo == 100
    _entregar_en_vivo(seg, [104, 105])
    assert seg.cursor == 100
    assert leer_estado(tmp_path)["cursor_serial"] == 100

    fake.status_acs = 200
    fake.paginas = [("OK", [item(s) for s in range(101, 106)])]
    enviados: list[dict] = []
    r.destino = enviados.append
    conexion(r)
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


def test_ventana_sin_terminar_en_max_paginas_es_fallida(tmp_path, isapi, monkeypatch):
    # Cierre completo: una ventana nunca se da por procesada a medias.
    monkeypatch.setattr(rec, "MAX_PAGINAS", 2)
    fake = isapi(paginas=[("MORE", [item(s) for s in range(101, 201)])])
    seg = seguimiento(tmp_path, cursor=100)
    enviados: list[dict] = []
    resumen = conexion(recuperador(seg, enviados.append))
    assert resumen["resultado"] == rec.FALLIDA
    assert enviados == []
    assert seg.techo == 100
    assert len(fake.acs()) == 2  # dos páginas, sin sondeo
    _entregar_en_vivo(seg, [300])
    assert seg.cursor == 100


def test_corrida_completa_sin_items_libera_y_el_cursor_sigue_al_vivo(tmp_path, isapi):
    isapi(paginas=[])
    seg = seguimiento(tmp_path, cursor=100)
    resumen = recuperador(seg, lambda r: None).correr()
    assert resumen["encolados"] == 0
    assert seg.techo is None
    _entregar_en_vivo(seg, [101, 102])
    assert seg.cursor == 102
    assert leer_estado(tmp_path)["cursor_serial"] == 102


def test_primer_arranque_inicializar_abre_techo_en_el_serial(tmp_path, isapi):
    # Sexta corrección: inicializar() abre el techo en el serial (antes quedaba en None).
    isapi(reciente=[item(500)])
    seg = seguimiento(tmp_path, cursor=None, mac=None)
    recuperador(seg, lambda r: None).correr()
    assert seg.techo == 500
    _entregar_en_vivo(seg, [501])
    assert seg.cursor == 500  # hasta que una corrida completa lo libere


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
    assert len(conds) == 3  # dos páginas de la ventana + sondeo
    assert all(c["beginSerialNo"] == 101 and c["endSerialNo"] == 101 + rec.TOPE_EVENTOS - 1 for c in conds[:2])
    assert (conds[2]["beginSerialNo"], conds[2]["endSerialNo"]) == (101 + rec.TOPE_EVENTOS, 999999999)
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
        resumen = conexion(r)
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
    assert [c[2]["AcsEventCond"]["major"] for c in fake.acs()] == [0, 5, 5]  # + sondeo
    assert resumen["encolados"] == 1
    assert "errorMsg 'major'" in caplog.text


def test_400_sin_error_msg_aborta_sin_fallback(tmp_path, isapi):
    fake = isapi(status_acs=400, paginas=[("OK", [item(101)])])
    seg = seguimiento(tmp_path, cursor=100)
    recuperador(seg, lambda r: None).correr()
    assert [c[2]["AcsEventCond"]["major"] for c in fake.acs()] == [0]


# ---------------------------------------------------------------------------
# (v)-(x) corrida cortada sin admitidos: el techo sube a lo procesado
# ---------------------------------------------------------------------------

def _viejo(serial: int) -> dict:
    return item(serial, time=(AHORA - timedelta(days=8)).isoformat())


def test_paginacion_cortada_todo_viejo_sube_el_techo_y_no_repite_el_rango(tmp_path, isapi):
    fake = isapi(paginas=[("OK", [_viejo(s) for s in range(1, 1081)])])
    seg = seguimiento(tmp_path, cursor=0)
    resumen = recuperador(seg, lambda r: None).correr()
    fin = rec.TOPE_EVENTOS  # fin de la primera ventana
    assert resumen["encolados"] == 0 and resumen["descartados"] == fin
    assert seg.techo == fin
    _entregar_en_vivo(seg, [5000])
    assert seg.cursor == fin
    assert leer_estado(tmp_path)["cursor_serial"] == fin

    recuperador(seg, lambda r: None).correr()
    assert _desde(fake) == [1, fin + 1]  # avanza: no repite el rango
    assert seg.techo is None
    assert seg.cursor == 5000


def test_ventana_sin_admitidos_sube_el_techo_al_fin_de_la_ventana(tmp_path, isapi):
    viejos = [_viejo(s) for s in range(1, 51)]
    recientes = [item(s) for s in range(51, 1056)]
    fake = isapi(paginas=[("OK", viejos + recientes)])
    seg = seguimiento(tmp_path, cursor=0)
    en_cola = [{"serial": s} for s in range(51, 1051)]
    assert all(seg.admitir(r) for r in en_cola)  # todos los recientes de la ventana ya vistos
    resumen = recuperador(seg, lambda r: None).correr()
    assert resumen["encolados"] == 0 and resumen["ya_vistos"] == 950
    assert resumen["resultado"] == rec.CORTADA  # los abandonados avanzaron el cursor
    assert seg.techo == 1000
    for r in en_cola:
        seg.entregado(r)
    _entregar_en_vivo(seg, [1200])
    assert seg.cursor == 1000

    enviados: list[dict] = []
    recuperador(seg, enviados.append).correr()
    assert _desde(fake) == [1, 1001]
    assert [r["serial"] for r in enviados] == [1051, 1052, 1053, 1054, 1055]
    assert seg.techo is None


def test_ventana_todos_ya_vistos_techo_en_el_fin_de_la_ventana(tmp_path, isapi, monkeypatch):
    monkeypatch.setattr(rec, "TOPE_EVENTOS", 60)
    fake = isapi(paginas=[("OK", [item(s) for s in range(101, 191)])])
    seg = seguimiento(tmp_path, cursor=100)
    pendientes = [{"serial": s} for s in range(101, 161)]
    assert all(seg.admitir(r) for r in pendientes)  # en vivo, en la cola
    resumen = recuperador(seg, lambda r: None).correr()
    assert resumen["encolados"] == 0 and resumen["ya_vistos"] == 60
    assert resumen["resultado"] == rec.FALLIDA  # sin avance hasta que se entreguen: backoff
    assert seg.techo == 160
    assert seg.cursor == 100  # los pendientes siguen frenando
    for r in pendientes:
        seg.entregado(r)
    _entregar_en_vivo(seg, [210])
    assert seg.cursor == 160

    enviados: list[dict] = []
    recuperador(seg, enviados.append).correr()
    assert _desde(fake)[-1] == 161
    assert [r["serial"] for r in enviados] == list(range(161, 191))
    assert seg.techo is None


def test_ventana_con_mezcla_de_admitidos_y_viejos_techo_en_el_fin_de_la_ventana(tmp_path, isapi):
    # Un viejo con serial fuera de la ventana (hora desordenada) queda para la próxima.
    validos = [_viejo(s) for s in range(1, 11)] + [item(s) for s in range(11, 1016)] + [_viejo(1020)]
    isapi(paginas=[("OK", validos)])
    seg = seguimiento(tmp_path, cursor=0)
    enviados: list[dict] = []
    resumen = recuperador(seg, enviados.append).correr()
    assert resumen["encolados"] == 990 and resumen["descartados"] == 10
    assert enviados[-1]["serial"] == 1000
    assert seg.techo == 1000
    for r in enviados:
        seg.entregado(r)
    _entregar_en_vivo(seg, [1100])
    assert seg.cursor == 1000


# ---------------------------------------------------------------------------
# (z) abandonados y sin record son estado final: suben el cursor sin entregas en vivo
# ---------------------------------------------------------------------------

def test_corrida_completa_todo_viejo_sin_vivo_sube_el_cursor(tmp_path, isapi):
    fake = isapi(paginas=[("OK", [_viejo(s) for s in range(101, 121)])])
    seg = seguimiento(tmp_path, cursor=100)
    resumen = recuperador(seg, lambda r: None).correr()
    assert resumen["encolados"] == 0 and resumen["descartados"] == 20
    assert seg.techo is None
    assert seg.cursor == 120
    assert leer_estado(tmp_path)["cursor_serial"] == 120

    fake.paginas = []
    recuperador(seg, lambda r: None).correr()
    assert _desde(fake) == [101, 121]


def test_paginacion_cortada_todo_viejo_sin_vivo_no_repite(tmp_path, isapi):
    fake = isapi(paginas=[("OK", [_viejo(s) for s in range(1, 1081)])])
    seg = seguimiento(tmp_path, cursor=0)
    recuperador(seg, lambda r: None).correr()
    fin = rec.TOPE_EVENTOS
    assert seg.techo == fin
    assert seg.cursor == fin  # sin ninguna entrega en vivo
    assert leer_estado(tmp_path)["cursor_serial"] == fin

    recuperador(seg, lambda r: None).correr()
    assert _desde(fake) == [1, fin + 1]


def test_record_none_cuenta_como_resuelto(tmp_path, isapi):
    fake = isapi(paginas=[("OK", [item(s) for s in range(101, 106)])])
    seg = seguimiento(tmp_path, cursor=100)
    r = recuperador(seg, None)
    enviados: list[dict] = []
    r.destino = enviados.append
    r.construir_record = lambda ev: (None if ev["AccessControllerEvent"]["serialNo"] in (102, 105)
                                     else record_desde_evento(ev, LOG))
    resumen = r.correr()
    assert [x["serial"] for x in enviados] == [101, 103, 104]
    assert resumen["encolados"] == 3
    assert seg.cursor == 100  # 101 pendiente frena
    for x in enviados:
        seg.entregado(x)
    assert seg.cursor == 105  # 105 sin record: resuelto, sube el cursor
    assert leer_estado(tmp_path)["cursor_serial"] == 105

    # Solo sin record y sin vivo: igual avanza.
    fake.paginas = [("OK", [item(106)])]
    r.construir_record = lambda ev: None
    r.correr()
    assert _desde(fake)[-1] == 106
    assert seg.cursor == 106


def test_pendiente_por_debajo_de_un_abandonado_sigue_frenando(tmp_path, isapi):
    seg = seguimiento(tmp_path, cursor=100)
    pendiente = {"serial": 103}
    assert seg.admitir(pendiente)  # en vivo, en la cola sin entregar
    isapi(paginas=[("OK", [_viejo(s) for s in (101, 102, 110)])])
    recuperador(seg, lambda r: None).correr()
    assert seg.cursor == 102  # pendiente − 1, aunque se abandonó hasta 110
    assert leer_estado(tmp_path)["cursor_serial"] == 102
    seg.entregado(pendiente)
    assert seg.cursor == 110


def test_abandonado_no_pasa_el_techo(tmp_path):
    seg = seguimiento(tmp_path, cursor=100)
    assert seg.abrir_techo() == 100
    seg.resolver_sin_envio([150])
    assert seg.cursor == 100
    seg.cerrar_techo()
    assert seg.cursor == 150


# ---------------------------------------------------------------------------
# (aa)-(ee) techo abierto en lanzar() y relanzamiento por conexión nueva
# ---------------------------------------------------------------------------

class Compuerta:
    """Reemplaza ``r.correr``: registra cada corrida y retiene la primera hasta ``liberar``."""

    def __init__(self, r: Recuperador):
        self.r = r
        self.original = r.correr
        self.llamadas = 0
        self.techos: list = []
        self.adentro = threading.Event()
        self.liberar = threading.Event()
        r.correr = self

    def __call__(self):
        self.llamadas += 1
        self.techos.append(self.r.seguimiento.techo)
        if self.llamadas == 1:
            self.adentro.set()
            assert self.liberar.wait(5)
        return self.original()

    def terminar(self) -> None:
        self.liberar.set()
        self.r._hilo.join(timeout=5)
        assert not self.r._hilo.is_alive()


def test_entrega_en_vivo_antes_del_hilo_no_pasa_el_techo(tmp_path, isapi):
    isapi(paginas=[("OK", [item(s) for s in range(101, 105)])])
    seg = seguimiento(tmp_path, cursor=100)
    enviados: list[dict] = []
    r = recuperador(seg, enviados.append)
    compuerta = Compuerta(r)
    assert r.lanzar() is True
    assert compuerta.adentro.wait(5)
    _entregar_en_vivo(seg, [104])  # 2xx en vivo antes de que la corrida empiece
    assert seg.techo == 100
    assert seg.cursor == 100
    assert leer_estado(tmp_path)["cursor_serial"] == 100
    compuerta.terminar()
    assert [x["serial"] for x in enviados] == [101, 102, 103]
    assert seg.techo is None
    for x in enviados:
        seg.entregado(x)
    assert seg.cursor == 104


def test_conexion_nueva_durante_la_corrida_relanza_sin_liberar_el_techo(tmp_path, isapi):
    fake = isapi(paginas=[("OK", [item(s) for s in range(101, 104)])])
    seg = seguimiento(tmp_path, cursor=100)
    enviados: list[dict] = []
    en_destino = threading.Event()
    seguir = threading.Event()

    def destino(record):
        enviados.append(record)
        if len(enviados) == 1:  # la primera corrida ya consultó: se queda a mitad de camino
            en_destino.set()
            assert seguir.wait(5)

    r = recuperador(seg, destino)
    techos: list = []
    original = r.correr

    def correr_registrando():
        techos.append(seg.techo)
        return original()

    r.correr = correr_registrando
    assert r.lanzar() is True
    assert en_destino.wait(5)
    # Desconexión y reconexión durante la corrida: 104..106 pasaron en el hueco nuevo.
    fake.paginas = [("OK", [item(s) for s in range(101, 108)])]
    assert r.lanzar() is False
    _entregar_en_vivo(seg, [107])  # en vivo de la conexión nueva
    assert seg.cursor == 100
    seguir.set()
    r._hilo.join(timeout=5)
    assert not r._hilo.is_alive()
    assert techos == [100, 100]  # la segunda arrancó con el techo todavía abierto
    assert _desde(fake) == [101, 101]
    assert [x["serial"] for x in enviados] == [101, 102, 103, 104, 105, 106]
    assert seg.techo is None  # recién la segunda, completa, lo libera
    for x in enviados:
        seg.entregado(x)
    assert seg.cursor == 107


def test_abrir_techo_nunca_sube_un_techo_abierto(tmp_path):
    seg = seguimiento(tmp_path, cursor=100)
    assert seg.abrir_techo() == 100
    _entregar_en_vivo(seg, [101, 102, 103])
    assert seg.abrir_techo() == 100  # el cursor efectivo de 103 no lo sube
    assert seg.cursor == 100
    seg.subir_techo(200)  # corrida cortada
    assert seg.cursor == 103
    assert seg.abrir_techo() == 103  # min(200, 103): baja
    _entregar_en_vivo(seg, [150])
    assert seg.cursor == 103


def test_varios_lanzar_durante_la_corrida_una_sola_extra(tmp_path, isapi, caplog):
    isapi(paginas=[])
    seg = seguimiento(tmp_path, cursor=100)
    r = recuperador(seg, lambda x: None)
    compuerta = Compuerta(r)
    with caplog.at_level(logging.INFO, logger=LOG.name):
        assert r.lanzar() is True
        assert compuerta.adentro.wait(5)
        assert [r.lanzar() for _ in range(3)] == [False, False, False]
        compuerta.terminar()
    assert compuerta.llamadas == 2
    assert caplog.text.count("se relanza al terminar") == 3
    assert seg.techo is None
    assert r.lanzar() is True  # terminado: una conexión nueva vuelve a arrancar un hilo
    r._hilo.join(timeout=5)
    assert compuerta.llamadas == 3


def test_reinicio_el_primer_lanzar_abre_el_techo_antes_de_cualquier_entrega(tmp_path, isapi):
    isapi(paginas=[("OK", [item(s) for s in range(101, 106)])])
    seguimiento(tmp_path, cursor=100)  # estado persistido por el proceso anterior
    seg = SeguimientoEntregas(EstadoPersistente(tmp_path / "face_state.json", LOG), LOG)
    assert seg.techo is None
    r = recuperador(seg, lambda x: None)
    compuerta = Compuerta(r)
    r.lanzar()
    assert seg.techo == 100  # sincrónico, antes de que el hilo corra
    _entregar_en_vivo(seg, [105])
    assert seg.cursor == 100
    compuerta.terminar()


def test_primer_arranque_lanzar_no_abre_techo(tmp_path, isapi):
    isapi(reciente=[item(500)])
    seg = seguimiento(tmp_path, cursor=None, mac=None)
    r = recuperador(seg, lambda x: None)
    compuerta = Compuerta(r)
    r.lanzar()
    assert seg.techo is None  # sin cursor, lanzar() no abre
    compuerta.terminar()
    # Sexta corrección: la inicialización sí lo abre en el serial (antes quedaba en None).
    assert seg.cursor == 500 and seg.techo == 500


# ---------------------------------------------------------------------------
# (ff)-(hh) inicializar() abre el techo en el serial de inicialización
# ---------------------------------------------------------------------------

def _retener_inicializacion(monkeypatch, fake: FakeISAPI):
    """Retiene la consulta por tiempo (inicialización) hasta ``seguir``."""
    en_consulta, seguir = threading.Event(), threading.Event()

    def retenida(metodo, url, json=None, **kwargs):  # noqa: A002
        if json and json["AcsEventCond"].get("timeReverseOrder"):
            en_consulta.set()
            assert seguir.wait(5)
        return fake(metodo, url, json=json, **kwargs)

    monkeypatch.setattr(rec.requests, "request", retenida)
    return en_consulta, seguir


def test_reconexion_durante_la_inicializacion_la_relanzada_recupera_el_hueco(tmp_path, isapi, monkeypatch):
    fake = isapi(reciente=[item(500)], paginas=[("OK", [item(s) for s in range(501, 506)])])
    en_consulta, seguir = _retener_inicializacion(monkeypatch, fake)
    seg = seguimiento(tmp_path, cursor=None, mac=None)
    enviados: list[dict] = []
    r = recuperador(seg, enviados.append)
    original = r.correr
    techos: list = []

    def correr():
        if techos:  # la relanzada: una 2xx en vivo de la conexión nueva le gana a la lectura
            _entregar_en_vivo(seg, [505])
        techos.append(seg.techo)
        return original()

    r.correr = correr
    assert r.lanzar() is True
    assert en_consulta.wait(5)
    assert r.lanzar() is False  # reconexión durante la inicialización: sin cursor, no abre
    assert seg.techo is None
    seguir.set()
    r._hilo.join(timeout=5)
    assert not r._hilo.is_alive()
    assert techos == [None, 500]  # inicializar abrió el techo en el serial
    assert _desde(fake) == [501]
    assert [x["serial"] for x in enviados] == [501, 502, 503, 504]  # 505: ya visto
    assert seg.techo is None  # la relanzada, completa, lo libera
    assert seg.cursor == 500
    for x in enviados:
        seg.entregado(x)
    assert seg.cursor == 505


def test_primer_arranque_normal_la_proxima_conexion_libera_y_sigue_al_vivo(tmp_path, isapi):
    fake = isapi(reciente=[item(500)])
    seg = seguimiento(tmp_path, cursor=None, mac=None)
    r = recuperador(seg, lambda x: None)
    resumen = conexion(r)
    assert resumen["encolados"] == 0
    assert seg.techo == 500
    _entregar_en_vivo(seg, [501, 502, 503])
    assert seg.cursor == 500
    assert leer_estado(tmp_path)["cursor_serial"] == 500

    fake.paginas = [("OK", [item(s) for s in range(501, 504)])]  # nada nuevo: todo ya visto
    resumen = conexion(r)
    assert _desde(fake) == [501]
    assert resumen["encolados"] == 0 and resumen["ya_vistos"] == 3
    assert seg.techo is None
    assert seg.cursor == 503
    _entregar_en_vivo(seg, [504])
    assert seg.cursor == 504


def test_entrega_en_vivo_antes_de_terminar_la_inicializacion_igual_abre_el_techo(tmp_path, isapi, monkeypatch):
    fake = isapi(reciente=[item(500)])
    en_consulta, seguir = _retener_inicializacion(monkeypatch, fake)
    seg = seguimiento(tmp_path, cursor=None, mac=None)
    enviados: list[dict] = []
    r = recuperador(seg, enviados.append)
    assert r.lanzar() is True
    assert en_consulta.wait(5)
    _entregar_en_vivo(seg, [505])  # fija el cursor antes de que inicializar termine
    assert seg.cursor == 505
    seguir.set()
    r._hilo.join(timeout=5)
    assert seg.techo == 500  # inicializar no pisó el cursor pero abrió el techo
    assert seg.cursor == 500
    assert leer_estado(tmp_path)["cursor_serial"] == 500

    fake.paginas = [("OK", [item(s) for s in range(501, 506)])]
    conexion(r)
    assert _desde(fake) == [501]
    assert [x["serial"] for x in enviados] == [501, 502, 503, 504]
    assert seg.techo is None
    for x in enviados:
        seg.entregado(x)
    assert seg.cursor == 505


# ---------------------------------------------------------------------------
# Cierre completo (#54): un test por hueco encontrado en la auditoría contra I1–I6
# ---------------------------------------------------------------------------

def _ev_vivo(serial: int, *, mac: str = MAC, time: str | None = None) -> dict:
    """Evento del alertStream (en vivo) con datos sintéticos."""
    return {
        "ipAddress": HOST, "macAddress": mac,
        "dateTime": time or item(serial)["time"],
        "eventType": "AccessControllerEvent",
        "AccessControllerEvent": {"majorEventType": 5, "subEventType": 75, "serialNo": serial,
                                  "employeeNoString": "5001", "name": "PERSONA PRUEBA",
                                  "currentEvent": True},
    }


def _correr_listener(tmp_path, monkeypatch, *, estado: dict, conexiones: list[list[bytes]],
                     fake: FakeISAPI, al_lanzar=None) -> tuple[list[dict], list[dict], list[int]]:
    """run() real con N conexiones del stream (una lista de chunks por conexión). La
    recuperación corre SINCRÓNICA dentro de lanzar() (determinismo). Devuelve (posts al
    backend, records emitidos a HA, seriales de cada lanzar())."""
    (tmp_path / "face_state.json").write_text(json.dumps(estado))
    cfg = Config(terminal_host=HOST, terminal_user="admin", terminal_password="x",
                 ha_webhook_url="https://ha.local/api/webhook/x", audit_log_path=tmp_path / "a.log",
                 backend_url="https://backend/x", backend_secret="s", reconnect_delay=1,
                 state_path=tmp_path / "face_state.json")
    monkeypatch.setattr(rec.requests, "request", fake)
    restantes = list(conexiones)

    def fake_get(url, **kwargs):
        return FakeStream(restantes.pop(0) if restantes else [])

    monkeypatch.setattr(mod.requests, "get", fake_get)
    lanzados: list[int] = []

    def lanzar_sincronico(self):
        self.seguimiento.abrir_techo()
        lanzados.append(self.seguimiento.cursor)
        if al_lanzar is not None:
            al_lanzar(len(lanzados))
        self.correr()
        return True

    monkeypatch.setattr(Recuperador, "lanzar", lanzar_sincronico)
    posts: list[dict] = []
    lock = threading.Lock()

    def fake_post(url, json, headers=None, timeout=None, **kw):  # noqa: A002
        if json.get("device_mac") == MAC:  # no los forwarders (daemon) de otros tests
            with lock:
                posts.append(json)
        return FakeResp(200)

    monkeypatch.setattr(mod.requests, "post", fake_post)
    ha_emit: list[dict] = []
    monkeypatch.setattr(mod, "_maybe_emit_ha_webhook", lambda record, *a, **k: ha_emit.append(record))

    def fake_sleep(_s):  # entre conexiones; sin conexiones restantes, fin
        if not restantes:
            raise _Stop()

    monkeypatch.setattr(mod.time, "sleep", fake_sleep)
    with pytest.raises(_Stop):
        run(cfg, LOG)
    threading.Event().wait(0.3)  # que el forwarder (hilo daemon) drene
    with lock:
        return list(posts), ha_emit, lanzados


# --- H1: reset de fábrica ⇒ cursor y techo en 0 y recuperación de la numeración nueva ---

def test_h1_reset_de_fabrica_recupera_la_numeracion_nueva_desde_1(tmp_path, monkeypatch):
    nuevos = [item(s) for s in range(1, 13)]  # el terminal reseteado ya registró 1..12
    fake = FakeISAPI(paginas=[("OK", nuevos)])
    vivo = _ev_vivo(12, time=nuevos[-1]["time"])
    posts, ha_emit, lanzados = _correr_listener(
        tmp_path, monkeypatch, estado={"cursor_serial": 5000, "terminal_mac": MAC},
        conexiones=[_como_stream([vivo])], fake=fake)
    assert lanzados[0] == 5000  # la conexión: nada después de 5000 en la numeración nueva
    assert lanzados[1] == 0  # el reset dispara la recuperación desde 1
    seriales = sorted(p["serial"] for p in posts)
    assert seriales == list(range(1, 13))  # 1..11 recuperados + 12 en vivo, una vez cada uno
    vivos = [p for p in posts if not p.get("recuperado")]
    assert [p["serial"] for p in vivos] == [12]  # el 12 salió en vivo, no como recuperado
    assert not any(r.get("recuperado") for r in ha_emit)


# --- H2: reset no detectado por el umbral ⇒ ancla ---

def _seg_con_ancla(tmp_path, *, cursor: int, ancla: tuple[int, str]) -> SeguimientoEntregas:
    path = tmp_path / "face_state.json"
    path.write_text(json.dumps({"cursor_serial": cursor, "terminal_mac": MAC,
                                "ancla_serial": ancla[0], "ancla_ts": ancla[1]}))
    return SeguimientoEntregas(EstadoPersistente(path, LOG), LOG)


@pytest.mark.parametrize("caso", ["ancla_ausente", "ancla_con_otra_hora"])
def test_h2_numeracion_cambiada_por_ancla_recupera_desde_1(tmp_path, isapi, caso, caplog):
    # Cursor 500 (< umbral de 1000): el serial en vivo nunca queda 1000 por debajo.
    hora_vieja = (AHORA - timedelta(days=2)).isoformat()
    nuevos = [item(s) for s in range(1, 31)]
    if caso == "ancla_con_otra_hora":
        nuevos += [item(s) for s in range(31, 501)]  # la numeración nueva ya pasó el 500
    fake = isapi(paginas=[("OK", nuevos)])
    seg = _seg_con_ancla(tmp_path, cursor=500, ancla=(500, hora_vieja))
    enviados: list[dict] = []
    with caplog.at_level(logging.WARNING):
        conexion(recuperador(seg, enviados.append))
    assert "serial ancla 500" in caplog.text
    assert _desde(fake) == [1]
    assert [r["serial"] for r in enviados] == [i["serialNo"] for i in nuevos]
    for r in enviados:
        seg.entregado(r)
    assert seg.cursor == nuevos[-1]["serialNo"]


def test_h2_ancla_vigente_no_reinicia(tmp_path, isapi):
    hora = item(500)["time"]
    fake = isapi(paginas=[("OK", [item(s) for s in range(1, 506)])])
    seg = _seg_con_ancla(tmp_path, cursor=500, ancla=(500, hora))
    enviados: list[dict] = []
    conexion(recuperador(seg, enviados.append))
    assert _desde(fake) == [501]
    assert [r["serial"] for r in enviados] == [501, 502, 503, 504, 505]


def test_h2_ancla_se_fija_con_la_entrega_de_acceso_y_se_persiste(tmp_path, isapi):
    isapi(paginas=[("OK", [item(101), item(102, minor=21)])])
    seg = seguimiento(tmp_path, cursor=100)
    enviados: list[dict] = []
    recuperador(seg, enviados.append).correr()
    for r in enviados:
        seg.entregado(r)
    estado = leer_estado(tmp_path)
    assert (estado["ancla_serial"], estado["ancla_ts"]) == (102, item(102)["time"])
    seg.entregado({"serial": 999})  # sin pendiente: se ignora (no mueve nada)
    assert leer_estado(tmp_path)["ancla_serial"] == 102


def test_h2_ancla_no_verificable_no_reinicia(tmp_path, isapi, monkeypatch):
    fake = isapi(paginas=[("OK", [item(501)])])
    real = fake.__call__

    def con_rechazo_al_ancla(metodo, url, json=None, **kw):  # noqa: A002
        cond = (json or {}).get("AcsEventCond", {})
        if cond.get("beginSerialNo") == cond.get("endSerialNo") == 500:
            return FakeResp(400, _rechazo("beginSerialNo"))
        return real(metodo, url, json=json, **kw)

    monkeypatch.setattr(rec.requests, "request", con_rechazo_al_ancla)
    seg = _seg_con_ancla(tmp_path, cursor=500, ancla=(500, item(500)["time"]))
    enviados: list[dict] = []
    conexion(recuperador(seg, enviados.append))
    assert [r["serial"] for r in enviados] == [501]  # sigue sin reiniciar


# --- H3: corte con orden por hora distinto del orden por serial ---

def test_h3_reloj_desordenado_no_saltea_seriales_al_cortar(tmp_path, isapi):
    # El reloj del terminal saltó para atrás: 900..1100 tienen hora anterior a 1..899, así
    # que AcsEvent (orden por hora) los devuelve primero.
    antes = AHORA - timedelta(hours=3)
    tarde = [item(s, time=(antes + timedelta(seconds=s)).isoformat()) for s in range(900, 1101)]
    temprano = [item(s, time=(antes + timedelta(hours=1, seconds=s)).isoformat()) for s in range(1, 900)]
    fake = isapi(paginas=[("OK", tarde + temprano)])
    seg = seguimiento(tmp_path, cursor=0)
    enviados: list[dict] = []
    recuperador(seg, enviados.append).correr()
    assert [r["serial"] for r in enviados] == list(range(1, 1001))
    assert seg.techo == 1000
    for r in enviados:
        seg.entregado(r)
    _entregar_en_vivo(seg, [2000])
    assert seg.cursor == 1000  # nada sin consultar por debajo del techo
    enviados.clear()
    recuperador(seg, enviados.append).correr()
    assert _desde(fake) == [1, 1001]
    assert [r["serial"] for r in enviados] == list(range(1001, 1101))


# --- H4: estado inesperado de AcsEvent tomado como completo ---

@pytest.mark.parametrize("estado", ["FAILED", "ausente", "MORE vacío"])
def test_h4_estado_inesperado_no_libera_el_techo(tmp_path, isapi, estado):
    isapi(paginas=[("OK", [item(101)])], estado_forzado=estado)
    seg = seguimiento(tmp_path, cursor=100)
    resumen = conexion(recuperador(seg, lambda r: None))
    assert seg.techo == 100
    assert resumen["resultado"] == rec.FALLIDA
    _entregar_en_vivo(seg, [105])
    assert seg.cursor == 100


# --- H5: lo pendiente se reintenta solo, sin esperar a otra reconexión ---

def _esperar_hilo(r: Recuperador, segundos: float = 5) -> None:
    for _ in range(int(segundos * 100)):
        with r._lock:
            if not r._en_curso:
                return
        threading.Event().wait(0.01)
    raise AssertionError("el hilo de recuperación no terminó")


def test_h5_corrida_fallida_se_reintenta_con_backoff_y_libera(tmp_path, isapi, monkeypatch):
    monkeypatch.setattr(rec, "REINTENTO_BASE", 0.05)
    fake = isapi(status_acs=500, paginas=[("OK", [item(s) for s in range(101, 104)])])
    seg = seguimiento(tmp_path, cursor=100)
    enviados: list[dict] = []
    r = recuperador(seg, enviados.append)
    llamadas = {"n": 0}
    original = r.correr

    def correr_y_arreglar():
        llamadas["n"] += 1
        resumen = original()
        fake.status_acs = 200  # el terminal vuelve a responder
        return resumen

    r.correr = correr_y_arreglar
    r.lanzar()
    _esperar_hilo(r)
    assert llamadas["n"] == 2  # la segunda sin reconexión
    assert [x["serial"] for x in enviados] == [101, 102, 103]
    assert seg.techo is None


def test_h5_entrega_fallida_dispara_un_reintento_sin_reconexion(tmp_path, isapi, monkeypatch):
    monkeypatch.setattr(rec, "REINTENTO_BASE", 0.05)
    isapi(paginas=[("OK", [item(s) for s in range(101, 104)])])
    seg = seguimiento(tmp_path, cursor=100)
    enviados: list[dict] = []
    r = recuperador(seg, enviados.append)
    _entregar_en_vivo(seg, [101, 103])
    pendiente = {"serial": 102}
    assert seg.admitir(pendiente)
    seg.fallido(pendiente)  # el forwarder agotó los intentos con el 102
    _esperar_hilo(r)
    assert [x["serial"] for x in enviados] == [102]  # lo volvió a pedir al terminal
    seg.entregado(enviados[0])
    assert seg.cursor == 103


def test_h5_corrida_cortada_sigue_con_la_ventana_siguiente(tmp_path, isapi, monkeypatch):
    monkeypatch.setattr(rec, "TOPE_EVENTOS", 50)
    monkeypatch.setattr(rec, "ESPERA_COLA_CORTE", 0.01, raising=False)
    fake = isapi(paginas=[("OK", [item(s) for s in range(101, 221)])])
    seg = seguimiento(tmp_path, cursor=100)
    enviados: list[dict] = []

    def destino(record):
        enviados.append(record)
        seg.entregado(record)  # backend instantáneo

    r = recuperador(seg, destino)
    r.lanzar()
    _esperar_hilo(r)
    assert _desde(fake) == [101, 151, 201]
    assert [x["serial"] for x in enviados] == list(range(101, 221))
    assert seg.techo is None and seg.cursor == 220


def test_h5_401_no_se_reintenta_hasta_la_proxima_conexion(tmp_path, isapi, monkeypatch):
    monkeypatch.setattr(rec, "REINTENTO_BASE", 0.01)
    fake = isapi(status_acs=401, paginas=[("OK", [item(101)])])
    seg = seguimiento(tmp_path, cursor=100)
    r = recuperador(seg, lambda x: None)
    r.lanzar()
    _esperar_hilo(r)
    pendiente = {"serial": 101}
    seg.admitir(pendiente)
    seg.fallido(pendiente)  # una entrega fallida tampoco reintenta tras un 401 (I6)
    threading.Event().wait(0.1)
    assert len(fake.acs()) == 1
    fake.status_acs = 200
    r.lanzar()  # conexión nueva: un intento más
    _esperar_hilo(r)
    assert len(fake.acs()) > 1


# --- H6: rechazo permanente del backend ---

def test_h6_rechazo_definitivo_se_resuelve_tras_3_veces_y_24_horas(tmp_path):
    seg = seguimiento(tmp_path, cursor=100)
    reloj = {"t": 1000.0}
    seg.reloj = lambda: reloj["t"]
    r = {"serial": 101}
    for _ in range(3):
        assert seg.admitir(r)
        seg.rechazado(r, 422)
        reloj["t"] += 60
    assert seg.cursor == 100  # 3 rechazos pero en menos de 24 h: sigue frenando
    reloj["t"] = 1000.0 + rec.RECHAZO_PLAZO
    assert seg.admitir(r)
    seg.rechazado(r, 422)
    assert seg.cursor == 101  # estado final
    assert leer_estado(tmp_path)["cursor_serial"] == 101


@pytest.mark.parametrize("status", [401, 403, 404, 429])
def test_h6_rechazo_de_configuracion_nunca_se_resuelve(tmp_path, status):
    seg = seguimiento(tmp_path, cursor=100)
    reloj = {"t": 0.0}
    seg.reloj = lambda: reloj["t"]
    r = {"serial": 101}
    for _ in range(5):
        assert seg.admitir(r)
        seg.rechazado(r, status)
        reloj["t"] += rec.RECHAZO_PLAZO
    assert seg.cursor == 100


def test_h6_forwarder_informa_el_status_del_rechazo(tmp_path, monkeypatch):
    seg = seguimiento(tmp_path, cursor=100)
    vistos: list[tuple[int, int]] = []
    seg.rechazado = lambda record, status: vistos.append((record["serial"], status))
    cfg = Config(terminal_host=HOST, terminal_user="a", terminal_password="x", ha_webhook_url="",
                 audit_log_path=tmp_path / "a.log", backend_url="https://b/x", backend_secret="s")
    fwd = BackendForwarder(cfg, LOG)
    fwd.seguimiento = seg
    monkeypatch.setattr(mod.requests, "post", lambda *a, **k: FakeResp(422))
    fwd.start()
    assert seg.admitir({"serial": 101})
    fwd.enqueue({"serial": 101})
    _esperar(fwd)
    assert vistos == [(101, 422)]


# --- H7: la recuperación no le quita la cola al vivo ---

def test_h7_recuperacion_usa_como_mucho_la_mitad_de_la_cola(tmp_path, isapi):
    cfg = Config(terminal_host=HOST, terminal_user="a", terminal_password="x", ha_webhook_url="",
                 audit_log_path=tmp_path / "a.log", backend_url="https://b/x", backend_secret="s",
                 backend_queue_maxsize=4)
    fwd = BackendForwarder(cfg, LOG)  # sin start(): la cola no se vacía
    seg = seguimiento(tmp_path, cursor=100)
    fwd.seguimiento = seg
    isapi(paginas=[("OK", [item(s) for s in range(101, 111)])])

    def destino(record):
        if not fwd.enqueue_recuperado(record, espera_max=0.05):
            raise RuntimeError("cola del backend ocupada")

    resumen = conexion(recuperador(seg, destino))
    assert resumen["resultado"] == rec.FALLIDA and resumen["encolados"] == 2
    assert seg.techo == 100
    # Lugar para el vivo: dos eventos más entran sin descarte.
    for s in (200, 201):
        assert seg.admitir({"serial": s})
        fwd.enqueue({"serial": s})
    assert fwd._dropped_count == 0
    assert seg.admitir({"serial": 103}) is True  # el que no entró quedó fallido (fuera de la puerta)


# --- H8: destino que falla después de admitir ---

def test_h8_destino_que_falla_deja_el_serial_fallido_no_colgado(tmp_path, isapi):
    isapi(paginas=[("OK", [item(s) for s in range(101, 104)])])
    seg = seguimiento(tmp_path, cursor=100)
    enviados: list[dict] = []

    def destino(record):
        if record["serial"] == 102:
            raise OSError("disco lleno")
        enviados.append(record)

    resumen = conexion(recuperador(seg, destino))
    assert resumen["resultado"] == rec.FALLIDA
    for r in enviados:
        seg.entregado(r)
    assert seg.cursor == 100  # corrida fallida: el techo queda; el 102 además frena
    assert seg.hay_fallidos
    enviados.clear()
    conexion(recuperador(seg, enviados.append))
    assert [r["serial"] for r in enviados] == [102, 103]  # se vuelve a pedir y se encola
    for r in enviados:
        seg.entregado(r)
    assert seg.cursor == 103 and not seg.hay_fallidos


# --- H9: no se puede crear el hilo ---

def test_h9_fallo_al_crear_el_hilo_no_tumba_el_stream_ni_bloquea_la_proxima(tmp_path, isapi, monkeypatch):
    isapi(paginas=[])
    seg = seguimiento(tmp_path, cursor=100)
    r = recuperador(seg, lambda x: None)
    start_real = threading.Thread.start
    fallas = {"n": 1}

    def start_que_falla(self):
        if self.name == "recuperacion" and fallas["n"]:
            fallas["n"] -= 1
            raise RuntimeError("can't start new thread")
        return start_real(self)

    monkeypatch.setattr(threading.Thread, "start", start_que_falla)
    assert r.lanzar() is False  # sin excepción hacia el stream
    assert seg.techo == 100  # el techo quedó abierto: nada se salta
    assert r.lanzar() is True  # la próxima conexión arranca normal
    _esperar_hilo(r)
    assert seg.techo is None


# --- H10: la escritura del estado no frena al stream ---

def test_h10_guardar_lento_no_bloquea_al_stream(tmp_path):
    seg = seguimiento(tmp_path, cursor=100)
    escribiendo, soltar = threading.Event(), threading.Event()
    guardar_real = seg.estado.guardar

    def guardar_lento(**kw):
        escribiendo.set()
        soltar.wait(5)
        return guardar_real(**kw)

    seg.estado.guardar = guardar_lento
    r = {"serial": 101}
    assert seg.admitir(r)
    hilo = threading.Thread(target=seg.entregado, args=(r,), daemon=True)  # el forwarder
    hilo.start()
    assert escribiendo.wait(5)
    hecho = threading.Event()

    def stream():
        seg.observar_vivo({"serial": 102, "device_mac": MAC})
        seg.admitir({"serial": 102})
        hecho.set()

    threading.Thread(target=stream, daemon=True).start()
    try:
        assert hecho.wait(1), "el stream quedó esperando al disco"
    finally:
        soltar.set()
        hilo.join(5)
    assert leer_estado(tmp_path)["cursor_serial"] == 101


# --- H12: la puerta no olvida seriales que la recuperación puede volver a pedir ---

def test_h12_puerta_retiene_seriales_por_encima_del_cursor(tmp_path):
    path = tmp_path / "face_state.json"
    path.write_text(json.dumps({"cursor_serial": 100, "terminal_mac": MAC}))
    seg = SeguimientoEntregas(EstadoPersistente(path, LOG), LOG, puerta_max=3)
    assert seg.admitir({"serial": 101})  # pendiente: frena el cursor en 100
    _entregar_en_vivo(seg, [102, 103, 104, 105, 106])
    assert seg.cursor == 100
    for s in (102, 103):  # salieron de la ventana de 3 pero siguen por encima del cursor
        assert seg.admitir({"serial": s, "recuperado": True}) is False
    seg.entregado({"serial": 101})
    assert seg.cursor == 106
    _entregar_en_vivo(seg, [107, 108, 109])  # al achicar, los retenidos ya pasados se sueltan
    assert seg._retenidos == set()


# --- H13: reset con entregas o corridas de la numeración vieja en vuelo ---

def test_h13_entrega_de_la_numeracion_vieja_tras_el_reset_no_mueve_el_cursor(tmp_path):
    seg = seguimiento(tmp_path, cursor=5000)
    viejo = {"serial": 5001, "major": 5, "device_ts": item(5001)["time"]}
    assert seg.admitir(viejo)  # en la cola del forwarder cuando el terminal se resetea
    seg.observar_vivo({"serial": 3, "device_mac": MAC})
    seg.entregado(viejo)
    assert seg.cursor == 0 and seg.ancla is None
    seg.cerrar_techo()
    assert seg.cursor == 0  # nada de la numeración vieja quedó como entregado


def test_h13_corrida_en_vuelo_durante_un_reset_no_toca_el_techo_nuevo(tmp_path, isapi):
    isapi(paginas=[("OK", [item(s) for s in range(5001, 5004)])])
    seg = seguimiento(tmp_path, cursor=5000)
    enviados: list[dict] = []

    def destino(record):
        enviados.append(record)
        if len(enviados) == 1:  # a mitad de la corrida, el stream ve el reset
            seg.observar_vivo({"serial": 2, "device_mac": MAC})

    r = recuperador(seg, destino)
    conexion(r)
    assert [x["serial"] for x in enviados] == [5001]  # lo demás de la época vieja no se admite
    assert seg.techo == 0  # la corrida vieja no lo liberó
    assert seg.cursor == 0


# --- H14: bloque JSON ilegible en el stream ---

def test_h14_bloque_json_ilegible_dispara_la_recuperacion(tmp_path, monkeypatch):
    fake = FakeISAPI(paginas=[])

    def al_lanzar(n):
        if n == 2:  # el bloque ilegible: el terminal ya registró 201 y 202
            fake.paginas = [("OK", [item(201), item(202)])]

    roto = b"--MIME_boundary\r\nContent-Type: application/json\r\n\r\n{\"eventType\": \"AccessCont"
    chunks = _como_stream([_ev_vivo(201)])[0].rsplit(b"--MIME_boundary\r\n", 1)[0]
    chunks += roto + b"\r\n" + _como_stream([_ev_vivo(203)])[0]
    posts, _ha, lanzados = _correr_listener(
        tmp_path, monkeypatch, estado={"cursor_serial": 200, "terminal_mac": MAC},
        conexiones=[[chunks]], fake=fake, al_lanzar=al_lanzar)
    assert len(lanzados) == 2  # la conexión + el bloque ilegible
    assert sorted(p["serial"] for p in posts) == [201, 202, 203]
    assert [p["serial"] for p in posts if p.get("recuperado")] == [202]


def test_h2_ancla_con_otro_formato_de_hora_no_reinicia(tmp_path, isapi):
    # Guarda: el mismo instante con y sin zona horaria no es "otra hora" (no hay reset).
    fake = isapi(paginas=[("OK", [item(s) for s in range(495, 503)])])
    sin_zona = datetime.fromisoformat(item(500)["time"]).replace(tzinfo=None).isoformat()
    seg = _seg_con_ancla(tmp_path, cursor=500, ancla=(500, sin_zona))
    enviados: list[dict] = []
    conexion(recuperador(seg, enviados.append))
    assert _desde(fake) == [501]
    assert [r["serial"] for r in enviados] == [501, 502]
