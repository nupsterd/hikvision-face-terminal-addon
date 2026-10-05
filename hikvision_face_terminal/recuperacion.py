"""Recuperación de eventos perdidos del DS-K1T344 vía ISAPI AcsEvent (#54, B6.2).

El alertStream solo entrega lo nuevo (y el buffer histórico con currentEvent=false se
descarta a propósito, §5.9.443). Todo lo que el terminal registra mientras el add-on está
caído o reconectando, lo que el backend no aceptó tras 3 intentos y lo que quedó en la cola
al reiniciar se perdía. Este módulo lo recupera del propio equipo:

- ``EstadoPersistente``: ``/config/face_state.json`` con ``cursor_serial``, ``terminal_mac``
  y ``updated_at``. Escritura atómica (tmp + fsync + rename); lectura tolerante.
- ``SeguimientoEntregas``: la puerta única por serial (ningún serial entra dos veces a la
  cola del forwarder en el proceso, venga del stream o de la recuperación) + el cursor:
  el mayor serial entregado con 2xx sin ningún serial pendiente o fallido por debajo.
- ``Recuperador``: después de cada conexión exitosa del stream, en un hilo aparte, pide a
  ``/ISAPI/AccessControl/AcsEvent`` todo lo posterior al cursor, lo reordena por serial, lo
  reconstruye con la forma del alertStream y lo pasa por el MISMO parser y el MISMO
  ``build_audit_record`` que el stream, con ``record["recuperado"] = True``.

Regla del diseño: un evento recuperado NUNCA dispara efectos en vivo. Acá eso significa que
nunca pasa por ``_maybe_emit_ha_webhook`` ni ``forward_to_ha``: solo audit + forwarder. El
backend (pv-backend PR #74) hace el resto.

Logs sin ``employee_no`` ni nombres: solo seriales, conteos y estados.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
import xml.etree.ElementTree as ET
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Optional

import requests
from requests.auth import HTTPDigestAuth

STATE_PATH_DEFAULT = Path("/config/face_state.json")

# Tamaño de la puerta por serial: los últimos N seriales admitidos a la cola.
PUERTA_MAX = 10_000

# Reset de fábrica: un serial en vivo tan por debajo del cursor es otra numeración.
RESET_UMBRAL = 1000

# Tope por corrida de recuperación.
TOPE_EVENTOS = 1000
TOPE_ANTIGUEDAD = timedelta(days=7)

# Paginación de AcsEvent.
MAX_RESULTS = 30
MAX_PAGINAS = 100  # 3000 ítems: margen sobre el tope de 1000 (la consulta se corta antes)

# Fin del rango de seriales en AcsEvent. Sondeo en el DS-K1T344 (prueba en hardware
# 2026-10-05): beginSerialNo sin endSerialNo ⇒ 400 {"subStatusCode": "badJsonContent",
# "errorMsg": "endSerialNo"}; endSerialNo 999999999 ⇒ 200; endSerialNo 4294967295 ⇒ 400
# (errorMsg "endSerialNo"). Se manda siempre 999999999.
SERIAL_FIN = 999_999_999

# major de AcsEvent: 0 = todos; si el equipo lo rechaza (400 con errorMsg sobre "major"),
# 5 (control de acceso).
MAJOR_TODOS = 0
MAJOR_ACCESO = 5

# Campos del ítem de AcsEvent que se copian al bloque AccessControllerEvent del stream.
# (major/minor se renombran a majorEventType/subEventType; time va a dateTime.)
_CAMPOS_ACE = (
    "serialNo",
    "employeeNoString",
    "name",
    "attendanceStatus",
    "currentVerifyMode",
    "cardType",
    "FaceRect",
    "mask",
    "userType",
    "label",
    "doorNo",
)


def normalizar_mac(valor: Any) -> Optional[str]:
    """MAC en el formato del ``macAddress`` del alertStream: minúsculas separadas por ':'.

    El stream entrega ``a4:d5:c2:75:fd:64``; deviceInfo puede usar mayúsculas o '-'.
    Devuelve ``None`` si el valor no es una MAC de 6 octetos.
    """
    if not isinstance(valor, str):
        return None
    hexa = valor.strip().lower().replace("-", ":").replace(".", "")
    partes = hexa.split(":") if ":" in hexa else [hexa[i:i + 2] for i in range(0, len(hexa), 2)]
    if len(partes) != 6 or not all(len(p) == 2 and all(c in "0123456789abcdef" for c in p) for p in partes):
        return None
    return ":".join(partes)


def mac_de_device_info(resp: requests.Response) -> Optional[str]:
    """MAC del cuerpo de ``/ISAPI/System/deviceInfo``: JSON o, si no, XML.

    El DS-K1T344 ignora ``?format=json`` y devuelve XML con namespace
    (``<DeviceInfo xmlns=...><macAddress>``): se busca el elemento cuyo tag termine en
    ``macAddress``, sin importar el namespace.
    """
    try:
        datos = resp.json()
    except ValueError:
        datos = None
    if isinstance(datos, dict):
        info = datos.get("DeviceInfo", datos)
        return normalizar_mac(info.get("macAddress") if isinstance(info, dict) else None)
    try:
        raiz = ET.fromstring(resp.content)
    except (ET.ParseError, TypeError, ValueError):
        return None
    for elem in raiz.iter():
        if isinstance(elem.tag, str) and elem.tag.endswith("macAddress"):
            return normalizar_mac(elem.text)
    return None


def serial_de(record: dict) -> Optional[int]:
    """``record["serial"]`` como int, o ``None`` (records ``kind=other`` no tienen)."""
    valor = record.get("serial")
    if isinstance(valor, bool) or not isinstance(valor, int):
        return None
    return valor


# ---------------------------------------------------------------------------
# Estado persistente
# ---------------------------------------------------------------------------

class EstadoPersistente:
    """``/config/face_state.json``: ``{cursor_serial, terminal_mac, updated_at}``.

    Lectura tolerante (ausente o corrupto ⇒ vacío + WARNING; nunca levanta). Escritura
    atómica: archivo temporal en el mismo directorio + ``fsync`` + ``os.replace``; un fallo
    de escritura se loguea y no corta nada (el próximo cambio vuelve a intentar).
    """

    def __init__(self, path: Path, log: logging.Logger):
        self.path = path
        self.log = log
        self._lock = threading.Lock()
        self.cursor_serial: Optional[int] = None
        self.terminal_mac: Optional[str] = None
        self.updated_at: Optional[str] = None
        self._cargar()

    def _cargar(self) -> None:
        try:
            datos = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self.log.warning("Estado de recuperación ausente (%s): arranque sin cursor.", self.path)
            return
        except (OSError, ValueError) as exc:
            self.log.warning(
                "Estado de recuperación ilegible (%s: %s): arranque sin cursor.", self.path, exc
            )
            return
        if not isinstance(datos, dict):
            self.log.warning("Estado de recuperación con forma inválida (%s): arranque sin cursor.", self.path)
            return
        cursor = datos.get("cursor_serial")
        if isinstance(cursor, int) and not isinstance(cursor, bool) and cursor >= 0:
            self.cursor_serial = cursor
        elif cursor is not None:
            self.log.warning("Estado de recuperación: cursor_serial inválido, se ignora.")
        self.terminal_mac = normalizar_mac(datos.get("terminal_mac"))
        updated = datos.get("updated_at")
        self.updated_at = updated if isinstance(updated, str) else None

    def guardar(self, *, cursor_serial: Optional[int], terminal_mac: Optional[str]) -> bool:
        with self._lock:
            self.cursor_serial = cursor_serial
            self.terminal_mac = terminal_mac
            self.updated_at = datetime.now().astimezone().isoformat()
            datos = {
                "cursor_serial": cursor_serial,
                "terminal_mac": terminal_mac,
                "updated_at": self.updated_at,
            }
            tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with tmp.open("w", encoding="utf-8") as f:
                    json.dump(datos, f)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, self.path)
                return True
            except OSError as exc:
                self.log.warning("No se pudo guardar el estado de recuperación (%s): %s", self.path, exc)
                try:
                    tmp.unlink()
                except OSError:
                    pass
                return False


# ---------------------------------------------------------------------------
# Puerta por serial + cursor
# ---------------------------------------------------------------------------

class SeguimientoEntregas:
    """Puerta única por serial y cursor de entregas, compartidos por stream, recuperación y
    forwarder (tres hilos: todo bajo un lock).

    Cursor efectivo = ``min(mayor_entregado, min(no_resueltos) - 1)``. ``no_resueltos`` son
    los seriales admitidos a la cola que todavía no tuvieron 2xx: los pendientes en la cola
    (un reinicio los pierde) y los fallidos (3 intentos agotados, 4xx o cola llena). Así el
    cursor persistido nunca pasa por encima de algo que el backend no confirmó, aunque el
    forwarder entregue fuera de orden (vivo encolado durante una recuperación).

    Un fallido sale de la puerta: la próxima recuperación lo vuelve a pedir y lo puede
    encolar. Los records sin serial no pasan por la puerta ni mueven el cursor.

    Techo por conexión: cada corrida de recuperación con cursor abre un techo en el cursor
    efectivo del momento (``abrir_techo``). Mientras está abierto, las entregas en vivo no
    suben el cursor por encima de seriales que la recuperación todavía no vio. Se libera
    solo cuando la corrida se completa (``cerrar_techo``); si se corta por tope sube hasta
    el mayor serial admitido (``subir_techo``); si falla (sin MAC, 401, error) queda donde
    estaba. Vive en memoria: tras un reinicio el cursor persistido ya quedó congelado.
    """

    def __init__(self, estado: EstadoPersistente, log: logging.Logger, puerta_max: int = PUERTA_MAX):
        self.estado = estado
        self.log = log
        self._lock = threading.Lock()
        self._puerta_max = puerta_max
        self._vistos: set[int] = set()
        self._orden: deque[int] = deque()
        self._no_resueltos: set[int] = set()
        self._mayor_entregado: Optional[int] = estado.cursor_serial
        self._mac: Optional[str] = estado.terminal_mac
        self._cursor_persistido: Optional[int] = estado.cursor_serial
        self._techo: Optional[int] = None

    # --- lectura -----------------------------------------------------------

    @property
    def cursor(self) -> Optional[int]:
        with self._lock:
            return self._cursor_efectivo()

    @property
    def mac(self) -> Optional[str]:
        with self._lock:
            return self._mac

    @property
    def techo(self) -> Optional[int]:
        with self._lock:
            return self._techo

    def _cursor_efectivo(self) -> Optional[int]:
        tope = min(self._no_resueltos) - 1 if self._no_resueltos else None
        if self._mayor_entregado is None:
            cursor = tope
        elif tope is None:
            cursor = self._mayor_entregado
        else:
            cursor = min(self._mayor_entregado, tope)
        if cursor is not None and self._techo is not None:
            cursor = min(cursor, self._techo)
        return cursor

    # --- techo por conexión ------------------------------------------------

    def abrir_techo(self) -> Optional[int]:
        """Inicio de una corrida con cursor: techo = cursor efectivo actual (lo devuelve)."""
        with self._lock:
            self._techo = self._cursor_efectivo()
            return self._techo

    def subir_techo(self, serial: Optional[int]) -> None:
        """Corrida cortada por tope: techo = mayor serial admitido (None ⇒ se mantiene)."""
        if serial is None:
            return
        with self._lock:
            if self._techo is None or serial > self._techo:
                self._techo = serial
            self._persistir_si_cambia()

    def cerrar_techo(self) -> None:
        """Corrida completa: se libera el techo (los admitidos siguen frenando por pendientes)."""
        with self._lock:
            self._techo = None
            self._persistir_si_cambia()

    # --- puerta ------------------------------------------------------------

    def admitir(self, record: dict) -> bool:
        """True si el record puede entrar a la cola. Marca su serial como visto y pendiente."""
        serial = serial_de(record)
        if serial is None:
            return True
        with self._lock:
            if serial in self._vistos:
                return False
            self._vistos.add(serial)
            self._orden.append(serial)
            while len(self._orden) > self._puerta_max:
                self._vistos.discard(self._orden.popleft())
            self._no_resueltos.add(serial)
            return True

    # --- resultado del forwarder -------------------------------------------

    def entregado(self, record: dict) -> None:
        serial = serial_de(record)
        if serial is None:
            return
        with self._lock:
            self._no_resueltos.discard(serial)
            if self._mayor_entregado is None or serial > self._mayor_entregado:
                self._mayor_entregado = serial
            self._persistir_si_cambia()

    def fallido(self, record: dict) -> None:
        serial = serial_de(record)
        if serial is None:
            return
        with self._lock:
            self._no_resueltos.add(serial)
            self._vistos.discard(serial)  # la recuperación lo puede volver a encolar
            self._persistir_si_cambia()
        self.log.warning("Serial %s sin entregar: el cursor no lo pasa hasta recuperarlo.", serial)

    def abandonar(self, serials: list[int]) -> None:
        """Seriales que la recuperación descartó por tope: dejan de frenar el cursor."""
        if not serials:
            return
        with self._lock:
            for s in serials:
                self._no_resueltos.discard(s)
            self._persistir_si_cambia()

    # --- stream en vivo ----------------------------------------------------

    def observar_vivo(self, record: dict) -> None:
        """MAC del último evento en vivo + detección de reset de fábrica (serial muy bajo)."""
        mac = normalizar_mac(record.get("device_mac"))
        serial = serial_de(record)
        with self._lock:
            cambio = False
            if mac is not None and mac != self._mac:
                self._mac = mac
                cambio = True
            cursor = self._cursor_efectivo()
            if serial is not None and cursor is not None and serial < cursor - RESET_UMBRAL:
                self.log.warning(
                    "Serial en vivo %s muy por debajo del cursor %s (posible reset de fábrica): "
                    "cursor reiniciado.", serial, cursor,
                )
                self._mayor_entregado = serial
                self._no_resueltos.clear()
                self._vistos.clear()
                self._orden.clear()
                self._techo = None  # el techo era de la numeración anterior
                cambio = True
            if cambio:
                self._persistir(forzar=True)

    @property
    def sin_cursor(self) -> bool:
        """True si nunca hubo cursor (primer arranque sin estado y nada entregado aún)."""
        with self._lock:
            return self._mayor_entregado is None

    def inicializar(self, serial: int) -> bool:
        """Primer arranque: fija el cursor en el serial más reciente del terminal SIN recuperar
        nada. No pisa un cursor que ya se fijó con una entrega en vivo."""
        with self._lock:
            if self._mayor_entregado is not None:
                return False
            self._mayor_entregado = serial
            self._persistir(forzar=True)
            return True

    def fijar_mac(self, mac: str) -> None:
        with self._lock:
            if mac != self._mac:
                self._mac = mac
                self._persistir(forzar=True)

    # --- persistencia ------------------------------------------------------

    def _persistir_si_cambia(self) -> None:
        self._persistir(forzar=False)

    def _persistir(self, *, forzar: bool) -> None:
        cursor = self._cursor_efectivo()
        if not forzar and cursor == self._cursor_persistido:
            return
        if self.estado.guardar(cursor_serial=cursor, terminal_mac=self._mac):
            self._cursor_persistido = cursor


# ---------------------------------------------------------------------------
# Reconstrucción
# ---------------------------------------------------------------------------

def reconstruir_evento(item: dict, terminal_host: str, mac: str) -> dict:
    """Ítem de ``AcsEvent.InfoList`` ⇒ evento con la forma del alertStream.

    ``dateTime`` es el ``time`` del ítem copiado TAL CUAL (mismo formato que el stream,
    verificado en el terminal): el backend compara ``device_ts`` como texto.
    """
    ace: dict[str, Any] = {
        "majorEventType": item.get("major"),
        "subEventType": item.get("minor"),
    }
    for campo in _CAMPOS_ACE:
        if campo in item:
            ace[campo] = item[campo]
    return {
        "ipAddress": terminal_host,
        "macAddress": mac,
        "dateTime": item.get("time"),
        "eventType": "AccessControllerEvent",
        "AccessControllerEvent": ace,
    }


# ---------------------------------------------------------------------------
# Recuperador
# ---------------------------------------------------------------------------

class _Abortar(Exception):
    """Corta la corrida sin reintentos (401, respuesta inválida, error de red)."""


class Recuperador:
    """Corre la recuperación en un hilo aparte después de cada conexión exitosa del stream.

    ``construir_record(evento) -> record | None`` es el MISMO camino del stream
    (``parse_event_block`` + ``build_audit_record``), inyectado por el listener para no
    duplicarlo ni importarlo en círculo. ``destino(record)`` escribe el audit y encola en el
    forwarder (nunca HA).
    """

    def __init__(
        self,
        *,
        terminal_host: str,
        terminal_user: str,
        terminal_password: str,
        seguimiento: SeguimientoEntregas,
        construir_record: Callable[[dict], Optional[dict]],
        destino: Callable[[dict], None],
        log: logging.Logger,
        ahora: Callable[[], datetime] = lambda: datetime.now().astimezone(),
    ):
        self.host = terminal_host
        self.auth = HTTPDigestAuth(terminal_user, terminal_password)
        self.seguimiento = seguimiento
        self.construir_record = construir_record
        self.destino = destino
        self.log = log
        self.ahora = ahora
        self._hilo: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._major: Optional[int] = None  # None = todavía no se probó major=0

    # --- disparo -----------------------------------------------------------

    def lanzar(self) -> bool:
        """Arranca una corrida en un hilo daemon. False si ya hay una en curso."""
        with self._lock:
            if self._hilo is not None and self._hilo.is_alive():
                self.log.info("Recuperación anterior todavía en curso: no se lanza otra.")
                return False
            self._hilo = threading.Thread(target=self._correr_seguro, name="recuperacion", daemon=True)
            self._hilo.start()
            return True

    def _correr_seguro(self) -> None:
        try:
            self.correr()
        except Exception as exc:  # nunca tumbar el proceso
            self.log.error("Recuperación falló: %s", exc)

    # --- HTTP --------------------------------------------------------------

    def _http(self, metodo: str, path: str, body: Optional[dict] = None) -> requests.Response:
        url = f"https://{self.host}{path}"
        try:
            resp = requests.request(
                metodo,
                url,
                json=body,
                auth=self.auth,
                headers={"Connection": "close"},  # §5.9.426
                verify=False,  # §5.9.427
                timeout=(10, 15),
            )
        except requests.RequestException as exc:
            raise _Abortar(f"error de red en {path}: {exc}") from exc
        if resp.status_code == 401:
            # §5.9.574: un reintento con credencial mala puede bloquear la cuenta 30 min.
            self.log.error(
                "401 en %s: la recuperación se suspende en esta conexión (sin reintento).", path
            )
            raise _Abortar("401")
        return resp

    def _mac_terminal(self) -> Optional[str]:
        mac = self.seguimiento.mac
        if mac is not None:
            return mac
        # Sin ?format=json: el DS-K1T344 lo ignora y responde XML igual.
        resp = self._http("GET", "/ISAPI/System/deviceInfo")
        mac = mac_de_device_info(resp) if resp.status_code == 200 else None
        if mac is None:
            self.log.warning(
                "Sin MAC del terminal (deviceInfo HTTP %s): no se recupera en esta conexión.",
                resp.status_code,
            )
            return None
        self.seguimiento.fijar_mac(mac)
        return mac

    def _pedir(self, cond: dict) -> dict:
        """Un POST a AcsEvent con ``cond`` + el ``major`` vigente. Devuelve el bloque
        ``AcsEvent``. Si el equipo rechaza ``major=0`` la primera vez (400 con un ``errorMsg``
        que menciona ``major``), cae a ``major=5`` y lo recuerda para el resto del proceso
        (log una sola vez). Cualquier otro rechazo aborta la corrida (el techo protege)."""
        while True:
            major = self._major if self._major is not None else MAJOR_TODOS
            body = {"AcsEventCond": {**cond, "major": major, "minor": 0}}
            resp = self._http("POST", "/ISAPI/AccessControl/AcsEvent?format=json", body)
            acs = self._cuerpo(resp)
            if acs is not None:
                break
            error = self._error_msg(resp)
            if self._major is None and resp.status_code == 400 and "major" in error.lower():
                self.log.warning(
                    "AcsEvent rechazó major=0 (HTTP 400, errorMsg %r): se recupera solo major=5.",
                    error,
                )
                self._major = MAJOR_ACCESO
                continue
            detalle = f", errorMsg {error!r}" if error else ""
            raise _Abortar(f"respuesta inválida de AcsEvent (HTTP {resp.status_code}{detalle})")
        if self._major is None:
            self._major = major
            self.log.info("AcsEvent acepta major=%s: se recupera con ese filtro.", major)
        return acs

    @staticmethod
    def _cuerpo(resp: requests.Response) -> Optional[dict]:
        if resp.status_code != 200:
            return None
        try:
            datos = resp.json()
        except ValueError:
            return None
        acs = datos.get("AcsEvent") if isinstance(datos, dict) else None
        return acs if isinstance(acs, dict) else None

    @staticmethod
    def _error_msg(resp: requests.Response) -> str:
        """``errorMsg`` del cuerpo de un rechazo ISAPI (texto del equipo, sin datos personales)."""
        try:
            datos = resp.json()
        except ValueError:
            return ""
        error = datos.get("errorMsg") if isinstance(datos, dict) else None
        return error[:200] if isinstance(error, str) else ""

    @staticmethod
    def _lista(acs: dict) -> list[dict]:
        lista = acs.get("InfoList") or []
        return [i for i in lista if isinstance(i, dict)] if isinstance(lista, list) else []

    def _consultar(self, desde: int) -> tuple[list[dict], int, bool]:
        """Todas las páginas desde ``desde``. Devuelve (ítems, páginas, cortado_por_tope)."""
        search_id = uuid.uuid4().hex
        items: list[dict] = []
        paginas = 0
        posicion = 0
        while paginas < MAX_PAGINAS:
            acs = self._pedir({
                "searchID": search_id,
                "searchResultPosition": posicion,
                "maxResults": MAX_RESULTS,
                "beginSerialNo": desde,
                "endSerialNo": SERIAL_FIN,
            })
            paginas += 1
            lista = self._lista(acs)
            items.extend(lista)
            n = acs.get("numOfMatches")
            n = n if isinstance(n, int) and n > 0 else len(lista)
            if acs.get("responseStatusStrg") != "MORE" or n == 0:
                return items, paginas, False
            if len(items) > TOPE_EVENTOS:
                return items, paginas, True
            posicion += n
        return items, paginas, True

    def _serial_mas_reciente(self) -> Optional[int]:
        """Serial del evento más reciente de los últimos 7 días (``timeReverseOrder``)."""
        ahora = self.ahora()
        acs = self._pedir({
            "searchID": uuid.uuid4().hex,
            "searchResultPosition": 0,
            "maxResults": 1,
            "timeReverseOrder": True,
            "startTime": (ahora - TOPE_ANTIGUEDAD).isoformat(timespec="seconds"),
            "endTime": (ahora + timedelta(days=1)).isoformat(timespec="seconds"),
        })
        seriales = [
            i["serialNo"] for i in self._lista(acs)
            if isinstance(i.get("serialNo"), int) and not isinstance(i.get("serialNo"), bool)
        ]
        return max(seriales) if seriales else None

    def _inicializar(self, resumen: dict) -> dict:
        """Punto 8: primer arranque sin estado ⇒ cursor = serial más reciente, sin recuperar."""
        try:
            serial = self._serial_mas_reciente()
        except _Abortar as exc:
            self.log.warning(
                "Inicialización del cursor falló (%s): se fija con el primer record entregado.", exc
            )
            return resumen
        if serial is None:
            self.log.warning(
                "Inicialización del cursor: el terminal no tiene eventos en 7 días; se fija "
                "con el primer record entregado."
            )
            return resumen
        if self.seguimiento.inicializar(serial):
            self.log.info(
                "Cursor inicializado desde el terminal en serial %s (sin recuperar historia).", serial
            )
        resumen["cursor_final"] = self.seguimiento.cursor
        return resumen

    # --- corrida -----------------------------------------------------------

    def correr(self) -> dict:
        """Una corrida completa (sincrónica; ``lanzar`` la pone en un hilo).

        Con cursor abre el techo por conexión: solo una corrida completa lo libera; una
        cortada por tope lo sube al mayor serial admitido; una fallida lo deja donde estaba.
        """
        resumen: dict[str, Any] = {"desde": None, "encolados": 0, "ya_vistos": 0, "paginas": 0,
                                   "descartados": 0, "cursor_final": self.seguimiento.cursor}
        if self.seguimiento.sin_cursor:
            return self._inicializar(resumen)
        cursor = self.seguimiento.abrir_techo()
        resumen["cursor_final"] = cursor
        if cursor is None:  # imposible con sin_cursor False; defensivo
            return resumen
        desde = cursor + 1
        resumen["desde"] = desde
        try:
            mac = self._mac_terminal()
            if mac is None:
                return resumen
            items, paginas, cortado = self._consultar(desde)
        except _Abortar as exc:
            self.log.error("Recuperación abortada desde serial %s: %s", desde, exc)
            return resumen
        resumen["paginas"] = paginas

        validos = [i for i in items if isinstance(i.get("serialNo"), int) and not isinstance(i.get("serialNo"), bool)]
        validos.sort(key=lambda i: i["serialNo"])  # AcsEvent ordena por hora, no por serial

        limite = self.ahora() - TOPE_ANTIGUEDAD
        viejos: list[int] = []
        recientes: list[dict] = []
        for item in validos:
            try:
                ts = datetime.fromisoformat(item.get("time"))
            except (TypeError, ValueError):
                ts = None
            if ts is not None and ts.tzinfo is not None and ts < limite:
                viejos.append(item["serialNo"])
            else:
                recientes.append(item)
        sobrantes = [i["serialNo"] for i in recientes[TOPE_EVENTOS:]]
        recientes = recientes[:TOPE_EVENTOS]
        if viejos or sobrantes or cortado:
            self.log.warning(
                "Recuperación con tope: %d con más de 7 días y %d por encima de %d descartados%s.",
                len(viejos), len(sobrantes), TOPE_EVENTOS,
                " (consulta cortada; el resto queda para la próxima conexión)" if cortado else "",
            )
        resumen["descartados"] = len(viejos) + len(sobrantes)
        # Los más viejos que 7 días se abandonan (dejan de frenar el cursor); los sobrantes por
        # encima del tope nunca se encolaron y quedan para la próxima corrida.
        self.seguimiento.abandonar(viejos)

        mayor_admitido: Optional[int] = None
        for item in recientes:
            record = self.construir_record(reconstruir_evento(item, self.host, mac))
            if record is None:
                continue
            record["recuperado"] = True
            if not self.seguimiento.admitir(record):
                resumen["ya_vistos"] += 1
                continue
            self.destino(record)
            resumen["encolados"] += 1
            mayor_admitido = serial_de(record)

        if sobrantes or cortado:
            self.seguimiento.subir_techo(mayor_admitido)
        else:
            self.seguimiento.cerrar_techo()

        resumen["cursor_final"] = self.seguimiento.cursor
        self.log.info(
            "Recuperación: desde serial %s, %d encolados, %d ya vistos, %d descartados, "
            "%d páginas, cursor %s.",
            desde, resumen["encolados"], resumen["ya_vistos"], resumen["descartados"],
            resumen["paginas"], resumen["cursor_final"],
        )
        return resumen
