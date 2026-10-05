"""Recuperación de eventos perdidos del DS-K1T344 vía ISAPI AcsEvent (#54, B6.2).

El alertStream solo entrega lo nuevo (y el buffer histórico con currentEvent=false se
descarta a propósito, §5.9.443). Todo lo que el terminal registra mientras el add-on está
caído o reconectando, lo que el backend no aceptó tras 3 intentos y lo que quedó en la cola
al reiniciar se perdía. Este módulo lo recupera del propio equipo:

- ``EstadoPersistente``: ``/config/face_state.json`` con ``cursor_serial``, ``terminal_mac``,
  el ancla de numeración y ``updated_at``. Escritura atómica (tmp + fsync + rename);
  lectura tolerante.
- ``SeguimientoEntregas``: la puerta única por serial (ningún serial entra dos veces a la
  cola del forwarder en el proceso, venga del stream o de la recuperación) + el cursor:
  el mayor serial entregado con 2xx sin ningún serial pendiente o fallido por debajo.
- ``Recuperador``: después de cada conexión exitosa del stream, en un hilo aparte, pide a
  ``/ISAPI/AccessControl/AcsEvent`` lo posterior al cursor por ventanas de seriales, lo
  reordena por serial, lo reconstruye con la forma del alertStream y lo pasa por el MISMO
  parser y el MISMO ``build_audit_record`` que el stream, con ``record["recuperado"] =
  True``. Si queda algo pendiente (corrida cortada o fallida, entregas fallidas) vuelve a
  correr solo, con backoff, sin esperar a otra reconexión.

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
import time
import uuid
import xml.etree.ElementTree as ET
from collections import OrderedDict
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

# Tope por corrida de recuperación: una ventana de TOPE_EVENTOS seriales consecutivos
# (a lo sumo TOPE_EVENTOS eventos). Más allá de la ventana, la corrida siguiente.
TOPE_EVENTOS = 1000
TOPE_ANTIGUEDAD = timedelta(days=7)

# Paginación de AcsEvent.
MAX_RESULTS = 30
MAX_PAGINAS = 100  # una ventana de 1000 son ≤ 34 páginas; más es una respuesta anómala

# Reintento sin reconexión (corrida fallida o entregas fallidas): backoff exponencial.
REINTENTO_BASE = 30.0
REINTENTO_MAX = 900.0
# Corrida cortada: antes de la ventana siguiente, esperar a que el forwarder vacíe lo
# encolado (como mucho esto, en segundos).
ESPERA_COLA_CORTE = 60.0

# Rechazo definitivo del backend: 4xx que no se arreglan reintentando el mismo payload.
# 401/403/404/408/429 y el resto son de configuración o transitorios: se reintentan siempre.
RECHAZO_DEFINITIVO = frozenset({400, 409, 410, 413, 415, 422})
RECHAZOS_MIN = 3
RECHAZO_PLAZO = 24 * 3600.0  # segundos desde el primer rechazo de ese serial

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


def _mismo_instante(a: Any, b: Any) -> bool:
    """Dos ``time``/``dateTime`` del terminal iguales: mismo texto o mismo instante ISO 8601.
    Si uno viene sin zona horaria se compara la hora de reloj: una diferencia de formato
    entre el stream y AcsEvent nunca se confunde con otro evento (eso dispararía un reset)."""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    if a == b:
        return True
    try:
        da, db = datetime.fromisoformat(a), datetime.fromisoformat(b)
    except ValueError:
        return False
    if da.tzinfo is None or db.tzinfo is None:
        return da.replace(tzinfo=None) == db.replace(tzinfo=None)
    return da == db


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
    """``/config/face_state.json``: ``{cursor_serial, terminal_mac, ancla_serial, ancla_ts,
    updated_at}``.

    Lectura tolerante (ausente o corrupto ⇒ vacío + WARNING; nunca levanta). Escritura
    atómica: archivo temporal en el mismo directorio + ``fsync`` + ``os.replace``; un fallo
    de escritura se loguea y no corta nada (el próximo cambio vuelve a intentar). Un corte de
    energía a mitad de escritura deja el archivo anterior entero (cursor más viejo ⇒ solo
    re-envíos que el backend absorbe como duplicate).
    """

    def __init__(self, path: Path, log: logging.Logger):
        self.path = path
        self.log = log
        self._lock = threading.Lock()
        self.cursor_serial: Optional[int] = None
        self.terminal_mac: Optional[str] = None
        self.ancla: Optional[tuple[int, str]] = None
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
        ancla_serial, ancla_ts = datos.get("ancla_serial"), datos.get("ancla_ts")
        if isinstance(ancla_serial, int) and not isinstance(ancla_serial, bool) and isinstance(ancla_ts, str):
            self.ancla = (ancla_serial, ancla_ts)
        updated = datos.get("updated_at")
        self.updated_at = updated if isinstance(updated, str) else None

    def guardar(self, *, cursor_serial: Optional[int], terminal_mac: Optional[str],
                ancla: Optional[tuple[int, str]] = None) -> bool:
        with self._lock:
            self.cursor_serial = cursor_serial
            self.terminal_mac = terminal_mac
            self.ancla = ancla
            self.updated_at = datetime.now().astimezone().isoformat()
            datos = {
                "cursor_serial": cursor_serial,
                "terminal_mac": terminal_mac,
                "ancla_serial": ancla[0] if ancla else None,
                "ancla_ts": ancla[1] if ancla else None,
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

    Cursor efectivo = ``min(mayor_entregado, min(no_resueltos) - 1, techo)``. ``no_resueltos``
    son los seriales admitidos a la cola que todavía no tuvieron 2xx: los pendientes en la
    cola (un reinicio los pierde) y los fallidos (3 intentos agotados, 4xx o cola llena). Así
    el cursor persistido nunca pasa por encima de algo que el backend no confirmó, aunque el
    forwarder entregue fuera de orden (vivo encolado durante una recuperación).

    Un fallido sale de la puerta: la próxima recuperación lo vuelve a pedir y lo puede
    encolar (``al_fallar`` avisa al recuperador para que no espere a otra reconexión). Los
    records sin serial no pasan por la puerta ni mueven el cursor. Un 2xx o un fallo de un
    serial que no está pendiente (admitido antes de un reset de fábrica) se ignora.

    ``mayor_entregado`` sube con todo serial procesado en estado final: entregado (2xx),
    abandonado por antigüedad, sin record o rechazado en forma definitiva por el backend
    (``resolver_sin_envio``).

    Puerta: los últimos ``puerta_max`` seriales admitidos; uno más viejo que siga por encima
    del cursor no se olvida (la recuperación lo podría volver a pedir).

    Techo por conexión: cada conexión del stream con cursor abre un techo en el cursor
    efectivo del momento (``abrir_techo``, desde ``Recuperador.lanzar`` en el hilo del stream,
    antes de leer eventos). Mientras está abierto, las entregas en vivo no suben el cursor
    por encima de seriales que la recuperación todavía no vio. Se libera solo cuando la
    corrida se completa (``cerrar_techo``); si se corta por tope sube hasta el fin de la
    ventana procesada (``subir_techo``); si falla queda donde estaba. Vive en memoria: tras
    un reinicio el cursor persistido ya quedó congelado.

    Época: un reset de fábrica (``reiniciar_numeracion``) la incrementa; lo que una corrida
    empezada antes intente admitir, resolver o hacer con el techo se ignora.

    Ancla: serial y hora del último evento de acceso (major 5) entregado con el serial más
    alto. Si el terminal ya no tiene ese serial con esa hora, la numeración cambió.

    La escritura del estado se hace FUERA del lock: el stream nunca espera un ``fsync``.
    """

    def __init__(self, estado: EstadoPersistente, log: logging.Logger, puerta_max: int = PUERTA_MAX):
        self.estado = estado
        self.log = log
        self._lock = threading.Lock()
        self._cambio = threading.Condition(self._lock)
        self._puerta_max = puerta_max
        self._vistos: OrderedDict[int, None] = OrderedDict()
        self._retenidos: set[int] = set()  # salieron de la ventana de la puerta, siguen > cursor
        self._no_resueltos: set[int] = set()
        self._fallidos: set[int] = set()
        self._rechazos: dict[int, tuple[int, float]] = {}  # serial ⇒ (cantidad, primer rechazo)
        self._mayor_entregado: Optional[int] = estado.cursor_serial
        self._mac: Optional[str] = estado.terminal_mac
        self._ancla: Optional[tuple[int, str]] = estado.ancla
        self._techo: Optional[int] = None
        self._epoca = 0
        # Persistencia: la última foto encolada para escribir y la última escrita.
        self._ultima_foto: Optional[tuple] = (estado.cursor_serial, estado.terminal_mac, estado.ancla)
        self._version = 0
        self._escrita = 0
        self._escritura = threading.Lock()
        self.al_fallar: Optional[Callable[[], None]] = None
        self.reloj: Callable[[], float] = time.monotonic

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

    @property
    def epoca(self) -> int:
        with self._lock:
            return self._epoca

    @property
    def ancla(self) -> Optional[tuple[int, str]]:
        with self._lock:
            return self._ancla

    @property
    def hay_fallidos(self) -> bool:
        with self._lock:
            return bool(self._fallidos)

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

    def esperar_cola(self, timeout: float) -> bool:
        """Espera (como mucho ``timeout``) a que no quede nada encolado sin resolver
        (los fallidos no cuentan: esperan a la próxima corrida). True si se vació."""
        with self._cambio:
            return self._cambio.wait_for(lambda: not (self._no_resueltos - self._fallidos), timeout)

    # --- techo por conexión ------------------------------------------------

    def abrir_techo(self) -> Optional[int]:
        """Conexión nueva del stream: techo = min(techo abierto, cursor efectivo). Nunca sube
        un techo ya abierto. Sin cursor (primer arranque) no abre nada. Devuelve el techo."""
        with self._lock:
            if self._mayor_entregado is None:
                return self._techo
            cursor = self._cursor_efectivo()  # ya acotado por el techo abierto, si lo hay
            if cursor is not None:
                self._techo = cursor if self._techo is None else min(self._techo, cursor)
            return self._techo

    def subir_techo(self, serial: Optional[int], epoca: Optional[int] = None) -> None:
        """Corrida cortada por tope: techo = hasta dónde se procesó (None ⇒ se mantiene)."""
        if serial is None:
            return
        with self._lock:
            if epoca is not None and epoca != self._epoca:
                return
            if self._techo is None or serial > self._techo:
                self._techo = serial
            foto = self._foto_si_cambia()
        self._escribir(foto)

    def cerrar_techo(self, epoca: Optional[int] = None) -> None:
        """Corrida completa: se libera el techo (los admitidos siguen frenando por pendientes)."""
        with self._lock:
            if epoca is not None and epoca != self._epoca:
                return
            self._techo = None
            foto = self._foto_si_cambia()
        self._escribir(foto)

    # --- puerta ------------------------------------------------------------

    def admitir(self, record: dict, epoca: Optional[int] = None) -> bool:
        """True si el record puede entrar a la cola. Marca su serial como visto y pendiente.
        Con ``epoca`` distinta de la vigente (corrida de antes de un reset) no admite."""
        serial = serial_de(record)
        if serial is None:
            return True
        with self._lock:
            if epoca is not None and epoca != self._epoca:
                return False
            if serial in self._vistos or serial in self._retenidos:
                return False
            self._vistos[serial] = None
            if len(self._vistos) > self._puerta_max:
                self._achicar_puerta()
            self._no_resueltos.add(serial)
            self._fallidos.discard(serial)
            return True

    def _achicar_puerta(self) -> None:
        cursor = self._cursor_efectivo()
        while len(self._vistos) > self._puerta_max:
            viejo, _ = self._vistos.popitem(last=False)
            if cursor is not None and viejo > cursor:
                self._retenidos.add(viejo)
        if cursor is not None and self._retenidos:
            self._retenidos = {s for s in self._retenidos if s > cursor}

    # --- resultado del forwarder -------------------------------------------

    def entregado(self, record: dict) -> None:
        serial = serial_de(record)
        if serial is None:
            return
        with self._lock:
            if serial not in self._no_resueltos:
                return  # admitido antes de un reset de fábrica: otra numeración
            self._no_resueltos.discard(serial)
            self._fallidos.discard(serial)
            self._rechazos.pop(serial, None)
            if self._mayor_entregado is None or serial > self._mayor_entregado:
                self._mayor_entregado = serial
                device_ts = record.get("device_ts")
                if record.get("major") == MAJOR_ACCESO and isinstance(device_ts, str):
                    self._ancla = (serial, device_ts)
            self._cambio.notify_all()
            foto = self._foto_si_cambia()
        self._escribir(foto)

    def fallido(self, record: dict) -> None:
        serial = serial_de(record)
        if serial is None:
            return
        with self._lock:
            if serial not in self._no_resueltos:
                return  # admitido antes de un reset de fábrica: otra numeración
            self._fallidos.add(serial)
            self._vistos.pop(serial, None)  # la recuperación lo puede volver a encolar
            self._retenidos.discard(serial)
            self._cambio.notify_all()
            foto = self._foto_si_cambia()
        self._escribir(foto)
        self.log.warning("Serial %s sin entregar: el cursor no lo pasa hasta recuperarlo.", serial)
        if self.al_fallar is not None:
            self.al_fallar()

    def rechazado(self, record: dict, status: int) -> None:
        """4xx del backend. Uno de ``RECHAZO_DEFINITIVO`` repetido al menos ``RECHAZOS_MIN``
        veces y durante al menos ``RECHAZO_PLAZO`` se da por resuelto (si no, el cursor
        quedaría congelado para siempre por un payload que el backend nunca va a aceptar);
        cualquier otro 4xx es un fallido común."""
        serial = serial_de(record)
        if serial is None or status not in RECHAZO_DEFINITIVO:
            self.fallido(record)
            return
        with self._lock:
            if serial not in self._no_resueltos:
                return
            ahora = self.reloj()
            cantidad, primero = self._rechazos.get(serial, (0, ahora))
            cantidad += 1
            self._rechazos[serial] = (cantidad, primero)
            definitivo = cantidad >= RECHAZOS_MIN and ahora - primero >= RECHAZO_PLAZO
        if not definitivo:
            self.fallido(record)
            return
        self.log.error(
            "Serial %s rechazado por el backend (HTTP %s) %d veces en %.0f h: se da por "
            "resuelto sin entregar.", serial, status, cantidad, (ahora - primero) / 3600,
        )
        self.resolver_sin_envio([serial])

    def resolver_sin_envio(self, serials: list[int], epoca: Optional[int] = None) -> None:
        """Seriales en estado final sin entrega (abandonados por antigüedad, sin record o
        rechazados en forma definitiva): cuentan como procesados igual que un 2xx. Dejan de
        frenar el cursor y lo suben hasta el mayor de ellos; un pendiente por debajo y el
        techo lo siguen limitando."""
        if not serials:
            return
        with self._lock:
            if epoca is not None and epoca != self._epoca:
                return
            for s in serials:
                self._no_resueltos.discard(s)
                self._fallidos.discard(s)
                self._rechazos.pop(s, None)
            mayor = max(serials)
            if self._mayor_entregado is None or mayor > self._mayor_entregado:
                self._mayor_entregado = mayor
            self._cambio.notify_all()
            foto = self._foto_si_cambia()
        self._escribir(foto)

    def abandonar(self, serials: list[int], epoca: Optional[int] = None) -> None:
        """Seriales que la recuperación descartó por antigüedad (más de 7 días)."""
        self.resolver_sin_envio(serials, epoca)

    # --- stream en vivo ----------------------------------------------------

    def observar_vivo(self, record: dict) -> bool:
        """MAC del último evento en vivo + detección de reset de fábrica (serial muy bajo).
        True si detectó un reset: el llamador tiene que lanzar una recuperación."""
        mac = normalizar_mac(record.get("device_mac"))
        serial = serial_de(record)
        reset = False
        with self._lock:
            cambio = False
            if mac is not None and mac != self._mac:
                self._mac = mac
                cambio = True
            cursor = self._cursor_efectivo()
            if serial is not None and cursor is not None and serial < cursor - RESET_UMBRAL:
                self.log.warning(
                    "Serial en vivo %s muy por debajo del cursor %s (posible reset de fábrica): "
                    "se recupera la numeración nueva desde 1.", serial, cursor,
                )
                self._reiniciar_bajo_lock()
                reset = cambio = True
            foto = self._foto(forzar=True) if cambio else None
        self._escribir(foto)
        return reset

    def reiniciar_numeracion(self) -> int:
        """Reset de fábrica detectado por la recuperación: cursor y techo en 0, puerta y
        pendientes limpios, época nueva (la devuelve)."""
        with self._lock:
            self._reiniciar_bajo_lock()
            epoca = self._epoca
            foto = self._foto(forzar=True)
        self._escribir(foto)
        return epoca

    def _reiniciar_bajo_lock(self) -> None:
        self._epoca += 1
        self._mayor_entregado = 0
        self._techo = 0
        self._ancla = None
        self._no_resueltos.clear()
        self._fallidos.clear()
        self._rechazos.clear()
        self._vistos.clear()
        self._retenidos.clear()
        self._cambio.notify_all()

    @property
    def sin_cursor(self) -> bool:
        """True si nunca hubo cursor (primer arranque sin estado y nada entregado aún)."""
        with self._lock:
            return self._mayor_entregado is None

    def inicializar(self, serial: int) -> bool:
        """Primer arranque: fija el cursor en el serial más reciente del terminal SIN recuperar
        nada. No pisa un cursor que ya se fijó con una entrega en vivo.

        En la misma operación SIEMPRE abre el techo en ``serial`` (``min`` si ya hay uno), aun
        si el cursor ya estaba fijado: una 2xx en vivo de una conexión nueva no puede pasar por
        encima de lo ocurrido después de la consulta. La corrida completa siguiente recupera
        desde ``serial + 1`` y lo libera. True si fijó el cursor."""
        with self._lock:
            self._techo = serial if self._techo is None else min(self._techo, serial)
            if self._mayor_entregado is not None:
                foto = self._foto_si_cambia()
                fijado = False
            else:
                self._mayor_entregado = serial
                foto = self._foto(forzar=True)
                fijado = True
        self._escribir(foto)
        return fijado

    def fijar_mac(self, mac: str) -> None:
        with self._lock:
            if mac == self._mac:
                return
            self._mac = mac
            foto = self._foto(forzar=True)
        self._escribir(foto)

    # --- persistencia (foto bajo lock, escritura fuera) ----------------------

    def _foto_si_cambia(self) -> Optional[tuple]:
        return self._foto(forzar=False)

    def _foto(self, *, forzar: bool) -> Optional[tuple]:
        datos = (self._cursor_efectivo(), self._mac, self._ancla)
        if not forzar and datos == self._ultima_foto:
            return None
        self._ultima_foto = datos
        self._version += 1
        return (self._version, datos)

    def _escribir(self, foto: Optional[tuple]) -> None:
        if foto is None:
            return
        version, (cursor, mac, ancla) = foto
        with self._escritura:
            if version <= self._escrita:
                return  # ya se escribió una foto más nueva
            if self.estado.guardar(cursor_serial=cursor, terminal_mac=mac, ancla=ancla):
                self._escrita = version
                return
        with self._lock:
            if self._version == version:
                self._ultima_foto = None  # falló: el próximo cambio vuelve a intentar


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

# Resultado de una corrida.
COMPLETA = "completa"
CORTADA = "cortada"  # quedan seriales más allá de la ventana
FALLIDA = "fallida"  # sin MAC, error de red/HTTP/JSON, cola ocupada, sin avance
BLOQUEADA_401 = "401"  # no se reintenta hasta la próxima conexión del stream (§5.9.574)


class _Abortar(Exception):
    """Corta la corrida sin reintentos (401, respuesta inválida, error de red)."""

    def __init__(self, motivo: str, *, es_401: bool = False):
        super().__init__(motivo)
        self.es_401 = es_401


class Recuperador:
    """Corre la recuperación en un hilo aparte después de cada conexión exitosa del stream.

    ``construir_record(evento) -> record | None`` es el MISMO camino del stream
    (``parse_event_block`` + ``build_audit_record``), inyectado por el listener para no
    duplicarlo ni importarlo en círculo. ``destino(record)`` encola en el forwarder y escribe
    el audit (nunca HA); si levanta, el record queda como fallido y la corrida se corta.

    Un solo hilo a la vez. Después de cada corrida: conexión nueva durante la corrida ⇒ otra
    enseguida; cortada ⇒ la ventana siguiente (después de que el forwarder vacíe); fallida o
    con entregas fallidas ⇒ otra con backoff (``REINTENTO_BASE`` … ``REINTENTO_MAX``); 401 ⇒
    nada hasta la próxima conexión.
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
        self._cond = threading.Condition(self._lock)
        self._en_curso = False  # hay un hilo de recuperación vivo (bajo _lock)
        self._relanzar = False  # hubo una conexión nueva durante la corrida (bajo _lock)
        self._reintentar = False  # hubo una entrega fallida durante la corrida (bajo _lock)
        self._bloqueado_401 = False  # 401 en esta conexión: nada hasta la próxima (bajo _lock)
        self._intentos = 0  # corridas seguidas con algo pendiente (backoff)
        self._major: Optional[int] = None  # None = todavía no se probó major=0
        seguimiento.al_fallar = self.programar_reintento

    # --- disparo -----------------------------------------------------------

    def lanzar(self) -> bool:
        """Conexión nueva del stream. Se llama en el hilo del stream ANTES de leer eventos:
        abre el techo ahí mismo (sincrónico), así ninguna entrega en vivo de esta conexión
        pasa por encima del hueco de la desconexión. Después arranca la corrida en un hilo
        daemon; si ya hay uno (corriendo o esperando un reintento), lo despierta y lo marca
        para relanzar, y devuelve False. Nunca levanta (el stream no se cae por esto)."""
        with self._cond:
            self.seguimiento.abrir_techo()
            self._bloqueado_401 = False  # conexión nueva: un intento más (§5.9.574)
            if self._en_curso:
                self._relanzar = True
                self._cond.notify_all()
                self.log.info("Recuperación en curso: se relanza al terminar (conexión nueva).")
                return False
            self._intentos = 0
            return self._arrancar(0.0)

    def programar_reintento(self) -> None:
        """Una entrega falló: otra corrida con backoff, sin esperar a otra reconexión."""
        with self._cond:
            if self._bloqueado_401:
                return
            if self._en_curso:
                self._reintentar = True
                return
            self._arrancar(self._proxima_espera())

    def _proxima_espera(self) -> float:
        self._intentos += 1
        return min(REINTENTO_BASE * 2 ** (self._intentos - 1), REINTENTO_MAX)

    def _arrancar(self, espera: float) -> bool:
        """Bajo ``_lock``. Un fallo al crear el hilo no tumba al llamador ni deja
        ``_en_curso`` colgado: el techo queda abierto y la próxima conexión reintenta."""
        hilo = threading.Thread(target=self._correr_seguro, args=(espera,), name="recuperacion", daemon=True)
        self._en_curso = True
        try:
            hilo.start()
        except RuntimeError as exc:
            self._en_curso = False
            self.log.error("No se pudo arrancar el hilo de recuperación: %s", exc)
            return False
        self._hilo = hilo
        return True

    def _correr_seguro(self, espera: float) -> None:
        """Corre y repite mientras quede algo pendiente (ver docstring de la clase)."""
        while True:
            if espera > 0:
                with self._cond:
                    self._cond.wait_for(lambda: self._relanzar, timeout=espera)
                    self._relanzar = False  # la corrida que sigue cubre la conexión nueva
            try:
                resultado = self.correr().get("resultado", COMPLETA)
            except Exception as exc:  # nunca tumbar el proceso
                self.log.error("Recuperación falló: %s", exc)
                resultado = FALLIDA
            if resultado == CORTADA:
                self.seguimiento.esperar_cola(ESPERA_COLA_CORTE)
            with self._cond:
                if self._relanzar:
                    self._relanzar = False
                    self._intentos = 0
                    espera = 0.0
                    continue
                if resultado == BLOQUEADA_401:
                    self._bloqueado_401 = True
                    self._reintentar = False
                    self._en_curso = False
                    return
                if resultado == CORTADA:
                    self._intentos = 0
                    espera = 0.0
                    continue
                pendiente = resultado == FALLIDA or self._reintentar or self.seguimiento.hay_fallidos
                self._reintentar = False
                if not pendiente:
                    self._intentos = 0
                    self._en_curso = False
                    return
                espera = self._proxima_espera()
            self.log.info("Recuperación con pendientes: se reintenta en %.0f s.", espera)

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
            raise _Abortar("401", es_401=True)
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

    @staticmethod
    def _estado(acs: dict) -> str:
        """``responseStatusStrg``: OK / NO MATCH (completo) o MORE. Otro ⇒ inválido."""
        estado = acs.get("responseStatusStrg")
        if estado not in ("OK", "MORE", "NO MATCH"):
            raise _Abortar(f"responseStatusStrg inesperado en AcsEvent: {estado!r}")
        return estado

    def _consultar(self, desde: int, hasta: int) -> tuple[list[dict], int]:
        """Todas las páginas de la ventana ``[desde, hasta]``. Devuelve (ítems, páginas).
        Nunca devuelve una ventana a medias: si no se puede completar, aborta."""
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
                "endSerialNo": hasta,
            })
            paginas += 1
            estado = self._estado(acs)
            lista = self._lista(acs)
            items.extend(lista)
            if estado != "MORE":
                return items, paginas
            n = acs.get("numOfMatches")
            n = n if isinstance(n, int) and n > 0 else len(lista)
            if n == 0:
                raise _Abortar("AcsEvent respondió MORE sin ítems")
            posicion += n
        raise _Abortar(f"AcsEvent no terminó la ventana en {MAX_PAGINAS} páginas")

    def _hay_despues(self, hasta: int) -> bool:
        """True si el terminal tiene algún evento con serial mayor que ``hasta``."""
        acs = self._pedir({
            "searchID": uuid.uuid4().hex,
            "searchResultPosition": 0,
            "maxResults": 1,
            "beginSerialNo": hasta + 1,
            "endSerialNo": SERIAL_FIN,
        })
        return self._estado(acs) != "NO MATCH" and bool(self._lista(acs))

    def _numeracion_cambio(self) -> bool:
        """True si el serial ancla ya no está en el terminal con la misma hora (reset de
        fábrica o terminal cambiado). Si el equipo no deja verificar, no se decide nada."""
        ancla = self.seguimiento.ancla
        if ancla is None:
            return False
        serial, ts = ancla
        try:
            acs = self._pedir({
                "searchID": uuid.uuid4().hex,
                "searchResultPosition": 0,
                "maxResults": 1,
                "beginSerialNo": serial,
                "endSerialNo": serial,
            })
            self._estado(acs)
        except _Abortar as exc:
            if exc.es_401:
                raise
            self.log.warning("No se pudo verificar la numeración del terminal (%s): se sigue.", exc)
            return False
        encontrado = [i for i in self._lista(acs) if i.get("serialNo") == serial]
        if encontrado and _mismo_instante(encontrado[0].get("time"), ts):
            return False
        self.log.warning(
            "El serial ancla %s %s en el terminal (posible reset de fábrica): se recupera la "
            "numeración nueva desde 1.", serial, "con otra hora" if encontrado else "ya no está",
        )
        return True

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
            if exc.es_401:
                resumen["resultado"] = BLOQUEADA_401
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
        """Una corrida (sincrónica; ``lanzar`` abre el techo y la pone en un hilo).

        Arranca en el cursor efectivo + 1 y procesa una ventana de ``TOPE_EVENTOS`` seriales
        entera (todos los seriales de la ventana quedan admitidos, ya vistos o resueltos).
        Si el terminal tiene algo más allá, la corrida es CORTADA y el techo sube al fin de
        la ventana; si no, es COMPLETA y libera el techo (salvo que haya habido una conexión
        nueva: se relanza). Una FALLIDA lo deja donde estaba.
        """
        resumen: dict[str, Any] = {"desde": None, "encolados": 0, "ya_vistos": 0, "paginas": 0,
                                   "descartados": 0, "cursor_final": self.seguimiento.cursor,
                                   "resultado": COMPLETA}
        if self.seguimiento.sin_cursor:
            return self._inicializar(resumen)
        epoca = self.seguimiento.epoca
        cursor = self.seguimiento.cursor
        resumen["cursor_final"] = cursor
        if cursor is None:  # imposible con sin_cursor False; defensivo
            return resumen
        desde = cursor + 1
        try:
            mac = self._mac_terminal()
            if mac is None:
                resumen["resultado"] = FALLIDA
                return resumen
            if self._numeracion_cambio():
                epoca = self.seguimiento.reiniciar_numeracion()
                desde = 1
            hasta = desde + TOPE_EVENTOS - 1
            resumen["desde"] = desde
            items, paginas = self._consultar(desde, hasta)
            hay_mas = self._hay_despues(hasta)
        except _Abortar as exc:
            self.log.error("Recuperación abortada desde serial %s: %s", desde, exc)
            resumen["resultado"] = BLOQUEADA_401 if exc.es_401 else FALLIDA
            return resumen
        resumen["paginas"] = paginas

        validos = [
            i for i in items
            if isinstance(i.get("serialNo"), int) and not isinstance(i.get("serialNo"), bool)
            and desde <= i["serialNo"] <= hasta
        ]
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
        if viejos or hay_mas:
            self.log.warning(
                "Recuperación con tope: %d con más de 7 días descartados%s.",
                len(viejos),
                f" (quedan seriales después de {hasta}: siguen en la corrida siguiente)" if hay_mas else "",
            )
        resumen["descartados"] = len(viejos)
        # Los más viejos que 7 días se abandonan (estado final: suben el cursor como una
        # entrega).
        self.seguimiento.abandonar(viejos, epoca)

        sin_record: list[int] = []
        for item in recientes:
            record = self.construir_record(reconstruir_evento(item, self.host, mac))
            if record is None:
                sin_record.append(item["serialNo"])
                continue
            record["recuperado"] = True
            if not self.seguimiento.admitir(record, epoca):
                resumen["ya_vistos"] += 1
                continue
            try:
                self.destino(record)
            except Exception as exc:
                # Admitido pero no encolado: fallido (sale de la puerta y frena el cursor
                # hasta la próxima corrida), nunca colgado como pendiente para siempre.
                self.seguimiento.fallido(record)
                self.seguimiento.resolver_sin_envio(sin_record, epoca)
                self.log.error("Recuperación cortada al encolar el serial %s: %s", item["serialNo"], exc)
                resumen["resultado"] = FALLIDA
                resumen["cursor_final"] = self.seguimiento.cursor
                return resumen
            resumen["encolados"] += 1
        # Sin record (el parser lo descarta): estado final, igual que un abandonado.
        self.seguimiento.resolver_sin_envio(sin_record, epoca)

        if hay_mas:
            # Toda la ventana quedó procesada: el techo sube a su fin.
            self.seguimiento.subir_techo(hasta, epoca)
            resumen["resultado"] = CORTADA
        else:
            # Bajo el lock de lanzar: una conexión nueva que llegue ahora o ya llegó deja el
            # techo abierto para la corrida siguiente.
            with self._lock:
                if not self._relanzar:
                    self.seguimiento.cerrar_techo(epoca)

        resumen["cursor_final"] = self.seguimiento.cursor
        if hay_mas and resumen["encolados"] == 0 and (resumen["cursor_final"] or 0) <= desde - 1:
            # Ventana entera ya vista y sin entregar todavía: sin avance ⇒ backoff, no un
            # bucle de consultas.
            resumen["resultado"] = FALLIDA
        self.log.info(
            "Recuperación: desde serial %s, %d encolados, %d ya vistos, %d descartados, "
            "%d páginas, cursor %s.",
            desde, resumen["encolados"], resumen["ya_vistos"], resumen["descartados"],
            resumen["paginas"], resumen["cursor_final"],
        )
        return resumen
