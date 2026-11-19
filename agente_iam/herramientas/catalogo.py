"""Catalogo oficial de acciones IAM, en formato maquina.

AWS publica la Service Authorization Reference como JSON, publico y sin
autenticacion:

    https://servicereference.us-east-1.amazonaws.com/v1/<servicio>/<servicio>.json

Cada accion trae un array "Resources". Si viene vacio, esa accion NO admite
permisos a nivel de recurso: exigirle un ARN produce una politica que no
concede nada. Eso convierte "que el agente consulte la documentacion" en un
chequeo determinista, sin interpretacion de por medio.

Fase 2: cada accion trae ademas "Annotations.Properties" con su nivel de
acceso (IsWrite, IsPermissionManagement, IsTaggingOnly, IsList). Con eso,
"tipo_acceso: lectura" deja de ser una instruccion al modelo y pasa a ser
un chequeo de codigo: la lista blanca la publica y mantiene AWS.

Se usa en tres sitios:
  - como dato para la capa de validacion (decide si un Resource "*" es
    legitimo o es un exceso),
  - como dato para los chequeos posteriores (¿la accion excede el
    tipo_acceso pedido?),
  - como herramienta del agente, para que consulte antes de redactar.
"""

import json
import logging
import os
import re
import tempfile
import time
import urllib.request
from fnmatch import fnmatch
from pathlib import Path

from strands import tool

from agente_iam.config import CADUCIDAD_CATALOGO_DIAS, DIR_CACHE_CATALOGO

log = logging.getLogger("agente-iam")

_URL = "https://servicereference.us-east-1.amazonaws.com/v1/{s}/{s}.json"
_PREFIJO = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_CACHE = Path(DIR_CACHE_CATALOGO)
_MEMORIA: dict[str, dict] = {}

# Que propiedad del catalogo EXCEDE cada tipo de acceso del formulario.
# La duda razonable: ¿tagging es escritura? Si: modifica el recurso, y
# ademas hay politicas que conceden por tag (ABAC), asi que etiquetar
# puede cambiar quien accede a que. Por eso lectura lo excluye.
#
# Revision 2026-10: NINGUN tipo concede IsPermissionManagement. Antes
# 'administracion' no restringia nada, y eso incluia s3:PutBucketPolicy,
# sqs:AddPermission, sns:AddPermission, logs:PutResourcePolicy o
# dynamodb:PutResourcePolicy: escribir politicas de RECURSO, que conceden
# acceso a terceros (otras cuentas incluidas) sin pasar por ninguna
# solicitud. Un sistema que existe para decidir quien accede a que no
# puede tener un nivel que concede el poder de saltarselo.
#
# Consecuencia que hay que decir: hoy 'administracion' y 'escritura'
# coinciden. Si hace falta distinguirlos, es una decision de producto
# (p.ej. borrar recursos), no un hueco que dejar abierto.
_EXCEDE_POR_TIPO: dict[str, tuple[str, ...]] = {
    "lectura": ("IsWrite", "IsPermissionManagement", "IsTaggingOnly"),
    "escritura": ("IsPermissionManagement",),
    "administracion": ("IsPermissionManagement",),
}


def _guardar_en_cache(archivo: Path, crudo: bytes) -> None:
    """Cachear es una OPTIMIZACION, no un requisito. Que falle no importa.

    En el paquete desplegado el catalogo viaja ya dentro, en un directorio
    de solo lectura. La version anterior hacia `mkdir` + `write_bytes`
    dentro del camino critico, asi que un directorio no escribible hacia
    que `_cargar` lanzara. Y esa excepcion la capturaban `soporta_recursos`
    y `_expandir` devolviendo None, o sea "no se pudo determinar" — con lo
    que `excede_tipo_acceso` pasaba a devolver None SIEMPRE, y el
    orquestador trata None como advertencia y no como bloqueo.

    Resultado: el chequeo posterior de nivel de acceso (Fase 2, punto 3)
    habria dejado de bloquear nada, sin un solo error en ningun log. Un
    control apagado en silencio, que es peor que no tenerlo, porque el
    registro sigue diciendo que se comprobo.

    La escritura es atomica (24-10-2026, O2): fichero temporal en la misma
    carpeta y `os.replace`. Con `write_bytes` directo, un proceso muerto a
    medias dejaba un JSON truncado que se leia para siempre como catalogo
    ilegible, es decir, como duda en cada accion de ese servicio.
    """
    temporal = None
    try:
        archivo.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=archivo.parent, prefix=f".{archivo.name}.", delete=False) as f:
            temporal = Path(f.name)
            f.write(crudo)
        os.replace(temporal, archivo)
    except OSError:
        if temporal is not None:
            temporal.unlink(missing_ok=True)


def _descargar(servicio: str) -> bytes:
    # bandit B310 revisado: esquema y host fijos en _URL; servicio validado en `_cargar`.
    with urllib.request.urlopen(_URL.format(s=servicio), timeout=30) as r:  # nosec B310
        return r.read()


def _escribible(carpeta: Path) -> bool:
    """La cache local se puede renovar; el catalogo empaquetado, no.

    Si la carpeta no existe todavia, cuenta como escribible: es la primera
    descarga. En el paquete existe y es de solo lectura.
    """
    return os.access(carpeta, os.W_OK) if carpeta.exists() else True


def _caducado(archivo: Path) -> bool:
    return time.time() - archivo.stat().st_mtime > CADUCIDAD_CATALOGO_DIAS * 86400


def _crudo(servicio: str) -> bytes:
    """Los bytes del catalogo de `servicio`, de la cache o de la red.

    Tres reglas (24-10-2026, O2), todas con el criterio de no quedarse sin
    catalogo, porque sin el el chequeo de nivel se degrada a advertencia:

      - Una cache caducada se renueva si la carpeta es escribible; si la
        descarga falla, se usa la vieja y se avisa de su edad.
      - Una cache que no es JSON se borra y se descarga una vez. Antes se
        quedaba para siempre y el servicio entero contaba como duda.
      - En el paquete (solo lectura) no caduca ni se borra nada.
    """
    archivo = _CACHE / f"{servicio}.json"
    escribible = _escribible(_CACHE)
    if archivo.exists():
        crudo = archivo.read_bytes()
        try:
            json.loads(crudo)
        except ValueError:
            if not escribible:
                raise
            log.warning("catalogo de %s ilegible en la cache; se descarga de nuevo", servicio)
            archivo.unlink(missing_ok=True)
        else:
            if not escribible or not _caducado(archivo):
                return crudo
            try:
                nuevo = _descargar(servicio)
                json.loads(nuevo)
            except Exception as e:  # red o respuesta rota: se usa la vieja
                dias = int((time.time() - archivo.stat().st_mtime) // 86400)
                log.warning("no se pudo renovar el catalogo de %s (%s); se usa la cache de hace %s dias",
                            servicio, e, dias)
                return crudo
            _guardar_en_cache(archivo, nuevo)
            return nuevo
    crudo = _descargar(servicio)
    json.loads(crudo)  # una respuesta que no es JSON no se cachea
    _guardar_en_cache(archivo, crudo)
    return crudo


def _cargar(servicio: str) -> dict[str, dict]:
    """Devuelve {nombre_minuscula: {"recursos": [...], "propiedades": {...}}}."""
    servicio = servicio.lower()
    # El servicio sale de acciones que escribe el modelo y acaba en una ruta
    # y en una URL: sin esto, `../secreto` leia o escribia fuera de la cache
    # (Fase 12). Los prefijos de AWS son minusculas, digitos y guiones.
    if not _PREFIJO.fullmatch(servicio):
        raise ValueError(f"prefijo de servicio no valido: {servicio!r}")
    if servicio in _MEMORIA:
        return _MEMORIA[servicio]

    datos = json.loads(_crudo(servicio))
    indice = {
        a["Name"].lower(): {
            "recursos": a.get("Resources", []),
            "propiedades": a.get("Annotations", {}).get("Properties", {}),
        }
        for a in datos.get("Actions", [])
    }
    _MEMORIA[servicio] = indice
    return indice


def no_disponibles(servicios: list[str]) -> list[str]:
    """Los servicios de la lista cuyo catalogo NO se puede cargar.

    Existe para comprobarlo al ARRANCAR y no al usarlo. Sin catalogo, el
    chequeo de nivel de acceso no falla: devuelve "no se pudo determinar",
    que el orquestador convierte en advertencia. O sea que el sistema
    seguiria proponiendo politicas, con un control menos y sin decirlo.

    Un control que se apaga solo tiene que hacer ruido en el unico momento
    en que alguien esta mirando: el arranque.
    """
    faltan = []
    for servicio in servicios:
        try:
            if not _cargar(servicio):
                faltan.append(servicio)
        except Exception:  # red, disco o JSON: da igual cual
            faltan.append(servicio)
    return faltan


def soporta_recursos(accion: str) -> bool | None:
    """True si la accion admite ARNs; False si exige "*"; None si se desconoce.

    'accion' viene en formato IAM completo: 'ec2:DescribeInstances'.
    """
    if ":" not in accion:
        return None
    servicio, nombre = accion.split(":", 1)
    if "*" in nombre:
        return None  # un comodin de prefijo no se puede resolver aqui
    try:
        indice = _cargar(servicio)
    except Exception:
        return None  # sin red o servicio desconocido: no bloqueamos por esto
    if nombre.lower() not in indice:
        return None
    return bool(indice[nombre.lower()]["recursos"])


# Las propiedades que hacen de una accion algo mas que leer o listar. Son
# las mismas que excede la `lectura` del formulario.
_NO_ES_LECTURA = ("IsWrite", "IsPermissionManagement", "IsTaggingOnly")


def es_escritura(accion: str) -> bool | None:
    """True si la accion no es de nivel List o Read; None si se desconoce.

    Existe para la excepcion de `Resource "*"` (revision del 24-10-2026,
    S3): una accion sin tipo de recurso que escribe suele actuar sobre la
    cuenta entera, asi que con "*" solo se acepta lectura. Un comodin en el
    nombre no se resuelve aqui: es duda.
    """
    if ":" not in accion:
        return None
    servicio, nombre = accion.split(":", 1)
    if "*" in nombre or "?" in nombre:
        return None
    try:
        indice = _cargar(servicio)
    except Exception:
        return None
    entrada = indice.get(nombre.lower())
    if entrada is None:
        return None
    return any(entrada["propiedades"].get(p) for p in _NO_ES_LECTURA)


def todas_exigen_wildcard(acciones: list[str]) -> bool:
    """True si TODAS las acciones dadas exigen Resource '*'.

    Conservador: si de alguna no se sabe, devuelve False. Una duda nunca
    debe convertirse en un permiso mas amplio.
    """
    respuestas = [soporta_recursos(a) for a in acciones]
    return bool(respuestas) and all(r is False for r in respuestas)


def _expandir(accion: str) -> list[str] | None:
    """Resuelve una accion (o un prefijo con comodin) a nombres concretos.

    'ec2:Describe*' se expande contra el catalogo a todas las acciones que
    cubre. Devuelve None si el catalogo no esta disponible o nada coincide:
    "no se pudo saber" y "no existe" se reportan igual, como duda.
    """
    if ":" not in accion:
        return None
    servicio, nombre = accion.split(":", 1)
    try:
        indice = _cargar(servicio)
    except Exception:
        return None
    patron = nombre.lower()
    nombres = [n for n in indice if fnmatch(n, patron)]
    return nombres or None


def excede_tipo_acceso(accion: str, tipo_acceso: str) -> bool | None:
    """¿La accion concede mas de lo que el tipo_acceso del formulario pide?

    True  -> la accion (o alguna que su comodin cubre) es de un nivel
             superior: p.ej. una escritura bajo 'lectura'.
    False -> todas las acciones cubiertas caben en el tipo pedido.
    None  -> no se pudo determinar (catalogo no disponible o accion
             desconocida). El que llama decide que hacer con la duda; aqui
             no se convierte en bloqueo ni en permiso.
    """
    propiedades_que_exceden = _EXCEDE_POR_TIPO.get(tipo_acceso)
    if propiedades_que_exceden is None:
        return None  # tipo de acceso desconocido: no inventamos reglas
    servicio = accion.split(":", 1)[0] if ":" in accion else ""
    nombres = _expandir(accion)
    if nombres is None:
        return None

    indice = _cargar(servicio)  # ya esta en memoria: _expandir lo cargo
    for nombre in nombres:
        props = indice[nombre]["propiedades"]
        if any(props.get(p) for p in propiedades_que_exceden):
            return True
    return False


def nivel_en_memoria(accion: str) -> str | None:
    """"lectura" o "escritura" de una accion (o de su comodin), solo con el
    catalogo que ya esta en memoria; None si no esta o la accion no existe.

    Fase 28: lo usa `coherencia.nivel_real` para decir en palabras llanas que
    concede una propuesta. No descarga nada a proposito: cuando se llama, los
    chequeos posteriores ya cargaron el catalogo de ese servicio, y en los
    tests sin red se queda en None en vez de salir a internet. "escritura"
    cubre escritura, tagging y gestion de permisos.
    """
    if ":" not in accion:
        return None
    servicio, nombre = accion.split(":", 1)
    indice = _MEMORIA.get(servicio.lower())
    if indice is None:
        return None
    nombres = [n for n in indice if fnmatch(n, nombre.lower())]
    if not nombres:
        return None
    for n in nombres:
        props = indice[n]["propiedades"]
        if any(props.get(p) for p in ("IsWrite", "IsPermissionManagement", "IsTaggingOnly")):
            return "escritura"
    return "lectura"


def acciones_en_memoria(accion: str) -> list[str]:
    """Los nombres concretos (en minusculas) que cubre `accion`, con el catalogo
    en memoria; sin catalogo, la propia accion sin servicio."""
    if ":" not in accion:
        return []
    servicio, nombre = accion.split(":", 1)
    indice = _MEMORIA.get(servicio.lower())
    if indice is None:
        return [nombre.lower()]
    return [n for n in indice if fnmatch(n, nombre.lower())] or [nombre.lower()]


@tool
def consultar_acciones(acciones: list[str]) -> dict:
    """Dice si cada accion IAM admite ARNs de recurso o exige Resource '*',
    y de que nivel de acceso es cada una.

    Consulta la referencia oficial de AWS (Service Authorization Reference).
    Usala ANTES de escribir el campo Resource: si una accion no admite
    recursos, ponerle un ARN produce una politica que no concede nada, y si
    los admite, usar '*' concede de mas. El nivel de acceso te dice si la
    accion cabe en el tipo_acceso del formulario: bajo 'lectura' no puedes
    conceder acciones de escritura, tagging ni gestion de permisos.

    Args:
        acciones: Acciones IAM completas, p.ej. ['s3:GetObject', 'ec2:DescribeInstances'].

    Returns:
        dict con 'admiten_arn', 'exigen_wildcard', 'desconocidas' y
        'nivel' (por accion: lectura | escritura | tagging |
        gestion_de_permisos | desconocido).
    """
    admiten: list[str] = []
    exigen: list[str] = []
    desconocidas: list[str] = []
    nivel: dict[str, str] = {}
    for a in acciones:
        r = soporta_recursos(a)
        (admiten if r else exigen if r is False else desconocidas).append(a)

        nombres = _expandir(a)
        if nombres is None:
            nivel[a] = "desconocido"
            continue
        indice = _cargar(a.split(":", 1)[0])
        props_todas = [indice[n]["propiedades"] for n in nombres]
        if any(p.get("IsPermissionManagement") for p in props_todas):
            nivel[a] = "gestion_de_permisos"
        elif any(p.get("IsWrite") for p in props_todas):
            nivel[a] = "escritura"
        elif any(p.get("IsTaggingOnly") for p in props_todas):
            nivel[a] = "tagging"
        else:
            nivel[a] = "lectura"
    return {
        "admiten_arn": admiten,
        "exigen_wildcard": exigen,
        "desconocidas": desconocidas,
        "nivel": nivel,
        "nota": "Las que exigen wildcard deben ir con Resource '*' y "
        "acotarse con un bloque Condition.",
    }
