"""El rol por persona (Fase 23): las piezas puras y dos funciones de lectura.

Cada solicitud aprobada se materializa en un rol creado para una persona:
techo como boundary, confianza solo para su `sub` de Cognito y vida de 1 a
12 horas. Este modulo guarda lo que NO toca la red: como se llama el rol, como
se forma el id de la solicitud, cuando vence el permiso y como queda el
documento de confianza.

Lo comparten el runtime (que forma el `solicitud_id` y comprueba el tope y la
redundancia contra los roles vigentes) y el aplicador (que crea el rol). Por
eso vive aparte y no importa el agente ni el modelo: ni el runtime puede
escribir en IAM por importar esto, ni el aplicador puede acabar hablando con
el modelo.

DOS FUNCIONES TIENEN RED, y por eso el modulo importa boto3: `roles_vigentes`
(ListRoles y ListRoleTags) y `cuenta_actual` (GetCallerIdentity). Son de
LECTURA. Las usan el runtime y el aplicador, cada uno con sus propios permisos
de lectura (el modulo no concede ninguno): el runtime para el tope y la
redundancia, y el aplicador, que repite el tope al aplicar. Quien llama puede
inyectar su cliente; el aplicador pasa siempre el suyo para que un solo
`Stubber` cubra todas sus llamadas.

DETERMINISTAS A PROPOSITO. De que el id y el nombre salgan siempre iguales
para la misma entrada depende la idempotencia, igual que
`aplicador.nombre_de_politica`: un reintento (doble clic, evento duplicado del
stream, corrida a medias) forma el mismo id y el mismo nombre, y encuentra lo
que ya hizo en vez de crear un segundo rol. Por eso el id lleva el hash de la
`clave_envio` y no un azar, y por eso el nombre se normaliza y se recorta
siempre igual.

LA FORMA DE LA CONFIANZA ESTA MEDIDA, no supuesta (`docs/MEDICIONES.md` N): la
persona canjea su token de identidad de Cognito con
`AssumeRoleWithWebIdentity`, y la confianza lo fija a su `sub` (la persona),
al cliente (`aud`, una lista de uno o dos clientes) y a la hora de
vencimiento. El vencimiento tambien entra en cada `Allow` de la politica
(`documento_con_vencimiento`), porque la sesion puede durar mas que el
permiso y la condicion lo corta a la hora exacta.
"""

from __future__ import annotations

import copy
import hashlib
import re
import unicodedata
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

import boto3

from agente_iam.config import AWS_REGION, HORAS_MAX, HORAS_MIN

PATH_PERSONAS = "/agente-iam/personas/"
PREFIJO_ROL = "agente-iam-persona-"

TAG_SOLICITUD = "agente-iam-solicitud"
TAG_PERSONA = "agente-iam-persona"
TAG_SUB = "agente-iam-sub"
TAG_VENCE = "agente-iam-vence"

FORMATO_VENCE = "%Y-%m-%dT%H:%M:%SZ"

# IAM limita el nombre de un rol a 64 caracteres.
_MAX_NOMBRE_ROL = 64
_FUERA_DEL_ALFABETO = re.compile(r"[^a-z0-9+=.@_-]")
# Largo del sufijo `-req-AAAAMMDD-xxxxxxxx` que forma `id_de_solicitud`: es
# fijo, y con el se calcula el recorte del usuario sin tener un id a mano.
_LARGO_SUFIJO_ID = len("-req-20260101-0123abcd")

# Clientes y cuenta cacheados en el modulo (como `identidad._iam`): crear un
# cliente de boto3 es caro y la cuenta no cambia durante la vida del proceso.
_cliente = None
_cuenta: str | None = None


def _iam():
    global _cliente
    if _cliente is None:
        _cliente = boto3.client("iam", region_name=AWS_REGION)
    return _cliente


def _en_utc(ahora: datetime) -> datetime:
    """La hora en UTC; una hora sin zona se toma por UTC (como el resto)."""
    if ahora.tzinfo is None:
        return ahora.replace(tzinfo=timezone.utc)
    return ahora.astimezone(timezone.utc)


def normalizar_usuario(usuario: str) -> str:
    r"""El nombre de usuario en el alfabeto de los nombres de rol de IAM.

    NFKC y `casefold`, igual que `aprobar._misma_persona` (ADR-003, B): dos
    nombres que esa funcion toma por la misma persona dan aqui el mismo
    texto. Despues todo caracter fuera de `[a-z0-9+=.@_-]` pasa a `-`. El
    resultado se usa en el nombre del rol Y como valor de la etiqueta
    `agente-iam-persona`; el alfabeto es la interseccion de los dos. La coma
    queda fuera porque IAM la admite en un nombre de rol pero no en el valor
    de una etiqueta (patron `[\p{L}\p{Z}\p{N}_.:/=+\-@]*`). Las mayusculas se
    pliegan porque IAM no distingue entre `Ana` y `ana`.

    Dos personas distintas pueden dar el mismo texto (`ana.` con una e de
    tilde agudo y otra de tilde grave, o nombres solo de caracteres no
    latinos, que dan `--`): el texto no identifica a una persona, el `sub` si.
    Por eso `roles_vigentes` admite filtrar por `sub`.
    """
    plegado = unicodedata.normalize("NFKC", usuario).casefold()
    return _FUERA_DEL_ALFABETO.sub("-", plegado)


def id_de_solicitud(clave_envio: str, ahora: datetime) -> str:
    """El id de la solicitud: `req-<AAAAMMDD UTC>-<8 hex de sha256(clave)>`.

    Lo forma el servidor, no el cliente ni el modelo. La misma `clave_envio`
    el mismo dia da el mismo id: un doble clic o un reintento no abre una
    segunda solicitud.
    """
    resumen = hashlib.sha256(clave_envio.encode()).hexdigest()[:8]
    return f"req-{_en_utc(ahora):%Y%m%d}-{resumen}"


def _usuario_recortado(usuario: str, largo_sufijo: int) -> str:
    """El usuario normalizado, recortado para que el nombre quepa en 64.

    Es la UNICA regla de recorte: `nombre_de_rol` la usa para formar el
    nombre y `roles_vigentes` para formar el prefijo con el que busca los
    roles de una persona. Si cada una la tuviera por su lado, un cambio en
    una dejaria a la otra sin encontrar los roles que la primera crea.
    """
    margen = _MAX_NOMBRE_ROL - len(PREFIJO_ROL) - largo_sufijo
    return normalizar_usuario(usuario)[: max(margen, 0)]


def nombre_de_rol(usuario: str, solicitud_id: str) -> str:
    """El nombre determinista del rol: prefijo, usuario y solicitud.

    `agente-iam-persona-<usuario>-<solicitud_id en minusculas>`, en minusculas
    por la misma razon que `aplicador.nombre_de_politica` (IAM no distingue
    mayusculas, asi que la colision tiene que ser visible y deliberada). El
    usuario normalizado se recorta lo justo para que el total no pase de 64;
    el id va siempre entero, y es lo que separa a dos usuarios que solo
    difieren dentro de lo recortado.
    """
    sufijo = "-" + solicitud_id.lower()
    return PREFIJO_ROL + _usuario_recortado(usuario, len(sufijo)) + sufijo


def arn_de_rol(cuenta: str, usuario: str, solicitud_id: str) -> str:
    return f"arn:aws:iam::{cuenta}:role{PATH_PERSONAS}{nombre_de_rol(usuario, solicitud_id)}"


def vence_desde(ahora: datetime, horas: int) -> str:
    """Cuando vence el permiso: `ahora` mas `horas`, en ISO 8601 UTC con `Z`.

    `horas` es a la vez la vida del permiso y la sesion maxima del rol; fuera
    de 1 a 12 es un `ValueError`, no se recorta en silencio.
    """
    if isinstance(horas, bool) or not isinstance(horas, int) or not HORAS_MIN <= horas <= HORAS_MAX:
        raise ValueError(f"horas debe estar entre {HORAS_MIN} y {HORAS_MAX}: {horas!r}")
    return (_en_utc(ahora) + timedelta(hours=horas)).strftime(FORMATO_VENCE)


def _con_vencimiento(sentencia: dict, vence: str) -> dict:
    condicion = sentencia.get("Condition", {})
    if not isinstance(condicion, dict):
        raise ValueError("Condition de un Allow no es un objeto")
    fecha = condicion.get("DateLessThan", {})
    if not isinstance(fecha, dict):
        raise ValueError("DateLessThan de un Allow no es un objeto")
    # Si ya traia `aws:CurrentTime` se sobrescribe: el vencimiento que manda
    # es el del sistema, no uno que venga en el documento.
    sentencia["Condition"] = {**condicion, "DateLessThan": {**fecha, "aws:CurrentTime": vence}}
    return sentencia


def documento_con_vencimiento(documento: dict, vence: str) -> dict:
    """Copia del documento con el vencimiento en cada `Allow`.

    Fusiona `"DateLessThan": {"aws:CurrentTime": vence}` en el `Condition`
    que el `Allow` ya tenga (la S5 `aws:ResourceAccount`, por ejemplo) sin
    perderlo, y conserva otras claves de un `DateLessThan` existente. Los
    `Deny` quedan intactos: un limite de tiempo en un Deny lo debilitaria.
    No muta la entrada; `Statement` puede ser lista o un solo objeto.
    """
    copia = copy.deepcopy(documento)
    sentencias = copia.get("Statement")
    if isinstance(sentencias, dict):
        sentencias = [sentencias]
    for sentencia in sentencias or []:
        if isinstance(sentencia, dict) and sentencia.get("Effect") == "Allow":
            _con_vencimiento(sentencia, vence)
    return copia


def emisor(pool_id: str, region: str = AWS_REGION) -> str:
    """El emisor OIDC del pool de Cognito, sin esquema (como lo pide IAM)."""
    return f"cognito-idp.{region}.amazonaws.com/{pool_id}"


def proveedor_oidc(cuenta: str, pool_id: str, region: str = AWS_REGION) -> str:
    """El ARN del proveedor OIDC del pool en la cuenta."""
    return f"arn:aws:iam::{cuenta}:oidc-provider/{emisor(pool_id, region)}"


def confianza(
    cuenta: str,
    pool_id: str,
    clientes: Sequence[str],
    sub: str,
    vence: str,
    region: str = AWS_REGION,
) -> dict:
    """El documento de confianza del rol por persona (MEDICIONES N.1).

    Solo el proveedor OIDC del pool puede asumirlo, con
    `AssumeRoleWithWebIdentity`, y solo con un token cuyo `aud` es uno de los
    clientes configurados y cuyo `sub` es el de la persona; despues de `vence`
    ya no se puede asumir. `StringEquals` con una lista en `:aud` es "alguno
    de estos clientes" (el cliente del CLI y el de la web).
    """
    prefijo = emisor(pool_id, region)
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": proveedor_oidc(cuenta, pool_id, region)},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {f"{prefijo}:aud": list(clientes), f"{prefijo}:sub": sub},
                    "DateLessThan": {"aws:CurrentTime": vence},
                },
            }
        ],
    }


def cuenta_actual(sts=None) -> str:
    """La cuenta en la que corre el proceso (`GetCallerIdentity`), cacheada.

    Hace falta para formar el ARN del rol previsto sin que lo declare nadie:
    la cuenta sale de las credenciales de quien corre, no de la peticion.
    `sts=None` crea un cliente de boto3 en `AWS_REGION`; se inyecta en tests.
    """
    global _cuenta
    if _cuenta is None:
        cliente = sts if sts is not None else boto3.client("sts", region_name=AWS_REGION)
        _cuenta = cliente.get_caller_identity()["Account"]
    return _cuenta


def vence_como_fecha(vence: str) -> datetime | None:
    """El vencimiento (`FORMATO_VENCE`) como fecha UTC, o None si no cuadra.

    Es la lectura inversa de `vence_desde`. Un texto que no cuadra devuelve
    None y no una excepcion, porque lo que se lee es una etiqueta de un rol
    que otro escribio: la duda cae del lado de no darlo por vigente.
    """
    try:
        return datetime.strptime(vence, FORMATO_VENCE).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def roles_vigentes(
    usuario: str, ahora: datetime, iam=None, sub: str | None = None
) -> list[dict]:
    """Los roles de persona de este usuario que siguen vigentes.

    Sirve para el tope por persona y para la redundancia: los roles que ya
    tiene son los permisos que ya puede usar. `ListRoles` por ruta trae los
    roles de TODAS las personas, y pedir las etiquetas de cada uno seria una
    llamada por rol de toda la cuenta; por eso solo se piden las de los
    roles cuyo nombre empieza por el prefijo que `nombre_de_rol` da a este
    usuario. El nombre solo acota la busqueda: la fuente de verdad son las
    etiquetas (`TAG_PERSONA` igual al usuario normalizado, `TAG_VENCE`
    posterior a `ahora`), porque dos usuarios pueden compartir prefijo
    (`ana` y `ana-maria`) y el recorte de un nombre largo tambien junta
    prefijos. Un `TAG_VENCE` que no se puede leer no es vigente: la duda cae
    del lado de no contar un permiso que no se sabe si sigue.

    Con `sub`, ademas, solo salen los roles cuya etiqueta `TAG_SUB` es ese
    `sub`: dos personas distintas pueden normalizar al mismo texto (ver
    `normalizar_usuario`), y contar o comparar contra los roles de la otra
    seria atribuirle permisos que no tiene. Sin `sub` salen los de todos los
    que comparten el texto normalizado.

    Cada rol sale como `{"arn", "nombre", "vence", "solicitud_id"}`. Los
    errores de IAM se propagan: decidir que hacer sin saberlo es de quien
    llama (el runtime lo trata como "no comprobada", ver
    `simulacion.redundancia_persona`).
    """
    cliente = iam if iam is not None else _iam()
    prefijo = PREFIJO_ROL + _usuario_recortado(usuario, _LARGO_SUFIJO_ID) + "-"
    persona = normalizar_usuario(usuario)
    limite = _en_utc(ahora)

    vigentes: list[dict] = []
    parametros: dict = {"PathPrefix": PATH_PERSONAS}
    while True:
        pagina = cliente.list_roles(**parametros)
        for rol in pagina["Roles"]:
            if not rol["RoleName"].startswith(prefijo):
                continue
            etiquetas = {
                t["Key"]: t["Value"]
                for t in cliente.list_role_tags(RoleName=rol["RoleName"])["Tags"]
            }
            if etiquetas.get(TAG_PERSONA) != persona:
                continue
            vence = etiquetas.get(TAG_VENCE, "")
            if sub is not None and etiquetas.get(TAG_SUB) != sub:
                continue
            fecha = vence_como_fecha(vence)
            if fecha is None or fecha <= limite:
                continue
            vigentes.append(
                {
                    "arn": rol["Arn"],
                    "nombre": rol["RoleName"],
                    "vence": vence,
                    "solicitud_id": etiquetas.get(TAG_SOLICITUD, ""),
                }
            )
        if not pagina.get("IsTruncated") or not pagina.get("Marker"):
            break
        parametros["Marker"] = pagina["Marker"]
    return vigentes
