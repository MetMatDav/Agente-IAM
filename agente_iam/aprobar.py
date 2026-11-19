"""El servidor de la aprobacion: los controles y la Lambda `agente-iam-aprobacion`.

Aprobar o rechazar una solicitud ya propuesta es una decision, y desde ADR-003
(A2) la escribe este modulo, en una Lambda con URL de funcion (AuthType
AWS_IAM) y no en la maquina de quien aprueba. La persona usa el cliente
(`agente_iam.aprobar_cliente`: lee, ensena la huella y manda la peticion
firmada con SigV4). `python -m agente_iam.aprobar` ya no es un comando: solo
dice a donde ir.

  - `manejador`: la puerta de la Lambda. Saca QUIEN firma del evento
    (`aprobador_desde_evento`), nunca del cuerpo, y llama a `decidir`.
  - `decidir`: una lectura, `aprobar` o `rechazar`, una escritura. Es lo que
    hacia el `main()` de antes, con la identidad ya dada.
  - `identificar_aprobador`: la misma resolucion contra STS, para el cliente en
    modo disco (desarrollo, sin servidor).

LA HUELLA ATA LO QUE SE LEYO CON LO QUE SE FIRMA (revision 2026-10). Antes
el comando decidia y escribia sin mostrar nada: el humano habia leido la
propuesta en otro momento (la salida del intake) y la huella certificaba lo
que hubiera en el almacen al aprobar, no lo que el leyo. Quien pudiera
escribir el registro entre medias conseguia que el propio comando del
aprobador firmara su version. Ahora el cliente pinta la propuesta y su huella,
y el servidor solo aprueba si la huella confirmada es la del registro que
acaba de leer.

El orden de los pasos de `aprobar` es deliberado y cada uno tiene su motivo:

  1. Lectura UNICA. De un solo objeto en memoria salen las dos cosas: lo
     que se comprueba y lo que se hashea. Leer dos veces seria un TOCTOU
     dentro de mi propio codigo — justo el bug que todo lo demas existe
     para evitar.
  2. Compuerta de estado, por lista blanca.
  3. Identidad del aprobador, desde la fuente (nunca un flag ni el cuerpo).
  4. Separacion de funciones, con tres desenlaces y ninguno silencioso.
  5. Revalidacion con las reglas de HOY.
  6. CheckNoNewAccess: la compuerta pagada, contra el techo del sistema.
  7. Huella.
  8. Escritura, con guardian.

Codigos de `decidir`: 200 la decision esta escrita, 404 no existe, 409 la
bloquea un control. El manejador anade 400, 405 y 500.
"""

import base64
import binascii
import json
import logging
import re
import sys
import unicodedata
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from pydantic import ValidationError

from agente_iam import almacen, huella
from agente_iam.coherencia import chequeos_formulario, chequeos_posteriores, riesgo_minimo
from agente_iam.config import AWS_REGION, NOMBRE_TECHO, SERVICIOS_PERMITIDOS
from agente_iam.herramientas import catalogo
from agente_iam.herramientas.validacion import validar_politica
from agente_iam.models import (
    ESTADOS_APROBABLES,
    AprobadorVerificado,
    PeticionAprobacion,
    PropuestaPolitica,
    SolicitudEstructurada,
    imprimible,
)

# Lo que se pinta lo escribieron otros (solicitante y modelo): se escapa
# todo lo no imprimible antes de que llegue a la terminal (S7).
_t = imprimible

# Hijo de "agente-iam" (como el de `servidor`), con su propio nivel: en Lambda
# el raiz esta en WARNING y la linea por peticion se perderia. El nivel solo
# toca a este hijo, no a los otros modulos.
log = logging.getLogger("agente-iam.aprobar")
log.setLevel(logging.INFO)

_RUTA_TECHO_LOCAL = Path("infra/boundary-agente-iam-techo.json")

# Se usa con `fullmatch`: `$` casa tambien antes de un salto de linea final.
_ARN_USUARIO = re.compile(r"arn:aws:iam::(\d{12}):user/.+")
# El ARN de un rol asumido NO es el del rol: cambia el servicio (sts en vez
# de iam), el tipo de recurso y lleva el nombre de sesion al final. Compararlo
# tal cual contra un ARN de IAM no coincide nunca, y ese "no coincide" se
# leeria como "son personas distintas" — un falso negativo en un control de
# separacion de funciones, que es la peor clase de fallo: parece que funciono.
_ARN_ROL_ASUMIDO = re.compile(r"arn:aws:sts::(\d{12}):assumed-role/([^/]+)/(.+)")

# Los roles de los permission sets de Identity Center viven en este path y se
# llaman AWSReservedSSO_<permission set>_<sufijo>. Solo el del aprobador da
# persona (ADR-003, B2); el sufijo cambia de una cuenta a otra.
#
# No basta con que el nombre EMPIECE igual (Fase 33): un permission set llamado
# `AgenteIAM-Aprobador_Extra` da el rol AWSReservedSSO_AgenteIAM-Aprobador_Extra_<sufijo>,
# que pasaba un `startswith`. Tras el prefijo solo puede venir el sufijo, y un
# sufijo no lleva `_`: cualquier nombre mas largo de permission set mete otro
# `_` antes de el. No se fija la longitud ni que sea hexadecimal: la guia de
# AWS lo da asi en sus ejemplos (16 hex), no como contrato.
_PATH_SSO = "/aws-reserved/sso.amazonaws.com/"
_PREFIJO_ROL_APROBADOR = "AWSReservedSSO_AgenteIAM-Aprobador_"
_ROL_APROBADOR = re.compile(re.escape(_PREFIJO_ROL_APROBADOR) + r"[0-9A-Za-z]+")

_sts_cliente = None
_iam_cliente = None
_aa_cliente = None


def _sts():
    global _sts_cliente
    if _sts_cliente is None:
        _sts_cliente = boto3.client("sts", region_name=AWS_REGION)
    return _sts_cliente


def _iam():
    global _iam_cliente
    if _iam_cliente is None:
        _iam_cliente = boto3.client("iam", region_name=AWS_REGION)
    return _iam_cliente


def _analyzer():
    global _aa_cliente
    if _aa_cliente is None:
        _aa_cliente = boto3.client("accessanalyzer", region_name=AWS_REGION)
    return _aa_cliente


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- Paso 3: quien aprueba ---------------------------------------------------


def identificar_aprobador() -> AprobadorVerificado:
    """Resuelve la identidad del que corre el comando, contra STS e IAM.

    `sts:GetCallerIdentity` no necesita permiso y no se puede denegar, asi
    que siempre hay respuesta. Lo que no siempre hay es una respuesta
    COMPARABLE con el ARN del beneficiario; de eso se ocupa `_resolver`, que
    comparte con `aprobador_desde_evento` (la Lambda de aprobacion, ADR-003).
    """
    ident = _sts().get_caller_identity()
    return _resolver(ident["Arn"], ident["UserId"], ident["Account"], "sts:GetCallerIdentity")


def aprobador_desde_evento(evento: dict) -> AprobadorVerificado:
    """La identidad de quien firmo la peticion, leida del evento de la URL de funcion.

    Con AuthType AWS_IAM, Lambda verifica la firma SigV4 antes de invocar y
    rellena `requestContext.authorizer.iam`. Esos tres campos son la misma
    informacion que daria `GetCallerIdentity` a quien firmo, asi que van por la
    misma resolucion. Nunca se lee ni se guarda `accessKey`: no hace falta para
    identificar y es una credencial temporal.

    Un evento sin identidad (AuthType NONE, `authorizer` ausente o a None, o
    `iam` incompleto) no es determinable, y nada se inventa para rellenarlo: lo
    que falta queda vacio. La cuenta de quien firma debe ser la de la funcion;
    si no, una cuenta ajena podria presentar un rol con el nombre del nuestro.
    """
    ctx = evento.get("requestContext") if isinstance(evento, dict) else None
    ctx = ctx if isinstance(ctx, dict) else {}
    authorizer = ctx.get("authorizer")
    iam = authorizer.get("iam") if isinstance(authorizer, dict) else None
    iam = iam if isinstance(iam, dict) else {}

    # Lo que no es un texto es duda, no un TypeError: se queda vacio y se dice
    # (un campo que falta y uno de otro tipo son dos motivos distintos).
    no_texto = [
        n for n in ("userArn", "userId", "accountId")
        if iam.get(n) is not None and not isinstance(iam.get(n), str)
    ]

    def texto(nombre: str) -> str:
        valor = iam.get(nombre)
        return valor if isinstance(valor, str) else ""

    arn, user_id, cuenta = texto("userArn"), texto("userId"), texto("accountId")

    def no_determinable(motivo: str) -> AprobadorVerificado:
        return AprobadorVerificado(
            arn_llamante=arn,
            arn_canonico=None,
            user_id=user_id,
            cuenta=cuenta,
            como_se_verifico=motivo,
            determinable=False,
        )

    if not iam:
        return no_determinable(
            "el evento no trae requestContext.authorizer.iam (la URL no exige "
            "firma IAM, o el evento no viene de la URL): no hay identidad"
        )
    if no_texto:
        return no_determinable(
            "requestContext.authorizer.iam trae " + ", ".join(no_texto) + " y no es un texto: identidad no valida"
        )
    faltan = [n for n, v in (("userArn", arn), ("userId", user_id), ("accountId", cuenta)) if not v]
    if faltan:
        return no_determinable(
            "requestContext.authorizer.iam no trae " + ", ".join(faltan) + ": identidad incompleta"
        )
    cuenta_funcion = ctx.get("accountId")
    if cuenta != cuenta_funcion:
        return no_determinable(
            f"la cuenta de quien firma ({cuenta}) no es la de la funcion "
            f"({cuenta_funcion or 'ausente en el evento'})"
        )
    return _resolver(arn, user_id, cuenta, "evento de la URL de funcion (authorizer.iam)")


def _resolver(arn: str, user_id: str, cuenta: str, fuente: str) -> AprobadorVerificado:
    """De (ARN, UserId, cuenta) a una identidad comparable y, si toca, a una persona.

    Tres casos. Usuario IAM: el ARN ya es el canonico. Rol asumido: el caso
    interesante, con el patron de la Fase 3: parsear para formular una
    hipotesis, y no fiarse de ella. Del ARN saco un nombre de rol candidato,
    se lo pregunto a IAM, y compruebo que el `RoleId` que devuelve sea el
    prefijo del `UserId` (`AROAXXXX:nombre-de-sesion`). Si cuadra, el ARN
    canonico es el que devolvio IAM, no el que yo construi. El resto no es
    determinable.

    La persona (ADR-003, B2) solo sale de un rol asumido ya verificado, y solo
    si ademas: el rol vive en el path de Identity Center, es del permission set
    del aprobador y el nombre de sesion del ARN es el que STS puso en el
    `UserId`. El nombre de sesion lo fija Identity Center, no la persona; con
    otro rol, un path distinto o una sesion que no cuadra, no hay persona, y
    `como_se_verifico` dice cual de las tres fallo.
    """
    usuario = _ARN_USUARIO.fullmatch(arn)
    if usuario and usuario.group(1) != cuenta:
        # Un ARN de otra cuenta no es "el usuario de esta": sin esta
        # comprobacion, `cuenta` (que la separacion y el techo leen) y el ARN
        # canonico podrian apuntar a cuentas distintas.
        return AprobadorVerificado(
            arn_llamante=arn,
            arn_canonico=None,
            user_id=user_id,
            cuenta=cuenta,
            como_se_verifico=(
                f"{fuente} da un usuario IAM de la cuenta {usuario.group(1)}, "
                f"y la cuenta de quien firma es {cuenta}"
            ),
            determinable=False,
        )
    if usuario:
        return AprobadorVerificado(
            arn_llamante=arn,
            arn_canonico=arn,
            user_id=user_id,
            cuenta=cuenta,
            como_se_verifico=(
                f"{fuente}; es un usuario IAM, asi que el ARN que devuelve ya "
                "es el canonico; un usuario IAM no tiene persona de Identity Center"
            ),
            determinable=True,
        )

    coincidencia = _ARN_ROL_ASUMIDO.fullmatch(arn)
    if coincidencia and coincidencia.group(1) != cuenta:
        # Igual que con el usuario IAM: la cuenta del ARN y la de `cuenta` (la
        # que leen la separacion y el techo) no pueden ser distintas. Antes
        # de preguntar a IAM, que contestaria por la cuenta del llamante.
        return AprobadorVerificado(
            arn_llamante=arn,
            arn_canonico=None,
            user_id=user_id,
            cuenta=cuenta,
            como_se_verifico=(
                f"{fuente} da un rol asumido de la cuenta {coincidencia.group(1)}, "
                f"y la cuenta de quien firma es {cuenta}"
            ),
            determinable=False,
        )
    if coincidencia:
        nombre, sesion = coincidencia.group(2), coincidencia.group(3)
        try:
            rol = _iam().get_role(RoleName=nombre)["Role"]
        except ClientError as e:
            return AprobadorVerificado(
                arn_llamante=arn,
                arn_canonico=None,
                user_id=user_id,
                cuenta=cuenta,
                como_se_verifico=(
                    f"{fuente} da un rol asumido, pero "
                    f"iam:GetRole('{nombre}') fallo: "
                    f"{e.response['Error']['Code']}"
                ),
                determinable=False,
            )

        if rol["RoleId"] != user_id.split(":", 1)[0]:
            # Un rol distinto con el mismo nombre (otra cuenta, o borrado y
            # recreado). El nombre coincide y la identidad no.
            return AprobadorVerificado(
                arn_llamante=arn,
                arn_canonico=None,
                user_id=user_id,
                cuenta=cuenta,
                como_se_verifico=(
                    f"el RoleId de '{nombre}' ({rol['RoleId']}) no es el "
                    f"prefijo del UserId de la sesion ({user_id})"
                ),
                determinable=False,
            )

        persona, motivo = None, ""
        if not rol.get("Path", "").startswith(_PATH_SSO):
            motivo = f"el rol no esta en el path {_PATH_SSO} de Identity Center"
        elif not _ROL_APROBADOR.fullmatch(rol["RoleName"]):
            motivo = f"el rol no es el del permission set ({_PREFIJO_ROL_APROBADOR}<sufijo>)"
        elif sesion != user_id.partition(":")[2]:
            motivo = "el nombre de sesion del ARN no es el del UserId"
        else:
            persona = sesion
        return AprobadorVerificado(
            arn_llamante=arn,
            arn_canonico=rol["Arn"],
            user_id=user_id,
            cuenta=cuenta,
            como_se_verifico=(
                f"{fuente} + iam:GetRole; el RoleId devuelto coincide con el "
                "prefijo del UserId de la sesion; "
                + (
                    "persona: el rol es del path y del permission set de Identity "
                    "Center y la sesion coincide con el UserId"
                    if persona
                    else f"sin persona: {motivo}"
                )
            ),
            determinable=True,
            persona=persona,
        )

    return AprobadorVerificado(
        arn_llamante=arn,
        arn_canonico=None,
        user_id=user_id,
        cuenta=cuenta,
        como_se_verifico=(
            "forma de ARN no reconocida (federated-user, SSO sin rol "
            "resoluble u otra); no se puede derivar una identidad "
            "comparable con la del beneficiario"
        ),
        determinable=False,
    )


# --- Paso 6: el techo del sistema -------------------------------------------


def techo(cuenta: str) -> tuple[dict, str]:
    """El documento contra el que se compara la propuesta, y de donde salio.

    Se prefiere el de IAM porque es el que esta EN VIGOR: el boundary que
    de verdad recorta al destino. El archivo de `infra/` es solo lo que
    declaramos querer. Si divergen y comparamos contra el archivo, la
    compuerta mide una cosa distinta de la que protege, asi que el origen
    se guarda en el registro para que se vea cual se uso.
    """
    arn = f"arn:aws:iam::{cuenta}:policy/{NOMBRE_TECHO}"
    try:
        version = _iam().get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
        documento = _iam().get_policy_version(PolicyArn=arn, VersionId=version)[
            "PolicyVersion"
        ]["Document"]
        if isinstance(documento, str):  # segun version de botocore
            documento = json.loads(urllib.parse.unquote(documento))
        return documento, f"IAM {arn} (version {version})"
    except ClientError as e:
        # Solo "no existe" justifica usar lo declarado. Un AccessDenied o un
        # throttling no dicen nada sobre el techo, y caer al archivo ahi
        # haria que la compuerta midiera otra cosa sin que nadie se entere.
        if e.response["Error"]["Code"] != "NoSuchEntity" or not _RUTA_TECHO_LOCAL.exists():
            raise
        return (
            json.loads(_RUTA_TECHO_LOCAL.read_text()),
            f"{_RUTA_TECHO_LOCAL} (DECLARADO, no en vigor: "
            f"'{NOMBRE_TECHO}' no existe todavia en la cuenta)",
        )


def comprobar_techo(documento: dict, cuenta: str) -> dict:
    """CheckNoNewAccess: ¿la propuesta concede algo por encima del techo?

    Esta es la unica llamada de pago del sistema, y esta aqui por eso: el
    coste queda acotado por actos humanos y no por vueltas del bucle. El
    simulador, que es gratis, sirve para iterar; esta es la compuerta final.

    La simetria que la justifica: el MISMO techo se comprueba en dos
    momentos y por dos mecanismos distintos. IAM lo impone en ejecucion, a
    traves del permission boundary del destino; esto lo comprueba antes de
    aplicar, aqui. Si el codigo fallara, quedaria el boundary; si alguien
    quitara el boundary, quedaria esto.
    """
    documento_techo, origen = techo(cuenta)
    respuesta = _analyzer().check_no_new_access(
        newPolicyDocument=json.dumps(documento),
        existingPolicyDocument=json.dumps(documento_techo),
        policyType="IDENTITY_POLICY",
    )
    return {
        "origen_del_techo": origen,
        "resultado": respuesta.get("result"),
        "mensaje": respuesta.get("message"),
        "motivos": [
            {"descripcion": m.get("description"), "indices": m.get("statementIndex")}
            for m in respuesta.get("reasons") or []
        ],
    }


# --- Paso 5: revalidacion con las reglas de hoy ------------------------------


def revalidar(registro: dict) -> dict:
    """Vuelve a correr barandas, Access Analyzer y chequeos posteriores.

    No es paranoia: el 29-08-2026, `052dd48a.json` (en `solicitudes/`, que
    no se versiona: un clon limpio no lo tiene) estaba en estado
    `propuesta` con una politica que las barandas de ese dia ya bloqueaban,
    porque se propuso bajo unas reglas que habian dejado de existir. Nadie
    debe aprobar a ciegas algo que las reglas actuales rechazan.

    Responde una pregunta DISTINTA de la huella: la huella dice "¿es esto
    lo que se aprobo?", esto dice "¿sigue siendo aceptable?". Un registro
    intacto puede haber quedado obsoleto.
    """
    try:
        solicitud = SolicitudEstructurada.model_validate(registro["solicitud"])
        propuesta = PropuestaPolitica.model_validate(registro["propuesta"])
    except ValidationError as e:
        # Un registro que ya no cumple el contrato (S9: un statement con
        # `NotResource`; S7: una justificacion con caracteres de control) no
        # se puede juzgar, y lo que no se puede juzgar no pasa. Antes la
        # excepcion subia y el aplicador moria con una traza.
        return {
            "aprobable": False,
            "bloqueos": [f"El registro no cumple el contrato de hoy: {e.error_count()} errores ({e.errors()[0]['msg']})."],
            "criticos": [],
            "menores": [],
            "cuando": _ahora(),
        }
    identidad = registro["identidad_verificada"]
    documento = propuesta.policy_document.model_dump(exclude_none=True)

    veredicto = validar_politica(json.dumps(documento))
    # El formulario guardado tambien se vuelve a juzgar (S8): sin esto, un
    # `servicio` fuera de SERVICIOS_PERMITIDOS hacia "del servicio pedido"
    # a las acciones de ese servicio.
    bloqueos = chequeos_formulario(solicitud.campos)
    posteriores, advertencias = chequeos_posteriores(propuesta, solicitud, identidad)
    bloqueos += posteriores
    if bloqueos:
        veredicto["aprobable"] = False
        veredicto["bloqueos"].extend(bloqueos)
    veredicto["menores"].extend(advertencias)
    veredicto["cuando"] = _ahora()
    return veredicto


# --- El flujo ----------------------------------------------------------------


def aprobar(
    registro: dict,
    aprobador: AprobadorVerificado,
    autoaprobacion_demo: bool = False,
    riesgo_confirmado: bool = False,
    huella_confirmada: str | None = None,
) -> tuple[dict | None, list[str]]:
    """Devuelve (registro_aprobado, bloqueos). Si hay bloqueos, no aprueba.

    El registro que entra es el UNICO leido, y el que sale es ese mismo
    objeto con el bloque de aprobacion atado encima. La huella se calcula
    sobre lo que habia antes de anadirlo (ver `huella.instantanea`).

    Quien aprueba LLEGA identificado (ADR-003): `aprobar` ya no pregunta a
    STS. Lo identifica quien llama (la CLI con `identificar_aprobador`, la
    Lambda con `aprobador_desde_evento`), y asi la misma decision se prueba
    con cualquier aprobador sin tocar la red.
    """
    bloqueos: list[str] = []

    # 2. Compuerta de estado.
    estado = registro.get("estado")
    if estado not in ESTADOS_APROBABLES:
        return None, [
            f"El estado es '{estado}' y solo se aprueba desde "
            f"{' o '.join(ESTADOS_APROBABLES)}. " + _por_que_no(estado)
        ]
    if registro.get("aprobacion") or registro.get("rechazo"):
        return None, ["Esta solicitud ya tiene una decision (aprobacion o rechazo)."]

    # Lo que se firma tiene que ser lo que el humano vio. Se compara contra
    # la huella de ESTE objeto, el mismo que se pinto y el mismo que se
    # escribira.
    huella_actual = huella.calcular(registro)
    if huella_confirmada is None:
        return None, [
            "Falta confirmar la huella. Revisa la propuesta y repite con "
            f"--huella {huella_actual}"
        ]
    if not huella.coincide(registro, huella_confirmada):
        return None, [
            f"La huella confirmada ({huella_confirmada}) no es la del registro "
            f"leido ahora ({huella_actual}): cambio desde que lo revisaste. "
            "Vuelve a revisarlo."
        ]

    # 3. Quien aprueba: ya viene en `aprobador`.
    # 4. Separacion de funciones.
    beneficiario = (registro.get("identidad_verificada") or {}).get("principal_arn", "")
    separacion, motivo_bloqueo = _separacion(aprobador, registro, autoaprobacion_demo)
    if motivo_bloqueo:
        bloqueos.append(motivo_bloqueo)

    # Friccion por riesgo. Dos fuentes, y basta una: lo que marco el modelo
    # (solo puede ANADIR friccion) y el minimo que fija el codigo
    # (22-10-2026). El minimo se RECALCULA aqui desde el registro leido, que
    # esta entero bajo la huella: editar el campo `riesgo_minimo` guardado
    # no lo rebaja. Un 'bajo' no relaja ningun otro control.
    nivel = (registro.get("propuesta") or {}).get("nivel_riesgo")
    motivos_riesgo = riesgo_minimo(
        registro.get("solicitud") or {},
        beneficiario,
        registro.get("historial_validacion") or [],
        registro.get("nivel_real"),
    )
    if (nivel == "alto" or motivos_riesgo) and not riesgo_confirmado:
        origen = "; ".join(motivos_riesgo) if motivos_riesgo else "lo marco el modelo"
        bloqueos.append(
            f"Riesgo alto ({origen}). Repitelo con --riesgo-alto-confirmado "
            "si aun asi la apruebas; quedara grabado que lo confirmaste."
        )

    # 5. Revalidacion.
    veredicto = revalidar(registro)
    if not veredicto["aprobable"]:
        bloqueos.append(
            "La propuesta NO pasa las barandas de hoy; se aprobo bajo reglas "
            "anteriores o algo cambio. Bloqueos: "
            + "; ".join(veredicto["bloqueos"])
        )

    # 6. Compuerta pagada. Contra el techo de la cuenta del BENEFICIARIO,
    # que es donde se aplicara, no la del aprobador.
    documento = registro["propuesta"]["policy_document"]
    cuenta = (registro.get("identidad_verificada") or {}).get("cuenta") or aprobador.cuenta
    try:
        resultado_techo = comprobar_techo(documento, cuenta)
    except Exception as e:
        # No poder correr la compuerta no es lo mismo que pasarla. Bloquea,
        # porque la alternativa es aprobar sin haber comprobado el techo.
        resultado_techo = {"resultado": "NO_EJECUTADO", "mensaje": str(e)}
        bloqueos.append(f"No se pudo ejecutar CheckNoNewAccess: {e}")
    else:
        if resultado_techo["resultado"] != "PASS":
            bloqueos.append(
                "CheckNoNewAccess dice que la propuesta concede acceso por "
                f"encima del techo del sistema: {resultado_techo['mensaje']}"
            )

    if bloqueos:
        return None, bloqueos

    # 7 y 8. La huella se calcula ANTES de atar el bloque, y sobre el
    # registro entero: de `campos` e `identidad_verificada` depende la
    # revalidacion del aplicador tanto como de `propuesta`.
    registro["aprobacion"] = {
        "cuando": _ahora(),
        "por": aprobador.model_dump(),
        "huella": huella_actual,
        "separacion_de_funciones": separacion,
        "revalidacion": veredicto,
        "techo": resultado_techo,
        "riesgo_confirmado": riesgo_confirmado,
    }
    registro["estado"] = "aprobada"
    return registro, []


def _por_que_no(estado: str | None) -> str:
    return {
        "requiere_revision_humana": "Ese estado necesita otro acto: un humano "
        "redactando la politica a mano, no una aprobacion.",
        "redundante_no_requiere_cambio": "No hay nada que aplicar.",
        "error": "No hay una propuesta valida que aprobar.",
        "aprobada": "Ya lo esta; sobrescribirla borraria evidencia.",
        "aplicada": "Ya se aplico; sobrescribirla borraria evidencia.",
        "bloqueada_al_aplicar": "El aplicador la bloqueo en el pre-vuelo; se tramita de nuevo con otro id.",
        "rechazada_en_chequeos_previos": "No hay una propuesta que aprobar.",
        "rechazada_por_aprobador": "Un humano ya la rechazo.",
    }.get(estado or "", "")


def _misma_persona(a: str, b: str) -> bool:
    """Dos nombres de usuario de Identity Center, por la misma persona?

    NFKC y `casefold` a los dos lados (ADR-003, B): tomar por distintos a
    `Aprobador.Demo` y `aprobador.demo`, o a una cadena en ancho completo y su
    forma normal, dejaria pasar una autoaprobacion. Tomar por iguales a dos
    nombres que solo difieren asi bloquea, a lo sumo, una aprobacion legitima,
    y de forma visible.
    """
    return unicodedata.normalize("NFKC", a).casefold() == unicodedata.normalize("NFKC", b).casefold()


def _persona(valor: object) -> str | None:
    """La persona si es un texto con contenido; cualquier otra cosa es duda."""
    return valor if isinstance(valor, str) and valor.strip() else None


def _separacion(
    aprobador: AprobadorVerificado, registro: dict, autoaprobacion_demo: bool
) -> tuple[dict, str | None]:
    """Los tres desenlaces. Ninguno pasa en silencio.

    Compara PERSONAS de Identity Center (ADR-003, B2): el aprobador frente al
    solicitante, y se mantiene el aprobador frente al beneficiario (su ARN, y
    el nombre si el beneficiario es un usuario IAM). Los problemas se juntan
    en orden y bloquea el primero; el resto viaja en el `motivo` del SALTADO,
    para que la puerta explicita deje grabado todo lo que se salto.

    La direccion de la duda: si no se puede determinar quien aprueba o quien
    pidio y se deja pasar, el control falla sin que nadie se entere. Si
    bloquea, molesta a alguien legitimo pero de forma visible y recuperable:
    ve el motivo, y o arregla sus credenciales o usa la puerta explicita, que
    deja rastro. Por eso la duda bloquea.
    """
    beneficiario = (registro.get("identidad_verificada") or {}).get("principal_arn", "")
    persona_aprobador = _persona(aprobador.persona)
    bloque_solicitante = registro.get("solicitante")
    persona_solicitante = _persona(
        bloque_solicitante.get("persona") if isinstance(bloque_solicitante, dict) else None
    )
    base = {
        "beneficiario": beneficiario,
        "aprobador": persona_aprobador,
        "solicitante": persona_solicitante,
    }

    problemas: list[str] = []
    if not aprobador.determinable:
        problemas.append(
            "No se pudo determinar una identidad comparable para el "
            f"aprobador: {aprobador.como_se_verifico}. No se puede "
            "comprobar la separacion de funciones."
        )
    elif persona_aprobador is None:
        problemas.append(
            "No se pudo determinar la persona del aprobador (solo la da un "
            f"rol de Identity Center): {aprobador.como_se_verifico}. No se "
            "puede comprobar la separacion de funciones."
        )
    if persona_solicitante is None:
        problemas.append(
            "No se pudo determinar la persona del solicitante "
            + (
                f"({bloque_solicitante.get('como_se_verifico')}). "
                if isinstance(bloque_solicitante, dict) and bloque_solicitante.get("como_se_verifico")
                else "(el registro no la trae). "
            )
            + "No se puede comprobar la separacion de funciones."
        )
    if persona_aprobador and persona_solicitante and _misma_persona(persona_aprobador, persona_solicitante):
        problemas.append(
            f"Autoaprobacion: el aprobador ({persona_aprobador}) es la misma persona "
            "que el solicitante de la solicitud."
        )
    if aprobador.determinable and aprobador.arn_canonico == beneficiario:
        problemas.append(
            f"Autoaprobacion: el aprobador ({aprobador.arn_canonico}) es el "
            "beneficiario de la solicitud."
        )
    # Solo un usuario IAM lleva nombre de persona; un rol no es una persona.
    # `fullmatch` y DOTALL: con `$`, un salto de linea final se colaba dentro del
    # nombre y "aprobador.demo\n" dejaba de ser la misma persona. El `strip` es
    # por el mismo motivo: un espacio al borde no hace a otra persona.
    usuario_iam = re.fullmatch(r"arn:aws:iam::\d{12}:user/(?:.*/)?([^/]+)", beneficiario, re.DOTALL)
    if (
        persona_aprobador
        and usuario_iam
        and _misma_persona(usuario_iam.group(1).strip(), persona_aprobador)
    ):
        problemas.append(
            f"Autoaprobacion: el beneficiario ({beneficiario}) lleva el nombre "
            f"del aprobador ({persona_aprobador})."
        )

    if not problemas:
        return {**base, "resultado": "cumplido"}, None

    if not autoaprobacion_demo:
        return {**base, "resultado": "cumplido"}, problemas[0] + (
            " Usa --autoaprobacion-demo si aun asi quieres aprobarla; "
            "quedara grabado que te saltaste el control."
        )

    return (
        {
            **base,
            "resultado": "SALTADO",
            "motivo": " ".join(problemas),
            "saltado_por": aprobador.arn_llamante,
            "cuando": _ahora(),
        },
        None,
    )


def rechazar(
    registro: dict, motivo: str, aprobador: AprobadorVerificado
) -> tuple[dict | None, list[str]]:
    """Un humano dice que no. Tambien es una decision que hay que registrar.

    Va en su propio bloque, `rechazo` (24-10-2026). Antes era una clave
    dentro de `aprobacion`, y un bloque llamado aprobacion que dice que no
    era una trampa para quien lo leyera, persona o codigo.
    """
    if registro.get("estado") not in ESTADOS_APROBABLES:
        return None, [f"El estado es '{registro.get('estado')}'; no hay nada que rechazar."]
    if registro.get("aprobacion") or registro.get("rechazo"):
        return None, ["Esta solicitud ya tiene una decision (aprobacion o rechazo)."]
    registro["rechazo"] = {
        "cuando": _ahora(),
        "por": aprobador.model_dump(),
        "huella": huella.calcular(registro),
        "motivo": motivo,
    }
    registro["estado"] = "rechazada_por_aprobador"
    return registro, []


# --- La Lambda de aprobacion (ADR-003, A2) -----------------------------------


def decidir(
    peticion: PeticionAprobacion, aprobador: AprobadorVerificado, *, exigir_persona: bool = False
) -> tuple[int, dict]:
    """Lo que hacia `main()` tras identificarse, con la identidad ya dada.

    Una sola lectura, `aprobar` o `rechazar`, una sola escritura condicionada
    al estado LEIDO. No resuelve a nadie: el aprobador llega verificado (el
    manejador lo saco de la firma). Codigos: 200 la decision esta escrita,
    404 no existe, 409 la bloquea un control (incluida una fila con forma
    imposible y una decision que se cruzo con otra). Todo cuerpo lleva el id
    y el aprobador, para que quien lo reciba vea a quien se le atribuyo.

    `exigir_persona` es la decision 2 de ADR-003 (aceptada): en el servidor
    solo decide el permission set AgenteIAM-Aprobador, asi que quien firma sin
    persona (un administrador con permiso de invocar, por ejemplo) ni aprueba
    ni rechaza, y `autoaprobacion_demo` no lo salva. Solo lo pone el
    manejador. El cliente en disco (desarrollo local) llama sin ella: ahi
    nadie firma con persona, y exigirla dejaria el desarrollo sin camino; en
    disco sigue siendo un problema de separacion que la puerta explicita salta.
    """
    base = {"id": peticion.id, "aprobador": aprobador.model_dump()}

    if exigir_persona and aprobador.persona is None:
        # Antes de leer: no hay nada que mirar si quien firma no puede decidir.
        return 409, {
            **base,
            "resultado": "bloqueada",
            "bloqueos": [
                "En el servidor solo puede decidir el permission set AgenteIAM-Aprobador "
                f"(Identity Center); tu identidad no es de ese permission set: {aprobador.como_se_verifico}"
            ],
        }

    if exigir_persona and peticion.autoaprobacion_demo:
        # La puerta existe para el cliente en disco, donde nadie firma con
        # persona. En el servidor no hay nada que saltar: aceptarla dejaba una
        # fila `aprobada` con separacion SALTADO, que el aplicador bloquea
        # despues; mejor no escribirla (Fase 33).
        return 409, {
            **base,
            "resultado": "bloqueada",
            "bloqueos": [
                "En el servidor no existe la puerta de autoaprobacion: `autoaprobacion_demo` "
                "solo vale en el cliente de desarrollo sobre disco. Repite la peticion sin ella."
            ],
        }

    try:
        registro = almacen.leer(peticion.id)
    except almacen.RegistroInconsistente as e:
        # Una fila con forma imposible (S1) es un control que salta.
        return 409, {**base, "resultado": "bloqueada", "bloqueos": [str(e)]}
    if registro is None:
        return 404, {**base, "resultado": "no_existe"}

    # Se apunta ANTES de decidir: `aprobar` y `rechazar` mutan el registro en
    # sitio, y condicionar la escritura con el estado nuevo no protegeria de nada.
    estado_leido = registro.get("estado", "")

    if peticion.accion == "rechazar":
        bloque = "rechazo"
        resultado, bloqueos = rechazar(registro, peticion.motivo or "", aprobador)
    elif exigir_persona and (registro.get("identidad_verificada") or {}).get("modo") != "rol_por_persona":
        # El runtime solo escribe filas del modo rol por persona. Adjuntar a un
        # principal que ya existe es el modo del CLI de desarrollo: en la
        # cuenta dejaria aprobar una concesion a cualquier principal que lleve
        # el techo, tambien al rol de otra persona (Fase 33). Rechazarla si se
        # puede: la cierra sin conceder nada.
        return 409, {
            **base,
            "resultado": "bloqueada",
            "bloqueos": [
                "En el servidor solo se aprueban solicitudes del modo rol por persona; "
                "esta fila es de otro modo. Puedes rechazarla."
            ],
        }
    else:
        bloque = "aprobacion"
        resultado, bloqueos = aprobar(
            registro,
            aprobador,
            peticion.autoaprobacion_demo,
            peticion.riesgo_alto_confirmado,
            peticion.huella,
        )

    if bloqueos:
        return 409, {**base, "resultado": "bloqueada", "bloqueos": bloqueos}

    # Sin bloqueos siempre hay resultado. Si se rompe, falla aqui y antes de
    # escribir (el manejador lo vuelve un 500), no dentro del almacen.
    if resultado is None:
        raise RuntimeError(f"{peticion.id}: sin bloqueos y sin resultado (contrato roto)")

    try:
        # Solo viaja el bloque de la decision y el estado. La clave es el id
        # pedido y leido, no el que diga el registro (S1).
        donde = almacen.guardar_decision(resultado, bloque, estado_leido, clave=peticion.id)
    except (almacen.EstadoCambiado, almacen.RegistroInconsistente) as e:
        return 409, {**base, "resultado": "bloqueada", "bloqueos": [str(e)]}

    return 200, {
        **base,
        "resultado": resultado["estado"],
        "estado": resultado["estado"],
        "decision": resultado[bloque],
        "guardado_en": donde,
    }


# Lo que se comprobo al arrancar (lista de problemas, vacia si todo bien). Se
# calcula una vez por arranque en frio: cargar los catalogos no es gratis y
# no cambian entre dos peticiones. Los tests la ponen a None para repetirlo.
_problemas_entorno: list[str] | None = None


def _comprobar_entorno() -> list[str]:
    """Por que esta Lambda no debe decidir nada todavia; vacio si puede.

    Dos condiciones: el almacen es DynamoDB (en disco no hay IAM que reserve
    el bloque a esta Lambda, y la garantia de ADR-003 se quedaria en el
    papel) y los catalogos de todos los servicios cargan (sin ellos el
    chequeo de nivel de acceso se apaga en silencio al revalidar).
    """
    global _problemas_entorno
    if _problemas_entorno is None:
        problemas = []
        if almacen.ALMACEN != "dynamodb":
            problemas.append(f"ALMACEN es '{almacen.ALMACEN}' y la aprobacion exige 'dynamodb'")
        faltan = catalogo.no_disponibles(SERVICIOS_PERMITIDOS)
        if faltan:
            problemas.append("catalogos de servicio no disponibles: " + ", ".join(faltan))
        _problemas_entorno = problemas
    return _problemas_entorno


def _identidad_firmada(evento: dict) -> dict[str, str] | None:
    """`userArn`, `userId` y `accountId` de la firma, o None si no estan (R3).

    Solo la identidad AUSENTE o ilegible corta aqui (400): no hay a quien
    atribuir nada. Una presente pero no comparable (federada, otra cuenta,
    rol ordinario) sigue a `decidir`, donde la separacion la bloquea con su
    motivo. `accessKey` ni se mira: es una credencial temporal.
    """
    ctx = evento.get("requestContext")
    authorizer = ctx.get("authorizer") if isinstance(ctx, dict) else None
    iam = authorizer.get("iam") if isinstance(authorizer, dict) else None
    if not isinstance(iam, dict):
        return None
    datos = {}
    for campo in ("userArn", "userId", "accountId"):
        valor = iam.get(campo)
        if not isinstance(valor, str) or not valor:
            return None
        datos[campo] = valor
    return datos


def _cuerpo_de_la_peticion(evento: dict) -> PeticionAprobacion:
    """El cuerpo de la URL de funcion como peticion; ValueError si no lo es."""
    cuerpo = evento.get("body")
    if not isinstance(cuerpo, str) or not cuerpo:
        raise ValueError("la peticion no trae cuerpo")
    if evento.get("isBase64Encoded") is True:
        try:
            cuerpo = base64.b64decode(cuerpo, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError("el cuerpo no es base64 de un texto UTF-8") from e
    try:
        datos = json.loads(cuerpo)
    except (ValueError, RecursionError) as e:  # JSONDecodeError; RecursionError: anidado sin fin
        raise ValueError("el cuerpo no es JSON") from e
    if not isinstance(datos, dict):
        raise ValueError("el cuerpo no es un objeto JSON")
    try:
        return PeticionAprobacion.model_validate(datos)
    except ValidationError as e:
        # Campo y motivo, sin `input`: no se devuelve lo que se envio.
        campos = ", ".join(sorted({".".join(str(p) for p in err["loc"]) or "(cuerpo)" for err in e.errors()}))
        raise ValueError(f"la peticion no cumple el contrato: {campos}") from e


def _respuesta(codigo: int, cuerpo: dict) -> dict:
    # ASCII: lo que el bloqueo cita lo escribieron otros (S7), y un U+202E o
    # un C1 llegarian crudos a la terminal del cliente. Escapado, no llega.
    return {
        "statusCode": codigo,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(cuerpo, ensure_ascii=True),
    }


def manejador(evento: dict, contexto) -> dict:
    """Punto de entrada de la Lambda `agente-iam-aprobacion` (URL de funcion, AWS_IAM).

    Orden: entorno, metodo, cuerpo, identidad firmada, `decidir`. Un entorno
    roto o un error inesperado es 500 y no escribe; la peticion mal formada
    o sin identidad es 400 y no lee. Un log por peticion con quien, que y el
    codigo; nunca la clave de acceso ni nada del registro.
    """
    traza: dict[str, str] = {"id": "-", "accion": "-", "userArn": "-", "userId": "-", "accountId": "-"}
    error = None
    try:
        codigo, cuerpo = _atender(evento, traza)
    except Exception as e:
        error = e  # `exc_info=True` fuera del `except` no traeria traza
        codigo, cuerpo = 500, {"error": "error inesperado", "tipo": type(e).__name__}
    log.log(
        logging.ERROR if codigo >= 500 else logging.INFO,
        "aprobacion id=%s accion=%s userArn=%s userId=%s accountId=%s status=%d",
        traza["id"], traza["accion"], traza["userArn"], traza["userId"], traza["accountId"], codigo,
        exc_info=error,
    )
    return _respuesta(codigo, cuerpo)


def _atender(evento: dict, traza: dict[str, str]) -> tuple[int, dict]:
    """El camino de una peticion; rellena `traza` segun va sabiendo cosas."""
    problemas = _comprobar_entorno()
    if problemas:
        return 500, {"error": "entorno no apto para decidir", "detalle": problemas}

    ctx = evento.get("requestContext") if isinstance(evento, dict) else None
    http = ctx.get("http") if isinstance(ctx, dict) else None
    if not isinstance(http, dict) or http.get("method") != "POST":
        return 405, {"error": "solo POST"}

    try:
        peticion = _cuerpo_de_la_peticion(evento)
    except ValueError as e:
        return 400, {"error": str(e)}
    traza["id"], traza["accion"] = peticion.id, peticion.accion

    firmada = _identidad_firmada(evento)
    if firmada is None:
        return 400, {"error": "la peticion no trae identidad firmada (requestContext.authorizer.iam)"}
    # Escapado: aunque AWS firma estos valores, el log no pinta nada crudo.
    traza.update({k: _t(v) for k, v in firmada.items()})

    return decidir(peticion, aprobador_desde_evento(evento), exigir_persona=True)


# --- Como se llega aqui -----------------------------------------------------

if __name__ == "__main__":
    # `main()` se fue (ADR-003, A2): este modulo es el servidor, y la persona
    # aprueba con su cliente. No se importa el cliente desde aqui.
    print("Para aprobar: python -m agente_iam.aprobar_cliente <id> (ADR-003)")
    sys.exit(1)
