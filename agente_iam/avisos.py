"""Los avisos: un correo a la persona cuando su solicitud acaba algo.

En la cuenta es la Lambda `agente-iam-avisos`, disparada por el stream de la
tabla (`manejador`). La persona que pidio por la web no tiene terminal ni lee
la tabla: sin este correo no se enteraria de que su permiso esta activo, de que
alguien lo rechazo o de que el sistema lo bloqueo. El aviso le dice solo que
paso y, si la solicitud quedo `aplicada`, con que rol y hasta cuando.

NUNCA lleva la politica, la justificacion ni quien aprobo. El correo sale del
sistema y no se controla donde acaba (un reenvio, un buzon compartido, un
archivo), asi que lo que viaja es lo minimo para actuar y nada que describa la
solicitud ni a las personas que intervinieron. El ARN del rol y la hora de
vencimiento si van en `aplicada`: es lo que la persona necesita para usarlo y no
es secreto, porque nadie mas puede asumir ese rol (la confianza esta atada a su
`sub`). El cuerpo se forma SOLO con el id, el estado, una frase fija por estado
y, en `aplicada`, esas dos lineas: no se copia nada mas del registro.

CUANDO AVISA. Por cada registro `INSERT` o `MODIFY` del stream, si el estado de
la imagen nueva esta en `ESTADOS_QUE_AVISAN`, es distinto del de la imagen vieja
(un `MODIFY` que solo toca otro atributo no repite el correo) y el documento
trae `correo_aviso`. El filtro del disparador deja pasar los mismos estados;
esto lo repite como defensa en profundidad y para decidir el cambio de estado,
que el filtro no ve.

SOLO TRAS UNA DECISION HUMANA (Fase 33). `correo_aviso` lo escribe quien pide y
nadie lo compara con su identidad: el token de acceso no trae correo y el
nombre de usuario de Identity Center no tiene por que serlo. Por eso no avisan
los estados que decide el intake solo (`rechazada_en_chequeos_previos`,
`requiere_revision_humana`, `redundante_no_requiere_cambio`): con ellos, una
persona con sesion haria que el sistema escribiera a la direccion de un
tercero tantas veces como quisiera, sin que nadie mas interviniera. Ese
resultado ya se lo da la respuesta del servidor al pedir, igual que
`propuesta`. Avisan los cuatro estados que siguen a la decision de un
aprobador, que ve la direccion de aviso antes de decidir.

UN CORREO QUE NO SALE NO ES UN FALLO DEL CIRCUITO. Mientras SES este en modo
inicial solo entrega a direcciones verificadas: `MessageRejected` (destino sin
verificar) y `MailFromDomainNotVerified` (remitente sin verificar) se registran
en WARNING, con el id, el estado, el codigo y SOLO el dominio del correo, y no se
relanzan ni se reintentan: la solicitud ya esta aplicada o rechazada, y
reintentar el mismo evento no verificaria la direccion. Cualquier otro
`ClientError` (throttling, un fallo de SES) sube: la invocacion falla y queda en
el log; el disparador no reintenta ni tiene cola (runtime.yaml), porque un aviso
no es el circuito.

LO QUE DEVUELVE. `{"avisados": [<id>, ...], "omitidos": [[<id>, <motivo>], ...]}`.
Los motivos son `sin_cambio_de_estado`, `estado_no_avisa`, `sin_correo`,
`evento_<nombre>` (REMOVE u otro) y el codigo de SES cuando lo rechaza.

EL LOG. Un `INFO` por registro con el id, el estado, si se aviso y el dominio
del correo. Nunca el correo entero (es un dato de la persona) ni el cuerpo.

Sin `AGENTE_IAM_REMITENTE` el manejador lanza antes de mirar nada: un entorno
roto no decide, y el fallo queda a la vista en el log de cada invocacion.
No habla con el modelo, no lee la tabla (todo lo que necesita viene en el
evento) ni toca IAM: su rol solo puede enviar correo desde la identidad
remitente y leer el stream.
"""

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

from agente_iam.config import AWS_REGION
from agente_iam.motivos import motivo_publico

log = logging.getLogger("agente-iam.avisos")
log.setLevel(logging.INFO)

# Estados que siguen a la decision de un aprobador. Los que decide el intake
# solo (y `propuesta`) no estan: los da la respuesta del servidor, y avisarlos
# convertia el alta de una solicitud en un correo a la direccion que eligiera
# quien pide (ver el docstring).
ESTADOS_QUE_AVISAN = (
    "aprobada",
    "rechazada_por_aprobador",
    "aplicada",
    "bloqueada_al_aplicar",
)

# Una frase fija por estado: no se arma con datos de la solicitud.
FRASES: dict[str, str] = {
    "aprobada": "Una persona aprobo tu solicitud; el permiso se esta aplicando.",
    "rechazada_por_aprobador": "Una persona rechazo tu solicitud.",
    "aplicada": "El permiso esta activo. Asume el rol con tu token de identidad antes de la hora de vencimiento.",
    "bloqueada_al_aplicar": "Un control del sistema bloqueo la aplicacion; hay que pedirla de nuevo.",
}

# Errores de SES que no son del circuito: el correo no sale y ya.
_RECHAZOS_DE_SES = ("MessageRejected", "MailFromDomainNotVerified")

REMITENTE = os.getenv("AGENTE_IAM_REMITENTE", "")
# La pagina, para el enlace con el id en el aviso de `aplicada` (Fase 28). Sin
# ella el correo sale sin enlace.
URL_WEB = os.getenv("AGENTE_IAM_URL_WEB", "")

_cliente_ses = None


def _ses():
    """El cliente de SES, creado una vez por entorno de ejecucion.

    Los tests lo sustituyen (`monkeypatch` de `avisos._ses`) por uno envuelto
    en `Stubber`.
    """
    global _cliente_ses
    if _cliente_ses is None:
        _cliente_ses = boto3.client("ses", region_name=AWS_REGION)
    return _cliente_ses


def cuerpo_del_correo(
    solicitud_id: str,
    estado: str,
    aplicacion: dict | None,
    motivo: str | None = None,
    url_web: str = "",
) -> tuple[str, str]:
    """(asunto, cuerpo) del aviso. El cuerpo se forma SOLO con id, estado, la
    frase (el `motivo` de `motivos.motivo_publico` si lo hay, que tambien se
    arma con frases fijas; si no, la de `FRASES`) y, en `aplicada`, el rol, el
    vencimiento del bloque `aplicacion` y el enlace a la pagina con el id."""
    asunto = f"Agente IAM: solicitud {solicitud_id} {estado}"
    cuerpo = f"Solicitud {solicitud_id}: {estado}. {motivo or FRASES[estado]}"
    if estado == "aplicada" and aplicacion:
        rol_arn = aplicacion.get("rol_arn")
        vence = aplicacion.get("vence")
        if rol_arn and vence:
            cuerpo += f"\nRol: {rol_arn}\nVence: {vence} (UTC)"
    if estado == "aplicada" and url_web:
        cuerpo += f"\nCredenciales: {url_web.rstrip('/')}/?solicitud={solicitud_id}"
    return asunto, cuerpo


def registro_de(imagen: dict | None) -> dict:
    """El registro de una imagen del stream: el `documento` (JSON) con el
    `estado` y los bloques de decision (`aprobacion`, `rechazo`, `aplicacion`,
    cada uno JSON en texto) encima. Lo que falte o no sea JSON se queda fuera."""
    registro: dict = {}
    texto = ((imagen or {}).get("documento") or {}).get("S")
    if texto:
        try:
            documento = json.loads(texto)
        except ValueError:
            documento = None
        if isinstance(documento, dict):
            registro.update(documento)
    for bloque in ("aprobacion", "rechazo", "aplicacion"):
        crudo = ((imagen or {}).get(bloque) or {}).get("S")
        if crudo:
            try:
                valor = json.loads(crudo)
            except ValueError:
                continue
            if isinstance(valor, dict):
                registro[bloque] = valor
    estado = estado_de(imagen)
    if estado:
        registro["estado"] = estado
    return registro


def estado_de(imagen: dict | None) -> str | None:
    """El `estado` de una imagen del stream, o None si no esta."""
    return ((imagen or {}).get("estado") or {}).get("S")


def id_de(imagen: dict | None) -> str | None:
    """El `id` de una imagen del stream, o None si no esta."""
    return ((imagen or {}).get("id") or {}).get("S")


def correo_de(imagen: dict | None) -> str | None:
    """El `correo_aviso` del documento de la imagen, o None si falta cualquier
    pieza o el documento no es un objeto JSON con la forma esperada."""
    texto = ((imagen or {}).get("documento") or {}).get("S")
    if not texto:
        return None
    try:
        documento = json.loads(texto)
    except ValueError:
        return None
    if not isinstance(documento, dict):
        return None
    solicitud = documento.get("solicitud")
    if not isinstance(solicitud, dict):
        return None
    correo = solicitud.get("correo_aviso")
    return correo if isinstance(correo, str) and correo else None


def aplicacion_de(imagen: dict | None) -> dict | None:
    """El bloque `aplicacion` de la imagen (JSON en texto), o None."""
    texto = ((imagen or {}).get("aplicacion") or {}).get("S")
    if not texto:
        return None
    try:
        bloque = json.loads(texto)
    except ValueError:
        return None
    return bloque if isinstance(bloque, dict) else None


def _dominio(correo: str | None) -> str:
    """Solo lo que hay tras la `@`: lo unico del correo que se escribe en el log."""
    if not correo or "@" not in correo:
        return "-"
    return correo.rsplit("@", 1)[1]


def manejador(evento: dict, contexto) -> dict:
    """Punto de entrada de la Lambda `agente-iam-avisos` (stream de la tabla).

    Devuelve `{"avisados": [id, ...], "omitidos": [[id, motivo], ...]}`.
    """
    if not REMITENTE:
        raise RuntimeError("AGENTE_IAM_REMITENTE no esta definido")

    avisados: list[str] = []
    omitidos: list[list[str]] = []
    for registro in evento.get("Records", []):
        nombre = registro.get("eventName")
        cambio = registro.get("dynamodb") or {}
        nueva = cambio.get("NewImage")
        vieja = cambio.get("OldImage")
        solicitud_id = id_de(nueva) or ((cambio.get("Keys") or {}).get("id") or {}).get("S") or "-"
        estado = estado_de(nueva)
        correo = correo_de(nueva)

        motivo = None
        if nombre not in ("INSERT", "MODIFY"):
            motivo = f"evento_{nombre}"
        elif estado not in ESTADOS_QUE_AVISAN:
            motivo = "estado_no_avisa"
        elif estado == estado_de(vieja):
            motivo = "sin_cambio_de_estado"
        elif not correo:
            motivo = "sin_correo"

        # Los `is not None` ya los garantiza `motivo is None`; estan para mypy.
        if motivo is None and estado is not None and correo is not None:
            texto_motivo = motivo_publico(registro_de(nueva))["texto"] or None
            asunto, cuerpo = cuerpo_del_correo(
                solicitud_id, estado, aplicacion_de(nueva), motivo=texto_motivo, url_web=URL_WEB
            )
            try:
                _ses().send_email(
                    Source=REMITENTE,
                    Destination={"ToAddresses": [correo]},
                    Message={
                        "Subject": {"Data": asunto, "Charset": "UTF-8"},
                        "Body": {"Text": {"Data": cuerpo, "Charset": "UTF-8"}},
                    },
                )
            except ClientError as e:
                codigo = e.response.get("Error", {}).get("Code", "")
                if codigo not in _RECHAZOS_DE_SES:
                    raise
                log.warning(
                    "aviso rechazado por SES id=%s estado=%s codigo=%s dominio=%s",
                    solicitud_id, estado, codigo, _dominio(correo),
                )
                motivo = codigo
            else:
                avisados.append(solicitud_id)

        if motivo is not None:
            omitidos.append([solicitud_id, motivo])
        log.info(
            "aviso id=%s estado=%s avisado=%s dominio=%s",
            solicitud_id, estado, motivo is None, _dominio(correo),
        )
    return {"avisados": avisados, "omitidos": omitidos}
