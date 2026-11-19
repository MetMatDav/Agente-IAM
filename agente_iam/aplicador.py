"""El aplicador: lleva a la cuenta una solicitud ya aprobada.

    python -m agente_iam.aplicador <id>      (solo desarrollo, almacen en disco)

En la cuenta el aplicador es la Lambda `agente-iam-aplicador`, disparada por
el stream de la tabla con el filtro `estado = aprobada` (`manejador`): ninguna
persona asume su rol, que era el riesgo de tener un CLI con escritura en IAM
en manos de alguien. El CLI (`main`) se conserva como camino de desarrollo
contra el almacen en disco.

Es la unica pieza del sistema con credenciales de escritura en IAM, y por
eso es la que menos hace: lee un registro aprobado, comprueba, crea una
politica y la adjunta.

NO HABLA CON EL MODELO. No lo importa, no lo invoca, y su rol lleva un
Deny explicito de `bedrock:*` para que siga siendo verdad aunque alguien
escriba el import por error. Es el corazon del diseno: el texto de la
solicitud es entrada no confiable, asi que quien la interpreta no puede
ser quien escribe en IAM.

DOS PREGUNTAS DISTINTAS, Y HACEN FALTA LAS DOS:

  - La huella responde "¿es esto lo que se aprobo?"
  - La revalidacion responde "¿sigue siendo aceptable?"

Un registro intacto puede haber quedado obsoleto porque las barandas
cambiaron; un registro que pasa las barandas de hoy puede no ser el que
el humano leyo. Ninguna de las dos sustituye a la otra.

Y UNA TERCERA DESDE EL 24-10-2026 (S4): "¿la aprobacion paso los controles
de `aprobar`?". Hasta esa fecha el aplicador solo exigia la huella, y
separacion de funciones, CheckNoNewAccess y la confirmacion de riesgo se
comprobaban solo en `aprobar.py`, en la maquina y con las credenciales del
aprobador: un `UpdateItem` directo se los saltaba. Ahora el pre-vuelo exige
el resultado de cada uno en el bloque y repite CheckNoNewAccess. Eso cierra
el descuido, no al aprobador malicioso, que puede escribir esos campos: la
huella no tiene secreto. Lo cierra una aprobacion registrada por una pieza
de servidor, que ya existe: la decision esta tomada (ADR-003) y la
aprobacion la escribe la Lambda de aprobacion, no la maquina del aprobador.

UN BLOQUEO ES UNA DECISION ESCRITA UNA VEZ. Como CLI, un bloqueo del
pre-vuelo salia con codigo 3 sin escribir y se podia relanzar. Como Lambda
reintentaria para siempre sobre el mismo evento, asi que el bloqueo se
escribe en la fila (estado `bloqueada_al_aplicar`, bloque `aplicacion` con
`decision: bloquear`) y deja de dispararse: el filtro del stream ya no la
ve como `aprobada`. Se tramita de nuevo con otro id.

LO QUE SE APLICA ES LO QUE SE VALIDO (S9). La politica se crea con el
documento que reconstruye el contrato (`PolicyDocument`, sin claves de
mas), y si el guardado no es exactamente ese, no se aplica nada.

IDEMPOTENCIA SIN MARCADOR. No hay registro de intencion, y no por
descuido: con el nombre derivado del `solicitud_id` de forma determinista
y el contenido verificado antes de asumir nada, el reintento converge solo
contra el estado de AWS, muera donde muera la corrida anterior. Un
marcador en nuestro archivo seria una segunda fuente de verdad sobre algo
que AWS ya sabe, y que puede discrepar de ella — justo lo que el §4 del
CONTEXTO evita al no comparar politicas a mano. Un marcador es una
afirmacion sobre el mundo; un nombre determinista es una coordenada en el
mundo. Para reintentar hacen falta coordenadas.

Por eso tampoco hay distincion entre "primera corrida" y "reintento": es
el mismo codigo, que mira AWS y decide.

SIN `iam:DeletePolicy`. Si la corrida muere entre crear y adjuntar queda
una politica sin adjuntar, y una politica sin adjuntar no concede nada.
No hay nada que compensar, asi que no se le da capacidad destructiva por
un fallo inerte.

MODO ROL POR PERSONA (Fase 23). Cuando `identidad_verificada.modo` es
`rol_por_persona` no hay un principal al que adjuntar: el beneficiario es un
rol que se crea ahora, para la persona del token. El orden de escritura es
CreatePolicy, CreateRole, AttachRolePolicy, y es ese a proposito: si la
corrida muere entre pasos, queda como mucho una politica sin adjuntar o un rol
sin permisos, y ninguna de las dos cosas concede nada. El reintento converge
por nombres deterministas (`personas.nombre_de_rol`), igual que con la
politica. `vence` (hora de aplicacion mas `horas`) se calcula una sola vez, la
primera, y va dentro del documento de la politica, asi que en un reintento NO
se recalcula: se lee de la `Description` de la politica ya creada, que es
inmutable. Si se recalculara, el documento final saldria con otra hora, no
coincidiria con el guardado y la corrida pararia por "documento distinto" en
vez de converger. El pre-vuelo de este modo no relee ningun principal (no hay
uno) y contrasta el `client_id` del token con `CLIENTES_COGNITO`: el
autorizador JWT del runtime ya lo exige (`allowedClients`), y repetirlo aqui
es defensa en profundidad, porque lo que se escribe es una confianza que deja
entrar a quien presente un token de ese `aud`.

El tope de roles vigentes por persona (`MAX_ROLES_VIGENTES_POR_PERSONA`) lo
aplica el runtime al recibir la solicitud; el aplicador lo repite antes de crear
nada, como defensa en profundidad: entre aprobar y aplicar pueden haberse
aplicado otras, y una persona no debe poder pasar del tope por la via de las
solicitudes ya aprobadas. Si el rol de la propia solicitud ya esta entre los
vigentes (la corrida se reanuda) no se bloquea. Ademas cruza los bloques del
registro entre si (`_coherencia_de_modo`) y, en un reintento, valida el
`vence` que lee de la politica ya creada: tiene que ser futuro y no pasar de las
horas pedidas. Si dos corridas casi simultaneas crean la politica con horas
distintas, converge la que llega segunda, adoptando el `vence` de la primera.

El modo de hoy (adjuntar a un principal que existe, solo en el CLI de
desarrollo) no cambia.
"""

import json
import logging
import re
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError
from pydantic import ValidationError

from agente_iam import almacen, config, huella, personas
from agente_iam.aprobar import comprobar_techo, identificar_aprobador, revalidar
from agente_iam.coherencia import riesgo_minimo
from agente_iam.config import AWS_REGION, NOMBRE_TECHO, PERMITIR_AUTOAPROBACION, SERVICIOS_PERMITIDOS
from agente_iam.herramientas import catalogo
from agente_iam.models import PropuestaPolitica, imprimible

# Hijo de "agente-iam" con su propio nivel, como el de `aprobar`: en Lambda
# el raiz esta en WARNING y la linea por registro se perderia.
log = logging.getLogger("agente-iam.aplicador")
log.setLevel(logging.INFO)

PATH_POLITICAS = "/agente-iam/"
TAG_SOLICITUD = personas.TAG_SOLICITUD

# Cuota por defecto de politicas gestionadas adjuntas. Es orientativa a
# proposito: se puede haber ampliado (usuario 10->20, rol 20->25), asi que
# el pre-vuelo solo AVISA. La respuesta autoritativa es el LimitExceeded
# que devuelve Attach*, y ese no se reintenta porque no mejora esperando.
_CUOTA_ORIENTATIVA = {"user": 10, "role": 20}

# Errores que si mejoran esperando: IAM es de consistencia eventual y una
# politica recien creada puede no verse todavia al adjuntarla. Lo que NO
# se reintenta nunca: AccessDenied (falta un permiso; esperar no lo
# concede) ni LimitExceeded (no hay hueco; esperar no lo crea).
_REINTENTABLES = ("NoSuchEntity", "ConcurrentModification")

_VENCE_EN_DESCRIPCION = re.compile(r"vence=(\S+)")

_VENCE_NO_VALIDO = (
    "El vencimiento de la politica ya creada no es valido o ya paso; tramita otra solicitud"
)

_cliente = None


class ControlNoEjecutable(Exception):
    """Un control del pre-vuelo no pudo EJECUTARSE (no es que fallara).

    Un control que no pudo correr no es un control que dijo que no: un
    throttle o un corte de red no prueba que la propuesta conceda de mas.
    Convertirlo en bloqueo mataria la solicitud para siempre (en la Lambda el
    bloqueo se escribe una vez y la fila deja de ser `aprobada`). Por eso se
    levanta y decide quien llama: la Lambda deja subir la excepcion, Lambda
    reintenta y la cola de fallos recoge lo que no se arregle; el CLI informa
    de un error (codigo 1), no de un bloqueo (codigo 3).
    """


def _iam():
    global _cliente
    if _cliente is None:
        _cliente = boto3.client("iam", region_name=AWS_REGION)
    return _cliente


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ahora_utc() -> datetime:
    """La hora de aplicacion, de la que sale `vence`. Aparte para fijarla en tests."""
    return datetime.now(timezone.utc)


def nombre_de_politica(solicitud_id: str) -> str:
    """El nombre determinista del que depende toda la idempotencia.

    En minusculas a proposito. Los nombres de IAM no distinguen
    mayusculas ("you cannot create resources named both MyResource and
    myresource") pero nuestro `_PATRON_ID` si las acepta, asi que
    `req-005` y `REQ-005` son dos solicitudes distintas que derivarian el
    mismo nombre. Normalizando aqui, la colision es visible y deliberada
    en vez de accidental, y la comprobacion de procedencia (la
    `Description`, que es inmutable) la caza.
    """
    return f"agente-iam-{solicitud_id.lower()}"


def arn_de_politica(cuenta: str, solicitud_id: str) -> str:
    return f"arn:aws:iam::{cuenta}:policy{PATH_POLITICAS}{nombre_de_politica(solicitud_id)}"


def _canonico(documento: dict) -> str:
    """Misma serializacion determinista que la huella, para comparar docs."""
    return json.dumps(documento, sort_keys=True, separators=(",", ":"))


def documento_validado(registro: dict) -> tuple[dict | None, str | None]:
    """El documento que se aplicaria, o (None, motivo) si no se puede (S9).

    Es el que reconstruye el contrato (`PropuestaPolitica`), volcado sin
    los None, que es como lo guarda el orquestador. Si el guardado no es
    exactamente ese, alguien lo escribio a mano: lo que paso la
    revalidacion no seria lo que llega a IAM.
    """
    crudo = (registro.get("propuesta") or {}).get("policy_document")
    try:
        validado = PropuestaPolitica.model_validate(registro.get("propuesta") or {}).policy_document
    except ValidationError as e:
        return None, f"La propuesta guardada no cumple el contrato: {e.errors()[0]['msg']}."
    documento = validado.model_dump(exclude_none=True)
    if not isinstance(crudo, dict) or _canonico(documento) != _canonico(crudo):
        return None, (
            "El documento guardado no es exactamente el que valida el contrato "
            "(lleva claves o valores de mas). Lo revalidado no seria lo aplicado."
        )
    return documento, None


def _controles_de_la_aprobacion(registro: dict, aprobacion: dict) -> list[str]:
    """Los controles de `aprobar`, leidos en el bloque y no supuestos (S4).

    Lo que se exige es lo que `aprobar` deja escrito cuando aprueba de
    verdad. Un bloque que no lo lleva no salio de `aprobar`, o salio de un
    `aprobar` que bloqueo: en los dos casos no es una aprobacion.
    """
    motivos: list[str] = []
    separacion = (aprobacion.get("separacion_de_funciones") or {}).get("resultado")
    if separacion == "SALTADO":
        if not PERMITIR_AUTOAPROBACION:
            motivos.append(
                "La aprobacion se salto la separacion de funciones (SALTADO). El "
                "aplicador solo la acepta con AGENTE_IAM_PERMITIR_AUTOAPROBACION=si "
                "en su propio entorno."
            )
    elif separacion != "cumplido":
        motivos.append(
            "El bloque de aprobacion no dice que la separacion de funciones se "
            f"cumpliera (resultado: {separacion!r}). No salio de `aprobar`."
        )
    if (aprobacion.get("techo") or {}).get("resultado") != "PASS":
        motivos.append(
            "El bloque de aprobacion no dice que CheckNoNewAccess pasara contra "
            "el techo (resultado: "
            f"{(aprobacion.get('techo') or {}).get('resultado')!r})."
        )
    # El riesgo se recalcula aqui, desde el registro que esta bajo la
    # huella, igual que en `aprobar`: el campo guardado no lo rebaja.
    nivel = (registro.get("propuesta") or {}).get("nivel_riesgo")
    beneficiario = (registro.get("identidad_verificada") or {}).get("principal_arn", "")
    motivos_riesgo = riesgo_minimo(
        registro.get("solicitud") or {},
        beneficiario,
        registro.get("historial_validacion") or [],
        registro.get("nivel_real"),
    )
    if (nivel == "alto" or motivos_riesgo) and aprobacion.get("riesgo_confirmado") is not True:
        motivos.append(
            "La solicitud es de riesgo alto ("
            + ("; ".join(motivos_riesgo) if motivos_riesgo else "lo marco el modelo")
            + ") y la aprobacion no lleva riesgo_confirmado."
        )
    return motivos


def _documento_de(arn: str) -> dict:
    version = _iam().get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
    documento = _iam().get_policy_version(PolicyArn=arn, VersionId=version)[
        "PolicyVersion"
    ]["Document"]
    if isinstance(documento, str):  # segun version de botocore
        documento = json.loads(urllib.parse.unquote(documento))
    return documento


def _coherencia_de_modo(registro: dict) -> list[str]:
    """Los bloques del registro tienen que describir al mismo beneficiario (solo lectura del registro).

    La huella prueba que nada cambio despues de aprobar, no que lo aprobado
    fuera coherente: un registro armado a mano con la huella recalculada la
    pasa. Aqui se cruzan los bloques entre si, sin llamar a nadie.

    Modo rol por persona: la solicitud guardada lleva `persona` y no
    `principal_arn_declarado`; la persona de la identidad congelada es la de la
    solicitud, la del bloque `solicitante` y la del token (`ejecutado_por.usuario`
    es el `username` de Cognito, con el prefijo `IdentityCenter_`); las horas son
    las de la solicitud; y el rol previsto es el que sale de la persona, la
    cuenta y el id. Modo principal existente: la solicitud no lleva `persona`.
    """
    identidad = registro.get("identidad_verificada")
    solicitud = registro.get("solicitud")
    identidad = identidad if isinstance(identidad, dict) else {}
    solicitud = solicitud if isinstance(solicitud, dict) else {}

    if identidad.get("modo") != "rol_por_persona":
        if solicitud.get("persona") is not None:
            return [
                "La identidad es del modo principal existente pero la solicitud guardada "
                "trae `persona`: los bloques del registro no son del mismo modo."
            ]
        return []

    if solicitud.get("persona") is None:
        return [
            "La identidad es del modo rol por persona pero la solicitud guardada no trae "
            "`persona`: los bloques del registro no son del mismo modo."
        ]
    if solicitud.get("principal_arn_declarado") is not None:
        return [
            "La identidad es del modo rol por persona pero la solicitud guardada trae "
            "`principal_arn_declarado`: los bloques del registro no son del mismo modo."
        ]

    motivos: list[str] = []
    persona = identidad.get("persona")
    usuario = persona.get("usuario") if isinstance(persona, dict) else None
    persona_solicitud = solicitud["persona"]
    de_la_solicitud = persona_solicitud.get("usuario") if isinstance(persona_solicitud, dict) else None
    if usuario != de_la_solicitud:
        motivos.append("El usuario de la identidad congelada no es el de la solicitud guardada.")
    solicitante = registro.get("solicitante")
    if usuario != (solicitante.get("persona") if isinstance(solicitante, dict) else None):
        motivos.append(
            "El usuario de la identidad congelada no es el solicitante verificado (`solicitante.persona`)."
        )
    ejecutado = registro.get("ejecutado_por")
    if not isinstance(usuario, str) or (ejecutado.get("usuario") if isinstance(ejecutado, dict) else None) != (
        "IdentityCenter_" + usuario
    ):
        motivos.append(
            "El usuario de la identidad congelada no es el del token: `ejecutado_por.usuario` "
            "tiene que ser `IdentityCenter_` seguido del usuario."
        )
    if identidad.get("horas") != solicitud.get("horas"):
        motivos.append("Las horas de la identidad congelada no son las de la solicitud guardada.")
    if not isinstance(usuario, str) or identidad.get("principal_arn") != personas.arn_de_rol(
        str(identidad.get("cuenta")), usuario, registro["id"]
    ):
        motivos.append(
            "El ARN del rol previsto (identidad congelada) no es el que se deriva de la cuenta, "
            "la persona y el id de la solicitud."
        )
    return motivos


# --- Paso 1: pre-vuelo, todo lectura ----------------------------------------


def prevuelo(registro: dict) -> tuple[dict, list[str], list[str]]:
    """Comprueba todo lo comprobable ANTES de escribir nada.

    Devuelve (identidad_actual, bloqueos, avisos). Ninguna de estas
    llamadas modifica la cuenta: si algo falla aqui, no hay nada que
    deshacer, que es exactamente el motivo de que el pre-vuelo exista.
    """
    bloqueos: list[str] = []
    avisos: list[str] = []

    if registro.get("estado") != "aprobada":
        return {}, [
            f"El estado es '{registro.get('estado')}' y solo se aplica desde "
            "'aprobada'."
        ], []

    aprobacion = registro.get("aprobacion")
    if not aprobacion or not aprobacion.get("huella"):
        return {}, ["El registro no lleva bloque de aprobacion con huella."], []
    # Una fila que ya lleva una decision (aplicacion o rechazo) no vuelve a
    # `aprobada` por el flujo normal: un estado 'aprobada' encima de ella es
    # un `estado` reescrito a mano. No se aplica de nuevo.
    if registro.get("aplicacion") is not None or registro.get("rechazo") is not None:
        # El rechazo junto a una aprobacion tambien: las dos escrituras se
        # excluyen, asi que si aparecen juntas alguien escribio a mano.
        if registro.get("rechazo") and not registro.get("aplicacion"):
            return {}, ["El registro lleva aprobacion y rechazo a la vez. No se aplica nada."], []
        return {}, [
            "La fila ya lleva una decision (aplicacion o rechazo); un estado "
            "'aprobada' encima de ella no sale del flujo normal. No se aplica nada."
        ], []

    # ¿Es esto lo que se aprobo?
    if not huella.coincide(registro, aprobacion["huella"]):
        return {}, [
            "La huella NO cuadra: el registro cambio despues de aprobarse. "
            "No se aplica nada."
        ], []

    # ¿La aprobacion paso los controles de `aprobar`? (S4)
    controles = _controles_de_la_aprobacion(registro, aprobacion)
    if controles:
        return {}, controles, []

    # ¿Lo que se aplicaria es lo que se valida? (S9)
    documento, motivo_documento = documento_validado(registro)
    if documento is None:
        return {}, [motivo_documento or "documento no valido"], []

    # ¿Las piezas del registro cuentan la misma historia? (modo, persona, rol)
    incoherencias = _coherencia_de_modo(registro)
    if incoherencias:
        return {}, incoherencias, []

    # ¿Sigue siendo aceptable? (Barandas, Access Analyzer y chequeos
    # posteriores con las reglas de HOY, no las de cuando se aprobo.)
    veredicto = revalidar(registro)
    # Access Analyzer que no pudo correr no es una baranda que dijo que no:
    # ver `ControlNoEjecutable`.
    if veredicto.get("no_ejecutado"):
        raise ControlNoEjecutable(
            "No se pudo ejecutar Access Analyzer desde el aplicador: "
            + "; ".join(veredicto["no_ejecutado"])
        )
    if not veredicto["aprobable"]:
        bloqueos.append(
            "La propuesta ya no pasa las barandas actuales: "
            + "; ".join(veredicto["bloqueos"])
        )

    # CheckNoNewAccess otra vez, desde aqui y contra el techo de HOY (S4).
    # Que lo diga el bloque no basta: lo escribe el aprobador. No poder
    # ejecutarlo no es pasarlo, igual que en `aprobar`; pero tampoco es un
    # bloqueo: ver `ControlNoEjecutable`. Un FAIL si es un bloqueo.
    # Si ya hay un bloqueo determinista, no se gasta (ni se arriesga) la
    # llamada de pago: se devuelven los bloqueos reunidos.
    if bloqueos:
        return {}, bloqueos, avisos
    cuenta = (registro.get("identidad_verificada") or {}).get("cuenta", "")
    try:
        techo_hoy = comprobar_techo(documento, cuenta)
    except Exception as e:
        raise ControlNoEjecutable(
            f"No se pudo ejecutar CheckNoNewAccess desde el aplicador: {e}"
        ) from e
    if techo_hoy.get("resultado") != "PASS":
        bloqueos.append(
            "CheckNoNewAccess, repetido por el aplicador, dice que la "
            f"propuesta concede por encima del techo: {techo_hoy.get('mensaje')}"
        )

    # En el modo rol por persona no hay principal que releer ni cuota que
    # mirar: el rol se crea despues. Lo comun termina aqui.
    congelada = registro["identidad_verificada"]
    if congelada.get("modo") == "rol_por_persona":
        return _prevuelo_persona(registro, congelada, bloqueos, avisos)

    # ¿El beneficiario sigue siendo LA MISMA entidad?
    actual, motivo = _identidad_actual(congelada)
    if motivo:
        bloqueos.append(motivo)
        return actual, bloqueos, avisos

    # ¿Lleva el techo? Es la condicion que el propio rol del aplicador
    # exige via `iam:PermissionsBoundary`; comprobarla aqui convierte un
    # AccessDenied cripticо en un mensaje que se entiende.
    boundary = (actual.get("boundary") or {}).get("PermissionsBoundaryArn")
    esperado = f"arn:aws:iam::{congelada['cuenta']}:policy/{NOMBRE_TECHO}"
    if boundary != esperado:
        bloqueos.append(
            f"El beneficiario no lleva el permission boundary '{NOMBRE_TECHO}' "
            f"(tiene: {boundary or 'ninguno'}). Sin el techo puesto, el "
            "sistema no puede concederle nada."
        )

    # Cuota: aviso, nunca bloqueo. Ver `_CUOTA_ORIENTATIVA`.
    tope = _CUOTA_ORIENTATIVA.get(congelada["tipo"], 10)
    if actual["adjuntas"] >= tope:
        avisos.append(
            f"El beneficiario ya tiene {actual['adjuntas']} politicas "
            f"gestionadas adjuntas y la cuota por defecto es {tope}. Si no "
            "se ha ampliado, el Attach fallara con LimitExceeded."
        )

    return actual, bloqueos, avisos


def _prevuelo_persona(
    registro: dict, congelada: dict, bloqueos: list[str], avisos: list[str]
) -> tuple[dict, list[str], list[str]]:
    """El pre-vuelo propio del modo rol por persona (solo lectura).

    Sin POOL_ID o sin clientes no se puede escribir la confianza: es un
    problema del entorno de esta Lambda, no una decision sobre la solicitud,
    asi que se levanta `ControlNoEjecutable` y no se escribe un bloqueo.

    Lo demas son bloqueos: el `sub` que ira en la confianza es el que grabo el
    runtime desde el JWT (`ejecutado_por.sub`) y tiene que ser el mismo que la
    identidad congelada bajo la huella; las horas estan en rango; el
    `client_id` del token es uno de los clientes admitidos; la persona no
    alcanza ya el tope de roles vigentes (salvo que uno sea el de esta
    solicitud); y el rol, si ya existe, es el de ESTA solicitud (misma
    etiqueta) y lleva el techo. Si alguno de los tres primeros falla no se
    llama a IAM. Un error de IAM al leer los roles vigentes sube tal cual: sin
    saber cuantos hay no se decide, y Lambda reintenta.
    """
    if not config.POOL_ID or not config.CLIENTES_COGNITO:
        raise ControlNoEjecutable(
            "Faltan AGENTE_IAM_POOL_ID o AGENTE_IAM_CLIENTES en el entorno del "
            "aplicador: sin ellos no se puede escribir la confianza del rol."
        )
    if config.CLIENTES_COGNITO_INVALIDOS:
        # Un id mal formado entraria en el `aud` de la confianza y nadie podria
        # asumir el rol: entorno roto, no bloqueo de la solicitud.
        raise ControlNoEjecutable(
            "AGENTE_IAM_CLIENTES trae ids que no tienen forma de cliente de Cognito: "
            + ", ".join(config.CLIENTES_COGNITO_INVALIDOS)
        )

    ejecutado = registro.get("ejecutado_por") or {}
    persona = congelada.get("persona") or {}
    usuario: str = persona.get("usuario") or ""
    sub = persona.get("sub")
    if not usuario:
        bloqueos.append("La identidad congelada no lleva la persona (usuario) del token.")
    if not sub:
        bloqueos.append("La identidad congelada no lleva el `sub` de la persona.")
    elif sub != ejecutado.get("sub"):
        bloqueos.append(
            "El `sub` de la persona no coincide con el `sub` del token que hizo la "
            "solicitud (ejecutado_por.sub). La confianza del rol no se escribe."
        )

    horas = congelada.get("horas")
    if isinstance(horas, bool) or not isinstance(horas, int) or not personas.HORAS_MIN <= horas <= personas.HORAS_MAX:
        bloqueos.append(
            f"Las horas deben ser un entero entre {personas.HORAS_MIN} y {personas.HORAS_MAX} (hay: {horas!r})."
        )

    client_id = ejecutado.get("client_id")
    if client_id not in config.CLIENTES_COGNITO:
        bloqueos.append(
            "El cliente de Cognito del token (ejecutado_por.client_id) no esta entre "
            "los clientes admitidos del sistema. La confianza del rol no se escribe."
        )

    if bloqueos:
        return {}, bloqueos, avisos

    solicitud_id = registro["id"]

    # El tope por persona, repetido aqui: el runtime lo comprueba al recibir la
    # solicitud, pero entre aprobar y aplicar pueden haberse aplicado otras. El
    # rol de ESTA solicitud cuenta entre los vigentes si la corrida se reanuda;
    # en ese caso no se bloquea, o se dejaria a medias lo que ya se empezo.
    vigentes = personas.roles_vigentes(usuario, _ahora_utc(), iam=_iam(), sub=sub)
    propio = personas.nombre_de_rol(usuario, solicitud_id)
    es_reanudacion = any(
        v.get("nombre") == propio or v.get("solicitud_id") == solicitud_id.lower() for v in vigentes
    )
    if len(vigentes) >= config.MAX_ROLES_VIGENTES_POR_PERSONA and not es_reanudacion:
        bloqueos.append(
            f"La persona ya tiene {len(vigentes)} roles de persona vigentes "
            f"(tope {config.MAX_ROLES_VIGENTES_POR_PERSONA}); se aprobo pero no se aplica: "
            "tramita otra solicitud cuando venza alguno"
        )
        return {}, bloqueos, avisos

    observado = observar_rol(personas.nombre_de_rol(usuario, solicitud_id))
    if observado["existe"]:
        if observado["tags"].get(personas.TAG_SOLICITUD) != solicitud_id.lower():
            bloqueos.append(
                "El nombre del rol ya lo ocupa otra solicitud (el rol existe y no lleva "
                f"la etiqueta {personas.TAG_SOLICITUD}={solicitud_id.lower()}). No se toca."
            )
        esperado = f"arn:aws:iam::{congelada['cuenta']}:policy/{NOMBRE_TECHO}"
        if observado["boundary"] != esperado:
            bloqueos.append(
                f"El rol ya existe y no lleva el permission boundary '{NOMBRE_TECHO}' "
                f"(tiene: {observado['boundary'] or 'ninguno'})."
            )

    actual = {
        "principal_arn": congelada["principal_arn"],
        "principal_id": observado.get("role_id") or "",
        "rol": observado,
    }
    return actual, bloqueos, avisos


def _identidad_actual(congelada: dict) -> tuple[dict, str | None]:
    """Relee el principal y compara el id unico, no el ARN.

    Fase 7b.0: entre aprobar y aplicar cabe que alguien borre el principal
    y cree otro con el mismo nombre. El ARN seria identico y la entidad
    otra — otras politicas, otra persona. El id que IAM asigna no se
    reutiliza, asi que es lo unico que cierra esa ventana.
    """
    nombre = congelada["principal_arn"].split("/")[-1]
    try:
        if congelada["tipo"] == "user":
            objeto = _iam().get_user(UserName=nombre)["User"]
            id_actual = objeto["UserId"]
            adjuntas = _iam().list_attached_user_policies(UserName=nombre)
        else:
            objeto = _iam().get_role(RoleName=nombre)["Role"]
            id_actual = objeto["RoleId"]
            adjuntas = _iam().list_attached_role_policies(RoleName=nombre)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return {}, (
                f"El beneficiario '{congelada['principal_arn']}' ya no existe. "
                "Se aprobo para alguien que ha desaparecido."
            )
        raise

    actual = {
        "principal_arn": objeto["Arn"],
        "principal_id": id_actual,
        "boundary": objeto.get("PermissionsBoundary"),
        "adjuntas": len(adjuntas["AttachedPolicies"]),
    }

    congelado = congelada.get("principal_id")
    if not congelado:
        return actual, (
            "El registro se aprobo antes de que existiera `principal_id`, asi "
            "que no se puede probar que el beneficiario siga siendo la misma "
            "entidad. Vuelve a tramitar la solicitud."
        )
    if congelado != id_actual:
        return actual, (
            f"El beneficiario tiene el mismo ARN pero NO es la misma entidad: "
            f"se aprobo para {congelado} y ahora hay {id_actual}. Alguien lo "
            "borro y lo recreo entre la aprobacion y ahora."
        )
    return actual, None


# --- Pasos 2 y 3: observar AWS y decidir ------------------------------------


def observar(cuenta: str, solicitud_id: str) -> dict:
    """El estado real en AWS. La unica fuente de verdad sobre que existe."""
    arn = arn_de_politica(cuenta, solicitud_id)
    try:
        politica = _iam().get_policy(PolicyArn=arn)["Policy"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return {"arn": arn, "existe": False}
        raise
    return {
        "arn": arn,
        "existe": True,
        "documento": _documento_de(arn),
        "descripcion": politica.get("Description", ""),
        "adjuntas": politica.get("AttachmentCount", 0),
    }


def observar_rol(nombre: str) -> dict:
    """El rol por persona tal como esta en AWS: `GetRole` y `ListRoleTags`.

    `{"existe": False}` o `{"existe": True, "arn", "role_id", "boundary" (el ARN
    o None), "tags": {clave: valor}, "max_session": segundos}`. Las etiquetas
    se piden aparte porque `GetRole` no las devuelve todas de forma fiable; son
    la prueba de a que solicitud pertenece el rol.
    """
    try:
        rol = _iam().get_role(RoleName=nombre)["Role"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return {"existe": False}
        raise
    etiquetas: dict[str, str] = {}
    parametros: dict = {"RoleName": nombre}
    while True:
        pagina = _iam().list_role_tags(**parametros)
        etiquetas.update({t["Key"]: t["Value"] for t in pagina["Tags"]})
        if not pagina.get("IsTruncated") or not pagina.get("Marker"):
            break
        parametros["Marker"] = pagina["Marker"]
    return {
        "existe": True,
        "arn": rol["Arn"],
        "role_id": rol["RoleId"],
        "boundary": (rol.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
        "tags": etiquetas,
        "max_session": rol.get("MaxSessionDuration", 3600),
    }


def vence_de_la_descripcion(descripcion: str) -> str | None:
    """El `vence=<ISO>` que `crear` dejo en la Description de la politica, o None.

    La Description es inmutable: es la unica copia del `vence` original que
    sobrevive a un reintento (ver el docstring del modulo).
    """
    encontrado = _VENCE_EN_DESCRIPCION.search(descripcion or "")
    return encontrado.group(1) if encontrado else None


def decidir(observado: dict, documento: dict, solicitud_id: str) -> tuple[str, str]:
    """Devuelve (accion, motivo). Acciones: crear | adjuntar | parar.

    No hay rama de "primera vez" ni de "reintento": se mira lo que hay y
    se decide. Si la corrida anterior murio despues de crear, esto lo ve y
    salta al adjuntar; si murio antes, crea. Converge desde cualquier punto.
    """
    if not observado["existe"]:
        return "crear", "no existe todavia"

    if _canonico(observado["documento"]) != _canonico(documento):
        return "parar", (
            f"Ya existe una politica llamada '{nombre_de_politica(solicitud_id)}' "
            "con un documento DISTINTO del aprobado. Ese nombre lo posee otra "
            "cosa; no se sobrescribe ni se adjunta."
        )

    # El documento coincide, pero eso no prueba la procedencia: dos
    # solicitudes pueden acabar con el mismo documento. La `Description` si
    # la prueba, porque es inmutable —no existe ninguna API que la cambie—
    # y la escribio el aplicador al crearla.
    if f"solicitud={solicitud_id.lower()}" not in observado["descripcion"].lower():
        return "parar", (
            "Existe una politica con ese nombre y el documento correcto, pero "
            f"su descripcion no la atribuye a esta solicitud: "
            f"'{observado['descripcion']}'."
        )

    return "adjuntar", "ya existe, identica y con la procedencia correcta"


# --- Paso 4: actuar ---------------------------------------------------------


def _con_reintento(operacion, *, intentos: int = 4, tambien: tuple[str, ...] = ()):
    """Backoff solo para lo que mejora esperando (consistencia eventual).

    `tambien` suma codigos reintentables SOLO para esta llamada: el Attach que
    sigue a un CreateRole de la misma corrida admite AccessDenied (el rol recien
    creado puede no haberse propagado para la condicion `iam:PermissionsBoundary`);
    el resto de llamadas siguen sin reintentarlo.
    """
    reintentables = _REINTENTABLES + tambien
    espera = 1.0
    for intento in range(1, intentos + 1):
        try:
            return operacion()
        except ClientError as e:
            codigo = e.response["Error"]["Code"]
            if codigo not in reintentables or intento == intentos:
                raise
            time.sleep(espera)
            espera *= 2


def _vence_valido(vence: str, horas: int) -> bool:
    """`vence` es una fecha legible, futura y a no mas de `horas` de ahora.

    Es la comprobacion de un `vence` que NO se calculo en esta corrida (el de la
    politica ya creada): ninguna corrida legitima deja uno pasado, ilegible o
    mas lejano que las horas pedidas, asi que uno asi no se adopta.
    """
    fecha = personas.vence_como_fecha(vence)
    if fecha is None:
        return False
    ahora = _ahora_utc()
    return ahora < fecha <= ahora + timedelta(hours=horas)


def crear(
    registro: dict, documento: dict, cuenta: str, vence: str | None = None
) -> tuple[str, str | None]:
    """CreatePolicy bajo nuestro path, con trazabilidad inmutable y tag. `(arn, vence)`.

    `vence` es el del modo rol por persona (None en el otro) y `documento` ya
    lo lleva dentro. Lo que se devuelve es el vence que quedo en AWS: si otra
    corrida creo la politica un instante antes con otra hora, se adopta la suya
    (ver el `EntityAlreadyExists` de abajo) y el llamante sigue con ella.

    La `Description` lleva el id y la huella y NO se puede cambiar despues
    (verificado: no existe ninguna accion `UpdatePolicy` en IAM). Es la
    unica evidencia del sistema que sobrevive a que alguien reescriba
    nuestro JSON, porque vive dentro de AWS.

    El tag es otra cosa: es la COMPUERTA. El rol del aplicador solo puede
    llamar a CreatePolicy si viene con `aws:RequestTag/agente-iam-solicitud`,
    asi que una politica sin trazar no se puede crear ni por error de
    codigo. Pero los tags son mutables (`TagPolicy`/`UntagPolicy` existen),
    asi que no valen como evidencia. Description evidencia, tags compuerta.
    """
    solicitud_id = registro["id"]
    descripcion = (
        f"agente-iam | solicitud={solicitud_id.lower()} | "
        f"huella={registro['aprobacion']['huella']} | "
        f"aprobada={registro['aprobacion']['cuando']}"
        + (f" | vence={vence}" if vence else "")
    )[:1000]

    try:
        respuesta = _iam().create_policy(
            PolicyName=nombre_de_politica(solicitud_id),
            Path=PATH_POLITICAS,
            PolicyDocument=json.dumps(documento),
            Description=descripcion,
            Tags=[{"Key": TAG_SOLICITUD, "Value": solicitud_id.lower()}],
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise
        # El cuarto estado. Los nombres de politica son unicos en TODA la
        # cuenta, no por path ("IAM user, group, role, and policy names
        # must be unique within the account"), asi que este error puede
        # significar que el nombre esta ocupado FUERA de nuestro path — y
        # entonces `observar` no lo encuentra, porque busca por ARN y el
        # ARN lleva el path. No es escalada, es denegacion de servicio
        # sobre este id, pero tiene que decirse y no salir como error opaco.
        observado = observar(cuenta, solicitud_id)
        if not observado["existe"]:
            raise RuntimeError(
                f"El nombre '{nombre_de_politica(solicitud_id)}' ya existe en "
                "la cuenta pero NO bajo nuestro path. Los nombres de politica "
                "son unicos en toda la cuenta. Hay que renombrar la solicitud "
                "o retirar la politica que ocupa el nombre."
            ) from e
        # Existe bajo nuestro path: alguien la creo entre `observar` y aqui.
        # Que exista no la hace nuestra; se decide igual que si la hubieramos
        # visto antes, con documento y procedencia.
        if vence is not None:
            # Dos corridas casi a la vez calculan `vence` por separado y salen
            # con horas distintas. La politica que ya esta manda (su
            # Description es inmutable): el documento se rehace con SU vence
            # para que la comparacion de `decidir` sea justa y la corrida
            # converja en vez de parar. Que ese vence sea aceptable lo mira
            # quien llama, con las horas de la identidad.
            de_la_otra = vence_de_la_descripcion(observado["descripcion"])
            if de_la_otra is None:
                raise RuntimeError(
                    "La politica que otra corrida creo a la vez no trae `vence=` en su "
                    "descripcion; no se puede saber a que hora vence. No se adopta."
                ) from e
            if de_la_otra != vence:
                documento = personas.documento_con_vencimiento(documento, de_la_otra)
                vence = de_la_otra
        accion, motivo = decidir(observado, documento, solicitud_id)
        if accion != "adjuntar":
            raise RuntimeError(motivo) from e
        return arn_de_politica(cuenta, solicitud_id), vence

    return respuesta["Policy"]["Arn"], vence


def crear_rol(registro: dict, congelada: dict, vence: str, cuenta: str, documento_confianza: dict) -> dict:
    """CreateRole del rol por persona: techo, confianza, vida y etiquetas.

    `{"arn", "role_id"}`. El techo va como boundary porque el rol del
    aplicador solo puede crear roles con el (su condicion `iam:PermissionsBoundary`).
    `MaxSessionDuration` es `horas` en segundos. La Description lleva el usuario
    normalizado (el alfabeto de la Description de IAM es Latin-1; un nombre con
    otros caracteres la haria fallar). Si el nombre ya existe, solo se acepta
    si la etiqueta de solicitud es la nuestra (alguien lo creo entre el
    pre-vuelo y aqui, o la corrida anterior murio): un rol ajeno con ese
    nombre no se adopta.
    """
    persona = congelada["persona"]
    solicitud_id = registro["id"].lower()
    usuario = personas.normalizar_usuario(persona["usuario"])
    nombre = personas.nombre_de_rol(persona["usuario"], registro["id"])
    try:
        respuesta = _iam().create_role(
            RoleName=nombre,
            Path=personas.PATH_PERSONAS,
            AssumeRolePolicyDocument=json.dumps(documento_confianza),
            PermissionsBoundary=f"arn:aws:iam::{cuenta}:policy/{NOMBRE_TECHO}",
            MaxSessionDuration=congelada["horas"] * 3600,
            Description=f"agente-iam | solicitud={solicitud_id} | persona={usuario} | vence={vence}"[:1000],
            Tags=[
                {"Key": personas.TAG_SOLICITUD, "Value": solicitud_id},
                {"Key": personas.TAG_PERSONA, "Value": usuario},
                {"Key": personas.TAG_SUB, "Value": persona["sub"]},
                {"Key": personas.TAG_VENCE, "Value": vence},
            ],
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise
        observado = observar_rol(nombre)
        if not observado["existe"] or observado["tags"].get(personas.TAG_SOLICITUD) != solicitud_id:
            raise RuntimeError(
                f"El nombre de rol '{nombre}' ya existe y no es de la solicitud "
                f"{solicitud_id}. No se adopta."
            ) from e
        return {"arn": observado["arn"], "role_id": observado["role_id"]}
    return {"arn": respuesta["Role"]["Arn"], "role_id": respuesta["Role"]["RoleId"]}


def adjuntar(policy_arn: str, congelada: dict) -> None:
    """Attach al principal. Es idempotente: repetirlo no rompe nada."""
    nombre = congelada["principal_arn"].split("/")[-1]
    if congelada["tipo"] == "user":
        _con_reintento(
            lambda: _iam().attach_user_policy(UserName=nombre, PolicyArn=policy_arn)
        )
    else:
        _con_reintento(
            lambda: _iam().attach_role_policy(RoleName=nombre, PolicyArn=policy_arn)
        )


# --- El flujo ---------------------------------------------------------------


def aplicar(registro: dict) -> tuple[dict | None, list[str], list[str]]:
    """Devuelve (registro_aplicado, bloqueos, avisos)."""
    actual, bloqueos, avisos = prevuelo(registro)
    if bloqueos:
        return None, bloqueos, avisos

    congelada = registro["identidad_verificada"]
    cuenta = congelada["cuenta"]
    # El documento validado, no el crudo (S9). El pre-vuelo ya comprobo que
    # coinciden; se vuelve a pedir para no arrastrar dos copias.
    documento, motivo_documento = documento_validado(registro)
    if documento is None:
        return None, [motivo_documento or "documento no valido"], avisos
    solicitud_id = registro["id"]

    en_modo_persona = congelada.get("modo") == "rol_por_persona"
    vence: str | None = None
    observado = observar(cuenta, solicitud_id)
    if en_modo_persona:
        # `vence` se calcula una vez. En un reintento sale de la politica ya
        # creada (ver el docstring del modulo), no se recalcula.
        if observado["existe"]:
            vence = vence_de_la_descripcion(observado["descripcion"])
            if vence is None:
                return None, [
                    "La politica ya existe pero su descripcion no trae `vence=`; no se puede "
                    "saber a que hora vence el permiso. No se adjunta."
                ], avisos
            if not _vence_valido(vence, congelada["horas"]):
                return None, [_VENCE_NO_VALIDO], avisos
        else:
            vence = personas.vence_desde(_ahora_utc(), congelada["horas"])
        documento = personas.documento_con_vencimiento(documento, vence)

    accion, motivo = decidir(observado, documento, solicitud_id)
    if accion == "parar":
        return None, [motivo], avisos

    # Quien aplica se resuelve ANTES de tocar la cuenta: si STS fallara
    # despues del Attach, la excepcion saldria con el cambio ya hecho y sin
    # el aviso con el ARN que da `main`.
    ejecutor = identificar_aprobador().model_dump()

    if accion == "crear":
        policy_arn, vence_en_aws = crear(registro, documento, cuenta, vence=vence)
        if vence_en_aws != vence and vence_en_aws is not None:
            # Otra corrida creo la politica antes y su vence manda (ver `crear`).
            # Se valida igual que el de un reintento, antes de crear el rol.
            if not _vence_valido(vence_en_aws, congelada["horas"]):
                return None, [_VENCE_NO_VALIDO], avisos
            vence = vence_en_aws
            documento = personas.documento_con_vencimiento(documento, vence)
            accion, motivo = "adjuntar", "la creo otra corrida a la vez; se adopta su vencimiento"
    else:
        policy_arn = arn_de_politica(cuenta, solicitud_id)
    rol: dict | None = None
    if en_modo_persona and vence is not None:
        rol = _rol_de_la_persona(registro, congelada, actual, vence, cuenta, policy_arn)
    else:
        adjuntar(policy_arn, congelada)

    # El aplicador escribe su bloque con `guardar_decision`, no con
    # `guardar_propuesta`: aquel guardian existe para que una nueva corrida
    # del intake no pise una decision humana, y aqui se anade el desenlace
    # de esa misma decision. Solo viajan `aplicacion` y `estado`.
    registro["aplicacion"] = {
        "cuando": _ahora(),
        "policy_arn": policy_arn,
        "decision": accion,
        "motivo": motivo,
        "por": ejecutor,
        "principal_id_confirmado": actual["principal_id"],
        "avisos": avisos,
    }
    if rol is not None and vence is not None:
        registro["aplicacion"].update(
            {
                "rol_arn": rol["arn"],
                "rol_id": rol["role_id"],
                "vence": vence,
                # El documento FINAL (con el vencimiento), que es lo que hay en IAM.
                "documento_aplicado": documento,
                "principal_id_confirmado": rol["role_id"],
            }
        )
    registro["estado"] = "aplicada"
    return registro, [], avisos


def _rol_de_la_persona(
    registro: dict, congelada: dict, actual: dict, vence: str, cuenta: str, policy_arn: str
) -> dict:
    """Crea el rol por persona si falta y le adjunta la politica. `{"arn", "role_id"}`.

    Si el rol ya existia (lo vio el pre-vuelo, con la etiqueta de esta solicitud)
    solo se adjunta. Si se crea aqui, el Attach siguiente admite ademas
    AccessDenied: IAM es de consistencia eventual y la condicion
    `iam:PermissionsBoundary` sobre un rol recien creado puede evaluarse antes de
    que el rol se propague. En cualquier otro Attach, AccessDenied no se reintenta.
    """
    existente = actual["rol"]
    nombre = personas.nombre_de_rol(congelada["persona"]["usuario"], registro["id"])
    if existente["existe"]:
        rol = {"arn": existente["arn"], "role_id": existente["role_id"]}
        extra: tuple[str, ...] = ()
    else:
        confianza = personas.confianza(
            cuenta, config.POOL_ID, config.CLIENTES_COGNITO, registro["ejecutado_por"]["sub"], vence
        )
        rol = crear_rol(registro, congelada, vence, cuenta, confianza)
        extra = ("AccessDenied",)
    _con_reintento(
        lambda: _iam().attach_role_policy(RoleName=nombre, PolicyArn=policy_arn),
        tambien=extra,
    )
    return rol


# --- La Lambda: el aplicador disparado por el stream ------------------------

# Lo que se comprobo al arrancar (lista de problemas, vacia si todo bien). Una
# vez por arranque en frio, igual que en `aprobar`; los tests la ponen a None.
_problemas_entorno: list[str] | None = None


def _comprobar_entorno() -> list[str]:
    """Por que esta Lambda no debe aplicar nada todavia; vacio si puede.

    Las mismas dos condiciones que la aprobacion: el almacen es DynamoDB (en
    disco no hay IAM que reserve el bloque `aplicacion` a este rol) y los
    catalogos de servicio cargan (sin ellos `revalidar` apaga en silencio el
    chequeo de nivel de acceso y el pre-vuelo aprobaria de mas).
    """
    global _problemas_entorno
    if _problemas_entorno is None:
        problemas = []
        if almacen.ALMACEN != "dynamodb":
            problemas.append(f"ALMACEN es '{almacen.ALMACEN}' y el aplicador exige 'dynamodb'")
        faltan = catalogo.no_disponibles(SERVICIOS_PERMITIDOS)
        if faltan:
            problemas.append("catalogos de servicio no disponibles: " + ", ".join(faltan))
        _problemas_entorno = problemas
    return _problemas_entorno


def procesar_aprobada(solicitud_id: str) -> dict:
    """Aplica una solicitud aprobada, o dice por que no. Nunca confia en el evento.

    Devuelve `{"id", "resultado", ...}` con `resultado` en `aplicada`,
    `bloqueada_al_aplicar` u `omitida`. Se relee la fila (requisito 7.2): el
    evento del stream puede ser viejo, y lo que manda es el estado de ahora.

    Las excepciones de AWS suben tal cual: Lambda reintenta dos veces y manda
    el evento a la cola de fallos, que es donde alguien tiene que mirar. Solo
    el bloqueo del pre-vuelo se convierte en decision escrita, porque
    reintentarlo no lo arregla.

    `ControlNoEjecutable` (un control que no pudo correr) sube a proposito: no
    es un bloqueo y escribirlo mataria una solicitud buena por un corte
    pasajero. Lambda reintenta dos veces y despues lo recoge la cola de fallos.
    """
    try:
        registro = almacen.leer(solicitud_id)
    except almacen.RegistroInconsistente as e:
        # Una fila con forma imposible es un control que salta (S1). No se
        # escribe: no hay un registro fiable sobre el que decidir.
        log.warning("aplicacion id=%s omitida: fila inconsistente", solicitud_id)
        return {"id": solicitud_id, "resultado": "omitida", "motivo": f"fila inconsistente: {imprimible(e)}"}
    if registro is None:
        return {"id": solicitud_id, "resultado": "omitida", "motivo": "no existe"}

    estado_leido = registro.get("estado", "")
    if estado_leido != "aprobada":
        return {
            "id": solicitud_id,
            "resultado": "omitida",
            "motivo": f"el evento es viejo: la fila esta en {estado_leido}",
        }

    # Una fila con decision ya tomada no vuelve a aplicarse aunque alguien
    # reescriba `estado` a 'aprobada'. Se grita (RuntimeError) para que el
    # evento llegue a la cola de fallos y salte la alarma; no se toca IAM.
    if registro.get("aplicacion") is not None or registro.get("rechazo") is not None:
        log.warning("aplicacion id=%s estado reescrito sobre una decision ya tomada", solicitud_id)
        raise RuntimeError(
            f"{solicitud_id}: estado reescrito sobre una decision ya tomada "
            "(la fila lleva aplicacion o rechazo); no se aplica nada. Revisa la fila a mano."
        )

    # `aplicar` muta el registro en sitio, asi que el estado que se exige al
    # escribir es el LEIDO, no el que quede en memoria.
    #
    # En la cuenta solo existe el modo rol por persona (el runtime no escribe
    # otro). El modo de adjuntar a un principal que ya existe es del CLI de
    # desarrollo: aqui dejaria adjuntar a cualquier principal que lleve el
    # techo, tambien al rol de otra persona. No se llega a `aplicar`: es un
    # bloqueo que reintentar no arregla, asi que se escribe (Fase 33).
    resultado: dict | None
    avisos: list[str]
    if (registro.get("identidad_verificada") or {}).get("modo") != "rol_por_persona":
        resultado, avisos = None, []
        bloqueos = [
            "La Lambda del aplicador solo aplica solicitudes del modo rol por persona; "
            "esta fila es de otro modo (adjuntar a un principal que ya existe), que solo "
            "vale en el CLI de desarrollo."
        ]
    else:
        resultado, bloqueos, avisos = aplicar(registro)

    if bloqueos:
        registro["aplicacion"] = {
            "cuando": _ahora(),
            "decision": "bloquear",
            "bloqueos": bloqueos,
            "avisos": avisos,
            "por": identificar_aprobador().model_dump(),
        }
        registro["estado"] = "bloqueada_al_aplicar"
        try:
            almacen.guardar_decision(registro, "aplicacion", estado_leido, clave=solicitud_id)
        except (almacen.EstadoCambiado, almacen.RegistroInconsistente) as e:
            # Otro proceso decidio primero; su decision prevalece.
            return {"id": solicitud_id, "resultado": "omitida", "motivo": f"otro proceso decidio: {imprimible(e)}"}
        return {"id": solicitud_id, "resultado": "bloqueada_al_aplicar", "bloqueos": bloqueos}

    if resultado is None:
        raise RuntimeError(
            f"{solicitud_id}: sin bloqueos y sin resultado (contrato roto); "
            "revisa a mano si la politica quedo aplicada en AWS"
        )
    policy_arn = resultado["aplicacion"]["policy_arn"]
    rol_arn = resultado["aplicacion"].get("rol_arn")
    try:
        almacen.guardar_decision(resultado, "aplicacion", estado_leido, clave=solicitud_id)
    except (almacen.EstadoCambiado, almacen.RegistroInconsistente) as e:
        # La politica YA esta creada y adjunta en AWS y el registro no lo
        # dice. No hay Detach ni DeletePolicy a proposito: se grita con el ARN
        # y el evento va a la cola de fallos. Reintentar converge (`decidir`
        # vera la politica y solo adjuntara), pero alguien tiene que mirar.
        log.error(
            "aplicacion id=%s policy_arn=%s rol_arn=%s aplicada en AWS pero sin registrar: %s",
            solicitud_id, policy_arn, rol_arn, e,
        )
        raise RuntimeError(
            f"{solicitud_id}: la politica ya se aplico en AWS ({policy_arn}"
            + (f", rol {rol_arn}" if rol_arn else "")
            + f") pero el registro "
            f"NO se pudo actualizar: {e}. Revisa el estado a mano."
        ) from e
    except Exception as e:
        # Cualquier otro fallo del guardado (red, throttling): la politica ya
        # esta en AWS y su ARN no puede quedar fuera de los logs.
        log.error(
            "aplicacion id=%s policy_arn=%s rol_arn=%s aplicada en AWS pero el guardado fallo: %s",
            solicitud_id, policy_arn, rol_arn, type(e).__name__,
        )
        raise
    salida = {"id": solicitud_id, "resultado": "aplicada", "policy_arn": policy_arn}
    if rol_arn:
        salida["rol_arn"] = rol_arn
    return salida


def manejador(evento: dict, contexto) -> dict:
    """Punto de entrada de la Lambda `agente-iam-aplicador` (stream de la tabla).

    Un entorno roto lanza antes de leer nada: igual que la aprobacion
    responde 500, un entorno que no puede comprobar no decide, y al lanzar el
    evento se reintenta y acaba en la cola de fallos. Del evento solo se toma
    el id y, como defensa en profundidad, el estado de la imagen nueva: el
    filtro del disparador ya deja pasar solo `aprobada`, y esto no lee la
    tabla por algo que el filtro no deberia haber dejado pasar. Lo que decide
    es la fila releida en `procesar_aprobada`. Un log por registro con id y
    resultado; nunca el registro ni el texto de la solicitud.
    """
    problemas = _comprobar_entorno()
    if problemas:
        raise RuntimeError("entorno no apto para aplicar: " + "; ".join(problemas))

    procesados = []
    for registro in evento.get("Records", []):
        cambio = registro.get("dynamodb") or {}
        solicitud_id = ((cambio.get("Keys") or {}).get("id") or {}).get("S")
        estado = ((cambio.get("NewImage") or {}).get("estado") or {}).get("S")
        if not solicitud_id:
            salida = {"id": "-", "resultado": "omitida", "motivo": "el evento no trae id"}
        elif registro.get("eventName") not in ("INSERT", "MODIFY"):
            salida = {"id": solicitud_id, "resultado": "omitida", "motivo": f"evento {registro.get('eventName')}"}
        elif estado != "aprobada":
            salida = {"id": solicitud_id, "resultado": "omitida", "motivo": f"la imagen nueva esta en {estado}"}
        else:
            salida = procesar_aprobada(solicitud_id)
        if salida.get("policy_arn") and salida.get("rol_arn"):
            log.info(
                "aplicacion id=%s resultado=%s policy_arn=%s rol_arn=%s",
                salida["id"], salida["resultado"], salida["policy_arn"], salida["rol_arn"],
            )
        elif salida.get("policy_arn"):
            log.info("aplicacion id=%s resultado=%s policy_arn=%s", salida["id"], salida["resultado"], salida["policy_arn"])
        else:
            log.info("aplicacion id=%s resultado=%s", salida["id"], salida["resultado"])
        procesados.append(salida)
    return {"procesados": procesados}


def main() -> None:
    """El CLI de desarrollo, contra el almacen en disco.

    En la cuenta el aplicador es la Lambda `agente-iam-aplicador` (`manejador`);
    esto se conserva para probar el flujo sin DynamoDB, y como alli un
    bloqueo sale con codigo 3 sin escribir.
    """
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)

    solicitud_id = sys.argv[1]
    try:
        registro = almacen.leer(solicitud_id)
    except almacen.RegistroInconsistente as e:
        # Una fila con forma imposible (S1): es el control, no un fallo.
        print(f"\nNO se aplica {solicitud_id}: {imprimible(e)}")
        sys.exit(3)
    if registro is None:
        print(f"No encuentro la solicitud '{solicitud_id}' en {almacen.describir()}")
        sys.exit(1)

    # Igual que en `aprobar`: `aplicar` muta el registro en sitio y lo deja
    # en 'aplicada', asi que el estado que exigimos al escribir es el que
    # habia al leer. El pre-vuelo ya comprueba que sea 'aprobada'; esto
    # comprueba que lo siga siendo en el almacen y no solo en memoria.
    estado_leido = registro.get("estado", "")
    try:
        resultado, bloqueos, avisos = aplicar(registro)
    except ControlNoEjecutable as e:
        # No es un bloqueo: no se escribe nada y sale como error, no con 3.
        print(f"\nNO se pudo comprobar {solicitud_id}: {imprimible(e)}")
        sys.exit(1)

    # Avisos y bloqueos citan partes del registro (acciones, ARN, motivos
    # de riesgo que copian la justificacion): se escapan (S7).
    for a in avisos:
        print(f"[AVISO] {imprimible(a)}")

    if bloqueos:
        print(f"\nNO se aplica {solicitud_id}. Motivos:\n")
        for b in bloqueos:
            print(f"  - {imprimible(b)}\n")
        sys.exit(3)

    # Contrato de aplicar: sin bloqueos siempre hay resultado (mypy, Fase
    # 13). Si se rompe, la politica pudo quedar aplicada: se dice.
    if resultado is None:
        raise RuntimeError(
            f"{solicitud_id}: sin bloqueos y sin resultado (contrato roto); "
            "revisa a mano si la politica quedo aplicada en AWS"
        )

    # Aqui la politica YA esta creada y adjunta en AWS. Si la escritura del
    # registro falla, el cambio real no se deshace —el aplicador no tiene
    # DeletePolicy ni Detach a proposito— asi que lo que toca es gritar con
    # el ARN por delante, no morir con una traza. La idempotencia hace que
    # reintentar converja: `decidir` vera la politica existente y adjuntara.
    try:
        donde = almacen.guardar_decision(resultado, "aplicacion", estado_leido, clave=solicitud_id)
    except (almacen.EstadoCambiado, almacen.RegistroInconsistente) as e:
        print(
            f"\n[GRAVE] La politica ya se aplico en AWS "
            f"({resultado['aplicacion']['policy_arn']}) pero el registro NO "
            f"se pudo actualizar: {e}\n"
            "Revisa el estado a mano; el cambio en la cuenta esta hecho."
        )
        sys.exit(1)

    ap = resultado["aplicacion"]
    print("\n" + "=" * 70)
    print(f"SOLICITUD {resultado['id']}  ->  {resultado['estado']}")
    print("=" * 70)
    print(f"Politica:  {ap['policy_arn']}")
    print(f"Decision:  {ap['decision']} ({ap['motivo']})")
    print(f"Adjunta a: {resultado['identidad_verificada']['principal_arn']}")
    print(f"Aplicado por: {ap['por']['arn_canonico']}")
    print(f"\nGuardado en: {donde}")


if __name__ == "__main__":
    main()
