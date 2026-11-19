"""El entrypoint de AgentCore Runtime.

    entryPoint: ["main.py"]   (que llama a `arrancar()`; ver main.py)

Es la MISMA pieza que `cli.py`, con otra puerta de entrada: valida la
forma, llama a `procesar`, guarda el registro y lo devuelve. Ni una regla
de negocio vive aqui. Si algo de lo que decide el sistema estuviera en
este archivo, existiria en la version desplegada y no en la local, y las
dos dejarian de ser el mismo sistema.

QUE SE DESPLIEGA Y QUE NO. Solo el analista. `aprobar` no puede estar
aqui: aprobar es un acto humano, y bajo el rol del runtime el aprobador
seria el rol — la separacion de funciones se evaporaria comparando el rol
consigo mismo. `aplicador` tampoco: tiene escritura en IAM, y ponerlo en
el mismo proceso que interpreta texto no confiable es exactamente el
invariante que sostiene todo el diseno. El despliegue mueve una caja del
diagrama; no lo redibuja. `scripts/empaquetar.sh` los quita del zip y
comprueba que no los lleva.

EL SDK COMPRUEBA EL NOMBRE DEL PARAMETRO, NO SU POSICION. En
`BedrockAgentCoreApp._takes_context`: `params[1] == "context"`. Si se
llamara `contexto`, como pediria el resto de este codigo, el SDK decidiria
que el handler no quiere contexto y lo dejaria a None para siempre, sin un
solo error. Por eso ese parametro esta en ingles y esta nota existe.

QUIEN PIDIO. El runtime va detras del autorizador JWT de AgentCore
(`customJWTAuthorizer`, Cognito federado con Identity Center). El autorizador
valida firma, emisor, caducidad y cliente ANTES de dejar pasar la peticion, y
el contenedor recibe la cabecera `Authorization` con ese token ya validado
(medido en la Prueba B, MEDICIONES D.2). De sus claims sale la persona que
pidio la politica, que es lo que hace real la separacion por persona de
ADR-003.

UN SOLO CONTRATO (diseno 5.5). Este servidor acepta una unica forma de
entrada, `SolicitudWeb`, y la convierte en una `SolicitudEstructurada` de modo
`rol_por_persona`. Dos cosas que el cliente NO decide: el beneficiario lo pone
el token (la persona del claim `username`, atada a su `sub`), y el
`solicitud_id` lo forma el servidor desde la `clave_envio` que el cliente
genera por envio. Un `principal_arn_declarado` o un `solicitud_id` en el
payload se rechazan por forma. Sin JWT, o con un token sin persona, sin `sub`
o sin `client_id`, no hay a quien atribuir ni a quien dar el permiso: la
respuesta es `sin_persona`, no se llama al modelo y no se guarda registro. El
`client_id` es obligatorio porque la confianza del rol lleva el `aud` del
cliente de Cognito: sin el, la solicitud se aprobaria pero nunca podria
aplicarse. El modo de adjuntar a un principal existente vive solo en el CLI de
desarrollo sobre disco, que no tiene token.

LA RESPUESTA ES UNA VISTA, NO EL REGISTRO. Lo que sale por HTTP lo ve cualquier
persona con token desde la web; el registro completo (propuesta, historial de
validacion, trazas, identidad de quien invoco, justificacion) vive en la tabla,
que tiene su propio control de acceso. `vista_publica` es la lista cerrada de
lo que se devuelve.
"""

import base64
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone

from pydantic import ValidationError

from agente_iam import almacen, personas
from agente_iam.config import ALMACEN, DIR_CACHE_CATALOGO, SERVICIOS_PERMITIDOS
from agente_iam.herramientas import catalogo
from agente_iam.motivos import motivo_publico
from agente_iam.models import (
    PersonaDelToken,
    SolicitanteVerificado,
    SolicitudEstructurada,
    SolicitudWeb,
)
from agente_iam.orquestador import procesar

# stdout/stderr van a CloudWatch Logs automaticamente. No se registra el
# contenido de la solicitud: la justificacion es texto libre de un humano y
# el registro de auditoria ya lo conserva en el almacen, que si tiene
# control de acceso propio.
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("agente-iam")

# El NameID de Identity Center llega a Cognito con este prefijo en `username`
# (federacion de Cognito con el proveedor SAML, ADR-001).
PREFIJO_USERNAME = "IdentityCenter_"

# Lista cerrada de claims que pueden llegar al registro. Un claim que no este
# aqui (email, grupos, scope...) se descarta al leer el token: lo que no se
# necesita para atribuir no se guarda.
CLAIMS_DEL_REGISTRO = ("sub", "username", "jti", "client_id")

# La forma de un id de cliente de Cognito; la misma que exige `PersonaDelToken`.
_CLIENT_ID = re.compile(r"[a-z0-9]{26}")

COMO_SE_VERIFICO_JWT = (
    "JWT validado por el autorizador de AgentCore (customJWTAuthorizer); el "
    "contenedor lee los claims sin volver a verificar la firma, porque solo "
    "es alcanzable a traves del runtime"
)

# Sin JWT no hay persona que verificar (ADR-003).
SIN_JWT = (
    "sin cabecera Authorization con un JWT: sin JWT no hay persona verificada "
    "(ADR-001, ADR-003 B2)"
)
SIN_USERNAME = (
    "JWT validado por el autorizador de AgentCore, pero sin claim `username`: "
    "no hay persona que atribuir (ADR-001, ADR-003 B2)"
)
USERNAME_SIN_PREFIJO = (
    "JWT validado por el autorizador de AgentCore, pero su `username` no "
    f"empieza por `{PREFIJO_USERNAME}`: no es una persona de Identity Center "
    "(ADR-001, ADR-003 B2)"
)
SIN_SUB = (
    "JWT validado por el autorizador de AgentCore, pero sin claim `sub` (o "
    "vacio): la confianza del rol se ata al `sub` de la persona, asi que sin "
    "el no hay a quien dar el permiso (diseno 5.2)"
)
SIN_CLIENT_ID = (
    "JWT validado por el autorizador de AgentCore, pero sin claim `client_id` "
    "(o con una forma que no es la de un cliente de Cognito, 26 caracteres "
    "a-z y 0-9): la confianza del rol lleva el `aud` del cliente, y sin el la "
    "solicitud se aprobaria pero nunca podria aplicarse (diseno 5.2)"
)
PERSONA_INVALIDA = (
    "JWT validado por el autorizador de AgentCore, pero los datos de la "
    "persona no tienen una forma admitida (por ejemplo, un `sub` o un "
    "`username` con caracteres o largo inesperados)"
)
CON_PERSONA = (
    "claim username del JWT validado por el autorizador de AgentCore "
    "(NameID de Identity Center, ADR-001)"
)


def _comprobar_almacen() -> None:
    """El almacen efimero es un fallo silencioso, asi que se para al arrancar.

    Desplegado con `ALMACEN=disco`, todo funcionaria: el agente propondria,
    el registro se escribiria... en el microVM, que AgentCore destruye al
    terminar la sesion. Nadie veria un error. Simplemente no habria
    solicitudes que aprobar, y el sistema cuyo argumento entero es la
    auditabilidad perderia el 100% de su rastro sin avisar.

    La puerta explicita existe para probar el servidor en local, y hay que
    escribirla a proposito — como `--autoaprobacion-demo`.
    """
    if ALMACEN == "dynamodb":
        return
    if os.getenv("PERMITIR_ALMACEN_EFIMERO") == "si":
        log.warning(
            "ALMACEN=%s con la puerta PERMITIR_ALMACEN_EFIMERO abierta. "
            "El registro NO sobrevive a la sesion.",
            ALMACEN,
        )
        return
    raise RuntimeError(
        f"ALMACEN='{ALMACEN}' en el servidor. El sistema de ficheros de "
        "AgentCore Runtime es efimero: el registro se perderia al terminar "
        "la sesion y nadie se enteraria. Usa ALMACEN=dynamodb, o "
        "PERMITIR_ALMACEN_EFIMERO=si si estas probando en local."
    )


def _comprobar_catalogo() -> None:
    """El catalogo tiene que estar ANTES de la primera solicitud.

    Es la otra compuerta de arranque, y por el mismo motivo que la del
    almacen: sin catalogo el sistema no falla, se degrada. `soporta_recursos`
    y `excede_tipo_acceso` devuelven "no se pudo determinar", y el
    orquestador trata esa duda como advertencia — asi que el chequeo de
    nivel de acceso dejaria de bloquear y el registro seguiria diciendo que
    se hizo la comprobacion.

    Se comprueban TODOS los servicios permitidos y no solo el que pida la
    primera solicitud: el fallo debe aparecer al desplegar, no la semana que
    viene con la primera peticion de `sqs`.
    """
    faltan = catalogo.no_disponibles(SERVICIOS_PERMITIDOS)
    if faltan:
        raise RuntimeError(
            f"No se pudo cargar el catalogo de acciones de: {', '.join(faltan)} "
            f"(directorio '{DIR_CACHE_CATALOGO}'). Sin el, el chequeo de "
            "nivel de acceso se degrada a advertencia y deja de bloquear. "
            "El paquete de despliegue debe traer el catalogo dentro; "
            "revisa `empaquetar.sh`."
        )


def claims_validados(context) -> dict | None:
    """Los claims del JWT que el autorizador de AgentCore ya valido, o None.

    DECODIFICA SIN VERIFICAR LA FIRMA, y aqui es correcto: la verificacion
    (firma, emisor, caducidad, cliente) la hizo el autorizador antes de dejar
    pasar la peticion, y este contenedor solo es alcanzable a traves del
    runtime. Es el patron de `agente_eco.claims_sin_verificar`. Copiarlo a un
    servicio que NO tenga delante un autorizador seria un agujero: cualquiera
    fabricaria los claims que quisiera.

    Devuelve SOLO `CLAIMS_DEL_REGISTRO`, nunca el token ni el resto de la
    carga: lo que se devuelve acaba en el registro, y un token guardado es
    una credencial guardada. Ante cualquier cosa que no sea un
    `Authorization: Bearer <jwt de tres partes con carga JSON objeto>`
    devuelve None, igual que sin cabecera: no se adivina ni se rellena.
    """
    cabeceras = getattr(context, "request_headers", None)
    if not isinstance(cabeceras, dict):
        return None
    valor = cabeceras.get("Authorization", cabeceras.get("authorization"))
    if not isinstance(valor, str) or not valor[:7].lower() == "bearer ":
        return None
    partes = valor[7:].strip().split(".")
    if len(partes) != 3:
        return None
    carga = partes[1] + "=" * (-len(partes[1]) % 4)
    try:
        datos = json.loads(base64.urlsafe_b64decode(carga))
    except ValueError:  # base64, UTF-8 y JSON invalidos son todos ValueError
        return None
    if not isinstance(datos, dict):
        return None
    return {k: datos[k] for k in CLAIMS_DEL_REGISTRO if k in datos}


def persona_de(claims: dict | None) -> str | None:
    """La persona de Identity Center: `username` sin el prefijo de Cognito.

    None si no hay claims, no hay `username` o no empieza por el prefijo
    (entonces no es una persona de Identity Center y no se atribuye). No
    normaliza nada: la comparacion con quien aprueba (NFKC + casefold) es de
    `aprobar._misma_persona`, y hacerla en dos sitios los dejaria divergir.
    """
    if not claims:
        return None
    username = claims.get("username")
    if not isinstance(username, str) or not username.startswith(PREFIJO_USERNAME):
        return None
    persona = username[len(PREFIJO_USERNAME) :]
    # Un prefijo sin nada detras no es una persona: no se registra CON_PERSONA.
    return persona or None


def _sub_de(claims: dict | None) -> str | None:
    """El `sub` del token si es una cadena no vacia; si no, None."""
    sub = (claims or {}).get("sub")
    return sub if isinstance(sub, str) and sub else None


def _client_id_de(claims: dict | None) -> str | None:
    """El `client_id` del token si tiene la forma de un cliente de Cognito."""
    client_id = (claims or {}).get("client_id")
    if isinstance(client_id, str) and _CLIENT_ID.fullmatch(client_id):
        return client_id
    return None


def _como_se_verifico_solicitante(claims: dict | None, persona: str | None) -> str:
    """Por que hay o no hay persona, y cual de las cinco cosas falto: el JWT,
    el `username`, su prefijo, el `sub` o el `client_id`. Es el `detalle` de
    `sin_persona`."""
    if persona is not None:
        if not _sub_de(claims):
            return SIN_SUB
        return CON_PERSONA if _client_id_de(claims) else SIN_CLIENT_ID
    if claims is None:
        return SIN_JWT
    if not isinstance(claims.get("username"), str):
        return SIN_USERNAME
    return USERNAME_SIN_PREFIJO


def _quien_invoco(context, claims: dict | None) -> dict:
    """Quien lanzo esta corrida.

    CON JWT, los claims que el autorizador de AgentCore ya valido son prueba
    criptografica: se graba el `sub`, el `username` completo, el `jti` y el
    `client_id` (el `username` es lo que luego se busca en Cognito; el
    `client_id` lo repite el aplicador contra los clientes admitidos antes de
    escribir la confianza), mas el id de sesion y de peticion del runtime. Un claim que falte en el
    token va como None; no se inventa.

    SIN JWT (SigV4) AgentCore no entrega al codigo la identidad del
    principal que invoco. No hay cabecera con su ARN. Existe
    `X-Amzn-Bedrock-AgentCore-Runtime-User-Id`, pero la propia doc de AWS
    avisa de que el servicio no lo verifica: es un valor que escribe el
    llamante. Rellenar este campo con esa cabecera seria peor que dejarlo
    vacio: un campo con nombre oficial, que parece verificado y no lo esta,
    invita a creerselo (el error del CONTEXTO §9.16). Asi que se declara no
    determinable y se graba con que correlacionar en CloudTrail, donde la
    atribucion del principal si es fiable: el id de sesion y el de peticion.
    """
    if claims is not None:
        return {
            "determinable": True,
            "sub": claims.get("sub"),
            "usuario": claims.get("username"),
            "jti": claims.get("jti"),
            "client_id": claims.get("client_id"),
            "sesion_runtime": getattr(context, "session_id", None),
            "request_id": _request_id(),
            "como_se_verifico": COMO_SE_VERIFICO_JWT,
        }
    return {
        "arn": None,
        "determinable": False,
        "motivo": (
            "sin cabecera Authorization con un JWT; con SigV4 AgentCore no "
            "entrega al codigo la identidad del principal llamante. La "
            "atribucion fiable esta en CloudTrail (InvokeAgentRuntime), "
            "correlacionable por los identificadores de abajo."
        ),
        "session_id": getattr(context, "session_id", None),
        "request_id": _request_id(),
    }


def _request_id() -> str | None:
    """El id de peticion, que es la otra mitad de la correlacion con CloudTrail.

    Solo existe dentro del runtime. Fuera (tests, prueba en local) el SDK
    puede no estar instalado, y eso no es un fallo: es que no hay peticion.
    Se devuelve None en vez de inventarse uno, que es lo mismo que hace
    `_quien_invoco` con el ARN.
    """
    try:
        from bedrock_agentcore.runtime.context import BedrockAgentCoreContext
    except ImportError:
        return None
    return BedrockAgentCoreContext.get_request_id()


def _error(codigo: str, detalle, **extra) -> dict:
    return {"resultado": "error", "codigo": codigo, "detalle": detalle, **extra}


def _campos_con_error(e: ValidationError) -> list[dict]:
    return [
        {"campo": ".".join(str(p) for p in err["loc"]), "motivo": err["msg"]}
        for err in e.errors()
    ]


def vista_publica(registro: dict) -> dict:
    """Lo unico del registro que sale por HTTP: una lista cerrada.

    La respuesta la ve cualquier persona con token desde la web; el registro
    completo vive en la tabla, con su control de acceso. Por eso no salen la
    propuesta, el historial de validacion, la validacion, la identidad entera,
    quien invoco (`ejecutado_por`), el uso del modelo ni la justificacion, y
    un registro de error lleva solo `fase` y `tipo`, nunca `detalle` ni
    `traza` (pueden traer ARNs, nombres internos y texto del modelo).

    La forma exacta:

        id, estado, creada, solicitante,
        exige_confirmacion_de_riesgo (bool),
        rol_previsto (principal_arn de la identidad verificada, o None),
        horas y correo_aviso (de la solicitud, o None);
        motivo {codigo, texto} (Fase 28, `motivos.motivo_publico`: frases fijas,
        nunca texto del modelo ni de la justificacion);
        motivos y acceso_nuevo, solo si el registro los trae;
        error {fase, tipo}, solo si estado == "error".

    Tolera un registro pobre (el de error de `procesar` puede no traer
    identidad ni solicitud): lo que falta sale como None, no se inventa.
    """
    solicitud = registro.get("solicitud") or {}
    identidad = registro.get("identidad_verificada") or {}
    vista: dict = {
        "id": registro.get("id"),
        "estado": registro.get("estado"),
        "creada": registro.get("creada"),
        "solicitante": registro.get("solicitante"),
        "exige_confirmacion_de_riesgo": bool(registro.get("exige_confirmacion_de_riesgo")),
        "rol_previsto": identidad.get("principal_arn"),
        "horas": solicitud.get("horas"),
        "correo_aviso": solicitud.get("correo_aviso"),
        "motivo": motivo_publico(registro),
    }
    for opcional in ("motivos", "acceso_nuevo"):
        if registro.get(opcional):
            vista[opcional] = registro[opcional]
    if registro.get("estado") == "error":
        error = registro.get("error") or {}
        vista["error"] = {"fase": error.get("fase"), "tipo": error.get("tipo")}
    return vista


def manejar(payload: dict, context) -> dict:
    """Una solicitud web entra, un registro sale. Un solo contrato (diseno 5.5).

    Los codigos de salida del CLI (0/1/2) se vuelven aqui el campo
    `resultado`, porque HTTP no tiene codigos de salida y meterlos en el
    status confundiria "la solicitud es invalida" con "el servicio fallo".
    Un 4xx haria que AgentCore devolviera 424 sin detalle y quien invoca no
    sabria que arreglar.

    El orden importa y cada paso corta antes de gastar el siguiente:

    1. La forma (`SolicitudWeb`). Un `principal_arn_declarado` o un
       `solicitud_id` salen como campo extra: nadie elige beneficiario ni id.
    2. La persona, del token y no del cuerpo. Sin persona o sin `sub` es
       `sin_persona`: ni modelo ni registro.
    3. El id, que forma el servidor desde la `clave_envio`: la misma clave el
       mismo dia da el mismo id, asi que un doble clic o un reintento acaba en
       `registro_existente` con ese id y nunca en dos registros ni dos roles.
    4. `procesar`, y despues se guarda el registro.

    LIMITE ACEPTADO: el id es idempotente para el REGISTRO, no para el COSTE.
    `procesar` (el modelo, de 30 a 90 s) corre ANTES de `guardar_propuesta`,
    asi que dos envios casi simultaneos con la misma clave gastan dos corridas
    del modelo y el segundo muere en `registro_existente`. Evitarlo pediria
    leer la tabla antes de procesar, y el runtime no tiene `GetItem` a
    proposito: el intake no lee (ADR-004). La pagina deshabilita Enviar
    mientras hay una peticion en vuelo, que es lo que lo hace raro en la
    practica.
    """
    # El payload llega SIN TOCAR: el docstring del decorador del SDK lo dice
    # ("payloads are passed to the registered function unchanged") y
    # encarga la validacion a la aplicacion. Es la misma frontera que el
    # CLI: la forma se valida antes de que nada la interprete.
    try:
        sol_web = SolicitudWeb.model_validate(payload)
    except ValidationError as e:
        # Equivalente del exit code 2: forma invalida, no se procesa y no
        # deja registro. Se devuelven los campos concretos porque quien
        # invoca tiene que poder corregir el formulario.
        return _error("forma_invalida", _campos_con_error(e))

    # Los claims se leen UNA vez por peticion y se pasan a las funciones que
    # los usan; el token completo no se guarda en ninguna variable.
    claims = claims_validados(context)
    persona = persona_de(claims)
    sub = _sub_de(claims)
    client_id = _client_id_de(claims)
    if claims is None or persona is None or sub is None or client_id is None:
        # Sin persona verificada, o sin el cliente que ata la confianza del
        # rol, no hay beneficiario: el modelo no corre y no se guarda nada.
        return _error("sin_persona", _como_se_verifico_solicitante(claims, persona))

    solicitud_id = personas.id_de_solicitud(sol_web.clave_envio, datetime.now(timezone.utc))
    try:
        sol = SolicitudEstructurada(
            solicitud_id=solicitud_id,
            persona=PersonaDelToken(usuario=persona, sub=sub, client_id=client_id),
            campos=sol_web.campos,
            justificacion=sol_web.justificacion,
            horas=sol_web.horas,
            correo_aviso=sol_web.correo_aviso,
            clave_envio=sol_web.clave_envio,
        )
    except ValidationError as e:
        # La forma del cuerpo ya paso arriba; lo que puede fallar aqui son los
        # datos del token (un `sub` o un `client_id` con forma rara).
        return _error(
            "sin_persona",
            f"{PERSONA_INVALIDA}: "
            + "; ".join(f"{d['campo']}: {d['motivo']}" for d in _campos_con_error(e)),
        )

    log.info("procesando solicitud %s persona=%s", sol.solicitud_id, persona)

    # `procesar` no lanza nunca (Fase 4): devuelve un registro con estado
    # 'error' si muere a mitad. Aqui no hay try/except por eso mismo.
    registro = procesar(sol)
    registro["ejecutado_por"] = _quien_invoco(context, claims)
    # Antes de guardar: asi entra en `documento`, bajo la huella.
    registro["solicitante"] = SolicitanteVerificado(
        persona=persona,
        como_se_verifico=_como_se_verifico_solicitante(claims, persona),
    ).model_dump()

    try:
        donde = almacen.guardar_propuesta(registro)
    except almacen.RegistroExistente as e:
        # Sale sobre cualquier registro previo con ese id, no solo sobre uno ya
        # decidido. Con la clave de envio repetida es justo lo esperado: el
        # mismo id, el mismo registro.
        return _error("registro_existente", str(e), id=sol.solicitud_id)
    except ValueError as e:  # el registro no cabe en el almacen
        return _error("registro_no_almacenable", str(e), id=sol.solicitud_id)

    log.info("solicitud %s -> %s (%s)", sol.solicitud_id, registro["estado"], donde)
    # Un registro de error de `procesar` puede no traer identidad: entonces no
    # hay rol previsto, y se dice con None en vez de inventarlo.
    identidad = registro.get("identidad_verificada") or {}
    return {
        "resultado": "procesada",
        "guardado_en": donde,
        "solicitud_id": solicitud_id,
        "rol_previsto": identidad.get("principal_arn"),
        "registro": vista_publica(registro),
    }


def construir_app():
    """Se construye tarde para que importar este modulo no exija el SDK.

    Los tests prueban `manejar` directamente, que es donde esta la logica,
    sin necesitar `bedrock-agentcore` ni levantar un servidor.
    """
    from bedrock_agentcore.runtime import BedrockAgentCoreApp

    app = BedrockAgentCoreApp()
    # El nombre `context` es obligatorio; ver la nota de cabecera.
    app.entrypoint(manejar)
    return app


def arrancar() -> None:
    """Comprueba las dos compuertas y levanta el servidor.

    Vive en una funcion porque el `entryPoint` real es `main.py`, en la
    raiz del zip: ejecutar `agente_iam/servidor.py` directamente pondria la
    carpeta del script como `sys.path[0]` y `from agente_iam import ...`
    dejaria de resolver.

    Las dos compuertas matan el proceso en vez de avisar. Las dos protegen
    de lo mismo: un sistema que arranca, responde y parece sano mientras un
    control esta apagado.
    """
    for compuerta in (_comprobar_almacen, _comprobar_catalogo):
        try:
            compuerta()
        except RuntimeError as e:
            log.error("%s", e)
            sys.exit(1)

    log.info("almacen: %s", almacen.describir())
    log.info("catalogo: %s servicios cargados", len(SERVICIOS_PERMITIDOS))
    # `/ping` y `/invocations` en 8080 los pone el SDK. Escribirlos a mano
    # solo anadiria una copia nuestra de un contrato que es de AWS.
    construir_app().run()


if __name__ == "__main__":
    arrancar()
