"""Modelos tipados: el contrato de salida del agente.

La idea central: el agente NO devuelve prosa ni un JSON improvisado.
Devuelve un objeto que Pydantic valida. Si el modelo se sale del formato,
falla aqui y no mas adelante, cuando ya seria un cambio en la cuenta.

Fase 1 del plan de correcciones — el mismo principio, aplicado a la ENTRADA:
cerrar lo cerrable, restringir lo que no, aislar lo libre.

  - Pydantic valida la FORMA (alfabetos, patrones, longitudes). Un campo
    que no puede contener espacios, comillas ni saltos de linea no puede
    llevar una instruccion en lenguaje natural hacia el prompt.
  - La validacion SEMANTICA (¿el servicio esta permitido?, ¿el principal
    existe?) sigue en `chequeos_previos`, porque alli produce un registro
    auditable con estado; Pydantic solo corta lo que ni siquiera tiene
    forma valida.
  - `justificacion` es texto libre por diseno y no se puede cerrar: se
    limita su longitud aqui y se aisla al serializarla en el prompt
    (ver `orquestador._prompt`). Desde el 24-10-2026 (S7) tampoco admite
    caracteres de control salvo el salto de linea, y todo texto no
    confiable se imprime con `imprimible`: una secuencia ESC en la pantalla
    del aprobador podia subir el cursor y reescribir la linea del
    beneficiario.

Fase 23 (26-10-2026): la entrada tiene dos modos y cada uno vive en su camino
(diseno 5.5). El servidor del runtime habla UN solo contrato, `SolicitudWeb`:
sin ARN declarado, porque el beneficiario es la persona del token y lo pone el
servidor (`PersonaDelToken`), nunca el cliente. El modo de principal existente
(adjuntar al ARN declarado, con el techo) queda solo en el CLI de desarrollo
sobre disco, que no tiene token; por eso `SolicitudEstructurada`, el sobre
interno que ve el resto del codigo, admite los dos y exige exactamente uno.
"""

import re
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

# Las horas de vida del permiso son una sola regla: `config` la fija, `personas`
# la aplica (`vence_desde`) y aqui se engancha al contrato de entrada. Se
# importan de `config` y no de `personas` porque este modulo viaja en la Lambda
# de aprobacion, que no lleva `personas`.
from agente_iam.config import HORAS_MAX, HORAS_MIN

# Alfabeto de nombres de recurso AWS (buckets, tablas, colas...): letras,
# digitos, punto, guion, guion bajo y "/" para prefijos. Sin espacios,
# comillas, llaves ni saltos de linea: con esto no se escribe una frase.
_PATRON_RECURSO = r"^[A-Za-z0-9._/-]{1,255}$"

# Forma de un ARN de principal IAM (user o role, con path opcional).
# El alfabeto de nombres es el que documenta IAM: [A-Za-z0-9+=,.@_-] mas
# "/" para el path. La existencia real se comprueba despues, contra IAM.
_PATRON_ARN_PRINCIPAL = r"^arn:aws:iam::\d{12}:(user|role)/[A-Za-z0-9+=,.@_/-]{1,512}$"

# El id se vuelve nombre de archivo en `solicitudes/`: sin "/", sin "..",
# sin nada que pueda escapar de la carpeta.
_PATRON_ID = r"^[A-Za-z0-9_-]{1,64}$"

# Forma de una region AWS (us-east-1, ap-southeast-2, us-gov-west-1...).
_PATRON_REGION = r"^[a-z]{2}(-[a-z0-9]+)+-\d$"

# Fase 28 (27-10-2026): el recurso se puede escribir tambien como ARN. De cada
# forma sale el nombre, que es lo que usa todo lo demas (coherencia, techo,
# existencia). Las formas son las de `coherencia._FORMA_DEL_RECURSO`, al reves:
# alli se comprueba que un ARN nombra el recurso; aqui se saca el nombre. EC2
# no tiene recurso unico (es inventario) y no admite ARN. S3 no lleva region ni
# cuenta en el ARN de un bucket; de un ARN de objetos se toma el bucket.
_NOMBRE_EN_EL_ARN = {
    "s3": r"(?P<n>[^/]+)(?:/.*)?",
    "dynamodb": r"table/(?P<n>[^/]+)(?:/.*)?",
    "lambda": r"function:(?P<n>[^:]+)(?::[^:/]+)?",
    "sqs": r"(?P<n>[^:/]+)",
    "sns": r"(?P<n>[^:/]+)",
    "logs": r"log-group:(?P<n>[^:]+)(?::\*)?",
    "cloudwatch": r"alarm:(?P<n>.+)",
}
_PATRON_ARN_DE_RECURSO = r"^arn:aws:[a-z0-9-]+:[a-z0-9-]*:(\d{12})?:[A-Za-z0-9._/:*-]{1,1024}$"


def nombre_desde_arn(servicio: str, arn: str) -> tuple[str, str, str]:
    """(nombre, region, cuenta) del ARN de un recurso de `servicio`.

    Lanza ValueError con el motivo si el ARN no es de ese servicio, no tiene la
    forma de un recurso que este sistema concede o el nombre no cabe en el
    alfabeto de recursos. La region y la cuenta salen vacias en S3.
    """
    partes = arn.split(":", 5)
    if len(partes) < 6 or partes[0] != "arn" or partes[1] != "aws":
        raise ValueError(f"'{arn}' no tiene la forma de un ARN de AWS")
    _, _, srv, region, cuenta, resto = partes
    if srv != servicio:
        raise ValueError(f"el ARN es de '{srv}' y el servicio elegido es '{servicio}'")
    patron = _NOMBRE_EN_EL_ARN.get(servicio)
    if patron is None:
        raise ValueError(f"en '{servicio}' no se pide un recurso concreto: escribe un nombre, no un ARN")
    if servicio == "s3" and (region or cuenta):
        raise ValueError("el ARN no es el de un bucket de s3 (lleva region o cuenta)")
    encaje = re.fullmatch(patron, resto)
    if encaje is None:
        raise ValueError(f"el ARN no tiene la forma de un recurso de '{servicio}' que este sistema conceda")
    nombre = encaje.group("n")
    if not re.fullmatch(_PATRON_RECURSO, nombre):
        raise ValueError(f"el nombre '{nombre}' del ARN tiene caracteres que no van en un nombre de recurso")
    return nombre, region, cuenta


# Caracteres de control: C0 (salvo el salto de linea), DEL y C1. El
# salto de linea se admite porque un formulario lo produce; el retorno de
# carro no, porque basta para reescribir una linea de la terminal. C1 entra
# aunque la regla minima eran C0 y DEL: `\x9b` es el CSI de 8 bits y algunas
# terminales lo interpretan igual que `ESC [`.
_CONTROL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]")

# Forma de la direccion de aviso: ASCII estricto, local de 1 a 64 sin comas ni
# angulos ni espacios, y un dominio de etiquetas de 1 a 63 separadas por puntos
# (al menos dos). La direccion es dato no confiable que acaba en la pantalla de
# quien revisa y en el cuerpo de un correo: un alfabeto abierto (`[^@\s]`)
# dejaba pasar secuencias de escape, controles bidireccionales o varias
# direcciones separadas por coma. Solo se valida la forma; puede no ser de la
# persona. Se usa en `SolicitudWeb` y en `SolicitudEstructurada`, junto con
# `_VALIDADOR_CONTROL` por si el alfabeto se ampliara algun dia.
_PATRON_CORREO = (
    r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$"
)

# La forma de un UUID sin exigir version: la clave de un solo uso del envio.
_PATRON_CLAVE_ENVIO = r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"

# Los dos modos de la solicitud (ver el docstring del modulo).
Modo = Literal["principal_existente", "rol_por_persona"]


def _sin_caracteres_de_control(valor: str) -> str:
    """Rechaza el texto con caracteres de control (salvo el salto de linea).

    UNA sola logica para todo texto no confiable que acaba en la pantalla de
    quien revisa: la justificacion (`SolicitudEstructurada` y `SolicitudWeb`) y
    el usuario del token. Se engancha a cada campo con `_VALIDADOR_CONTROL`.
    """
    if _CONTROL.search(valor):
        raise ValueError(
            "el texto no admite caracteres de control (salvo el "
            "salto de linea): pueden reescribir la pantalla de quien lo revisa"
        )
    return valor


_VALIDADOR_CONTROL = AfterValidator(_sin_caracteres_de_control)


def imprimible(texto: object) -> str:
    r"""El texto con todo lo no imprimible escapado (`\x1b`, `\n`, `\u202e`).

    Para pintar en una terminal lo que escribio otro: la justificacion, los
    supuestos y la justificacion del modelo, y los motivos que los citan.
    El salto de linea tambien se escapa: en una salida de una linea por
    campo, una linea nueva puede imitar otro campo ("Beneficiario: ...").
    `str.isprintable` deja fuera los de control y los de formato, como el
    U+202E que invierte el sentido del texto.
    """
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(texto))


class Statement(BaseModel):
    """Un statement de una politica IAM.

    `extra="forbid"` (24-10-2026, S9): Pydantic descartaba en silencio las
    claves que no conoce (`NotAction`, `NotResource`, `NotPrincipal`), asi
    que `revalidar` juzgaba un documento y el aplicador aplicaba otro, el
    crudo. Ahora un documento con claves de mas no valida.
    """

    model_config = ConfigDict(extra="forbid")

    Sid: str | None = Field(
        default=None, description="Identificador corto del statement, sin espacios"
    )
    Effect: Literal["Allow", "Deny"]
    Action: list[str] = Field(
        description="Acciones IAM completas, p.ej. ['s3:GetObject']. "
        "Nunca uses comodines amplios como 's3:*' o '*'."
    )
    Resource: list[str] = Field(
        description="ARNs concretos. Evita '*' salvo que la accion no soporte "
        "recursos con ARN, y en ese caso explicalo en los supuestos."
    )
    Condition: dict[str, Any] | None = Field(
        default=None, description="Bloque Condition opcional de IAM"
    )


class PolicyDocument(BaseModel):
    """Documento de politica IAM completo. Sin claves de mas (S9)."""

    model_config = ConfigDict(extra="forbid")

    Version: Literal["2012-10-17"] = "2012-10-17"
    Statement: list[Statement]


class PropuestaPolitica(BaseModel):
    """Lo que el agente entrega al humano que aprueba."""

    accion: Literal["crear", "modificar", "asignar"] = Field(
        description="Que hay que hacer para cumplir la solicitud"
    )
    nombre_politica: str = Field(
        description="Nombre propuesto para la politica, en PascalCase"
    )
    principal_arn: str = Field(
        description="ARN del usuario o rol destino. Si no se puede determinar "
        "con lo que dio el solicitante, escribe 'DESCONOCIDO'."
    )
    justificacion: str = Field(
        description="Por que esta politica cumple la solicitud, en 2-3 frases"
    )
    policy_document: PolicyDocument
    nivel_riesgo: Literal["bajo", "medio", "alto"]
    # Fase 28: el formulario ya no pide el tipo de acceso. El modelo declara lo
    # que entendio de la solicitud y `coherencia.chequeos_posteriores` bloquea
    # una politica que vaya mas alla. Opcional por las propuestas guardadas
    # antes; una propuesta nueva sin el se bloquea y se repara.
    nivel_entendido: Literal["lectura", "modificacion"] | None = Field(
        default=None,
        description="Lo que la solicitud pide, segun su texto: 'lectura' si solo pide ver, "
        "listar o descargar; 'modificacion' si pide subir, cambiar o borrar algo.",
    )
    supuestos: list[str] = Field(
        description="Todo lo que tuviste que asumir por falta de informacion. "
        "Si asumiste algo, dilo aqui en vez de inventarlo en silencio."
    )


# --- Entrada estructurada ---------------------------------------------------
# El principio: separar lo verificado de lo declarado. Los campos de
# identidad NO los aporta el solicitante; se resuelven contra IAM. La
# justificacion si es texto libre y se trata como dato no confiable.


class CamposEstructurados(BaseModel):
    """Lo que el formulario captura con listas cerradas o alfabetos cerrados.

    `tipo_acceso` es una lista cerrada de verdad (Literal), opcional desde la
    Fase 28. `servicio` y
    `region` tienen alfabeto cerrado aqui y lista cerrada en
    `chequeos_previos` (para que el rechazo deje registro). `recurso` no
    puede ser lista cerrada — los nombres de buckets y tablas son
    arbitrarios — asi que se cierra su alfabeto.
    """

    servicio: str = Field(
        pattern=r"^[a-z0-9-]{1,40}$",
        description="Servicio AWS objetivo, p.ej. 's3'",
    )
    recurso: str = Field(
        pattern=_PATRON_RECURSO,
        description="Nombre del recurso, p.ej. 'finanzas-2026'",
    )
    # Fase 28: el formulario ya no lo pide; el nivel lo declara el modelo
    # (`PropuestaPolitica.nivel_entendido`). Sigue aqui, opcional, porque los
    # registros anteriores lo llevan y `aprobar` y el aplicador los revalidan
    # con el; el CLI de desarrollo tambien puede mandarlo.
    tipo_acceso: Literal["lectura", "escritura", "administracion"] | None = None
    region: str = Field(
        default="us-east-1",
        pattern=_PATRON_REGION,
        description="Region del recurso",
    )
    recurso_arn: str | None = Field(
        default=None,
        pattern=_PATRON_ARN_DE_RECURSO,
        description="El ARN tal como lo escribio el solicitante, si escribio un ARN",
    )

    @model_validator(mode="before")
    @classmethod
    def _recurso_como_arn(cls, datos: Any) -> Any:
        """Si `recurso` es un ARN, lo separa: el nombre a `recurso`, el ARN a
        `recurso_arn`. El servicio y la region del ARN tienen que ser los del
        formulario; la cuenta la comprueba `coherencia.motivos_de_la_cuenta_del_arn`."""
        if not isinstance(datos, dict):
            return datos
        recurso = datos.get("recurso")
        if not isinstance(recurso, str) or not recurso.startswith("arn:"):
            return datos
        servicio = str(datos.get("servicio", ""))
        nombre, region_arn, _ = nombre_desde_arn(servicio, recurso)
        region = datos.get("region", "us-east-1")
        if region_arn and region_arn != region:
            raise ValueError(f"el ARN es de la region '{region_arn}' y la region elegida es '{region}'")
        return {**datos, "recurso": nombre, "recurso_arn": recurso}


class PersonaDelToken(BaseModel):
    """Quien pide, tomado del JWT que verifico el autorizador y nunca del cuerpo.

    `usuario` es el nombre de la persona de Identity Center (claim `username`),
    `sub` su identificador estable en el pool (es lo que ata la confianza del rol)
    y `client_id` el cliente de Cognito que emitio el token (obligatorio: el
    servidor exige el claim y la confianza del rol lo ata al `aud`). Lo pone el
    servidor; el cliente no puede elegirlo.
    """

    usuario: Annotated[str, Field(min_length=1, max_length=128), _VALIDADOR_CONTROL]
    sub: str = Field(pattern=r"^[A-Za-z0-9-]{1,64}$")
    client_id: str = Field(pattern=r"^[a-z0-9]{26}$")


class IdentidadVerificada(BaseModel):
    """Resuelta contra IAM, no tomada del formulario.

    Fase 3: cuando `existe` es True, `principal_arn` es el ARN CANONICO
    que devolvio la API de IAM, no el declarado por el intake. Cuando es
    False, `detalle` explica exactamente por que (no existe, o el ARN
    declarado no corresponde al principal real).
    """

    principal_arn: str
    tipo: Literal["user", "role", "desconocido"]
    existe: bool
    cuenta: str
    # El id unico que asigna IAM (AIDA... para usuarios, AROA... para roles).
    # Sale del mismo GetUser/GetRole que ya se llama: cero peticiones nuevas.
    #
    # Existe porque el ARN NO identifica una entidad, identifica un nombre.
    # Si alguien borra 'ana.gomez' y crea otra 'ana.gomez', el ARN es
    # identico y la entidad es otra: otro id, otras politicas, otra persona.
    # Entre aprobar y aplicar cabe esa ventana, y el aplicador compara el id
    # congelado en la huella contra el de ahora. Es la misma leccion de la
    # Fase 3 un nivel mas abajo: alli el nombre no bastaba y hacia falta el
    # ARN; aqui el ARN no basta y hace falta el id.
    principal_id: str = ""
    # El ARN del permission boundary que lleva el principal, o None. Sale
    # del mismo GetUser/GetRole: cero llamadas nuevas. Es el requisito de
    # alta del sistema (ver `config.NOMBRE_TECHO`).
    permissions_boundary: str | None = None
    politicas_actuales: list[str] = Field(default_factory=list)
    detalle: str | None = None
    # Fase 23: en el modo `rol_por_persona` esto describe a la persona del token
    # y al rol que se creara (`principal_arn` es el ARN previsto; `existe` True
    # significa aqui "beneficiario verificado", por el token, aunque el rol se
    # cree al aplicar; `principal_id` queda vacio hasta entonces), no a un
    # principal que ya existe. El valor por defecto es el modo de hoy, asi que
    # los registros y los tests anteriores no cambian.
    modo: Modo = "principal_existente"
    persona: PersonaDelToken | None = None
    horas: int | None = None


# --- Estados y aprobacion ---------------------------------------------------

Estado = Literal[
    "rechazada_en_chequeos_previos",
    "propuesta",
    "requiere_revision_humana",
    "redundante_no_requiere_cambio",
    "aprobada",
    "rechazada_por_aprobador",
    "aplicada",
    "bloqueada_al_aplicar",
    "error",
]
# Ya no existe `rechazada_por_validacion`. Era inalcanzable y se comprobo
# leyendo el loop: `_correr_loop` solo sale por `break` (aprobable) o por
# agotar el rango, asi que al salir o hay veredicto aprobable o
# `intentos == MAX_INTENTOS`. Un estado que el codigo no puede producir es
# documentacion falsa: quien lea la tabla creera que existe esa via.

# Los unicos estados desde los que se puede aprobar. Lista blanca: lo que
# no este aqui se rechaza con motivo, en vez de colarse por descuido.
ESTADOS_APROBABLES = ("propuesta",)


class AprobadorVerificado(BaseModel):
    """Quien aprueba, resuelto contra STS e IAM y nunca declarado.

    Se guardan el ARN crudo Y el canonico. El crudo es el hecho que
    devolvio la API; el canonico es NUESTRA interpretacion de ese hecho.
    Quien audite tiene que poder revisar el razonamiento, no creerselo.
    """

    arn_llamante: str
    arn_canonico: str | None
    user_id: str
    cuenta: str
    como_se_verifico: str
    determinable: bool
    # La persona de Identity Center (ADR-003, B2): el nombre de sesion de un rol
    # del permission set del aprobador, y solo si las tres comprobaciones de
    # `aprobar._resolver` pasan. None para un usuario IAM o cualquier otro rol;
    # `como_se_verifico` dice cual fallo. No es lo mismo que `determinable`:
    # un rol ordinario es comparable por ARN y aun asi no tiene persona.
    persona: str | None = None


class SolicitanteVerificado(BaseModel):
    """Quien PIDIO la politica, con la honestidad de cuanto se comprobo.

    No es `ejecutado_por`: eso es quien lanzo el proceso. Aqui va la persona
    de Identity Center que formulo la peticion, y la separacion de funciones
    de ADR-003 la compara con quien aprueba. Sin JWT nadie la verifica, asi
    que `persona` es None y `como_se_verifico` dice por que; la duda bloquea
    la aprobacion, no se rellena con lo que declara el formulario.
    Sin valores por defecto: cada sitio que graba un registro decide.
    """

    persona: str | None
    como_se_verifico: str


class PeticionAprobacion(BaseModel):
    """Lo unico que viaja a la Lambda de aprobacion (ADR-003, A2).

    Quien aprueba NO esta aqui: lo dice la firma SigV4 de la peticion, nunca
    el cuerpo. Un campo que nombre al aprobador, el estado o el bloque a
    escribir es un campo de mas, y `extra="forbid"` lo rechaza entero. `strict`
    evita que `"true"` o `1` valgan como booleano en las dos puertas que
    relajan un control (`autoaprobacion_demo`, `riesgo_alto_confirmado`).
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(pattern=_PATRON_ID)
    accion: Literal["aprobar", "rechazar"]
    # La forma exacta de `huella.calcular` y un tope para el motivo: el cuerpo
    # lo escribe quien firma, y sin esto cualquier texto (no ASCII, enorme)
    # llegaba hasta la comparacion y el almacen.
    huella: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    motivo: str | None = Field(default=None, max_length=2000)
    autoaprobacion_demo: bool = False
    riesgo_alto_confirmado: bool = False

    @model_validator(mode="after")
    def _rechazar_pide_motivo(self) -> "PeticionAprobacion":
        if self.accion == "rechazar" and not (self.motivo and self.motivo.strip()):
            raise ValueError("rechazar necesita un motivo no vacio")
        return self


# `SeparacionDeFunciones` y `Aprobacion` vivieron aqui hasta el 24-10-2026
# (revision O16): nadie los importaba, el bloque de aprobacion se arma como
# dict en `aprobar.aprobar` y ya divergian de el (`_separacion` puede
# devolver "cumplido" junto a un bloqueo, y el modelo decia que ese caso
# nunca se escribia). Un contrato que
# no se aplica es documentacion falsa. Lo que el aplicador exige del bloque
# (separacion cumplida, techo PASS, riesgo confirmado) lo comprueba su
# pre-vuelo desde el 24-10-2026 (S4), con sus tests en test_aplicador.py.


class SolicitudWeb(BaseModel):
    """El unico contrato que acepta el servidor del runtime (diseno 5.1).

    Es lo que manda la pagina: sin `principal_arn_declarado` y sin `solicitud_id`
    (`extra="forbid"` los rechaza por forma, porque serian un intento de elegir
    beneficiario o id). El beneficiario es la persona del token y el id lo forma
    el servidor a partir de `clave_envio`, la clave de un solo uso que el cliente
    genera al pulsar enviar y repite si reintenta. `horas` es la vida del permiso
    (estricto: ni "4" ni 4.0). `correo_aviso` y `justificacion` son dato no
    confiable; solo se valida su forma.
    """

    model_config = ConfigDict(extra="forbid")

    clave_envio: str = Field(
        pattern=_PATRON_CLAVE_ENVIO,
        description="UUID de un solo uso por envio; el servidor deriva de el el solicitud_id",
    )
    campos: CamposEstructurados
    horas: int = Field(
        ge=HORAS_MIN, le=HORAS_MAX, strict=True, description="Vida del permiso, en horas"
    )
    correo_aviso: Annotated[str, _VALIDADOR_CONTROL] = Field(
        pattern=_PATRON_CORREO,
        max_length=254,
        description="Direccion a la que avisar de la decision. DATO NO CONFIABLE.",
    )
    justificacion: Annotated[str, _VALIDADOR_CONTROL] = Field(
        min_length=1,
        max_length=1500,
        description="Texto libre del solicitante. DATO NO CONFIABLE.",
    )


class SolicitudEstructurada(BaseModel):
    """El sobre que llega al orquestador, en uno de dos modos (diseno 5.5).

    - `rol_por_persona` (el del servidor): lo arma el servidor a partir de una
      `SolicitudWeb` validada y del JWT. Lleva `persona` (del token), `horas` y,
      si vienen, `correo_aviso` y `clave_envio`. No hay ARN declarado: el
      beneficiario es el rol que se creara para esa persona.
    - `principal_existente` (solo el CLI de desarrollo sobre disco, que no tiene
      token): lleva `principal_arn_declarado` y se adjunta a ese principal con el
      techo. Es el payload de siempre, asi que el corpus de `ejemplos/` y las
      mediciones M.4 y M.5 siguen sirviendo.

    Se exige exactamente uno de `principal_arn_declarado` o `persona`; `horas`
    solo existe con persona, y `correo_aviso` y `clave_envio` tambien. Un sobre
    que mezcle los modos no tiene forma valida.
    """

    solicitud_id: str = Field(
        pattern=_PATRON_ID,
        description="Identificador de la solicitud; se usa como nombre de "
        "archivo, por eso su alfabeto esta cerrado",
    )
    principal_arn_declarado: str | None = Field(
        default=None,
        pattern=_PATRON_ARN_PRINCIPAL,
        description="ARN declarado por el intake; se verifica contra IAM. "
        "Solo en el modo principal_existente.",
    )
    campos: CamposEstructurados
    justificacion: Annotated[str, _VALIDADOR_CONTROL] = Field(
        min_length=1,
        max_length=1500,
        description="Texto libre del solicitante. DATO NO CONFIABLE.",
    )
    persona: PersonaDelToken | None = None
    horas: int | None = Field(default=None, ge=HORAS_MIN, le=HORAS_MAX)
    correo_aviso: Annotated[str, _VALIDADOR_CONTROL] | None = Field(
        default=None, pattern=_PATRON_CORREO, max_length=254
    )
    clave_envio: str | None = Field(default=None, pattern=_PATRON_CLAVE_ENVIO)

    @model_validator(mode="after")
    def _un_solo_modo(self) -> "SolicitudEstructurada":
        if (self.principal_arn_declarado is None) == (self.persona is None):
            raise ValueError(
                "la solicitud necesita exactamente uno de principal_arn_declarado "
                "(modo de principal existente) o persona (rol por persona)"
            )
        if (self.horas is None) != (self.persona is None):
            raise ValueError("horas va si y solo si hay persona (rol por persona)")
        if self.persona is None and (self.correo_aviso is not None or self.clave_envio is not None):
            raise ValueError("correo_aviso y clave_envio solo existen en el modo de rol por persona")
        return self

    @property
    def modo(self) -> Modo:
        return "rol_por_persona" if self.persona is not None else "principal_existente"
