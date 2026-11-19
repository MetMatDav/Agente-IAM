"""Coherencia entre la propuesta del modelo y la solicitud que la origino.

Las tres capas de validacion miran el DOCUMENTO de politica. Ninguna mira
el formulario. Esta es la cuarta pregunta, la que solo responde el codigo:
¿la propuesta corresponde a lo que se pidio?

Vive aparte del orquestador por una razon de dependencias: `aprobar` y el
aplicador la necesitan para revalidar, y el orquestador importa el agente
(Strands + BedrockModel). El aplicador no debe ni importar el modelo.

Antes de las seis, `chequeos_formulario` mira el formulario solo (servicio
permitido, solo lectura por tipo, region permitida, recurso del sistema,
palabras del formato de ARN). La usan el orquestador antes del modelo y
`revalidar` al aprobar y al aplicar (24-10-2026, S8): hasta esa fecha la
revalidacion no volvia a mirar SERVICIOS_PERMITIDOS, y un `documento` con
`servicio: kms` hacia que las acciones de kms fueran "del servicio pedido".

Seis comprobaciones, todas deterministas:

  1. Destinatario. `principal_arn` == el ARN verificado.
  2. Servicio. Toda accion Allow es del servicio del formulario.
  3. Nivel de acceso. Lo decide el catalogo oficial, no una lista a mano.
  4. Recurso (revision 2026-10; posicion, 24-10-2026). Todo recurso Allow
     nombra el recurso del formulario EN EL SITIO del ARN que corresponde
     a su servicio (`_FORMA_DEL_RECURSO`). Faltaba, y era el hueco mas
     ancho del sistema: la baranda
     de comodines solo miraba region y cuenta, asi que
     `arn:aws:s3:::*` o `table/*` pasaban las tres capas. El techo tampoco
     lo frenaba, porque permite enteros los servicios permitidos: la
     interseccion de "GetObject sobre todos los buckets" con "s3:* sobre
     *" es "GetObject sobre todos los buckets". En S3 se exige ademas la
     condicion de cuenta del recurso (S5): el ARN de un bucket no dice de
     quien es.
  5. Solo lectura (ADR-002, opcion B). En un servicio de `SOLO_LECTURA`
     toda accion Allow encaja en su patron: en EC2, `Describe*`. El nivel
     del catalogo no basta, porque `lectura` admite las 52 de nivel Read
     de EC2, entre ellas `GetConsoleOutput` y `GetPasswordData`.
  6. Recursos del sistema (ADR-002, D3). Ningun componente de un ARN
     Allow empieza por un prefijo del propio agente. El 4 no lo cubre:
     `arn:aws:s3:::agente-iam-paquete-x/finanzas-2026` nombra el recurso
     del formulario como componente completo.
"""

import re
from fnmatch import fnmatchcase

from agente_iam import config
from agente_iam.config import (
    ACCIONES_PROHIBIDAS,
    PREFIJOS_DEL_SISTEMA,
    REGIONES_PERMITIDAS,
    SERVICIOS_PERMITIDOS,
    SOLO_LECTURA,
)
from agente_iam.herramientas.catalogo import acciones_en_memoria, excede_tipo_acceso, nivel_en_memoria
from agente_iam.models import CamposEstructurados, PropuestaPolitica, SolicitudEstructurada, nombre_desde_arn

# Donde va el nombre del recurso en el ARN de cada servicio (revision del
# 24-10-2026, S2). `{n}` es el nombre del formulario, literal; el resto se
# compara entero con el trozo del ARN que va detras de la cuenta. Hasta esa
# fecha bastaba con que el nombre fuera un componente COMPLETO en cualquier
# posicion, y eso aceptaba `arn:aws:s3:::nominas/finanzas-2026/*` (objetos
# de OTRO bucket bajo esa clave) o, con `recurso: "table"`, `table/*`.
#
#   s3          el bucket, o lo que hay dentro de el
#   dynamodb    la tabla y sus subrecursos (indices, streams, backups...)
#   lambda      la funcion, con un calificador opcional (version o alias)
#   sqs, sns    la cola o el tema, enteros
#   logs        el grupo, `:*` o sus streams
#   cloudwatch  la alarma
#
# EC2 no esta a proposito: solo concede inventario (`Describe*`), que va con
# `Resource "*"`, y cualquier ARN de EC2 se rechaza. Un servicio sin fila
# tampoco acepta ningun ARN: la duda no concede.
_FORMA_DEL_RECURSO = {
    "s3": r"{n}(?:/.*)?",
    "dynamodb": r"table/{n}(?:/.*)?",
    "lambda": r"function:{n}(?::[^:/]+)?",
    "sqs": r"{n}",
    "sns": r"{n}",
    "logs": r"log-group:{n}(?::\*|:log-stream:.*)?",
    "cloudwatch": r"alarm:{n}",
}

# Las palabras literales del formato de ARN de cada servicio, sacadas de los
# `ARNFormats` de la referencia de autorizacion el 23-10-2026 (S2). Un
# `recurso` que es una de ellas no nombra un recurso: nombra un TIPO, y con
# el `table/*` o `function:*` parecian "el recurso pedido". La posicion de
# `_FORMA_DEL_RECURSO` ya lo frena; esto lo corta antes del modelo, con el
# motivo en el registro. EC2, SQS y SNS no tienen palabras (EC2 no concede
# ARN; en SQS y SNS el nombre es el ARN entero).
PALABRAS_DEL_ARN: dict[str, frozenset[str]] = {
    "s3": frozenset({
        "access-grants", "accesspoint", "async-request", "default", "grant", "job",
        "location", "mrap", "object", "storage-lens", "storage-lens-group",
    }),
    "dynamodb": frozenset({"backup", "export", "global-table", "import", "index", "stream", "table"}),
    "lambda": frozenset({
        "capacity-provider", "code-signing-config", "durable-execution", "endpoint",
        "event-source-mapping", "function", "layer", "microvm-image", "network-connector",
        "revision", "web-function",
    }),
    "logs": frozenset({
        "anomaly-detector", "delivery", "delivery-destination", "delivery-source",
        "destination", "log-group", "log-stream", "lookup-table", "scheduled-query",
    }),
    "cloudwatch": frozenset({
        "access-grant", "access-profile", "alarm", "alarm-mute-rule", "alert", "dashboard",
        "dataset", "domain", "ingestion-endpoint", "insight-rule", "integration",
        "metric-stream", "omni-dashboard", "organization-access-grant",
        "organization-domain", "service", "slo", "space", "view",
    }),
}

# La clave que dice de quien es el recurso (S5). En S3 el ARN no lleva
# cuenta, asi que sin ella un bucket de otra cuenta era "el recurso pedido".
# Solo `aws:ResourceAccount`: Access Analyzer compara `s3:ResourceAccount` y
# `aws:ResourceAccount` como claves distintas y el techo usa la segunda, asi
# que una propuesta con la primera fallaba CheckNoNewAccess (medido el
# 25-10-2026). Las claves de condicion de IAM no distinguen mayusculas.
_CLAVE_DE_CUENTA = "aws:resourceaccount"


def fuera_del_recurso(
    recurso: str, servicio: str, nombre: str, region: str, cuenta: str
) -> str | None:
    """Motivo por el que `recurso` NO es el del formulario, o None si lo es.

    La regla (24-10-2026): el nombre del formulario tiene que estar en la
    POSICION que nombra el recurso en el ARN de su servicio
    (`_FORMA_DEL_RECURSO`), no en cualquier componente:

      arn:aws:s3:::finanzas-2026                  pasa
      arn:aws:s3:::finanzas-2026/*                pasa: objetos DENTRO del bucket
      arn:aws:s3:::finanzas-2026*                 no: tambien es finanzas-2026-rrhh
      arn:aws:s3:::*/finanzas-2026                no: esa clave en cualquier bucket
      arn:aws:s3:::nominas/finanzas-2026/*        no: objetos de OTRO bucket
      arn:aws:dynamodb:...:table/pedidos/index/x  pasa
      arn:aws:dynamodb:...:table/nominas/index/pedidos   no: indice de otra tabla
      arn:aws:dynamodb:...:table/*                no: todas las tablas

    `Resource: "*"` no se juzga aqui: es legitimo solo para acciones que
    no admiten ARN, y eso lo decide la baranda de `validacion` con el
    catalogo (y le exige lectura y un Condition).
    """
    if recurso == "*":
        return None
    partes = recurso.split(":", 5)
    if len(partes) < 6 or partes[0] != "arn":
        return f"'{recurso}' no es un ARN"
    _, _, srv, reg, cta, resto = partes
    if srv.lower() != servicio:
        return f"'{recurso}' es un recurso de '{srv}' y la solicitud es de '{servicio}'"
    forma = _FORMA_DEL_RECURSO.get(servicio)
    if forma is None:
        return (
            f"'{recurso}': en '{servicio}' este sistema no concede ARN concretos "
            "(en ec2, solo inventario con Resource '*')"
        )
    if servicio == "s3" and (reg or cta):
        # El ARN de un bucket y de sus objetos no lleva region ni cuenta. Si
        # las lleva es otro tipo (punto de acceso, trabajo, Storage Lens).
        return f"'{recurso}' no es el ARN de un bucket ni de sus objetos"
    if reg and reg != region:
        return f"'{recurso}' es de la region '{reg}' y la solicitud es de '{region}'"
    if cta and cta != cuenta:
        return f"'{recurso}' es de la cuenta '{cta}', no de la cuenta del beneficiario"
    if re.fullmatch(forma.format(n=re.escape(nombre)), resto):
        return None
    return (
        f"'{recurso}' no se limita al recurso '{nombre}' del formulario "
        "(el nombre no esta donde el ARN nombra el recurso, o va detras de un comodin)"
    )


def valor_esperado_de_la_cuenta(cuenta: str) -> str:
    """El valor que debe llevar `aws:ResourceAccount` en una propuesta de S3."""
    if config.VALOR_CUENTA_DEL_RECURSO is None:
        return cuenta
    return config.VALOR_CUENTA_DEL_RECURSO


def lleva_la_cuenta_del_recurso(condicion: dict | None, cuenta: str) -> bool:
    """True si el Condition exige que el recurso sea de `cuenta` (S5).

    Solo vale `StringEquals` con `aws:ResourceAccount` y todos los valores
    iguales a `config.VALOR_CUENTA_DEL_RECURSO` (o a la cuenta verificada si
    esa constante es None). La forma tiene que ser la del techo: la literal
    falla contra un techo con la variable y viceversa. `...IfExists` no:
    dejaria pasar una peticion sin la clave.
    """
    if not cuenta or not isinstance(condicion, dict):
        return False
    iguales = condicion.get("StringEquals")
    if not isinstance(iguales, dict):
        return False
    esperado = valor_esperado_de_la_cuenta(cuenta)
    for clave, valor in iguales.items():
        if clave.lower() == _CLAVE_DE_CUENTA:
            valores = valor if isinstance(valor, list) else [valor]
            if valores and all(v == esperado for v in valores):
                return True
    return False


def chequeos_formulario(campos: CamposEstructurados) -> list[str]:
    """Lo que se puede rechazar mirando solo el formulario. Sin red.

    Los textos de `chequeos_formulario_con_codigo`, que es la fuente (Fase 28:
    cada motivo lleva un codigo para el mensaje de la pagina y del correo).
    """
    return [texto for _, texto in chequeos_formulario_con_codigo(campos)]


def chequeos_formulario_con_codigo(campos: CamposEstructurados) -> list[tuple[str, str]]:
    """Lo que se puede rechazar mirando solo el formulario, como (codigo, texto). Sin red.

    Incluye la region, que debe estar en `REGIONES_PERMITIDAS` (Fase 23).

    Es la parte determinista de `orquestador.chequeos_previos`, que la usa
    antes del modelo, y la repite `aprobar.revalidar` (y con ella el
    aplicador) sobre el formulario guardado (S8). La verificacion de
    identidad no esta aqui: necesita IAM, y el aplicador ya la repite a su
    manera (`principal_id` y techo). El codigo es lo que lee
    `motivos.motivo_publico`; el texto queda en el registro.
    """
    motivos: list[tuple[str, str]] = []
    servicio = campos.servicio.lower()

    if servicio not in SERVICIOS_PERMITIDOS:
        motivos.append((
            "servicio_no_admitido",
            f"El servicio '{campos.servicio}' no esta en la lista de "
            f"servicios permitidos por este sistema",
        ))
    elif servicio in SOLO_LECTURA and campos.tipo_acceso not in (None, "lectura"):
        # ADR-002, opcion B: el techo solo deja leer este servicio, asi que
        # cualquier otra cosa acabaria en un AccessDenied tras el modelo y
        # una aprobacion. Se corta aqui, con el motivo en el registro. Sin
        # tipo de acceso (Fase 28) lo corta despues el patron de SOLO_LECTURA.
        motivos.append((
            "solo_lectura",
            f"El servicio '{campos.servicio}' solo se concede para lectura "
            f"(inventario); se pidio '{campos.tipo_acceso}'",
        ))

    # Fase 23: la region es una lista cerrada (la SCP de la cuenta solo deja
    # us-east-1); otra region se corta aqui y no tras el modelo.
    if campos.region not in REGIONES_PERMITIDAS:
        motivos.append((
            "region_no_admitida",
            f"La region '{campos.region}' no esta entre las regiones "
            "permitidas por este sistema",
        ))

    # ADR-002, D3: los recursos del propio agente no se conceden a nadie.
    # Mismo criterio que los chequeos posteriores, sobre el nombre pedido
    # (que puede traer `/`, como un grupo de logs `/aws/lambda/agente-iam-x`).
    if del_sistema(campos.recurso):
        motivos.append((
            "recurso_del_sistema",
            f"El recurso '{campos.recurso}' es del propio sistema; ningun "
            "beneficiario puede recibir permisos sobre el",
        ))

    if campos.recurso.lower() in PALABRAS_DEL_ARN.get(servicio, frozenset()):
        motivos.append((
            "palabra_del_arn",
            f"El recurso '{campos.recurso}' es una palabra del formato de ARN de "
            f"'{servicio}' (un tipo de recurso, no un nombre): con el, "
            "'table/*' o 'function:*' parecerian el recurso pedido",
        ))
    return motivos


def motivos_de_la_cuenta_del_arn(campos: CamposEstructurados, cuenta: str) -> list[tuple[str, str]]:
    """Si el recurso se escribio como ARN de otra cuenta, el motivo de rechazo (Fase 28).

    `models.CamposEstructurados` ya comprobo servicio y region; la cuenta solo
    se conoce en los chequeos previos. S3 no lleva cuenta en el ARN: lo
    resuelve la comprobacion de existencia, que solo ve los buckets propios.
    """
    if not campos.recurso_arn:
        return []
    _, _, cuenta_del_arn = nombre_desde_arn(campos.servicio.lower(), campos.recurso_arn)
    if cuenta_del_arn and cuenta_del_arn != cuenta:
        return [("arn_no_coincide", f"El ARN del recurso es de la cuenta '{cuenta_del_arn}', no de esta cuenta")]
    return []


def del_sistema(recurso: str) -> str | None:
    """El componente de `recurso` que pertenece al propio agente, o None.

    Se parte el ARN por `:` y `/` y se mira cada trozo en minusculas: asi
    caen el bucket del paquete, sus objetos, la tabla y sus streams, y los
    grupos de logs `/aws/lambda/agente-iam-*` o `.../runtimes/agente_iam*`.
    """
    for parte in re.split(r"[:/]", recurso):
        if parte.lower().startswith(PREFIJOS_DEL_SISTEMA):
            return parte
    return None


# Fase 28: el nivel que declara el modelo, en los terminos de la barrera de
# `catalogo.excede_tipo_acceso` ("escritura" y "administracion" son alli lo
# mismo: solo excluyen la gestion de permisos).
_TIPO_POR_NIVEL = {"lectura": "lectura", "modificacion": "escritura"}
_PREFIJOS_DE_BORRADO = ("delete", "remove", "purge", "terminate")


def nivel_real(documento: dict) -> str | None:
    """Lo que concede de verdad un documento de politica: "lectura", "modifica" o "borra".

    Lo calcula el codigo con el catalogo oficial (Fase 28), no el modelo: es lo
    que ven la persona, el aprobador y el correo, y lo que sube el riesgo
    minimo. Solo mira los Allow. "borra" si alguna accion cubierta empieza por
    Delete, Remove, Purge o Terminate. None si no se pudo determinar ninguna
    accion (catalogo sin cargar): no se adivina.
    """
    niveles: set[str] = set()
    borra = False
    dudas = False
    for st in documento.get("Statement") or []:
        if st.get("Effect") != "Allow":
            continue
        acciones = st.get("Action") or []
        for accion in [acciones] if isinstance(acciones, str) else acciones:
            if any(n.startswith(_PREFIJOS_DE_BORRADO) for n in acciones_en_memoria(accion)):
                borra = True
            nivel = nivel_en_memoria(accion)
            if nivel is None:
                dudas = True
            else:
                niveles.add(nivel)
    if borra:
        return "borra"
    if "escritura" in niveles:
        return "modifica"
    if dudas or not niveles:
        return None
    return "lectura"


def chequeos_posteriores(
    propuesta: PropuestaPolitica, sol: SolicitudEstructurada, identidad: dict
) -> tuple[list[str], list[dict]]:
    """Devuelve (bloqueos, advertencias).

    Los bloqueos entran al loop de reparacion como cualquier otro; las
    advertencias (nivel indeterminable) quedan en `menores` para el
    aprobador: una duda del catalogo no debe ser falso positivo, pero
    tampoco pasar en silencio.
    """
    bloqueos: list[str] = []
    advertencias: list[dict] = []

    if propuesta.principal_arn != identidad["principal_arn"]:
        bloqueos.append(
            f"La propuesta apunta a '{propuesta.principal_arn}', pero la "
            f"solicitud verificada es para '{identidad['principal_arn']}'. "
            "El destinatario no se negocia: usa exactamente ese ARN."
        )

    servicio_pedido = sol.campos.servicio.lower()
    # Fase 28: sin tipo de acceso en el formulario, la barrera de nivel se
    # aplica contra el que declara el modelo (`nivel_entendido`). Atrapa al
    # modelo que dice "lectura" y propone una escritura. Los registros
    # anteriores traen `tipo_acceso` y se revalidan con el.
    tipo = sol.campos.tipo_acceso or _TIPO_POR_NIVEL.get(propuesta.nivel_entendido or "")
    if tipo is None:
        bloqueos.append(
            "Falta 'nivel_entendido': declara 'lectura' si la solicitud solo pide ver, "
            "listar o descargar, o 'modificacion' si pide subir, cambiar o borrar."
        )

    for i, st in enumerate(propuesta.policy_document.Statement):
        if st.Effect != "Allow":
            continue  # un Deny extra restringe; no concede nada
        for accion in st.Action:
            srv = accion.split(":", 1)[0].lower()
            if srv != servicio_pedido:
                bloqueos.append(
                    f"Statement {i}: la accion '{accion}' es del servicio "
                    f"'{srv}', pero la solicitud es de '{servicio_pedido}'. "
                    "Solo puedes conceder acciones del servicio solicitado."
                )
                continue
            patron = SOLO_LECTURA.get(srv)
            if patron and not fnmatchcase(accion.split(":", 1)[1].lower(), patron.lower()):
                bloqueos.append(
                    f"Statement {i}: la accion '{accion}' no es '{srv}:{patron}'. "
                    f"En '{srv}' este sistema solo concede inventario: usa "
                    f"acciones '{patron}' concretas, una a una."
                )
                continue
            if tipo is None:
                continue
            excede = excede_tipo_acceso(accion, tipo)
            if excede:
                bloqueos.append(
                    f"Statement {i}: la accion '{accion}' excede el "
                    f"nivel '{tipo}' segun el catalogo oficial de AWS. "
                    "Ningun tipo de acceso permite gestion de permisos "
                    "(politicas de recurso, ACL): concederla dejaria al "
                    "beneficiario repartir acceso fuera de este sistema."
                )
            elif excede is None:
                advertencias.append(
                    {
                        "tipo": "WARNING",
                        "codigo": "NIVEL_DE_ACCESO_DESCONOCIDO",
                        "detalle": f"No se pudo determinar el nivel de "
                        f"acceso de '{accion}' con el catalogo; el aprobador "
                        "debe revisarla a mano.",
                    }
                )
        if servicio_pedido == "s3" and not lleva_la_cuenta_del_recurso(
            st.Condition, identidad.get("cuenta", "")
        ):
            # S5 (24-10-2026): el ARN de S3 no lleva cuenta, asi que ni el
            # chequeo 4 ni el techo sabian de quien es el bucket. Sin esto,
            # `s3:PutObject` en un bucket de otra cuenta copiaba fuera lo
            # que el beneficiario ya podia leer.
            bloqueos.append(
                f"Statement {i}: en s3 toda concesion lleva la condicion de "
                "cuenta del recurso, porque el ARN de un bucket no dice de quien "
                "es. Anade al statement \"Condition\": {\"StringEquals\": "
                f"{{\"aws:ResourceAccount\": \"{valor_esperado_de_la_cuenta(identidad.get('cuenta', ''))}\"}}}}."
            )
        for recurso in st.Resource:
            propio = del_sistema(recurso)
            if propio:
                bloqueos.append(
                    f"Statement {i}: '{recurso}' es un recurso del propio "
                    f"sistema ('{propio}'). Ningun beneficiario puede recibir "
                    "permisos sobre el."
                )
                continue
            motivo = fuera_del_recurso(
                recurso,
                servicio_pedido,
                sol.campos.recurso,
                sol.campos.region,
                identidad.get("cuenta", ""),
            )
            if motivo:
                bloqueos.append(
                    f"Statement {i}: {motivo}. Concede solo sobre el recurso "
                    "de la solicitud."
                )

    return bloqueos, advertencias


# --- Riesgo minimo, fijado por el codigo (22-10-2026) -------------------------
#
# `nivel_riesgo` lo escribe el modelo, y en la comparacion del 22-10-2026
# cada modelo fallaba en un caso distinto: Sonnet 4.6 marcaba `medio` cuando
# la justificacion pedia cambiar el destinatario (4 de 5), Haiku 4.5 marcaba
# `bajo` o `medio` una lambda en nivel de administracion (3 de 5). El riesgo
# solo anade friccion (una confirmacion al aprobar), pero que dependa del
# modelo lo hacia impredecible. Estas reglas lo fijan desde abajo: el modelo
# puede subirlo, nunca bajarlo de aqui. Solo miran lo que el codigo sabe con
# certeza: el formulario, la identidad verificada y lo que el modelo propuso
# en cada intento.

_ARN_DE_PRINCIPAL_EN_TEXTO = re.compile(r"arn:aws[a-z-]*:(?:iam|sts)::\d{12}:[^\s\"',;)]+")
_ACCION_DE_ESCALADA_EN_TEXTO = re.compile(r"\b(iam|sts|organizations):[A-Za-z*]", re.IGNORECASE)
_POLITICAS_AMPLIAS = re.compile(r"administratoraccess|poweruseraccess|iamfullaccess", re.IGNORECASE)
_PREFIJOS_DE_ESCALADA = ("iam:", "sts:", "organizations:")


def riesgo_minimo(
    solicitud: dict, principal_arn: str, historial: list[dict], nivel_real: str | None = None
) -> list[str]:
    """Motivos por los que la solicitud es de riesgo alto, sea cual sea la
    opinion del modelo. Lista vacia: el codigo no fija minimo.

    Recibe dicts y no modelos para que `aprobar` la recalcule desde el
    registro leido: el registro entero esta bajo la huella, asi que nadie
    puede rebajar el riesgo editando un campo guardado.
    """
    motivos: list[str] = []
    campos = solicitud.get("campos") or {}
    texto = solicitud.get("justificacion") or ""

    if campos.get("tipo_acceso") == "administracion":
        motivos.append("se pide nivel de administracion")

    # Fase 28: lo que concede la propuesta, calculado por el codigo
    # (`nivel_real`, guardado en el registro bajo la huella). Modificar o
    # borrar datos exige que el aprobador confirme el riesgo.
    if nivel_real == "borra":
        motivos.append("la propuesta puede borrar datos")
    elif nivel_real == "modifica":
        motivos.append("la propuesta modifica datos")

    # Solo ARN de principales: el del bucket o la tabla en la justificacion
    # es normal y no debe subir el riesgo.
    encontrados = {a.rstrip(".:") for a in _ARN_DE_PRINCIPAL_EN_TEXTO.findall(texto)}
    otros = sorted(encontrados - {principal_arn})
    if otros:
        motivos.append(f"la justificacion nombra otro principal: {', '.join(otros)}")

    if _ACCION_DE_ESCALADA_EN_TEXTO.search(texto) or _POLITICAS_AMPLIAS.search(texto):
        motivos.append("la justificacion pide acciones de IAM, STS u Organizations o una politica amplia")

    prohibidas = {a.lower() for a in ACCIONES_PROHIBIDAS}
    for paso in historial:
        acciones: list[str] = []
        for s in (paso.get("documento") or {}).get("Statement", []):
            a = s.get("Action", [])
            acciones.extend([a] if isinstance(a, str) else a)
        malas = sorted({a for a in acciones if a.lower() in prohibidas or a.lower().startswith(_PREFIJOS_DE_ESCALADA)})
        if malas:
            motivos.append(f"el modelo propuso {', '.join(malas)} en el intento {paso.get('intento')}")
    return motivos
