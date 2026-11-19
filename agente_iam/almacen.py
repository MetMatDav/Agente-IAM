"""Donde vive el registro de una solicitud.

Existe por el despliegue: el sistema de ficheros de AgentCore Runtime es
efimero (un microVM por sesion, que se destruye al terminar), asi que
`solicitudes/*.json` dejaria de existir en cuanto la corrida acabase. Y el
registro NO es un subproducto: es el producto auditable de todo el sistema.

Ademas, la aprobacion la escribe la Lambda `agente-iam-aprobacion` (ADR-003)
y aplicar sigue en la maquina del humano (hasta la Lambda del aplicador). Si
el agente escribiera en la nube y el aprobador leyera del disco, el circuito
estaria partido en dos y nadie lo notaria hasta buscar una solicitud que no
esta. Por eso el intake, la aprobacion y el aplicador pasan por aqui.

DOS OPERACIONES DE ESCRITURA, NO UNA. No es una comodidad: son dos
preguntas distintas, y confundirlas es como abrir un hueco.

  - `guardar_propuesta` la usa el intake. Solo escribe si el registro NO
    existe (24-10-2026, S6). Hasta esa fecha se negaba solo a pisar una
    decision humana, y pisaba todo lo demas: un intento de inyeccion que
    quedo en `requiere_revision_humana` se borraba reenviando una solicitud
    limpia con el mismo `solicitud_id`, que elige quien pide. Volver a
    correr el intake con el mismo id ya no es un cambio de estado: es otra
    solicitud, y necesita otro id.
  - `guardar_decision` la usan `aprobar` y `aplicador`, que precisamente
    vienen a anadir esa decision. Exigen a cambio que el estado en el
    almacen siga siendo el que leyeron.

EL ESTADO ESPERADO CIERRA UN TOCTOU QUE YA EXISTIA. Hoy `aprobar` lee el
archivo, comprueba el estado en memoria y escribe. Entre la lectura y la
escritura cabe otra corrida. En disco eso no se puede cerrar del todo y se
dice; en DynamoDB una escritura condicional lo cierra de verdad, porque la
comprobacion y la escritura son la misma operacion atomica. Misma
intencion en los dos backends, garantia distinta — y la diferencia se
declara en vez de disimularse.

CADA ACTOR ESCRIBE SOLO SUS ATRIBUTOS (bloque 3, 24-10-2026). Hasta esta
fecha la fila era un unico JSON (`documento`) y toda escritura un PutItem,
que reemplaza la fila entera: IAM no podia distinguir "aprobar" de
"reescribir la propuesta", porque `dynamodb:Attributes` no limita PutItem
(guia de DynamoDB; Access Analyzer lo marca como
DYNAMODB_REPLACE_OPERATION_WITH_ATTRIBUTES). Ahora la fila tiene un
atributo por actor y nadie usa PutItem:

    id          la clave
    documento   el intake (runtime): solicitud, identidad, propuesta...
    estado      los tres; es la fuente de verdad del estado actual
    aprobacion  el aprobador
    rechazo     el aprobador
    aplicacion  el aplicador

Todas las escrituras son UpdateItem de `documento` o de un bloque, mas
`estado`. Asi cada rol puede llevar `dynamodb:Attributes` con solo los
suyos, e IAM garantiza que el aprobador no toca la propuesta. La otra
mitad que se afirmaba aqui, "el runtime no toca decisiones", era FALSA
hasta el 24-10-2026 (S1): la lectura recomponia el registro desde
`documento` y solo sobrescribia un bloque si su atributo existia, asi que
un `documento` con su propia clave `aprobacion` llegaba al aplicador como
si la hubiera escrito el aprobador. Ahora `_dynamo_leer` rechaza un
`documento` que traiga `estado` o un bloque, o un `id` que no es la clave,
y los bloques solo salen de sus atributos. Lo que sigue sin cerrar: la
huella no tiene secreto, asi que quien escriba el atributo `aprobacion`
(el permission set del aprobador) fabrica una aprobacion valida. Decidido
el 24-10-2026 que la escriba solo una Lambda de aprobacion (ADR-003, A2),
sin implementar. Las condiciones nombran solo atributos que ese actor ya
escribe (la del intake mira `id`, no los bloques): `dynamodb:Attributes`
cuenta tambien los de la condicion (medido el 24-10-2026 con llamadas
reales, MEDICIONES F.6), asi que nombrar uno ajeno seria un AccessDenied.

`estado` lo comparten los tres. Ponerlo a cualquier valor no consigue
aplicar nada en una fila sin aprobacion real: el aplicador exige el bloque
`aprobacion` con su huella. En una fila ya decidida (con `aplicacion` o
`rechazo`) el aplicador se niega y el evento va a la cola de fallos.
Lo que IAM no puede exigir es "solo si el bloque no existe": eso lo pone
la condicion de cada escritura.

POR QUE CADA ATRIBUTO ES UNA CADENA JSON Y NO UN MAPA. DynamoDB no tiene
tipo float: boto3 devuelve `Decimal` para todo numero. Un `"intentos": 1`
volveria como `Decimal('1')`, y `huella.calcular` hace `json.dumps` sobre
eso — o revienta, o serializa distinto. La huella dejaria de cuadrar por
el viaje de ida y vuelta, no por manipulacion: el peor fallo posible,
porque parece manipulacion. Guardando cada parte como una cadena, el
round-trip es exacto byte a byte.
"""

import json
import os
from pathlib import Path

from agente_iam.config import ALMACEN, AWS_REGION, DIR_SOLICITUDES, TABLA_SOLICITUDES

# Limite de un item de DynamoDB. Se comprueba antes de escribir para que el
# fallo diga que pasa, en vez de llegar como un ValidationException opaco
# justo cuando se acaba de gastar una corrida entera del modelo.
_LIMITE_ITEM = 400 * 1024

# Los bloques de decision: cada uno es un atributo propio de la fila y solo
# lo escribe su actor. Lo que no es bloque ni `estado` va en `documento`.
BLOQUES = ("aprobacion", "rechazo", "aplicacion")

# La condicion del intake (24-10-2026, S6). Hasta esa fecha era "no esta en
# un estado decidido" (`ESTADOS_DECIDIDOS`, que ya no existe), y pisaba los
# demas. `id` es la clave: siempre existe en una fila que existe.
_CONDICION_INTAKE = "attribute_not_exists(id)"

# La condicion de cada decision. Solo nombra atributos que ese actor escribe.
_CONDICION = {
    "aprobacion": "estado = :esperado AND attribute_not_exists(aprobacion) AND attribute_not_exists(rechazo)",
    "rechazo": "estado = :esperado AND attribute_not_exists(aprobacion) AND attribute_not_exists(rechazo)",
    "aplicacion": "estado = :esperado AND attribute_not_exists(aplicacion)",
}


class RegistroExistente(Exception):
    """El intake intento escribir un registro que ya existe, en el estado que sea.

    Hasta el 24-10-2026 se llamaba `RegistroYaAprobado`, y solo se lanzaba
    sobre una decision humana; ahora cubre cualquier registro previo, y el
    nombre viejo mentiria (S6).
    """


class RegistroInconsistente(Exception):
    """El registro leido no tiene la forma que su almacen garantiza (S1).

    No es un fallo de red ni un registro ausente: es una fila cuyo
    `documento` trae lo que no le corresponde (el estado, una decision, otro
    id). No se repara ni se avisa: se para, porque esa fila es justo la que
    alguien escribio para que el aplicador la diera por aprobada.
    """


class EstadoCambiado(Exception):
    """El registro cambio en el almacen entre que se leyo y se fue a escribir."""


# --- Backend de disco --------------------------------------------------------


def _ruta(solicitud_id: str) -> Path:
    # El alfabeto de `solicitud_id` esta cerrado en `models._PATRON_ID` (sin
    # "/" ni ".."), asi que aqui no hace falta defenderse del path traversal:
    # ya se rechazo en el contrato de entrada.
    return Path(DIR_SOLICITUDES) / f"{solicitud_id}.json"


def _disco_leer(solicitud_id: str) -> dict | None:
    ruta = _ruta(solicitud_id)
    if not ruta.exists():
        return None
    registro = json.loads(ruta.read_text())
    # En disco el fichero lo lleva todo (estado y bloques incluidos), asi
    # que de S1 solo aplica una parte: el registro tiene que ser el de su
    # nombre de fichero. Si no, una decision tomada sobre `req-x` se
    # escribiria en otro.
    if not isinstance(registro, dict) or registro.get("id") != solicitud_id:
        raise RegistroInconsistente(
            f"'{ruta}' no es el registro '{solicitud_id}' (su id es "
            f"'{registro.get('id') if isinstance(registro, dict) else None}'). No se usa."
        )
    return registro


def _disco_escribir(registro: dict, solicitud_id: str) -> str:
    ruta = _ruta(solicitud_id)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(json.dumps(registro, indent=2, ensure_ascii=False))
    return str(ruta)


def _disco_crear(registro: dict) -> str:
    """Escribe un registro NUEVO. Si el fichero ya existe, no lo toca (S6).

    El modo "x" de `open` crea el fichero solo si no existe, y lo comprueba
    y lo crea en la misma llamada al sistema: aqui no queda la ventana que
    si queda en `guardar_decision`. Un fichero ilegible tambien cuenta como
    existente: es evidencia, y no se sabe que decia.
    """
    ruta = _ruta(registro["id"])
    ruta.parent.mkdir(parents=True, exist_ok=True)
    try:
        with ruta.open("x", encoding="utf-8") as f:
            f.write(json.dumps(registro, indent=2, ensure_ascii=False))
    except FileExistsError as e:
        raise RegistroExistente(
            f"'{ruta}' ya existe. El intake no escribe encima de un registro "
            "anterior, este en el estado que este: usa otro solicitud_id."
        ) from e
    return str(ruta)


# --- Backend de DynamoDB -----------------------------------------------------

_tabla = None


def _dynamo():
    global _tabla
    if _tabla is None:
        import boto3

        _tabla = boto3.resource("dynamodb", region_name=AWS_REGION).Table(
            TABLA_SOLICITUDES
        )
    return _tabla


def _documento(registro: dict) -> str:
    """Lo que escribe el intake: el registro menos el estado y los bloques."""
    return json.dumps(
        {k: v for k, v in registro.items() if k != "estado" and k not in BLOQUES},
        ensure_ascii=False,
    )


def _comprobar_tamano(registro: dict) -> None:
    """La fila entera (documento y bloques) cabe en un item de DynamoDB."""
    partes = [_documento(registro)] + [
        json.dumps(registro[b], ensure_ascii=False) for b in BLOQUES if b in registro
    ]
    total = sum(len(p.encode("utf-8")) for p in partes)
    if total > _LIMITE_ITEM:
        raise ValueError(
            f"El registro '{registro['id']}' ocupa {total} bytes y el limite "
            f"de un item de DynamoDB es {_LIMITE_ITEM}. No se guarda "
            "truncado: un registro de auditoria incompleto es peor que ninguno."
        )


def _dynamo_leer(solicitud_id: str) -> dict | None:
    respuesta = _dynamo().get_item(
        Key={"id": solicitud_id},
        # Lectura fuertemente consistente: la eventual podria devolver el
        # registro de ANTES de una aprobacion que acaba de escribirse, y el
        # aplicador lo leeria como todavia no aprobado. En un flujo de
        # permisos, leer el pasado y actuar sobre el no es aceptable.
        ConsistentRead=True,
    ).get("Item")
    if not respuesta:
        return None
    # Un UpdateItem sobre un id que no existe crea la fila, asi que una fila
    # puede no tener `documento` o `estado` (Fase 18). Hasta el 24-10-2026
    # eso era un KeyError: paraba igual, pero sin decir por que.
    faltan = [a for a in ("documento", "estado") if a not in respuesta]
    if faltan:
        raise RegistroInconsistente(
            f"'{solicitud_id}': la fila no tiene {', '.join(faltan)}. No salio del intake; no se usa."
        )
    # Se recompone el registro como lo ve el resto del sistema: el documento,
    # el estado actual y los bloques que haya. Cada parte sale SOLO de su
    # atributo (S1, 24-10-2026): el `documento` lo escribe el runtime, la
    # pieza que procesa texto no confiable, y si pudiera traer su propia
    # `aprobacion` el runtime aprobaria sin humano. Por eso no se le quita
    # la clave sobrante en silencio: una fila asi no sale del flujo normal
    # (`_documento` nunca las escribe) y se para.
    registro = json.loads(respuesta["documento"])
    if not isinstance(registro, dict):
        raise RegistroInconsistente(f"'{solicitud_id}': el documento no es un objeto JSON.")
    intrusas = [k for k in ("estado", *BLOQUES) if k in registro]
    if intrusas:
        raise RegistroInconsistente(
            f"'{solicitud_id}': el documento trae {', '.join(intrusas)}, que solo "
            "pueden salir de sus propios atributos. Alguien escribio la fila a mano; "
            "no se usa."
        )
    if registro.get("id") != solicitud_id or respuesta.get("id") != solicitud_id:
        raise RegistroInconsistente(
            f"'{solicitud_id}': el documento dice ser '{registro.get('id')}'. "
            "Una decision sobre esta fila acabaria escrita en otra; no se usa."
        )
    registro["estado"] = respuesta["estado"]
    for bloque in BLOQUES:
        if bloque in respuesta:
            registro[bloque] = json.loads(respuesta[bloque])
    return registro


def _dynamo_actualizar(solicitud_id: str, valores: dict, condicion: str, extra: dict) -> str:
    """UpdateItem de exactamente `valores` (nombre -> valor). Nunca PutItem.

    El `ConditionalCheckFailedException` sube tal cual: quien llama es el
    que sabe que significa incumplir SU condicion. No se pide ReturnValues:
    el aprobador solo puede pedir NONE o UPDATED_* (su permission set).
    """
    expresion = "SET " + ", ".join(f"{k} = :{k}" for k in valores)
    _dynamo().update_item(
        Key={"id": solicitud_id},
        UpdateExpression=expresion,
        ConditionExpression=condicion,
        ExpressionAttributeValues={**{f":{k}": v for k, v in valores.items()}, **extra},
    )
    return f"dynamodb://{TABLA_SOLICITUDES}/{solicitud_id}"


# --- La interfaz que usa el resto del sistema --------------------------------


def leer(solicitud_id: str) -> dict | None:
    """El registro, o None si no existe. Una sola lectura, como siempre."""
    if ALMACEN == "dynamodb":
        return _dynamo_leer(solicitud_id)
    return _disco_leer(solicitud_id)


def guardar_propuesta(registro: dict) -> str:
    """Escribe el resultado del intake, solo si el registro no existe (S6).

    Devuelve una referencia legible de donde quedo (ruta o URI), que es lo
    que el CLI imprime al final. Si ya existe, lanza `RegistroExistente`:
    el intake no pisa nada, ni una decision humana ni el rastro de una
    corrida anterior (su historial y su `riesgo_minimo` incluidos).
    """
    con_bloque = [b for b in BLOQUES if b in registro]
    if con_bloque:
        # El intake no decide. Un registro suyo con un bloque es un error de
        # quien llama, y en DynamoDB el bloque ni siquiera se escribiria.
        raise ValueError(
            f"'{registro['id']}': el intake no escribe decisiones y el "
            f"registro trae {', '.join(con_bloque)}."
        )
    _comprobar_tamano(registro)

    if ALMACEN == "dynamodb":
        from botocore.exceptions import ClientError

        try:
            # "Solo si no existe". La comprobacion y la escritura son la
            # MISMA operacion, asi que no hay ventana entre una y otra.
            return _dynamo_actualizar(
                registro["id"],
                {"documento": _documento(registro), "estado": registro.get("estado", "")},
                _CONDICION_INTAKE,
                {},
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            raise RegistroExistente(
                f"'{registro['id']}' ya existe en la tabla. El intake no escribe "
                "encima de un registro anterior: usa otro solicitud_id."
            ) from e

    return _disco_crear(registro)


def guardar_decision(registro: dict, bloque: str, estado_esperado: str, *, clave: str) -> str:
    """Escribe UNA decision (aprobacion, rechazo o aplicacion) y el estado.

    Del registro en memoria solo viajan `registro[bloque]` y
    `registro["estado"]`: el resto (la propuesta) no se escribe aunque haya
    cambiado en memoria. `estado_esperado` es el estado que el comando LEYO
    antes de decidir. Si el almacen ya no esta en ese estado, o el bloque
    ya existe, otro proceso decidio primero y esta escritura llegaria
    pisandolo.

    `clave` es el id con el que el comando LEYO la fila (S1, 24-10-2026), y
    es la clave de la escritura. Antes la clave salia de `registro["id"]`,
    que viene del `documento` que escribe el runtime: con un `id` distinto
    de la clave, `aprobar req-x` escribia su decision en OTRA fila. Si el
    registro en memoria no es el de esa clave, no se escribe nada.
    """
    if bloque not in BLOQUES:
        raise ValueError(f"'{bloque}' no es un bloque de decision ({', '.join(BLOQUES)})")
    if registro.get("id") != clave:
        raise RegistroInconsistente(
            f"Se leyo '{clave}' y el registro en memoria dice ser '{registro.get('id')}'. "
            "La decision no se escribe en ninguna de las dos."
        )
    _comprobar_tamano(registro)

    if ALMACEN == "dynamodb":
        from botocore.exceptions import ClientError

        try:
            return _dynamo_actualizar(
                clave,
                {bloque: json.dumps(registro[bloque], ensure_ascii=False), "estado": registro["estado"]},
                _CONDICION[bloque],
                {":esperado": estado_esperado},
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            raise EstadoCambiado(
                f"'{clave}' ya no esta en estado '{estado_esperado}' "
                f"o ya tiene '{bloque}': otra corrida decidio sobre esta "
                "solicitud mientras esta estaba en curso. No se escribe encima."
            ) from e

    # En disco la comprobacion y la escritura son dos operaciones, asi que
    # esto estrecha la ventana pero no la cierra. Se dice aqui en vez de
    # dejar creer que el backend de desarrollo da la misma garantia que el
    # de produccion. Las mismas condiciones, y tambien aqui solo viajan el
    # bloque y el estado: se escriben sobre lo que hay en disco.
    actual = _disco_leer_tolerante(clave)
    if not actual:
        raise EstadoCambiado(f"'{clave}' no existe en el almacen: no hay sobre que decidir.")
    if actual.get("estado") != estado_esperado:
        raise EstadoCambiado(
            f"'{clave}' esta en estado '{actual.get('estado')}' y se leyo "
            f"como '{estado_esperado}'. Otra corrida decidio en medio."
        )
    excluyentes = ("aprobacion", "rechazo") if bloque != "aplicacion" else ("aplicacion",)
    ya = [b for b in excluyentes if actual.get(b)]
    if ya:
        raise EstadoCambiado(f"'{clave}' ya tiene '{ya[0]}'. No se escribe encima.")
    actual[bloque] = registro[bloque]
    actual["estado"] = registro["estado"]
    return _disco_escribir(actual, clave)


def _disco_leer_tolerante(solicitud_id: str) -> dict:
    """Como `_disco_leer`, pero un archivo ilegible cuenta como vacio.

    Solo la usa `guardar_decision`: sobre un archivo que no se puede leer
    no se decide, y "vacio" lleva a `EstadoCambiado`. Hasta el 24-10-2026
    la usaba tambien el intake para escribir encima de un JSON corrupto;
    ya no (S6): un fichero ilegible es evidencia que no se sabe que decia.
    Un registro con otro id no se tolera: `RegistroInconsistente` sube.
    """
    try:
        return _disco_leer(solicitud_id) or {}
    except (json.JSONDecodeError, OSError):
        return {}


def describir() -> str:
    """De donde lee y escribe este proceso. Va en la salida de los comandos.

    Un sistema con dos backends donde no se ve cual esta activo invita al
    error de mirar el disco mientras el agente escribe en la nube.
    """
    if ALMACEN == "dynamodb":
        return f"DynamoDB tabla '{TABLA_SOLICITUDES}' ({AWS_REGION})"
    return f"disco, carpeta '{os.path.abspath(DIR_SOLICITUDES)}'"
