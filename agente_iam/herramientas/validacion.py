"""Validacion de politicas IAM: la capa que NO confia en el modelo.

Dos niveles, ambos deterministas:

1. IAM Access Analyzer (ValidatePolicy): revisa gramatica, errores y malas
   practicas de seguridad. Es un servicio de AWS, no un LLM, y no tiene costo.
2. Lista negra local: acciones que este sistema jamas debe conceder, evaluadas
   en codigo. Aqui vive la ultima palabra.
"""

import json
from fnmatch import fnmatch

import boto3
from strands import tool

from agente_iam.config import (
    ACCIONES_PROHIBIDAS,
    AWS_REGION,
    BLOQUEAR_ACCION_WILDCARD,
    BLOQUEAR_ARN_COMODIN,
    ESCRITURAS_SIN_RECURSO_PERMITIDAS,
)
from agente_iam.herramientas.catalogo import es_escritura, todas_exigen_wildcard

_cliente = None


def _analyzer():
    """Cliente boto3 perezoso, para no abrir sesion al importar el modulo."""
    global _cliente
    if _cliente is None:
        _cliente = boto3.client("accessanalyzer", region_name=AWS_REGION)
    return _cliente


def _concede(accion: str, prohibida: str) -> bool:
    """True si la accion propuesta CUBRE una accion prohibida.

    La direccion importa. Lo que evaluamos es que permisos concede realmente
    la accion propuesta: 'iam:*' concede 'iam:CreateUser', asi que se bloquea.
    's3:GetObject' no concede ninguna prohibida, asi que pasa. Comparar al
    reves bloquearia todo en cuanto la lista tuviera un comodin.
    """
    return fnmatch(prohibida.lower(), accion.lower())


def _es_comodin_amplio(accion: str) -> bool:
    """'*' o 'servicio:*' son comodines de servicio completo."""
    a = accion.strip()
    return a == "*" or a.endswith(":*")


def _arn_demasiado_amplio(recurso: str) -> str | None:
    """Detecta comodines peligrosos dentro de un ARN.

    'arn:aws:dynamodb:*:123:table/x' concede la tabla en todas las regiones.
    El comodin de ruta final ('bucket/*') es legitimo y no se toca.
    """
    if recurso == "*":
        return "recurso '*' sin limite"
    partes = recurso.split(":", 5)
    if len(partes) < 6 or partes[0] != "arn":
        return None
    _, _, servicio, region, cuenta, _resto = partes
    if region == "*":
        return f"region comodin en '{recurso}' (aplica a todas las regiones)"
    if cuenta == "*":
        return f"cuenta comodin en '{recurso}'"
    # Revision 2026-10: el comodin COMO recurso ('arn:aws:s3:::*',
    # 'arn:aws:sqs:...:*') concede el servicio entero en la cuenta, igual que
    # Resource "*". La coherencia con el formulario (`coherencia`) cubre
    # ademas 'table/*' y similares, que esta regla generica no distingue de
    # un 'bucket/*' legitimo.
    if _resto.startswith(("*", "?")):
        return f"el recurso de '{recurso}' es un comodin (todo el servicio en la cuenta)"
    return None


def _revisar_lista_negra(documento: dict) -> list[str]:
    """Devuelve los motivos de bloqueo encontrados en el documento."""
    bloqueos: list[str] = []
    statements = documento.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for i, st in enumerate(statements):
        if st.get("Effect") != "Allow":
            continue  # un Deny nunca concede permisos

        acciones = st.get("Action", [])
        if isinstance(acciones, str):
            acciones = [acciones]
        recursos = st.get("Resource", [])
        if isinstance(recursos, str):
            recursos = [recursos]

        for accion in acciones:
            if BLOQUEAR_ACCION_WILDCARD and _es_comodin_amplio(accion):
                bloqueos.append(
                    f"Statement {i}: la accion '{accion}' es un comodin de "
                    f"servicio completo"
                )
                continue
            for prohibida in ACCIONES_PROHIBIDAS:
                if _concede(accion, prohibida):
                    bloqueos.append(
                        f"Statement {i}: la accion '{accion}' concede "
                        f"'{prohibida}', que esta prohibida"
                    )
                    break

        if BLOQUEAR_ARN_COMODIN:
            # Excepcion legitima: hay acciones que NO admiten ARNs (todas las
            # ec2:Describe*, por ejemplo). Exigirles un recurso concreto
            # produce una politica que no concede nada. Para esas, Resource
            # "*" es la unica forma valida, pero se exige un Condition que
            # acote el alcance. Quien decide no es el modelo ni nosotros:
            # es el catalogo oficial de AWS.
            exige_wildcard = todas_exigen_wildcard(acciones)
            tiene_condition = bool(st.get("Condition"))

            for recurso in recursos:
                motivo = _arn_demasiado_amplio(recurso)
                if not motivo:
                    continue
                if recurso == "*" and exige_wildcard:
                    # Revision del 24-10-2026 (S3): con "*" los chequeos de
                    # recurso y de recursos del sistema no juzgan nada, y
                    # las escrituras sin tipo de recurso son casi todas de
                    # alcance de cuenta (PutAccountPolicy, compras de
                    # capacidad, limites de gasto de SMS). Cualquier
                    # Condition las daba por acotadas. Ahora solo pasan las
                    # de lectura o listado, o las de la lista blanca.
                    escrituras = _escrituras_no_permitidas(acciones)
                    if escrituras:
                        bloqueos.append(
                            f"Statement {i}: {', '.join(escrituras)} no es de "
                            "lectura ni de listado y no admite ARN: actua sobre "
                            "la cuenta entera. Con Resource '*' este sistema solo "
                            "concede acciones de lectura o listado; quitala de la "
                            "propuesta."
                        )
                        continue
                    if tiene_condition:
                        continue
                    bloqueos.append(
                        f"Statement {i}: estas acciones exigen Resource '*' "
                        f"por diseno de AWS, pero falta un bloque Condition "
                        f"que acote el alcance (p.ej. aws:RequestedRegion)"
                    )
                    continue
                bloqueos.append(f"Statement {i}: {motivo}")
    return bloqueos


def _escrituras_no_permitidas(acciones: list[str]) -> list[str]:
    """Las acciones que no son de lectura (o que el catalogo no sabe) y no
    estan en la lista blanca de `config`. Una duda cuenta como escritura."""
    permitidas = {a.lower() for a in ESCRITURAS_SIN_RECURSO_PERMITIDAS}
    return [
        a for a in acciones
        if es_escritura(a) is not False and a.lower() not in permitidas
    ]


@tool
def validar_politica(policy_json: str) -> dict:
    """Valida un documento de politica IAM y devuelve los hallazgos.

    Ejecuta IAM Access Analyzer (ValidatePolicy) sobre el documento y ademas
    una lista negra local de acciones que este sistema nunca debe conceder.
    Usa esta herramienta SIEMPRE antes de entregar una propuesta, y corrige
    la politica si aparecen bloqueos o errores.

    Args:
        policy_json: El documento de politica IAM completo, como string JSON.

    Returns:
        Un dict con 'aprobable' (bool), 'bloqueos' (lista de motivos que
        impiden aprobar), 'criticos' (errores y avisos de seguridad de
        Access Analyzer) y 'menores' (advertencias y sugerencias).
    """
    try:
        documento = json.loads(policy_json)
    except json.JSONDecodeError as e:
        return {
            "aprobable": False,
            "bloqueos": [f"El documento no es JSON valido: {e}"],
            "criticos": [],
            "menores": [],
        }

    bloqueos = _revisar_lista_negra(documento)

    criticos: list[dict] = []
    menores: list[dict] = []
    # Controles que no pudieron EJECUTARSE (distinto de los que dijeron que no).
    # Quien pueda reintentar (el aplicador) lo distingue de un bloqueo real.
    no_ejecutado: list[str] = []
    try:
        respuesta = _analyzer().validate_policy(
            policyDocument=json.dumps(documento),
            policyType="IDENTITY_POLICY",
        )
        for f in respuesta.get("findings", []):
            item = {
                "tipo": f.get("findingType"),
                "codigo": f.get("issueCode"),
                "detalle": f.get("findingDetails"),
            }
            if f.get("findingType") in ("ERROR", "SECURITY_WARNING"):
                criticos.append(item)
            else:
                menores.append(item)
    except Exception as e:  # queremos ver el error, no ocultarlo
        bloqueos.append(f"No se pudo ejecutar Access Analyzer: {e}")
        no_ejecutado.append(str(e))

    resultado: dict = {
        "aprobable": not bloqueos and not criticos,
        "bloqueos": bloqueos,
        "criticos": criticos,
        "menores": menores,
    }
    if no_ejecutado:
        resultado["no_ejecutado"] = no_ejecutado
    return resultado
