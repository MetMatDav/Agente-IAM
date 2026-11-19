"""Sonda de `aws:ResourceAccount` con llamadas reales (Fase 18, tarea 2).

    ./.venv/bin/python scripts/sonda_cuenta.py                         # solo muestra el plan
    AWS_PROFILE=org-agente-iam ./.venv/bin/python scripts/sonda_cuenta.py --ejecutar --capa <ARN>

POR QUE EXISTE (24-10-2026). El techo del repositorio anade el Deny
`SoloRecursosDeLaPropiaCuenta` (S5): niega los ocho servicios con
`StringNotEqualsIfExists aws:ResourceAccount = ${aws:PrincipalAccount}`.
Antes de desplegarlo hay que saber, llamada por llamada, si la clave llega y
que haria ese Deny. Ningun test unitario lo puede decir: es comportamiento de
AWS, y el simulador no sirve para esto: rellena `aws:ResourceAccount` por su
cuenta con la cuenta de quien llama (medido el 24-10-2026, MEDICIONES E.8), asi
que nunca ve una llamada sin la clave. La guia de operadores de condicion de
IAM dice que un Deny con `...IfExists` negado niega tambien cuando la clave
falta: por eso importa saber si llega.

COMO MIDE. La pila temporal `agente-iam-sonda-cuenta`
(`infra/cfn/sonda-cuenta.yaml`) crea un rol de solo lectura y recursos propios
vacios. El script asume ese rol cuatro veces, cada una con una politica de
sesion distinta, y repite cada llamada en las cuatro:

    control  lo que la sonda llama, sin Deny: si falla aqui, la llamada no prueba nada
    techo    + la sentencia S5 del techo, copiada del JSON: lo que se quiere saber
    ausente  + Deny con Null aws:ResourceAccount = true: niega si la clave falta
    propia   + Deny con StringEquals ... = cuenta propia: niega si es la propia

El estado de la clave sale de `ausente` y `propia` (si ninguna niega, llega con
otra cuenta). La columna `techo` no se deduce: se mide. La politica de sesion
recorta lo que el rol permite, y un Deny en ella vale como cualquier otro.

LO QUE NO TOCA. Solo llamadas de lectura, sobre recursos vacios de la pila o
publicos de AWS. No crea nada: la pila la crea y la borra el administrador. Las
cuentas de 12 digitos se enmascaran (quedan los 4 ultimos).

SALIDA. Tabla en consola y `evidencias/sonda-cuenta/<fecha UTC>/resultado.json`
(`evidencias/` esta en .gitignore). Codigo de salida: 0 medida; 3 alguna
llamada inconsistente; 1 error de corrida o sonda rota (la tabla propia no
sale `propia`: la medicion no vale).
"""

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

RAIZ = Path(__file__).resolve().parent.parent
REGION = "us-east-1"
PILA = "agente-iam-sonda-cuenta"
NOMBRE = "agente-iam-sonda"  # tabla, cola, tema y grupo de logs de la pila
SID_S5 = "SoloRecursosDeLaPropiaCuenta"
SESIONES = ("control", "techo", "ausente", "propia")
PROPAGACION_S = 10

# Cada servicio devuelve la denegacion con su propio codigo.
CODIGOS_DENEGACION = ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError")

# Recursos de otras cuentas, publicos. Si no se pueden leer ni con la sesion de
# control, la fila sale `no_concluyente` y no pasa nada.
BUCKET_PUBLICO = "noaa-ghcn-pds"
TEMA_PUBLICO = "arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged"

_CUENTA = re.compile(r"(?<!\d)(\d{8})(\d{4})(?!\d)")


def enmascarar(valor: Any) -> Any:
    """Las cuentas de 12 digitos quedan en sus 4 ultimos, en toda la estructura."""
    if isinstance(valor, str):
        return _CUENTA.sub(lambda m: "*" * 8 + m.group(2), valor)
    if isinstance(valor, dict):
        return {k: enmascarar(v) for k, v in valor.items()}
    if isinstance(valor, list):
        return [enmascarar(v) for v in valor]
    return valor


# --- Politicas de sesion ----------------------------------------------------

def _sentencia_s5() -> dict:
    techo = json.loads((RAIZ / "infra" / "boundary-agente-iam-techo.json").read_text(encoding="utf-8"))
    return next(s for s in techo["Statement"] if s["Sid"] == SID_S5)


_CONDICION_DE_PRUEBA = {
    "ausente": {"Null": {"aws:ResourceAccount": "true"}},
    "propia": {"StringEquals": {"aws:ResourceAccount": "${aws:PrincipalAccount}"}},
}


def politica_de_sesion(nombre: str) -> dict:
    """Lo que la sonda llama y, salvo en `control`, un Deny de prueba sobre los ocho servicios."""
    acciones = sorted({ll.accion_iam for ll in LLAMADAS})
    sentencias: list[dict] = [{"Sid": "LoQueLaSondaLlama", "Effect": "Allow", "Action": acciones, "Resource": "*"}]
    if nombre != "control":
        s5 = _sentencia_s5()
        condicion = s5["Condition"] if nombre == "techo" else _CONDICION_DE_PRUEBA[nombre]
        sentencias.append({"Sid": "Prueba", "Effect": "Deny", "Action": s5["Action"], "Resource": s5["Resource"], "Condition": condicion})
    return {"Version": "2012-10-17", "Statement": sentencias}


# --- Clasificacion ----------------------------------------------------------

def resultado(error: BaseException | None) -> str:
    if error is None:
        return "ok"
    if isinstance(error, ClientError):
        codigo = error.response.get("Error", {}).get("Code", "")
        return "denegado" if codigo in CODIGOS_DENEGACION else f"error:{codigo}"
    return f"error:{type(error).__name__}"


def clasificar(resultados: dict[str, str]) -> dict:
    """De los cuatro resultados de una llamada, el estado de la clave y lo que hace el techo."""
    if resultados["control"] != "ok" or any(resultados[s] not in ("ok", "denegado") for s in SESIONES):
        return {"clave": "no_concluyente", "techo": None}
    ausente = resultados["ausente"] == "denegado"
    propia = resultados["propia"] == "denegado"
    techo = "niega" if resultados["techo"] == "denegado" else "pasa"
    if ausente and propia:
        clave = "inconsistente"
    elif ausente:
        clave = "ausente"
    elif propia:
        clave = "propia" if techo == "pasa" else "inconsistente"
    else:
        clave = "ajena" if techo == "niega" else "inconsistente"
    return {"clave": clave, "techo": techo}


# --- Las llamadas -----------------------------------------------------------

@dataclass
class Llamada:
    nombre: str
    servicio: str
    accion_iam: str
    metodo: str  # metodo de boto3
    params: dict = field(default_factory=dict)  # "{cuenta}" y "{capa}" se rellenan al ejecutar
    recurso: str = "ninguno"  # propio | aws | ninguno


LLAMADA_DE_CONTROL = "dynamodb DescribeTable (propia)"

LLAMADAS = [
    Llamada("s3 ListBuckets", "s3", "s3:ListAllMyBuckets", "list_buckets"),
    Llamada("s3 ListObjectsV2 (propio)", "s3", "s3:ListBucket", "list_objects_v2",
            {"Bucket": "agente-iam-sonda-{cuenta}", "MaxKeys": 1}, "propio"),
    Llamada("s3 ListObjectsV2 (publico de AWS)", "s3", "s3:ListBucket", "list_objects_v2",
            {"Bucket": BUCKET_PUBLICO, "MaxKeys": 1}, "aws"),
    Llamada("dynamodb ListTables", "dynamodb", "dynamodb:ListTables", "list_tables", {"Limit": 1}),
    Llamada(LLAMADA_DE_CONTROL, "dynamodb", "dynamodb:DescribeTable", "describe_table", {"TableName": NOMBRE}, "propio"),
    Llamada("sqs ListQueues", "sqs", "sqs:ListQueues", "list_queues", {"MaxResults": 1}),
    Llamada("sqs GetQueueAttributes (propia)", "sqs", "sqs:GetQueueAttributes", "get_queue_attributes",
            {"QueueUrl": "https://sqs.us-east-1.amazonaws.com/{cuenta}/" + NOMBRE, "AttributeNames": ["QueueArn"]}, "propio"),
    Llamada("sns ListTopics", "sns", "sns:ListTopics", "list_topics"),
    Llamada("sns GetTopicAttributes (propio)", "sns", "sns:GetTopicAttributes", "get_topic_attributes",
            {"TopicArn": "arn:aws:sns:us-east-1:{cuenta}:" + NOMBRE}, "propio"),
    Llamada("sns GetTopicAttributes (publico de AWS)", "sns", "sns:GetTopicAttributes", "get_topic_attributes",
            {"TopicArn": TEMA_PUBLICO}, "aws"),
    Llamada("logs DescribeLogGroups", "logs", "logs:DescribeLogGroups", "describe_log_groups", {"limit": 1}),
    Llamada("logs FilterLogEvents (propio)", "logs", "logs:FilterLogEvents", "filter_log_events",
            {"logGroupName": NOMBRE, "limit": 1}, "propio"),
    Llamada("cloudwatch ListMetrics", "cloudwatch", "cloudwatch:ListMetrics", "list_metrics", {"Namespace": "AWS/Logs"}),
    Llamada("ec2 DescribeRegions", "ec2", "ec2:DescribeRegions", "describe_regions"),
    Llamada("ec2 DescribeInstances", "ec2", "ec2:DescribeInstances", "describe_instances", {"MaxResults": 5}),
    Llamada("ec2 DescribeImages (de Amazon)", "ec2", "ec2:DescribeImages", "describe_images",
            {"Owners": ["amazon"], "MaxResults": 5}, "aws"),
    Llamada("lambda ListFunctions", "lambda", "lambda:ListFunctions", "list_functions", {"MaxItems": 1}),
    Llamada("lambda GetLayerVersionByArn (capa de AWS)", "lambda", "lambda:GetLayerVersion", "get_layer_version_by_arn",
            {"Arn": "{capa}"}, "aws"),
]


def _rellenar(params: dict, valores: dict[str, str]) -> dict:
    return {k: v.format(**valores) if isinstance(v, str) else v for k, v in params.items()}


def sonda_rota(filas: list[dict]) -> bool:
    """La tabla propia lleva la clave con la cuenta propia; si no sale asi, la sonda mide mal."""
    return not any(f["llamada"] == LLAMADA_DE_CONTROL and f["clave"] == "propia" for f in filas)


# --- Ejecucion --------------------------------------------------------------

def mostrar_plan(llamadas: list[Llamada]) -> None:
    print(f"{len(llamadas)} llamadas x {len(SESIONES)} sesiones ({', '.join(SESIONES)}), region {REGION}")
    print(f"  rol: el de la pila {PILA} (salida RolArn)")
    for ll in llamadas:
        print(f"  {ll.nombre}  [{ll.accion_iam}, recurso {ll.recurso}]")
    print("  salida: evidencias/sonda-cuenta/<fecha UTC>/resultado.json")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ejecutar", action="store_true", help="correr de verdad (llama a AWS)")
    ap.add_argument("--perfil", default="org-agente-iam", help="perfil que puede asumir el rol de la sonda")
    ap.add_argument("--capa", default="", help="ARN de una capa de Lambda de AWS; sin el, esa llamada no se hace")
    args = ap.parse_args(argv)

    llamadas = [ll for ll in LLAMADAS if ll.params.get("Arn") != "{capa}" or args.capa]
    mostrar_plan(llamadas)
    if not args.ejecutar:
        print("\nSolo el plan. Para correrlo: --ejecutar")
        return 0

    # boto3 se importa aqui y no arriba: sin --ejecutar el script no lo toca.
    import boto3

    try:
        base = boto3.Session(profile_name=args.perfil, region_name=REGION)
        cuenta = base.client("sts").get_caller_identity()["Account"]
        salidas = base.client("cloudformation").describe_stacks(StackName=PILA)["Stacks"][0].get("Outputs", [])
        rol_arn = next(o["OutputValue"] for o in salidas if o["OutputKey"] == "RolArn")
        sesiones = {}
        for nombre in SESIONES:
            c = base.client("sts").assume_role(
                RoleArn=rol_arn, RoleSessionName=f"sonda-{nombre}", DurationSeconds=900,
                Policy=json.dumps(politica_de_sesion(nombre), separators=(",", ":")),
            )["Credentials"]
            clave, secreto, token = c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"]
            sesiones[nombre] = boto3.Session(
                aws_access_key_id=clave, aws_secret_access_key=secreto, aws_session_token=token, region_name=REGION,
            )
    except (ClientError, BotoCoreError, StopIteration) as e:
        print(f"\nerror de corrida: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    time.sleep(PROPAGACION_S)
    valores = {"cuenta": cuenta, "capa": args.capa}
    filas = []
    for ll in llamadas:
        por_sesion = {}
        for nombre, sesion in sesiones.items():
            try:
                getattr(sesion.client(ll.servicio), ll.metodo)(**_rellenar(ll.params, valores))
                error = None
            except (ClientError, BotoCoreError) as e:
                error = e
            por_sesion[nombre] = resultado(error)
        filas.append({"llamada": ll.nombre, "recurso": ll.recurso, **clasificar(por_sesion), "sesiones": por_sesion})
        f = filas[-1]
        print(f"  {ll.nombre:<45} clave {f['clave']:<15} techo {f['techo'] or '-'}", flush=True)

    fecha = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    carpeta = RAIZ / "evidencias" / "sonda-cuenta" / fecha
    carpeta.mkdir(parents=True)
    (carpeta / "resultado.json").write_text(
        json.dumps(enmascarar({"fecha_utc": fecha, "perfil": args.perfil, "capa": args.capa, "filas": filas}),
                   ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"\n{carpeta / 'resultado.json'}")
    if sonda_rota(filas):
        print(f"sonda rota: '{LLAMADA_DE_CONTROL}' no salio 'propia'; la medicion no vale.", file=sys.stderr)
        return 1
    return 3 if any(f["clave"] == "inconsistente" for f in filas) else 0


if __name__ == "__main__":
    sys.exit(main())
