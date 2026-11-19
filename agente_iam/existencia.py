"""Que el recurso pedido existe en esta cuenta, antes de llamar al modelo (Fase 28).

POR QUE EXISTE. Era requisito del sistema y no estaba: el 27-10-2026 una
solicitud sobre `bucket-de-ejemplo`, que no existe, paso por Bedrock, quedo
`propuesta` y esperaba a un aprobador (docs/MEDICIONES.md Q.1). El modelo solo
lo anoto como supuesto. Comprobarlo antes no es una barrera de seguridad (la
condicion de cuenta y el techo ya impiden usar un recurso ajeno): es no gastar
modelo, ni el tiempo del solicitante y del aprobador, en algo que no sirve.

COMO. Una lectura por servicio que no devuelve contenido, solo si el recurso
esta (docs/superpowers/specs/2026-10-27-solicitud-en-texto-y-motivos-design.md,
punto 3). En S3 se listan los buckets de la cuenta: un bucket ajeno con el
mismo nombre cuenta como inexistente. En Lambda se piden las etiquetas y no la
configuracion, que trae las variables de entorno.

TRES RESPUESTAS Y NO DOS. `existe`, `no_existe` y `no_comprobado` (permiso
denegado, red, throttling). Solo `no_existe` rechaza: que la comprobacion falle
no debe tumbar todas las solicitudes, y la duda queda escrita para el
aprobador. `no_aplica` para EC2 (inventario, sin recurso unico) y lo que no
tenga comprobacion.

APAGADO EN LOS TESTS. `orquestador` solo llama a `comprobar` si
`AGENTE_IAM_COMPROBAR_EXISTENCIA` no es "0"; `tests/conftest.py` lo pone a "0"
en unitarios y seguridad, que no salen a AWS. Esta funcion se prueba aparte con
`Stubber` (`tests/unitarios/test_existencia.py`).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any, Literal

import boto3
from botocore.exceptions import BotoCoreError, ClientError

Resultado = Literal["existe", "no_existe", "no_comprobado", "no_aplica"]

# Codigos de error que significan "no esta", por servicio. Cualquier otro error
# es `no_comprobado`.
_NO_ESTA = {
    "dynamodb": {"ResourceNotFoundException"},
    "lambda": {"ResourceNotFoundException"},
    "sqs": {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"},
    "sns": {"NotFound"},
}


def activa() -> bool:
    """La comprobacion se hace salvo que `AGENTE_IAM_COMPROBAR_EXISTENCIA` sea "0"."""
    return os.getenv("AGENTE_IAM_COMPROBAR_EXISTENCIA", "1") != "0"


def _crear_cliente(servicio: str, region: str):
    return boto3.client(servicio, region_name=region)


def comprobar(
    servicio: str,
    nombre: str,
    region: str,
    cuenta: str,
    crear_cliente: Callable[[str, str], Any] | None = None,
) -> tuple[Resultado, str]:
    """(resultado, detalle) de buscar `nombre` en `servicio`, `region` y `cuenta`.

    `detalle` es corto y sin datos del recurso: el codigo de error si lo hubo.
    `crear_cliente(servicio_boto3, region)` se inyecta en los tests.
    """
    crear = crear_cliente or _crear_cliente
    try:
        if servicio == "s3":
            return _s3(crear("s3", region), nombre)
        if servicio == "dynamodb":
            crear("dynamodb", region).describe_table(TableName=nombre)
            return "existe", ""
        if servicio == "lambda":
            arn = f"arn:aws:lambda:{region}:{cuenta}:function:{nombre}"
            crear("lambda", region).list_tags(Resource=arn)
            return "existe", ""
        if servicio == "sqs":
            crear("sqs", region).get_queue_url(QueueName=nombre, QueueOwnerAWSAccountId=cuenta)
            return "existe", ""
        if servicio == "sns":
            arn = f"arn:aws:sns:{region}:{cuenta}:{nombre}"
            crear("sns", region).get_topic_attributes(TopicArn=arn)
            return "existe", ""
        if servicio == "logs":
            grupos = crear("logs", region).describe_log_groups(logGroupNamePrefix=nombre).get("logGroups", [])
            return ("existe", "") if any(g.get("logGroupName") == nombre for g in grupos) else ("no_existe", "")
        if servicio == "cloudwatch":
            r = crear("cloudwatch", region).describe_alarms(AlarmNames=[nombre])
            hay = r.get("MetricAlarms") or r.get("CompositeAlarms")
            return ("existe", "") if hay else ("no_existe", "")
    except ClientError as error:
        codigo = error.response.get("Error", {}).get("Code", "")
        if codigo in _NO_ESTA.get(servicio, set()):
            return "no_existe", ""
        return "no_comprobado", codigo or "error del servicio"
    except BotoCoreError as error:
        return "no_comprobado", type(error).__name__
    return "no_aplica", ""


def _s3(cliente, nombre: str) -> tuple[Resultado, str]:
    """Solo los buckets de esta cuenta: `ListBuckets` no ve los ajenos."""
    if cliente.can_paginate("list_buckets"):
        nombres = {
            b["Name"] for pagina in cliente.get_paginator("list_buckets").paginate() for b in pagina.get("Buckets", [])
        }
    else:
        nombres = {b["Name"] for b in cliente.list_buckets().get("Buckets", [])}
    return ("existe", "") if nombre in nombres else ("no_existe", "")
