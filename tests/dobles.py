"""Dobles y datos compartidos entre carpetas de tests.

Un archivo de `seguridad/` no importa de un `test_*.py` de `unitarios/`:
lo que comparten vive aqui. Asi cada carpeta se puede mover, correr o
borrar sin arrastrar a la otra (lo vigila `test_documentacion.py`).
"""

import boto3

from agente_iam.models import (
    AprobadorVerificado,
    PolicyDocument,
    PropuestaPolitica,
    SolicitudEstructurada,
    Statement,
)

_CUENTA = "111122223333"
_BENEFICIARIO = "arn:aws:iam::111122223333:user/jose.torres"
_APROBADOR = "arn:aws:iam::111122223333:user/Mateo"
# La beneficiaria de los tests del intake (orquestador, coherencia, techo).
_ANA = f"arn:aws:iam::{_CUENTA}:user/ana.gomez"


# --- Constructores compartidos (24-10-2026, revision O15) --------------------
#
# Hasta esa fecha `_solicitud`, `_propuesta` y el cliente de boto3 de juguete
# estaban copiados en cinco o siete ficheros, cada uno con su variante. Aqui
# van con argumentos por defecto; cada test pasa solo lo que prueba. Un campo
# nuevo en `SolicitudEstructurada` se toca en un sitio.


def _cliente(servicio: str):
    """Un cliente de boto3 con credenciales falsas, para envolverlo en
    `Stubber`. Nunca sale a la red: el guardian de tests/conftest.py lo
    pararia, y `Stubber` responde antes."""
    return boto3.client(
        servicio,
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


def _solicitud(
    servicio: str = "s3",
    recurso: str = "finanzas-2026",
    tipo: str = "lectura",
    *,
    solicitud_id: str = "req-prueba",
    principal: str = _ANA,
    justificacion: str = "prueba",
) -> SolicitudEstructurada:
    return SolicitudEstructurada.model_validate({
        "solicitud_id": solicitud_id,
        "principal_arn_declarado": principal,
        "campos": {"servicio": servicio, "recurso": recurso, "tipo_acceso": tipo, "region": "us-east-1"},
        "justificacion": justificacion,
    })


def _solicitud_persona(
    servicio: str = "s3",
    recurso: str = "finanzas-demo-111122223333",
    tipo: str = "lectura",
    *,
    solicitud_id: str = "req-20261026-ab12cd34",
    usuario: str = "solicitante.demo",
    sub: str = "sub-1234",
    client_id: str = "a" * 26,
    horas: int = 4,
    correo: str = "persona@example.com",
    justificacion: str = "prueba",
) -> SolicitudEstructurada:
    """Una solicitud del modo rol por persona (Fase 23): sin ARN declarado, con la
    persona del token y las horas. Es lo que arma el servidor tras validar una
    `SolicitudWeb`."""
    return SolicitudEstructurada.model_validate({
        "solicitud_id": solicitud_id,
        "campos": {"servicio": servicio, "recurso": recurso, "tipo_acceso": tipo, "region": "us-east-1"},
        "justificacion": justificacion,
        "persona": {"usuario": usuario, "sub": sub, "client_id": client_id},
        "horas": horas,
        "correo_aviso": correo,
    })


def _propuesta(
    acciones: list[str] | None = None,
    recursos: list[str] | None = None,
    *,
    principal: str = _ANA,
    effect: str = "Allow",
    condicion: dict | None = None,
    nombre: str = "Prueba",
) -> PropuestaPolitica:
    """Una propuesta de un solo statement; por defecto, leer el bucket."""
    st = Statement(
        Effect=effect,
        Action=acciones or ["s3:GetObject"],
        Resource=recursos or ["arn:aws:s3:::finanzas-2026/*"],
        Condition=condicion,
    )
    return PropuestaPolitica(
        accion="crear", nombre_politica=nombre, principal_arn=principal, justificacion="prueba",
        policy_document=PolicyDocument(Statement=[st]), nivel_riesgo="bajo", supuestos=[],
    )


def _registro(**cambios) -> dict:
    base = {
        "id": "req-prueba",
        "creada": "2026-08-29T10:00:00+00:00",
        "estado": "propuesta",
        "intentos": 1,
        "solicitud": {
            "solicitud_id": "req-prueba",
            "principal_arn_declarado": _BENEFICIARIO,
            "campos": {
                "servicio": "s3",
                "recurso": "finanzas-2026",
                "tipo_acceso": "lectura",
                "region": "us-east-1",
            },
            "justificacion": "Necesito leer el bucket.",
        },
        "identidad_verificada": {
            "principal_arn": _BENEFICIARIO,
            "tipo": "user",
            "existe": True,
            "cuenta": "111122223333",
            "politicas_actuales": [],
            "detalle": None,
        },
        "propuesta": {
            "accion": "crear",
            "nombre_politica": "S3Lectura",
            "principal_arn": _BENEFICIARIO,
            "justificacion": "lectura del bucket",
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": ["arn:aws:s3:::finanzas-2026/*"],
                    }
                ],
            },
            "nivel_riesgo": "bajo",
            "supuestos": [],
        },
    }
    base.update(cambios)
    return base


def _aprobador(arn_canonico, determinable=True):
    return AprobadorVerificado(
        arn_llamante=arn_canonico or "arn:aws:sts::111122223333:federated-user/x",
        arn_canonico=arn_canonico,
        user_id="AIDAEJEMPLO",
        cuenta="111122223333",
        como_se_verifico="prueba",
        determinable=determinable,
    )


def _aprobador_sso(persona: str | None = "aprobador.demo", *, arn_canonico: str | None = None):
    """Un aprobador determinable con rol de Identity Center y esa persona
    (ADR-003, B2). `arn_canonico` solo se cambia para probar la coincidencia
    con el beneficiario."""
    arn = arn_canonico or (
        "arn:aws:sts::111122223333:assumed-role/"
        "AWSReservedSSO_AgenteIAM-Aprobador_0123456789abcdef/" + str(persona)
    )
    return AprobadorVerificado(
        arn_llamante=arn,
        arn_canonico=arn,
        user_id="AROAEJEMPLO:" + str(persona),
        cuenta="111122223333",
        como_se_verifico="prueba",
        determinable=True,
        persona=persona,
    )


def _solicitante(persona: str | None = "solicitante.demo") -> dict:
    """El bloque `solicitante` que graba el intake (Tarea 1)."""
    return {"persona": persona, "como_se_verifico": "prueba"}


def _evento(
    *,
    user_arn: str | None = None,
    user_id: str | None = None,
    cuenta_llamante: str = _CUENTA,
    cuenta_funcion: str = _CUENTA,
    authorizer: object = "iam",
    metodo: str = "POST",
    body: str = "{}",
) -> dict:
    """Un evento de la URL de funcion (payload 2.0) con la forma de la guia de Lambda
    "Invoking Lambda function URLs" (leida el 24-10-2026).

    Con `authorizer="iam"` (por defecto) el bloque `iam` lleva solo los campos que se
    pasan, para probar que falte cualquiera; `authorizer=None` es un evento sin
    identidad (AuthType NONE) y `authorizer="falta"` quita la clave entera. `accessKey`
    va siempre: el codigo no debe leerlo ni guardarlo, y los tests lo comprueban.
    """
    ctx: dict = {
        "accountId": cuenta_funcion,
        "http": {"method": metodo, "path": "/"},
    }
    if authorizer == "iam":
        iam = {"accountId": cuenta_llamante, "accessKey": "ASIAEJEMPLOCLAVE", "callerId": user_id}
        if user_arn is not None:
            iam["userArn"] = user_arn
        if user_id is not None:
            iam["userId"] = user_id
        ctx["authorizer"] = {"iam": iam}
    elif authorizer != "falta":
        ctx["authorizer"] = authorizer
    return {"requestContext": ctx, "body": body, "isBase64Encoded": False}


# --- Plantillas de CloudFormation (Fase 18) ----------------------------------


def resolver_sub(valor, cuenta: str = _CUENTA):
    """Sustituye `{"Fn::Sub": "...${AWS::AccountId}..."}` por la cuenta de ejemplo, en toda la estructura.

    Asi una politica de una plantilla se compara con los patrones de ARN de los
    JSON de `infra/`, que ya llevan `111122223333`.
    """
    if isinstance(valor, dict) and set(valor) == {"Fn::Sub"}:
        return valor["Fn::Sub"].replace("${AWS::AccountId}", cuenta)
    if isinstance(valor, dict):
        return {k: resolver_sub(v, cuenta) for k, v in valor.items()}
    if isinstance(valor, list):
        return [resolver_sub(v, cuenta) for v in valor]
    return valor


def sentencias_de_rol(plantilla: dict, recurso: str) -> list[dict]:
    """Las sentencias de las politicas inline de un `AWS::IAM::Role`, con `Fn::Sub` resuelto."""
    politicas = plantilla["Resources"][recurso]["Properties"]["Policies"]
    return [s for p in politicas for s in resolver_sub(p["PolicyDocument"])["Statement"]]
