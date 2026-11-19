"""Verificacion de identidad del solicitante.

Regla: lo que el solicitante declara sobre si mismo no vale nada. Aqui
tomamos el ARN declarado y lo contrastamos contra IAM. Lo que devuelve
esta funcion es lo unico que el resto del sistema puede tratar como cierto.

Fase 3 — el principio operativo: no comparamos lo que NOSOTROS parseamos,
comparamos lo que IAM RESPONDE. GetUser/GetRole devuelven el objeto
completo con su Arn canonico (cuenta, path y nombre reales). Ese Arn se
compara contra el declarado, caracter por caracter:

  - cuenta distinta        -> no verificado (antes pasaba: la llamada iba
                              contra NUESTRA cuenta y el numero declarado
                              jamas se contrastaba)
  - path omitido o de mas  -> no verificado, con el canonico en `detalle`
  - coincidencia exacta    -> verificado, y lo que viaja al resto del
                              sistema es el ARN de la API, no el declarado

La comparacion es estricta a proposito: en un sistema de permisos, una
declaracion imprecisa se rechaza y se informa el canonico; no se acepta
una "casi coincidencia".

En produccion esta capa la reemplaza el IdP (Cognito, Entra, Okta o
Identity Center): la identidad llegaria firmada en un token y ni siquiera
pasaria por el formulario. La forma del resultado no cambia.
"""

import re
from typing import Literal

import boto3
from botocore.exceptions import ClientError

from agente_iam.config import AWS_REGION
from agente_iam.models import IdentidadVerificada

_ARN = re.compile(r"^arn:aws:iam::(\d{12}):(user|role)/(.+)$")

_cliente = None


def _iam():
    global _cliente
    if _cliente is None:
        _cliente = boto3.client("iam", region_name=AWS_REGION)
    return _cliente


def verificar(principal_arn: str) -> IdentidadVerificada:
    """Contrasta el ARN declarado contra IAM y devuelve lo que se comprobo."""
    declarado = principal_arn.strip()
    m = _ARN.match(declarado)
    if not m:
        return IdentidadVerificada(
            principal_arn=declarado,
            tipo="desconocido",
            existe=False,
            cuenta="",
            detalle="el ARN no tiene forma de principal IAM (user o role)",
        )

    cuenta, resto = m.group(1), m.group(3)
    # _ARN solo deja pasar user o role; se dice explicito para que el tipo
    # lo sepa tambien (mypy, Fase 13), no solo la expresion regular.
    tipo: Literal["user", "role"] = "user" if m.group(2) == "user" else "role"
    # GetUser/GetRole reciben el nombre amigable, SIN el path: de
    # 'finanzas/ana' se llama con 'ana'. El path no se pierde: viene de
    # vuelta dentro del Arn canonico de la respuesta y se compara ahi.
    nombre = resto.split("/")[-1]

    try:
        # Del mismo objeto salen el ARN canonico y el id unico. El id no
        # cuesta una llamada extra y responde una pregunta que el ARN no
        # puede: si esta es LA MISMA entidad de antes, o una recreada con
        # el mismo nombre.
        if tipo == "user":
            objeto = _iam().get_user(UserName=nombre)["User"]
            arn_real, id_real = objeto["Arn"], objeto["UserId"]
        else:
            objeto = _iam().get_role(RoleName=nombre)["Role"]
            arn_real, id_real = objeto["Arn"], objeto["RoleId"]
        boundary = (objeto.get("PermissionsBoundary") or {}).get(
            "PermissionsBoundaryArn"
        )
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchEntity", "ValidationError"):
            return IdentidadVerificada(
                principal_arn=declarado,
                tipo=tipo,
                existe=False,
                cuenta=cuenta,
                detalle=f"no existe ningun {tipo} llamado '{nombre}' en la cuenta",
            )
        raise  # otros errores (throttling, red) no son "no existe": suben

    if arn_real != declarado:
        # El principal del nombre existe, pero NO es el que se declaro:
        # cuenta distinta, path distinto o mayusculas cambiadas. El sello
        # de "verificado" no se le pone a un ARN que IAM no confirmo.
        return IdentidadVerificada(
            principal_arn=declarado,
            tipo=tipo,
            existe=False,
            cuenta=cuenta,
            detalle=(
                "el ARN declarado no corresponde al principal real; "
                f"el canonico es '{arn_real}'"
            ),
        )

    # Solo un principal confirmado llega aqui. Las politicas listadas son
    # informativas (adjuntas e inline; las de grupo las ve el simulador).
    if tipo == "user":
        adj = _iam().list_attached_user_policies(UserName=nombre)
        politicas = [p["PolicyName"] for p in adj["AttachedPolicies"]]
        politicas += _iam().list_user_policies(UserName=nombre)["PolicyNames"]
    else:
        adj = _iam().list_attached_role_policies(RoleName=nombre)
        politicas = [p["PolicyName"] for p in adj["AttachedPolicies"]]
        politicas += _iam().list_role_policies(RoleName=nombre)["PolicyNames"]

    return IdentidadVerificada(
        principal_arn=arn_real,
        tipo=tipo,
        existe=True,
        cuenta=cuenta,
        principal_id=id_real,
        permissions_boundary=boundary,
        politicas_actuales=politicas,
    )
