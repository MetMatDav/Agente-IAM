"""Fase 28, punto 2: el campo `recurso` admite el nombre o el ARN del recurso.

Un ARN se separa en el formulario mismo (`models.CamposEstructurados`): su
servicio y su region tienen que ser los del formulario, y de el sale el nombre,
que es lo que usa todo lo demas. El ARN original se guarda en `recurso_arn`.
La cuenta solo se puede comparar donde se conoce: en los chequeos previos, con
el motivo `arn_no_coincide`. Estos tests se ponen en rojo si un ARN de otro
servicio o de otra region pasa, si el nombre sale mal, o si un ARN de otra
cuenta llega al modelo. Sin red.
"""

import pytest
from pydantic import ValidationError

from agente_iam import coherencia
from agente_iam.models import CamposEstructurados, nombre_desde_arn

CUENTA = "111122223333"


def _campos(servicio: str, recurso: str, region: str = "us-east-1") -> CamposEstructurados:
    return CamposEstructurados.model_validate({"servicio": servicio, "recurso": recurso, "region": region})


@pytest.mark.parametrize(
    ("servicio", "arn", "nombre"),
    [
        ("s3", "arn:aws:s3:::finanzas-2026", "finanzas-2026"),
        ("s3", "arn:aws:s3:::finanzas-2026/cierres/*", "finanzas-2026"),
        ("dynamodb", f"arn:aws:dynamodb:us-east-1:{CUENTA}:table/Ventas", "Ventas"),
        ("dynamodb", f"arn:aws:dynamodb:us-east-1:{CUENTA}:table/Ventas/index/porFecha", "Ventas"),
        ("lambda", f"arn:aws:lambda:us-east-1:{CUENTA}:function:cobros", "cobros"),
        ("lambda", f"arn:aws:lambda:us-east-1:{CUENTA}:function:cobros:prod", "cobros"),
        ("sqs", f"arn:aws:sqs:us-east-1:{CUENTA}:pedidos", "pedidos"),
        ("sns", f"arn:aws:sns:us-east-1:{CUENTA}:alertas", "alertas"),
        ("logs", f"arn:aws:logs:us-east-1:{CUENTA}:log-group:/app/pagos", "/app/pagos"),
        ("logs", f"arn:aws:logs:us-east-1:{CUENTA}:log-group:/app/pagos:*", "/app/pagos"),
        ("cloudwatch", f"arn:aws:cloudwatch:us-east-1:{CUENTA}:alarm:cpu-alta", "cpu-alta"),
    ],
)
def test_del_arn_sale_el_nombre_y_se_guarda_el_arn(servicio, arn, nombre):
    campos = _campos(servicio, arn)
    assert campos.recurso == nombre
    assert campos.recurso_arn == arn


def test_un_nombre_sigue_siendo_un_nombre_y_sin_arn():
    campos = _campos("s3", "finanzas-2026")
    assert campos.recurso == "finanzas-2026"
    assert campos.recurso_arn is None


def test_validar_dos_veces_no_cambia_nada():
    """`aprobar` y el aplicador revalidan los campos guardados: ya traen el nombre y el ARN."""
    guardado = _campos("dynamodb", f"arn:aws:dynamodb:us-east-1:{CUENTA}:table/Ventas").model_dump()
    assert CamposEstructurados.model_validate(guardado).model_dump() == guardado


@pytest.mark.parametrize(
    ("servicio", "arn", "pista"),
    [
        ("s3", f"arn:aws:dynamodb:us-east-1:{CUENTA}:table/Ventas", "servicio"),
        ("dynamodb", f"arn:aws:dynamodb:eu-west-1:{CUENTA}:table/Ventas", "region"),
        ("s3", f"arn:aws:s3:us-east-1:{CUENTA}:accesspoint/x", "bucket"),
        ("dynamodb", f"arn:aws:dynamodb:us-east-1:{CUENTA}:backup/x", "forma"),
        ("lambda", f"arn:aws:lambda:us-east-1:{CUENTA}:layer:x", "forma"),
        ("ec2", f"arn:aws:ec2:us-east-1:{CUENTA}:instance/i-0abc", "ec2"),
        ("s3", "arn:aws:s3:::nombre con espacios", "nombre"),
        ("s3", "arn:aws-cn:s3:::finanzas", "forma"),
        ("s3", "arn:aws:s3:::", "forma"),
    ],
)
def test_un_arn_que_no_encaja_no_tiene_forma_valida(servicio, arn, pista):
    with pytest.raises(ValidationError) as error:
        _campos(servicio, arn)
    assert pista in str(error.value)


def test_nombre_desde_arn_devuelve_nombre_region_y_cuenta():
    assert nombre_desde_arn("sqs", f"arn:aws:sqs:us-east-1:{CUENTA}:pedidos") == ("pedidos", "us-east-1", CUENTA)
    assert nombre_desde_arn("s3", "arn:aws:s3:::finanzas") == ("finanzas", "", "")


def test_un_arn_de_otra_cuenta_se_rechaza_antes_del_modelo_con_su_codigo():
    campos = _campos("sqs", "arn:aws:sqs:us-east-1:999999999999:pedidos")
    assert coherencia.motivos_de_la_cuenta_del_arn(campos, CUENTA) == [
        (
            "arn_no_coincide",
            "El ARN del recurso es de la cuenta '999999999999', no de esta cuenta",
        )
    ]
    assert coherencia.motivos_de_la_cuenta_del_arn(_campos("sqs", f"arn:aws:sqs:us-east-1:{CUENTA}:pedidos"), CUENTA) == []
    assert coherencia.motivos_de_la_cuenta_del_arn(_campos("s3", "arn:aws:s3:::finanzas"), CUENTA) == []
    assert coherencia.motivos_de_la_cuenta_del_arn(_campos("sqs", "pedidos"), CUENTA) == []
