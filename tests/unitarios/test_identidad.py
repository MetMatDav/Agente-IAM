"""Fase 3: la identidad se confirma contra el ARN canonico de la API.

Aqui aparece una herramienta nueva en el proyecto: botocore.stub.Stubber,
el stub oficial de boto3. Envuelve un cliente real y, en vez de ir a la
red, responde con lo que el test le programe — y ademas VERIFICA que la
llamada llevo los parametros esperados (expected_params). Ningun test de
este archivo necesita credenciales ni cuenta AWS.
"""

from datetime import datetime, timezone

import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from agente_iam import identidad
from tests.dobles import _cliente

_CUENTA = "111122223333"
_FECHA = datetime(2026, 8, 28, tzinfo=timezone.utc)


@pytest.fixture
def iam(monkeypatch):
    """Cliente IAM con Stubber inyectado en el modulo identidad."""
    cliente = _cliente("iam")
    stub = Stubber(cliente)
    monkeypatch.setattr(identidad, "_cliente", cliente)
    with stub:
        yield stub
        # Si un test programo respuestas que el codigo nunca pidio,
        # tambien es un fallo: el flujo no fue el esperado.
        stub.assert_no_pending_responses()


def _respuesta_user(arn: str, nombre: str) -> dict:
    return {
        "User": {
            "Path": "/",
            "UserName": nombre,
            "UserId": "AIDAEXAMPLE123456789",
            "Arn": arn,
            "CreateDate": _FECHA,
        }
    }


def test_arn_coincidente_queda_verificado(iam):
    arn = f"arn:aws:iam::{_CUENTA}:user/ana.gomez"
    iam.add_response("get_user", _respuesta_user(arn, "ana.gomez"), {"UserName": "ana.gomez"})
    iam.add_response(
        "list_attached_user_policies",
        {"AttachedPolicies": [{"PolicyName": "AmazonBedrockReadOnly"}]},
        {"UserName": "ana.gomez"},
    )
    iam.add_response(
        "list_user_policies", {"PolicyNames": ["inline-1"]}, {"UserName": "ana.gomez"}
    )

    r = identidad.verificar(arn)

    assert r.existe is True
    assert r.principal_arn == arn  # el canonico, confirmado por la API
    # Fase 7b.0: el id unico viaja tambien. El ARN identifica un NOMBRE;
    # el id identifica la ENTIDAD. Si alguien borra 'ana.gomez' y crea otra,
    # el ARN es identico y el id no, y eso es lo que el aplicador compara
    # entre el momento de aprobar y el de aplicar.
    assert r.principal_id == "AIDAEXAMPLE123456789"
    assert r.politicas_actuales == ["AmazonBedrockReadOnly", "inline-1"]
    assert r.detalle is None


def test_cuenta_ajena_no_se_verifica(iam):
    # EL bug de la Fase 3: la cuenta declarada es otra, pero el nombre
    # existe en la nuestra. Antes esto quedaba "verificado" y reventaba
    # despues en el simulador, con los tokens ya gastados.
    declarado = "arn:aws:iam::999999999999:user/Mateo"
    canonico = f"arn:aws:iam::{_CUENTA}:user/Mateo"
    iam.add_response("get_user", _respuesta_user(canonico, "Mateo"), {"UserName": "Mateo"})

    r = identidad.verificar(declarado)

    assert r.existe is False
    assert canonico in r.detalle  # informa el ARN real al aprobador
    assert r.principal_arn == declarado  # NO adopta un ARN no confirmado


def test_principal_con_path_ya_no_es_falso_positivo(iam):
    # El otro bug: 'user/finanzas/ana' llamaba GetUser('finanzas/ana') y
    # se rechazaba como inexistente. Ahora se llama con el nombre amigable
    # ('ana', y expected_params lo verifica) y el path se compara via el
    # Arn canonico de la respuesta.
    arn = f"arn:aws:iam::{_CUENTA}:user/finanzas/ana"
    iam.add_response("get_user", _respuesta_user(arn, "ana"), {"UserName": "ana"})
    iam.add_response(
        "list_attached_user_policies", {"AttachedPolicies": []}, {"UserName": "ana"}
    )
    iam.add_response("list_user_policies", {"PolicyNames": []}, {"UserName": "ana"})

    r = identidad.verificar(arn)

    assert r.existe is True
    assert r.principal_arn == arn


def test_path_omitido_no_se_verifica(iam):
    # El usuario real tiene path; el declarado no lo trae. Comparacion
    # estricta: se rechaza y se informa el canonico.
    declarado = f"arn:aws:iam::{_CUENTA}:user/ana"
    canonico = f"arn:aws:iam::{_CUENTA}:user/finanzas/ana"
    iam.add_response("get_user", _respuesta_user(canonico, "ana"), {"UserName": "ana"})

    r = identidad.verificar(declarado)

    assert r.existe is False
    assert canonico in r.detalle


def test_principal_inexistente(iam):
    iam.add_client_error(
        "get_user", service_error_code="NoSuchEntity", http_status_code=404
    )
    r = identidad.verificar(f"arn:aws:iam::{_CUENTA}:user/no.existe")
    assert r.existe is False
    assert "no existe" in r.detalle


def test_rol_coincidente_queda_verificado(iam):
    arn = f"arn:aws:iam::{_CUENTA}:role/AgenteIAM-Analista"
    iam.add_response(
        "get_role",
        {
            "Role": {
                "Path": "/",
                "RoleName": "AgenteIAM-Analista",
                "RoleId": "AROAEXAMPLE123456789",
                "Arn": arn,
                "CreateDate": _FECHA,
            }
        },
        {"RoleName": "AgenteIAM-Analista"},
    )
    iam.add_response(
        "list_attached_role_policies",
        {"AttachedPolicies": []},
        {"RoleName": "AgenteIAM-Analista"},
    )
    iam.add_response(
        "list_role_policies", {"PolicyNames": []}, {"RoleName": "AgenteIAM-Analista"}
    )

    r = identidad.verificar(arn)
    assert r.existe is True
    assert r.tipo == "role"
    assert r.principal_id == "AROAEXAMPLE123456789"


def test_arn_sin_forma_de_principal(iam):
    # Ni siquiera llega a llamar a la API (el Stubber lo confirmaria:
    # una llamada no programada revienta el test).
    r = identidad.verificar("arn:aws:s3:::finanzas-2026")
    assert r.existe is False
    assert r.tipo == "desconocido"
    assert "forma" in r.detalle


def test_otros_errores_de_api_suben(iam):
    # Throttling NO es "no existe": la excepcion debe propagarse para que
    # la Fase 4 la registre como error, nunca como rechazo del principal.
    iam.add_client_error(
        "get_user", service_error_code="Throttling", http_status_code=429
    )
    # ClientError con su codigo, no "cualquier excepcion": con
    # pytest.raises(Exception) un TypeError del propio codigo tambien
    # dejaba el test en verde (lo marco ruff, B017, el 22-10-2026).
    with pytest.raises(ClientError) as error:
        identidad.verificar(f"arn:aws:iam::{_CUENTA}:user/ana.gomez")
    assert error.value.response["Error"]["Code"] == "Throttling"
