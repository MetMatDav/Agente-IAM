"""Fase 7a: la aprobacion humana, y los dos huecos que tapa de paso.

Ninguno de estos tests toca la red. Los que necesitan STS o IAM usan
Stubber, y `expected_params` verifica que la llamada va con lo que debe.
"""

import base64
import json
import logging
from typing import get_args

import pytest
from botocore.stub import Stubber
from pydantic import ValidationError

from agente_iam import almacen, aprobar, coherencia, huella, models, orquestador
from agente_iam.config import MAX_INTENTOS
from agente_iam.herramientas import catalogo

from tests.dobles import (
    _APROBADOR,
    _BENEFICIARIO,
    _aprobador,
    _aprobador_sso,
    _cliente,
    _evento,
    _propuesta,
    _registro,
    _solicitante,
    _solicitud_persona,
)


# ---------------------------------------------------------------------------
# La huella
# ---------------------------------------------------------------------------


def test_la_huella_ignora_lo_que_se_anade_despues():
    # Si el bloque de aprobacion entrara en la huella seria imposible
    # verificarla: guardar el resultado cambiaria aquello sobre lo que se
    # calculo.
    registro = _registro()
    antes = huella.calcular(registro)
    registro["aprobacion"] = {"cuando": "ya", "huella": antes}
    registro["aplicacion"] = {"policy_arn": "arn:aws:iam::111122223333:policy/x"}
    assert huella.calcular(registro) == antes
    assert huella.coincide(registro, antes)


def test_la_huella_ignora_el_rechazo():
    """Bloque propio desde el 24-10-2026: guardarlo no puede mover la huella
    que lleva dentro."""
    registro = _registro()
    antes = huella.calcular(registro)
    registro["rechazo"] = {"cuando": "ya", "huella": antes, "motivo": "no"}
    assert huella.coincide(registro, antes)


def test_la_huella_sobrevive_al_cambio_de_estado():
    # Regresion de un bug que los tests de la funcion aislada NO cogieron y
    # que solo aparecio al correr el comando contra la cuenta: se calculaba
    # la huella y despues se ponia `estado: aprobada`, asi que la huella
    # guardada no verificaba y el aplicador habria rechazado todo.
    #
    # El estado es el campo que el flujo esta disenado para ir cambiando;
    # una firma que lo incluya se rompe en cada transicion legitima.
    registro = _registro()
    firma = huella.calcular(registro)
    for estado in ("aprobada", "aplicada"):
        registro["estado"] = estado
        assert huella.coincide(registro, firma), f"la huella se rompio en '{estado}'"


def test_la_huella_cubre_los_campos_de_la_solicitud():
    # El motivo de hashear el registro entero y no solo la propuesta: los
    # chequeos posteriores se revalidan contra `campos`, asi que cambiar el
    # servicio sin mover la huella dejaria al aplicador revalidando contra
    # datos distintos de los que leyo el humano.
    registro = _registro()
    original = huella.calcular(registro)
    registro["solicitud"]["campos"]["servicio"] = "iam"
    assert huella.calcular(registro) != original


def test_la_huella_cubre_al_beneficiario():
    registro = _registro()
    original = huella.calcular(registro)
    registro["identidad_verificada"]["principal_arn"] = _APROBADOR
    assert huella.calcular(registro) != original


def test_la_huella_no_depende_del_orden_de_las_claves():
    registro = _registro()
    reordenado = json.loads(json.dumps(registro))
    reordenado["solicitud"] = dict(reversed(list(reordenado["solicitud"].items())))
    assert huella.calcular(reordenado) == huella.calcular(registro)


# ---------------------------------------------------------------------------
# Quien aprueba: los tres casos de GetCallerIdentity
# ---------------------------------------------------------------------------


@pytest.fixture
def aws(monkeypatch):
    """Stubs de STS e IAM para el modulo de aprobacion."""
    sts = _cliente("sts")
    iam = _cliente("iam")
    stub_sts, stub_iam = Stubber(sts), Stubber(iam)
    monkeypatch.setattr(aprobar, "_sts_cliente", sts)
    monkeypatch.setattr(aprobar, "_iam_cliente", iam)
    with stub_sts, stub_iam:
        yield stub_sts, stub_iam
        stub_sts.assert_no_pending_responses()
        stub_iam.assert_no_pending_responses()


def _identidad(arn, user_id="AIDAEJEMPLO"):
    return {"UserId": user_id, "Account": "111122223333", "Arn": arn}


def test_usuario_iam_es_directamente_comparable(aws):
    stub_sts, _ = aws
    stub_sts.add_response("get_caller_identity", _identidad(_APROBADOR))
    r = aprobar.identificar_aprobador()
    assert r.determinable is True
    assert r.arn_canonico == _APROBADOR


def test_rol_asumido_se_resuelve_contra_iam(aws):
    # El ARN de STS no es comparable con uno de IAM. Se parsea el nombre
    # como HIPOTESIS y se confirma contra la fuente: el RoleId que devuelve
    # IAM debe ser el prefijo del UserId de la sesion.
    stub_sts, stub_iam = aws
    stub_sts.add_response(
        "get_caller_identity",
        _identidad(
            "arn:aws:sts::111122223333:assumed-role/Aprobadores/sesion-1",
            user_id="AROAXAMEBNOSHSQ2SFR6N:sesion-1",
        ),
    )
    stub_iam.add_response(
        "get_role",
        {
            "Role": {
                "Path": "/",
                "RoleName": "Aprobadores",
                "RoleId": "AROAXAMEBNOSHSQ2SFR6N",
                "Arn": "arn:aws:iam::111122223333:role/Aprobadores",
                "CreateDate": "2026-01-01T00:00:00Z",
            }
        },
        {"RoleName": "Aprobadores"},
    )
    r = aprobar.identificar_aprobador()
    assert r.determinable is True
    # El canonico es el que devolvio IAM, no uno construido por nosotros.
    assert r.arn_canonico == "arn:aws:iam::111122223333:role/Aprobadores"


def test_rol_con_el_mismo_nombre_pero_otro_id_no_es_determinable(aws):
    # Mismo nombre, rol distinto (borrado y recreado, u otra cuenta). El
    # nombre coincide y la identidad no: no se le pone el sello.
    stub_sts, stub_iam = aws
    stub_sts.add_response(
        "get_caller_identity",
        _identidad(
            "arn:aws:sts::111122223333:assumed-role/Aprobadores/sesion-1",
            user_id="AROAZZZZZZZZZZZZZZZZZ:sesion-1",
        ),
    )
    stub_iam.add_response(
        "get_role",
        {
            "Role": {
                "Path": "/",
                "RoleName": "Aprobadores",
                "RoleId": "AROAXAMEBNOSHSQ2SFR6N",
                "Arn": "arn:aws:iam::111122223333:role/Aprobadores",
                "CreateDate": "2026-01-01T00:00:00Z",
            }
        },
        {"RoleName": "Aprobadores"},
    )
    r = aprobar.identificar_aprobador()
    assert r.determinable is False
    assert r.arn_canonico is None


def test_identidad_federada_no_es_determinable(aws):
    stub_sts, _ = aws
    stub_sts.add_response(
        "get_caller_identity",
        _identidad("arn:aws:sts::111122223333:federated-user/alguien"),
    )
    assert aprobar.identificar_aprobador().determinable is False


# ---------------------------------------------------------------------------
# La persona de Identity Center (ADR-003, B2): STS o evento, la misma resolucion
# ---------------------------------------------------------------------------

_NOMBRE_SSO = "AWSReservedSSO_AgenteIAM-Aprobador_0a1b2c3d4e5f6a7b"
_ARN_SSO = f"arn:aws:sts::111122223333:assumed-role/{_NOMBRE_SSO}/aprobador.demo"
# GetRole exige RoleId de 16 caracteres o mas: el doble valida los parametros.
_ID_SSO = "AROAEJEMPLOSSO0001"
_USER_ID_SSO = f"{_ID_SSO}:aprobador.demo"
_ARN_ROL_SSO = f"arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/{_NOMBRE_SSO}"


def _rol(nombre=_NOMBRE_SSO, role_id=_ID_SSO, path="/aws-reserved/sso.amazonaws.com/"):
    arn = f"arn:aws:iam::111122223333:role{path}{nombre}"
    return {
        "Role": {"Path": path, "RoleName": nombre, "RoleId": role_id, "Arn": arn,
                 "CreateDate": "2026-01-01T00:00:00Z"}
    }


def _sesion(aws, arn=_ARN_SSO, user_id=_USER_ID_SSO, rol=None):
    """Prepara STS (con el ARN y el UserId dados) e IAM (GetRole del rol dado)."""
    stub_sts, stub_iam = aws
    stub_sts.add_response("get_caller_identity", _identidad(arn, user_id=user_id))
    rol = rol or _rol()
    stub_iam.add_response("get_role", rol, {"RoleName": rol["Role"]["RoleName"]})


def test_sesion_del_permission_set_da_la_persona(aws):
    _sesion(aws)
    a = aprobar.identificar_aprobador()
    assert a.determinable
    assert a.persona == "aprobador.demo"
    assert a.arn_canonico == _ARN_ROL_SSO


def test_otro_permission_set_no_da_persona(aws):
    nombre = "AWSReservedSSO_AWSAdministratorAccess_0a1b2c3d4e5f6a7b"
    _sesion(aws, arn=f"arn:aws:sts::111122223333:assumed-role/{nombre}/aprobador.demo",
            rol=_rol(nombre=nombre))
    a = aprobar.identificar_aprobador()
    assert a.persona is None
    assert "AgenteIAM-Aprobador" in a.como_se_verifico


@pytest.mark.parametrize(
    "nombre",
    [
        "AWSReservedSSO_AgenteIAM-Aprobador_Extra_0a1b2c3d4e5f6a7b",  # otro permission set que empieza igual
        "AWSReservedSSO_AgenteIAM-Aprobador__0a1b2c3d4e5f6a7b",
        "AWSReservedSSO_AgenteIAM-Aprobador_0a1b2c3d-4e5f6a7b",
        "AWSReservedSSO_AgenteIAM-Aprobador_",
    ],
)
def test_un_permission_set_que_solo_empieza_igual_no_da_persona(aws, nombre):
    """Fase 33: el rol es AWSReservedSSO_<permission set>_<sufijo>. Con solo
    mirar el prefijo, un permission set llamado `AgenteIAM-Aprobador_Extra`
    daba persona. Tras el prefijo solo vale el sufijo: letras y cifras."""
    _sesion(aws, arn=f"arn:aws:sts::111122223333:assumed-role/{nombre}/aprobador.demo",
            rol=_rol(nombre=nombre))
    a = aprobar.identificar_aprobador()
    assert a.persona is None
    assert "AgenteIAM-Aprobador" in a.como_se_verifico


def test_rol_fuera_del_path_de_identity_center_no_da_persona(aws):
    _sesion(aws, rol=_rol(path="/"))
    a = aprobar.identificar_aprobador()
    assert a.persona is None
    assert "aws-reserved/sso.amazonaws.com" in a.como_se_verifico


def test_nombre_de_sesion_distinto_del_user_id_no_da_persona(aws):
    _sesion(aws, user_id=f"{_ID_SSO}:otra")
    a = aprobar.identificar_aprobador()
    assert a.persona is None
    assert "sesion" in a.como_se_verifico


def test_usuario_iam_no_tiene_persona(aws):
    stub_sts, _ = aws
    stub_sts.add_response("get_caller_identity", _identidad(_APROBADOR))
    a = aprobar.identificar_aprobador()
    assert a.determinable
    assert a.persona is None


def test_rol_ordinario_determinable_no_tiene_persona(aws):
    # Lo que ya funcionaba sigue igual: comparable por ARN, sin persona.
    _sesion(aws, arn="arn:aws:sts::111122223333:assumed-role/Aprobadores/sesion-1",
            user_id="AROAXAMEBNOSHSQ2SFR6N:sesion-1",
            rol=_rol(nombre="Aprobadores", role_id="AROAXAMEBNOSHSQ2SFR6N", path="/"))
    a = aprobar.identificar_aprobador()
    assert a.determinable
    assert a.persona is None


def test_el_evento_de_la_url_se_resuelve_igual(aws):
    _, stub_iam = aws
    stub_iam.add_response("get_role", _rol(), {"RoleName": _NOMBRE_SSO})
    a = aprobar.aprobador_desde_evento(_evento(user_arn=_ARN_SSO, user_id=_USER_ID_SSO))
    assert a.persona == "aprobador.demo"
    assert a.arn_llamante == _ARN_SSO
    assert a.determinable
    assert a.cuenta == "111122223333"
    assert "evento" in a.como_se_verifico


def test_el_evento_no_lee_ni_guarda_la_access_key(aws):
    _, stub_iam = aws
    stub_iam.add_response("get_role", _rol(), {"RoleName": _NOMBRE_SSO})
    a = aprobar.aprobador_desde_evento(_evento(user_arn=_ARN_SSO, user_id=_USER_ID_SSO))
    assert "ASIAEJEMPLOCLAVE" not in a.model_dump_json()


def test_evento_sin_identidad_iam_no_es_determinable(aws):
    a = aprobar.aprobador_desde_evento(_evento(authorizer=None))
    assert not a.determinable
    assert a.persona is None
    assert a.arn_llamante == ""
    assert "authorizer" in a.como_se_verifico


def test_evento_sin_authorizer_no_es_determinable(aws):
    a = aprobar.aprobador_desde_evento(_evento(authorizer="falta"))
    assert not a.determinable
    assert a.persona is None


def test_evento_con_iam_incompleto_no_es_determinable(aws):
    a = aprobar.aprobador_desde_evento(_evento(user_arn=_ARN_SSO))  # sin userId
    assert not a.determinable
    assert a.persona is None
    assert "userId" in a.como_se_verifico
    assert a.arn_llamante == _ARN_SSO  # lo que hay, sin inventar el resto
    b = aprobar.aprobador_desde_evento(_evento(user_id=_USER_ID_SSO))  # sin userArn
    assert not b.determinable
    assert "userArn" in b.como_se_verifico


def test_evento_de_otra_cuenta_no_es_determinable(aws):
    a = aprobar.aprobador_desde_evento(
        _evento(user_arn=_ARN_SSO, user_id=_USER_ID_SSO, cuenta_llamante="999988887777")
    )
    assert not a.determinable
    assert a.persona is None
    assert "cuenta" in a.como_se_verifico


def test_evento_sin_cuenta_de_la_funcion_no_es_determinable(aws):
    evento = _evento(user_arn=_ARN_SSO, user_id=_USER_ID_SSO)
    del evento["requestContext"]["accountId"]
    assert not aprobar.aprobador_desde_evento(evento).determinable


def test_evento_que_no_es_un_dict_no_es_determinable(aws):
    assert not aprobar.aprobador_desde_evento(None).determinable
    assert not aprobar.aprobador_desde_evento({"requestContext": "x"}).determinable


@pytest.mark.parametrize("campo", ["user_arn", "user_id"])
@pytest.mark.parametrize("valor", [123, ["x"], {"a": 1}, True])
def test_evento_con_campos_que_no_son_texto_no_es_determinable(aws, campo, valor):
    # Un valor que no es un texto no puede romper con TypeError: es duda.
    datos = {"user_arn": _ARN_SSO, "user_id": _USER_ID_SSO, campo: valor}
    a = aprobar.aprobador_desde_evento(_evento(**datos))
    assert not a.determinable
    assert a.persona is None
    assert "no es un texto" in a.como_se_verifico


def test_evento_con_la_cuenta_que_no_es_texto_no_es_determinable(aws):
    evento = _evento(user_arn=_ARN_SSO, user_id=_USER_ID_SSO)
    evento["requestContext"]["authorizer"]["iam"]["accountId"] = 111122223333
    a = aprobar.aprobador_desde_evento(evento)
    assert not a.determinable
    assert "accountId" in a.como_se_verifico


def test_usuario_iam_de_otra_cuenta_que_la_del_llamante_no_es_determinable():
    a = aprobar._resolver("arn:aws:iam::999988887777:user/Mateo", "AIDAEJEMPLO", "111122223333", "prueba")
    assert not a.determinable
    assert a.arn_canonico is None
    assert "cuenta" in a.como_se_verifico


def test_rol_asumido_de_otra_cuenta_que_la_del_llamante_no_es_determinable(monkeypatch):
    """Como el usuario IAM de otra cuenta: `cuenta` (la que leen la separacion
    y el techo) y la del ARN no pueden divergir. Ni se pregunta a IAM."""
    monkeypatch.setattr(aprobar, "_iam", lambda: pytest.fail("no deberia preguntar a IAM"))
    a = aprobar._resolver(
        "arn:aws:sts::999988887777:assumed-role/Aprobadores/sesion-1",
        "AROAXAMEBNOSHSQ2SFR6N:sesion-1",
        "111122223333",
        "prueba",
    )
    assert not a.determinable
    assert a.arn_canonico is None
    assert a.persona is None
    assert "999988887777" in a.como_se_verifico
    assert "111122223333" in a.como_se_verifico


def test_arn_de_usuario_con_salto_de_linea_final_no_es_determinable():
    a = aprobar._resolver(_APROBADOR + "\n", "AIDAEJEMPLO", "111122223333", "prueba")
    assert not a.determinable


# ---------------------------------------------------------------------------
# Separacion de funciones: tres desenlaces, ninguno en silencio
# ---------------------------------------------------------------------------


def _reg(persona="solicitante.demo", beneficiario=_BENEFICIARIO):
    """Un registro con solicitante verificado y ese beneficiario."""
    r = _registro(solicitante=_solicitante(persona))
    r["identidad_verificada"]["principal_arn"] = beneficiario
    return r


def test_personas_distintas_cumple():
    sep, motivo = aprobar._separacion(_aprobador_sso("aprobador.demo"), _reg(), False)
    assert motivo is None
    assert sep["resultado"] == "cumplido"
    assert sep["aprobador"] == "aprobador.demo"
    assert sep["solicitante"] == "solicitante.demo"
    assert sep["beneficiario"] == _BENEFICIARIO


def test_aprobar_lo_que_uno_mismo_pidio_bloquea():
    sep, motivo = aprobar._separacion(
        _aprobador_sso("aprobador.demo"), _reg(persona="aprobador.demo"), False
    )
    assert motivo is not None
    assert "Autoaprobacion" in motivo
    assert "misma persona" in motivo
    assert "--autoaprobacion-demo" in motivo


def test_la_misma_persona_con_otras_mayusculas_bloquea():
    sep, motivo = aprobar._separacion(
        _aprobador_sso("Aprobador.Demo"), _reg(persona="aprobador.demo"), False
    )
    assert motivo is not None
    assert "Autoaprobacion" in motivo
    assert "misma persona" in motivo


def test_la_misma_persona_en_ancho_completo_bloquea():
    # NFKC lleva el ancho completo a ASCII: sin normalizar serian "distintas".
    sep, motivo = aprobar._separacion(
        _aprobador_sso("aprobador.demo"), _reg(persona="\uff41\uff50\uff52\uff4f\uff42\uff41\uff44\uff4f\uff52.demo"), False
    )
    assert motivo is not None
    assert "Autoaprobacion" in motivo
    assert "misma persona" in motivo


def test_misma_persona_normaliza_los_dos_lados():
    assert aprobar._misma_persona("Aprobador.Demo", "aprobador.demo")
    assert aprobar._misma_persona("aprobador.demo", "\uff21PROBADOR.demo")
    assert not aprobar._misma_persona("aprobador.demo", "aprobador.demo2")


def test_sin_persona_del_solicitante_bloquea():
    sep, motivo = aprobar._separacion(_aprobador_sso(), _reg(persona=None), False)
    assert motivo is not None
    assert "solicitante" in motivo
    assert sep["solicitante"] is None


def test_una_fila_anterior_sin_solicitante_bloquea():
    # Las filas de antes de ADR-003 no traen la clave: motivo, no KeyError.
    registro = _registro()
    assert "solicitante" not in registro
    sep, motivo = aprobar._separacion(_aprobador_sso(), registro, False)
    assert motivo is not None
    assert "solicitante" in motivo
    assert sep["solicitante"] is None


def test_un_bloque_de_solicitante_que_no_es_un_dict_bloquea():
    registro = _registro(solicitante="solicitante.demo")
    sep, motivo = aprobar._separacion(_aprobador_sso(), registro, False)
    assert motivo is not None
    assert sep["solicitante"] is None


def test_sin_persona_del_aprobador_bloquea():
    # Un usuario IAM es determinable pero no tiene persona de Identity Center.
    sep, motivo = aprobar._separacion(_aprobador(_APROBADOR), _reg(), False)
    assert motivo is not None
    assert "persona del aprobador" in motivo
    assert "Autoaprobacion" not in motivo
    assert sep["aprobador"] is None


def test_el_beneficiario_con_el_nombre_del_aprobador_bloquea():
    beneficiario = "arn:aws:iam::111122223333:user/equipo/aprobador.demo"
    sep, motivo = aprobar._separacion(
        _aprobador_sso("Aprobador.Demo"), _reg(beneficiario=beneficiario), False
    )
    assert motivo is not None
    assert "beneficiario" in motivo


def test_el_beneficiario_con_salto_de_linea_final_tambien_bloquea():
    # `$` casa antes de un salto de linea final y `[^/]+` se lo comia: el
    # nombre dejaba de coincidir y la autoaprobacion pasaba.
    beneficiario = "arn:aws:iam::111122223333:user/aprobador.demo\n"
    sep, motivo = aprobar._separacion(
        _aprobador_sso("aprobador.demo"), _reg(beneficiario=beneficiario), False
    )
    assert motivo is not None
    assert "beneficiario" in motivo


def test_un_rol_con_el_nombre_del_aprobador_no_es_la_persona():
    beneficiario = "arn:aws:iam::111122223333:role/aprobador.demo"
    sep, motivo = aprobar._separacion(_aprobador_sso("aprobador.demo"), _reg(beneficiario=beneficiario), False)
    assert motivo is None


def test_el_aprobador_que_es_el_beneficiario_sigue_bloqueando():
    sep, motivo = aprobar._separacion(
        _aprobador_sso("aprobador.demo", arn_canonico=_BENEFICIARIO), _reg(), False
    )
    assert motivo is not None
    assert "Autoaprobacion" in motivo


def test_identidad_no_determinable_bloquea():
    # La direccion de la duda: dejar pasar seria un fallo silencioso del
    # control; bloquear molesta pero se ve y se puede resolver.
    sep, motivo = aprobar._separacion(_aprobador(None, False), _reg(), False)
    assert motivo is not None
    assert "separacion de funciones" in motivo


def test_el_orden_de_los_problemas_y_el_rastro_de_todos():
    # Aprobador sin persona Y solicitante sin persona: bloquea con el primero
    # y la puerta explicita graba los dos.
    aprobador = _aprobador(_APROBADOR)
    sep, motivo = aprobar._separacion(aprobador, _reg(persona=None), False)
    assert "aprobador" in motivo
    assert "solicitante" not in motivo.split(".")[0]
    sep, motivo = aprobar._separacion(aprobador, _reg(persona=None), True)
    assert motivo is None
    assert sep["resultado"] == "SALTADO"
    assert "aprobador" in sep["motivo"]
    assert "solicitante" in sep["motivo"]


def test_la_puerta_explicita_sigue_dejando_rastro():
    sep, motivo = aprobar._separacion(
        _aprobador_sso("aprobador.demo", arn_canonico=_BENEFICIARIO), _reg(), True
    )
    assert motivo is None
    assert sep["resultado"] == "SALTADO"
    assert sep["saltado_por"]
    assert sep["cuando"]
    assert "Autoaprobacion" in sep["motivo"]
    assert sep["aprobador"] == "aprobador.demo"
    assert sep["solicitante"] == "solicitante.demo"
    assert sep["beneficiario"] == _BENEFICIARIO


def test_aprobar_no_identifica_a_nadie(monkeypatch):
    # El aprobador llega inyectado: `aprobar` ya no pregunta a STS.
    monkeypatch.setattr(aprobar, "identificar_aprobador", lambda: pytest.fail("no deberia identificar"))
    monkeypatch.setattr(aprobar, "revalidar", lambda r: {"aprobable": True, "bloqueos": [], "criticos": [], "menores": []})
    monkeypatch.setattr(aprobar, "comprobar_techo", lambda doc, cuenta: {"resultado": "PASS"})
    leido = _registro(solicitante=_solicitante())
    registro, bloqueos = aprobar.aprobar(leido, _aprobador_sso(), huella_confirmada=huella.calcular(leido))
    assert bloqueos == []
    assert registro["aprobacion"]["por"]["persona"] == "aprobador.demo"
    assert registro["aprobacion"]["separacion_de_funciones"]["solicitante"] == "solicitante.demo"


def test_aprobar_la_propia_solicitud_bloquea_dentro_de_aprobar(monkeypatch):
    monkeypatch.setattr(aprobar, "revalidar", lambda r: {"aprobable": True, "bloqueos": [], "criticos": [], "menores": []})
    monkeypatch.setattr(aprobar, "comprobar_techo", lambda doc, cuenta: {"resultado": "PASS"})
    leido = _registro(solicitante=_solicitante("aprobador.demo"))
    registro, bloqueos = aprobar.aprobar(leido, _aprobador_sso(), huella_confirmada=huella.calcular(leido))
    assert registro is None
    assert any("solicitante" in b for b in bloqueos)


# ---------------------------------------------------------------------------
# Compuerta de estado
# ---------------------------------------------------------------------------


# Todos los estados del contrato menos `propuesta`, sacados de `models.Estado`:
# un estado nuevo entra aqui solo. La lista de lo aprobable la fija el test
# ("propuesta"), no `ESTADOS_APROBABLES`: si se derivara de el, colar un
# estado en la lista blanca lo sacaria tambien de esta lista y nada se
# pondria en rojo. (Hasta el 24-10-2026 eran tres listas a mano, 12 casos,
# y ninguna probaba aprobar desde `rechazada_por_aprobador`.)
_NO_APROBABLES = [e for e in get_args(models.Estado) if e != "propuesta"]


@pytest.mark.parametrize("estado", _NO_APROBABLES)
def test_solo_se_aprueba_o_rechaza_desde_propuesta(monkeypatch, estado):
    """Lo que no es una propuesta no se aprueba ni se rechaza: no hay nada
    que decidir, no se identifica a nadie y el registro leido no cambia. Con
    una decision anterior escrita, rechazar la borraria (quien aprobo,
    cuando y sobre que huella): es borrar evidencia, igual que aprobar dos
    veces. La compuerta que corta es la de estado (el motivo lo nombra)."""
    monkeypatch.setattr(aprobar, "identificar_aprobador", lambda: pytest.fail("no deberia identificar"))
    registro, bloqueos = aprobar.aprobar(_registro(estado=estado), _aprobador_sso())
    assert registro is None
    assert bloqueos
    assert estado in bloqueos[0]

    anterior = {"cuando": "antes", "huella": "sha256:x"}
    leido = _registro(estado=estado, aprobacion=dict(anterior))
    registro, bloqueos = aprobar.rechazar(leido, "tarde", _aprobador_sso())
    assert registro is None
    assert estado in bloqueos[0]
    assert leido["aprobacion"] == anterior
    assert leido["estado"] == estado
    assert "rechazo" not in leido


def test_no_se_aprueba_dos_veces():
    registro, bloqueos = aprobar.aprobar(
        _registro(aprobacion={"cuando": "ya", "huella": "sha256:x"}), _aprobador_sso()
    )
    assert registro is None


# ---------------------------------------------------------------------------
# El guardian del almacen
#
# El guardian se mudo de `cli.guardar` a `almacen.guardar_propuesta` con el
# despliegue (el runtime tiene el disco efimero). Los tests siguen probando
# el mismo comportamiento porque el comportamiento no cambio: cambio donde
# vive. Estos corren contra el backend de disco, que es el de desarrollo.
# ---------------------------------------------------------------------------


def test_guardar_se_niega_a_pisar_una_aprobacion(tmp_path, monkeypatch):
    # Volver a correr el intake con el mismo id borraria quien aprobo,
    # cuando y sobre que huella. Eso no es cambiar de estado: es borrar
    # evidencia, y sin dejar rastro de que se borro.
    monkeypatch.setattr(almacen, "DIR_SOLICITUDES", str(tmp_path))
    monkeypatch.setattr(almacen, "ALMACEN", "disco")
    aprobado = _registro(estado="aprobada", aprobacion={"cuando": "ya"})
    (tmp_path / "req-prueba.json").write_text(json.dumps(aprobado))

    with pytest.raises(almacen.RegistroExistente):
        almacen.guardar_propuesta(_registro())

    # Y el archivo sigue intacto.
    en_disco = json.loads((tmp_path / "req-prueba.json").read_text())
    assert en_disco["estado"] == "aprobada"


def test_guardar_tampoco_pisa_lo_que_no_esta_aprobado(tmp_path, monkeypatch):
    """Hasta el 24-10-2026 este test se llamaba `..._sobrescribe_lo_que_no_esta_aprobado`
    y fijaba el comportamiento que S6 cierra: una segunda corrida con el
    mismo id borraba la primera, historial y riesgo incluidos."""
    monkeypatch.setattr(almacen, "DIR_SOLICITUDES", str(tmp_path))
    monkeypatch.setattr(almacen, "ALMACEN", "disco")
    almacen.guardar_propuesta(_registro())
    with pytest.raises(almacen.RegistroExistente):
        almacen.guardar_propuesta(_registro(intentos=2))
    assert json.loads((tmp_path / "req-prueba.json").read_text())["intentos"] == 1


def test_una_decision_no_pisa_a_otra_que_llego_antes(tmp_path, monkeypatch):
    # El TOCTOU que `guardar_decision` cierra: dos aprobadores leen la misma
    # solicitud en 'propuesta', uno decide, y el segundo llega a escribir
    # sobre una decision que ya existe. Su escritura se rechaza.
    monkeypatch.setattr(almacen, "DIR_SOLICITUDES", str(tmp_path))
    monkeypatch.setattr(almacen, "ALMACEN", "disco")
    almacen.guardar_propuesta(_registro(estado="propuesta"))

    # El primero decide y escribe.
    almacen.guardar_decision(
        _registro(estado="aprobada", aprobacion={"cuando": "primero"}), "aprobacion", "propuesta",
        clave="req-prueba",
    )

    # El segundo leyo 'propuesta' y llega tarde.
    with pytest.raises(almacen.EstadoCambiado):
        almacen.guardar_decision(
            _registro(estado="rechazada_por_aprobador", rechazo={"cuando": "tarde"}),
            "rechazo",
            "propuesta",
            clave="req-prueba",
        )

    en_disco = json.loads((tmp_path / "req-prueba.json").read_text())
    assert en_disco["aprobacion"]["cuando"] == "primero"


# ---------------------------------------------------------------------------
# El hueco que nadie habia probado: la escalada a humano
# ---------------------------------------------------------------------------


def test_agotar_los_intentos_escala_a_humano(monkeypatch):
    """`requiere_revision_humana` no tenia ni un test ni una corrida en vivo.

    Forzarlo con el modelo real es poco practico —hace falta un prompt que
    lo derrote tres veces seguidas— pero es la unica rama terminal del loop
    y no puede quedarse sin cubrir. Un doble que siempre devuelve una
    propuesta bloqueada lo prueba en milisegundos.
    """
    from tests.unitarios.test_errores import _AgenteFalso, _identidad_obj

    monkeypatch.setattr(orquestador, "verificar", lambda arn: _identidad_obj())
    monkeypatch.setattr(orquestador, "construir_agente", lambda: _AgenteFalso())
    monkeypatch.setattr(orquestador, "chequeos_posteriores", lambda p, s, i: ([], []))
    monkeypatch.setattr(
        orquestador,
        "validar_politica",
        lambda doc: {
            "aprobable": False,
            "bloqueos": ["accion prohibida"],
            "criticos": [],
            "menores": [],
        },
    )

    from agente_iam.models import SolicitudEstructurada

    solicitud = SolicitudEstructurada.model_validate(
        {
            "solicitud_id": "req-escalada",
            "principal_arn_declarado": "arn:aws:iam::111122223333:user/ana.gomez",
            "campos": {
                "servicio": "s3",
                "recurso": "finanzas-2026",
                "tipo_acceso": "lectura",
                "region": "us-east-1",
            },
            "justificacion": "Necesito leer el bucket.",
        }
    )
    registro = orquestador.procesar(solicitud)

    assert registro["estado"] == "requiere_revision_humana"
    assert registro["intentos"] == MAX_INTENTOS
    # El historial conserva las tres vueltas: sin el no se puede auditar
    # por que fallo cada una.
    assert len(registro["historial_validacion"]) == MAX_INTENTOS
    # Y nunca se aprueba sola.
    assert registro["propuesta"] is not None
    assert registro["validacion"]["aprobable"] is False


def test_el_flujo_completo_deja_una_huella_que_verifica(monkeypatch):
    """El test de integracion que faltaba.

    Los tests de `huella` sola pasaban y aun asi la huella guardada no
    verificaba: el bug estaba en el ORDEN de `aprobar()`, no en la funcion.
    Probar la pieza aislada no prueba el flujo que la usa.
    """
    monkeypatch.setattr(
        aprobar,
        "revalidar",
        lambda r: {"aprobable": True, "bloqueos": [], "criticos": [], "menores": []},
    )
    monkeypatch.setattr(
        aprobar, "comprobar_techo", lambda doc, cuenta: {"resultado": "PASS"}
    )

    leido = _registro(solicitante=_solicitante())
    registro, bloqueos = aprobar.aprobar(
        leido, _aprobador_sso(), huella_confirmada=huella.calcular(leido)
    )
    assert bloqueos == []
    assert registro["estado"] == "aprobada"
    # Lo que de verdad importa: la huella guardada verifica contra el
    # registro tal y como quedo guardado.
    assert huella.coincide(registro, registro["aprobacion"]["huella"])


def test_el_riesgo_alto_exige_confirmacion(monkeypatch):
    # `nivel_riesgo` lo escribe el modelo, asi que solo puede anadir
    # friccion. Un 'alto' obliga a un gesto extra; nunca relaja nada.
    monkeypatch.setattr(
        aprobar,
        "revalidar",
        lambda r: {"aprobable": True, "bloqueos": [], "criticos": [], "menores": []},
    )
    monkeypatch.setattr(
        aprobar, "comprobar_techo", lambda doc, cuenta: {"resultado": "PASS"}
    )

    arriesgada = _registro(solicitante=_solicitante())
    arriesgada["propuesta"]["nivel_riesgo"] = "alto"

    confirmada = huella.calcular(arriesgada)
    registro, bloqueos = aprobar.aprobar(arriesgada, _aprobador_sso(), huella_confirmada=confirmada)
    assert registro is None
    assert any("Riesgo alto (lo marco el modelo)" in b for b in bloqueos)

    registro, bloqueos = aprobar.aprobar(
        arriesgada, _aprobador_sso(), riesgo_confirmado=True, huella_confirmada=confirmada
    )
    assert bloqueos == []
    assert registro["aprobacion"]["riesgo_confirmado"] is True


def test_una_propuesta_escalada_no_se_puede_aprobar():
    # La compuerta de estado y la escalada se tocan aqui: lo que el loop
    # mando a un humano no entra por la puerta de la aprobacion normal.
    registro, bloqueos = aprobar.aprobar(_registro(estado="requiere_revision_humana"), _aprobador_sso())
    assert registro is None
    assert "humano redactando" in bloqueos[0]


# ---------------------------------------------------------------------------
# Rechazar: tambien es una decision humana, y tambien se registra
# ---------------------------------------------------------------------------


def test_rechazar_deja_quien_cuando_y_por_que(monkeypatch):
    monkeypatch.setattr(aprobar, "identificar_aprobador", lambda: pytest.fail("no deberia identificar"))
    leido = _registro()
    registro, bloqueos = aprobar.rechazar(leido, "no justifica el acceso", _aprobador(_APROBADOR))
    assert bloqueos == []
    assert registro["estado"] == "rechazada_por_aprobador"
    # Bloque propio desde el 24-10-2026, no una clave dentro de `aprobacion`.
    assert "aprobacion" not in registro
    assert registro["rechazo"]["motivo"] == "no justifica el acceso"
    assert registro["rechazo"]["por"]["arn_canonico"] == _APROBADOR
    assert registro["rechazo"]["cuando"]
    # La huella es la de lo que se rechazo, y sigue verificando guardada.
    assert huella.coincide(registro, registro["rechazo"]["huella"])


def test_el_rechazo_graba_la_persona():
    registro, bloqueos = aprobar.rechazar(_registro(), "no procede", _aprobador_sso("aprobador.demo"))
    assert bloqueos == []
    assert registro["rechazo"]["por"]["persona"] == "aprobador.demo"


def test_rechazar_no_pisa_un_bloque_que_ya_existe(monkeypatch):
    """Aunque el estado diga 'propuesta' (alguien lo devolvio a mano), un
    bloque de decision ya escrito no se pisa."""
    monkeypatch.setattr(aprobar, "identificar_aprobador", lambda: pytest.fail("no deberia identificar"))
    registro, bloqueos = aprobar.rechazar(_registro(aprobacion={"cuando": "antes"}), "tarde", _aprobador_sso())
    assert registro is None
    assert "ya tiene una decision" in bloqueos[0]


# ---------------------------------------------------------------------------
# PeticionAprobacion: lo unico que entra por la URL de funcion
# ---------------------------------------------------------------------------


def test_la_peticion_valida_se_acepta_con_valores_por_defecto():
    p = models.PeticionAprobacion.model_validate({"id": "req-prueba", "accion": "aprobar"})
    assert p.huella is None
    assert p.motivo is None
    assert p.autoaprobacion_demo is False
    assert p.riesgo_alto_confirmado is False


@pytest.mark.parametrize(
    "cuerpo",
    [
        {"accion": "aprobar"},  # sin id
        {"id": "../x", "accion": "aprobar"},  # id fuera del patron
        {"id": "req-prueba", "accion": "aplicar"},  # accion que no existe
        {"id": "req-prueba", "accion": "rechazar"},  # rechazar sin motivo
        {"id": "req-prueba", "accion": "rechazar", "motivo": "   "},  # motivo en blanco
        {"id": "req-prueba", "accion": "aprobar", "estado": "aprobada"},  # campo de mas
        {"id": "req-prueba", "accion": "aprobar", "autoaprobacion_demo": "true"},  # el texto no es un booleano
        {"id": "req-prueba", "accion": "aprobar", "riesgo_alto_confirmado": 1},
    ],
)
def test_la_peticion_mal_formada_se_rechaza(cuerpo):
    with pytest.raises(ValidationError):
        models.PeticionAprobacion.model_validate(cuerpo)


# ---------------------------------------------------------------------------
# decidir: lo que hacia main() tras leer, ahora con la identidad dada
# ---------------------------------------------------------------------------


def _peticion(**campos):
    base = {"id": "req-prueba", "accion": "aprobar", "huella": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
    base.update(campos)
    return models.PeticionAprobacion.model_validate(base)


def _controles_en_verde(monkeypatch):
    monkeypatch.setattr(
        aprobar, "revalidar", lambda r: {"aprobable": True, "bloqueos": [], "criticos": [], "menores": []}
    )
    monkeypatch.setattr(aprobar, "comprobar_techo", lambda doc, cuenta: {"resultado": "PASS"})


def _escrituras(monkeypatch):
    escrito = []
    monkeypatch.setattr(
        almacen,
        "guardar_decision",
        lambda r, bloque, esperado, *, clave: escrito.append((bloque, r["estado"], esperado, clave))
        or "dynamodb://solicitudes/req-prueba",
    )
    return escrito


def _no_escribir(monkeypatch):
    def prohibido(*a, **k):
        pytest.fail("no deberia escribir")

    monkeypatch.setattr(almacen, "guardar_decision", prohibido)


def test_decidir_aprueba_y_escribe_solo_su_bloque(monkeypatch):
    _controles_en_verde(monkeypatch)
    leido = _registro(solicitante=_solicitante())
    monkeypatch.setattr(almacen, "leer", lambda sid: leido)
    escrito = _escrituras(monkeypatch)
    codigo, cuerpo = aprobar.decidir(_peticion(huella=huella.calcular(leido)), _aprobador_sso())
    # El estado esperado es el que se LEYO: `aprobar` muta el registro en sitio.
    assert escrito == [("aprobacion", "aprobada", "propuesta", "req-prueba")]
    assert codigo == 200
    assert cuerpo["resultado"] == "aprobada"
    assert cuerpo["id"] == "req-prueba"
    assert cuerpo["aprobador"]["persona"] == "aprobador.demo"
    assert cuerpo["estado"] == "aprobada"
    assert cuerpo["decision"]["por"]["persona"] == "aprobador.demo"
    assert cuerpo["decision"]["huella"] == huella.calcular(leido)
    assert cuerpo["guardado_en"] == "dynamodb://solicitudes/req-prueba"
    assert "bloqueos" not in cuerpo


def test_decidir_con_otra_huella_no_escribe(monkeypatch):
    _controles_en_verde(monkeypatch)
    monkeypatch.setattr(almacen, "leer", lambda sid: _registro(solicitante=_solicitante()))
    _no_escribir(monkeypatch)
    codigo, cuerpo = aprobar.decidir(_peticion(huella="sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), _aprobador_sso())
    assert codigo == 409
    assert cuerpo["resultado"] == "bloqueada"
    assert "huella confirmada" in cuerpo["bloqueos"][0]
    assert cuerpo["aprobador"]["persona"] == "aprobador.demo"
    assert "decision" not in cuerpo
    assert "guardado_en" not in cuerpo


def test_decidir_la_autoaprobacion_bloquea_con_su_motivo(monkeypatch):
    _controles_en_verde(monkeypatch)
    leido = _registro(solicitante=_solicitante("aprobador.demo"))
    monkeypatch.setattr(almacen, "leer", lambda sid: leido)
    _no_escribir(monkeypatch)
    codigo, cuerpo = aprobar.decidir(_peticion(huella=huella.calcular(leido)), _aprobador_sso())
    assert codigo == 409
    assert cuerpo["resultado"] == "bloqueada"
    assert "Autoaprobacion" in cuerpo["bloqueos"][0]


def test_decidir_escribe_en_el_id_pedido(monkeypatch):
    """S1: el documento dice otro id. Con el guardian REAL del almacen, la
    decision no va a ninguna de las dos filas."""
    _controles_en_verde(monkeypatch)
    leido = _registro(id="victima", solicitante=_solicitante())
    monkeypatch.setattr(almacen, "leer", lambda sid: leido)
    for interno in ("_dynamo_actualizar", "_disco_escribir"):
        monkeypatch.setattr(almacen, interno, lambda *a, **k: pytest.fail("escribio en una fila"))
    codigo, cuerpo = aprobar.decidir(_peticion(huella=huella.calcular(leido)), _aprobador_sso())
    assert codigo == 409
    assert cuerpo["resultado"] == "bloqueada"
    assert "victima" in cuerpo["bloqueos"][0]


def test_decidir_fila_inconsistente_es_409(monkeypatch):
    def inconsistente(sid):
        raise almacen.RegistroInconsistente("el documento trae aprobacion")

    monkeypatch.setattr(almacen, "leer", inconsistente)
    _no_escribir(monkeypatch)
    codigo, cuerpo = aprobar.decidir(_peticion(), _aprobador_sso())
    assert codigo == 409
    assert cuerpo["resultado"] == "bloqueada"
    assert "trae aprobacion" in cuerpo["bloqueos"][0]
    assert cuerpo["id"] == "req-prueba"
    assert cuerpo["aprobador"]["persona"] == "aprobador.demo"


def test_decidir_otra_corrida_gano_es_409(monkeypatch):
    _controles_en_verde(monkeypatch)
    leido = _registro(solicitante=_solicitante())
    monkeypatch.setattr(almacen, "leer", lambda sid: leido)

    def perdida(*a, **k):
        raise almacen.EstadoCambiado("otra corrida decidio primero")

    monkeypatch.setattr(almacen, "guardar_decision", perdida)
    codigo, cuerpo = aprobar.decidir(_peticion(huella=huella.calcular(leido)), _aprobador_sso())
    assert codigo == 409
    assert cuerpo["resultado"] == "bloqueada"
    assert "otra corrida" in cuerpo["bloqueos"][0]
    assert "decision" not in cuerpo


def test_decidir_no_existe_es_404(monkeypatch):
    monkeypatch.setattr(almacen, "leer", lambda sid: None)
    _no_escribir(monkeypatch)
    codigo, cuerpo = aprobar.decidir(_peticion(), _aprobador_sso())
    assert codigo == 404
    assert cuerpo["resultado"] == "no_existe"
    assert cuerpo["id"] == "req-prueba"
    assert cuerpo["aprobador"]["persona"] == "aprobador.demo"


def test_decidir_rechaza_con_motivo(monkeypatch):
    monkeypatch.setattr(aprobar, "aprobar", lambda *a, **k: pytest.fail("con rechazar no se aprueba"))
    monkeypatch.setattr(almacen, "leer", lambda sid: _registro())
    escrito = _escrituras(monkeypatch)
    codigo, cuerpo = aprobar.decidir(
        _peticion(accion="rechazar", motivo="no procede", huella=None), _aprobador_sso()
    )
    assert escrito == [("rechazo", "rechazada_por_aprobador", "propuesta", "req-prueba")]
    assert codigo == 200
    assert cuerpo["resultado"] == "rechazada_por_aprobador"
    assert cuerpo["decision"]["motivo"] == "no procede"
    assert cuerpo["estado"] == "rechazada_por_aprobador"


def test_decidir_rechazar_lo_ya_decidido_es_409(monkeypatch):
    monkeypatch.setattr(almacen, "leer", lambda sid: _registro(aprobacion={"cuando": "antes"}))
    _no_escribir(monkeypatch)
    codigo, cuerpo = aprobar.decidir(_peticion(accion="rechazar", motivo="tarde"), _aprobador_sso())
    assert codigo == 409
    assert cuerpo["resultado"] == "bloqueada"
    assert "ya tiene una decision" in cuerpo["bloqueos"][0]


def test_decidir_no_resuelve_la_identidad(monkeypatch):
    # La identidad llega dada: ni STS ni IAM ni el evento.
    monkeypatch.setattr(aprobar, "identificar_aprobador", lambda: pytest.fail("no deberia identificar"))
    monkeypatch.setattr(aprobar, "aprobador_desde_evento", lambda e: pytest.fail("no deberia identificar"))
    monkeypatch.setattr(almacen, "leer", lambda sid: None)
    assert aprobar.decidir(_peticion(), _aprobador_sso())[0] == 404


def test_decidir_no_escribe_si_aprobar_rompe_su_contrato(monkeypatch):
    """Fase 13 (lo marco mypy): sin bloqueos, `aprobar` siempre devuelve
    resultado. Si algun cambio lo rompe, `decidir` falla con el motivo y SIN
    escribir (el manejador lo vuelve un 500), en vez de pasar None al almacen."""
    monkeypatch.setattr(almacen, "leer", lambda sid: {"id": sid, "estado": "propuesta"})
    monkeypatch.setattr(aprobar, "aprobar", lambda *a: (None, []))
    _no_escribir(monkeypatch)
    with pytest.raises(RuntimeError, match="contrato roto"):
        aprobar.decidir(_peticion(), _aprobador_sso())


def test_decidir_sin_la_exigencia_deja_la_puerta_en_disco(monkeypatch):
    """Decision 2 solo se exige en el servidor (`exigir_persona=True`). En
    disco (desarrollo local) nadie firma con persona: sin la bandera, el
    firmante sin persona sigue siendo un problema de separacion que la puerta
    explicita puede saltar, como antes."""
    _controles_en_verde(monkeypatch)
    leido = _registro(solicitante=_solicitante())
    monkeypatch.setattr(almacen, "leer", lambda sid: leido)
    escrito = _escrituras(monkeypatch)
    sin_persona = _aprobador_sso(None)
    codigo, cuerpo = aprobar.decidir(
        _peticion(huella=huella.calcular(leido), autoaprobacion_demo=True), sin_persona
    )
    assert codigo == 200
    assert cuerpo["decision"]["separacion_de_funciones"]["resultado"] == "SALTADO"
    assert escrito == [("aprobacion", "aprobada", "propuesta", "req-prueba")]


@pytest.mark.parametrize("accion", ["aprobar", "rechazar"])
def test_decidir_exigiendo_persona_no_lee_ni_escribe_sin_ella(monkeypatch, accion):
    _sin_leer(monkeypatch)
    campos = {"accion": accion, "autoaprobacion_demo": True}
    if accion == "rechazar":
        campos.update(motivo="no procede", huella=None)
    sin_persona = _aprobador_sso(None).model_copy(update={"como_se_verifico": "evidencia-xyz"})
    codigo, cuerpo = aprobar.decidir(_peticion(**campos), sin_persona, exigir_persona=True)
    assert codigo == 409
    assert cuerpo["resultado"] == "bloqueada"
    assert "AgenteIAM-Aprobador" in cuerpo["bloqueos"][0]
    assert "evidencia-xyz" in cuerpo["bloqueos"][0]
    assert cuerpo["aprobador"]["persona"] is None


def _fila_del_servidor(**cambios) -> dict:
    """Una fila como las que escribe el runtime: del modo rol por persona."""
    fila = _registro(solicitante=_solicitante(), **cambios)
    fila["identidad_verificada"]["modo"] = "rol_por_persona"
    return fila


def test_decidir_exigiendo_persona_deja_pasar_a_quien_la_tiene(monkeypatch):
    _controles_en_verde(monkeypatch)
    leido = _fila_del_servidor()
    monkeypatch.setattr(almacen, "leer", lambda sid: leido)
    _escrituras(monkeypatch)
    codigo, _ = aprobar.decidir(_peticion(huella=huella.calcular(leido)), _aprobador_sso(), exigir_persona=True)
    assert codigo == 200


@pytest.mark.parametrize("accion", ["aprobar", "rechazar"])
def test_el_servidor_no_tiene_puerta_de_autoaprobacion(monkeypatch, accion):
    """Fase 33: `autoaprobacion_demo` es la puerta del cliente en disco. En el
    servidor, con persona y todo, la peticion que la trae se bloquea antes de
    leer: la Lambda no deja nunca una fila `aprobada` con separacion SALTADO."""
    _sin_leer(monkeypatch)
    campos = {"accion": accion, "autoaprobacion_demo": True}
    if accion == "rechazar":
        campos.update(motivo="no procede", huella=None)
    codigo, cuerpo = aprobar.decidir(_peticion(**campos), _aprobador_sso(), exigir_persona=True)
    assert codigo == 409
    assert cuerpo["resultado"] == "bloqueada"
    assert "autoaprobacion" in cuerpo["bloqueos"][0]


def test_el_servidor_no_aprueba_una_fila_del_modo_principal_existente(monkeypatch):
    """Fase 33: adjuntar a un principal que ya existe es el modo del CLI de
    desarrollo. El runtime solo escribe filas del modo rol por persona, asi que
    en el servidor una fila del otro modo no se aprueba ni se escribe."""
    _controles_en_verde(monkeypatch)
    leido = _registro(solicitante=_solicitante())
    monkeypatch.setattr(almacen, "leer", lambda sid: leido)
    escrito = _escrituras(monkeypatch)
    codigo, cuerpo = aprobar.decidir(_peticion(huella=huella.calcular(leido)), _aprobador_sso(), exigir_persona=True)
    assert codigo == 409
    assert "rol por persona" in cuerpo["bloqueos"][0]
    assert escrito == []


def test_el_servidor_si_deja_rechazar_una_fila_del_modo_principal_existente(monkeypatch):
    """Rechazarla la cierra sin conceder nada: no hay motivo para dejarla viva."""
    leido = _registro(solicitante=_solicitante())
    monkeypatch.setattr(almacen, "leer", lambda sid: leido)
    escrito = _escrituras(monkeypatch)
    codigo, _ = aprobar.decidir(
        _peticion(accion="rechazar", motivo="no procede", huella=None), _aprobador_sso(), exigir_persona=True
    )
    assert codigo == 200
    assert [e[:2] for e in escrito] == [("rechazo", "rechazada_por_aprobador")]


# ---------------------------------------------------------------------------
# manejador: la puerta de la Lambda
# ---------------------------------------------------------------------------


@pytest.fixture
def entorno_sano(monkeypatch):
    """DynamoDB como almacen y catalogos cargables, con la cache de arranque limpia."""
    monkeypatch.setattr(aprobar, "_problemas_entorno", None)
    monkeypatch.setattr(almacen, "ALMACEN", "dynamodb")
    monkeypatch.setattr(catalogo, "no_disponibles", lambda servicios: [])


def _evento_post(cuerpo=None, **cambios):
    datos = {"user_arn": _ARN_SSO, "user_id": _USER_ID_SSO}
    datos.update(cambios)
    cuerpo = {"id": "req-prueba", "accion": "aprobar", "huella": "sha256:0000000000000000000000000000000000000000000000000000000000000000"} if cuerpo is None else cuerpo
    return _evento(body=cuerpo if isinstance(cuerpo, str) else json.dumps(cuerpo), **datos)


def _identidad_dada(monkeypatch, aprobador=None):
    monkeypatch.setattr(aprobar, "aprobador_desde_evento", lambda e: aprobador or _aprobador_sso())


def _sin_leer(monkeypatch):
    monkeypatch.setattr(almacen, "leer", lambda sid: pytest.fail("no deberia leer"))
    _no_escribir(monkeypatch)


def test_manejador_solo_post(entorno_sano, monkeypatch):
    _sin_leer(monkeypatch)
    for metodo in ("GET", "PUT", "DELETE"):
        r = aprobar.manejador(_evento_post(metodo=metodo), None)
        assert r["statusCode"] == 405, metodo
    sin_metodo = _evento_post()
    del sin_metodo["requestContext"]["http"]
    assert aprobar.manejador(sin_metodo, None)["statusCode"] == 405


@pytest.mark.parametrize(
    "cuerpo",
    [
        "no es json",
        "[]",
        '"texto"',
        {"id": "req-prueba"},
        {"id": "../x", "accion": "aprobar"},
        {"id": "req-prueba", "accion": "rechazar"},
        {"id": "req-prueba", "accion": "aprobar", "estado": "aprobada"},
    ],
)
def test_manejador_cuerpo_invalido_o_con_campos_de_mas_es_400(entorno_sano, monkeypatch, cuerpo):
    _identidad_dada(monkeypatch)
    _sin_leer(monkeypatch)
    r = aprobar.manejador(_evento_post(cuerpo), None)
    assert r["statusCode"] == 400


@pytest.mark.parametrize(
    "cuerpo",
    [
        # Una huella con la forma de las nuestras y nada mas: sin esto, texto
        # no ASCII o enorme llegaba hasta la comparacion (y a un 500).
        {"id": "req-prueba", "accion": "aprobar", "huella": "sha256:\u00e9" + "0" * 63},
        {"id": "req-prueba", "accion": "aprobar", "huella": "sha256:" + "0" * 64 + "\n"},
        {"id": "req-prueba", "accion": "aprobar", "huella": "sha256:" + "A" * 64},
        {"id": "req-prueba", "accion": "aprobar", "huella": "sha256:x"},
        {"id": "req-prueba", "accion": "aprobar", "huella": "x" * 100000},
        {"id": "req-prueba", "accion": "rechazar", "motivo": "m" * 2001},
        # Un JSON anidado hasta el infinito rompe el parser con RecursionError.
        "[" * 100000,
        '{"id": ' * 100000,
    ],
)
def test_manejador_campos_fuera_de_contrato_son_400_y_no_leen(entorno_sano, monkeypatch, cuerpo):
    _identidad_dada(monkeypatch)
    _sin_leer(monkeypatch)
    r = aprobar.manejador(_evento_post(cuerpo), None)
    assert r["statusCode"] == 400, r["body"]


def test_manejador_un_motivo_de_2000_y_una_huella_buena_pasan_el_contrato(entorno_sano, monkeypatch):
    _identidad_dada(monkeypatch)
    monkeypatch.setattr(almacen, "leer", lambda sid: None)
    por_motivo = {"id": "req-prueba", "accion": "rechazar", "motivo": "m" * 2000}
    assert aprobar.manejador(_evento_post(por_motivo), None)["statusCode"] == 404
    por_huella = {"id": "req-prueba", "accion": "aprobar", "huella": "sha256:" + "0123456789abcdef" * 4}
    assert aprobar.manejador(_evento_post(por_huella), None)["statusCode"] == 404


def test_manejador_sin_cuerpo_es_400(entorno_sano, monkeypatch):
    _identidad_dada(monkeypatch)
    _sin_leer(monkeypatch)
    evento = _evento_post()
    del evento["body"]
    assert aprobar.manejador(evento, None)["statusCode"] == 400


def test_manejador_el_400_no_devuelve_lo_que_se_envio(entorno_sano, monkeypatch):
    _identidad_dada(monkeypatch)
    _sin_leer(monkeypatch)
    r = aprobar.manejador(_evento_post({"id": "req-prueba", "accion": "x", "secreto": "SALE?"}), None)
    assert r["statusCode"] == 400
    assert "SALE?" not in r["body"]


@pytest.mark.parametrize(
    "evento",
    [
        _evento(user_arn=_ARN_SSO, user_id=_USER_ID_SSO, authorizer=None, body='{"id":"req-prueba","accion":"aprobar"}'),
        _evento(user_arn=_ARN_SSO, user_id=_USER_ID_SSO, authorizer="falta", body='{"id":"req-prueba","accion":"aprobar"}'),
        _evento(user_arn=_ARN_SSO, user_id=_USER_ID_SSO, authorizer={"iam": "x"}, body='{"id":"req-prueba","accion":"aprobar"}'),
        _evento(user_arn=_ARN_SSO, body='{"id":"req-prueba","accion":"aprobar"}'),
        _evento(user_id=_USER_ID_SSO, body='{"id":"req-prueba","accion":"aprobar"}'),
        _evento(user_arn="", user_id=_USER_ID_SSO, body='{"id":"req-prueba","accion":"aprobar"}'),
        _evento(user_arn=123, user_id=_USER_ID_SSO, body='{"id":"req-prueba","accion":"aprobar"}'),
        _evento(user_arn=_ARN_SSO, user_id=["x"], body='{"id":"req-prueba","accion":"aprobar"}'),
        _evento(user_arn=_ARN_SSO, user_id=_USER_ID_SSO, cuenta_llamante=None, body='{"id":"req-prueba","accion":"aprobar"}'),
        _evento(user_arn=_ARN_SSO, user_id=_USER_ID_SSO, cuenta_llamante=111122223333, body='{"id":"req-prueba","accion":"aprobar"}'),
    ],
)
def test_manejador_sin_identidad_firmada_es_400_y_no_lee(entorno_sano, monkeypatch, evento):
    monkeypatch.setattr(aprobar, "decidir", lambda *a, **k: pytest.fail("no deberia decidir"))
    _sin_leer(monkeypatch)
    assert aprobar.manejador(evento, None)["statusCode"] == 400


def test_manejador_identidad_no_determinable_llega_a_decidir_y_bloquea(entorno_sano, monkeypatch):
    # R3: solo la identidad AUSENTE es 400. Una federada esta firmada pero no
    # es comparable: la separacion la bloquea con su motivo (409).
    _controles_en_verde(monkeypatch)
    leido = _registro(solicitante=_solicitante())
    monkeypatch.setattr(almacen, "leer", lambda sid: leido)
    _no_escribir(monkeypatch)
    evento = _evento_post(
        {"id": "req-prueba", "accion": "aprobar", "huella": huella.calcular(leido)},
        user_arn="arn:aws:sts::111122223333:federated-user/alguien",
        user_id="AIDAEJEMPLO:alguien",
    )
    r = aprobar.manejador(evento, None)
    cuerpo = json.loads(r["body"])
    assert r["statusCode"] == 409
    assert cuerpo["resultado"] == "bloqueada"
    assert "AgenteIAM-Aprobador" in cuerpo["bloqueos"][0]
    assert cuerpo["aprobador"]["como_se_verifico"] in cuerpo["bloqueos"][0]
    assert cuerpo["aprobador"]["determinable"] is False


def _firmante_sin_persona_no_decide(monkeypatch, accion):
    """Decision 2 (aceptada): en el servidor solo decide el permission set
    AgenteIAM-Aprobador. Un administrador con permiso de invocar no aprueba ni
    rechaza, ni siquiera con `autoaprobacion_demo`; y no se lee ni se escribe."""
    _identidad_dada(monkeypatch, _aprobador_sso(None).model_copy(update={"como_se_verifico": "evidencia-xyz"}))
    _sin_leer(monkeypatch)
    cuerpo = {"id": "req-prueba", "accion": accion, "autoaprobacion_demo": True}
    if accion == "aprobar":
        cuerpo["huella"] = "sha256:" + "0" * 64
    else:
        cuerpo["motivo"] = "no procede"
    r = aprobar.manejador(_evento_post(cuerpo), None)
    salida = json.loads(r["body"])
    assert r["statusCode"] == 409
    assert salida["resultado"] == "bloqueada"
    assert "AgenteIAM-Aprobador" in salida["bloqueos"][0]
    assert "evidencia-xyz" in salida["bloqueos"][0]
    assert salida["aprobador"]["persona"] is None
    assert "decision" not in salida


def test_un_firmante_sin_persona_no_aprueba_ni_con_la_puerta(entorno_sano, monkeypatch):
    _firmante_sin_persona_no_decide(monkeypatch, "aprobar")


def test_un_firmante_sin_persona_no_rechaza(entorno_sano, monkeypatch):
    _firmante_sin_persona_no_decide(monkeypatch, "rechazar")


def test_manejador_pasa_la_peticion_y_el_aprobador_a_decidir(entorno_sano, monkeypatch):
    aprobador = _aprobador_sso()
    _identidad_dada(monkeypatch, aprobador)
    vistos = []

    def decidir(peticion, quien, *, exigir_persona):
        vistos.append((peticion, quien, exigir_persona))
        return 200, {"id": peticion.id, "resultado": "aprobada", "aprobador": quien.model_dump()}

    monkeypatch.setattr(aprobar, "decidir", decidir)
    cuerpo = {"id": "req-prueba", "accion": "aprobar", "huella": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "riesgo_alto_confirmado": True}
    r = aprobar.manejador(_evento_post(cuerpo), None)
    assert r["statusCode"] == 200
    assert r["headers"] == {"content-type": "application/json"}
    assert json.loads(r["body"])["aprobador"]["persona"] == "aprobador.demo"
    assert vistos[0][0].huella == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert vistos[0][0].riesgo_alto_confirmado is True
    assert vistos[0][1] is aprobador
    assert vistos[0][2] is True  # decision 2: en el servidor siempre se exige la persona


def test_manejador_devuelve_el_codigo_de_decidir(entorno_sano, monkeypatch):
    _identidad_dada(monkeypatch)
    monkeypatch.setattr(almacen, "leer", lambda sid: None)
    r = aprobar.manejador(_evento_post(), None)
    assert r["statusCode"] == 404
    assert json.loads(r["body"])["resultado"] == "no_existe"


def test_manejador_cuerpo_en_base64(entorno_sano, monkeypatch):
    _identidad_dada(monkeypatch)
    monkeypatch.setattr(almacen, "leer", lambda sid: None)
    evento = _evento_post()
    evento["body"] = base64.b64encode(evento["body"].encode()).decode()
    evento["isBase64Encoded"] = True
    assert aprobar.manejador(evento, None)["statusCode"] == 404
    evento["body"] = "%%%no-es-base64%%%"
    assert aprobar.manejador(evento, None)["statusCode"] == 400


def test_manejador_sin_dynamodb_es_500_y_no_escribe(entorno_sano, monkeypatch):
    monkeypatch.setattr(almacen, "ALMACEN", "disco")
    _sin_leer(monkeypatch)
    monkeypatch.setattr(aprobar, "aprobador_desde_evento", lambda e: pytest.fail("no deberia identificar"))
    r = aprobar.manejador(_evento_post(), None)
    assert r["statusCode"] == 500
    assert "dynamodb" in r["body"]


def test_manejador_sin_catalogo_es_500_y_no_escribe(entorno_sano, monkeypatch):
    monkeypatch.setattr(catalogo, "no_disponibles", lambda servicios: ["s3"])
    _sin_leer(monkeypatch)
    r = aprobar.manejador(_evento_post(), None)
    assert r["statusCode"] == 500
    assert "s3" in r["body"]


def test_manejador_comprueba_el_entorno_una_vez_por_arranque(entorno_sano, monkeypatch):
    llamadas = []
    monkeypatch.setattr(catalogo, "no_disponibles", lambda servicios: llamadas.append(1) or [])
    _identidad_dada(monkeypatch)
    monkeypatch.setattr(almacen, "leer", lambda sid: None)
    for _ in range(3):
        assert aprobar.manejador(_evento_post(), None)["statusCode"] == 404
    assert len(llamadas) == 1


def test_manejador_error_inesperado_es_500_con_su_tipo(entorno_sano, monkeypatch):
    _identidad_dada(monkeypatch)

    def roto(sid):
        raise KeyError("dato secreto del registro")

    monkeypatch.setattr(almacen, "leer", roto)
    r = aprobar.manejador(_evento_post(), None)
    assert r["statusCode"] == 500
    assert "KeyError" in r["body"]
    assert "dato secreto" not in r["body"]


def test_manejador_responde_en_ascii(entorno_sano, monkeypatch):
    _identidad_dada(monkeypatch)
    monkeypatch.setattr(
        aprobar, "decidir", lambda p, a, **k: (409, {"id": p.id, "resultado": "bloqueada", "bloqueos": ["a\u202eb ñ"]})
    )
    r = aprobar.manejador(_evento_post(), None)
    assert "\\u202e" in r["body"]
    assert r["body"].isascii()
    assert json.loads(r["body"])["bloqueos"] == ["a\u202eb ñ"]


def test_manejador_no_registra_la_clave_de_acceso(entorno_sano, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    _identidad_dada(monkeypatch)
    monkeypatch.setattr(almacen, "leer", lambda sid: None)
    evento = _evento_post()
    evento["requestContext"]["authorizer"]["iam"]["accessKey"] = "AKIAEJEMPLOSECRETA"
    r = aprobar.manejador(evento, None)
    assert "AKIA" not in caplog.text
    assert "AKIA" not in r["body"]


def test_manejador_deja_una_linea_por_peticion(entorno_sano, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    _identidad_dada(monkeypatch)
    monkeypatch.setattr(almacen, "leer", lambda sid: _registro(solicitante=_solicitante("x")))
    aprobar.manejador(_evento_post(), None)
    lineas = [r.getMessage() for r in caplog.records if r.name.startswith("agente-iam")]
    assert len(lineas) == 1
    for dato in ("req-prueba", "aprobar", _ARN_SSO, _USER_ID_SSO, "111122223333", "409"):
        assert dato in lineas[0], dato
    # Nada del registro: ni la justificacion ni la propuesta.
    assert "Necesito leer el bucket" not in lineas[0]
    assert "S3Lectura" not in lineas[0]


def test_manejador_el_error_inesperado_deja_traza_en_el_log(entorno_sano, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    _identidad_dada(monkeypatch)
    monkeypatch.setattr(almacen, "leer", lambda sid: (_ for _ in ()).throw(RuntimeError("boom")))
    aprobar.manejador(_evento_post(), None)
    registros = [r for r in caplog.records if r.name.startswith("agente-iam")]
    assert len(registros) == 1
    assert registros[0].levelno == logging.ERROR
    assert registros[0].exc_info[0] is RuntimeError


# ---------------------------------------------------------------------------
# Fase 23: el modo rol por persona pasa por los mismos controles
# ---------------------------------------------------------------------------

_ROL_PERSONA = "arn:aws:iam::111122223333:role/agente-iam/personas/agente-iam-persona-solicitante-demo-req-1"


def _registro_persona(servicio_propuesta: str = "s3") -> dict:
    """Un registro del modo persona: sin ARN declarado, beneficiario = el rol
    previsto, solicitante = la persona del token."""
    solicitud = _solicitud_persona(servicio="s3", recurso="finanzas-demo-111122223333")
    ident = models.IdentidadVerificada(
        principal_arn=_ROL_PERSONA,
        tipo="role",
        existe=False,
        cuenta="111122223333",
        modo="rol_por_persona",
        persona=solicitud.persona,
        horas=solicitud.horas,
    )
    if servicio_propuesta == "s3":
        propuesta = _propuesta(
            ["s3:GetObject"],
            ["arn:aws:s3:::finanzas-demo-111122223333/*"],
            principal=_ROL_PERSONA,
            condicion={"StringEquals": {"aws:ResourceAccount": "${aws:PrincipalAccount}"}},
        )
    else:
        propuesta = _propuesta(
            [f"{servicio_propuesta}:ListFunctions"], ["*"], principal=_ROL_PERSONA
        )
    return _registro(
        solicitud=solicitud.model_dump(mode="json", exclude_none=True),
        identidad_verificada=ident.model_dump(mode="json"),
        propuesta=propuesta.model_dump(mode="json", exclude_none=True),
        solicitante=_solicitante("solicitante.demo"),
    )


def _sin_red(monkeypatch) -> None:
    monkeypatch.setattr(
        aprobar,
        "validar_politica",
        lambda doc: {"aprobable": True, "bloqueos": [], "criticos": [], "menores": []},
    )
    monkeypatch.setattr(aprobar, "comprobar_techo", lambda doc, cuenta: {"resultado": "PASS"})
    # El nivel de acceso sale del catalogo; sin cache (el CI) lo bajaria de internet.
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: False)


def test_aprobar_en_modo_persona_separa_a_aprobador_y_solicitante_y_pasa(monkeypatch):
    _sin_red(monkeypatch)

    leido = _registro_persona()
    registro, bloqueos = aprobar.aprobar(leido, _aprobador_sso("aprobador.demo"), huella_confirmada=huella.calcular(leido))
    assert bloqueos == []
    assert registro["estado"] == "aprobada"
    sep = registro["aprobacion"]["separacion_de_funciones"]
    assert sep["resultado"] == "cumplido"
    assert sep["beneficiario"] == _ROL_PERSONA
    assert sep["aprobador"] == "aprobador.demo"
    assert sep["solicitante"] == "solicitante.demo"
    assert registro["aprobacion"]["revalidacion"]["aprobable"] is True

    # La misma persona pidio y aprueba: autoaprobacion, aunque el beneficiario
    # sea un rol que nadie mas tiene.
    propio = _registro_persona()
    registro, bloqueos = aprobar.aprobar(
        propio, _aprobador_sso("solicitante.demo"), huella_confirmada=huella.calcular(propio)
    )
    assert registro is None
    assert any("Autoaprobacion" in b for b in bloqueos)


def test_revalidar_en_modo_persona_juzga_el_formulario_y_la_propuesta(monkeypatch):
    _sin_red(monkeypatch)

    assert aprobar.revalidar(_registro_persona())["aprobable"] is True

    # El formulario pide s3 y la propuesta concede otro servicio.
    veredicto = aprobar.revalidar(_registro_persona(servicio_propuesta="lambda"))
    assert veredicto["aprobable"] is False
    assert any("solo puedes conceder acciones del servicio solicitado" in b.lower() for b in veredicto["bloqueos"])

    # Una propuesta que apunta a otro rol que el previsto tampoco pasa.
    otro = _registro_persona()
    otro["propuesta"]["principal_arn"] = "arn:aws:iam::111122223333:role/agente-iam/personas/otro"
    assert aprobar.revalidar(otro)["aprobable"] is False

    # El formulario guardado se vuelve a juzgar: un servicio fuera de la lista.
    fuera = _registro_persona()
    fuera["solicitud"]["campos"]["servicio"] = "iam"
    assert aprobar.revalidar(fuera)["aprobable"] is False
