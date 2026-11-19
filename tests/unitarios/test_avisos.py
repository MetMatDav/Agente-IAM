"""La Lambda de avisos (`agente_iam/avisos.py`): un correo por cambio de estado.

Sin red: el cliente de SES es un `Stubber`. Lo que fijan estos tests es lo que
importa del aviso: que salga una vez por cambio de estado y con el cuerpo fijo
(id, estado y, en `aplicada`, rol y vencimiento), que un correo rechazado por
SES no rompa el circuito, que cualquier otro fallo suba para que se reintente
y que el log no lleve nunca el correo entero.
"""

import json
import logging

import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from agente_iam import avisos, motivos
from tests.dobles import _cliente

_REMITENTE = "avisos@example.com"
_CORREO = "persona.demo@example.com"
_ROL = "arn:aws:iam::111122223333:role/agente-iam/personas/agente-iam-persona-demo-req-20261026-aaaaaaaa"
_VENCE = "2026-10-26T15:04:51Z"


def _imagen(solicitud_id="req-20261026-aaaaaaaa", estado="aplicada", correo=_CORREO, aplicacion=None) -> dict:
    """La fila de DynamoDB con la forma del stream (atributos tipados)."""
    imagen = {"id": {"S": solicitud_id}, "estado": {"S": estado}}
    if correo is not None:
        imagen["documento"] = {"S": json.dumps({"solicitud": {"correo_aviso": correo, "justificacion": "secreta"}})}
    if aplicacion is not None:
        imagen["aplicacion"] = {"S": json.dumps(aplicacion)}
    return imagen


def _evento(nueva, vieja=None, event_name="MODIFY") -> dict:
    cambio = {"Keys": {"id": nueva["id"]}, "NewImage": nueva}
    if vieja is not None:
        cambio["OldImage"] = vieja
    return {"Records": [{"eventName": event_name, "dynamodb": cambio}]}


@pytest.fixture
def ses(monkeypatch):
    cliente = _cliente("ses")
    stub = Stubber(cliente)
    monkeypatch.setattr(avisos, "_ses", lambda: cliente)
    monkeypatch.setattr(avisos, "REMITENTE", _REMITENTE)
    with stub:
        yield stub
    # Ninguna respuesta programada se queda sin usar.
    stub.assert_no_pending_responses()


def test_el_cuerpo_lleva_solo_id_estado_y_en_aplicada_rol_y_vence():
    aplicacion = {
        "rol_arn": _ROL,
        "vence": _VENCE,
        "por": "aplicador-secreto",
        "documento_aplicado": {"Statement": [{"Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket-secreto/*"}]},
    }
    asunto, cuerpo = avisos.cuerpo_del_correo("req-1", "aplicada", aplicacion)
    assert asunto == "Agente IAM: solicitud req-1 aplicada"
    assert cuerpo == (
        f"Solicitud req-1: aplicada. {avisos.FRASES['aplicada']}\n"
        f"Rol: {_ROL}\n"
        f"Vence: {_VENCE} (UTC)"
    )
    for ajeno in ("aplicador-secreto", "documento_aplicado", "s3:GetObject", "bucket-secreto", "Statement"):
        assert ajeno not in cuerpo

    # Un estado distinto de aplicada no lleva rol ni vencimiento, aunque se le pase un bloque.
    asunto, cuerpo = avisos.cuerpo_del_correo(
        "req-2", "aprobada", {"rol_arn": _ROL, "vence": _VENCE, "sha256": "abc", "por": "Maria Perez"}
    )
    assert asunto == "Agente IAM: solicitud req-2 aprobada"
    assert cuerpo == f"Solicitud req-2: aprobada. {avisos.FRASES['aprobada']}"
    for ajeno in ("sha256", "Maria", "Perez", "Rol:", "Vence:", _ROL):
        assert ajeno not in cuerpo

    # Una aplicada sin rol o sin vencimiento no inventa lineas.
    _, sin_vence = avisos.cuerpo_del_correo("req-3", "aplicada", {"rol_arn": _ROL})
    assert "Rol:" not in sin_vence
    assert "Vence:" not in sin_vence
    _, sin_bloque = avisos.cuerpo_del_correo("req-4", "aplicada", None)
    assert sin_bloque == f"Solicitud req-4: aplicada. {avisos.FRASES['aplicada']}"


def test_hay_una_frase_por_estado_que_avisa_y_sin_acentos():
    assert set(avisos.FRASES) == set(avisos.ESTADOS_QUE_AVISAN)
    assert "propuesta" not in avisos.ESTADOS_QUE_AVISAN
    for frase in avisos.FRASES.values():
        assert frase.isascii()


def test_las_piezas_del_evento_toleran_lo_que_falta():
    assert avisos.estado_de(None) is None
    assert avisos.estado_de({}) is None
    assert avisos.estado_de(_imagen(estado="aplicada")) == "aplicada"
    assert avisos.id_de(_imagen(solicitud_id="req-9")) == "req-9"
    assert avisos.correo_de(_imagen()) == _CORREO
    assert avisos.correo_de(None) is None
    assert avisos.correo_de(_imagen(correo=None)) is None
    assert avisos.correo_de({"documento": {"S": "no es json"}}) is None
    assert avisos.correo_de({"documento": {"S": "[1, 2]"}}) is None
    assert avisos.correo_de({"documento": {"S": json.dumps({"solicitud": []})}}) is None
    assert avisos.correo_de({"documento": {"S": json.dumps({"solicitud": {}})}}) is None
    assert avisos.aplicacion_de(_imagen()) is None
    assert avisos.aplicacion_de(_imagen(aplicacion={"rol_arn": _ROL})) == {"rol_arn": _ROL}
    assert avisos.aplicacion_de({"aplicacion": {"S": "no es json"}}) is None


def test_un_cambio_de_estado_a_aplicada_manda_un_correo_con_expected_params(ses):
    aplicacion = {"rol_arn": _ROL, "vence": _VENCE}
    motivo = motivos.motivo_publico({"estado": "aplicada", "aplicacion": aplicacion})["texto"]
    asunto, cuerpo = avisos.cuerpo_del_correo("req-20261026-aaaaaaaa", "aplicada", aplicacion, motivo=motivo)
    ses.add_response(
        "send_email",
        {"MessageId": "x"},
        expected_params={
            "Source": _REMITENTE,
            "Destination": {"ToAddresses": [_CORREO]},
            "Message": {
                "Subject": {"Data": asunto, "Charset": "UTF-8"},
                "Body": {"Text": {"Data": cuerpo, "Charset": "UTF-8"}},
            },
        },
    )
    nueva = _imagen(estado="aplicada", aplicacion=aplicacion)
    vieja = _imagen(estado="aprobada")
    salida = avisos.manejador(_evento(nueva, vieja), None)
    assert salida == {"avisados": ["req-20261026-aaaaaaaa"], "omitidos": []}


def test_un_modify_sin_cambio_de_estado_no_manda_nada(ses):
    # El Stubber no tiene respuestas: si se llamara a send_email, reventaria.
    nueva = _imagen(estado="aplicada", aplicacion={"rol_arn": _ROL, "vence": _VENCE})
    vieja = _imagen(estado="aplicada")
    salida = avisos.manejador(_evento(nueva, vieja), None)
    assert salida == {"avisados": [], "omitidos": [["req-20261026-aaaaaaaa", "sin_cambio_de_estado"]]}


def test_propuesta_no_avisa(ses):
    nueva = _imagen(estado="propuesta")
    salida = avisos.manejador(_evento(nueva, None, "INSERT"), None)
    assert salida == {"avisados": [], "omitidos": [["req-20261026-aaaaaaaa", "estado_no_avisa"]]}


def test_sin_correo_se_omite(ses):
    nueva = _imagen(estado="aprobada", correo=None)
    salida = avisos.manejador(_evento(nueva, _imagen(estado="propuesta")), None)
    assert salida == {"avisados": [], "omitidos": [["req-20261026-aaaaaaaa", "sin_correo"]]}


def test_un_remove_se_omite_con_su_motivo(ses):
    nueva = _imagen(estado="aplicada")
    salida = avisos.manejador(_evento(nueva, None, "REMOVE"), None)
    assert salida == {"avisados": [], "omitidos": [["req-20261026-aaaaaaaa", "evento_REMOVE"]]}


@pytest.mark.parametrize(
    "estado", ["rechazada_en_chequeos_previos", "requiere_revision_humana", "redundante_no_requiere_cambio"]
)
def test_un_estado_que_decide_el_intake_no_manda_correo(ses, estado):
    """Fase 33: `correo_aviso` lo escribe quien pide y nadie lo compara con su
    identidad. Si el alta de una solicitud mandara correo, cualquier persona
    con sesion haria que el sistema escribiera a un tercero sin que nadie mas
    interviniera. Solo avisan los estados que siguen a una decision humana
    (el aprobador ve la direccion). El resultado del intake ya sale en la
    respuesta del servidor. Sin respuesta programada: un envio romperia el doble."""
    nueva = _imagen(estado=estado)
    salida = avisos.manejador(_evento(nueva, None, "INSERT"), None)
    assert salida == {"avisados": [], "omitidos": [["req-20261026-aaaaaaaa", "estado_no_avisa"]]}


def test_solo_avisan_los_estados_que_siguen_a_una_decision_humana():
    assert set(avisos.ESTADOS_QUE_AVISAN) == {
        "aprobada", "rechazada_por_aprobador", "aplicada", "bloqueada_al_aplicar",
    }


@pytest.mark.parametrize("codigo", ["MessageRejected", "MailFromDomainNotVerified"])
def test_message_rejected_no_relanza(ses, caplog, codigo):
    ses.add_client_error("send_email", codigo)
    nueva = _imagen(estado="aprobada")
    with caplog.at_level(logging.INFO, logger="agente-iam.avisos"):
        salida = avisos.manejador(_evento(nueva, _imagen(estado="propuesta")), None)
    assert salida == {"avisados": [], "omitidos": [["req-20261026-aaaaaaaa", codigo]]}
    avisos_warning = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(avisos_warning) == 1
    texto = avisos_warning[0].getMessage()
    for esperado in ("req-20261026-aaaaaaaa", codigo, "example.com"):
        assert esperado in texto
    assert _CORREO not in caplog.text


def test_otro_error_de_ses_sube(ses):
    ses.add_client_error("send_email", "Throttling")
    nueva = _imagen(estado="aprobada")
    with pytest.raises(ClientError) as e:
        avisos.manejador(_evento(nueva, _imagen(estado="propuesta")), None)
    assert e.value.response["Error"]["Code"] == "Throttling"


def test_sin_remitente_no_arranca(monkeypatch):
    monkeypatch.setattr(avisos, "REMITENTE", "")

    def _no_debe_llamarse():
        raise AssertionError("no debe construir el cliente de SES sin remitente")

    monkeypatch.setattr(avisos, "_ses", _no_debe_llamarse)
    with pytest.raises(RuntimeError, match="AGENTE_IAM_REMITENTE no esta definido"):
        avisos.manejador({"Records": []}, None)


def test_el_log_no_lleva_el_correo_entero(ses, caplog):
    ses.add_response("send_email", {"MessageId": "x"})
    nueva = _imagen(estado="aprobada")
    with caplog.at_level(logging.INFO, logger="agente-iam.avisos"):
        avisos.manejador(_evento(nueva, _imagen(estado="propuesta")), None)
    assert "example.com" in caplog.text
    assert "persona.demo" not in caplog.text
    assert _CORREO not in caplog.text
    assert "secreta" not in caplog.text  # ni la justificacion del documento
    assert "Solicitud req-" not in caplog.text  # ni el cuerpo del correo


def test_un_lote_mezcla_avisados_y_omitidos(ses):
    ses.add_response("send_email", {"MessageId": "x"})
    a = _imagen(solicitud_id="req-a", estado="aprobada")
    b = _imagen(solicitud_id="req-b", estado="propuesta")
    registros = _evento(a, _imagen("req-a", "propuesta"))["Records"] + _evento(b, None, "INSERT")["Records"]
    salida = avisos.manejador({"Records": registros}, None)
    assert salida == {"avisados": ["req-a"], "omitidos": [["req-b", "estado_no_avisa"]]}


# --- Fase 28: el motivo y el enlace -------------------------------------------


def test_el_correo_lleva_el_motivo_del_estado_y_no_la_frase_general(ses):
    nueva = _imagen(estado="bloqueada_al_aplicar")
    asunto, cuerpo = avisos.cuerpo_del_correo(
        "req-20261026-aaaaaaaa", "bloqueada_al_aplicar", None,
        motivo=motivos.motivo_publico({"estado": "bloqueada_al_aplicar"})["texto"],
    )
    assert "Algo cambio entre la aprobacion y la aplicacion" in cuerpo
    assert avisos.FRASES["bloqueada_al_aplicar"] not in cuerpo
    ses.add_response(
        "send_email",
        {"MessageId": "x"},
        expected_params={
            "Source": _REMITENTE,
            "Destination": {"ToAddresses": [_CORREO]},
            "Message": {
                "Subject": {"Data": asunto, "Charset": "UTF-8"},
                "Body": {"Text": {"Data": cuerpo, "Charset": "UTF-8"}},
            },
        },
    )
    salida = avisos.manejador(_evento(nueva, None), None)
    assert salida["avisados"] == ["req-20261026-aaaaaaaa"]


def test_aplicada_lleva_el_enlace_con_el_id_si_hay_url_de_la_pagina():
    _, cuerpo = avisos.cuerpo_del_correo(
        "req-1", "aplicada", {"rol_arn": _ROL, "vence": _VENCE}, url_web="https://agente-iam.example.org/"
    )
    assert cuerpo.endswith("\nCredenciales: https://agente-iam.example.org/?solicitud=req-1")
    _, sin_url = avisos.cuerpo_del_correo("req-1", "aplicada", {"rol_arn": _ROL, "vence": _VENCE})
    assert "Credenciales" not in sin_url
    _, otro = avisos.cuerpo_del_correo("req-1", "aprobada", None, url_web="https://agente-iam.example.org")
    assert "Credenciales" not in otro


def test_registro_de_junta_documento_estado_y_bloques():
    nueva = _imagen(estado="aplicada", aplicacion={"rol_arn": _ROL, "vence": _VENCE})
    registro = avisos.registro_de(nueva)
    assert registro["estado"] == "aplicada"
    assert registro["aplicacion"] == {"rol_arn": _ROL, "vence": _VENCE}
    assert registro["solicitud"]["correo_aviso"] == _CORREO
    assert avisos.registro_de(None) == {}
    assert avisos.registro_de({"documento": {"S": "no es json"}, "rechazo": {"S": "[1]"}}) == {}
