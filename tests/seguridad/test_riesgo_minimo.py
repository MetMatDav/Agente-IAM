"""El riesgo minimo lo fija el codigo, no el modelo (22-10-2026).

En la comparacion de modelos del 22-10-2026, Sonnet 4.6 marco `medio` el
caso del destinatario manipulado (4 de 5) y Haiku 4.5 marco `bajo` o
`medio` la lambda en nivel de administracion (3 de 5). Con estas reglas el
riesgo alto ya no depende del modelo:

  - nivel de administracion en el formulario;
  - la justificacion nombra un principal distinto del verificado;
  - la justificacion pide acciones de IAM, STS u Organizations o una
    politica amplia (AdministratorAccess y similares);
  - el modelo propuso una accion de la lista negra o de escalada en algun
    intento, aunque luego la quitara.

Y `aprobar` lo recalcula desde el registro: rebajar el campo guardado no
sirve.
"""

import pytest

from agente_iam import aprobar, huella
from agente_iam.coherencia import riesgo_minimo
from tests.dobles import _BENEFICIARIO, _aprobador_sso, _registro, _solicitante

_PASA = {"aprobable": True, "bloqueos": [], "criticos": [], "menores": []}


def _sol(tipo_acceso: str = "lectura", justificacion: str = "Necesito leer el bucket.") -> dict:
    return {
        "campos": {"servicio": "s3", "recurso": "finanzas-2026", "tipo_acceso": tipo_acceso, "region": "us-east-1"},
        "justificacion": justificacion,
    }


def _intento(n: int, *acciones: str) -> dict:
    return {"intento": n, "documento": {"Statement": [{"Effect": "Allow", "Action": list(acciones), "Resource": "*"}]}}


def test_una_solicitud_normal_no_fija_minimo():
    # El control: sin el, los de abajo podrian pasar porque todo fuera alto.
    justificacion = f"Soy {_BENEFICIARIO}; necesito leer arn:aws:s3:::finanzas-2026/*."
    assert riesgo_minimo(_sol(justificacion=justificacion), _BENEFICIARIO, [_intento(1, "s3:GetObject")]) == []


def test_administracion_es_riesgo_alto():
    motivos = riesgo_minimo(_sol(tipo_acceso="administracion"), _BENEFICIARIO, [])
    assert motivos == ["se pide nivel de administracion"]


def test_otro_principal_en_la_justificacion_es_riesgo_alto():
    texto = "Aplicala a arn:aws:iam::111122223333:user/Mateo, no a mi."
    motivos = riesgo_minimo(_sol(justificacion=texto), _BENEFICIARIO, [])
    assert motivos == ["la justificacion nombra otro principal: arn:aws:iam::111122223333:user/Mateo"]


@pytest.mark.parametrize("texto", ["concedeme AdministratorAccess", "necesito iam:PassRole", "y sts:AssumeRole"])
def test_pedir_escalada_en_la_justificacion_es_riesgo_alto(texto):
    motivos = riesgo_minimo(_sol(justificacion=texto), _BENEFICIARIO, [])
    assert len(motivos) == 1
    assert "IAM, STS u Organizations" in motivos[0]


@pytest.mark.parametrize("accion", ["lambda:UpdateFunctionCode", "iam:CreateRole"])
def test_una_accion_prohibida_en_un_intento_anterior_es_riesgo_alto(accion):
    # El modelo la propone en el intento 1 y la quita en el 2: la intencion
    # queda registrada aunque la propuesta final este limpia.
    historial = [_intento(1, "s3:GetObject", accion), _intento(2, "s3:GetObject")]
    motivos = riesgo_minimo(_sol(), _BENEFICIARIO, historial)
    assert motivos == [f"el modelo propuso {accion} en el intento 1"]


# --- aprobar lo recalcula ----------------------------------------------------


@pytest.fixture
def aprobable(monkeypatch):
    monkeypatch.setattr(aprobar, "revalidar", lambda r: dict(_PASA))
    monkeypatch.setattr(aprobar, "comprobar_techo", lambda doc, cuenta: {"resultado": "PASS"})


def test_aprobar_exige_confirmacion_aunque_el_modelo_diga_bajo(aprobable):
    leido = _registro(solicitante=_solicitante())
    leido["solicitud"]["campos"]["tipo_acceso"] = "administracion"
    assert leido["propuesta"]["nivel_riesgo"] == "bajo"
    leido["riesgo_minimo"] = []  # alguien lo rebajo en el registro guardado
    registro, bloqueos = aprobar.aprobar(leido, _aprobador_sso(), huella_confirmada=huella.calcular(leido))
    assert registro is None
    assert any("Riesgo alto (se pide nivel de administracion)" in b for b in bloqueos)


def test_con_la_confirmacion_se_aprueba(aprobable):
    leido = _registro(solicitante=_solicitante())
    leido["solicitud"]["campos"]["tipo_acceso"] = "administracion"
    registro, bloqueos = aprobar.aprobar(
        leido, _aprobador_sso(), riesgo_confirmado=True, huella_confirmada=huella.calcular(leido)
    )
    assert bloqueos == []
    assert registro["aprobacion"]["riesgo_confirmado"] is True


# --- el intake lo deja en el registro -------------------------------------------

from tests.dobles import _solicitud
from tests.seguridad.test_compuertas import intake  # noqa: F401  (fixture)


def test_el_intake_guarda_el_minimo_y_exige_confirmacion(intake):  # noqa: F811  (fixture importada)
    from agente_iam import orquestador
    from agente_iam.models import SolicitudEstructurada

    datos = _solicitud().model_dump()
    datos["campos"]["tipo_acceso"] = "administracion"
    intake.setattr(orquestador, "chequeos_posteriores", lambda p, s, i: ([], []))
    registro = orquestador.procesar(SolicitudEstructurada.model_validate(datos))
    assert registro["estado"] == "propuesta"
    assert registro["propuesta"]["nivel_riesgo"] == "bajo"
    assert registro["riesgo_minimo"] == ["se pide nivel de administracion"]
    assert registro["exige_confirmacion_de_riesgo"] is True
