"""Las compuertas en negativo: que digan que NO cuando toca.

Hasta el 22-10-2026 cada compuerta de `aprobar` y la tool `validar_politica`
solo se probaban por el lado bueno: en los tests de aprobacion,
`comprobar_techo` devolvia siempre PASS y `revalidar` siempre aprobable, y
`validar_politica` no se ejecutaba nunca (siempre era un doble). Se podia
borrar el bloqueo de cualquiera de ellas y la bateria seguia en verde.

Aqui cada test se pone en rojo si se quita la linea que bloquea. Ninguno
toca la red: Access Analyzer e IAM van con `Stubber`, y el catalogo con
monkeypatch.
"""

import json

import pytest
from botocore.stub import Stubber

from agente_iam import aprobar, coherencia, huella, orquestador
from agente_iam.herramientas import validacion
from agente_iam.models import IdentidadVerificada
from tests.dobles import (
    _ANA,
    _APROBADOR,
    _BENEFICIARIO,
    _aprobador,
    _aprobador_sso,
    _cliente,
    _propuesta,
    _registro,
    _solicitante,
    _solicitud,
)

_PASA = {"aprobable": True, "bloqueos": [], "criticos": [], "menores": []}


# --- aprobar: las tres compuertas que van despues de la huella ---------------


@pytest.fixture
def aprobable(monkeypatch):
    """Todo en regla salvo lo que cada test rompa."""
    monkeypatch.setattr(aprobar, "revalidar", lambda r: dict(_PASA))
    monkeypatch.setattr(aprobar, "comprobar_techo", lambda doc, cuenta: {"resultado": "PASS"})
    leido = _registro(solicitante=_solicitante())
    return leido, huella.calcular(leido)


def test_el_control_aprueba_si_todo_esta_en_regla(aprobable):
    # El caso de control: sin el, los tests de abajo podrian estar en verde
    # porque la fixture ya bloqueaba por otra cosa.
    leido, vista = aprobable
    registro, bloqueos = aprobar.aprobar(leido, _aprobador_sso(), huella_confirmada=vista)
    assert bloqueos == []
    assert registro["estado"] == "aprobada"


@pytest.mark.parametrize("resultado", ["FAIL", None])
def test_check_no_new_access_distinto_de_pass_no_aprueba(aprobable, monkeypatch, resultado):
    # None: una respuesta sin `result`. La compuerta exige PASS, no "que no
    # diga FAIL"; con `== "FAIL"` el caso None pasaria.
    leido, vista = aprobable
    monkeypatch.setattr(
        aprobar, "comprobar_techo",
        lambda doc, cuenta: {"resultado": resultado, "mensaje": "concede s3:DeleteBucket"},
    )
    registro, bloqueos = aprobar.aprobar(leido, _aprobador_sso(), huella_confirmada=vista)
    assert registro is None
    assert any("CheckNoNewAccess" in b and "concede s3:DeleteBucket" in b for b in bloqueos)
    assert leido["estado"] == "propuesta"
    assert "aprobacion" not in leido


def test_no_poder_ejecutar_check_no_new_access_no_es_pasarlo(aprobable, monkeypatch):
    leido, vista = aprobable

    def revienta(doc, cuenta):
        raise RuntimeError("AccessDenied en access-analyzer:CheckNoNewAccess")

    monkeypatch.setattr(aprobar, "comprobar_techo", revienta)
    registro, bloqueos = aprobar.aprobar(leido, _aprobador_sso(), huella_confirmada=vista)
    assert registro is None
    assert any("No se pudo ejecutar CheckNoNewAccess" in b for b in bloqueos)


def test_lo_que_no_pasa_las_barandas_de_hoy_no_se_aprueba(aprobable, monkeypatch):
    leido, vista = aprobable
    monkeypatch.setattr(
        aprobar, "revalidar",
        lambda r: {**_PASA, "aprobable": False, "bloqueos": ["la accion 's3:*' es un comodin"]},
    )
    registro, bloqueos = aprobar.aprobar(leido, _aprobador_sso(), huella_confirmada=vista)
    assert registro is None
    assert any("NO pasa las barandas de hoy" in b and "'s3:*'" in b for b in bloqueos)


@pytest.mark.parametrize("quien", ["beneficiario", "indeterminable", "solicitante"])
def test_la_separacion_de_funciones_bloquea_dentro_de_aprobar(aprobable, quien):
    """`_separacion` tiene sus tests, pero ninguno comprobaba que `aprobar`
    hiciera caso de su veredicto: se podia borrar el `bloqueos.append` y la
    bateria seguia en verde."""
    leido, vista = aprobable
    if quien == "beneficiario":
        aprobador = _aprobador_sso("aprobador.demo", arn_canonico=_BENEFICIARIO)
    elif quien == "solicitante":
        aprobador = _aprobador_sso("solicitante.demo")
    else:
        aprobador = _aprobador(None, False)
    registro, bloqueos = aprobar.aprobar(leido, aprobador, huella_confirmada=vista)
    assert registro is None
    assert any("separacion de funciones" in b or "Autoaprobacion" in b for b in bloqueos)


def test_un_registro_que_ya_trae_bloque_de_aprobacion_no_se_aprueba(aprobable):
    """Un 'propuesta' con bloque de aprobacion no sale del flujo normal
    (alguien escribio el registro). La huella no cubre ese bloque, asi que
    la confirmacion cuadra igual; aprobar encima borraria lo que hubiera."""
    # De la fixture solo interesan sus dobles: el registro es otro.
    anterior = {"cuando": "antes", "por": {"arn_canonico": "otro"}}
    leido = _registro(aprobacion=dict(anterior))
    registro, bloqueos = aprobar.aprobar(leido, _aprobador_sso(), huella_confirmada=huella.calcular(leido))
    assert registro is None
    assert "ya tiene una decision" in bloqueos[0]
    assert leido["aprobacion"] == anterior
    assert leido["estado"] == "propuesta"


def test_un_registro_que_ya_trae_un_rechazo_no_se_aprueba(aprobable):
    """El rechazo es bloque propio desde el 24-10-2026: aprobar encima de
    uno convertiria un no en un si, con el estado devuelto a mano."""
    anterior = {"cuando": "antes", "motivo": "no", "por": {"arn_canonico": "otro"}}
    leido = _registro(rechazo=dict(anterior))
    registro, bloqueos = aprobar.aprobar(leido, _aprobador_sso(), huella_confirmada=huella.calcular(leido))
    assert registro is None
    assert "ya tiene una decision" in bloqueos[0]
    assert leido["rechazo"] == anterior
    assert "aprobacion" not in leido


# --- revalidar y comprobar_techo, sin dobles de si mismas --------------------


def test_revalidar_suma_los_chequeos_posteriores(monkeypatch):
    """Access Analyzer y la lista negra dan el visto bueno, pero la politica
    va dirigida a otra persona: `revalidar` tiene que decir que no."""
    aa = _cliente("accessanalyzer")
    monkeypatch.setattr(validacion, "_cliente", aa)
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: False)
    registro = _registro()
    registro["propuesta"]["principal_arn"] = _APROBADOR  # destinatario cambiado
    with Stubber(aa) as stub:
        stub.add_response("validate_policy", {"findings": []})
        veredicto = aprobar.revalidar(registro)
        stub.assert_no_pending_responses()
    assert veredicto["aprobable"] is False
    assert any("destinatario" in b for b in veredicto["bloqueos"])


def test_comprobar_techo_compara_la_propuesta_contra_el_techo(monkeypatch):
    """La propuesta es la NUEVA y el techo la EXISTENTE. Al reves, la
    pregunta seria "¿el techo concede algo que la propuesta no?" y la
    compuerta diria PASS a casi cualquier cosa. El resultado se transmite
    tal cual, sin redondear a PASS."""
    aa = _cliente("accessanalyzer")
    monkeypatch.setattr(aprobar, "_aa_cliente", aa)
    techo = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]}
    monkeypatch.setattr(aprobar, "techo", lambda cuenta: (techo, "prueba"))
    propuesta = _registro()["propuesta"]["policy_document"]
    with Stubber(aa) as stub:
        stub.add_response(
            "check_no_new_access",
            {"result": "FAIL", "message": "nuevo acceso", "reasons": [{"description": "d", "statementIndex": 0}]},
            {"newPolicyDocument": json.dumps(propuesta),
             "existingPolicyDocument": json.dumps(techo),
             "policyType": "IDENTITY_POLICY"},
        )
        r = aprobar.comprobar_techo(propuesta, "111122223333")
    assert r["resultado"] == "FAIL"
    assert r["motivos"] == [{"descripcion": "d", "indices": 0}]


# --- validar_politica: la tool que el modelo usa y el aprobador repite -------


@pytest.fixture
def analyzer(monkeypatch):
    aa = _cliente("accessanalyzer")
    monkeypatch.setattr(validacion, "_cliente", aa)
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    with Stubber(aa) as stub:
        yield stub
        stub.assert_no_pending_responses()


_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::finanzas-2026/*"]}],
}


def _hallazgo(tipo: str, codigo: str) -> dict:
    return {"findingType": tipo, "issueCode": codigo, "findingDetails": "d",
            "learnMoreLink": "https://example.com", "locations": []}


def _validar(doc=_DOC) -> dict:
    return validacion.validar_politica(json.dumps(doc))


def test_validar_politica_limpia_es_aprobable(analyzer):
    analyzer.add_response(
        "validate_policy", {"findings": []},
        {"policyDocument": json.dumps(_DOC), "policyType": "IDENTITY_POLICY"},
    )
    assert _validar() == {"aprobable": True, "bloqueos": [], "criticos": [], "menores": []}


def test_json_invalido_no_es_aprobable(analyzer):
    # Ni siquiera llega a Access Analyzer (el Stubber no tiene respuestas).
    r = validacion.validar_politica('{"Statement": [')
    assert r["aprobable"] is False
    assert "no es JSON valido" in r["bloqueos"][0]


@pytest.mark.parametrize("tipo", ["ERROR", "SECURITY_WARNING"])
def test_un_hallazgo_critico_impide_aprobar(analyzer, tipo):
    analyzer.add_response("validate_policy", {"findings": [_hallazgo(tipo, "X")]})
    r = _validar()
    assert r["aprobable"] is False
    assert r["criticos"] == [{"tipo": tipo, "codigo": "X", "detalle": "d"}]
    assert r["menores"] == []


def test_una_sugerencia_no_impide_aprobar(analyzer):
    analyzer.add_response(
        "validate_policy",
        {"findings": [_hallazgo("SUGGESTION", "EMPTY_ARRAY"), _hallazgo("WARNING", "W")]},
    )
    r = _validar()
    assert r["aprobable"] is True
    assert [m["tipo"] for m in r["menores"]] == ["SUGGESTION", "WARNING"]
    assert r["criticos"] == []


def test_si_access_analyzer_falla_no_es_aprobable(analyzer):
    """Fail-closed: no haber podido validar no es haber validado."""
    analyzer.add_client_error("validate_policy", service_error_code="AccessDeniedException")
    r = _validar()
    assert r["aprobable"] is False
    assert any("No se pudo ejecutar Access Analyzer" in b for b in r["bloqueos"])


def test_la_lista_negra_bloquea_aunque_access_analyzer_calle(analyzer):
    analyzer.add_response("validate_policy", {"findings": []})
    doc = {"Version": "2012-10-17",
           "Statement": [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": ["arn:aws:iam::111122223333:role/x"]}]}
    r = _validar(doc)
    assert r["aprobable"] is False
    assert any("prohibida" in b for b in r["bloqueos"])


# --- orquestador: lo que el loop no puede dar por bueno ----------------------

_ARN_ANA = _ANA
_TECHO = "arn:aws:iam::111122223333:policy/AgenteIAM-Techo"


def _identidad() -> IdentidadVerificada:
    return IdentidadVerificada(principal_arn=_ARN_ANA, tipo="user", existe=True,
                               cuenta="111122223333", principal_id="AIDAANA", permissions_boundary=_TECHO)


class _AgenteFijo:
    """Siempre la misma propuesta, sin Bedrock."""

    def __call__(self, mensaje, structured_output_model=None):
        return type("R", (), {"structured_output": _propuesta()})()


_EFECTIVA = {"acciones_efectivas": ["s3:GetObject"], "acciones_condicionales": [], "acciones_sin_efecto": [],
             "claves_sin_resolver": [], "concede_algo": True, "no_evaluable": False}


@pytest.fixture
def intake(monkeypatch):
    """`procesar` sin red: todo en regla salvo lo que cada test rompa."""
    monkeypatch.setattr(orquestador, "verificar", lambda arn: _identidad())
    monkeypatch.setattr(orquestador, "construir_agente", _AgenteFijo)
    monkeypatch.setattr(orquestador, "validar_politica", lambda doc: {**_PASA, "bloqueos": [], "menores": []})
    monkeypatch.setattr(orquestador, "chequeos_posteriores", lambda p, s, i: ([], []))
    monkeypatch.setattr(orquestador, "documento_de_politica", lambda arn: {"Statement": []})
    monkeypatch.setattr(orquestador, "eficacia", lambda doc, ctx=None, boundary=None: dict(_EFECTIVA))
    monkeypatch.setattr(orquestador, "redundancia", lambda arn, doc, ctx=None: {
        "ya_tenia": [], "acceso_nuevo": ["s3:GetObject"], "es_totalmente_redundante": False})
    return monkeypatch


def test_el_control_del_intake_propone(intake):
    assert orquestador.procesar(_solicitud())["estado"] == "propuesta"


def test_un_servicio_no_permitido_se_rechaza_antes_del_modelo(intake):
    intake.setattr(orquestador, "construir_agente", lambda: pytest.fail("no debia llegar al modelo"))
    registro = orquestador.procesar(_solicitud("iam"))
    assert registro["estado"] == "rechazada_en_chequeos_previos"
    assert any("servicios permitidos" in m for m in registro["motivos"])


def test_los_chequeos_posteriores_bloquean_dentro_del_loop(intake):
    """Access Analyzer y la lista negra dicen que si, pero la propuesta no
    es la que se pidio: tras agotar los intentos va a un humano."""
    intake.setattr(orquestador, "chequeos_posteriores",
                   lambda p, s, i: (["Statement 0: otro destinatario"], []))
    registro = orquestador.procesar(_solicitud())
    assert registro["estado"] == "requiere_revision_humana"
    assert "Statement 0: otro destinatario" in registro["historial_validacion"][-1]["veredicto"]["bloqueos"]


def test_una_politica_que_no_concede_nada_no_se_propone(intake):
    intake.setattr(orquestador, "eficacia", lambda doc, ctx=None, boundary=None: {
        **_EFECTIVA, "acciones_efectivas": [], "acciones_sin_efecto": ["s3:GetObject"], "concede_algo": False})
    registro = orquestador.procesar(_solicitud())
    assert registro["estado"] == "requiere_revision_humana"
    assert any("no concede ninguna" in b for b in registro["historial_validacion"][-1]["veredicto"]["bloqueos"])



# --- S8 (24-10-2026): revalidar vuelve a juzgar el formulario ----------------


@pytest.fixture
def revalidacion_sin_red(monkeypatch):
    """Access Analyzer y el catalogo con dobles: solo queda el codigo."""
    monkeypatch.setattr(validacion, "_analyzer", lambda: type("AA", (), {
        "validate_policy": lambda self, **kw: {"findings": []}})())
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: None)


def _con_formulario(servicio, recurso, tipo, accion, arn) -> dict:
    registro = _registro()
    registro["solicitud"]["campos"].update(servicio=servicio, recurso=recurso, tipo_acceso=tipo)
    registro["propuesta"]["policy_document"]["Statement"] = [
        {"Effect": "Allow", "Action": [accion], "Resource": [arn]}]
    return registro


def test_revalidar_bloquea_un_servicio_no_permitido(revalidacion_sin_red):
    """Con `servicio: kms` en el documento, las acciones de kms eran "del
    servicio pedido" y el nivel quedaba en duda: `aprobable`."""
    registro = _con_formulario("kms", "clave-x", "administracion", "kms:ScheduleKeyDeletion",
                               "arn:aws:kms:us-east-1:111122223333:key/clave-x")
    veredicto = aprobar.revalidar(registro)
    assert veredicto["aprobable"] is False
    assert any("servicios permitidos" in b for b in veredicto["bloqueos"])


@pytest.mark.parametrize("servicio,recurso,tipo,motivo", [
    ("ec2", "todas-las-instancias", "escritura", "solo se concede para lectura"),
    ("s3", "agente-iam-paquete-111122223333", "lectura", "es del propio sistema"),
    ("dynamodb", "table", "lectura", "palabra del formato de ARN"),
])
def test_revalidar_repite_los_chequeos_del_formulario(revalidacion_sin_red, servicio, recurso, tipo, motivo):
    registro = _con_formulario(servicio, recurso, tipo, f"{servicio}:Algo", "*")
    veredicto = aprobar.revalidar(registro)
    assert veredicto["aprobable"] is False
    assert any(motivo in b for b in veredicto["bloqueos"]), veredicto["bloqueos"]


def test_revalidar_no_revienta_con_un_registro_fuera_de_contrato(revalidacion_sin_red):
    """S9: un `NotResource` ya no valida. Antes de capturarlo, el aplicador
    moria con una traza; ahora es un bloqueo con motivo."""
    registro = _registro()
    registro["propuesta"]["policy_document"]["Statement"][0]["NotResource"] = ["*"]
    veredicto = aprobar.revalidar(registro)
    assert veredicto["aprobable"] is False
    assert "contrato" in veredicto["bloqueos"][0]


# --- S1 + S4 de punta a punta: una aprobacion que no escribio el aprobador ---


def test_una_aprobacion_dentro_del_documento_no_llega_al_aplicador(monkeypatch):
    """El escenario de S1: el runtime escribe `documento` con su propia
    `aprobacion` (huella calculada por el) y `estado = aprobada`, sin el
    atributo `aprobacion`. Hasta el 24-10-2026 `leer` la devolvia y el
    pre-vuelo pasaba. Ahora `leer` para, y el aplicador sale con 3."""
    import sys

    from agente_iam import aplicador, almacen

    registro = _registro()
    documento = {k: v for k, v in registro.items() if k != "estado"}
    documento["aprobacion"] = {"huella": huella.calcular(registro), "por": {"arn_canonico": "inventado"}}
    fila = {"id": "req-prueba", "documento": json.dumps(documento), "estado": "aprobada"}
    monkeypatch.setattr(almacen, "ALMACEN", "dynamodb")
    monkeypatch.setattr(almacen, "_tabla", type("T", (), {"get_item": lambda self, **kw: {"Item": fila}})())
    monkeypatch.setattr(aplicador, "aplicar", lambda r: pytest.fail("no debia llegar a aplicar"))
    monkeypatch.setattr(sys, "argv", ["aplicador", "req-prueba"])
    with pytest.raises(SystemExit) as salida:
        aplicador.main()
    assert salida.value.code == 3


def test_una_aprobacion_escrita_a_mano_sin_los_controles_no_se_aplica(monkeypatch):
    """El escenario de S4: un UpdateItem directo con la huella y el estado,
    con la separacion SALTADA, el techo en FAIL y el riesgo sin confirmar."""
    from agente_iam import aplicador

    registro = _registro()
    registro["propuesta"]["nivel_riesgo"] = "alto"
    registro["aprobacion"] = {
        "huella": huella.calcular(registro), "por": {"arn_canonico": _BENEFICIARIO},
        "separacion_de_funciones": {"resultado": "SALTADO"}, "techo": {"resultado": "FAIL"},
        "riesgo_confirmado": False,
    }
    registro["estado"] = "aprobada"
    monkeypatch.setattr(aplicador, "revalidar", lambda r: dict(_PASA))
    monkeypatch.setattr(aplicador, "_identidad_actual", lambda c: pytest.fail("bloquea antes de leer IAM"))
    _, bloqueos, _ = aplicador.prevuelo(registro)
    assert len(bloqueos) == 3, bloqueos
