"""Fase 7b.1: el aplicador. Cada rama del pre-vuelo y las tres decisiones.

Ninguno toca la red. El aplicador es la unica pieza con credenciales de
escritura, asi que es la que mas barato sale probar en seco y la que mas
caro sale probar en caliente.
"""

import json
import urllib.parse

import pytest
from botocore.stub import Stubber

from agente_iam import aplicador, config, huella, personas
from tests.dobles import _cliente, _solicitud_persona
from tests.dobles import _registro as _registro_base

_CUENTA = "111122223333"
_ARN = f"arn:aws:iam::{_CUENTA}:user/jose.torres"
_ID = "AIDAJOSETORRES123456"
_TECHO = f"arn:aws:iam::{_CUENTA}:policy/AgenteIAM-Techo"

_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::finanzas-2026/*"],
        }
    ],
}


def _registro(**cambios) -> dict:
    """El registro de tests/dobles.py ya aprobado: con su id, el UserId que
    el aplicador vuelve a confirmar y el bloque que deja `aprobar`."""
    base = _registro_base(id="req-jose", creada="2026-08-30T10:00:00+00:00", estado="aprobada")
    base["solicitud"]["solicitud_id"] = "req-jose"
    base["identidad_verificada"]["principal_id"] = _ID
    base["propuesta"]["policy_document"] = _DOC
    base.update(cambios)
    base["aprobacion"] = cambios.get(
        "aprobacion",
        {
            "cuando": "2026-08-30T11:00:00+00:00",
            "huella": huella.calcular(base),
            "por": {"arn_canonico": f"arn:aws:iam::{_CUENTA}:user/Mateo"},
            # Lo que `aprobar` deja escrito cuando aprueba de verdad; el
            # aplicador lo exige desde el 24-10-2026 (S4).
            "separacion_de_funciones": {"beneficiario": _ARN, "resultado": "cumplido"},
            "techo": {"resultado": "PASS"},
            "riesgo_confirmado": False,
        },
    )
    return base


@pytest.fixture
def iam(monkeypatch):
    cliente = _cliente("iam")
    stub = Stubber(cliente)
    monkeypatch.setattr(aplicador, "_cliente", cliente)
    # La revalidacion tiene su propia bateria de tests; aqui se neutraliza
    # para que cada test pruebe UNA rama del pre-vuelo.
    monkeypatch.setattr(
        aplicador,
        "revalidar",
        lambda r: {"aprobable": True, "bloqueos": [], "criticos": [], "menores": []},
    )
    # CheckNoNewAccess repetido por el aplicador (S4): tiene sus tests abajo.
    monkeypatch.setattr(aplicador, "comprobar_techo", lambda doc, cuenta: {"resultado": "PASS"})
    with stub:
        yield stub
        stub.assert_no_pending_responses()


def _respuesta_usuario(user_id=_ID, boundary=_TECHO):
    usuario = {
        "Path": "/",
        "UserName": "jose.torres",
        "UserId": user_id,
        "Arn": _ARN,
        "CreateDate": "2026-01-01T00:00:00Z",
    }
    if boundary:
        usuario["PermissionsBoundary"] = {
            "PermissionsBoundaryType": "Policy",
            "PermissionsBoundaryArn": boundary,
        }
    return {"User": usuario}


def _programar_lectura_del_principal(stub, **kwargs):
    stub.add_response("get_user", _respuesta_usuario(**kwargs), {"UserName": "jose.torres"})
    stub.add_response(
        "list_attached_user_policies",
        {"AttachedPolicies": []},
        {"UserName": "jose.torres"},
    )


# ---------------------------------------------------------------------------
# Nombre determinista: de el depende toda la idempotencia
# ---------------------------------------------------------------------------


def test_el_nombre_es_determinista_y_en_minusculas():
    # Los nombres de IAM no distinguen mayusculas pero nuestro alfabeto de
    # ids si, asi que dos ids distintos derivarian el mismo nombre. Se
    # normaliza para que la colision sea visible, no accidental.
    assert aplicador.nombre_de_politica("req-005") == "agente-iam-req-005"
    assert aplicador.nombre_de_politica("REQ-005") == "agente-iam-req-005"


def test_el_nombre_cabe_en_el_limite_de_iam():
    # solicitud_id llega a 64 caracteres y el limite de PolicyName es 128.
    assert len(aplicador.nombre_de_politica("x" * 64)) <= 128


# ---------------------------------------------------------------------------
# Pre-vuelo: cada rama por separado
# ---------------------------------------------------------------------------


def test_solo_se_aplica_desde_aprobada(iam):
    _, bloqueos, _ = aplicador.prevuelo(_registro(estado="propuesta"))
    assert "propuesta" in bloqueos[0]


def test_aprobacion_y_rechazo_a_la_vez_no_se_aplica(iam):
    """El flujo normal no lo produce (las dos escrituras se excluyen): si
    aparece, alguien escribio a mano, y la duda no se aplica."""
    registro = _registro(rechazo={"cuando": "ya", "motivo": "no"})
    _, bloqueos, _ = aplicador.prevuelo(registro)
    assert "aprobacion y rechazo" in bloqueos[0]


def test_una_fila_ya_decidida_con_estado_reescrito_no_se_aplica_en_el_cli(iam):
    """`aplicacion` o `rechazo` ya escritos: un 'aprobada' encima no sale del
    flujo normal y el pre-vuelo lo bloquea."""
    _, bloqueos, _ = aplicador.prevuelo(_registro(aplicacion={"decision": "crear", "policy_arn": "x"}))
    assert "ya lleva una decision" in bloqueos[0]
    _, bloqueos, _ = aplicador.prevuelo(_registro(rechazo={"cuando": "ya", "motivo": "no"}))
    assert bloqueos
    assert "rechazo" in bloqueos[0]


def test_sin_bloque_de_aprobacion_no_se_aplica(iam):
    registro = _registro()
    del registro["aprobacion"]
    _, bloqueos, _ = aplicador.prevuelo(registro)
    assert "bloque de aprobacion" in bloqueos[0]


def test_la_huella_manipulada_para_todo(iam):
    registro = _registro()
    # Alguien anade una accion despues de que el humano aprobara.
    registro["propuesta"]["policy_document"]["Statement"][0]["Action"].append(
        "s3:DeleteObject"
    )
    _, bloqueos, _ = aplicador.prevuelo(registro)
    assert "huella NO cuadra" in bloqueos[0]
    # Y no llego a mirar AWS siquiera: el Stubber lo confirma al no tener
    # respuestas pendientes ni haber recibido llamadas.


def test_principal_recreado_con_el_mismo_arn_se_detecta(iam):
    # La ventana que cierra `principal_id`: mismo nombre, mismo ARN, otra
    # entidad. Lo unico que lo distingue es el id que asigna IAM.
    _programar_lectura_del_principal(iam, user_id="AIDAOTRODISTINTO9999")
    _, bloqueos, _ = aplicador.prevuelo(_registro())
    assert "NO es la misma entidad" in bloqueos[0]


def test_registro_sin_principal_id_no_se_puede_probar(iam):
    # Aprobado antes de que el campo existiera: no se puede demostrar que
    # sea la misma entidad, asi que la duda bloquea.
    registro = _registro()
    registro["identidad_verificada"]["principal_id"] = ""
    registro["aprobacion"]["huella"] = huella.calcular(registro)
    _programar_lectura_del_principal(iam)
    _, bloqueos, _ = aplicador.prevuelo(registro)
    assert "antes de que existiera" in bloqueos[0]


def test_sin_el_techo_puesto_no_se_aplica(iam):
    _programar_lectura_del_principal(iam, boundary=None)
    _, bloqueos, _ = aplicador.prevuelo(_registro())
    assert "permission boundary" in bloqueos[0]


def test_la_cuota_avisa_pero_no_bloquea(iam, monkeypatch):
    # La cuota por defecto puede estar ampliada, asi que el pre-vuelo no
    # puede ser autoritativo. La respuesta de verdad es el LimitExceeded
    # del Attach, y ese no se reintenta.
    iam.add_response("get_user", _respuesta_usuario(), {"UserName": "jose.torres"})
    iam.add_response(
        "list_attached_user_policies",
        {"AttachedPolicies": [{"PolicyName": f"p{i}"} for i in range(10)]},
        {"UserName": "jose.torres"},
    )
    _, bloqueos, avisos = aplicador.prevuelo(_registro())
    assert bloqueos == []
    assert avisos
    assert "LimitExceeded" in avisos[0]


def test_prevuelo_limpio(iam):
    _programar_lectura_del_principal(iam)
    actual, bloqueos, avisos = aplicador.prevuelo(_registro())
    assert bloqueos == []
    assert avisos == []
    assert actual["principal_id"] == _ID


# ---------------------------------------------------------------------------
# Las tres decisiones
# ---------------------------------------------------------------------------


def _observado(documento=None, descripcion="agente-iam | solicitud=req-jose | huella=x"):
    return {
        "arn": aplicador.arn_de_politica(_CUENTA, "req-jose"),
        "existe": True,
        "documento": documento if documento is not None else _DOC,
        "descripcion": descripcion,
        "adjuntas": 0,
    }


def test_decision_crear_si_no_existe():
    accion, _ = aplicador.decidir({"existe": False}, _DOC, "req-jose")
    assert accion == "crear"


def test_decision_adjuntar_si_existe_identica():
    # El reintento converge aqui: la corrida anterior creo y murio antes de
    # adjuntar. Mismo codigo, sin rama especial de reintento.
    accion, _ = aplicador.decidir(_observado(), _DOC, "req-jose")
    assert accion == "adjuntar"


def test_el_orden_de_las_claves_no_cambia_la_decision():
    # AWS devuelve el documento con otro orden de claves; comparar textos
    # crudos daria "distinto" y pararia una aplicacion correcta.
    reordenado = json.loads(json.dumps(_DOC))
    reordenado["Statement"][0] = dict(
        reversed(list(reordenado["Statement"][0].items()))
    )
    accion, _ = aplicador.decidir(_observado(reordenado), _DOC, "req-jose")
    assert accion == "adjuntar"


def test_decision_parar_si_el_documento_difiere():
    otro = json.loads(json.dumps(_DOC))
    otro["Statement"][0]["Action"] = ["s3:*"]
    accion, motivo = aplicador.decidir(_observado(otro), _DOC, "req-jose")
    assert accion == "parar"
    assert "DISTINTO" in motivo


def test_decision_parar_si_la_procedencia_no_cuadra():
    # Mismo nombre y mismo documento, pero creada para otra solicitud. Dos
    # solicitudes pueden producir el mismo documento; lo que prueba la
    # procedencia es la Description, que es inmutable.
    accion, motivo = aplicador.decidir(
        _observado(descripcion="agente-iam | solicitud=req-otra | huella=y"),
        _DOC,
        "req-jose",
    )
    assert accion == "parar"
    assert "descripcion no la atribuye" in motivo


# ---------------------------------------------------------------------------
# Reintento: solo lo que mejora esperando
# ---------------------------------------------------------------------------


def test_no_se_reintenta_lo_que_no_mejora_esperando():
    from botocore.exceptions import ClientError

    intentos = []

    def falla():
        intentos.append(1)
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "AttachUserPolicy"
        )

    with pytest.raises(ClientError):
        aplicador._con_reintento(falla)
    assert len(intentos) == 1, "AccessDenied no se reintenta: esperar no concede nada"


def test_si_se_reintenta_la_consistencia_eventual(monkeypatch):
    from botocore.exceptions import ClientError

    # Sin esperar de verdad: era 1 s de los ~3,6 de toda la bateria.
    esperas = []
    monkeypatch.setattr(aplicador.time, "sleep", esperas.append)
    intentos = []

    def falla_una_vez():
        intentos.append(1)
        if len(intentos) == 1:
            raise ClientError(
                {"Error": {"Code": "NoSuchEntity", "Message": "todavia no"}},
                "AttachUserPolicy",
            )
        return "ok"

    assert aplicador._con_reintento(falla_una_vez, intentos=3) == "ok"
    assert len(intentos) == 2
    assert esperas == [1.0]


def test_main_no_escribe_si_aplicar_rompe_su_contrato(monkeypatch):
    """Fase 13 (lo marco mypy): sin bloqueos, `aplicar` siempre devuelve
    resultado. Si se rompe, el error lo dice y avisa de mirar AWS."""
    from agente_iam import almacen

    monkeypatch.setattr("sys.argv", ["aplicador", "req-x"])
    monkeypatch.setattr(almacen, "leer", lambda sid: {"id": sid, "estado": "aprobada"})
    monkeypatch.setattr(aplicador, "aplicar", lambda r: (None, [], []))

    def no_escribir(*a, **k):
        raise AssertionError("guardo con un resultado None")

    monkeypatch.setattr(almacen, "guardar_decision", no_escribir)
    with pytest.raises(RuntimeError, match="contrato roto.*AWS"):
        aplicador.main()


# ---------------------------------------------------------------------------
# aplicar de punta a punta, con IAM stubeado
# ---------------------------------------------------------------------------

_POLITICA_ARN = f"arn:aws:iam::{_CUENTA}:policy/agente-iam/agente-iam-req-jose"


@pytest.fixture
def ejecutor(monkeypatch):
    from tests.dobles import _APROBADOR, _aprobador

    monkeypatch.setattr(aplicador, "identificar_aprobador", lambda: _aprobador(_APROBADOR))
    return _APROBADOR


def test_aplicar_crea_adjunta_y_lo_registra(iam, ejecutor):
    registro = _registro()
    _programar_lectura_del_principal(iam)
    iam.add_client_error("get_policy", service_error_code="NoSuchEntity",
                         expected_params={"PolicyArn": _POLITICA_ARN})
    iam.add_response(
        "create_policy",
        {"Policy": {"PolicyName": "agente-iam-req-jose", "Arn": _POLITICA_ARN}},
        {
            "PolicyName": "agente-iam-req-jose",
            "Path": "/agente-iam/",
            "PolicyDocument": json.dumps(_DOC),
            "Description": (
                f"agente-iam | solicitud=req-jose | huella={registro['aprobacion']['huella']} | "
                f"aprobada={registro['aprobacion']['cuando']}"
            ),
            # La compuerta del rol: sin este tag, CreatePolicy se deniega.
            "Tags": [{"Key": "agente-iam-solicitud", "Value": "req-jose"}],
        },
    )
    iam.add_response("attach_user_policy", {},
                     {"UserName": "jose.torres", "PolicyArn": _POLITICA_ARN})

    resultado, bloqueos, avisos = aplicador.aplicar(registro)

    assert bloqueos == []
    assert avisos == []
    assert resultado["estado"] == "aplicada"
    ap = resultado["aplicacion"]
    assert ap["policy_arn"] == _POLITICA_ARN
    assert ap["decision"] == "crear"
    assert ap["por"]["arn_canonico"] == ejecutor
    assert ap["principal_id_confirmado"] == _ID


def test_si_ya_existe_identica_y_nuestra_solo_se_adjunta(iam, ejecutor):
    """El reintento tras morir entre CreatePolicy y Attach: no se crea otra."""
    registro = _registro()
    politica = {"Policy": {"PolicyName": "agente-iam-req-jose", "Arn": _POLITICA_ARN,
                           "DefaultVersionId": "v1", "AttachmentCount": 0,
                           "Description": "agente-iam | solicitud=req-jose | huella=x"}}
    _programar_lectura_del_principal(iam)
    iam.add_response("get_policy", politica, {"PolicyArn": _POLITICA_ARN})
    iam.add_response("get_policy", politica, {"PolicyArn": _POLITICA_ARN})
    iam.add_response("get_policy_version", {"PolicyVersion": {
        "Document": urllib.parse.quote(json.dumps(_DOC)), "VersionId": "v1", "IsDefaultVersion": True,
    }}, {"PolicyArn": _POLITICA_ARN, "VersionId": "v1"})
    iam.add_response("attach_user_policy", {},
                     {"UserName": "jose.torres", "PolicyArn": _POLITICA_ARN})

    resultado, bloqueos, _ = aplicador.aplicar(registro)

    assert bloqueos == []
    assert resultado["aplicacion"]["decision"] == "adjuntar"


def test_quien_aplica_se_identifica_antes_de_escribir(iam, monkeypatch):
    """Fase 9 (7): si STS fallara DESPUES del Attach, la politica quedaria
    aplicada y el error saldria sin el ARN ni registro. Se resuelve antes:
    si falla, no se ha creado ni adjuntado nada (el Stubber reventaria con
    otro error si se llamara a CreatePolicy o AttachUserPolicy)."""
    def sts_caido():
        raise RuntimeError("STS caido")

    monkeypatch.setattr(aplicador, "identificar_aprobador", sts_caido)
    _programar_lectura_del_principal(iam)
    iam.add_client_error("get_policy", service_error_code="NoSuchEntity")
    with pytest.raises(RuntimeError, match="STS caido"):
        aplicador.aplicar(_registro())


def test_la_revalidacion_del_aplicador_bloquea(iam, monkeypatch):
    """Lo aprobado ayer con reglas de ayer: si hoy no pasa, no se aplica."""
    monkeypatch.setattr(
        aplicador, "revalidar",
        lambda r: {"aprobable": False, "bloqueos": ["la accion 's3:*' es un comodin"],
                   "criticos": [], "menores": []},
    )
    # Con un bloqueo determinista el pre-vuelo corta antes de leer IAM (D2).
    resultado, bloqueos, _ = aplicador.aplicar(_registro())
    assert resultado is None
    assert any("ya no pasa las barandas" in b and "'s3:*'" in b for b in bloqueos)


def test_beneficiario_borrado_no_se_aplica(iam):
    iam.add_client_error("get_user", service_error_code="NoSuchEntity",
                         expected_params={"UserName": "jose.torres"})
    resultado, bloqueos, _ = aplicador.aplicar(_registro())
    assert resultado is None
    assert "ya no existe" in bloqueos[0]


def test_aplicar_no_adjunta_una_politica_que_no_es_la_aprobada(iam, monkeypatch):
    """`decidir` dice "parar" y `aplicar` tiene que hacerle caso. Sin ese
    `if`, la rama de "no crear" toma el ARN existente y lo ADJUNTA: se daria
    al beneficiario un documento que nadie aprobo. Los tests de `decidir`
    no lo cubrian porque prueban la decision, no lo que se hace con ella."""
    monkeypatch.setattr(aplicador, "identificar_aprobador",
                        lambda: pytest.fail("parar no llega a identificar ni a escribir"))
    ajena = {"Policy": {"PolicyName": "agente-iam-req-jose", "Arn": _POLITICA_ARN,
                        "DefaultVersionId": "v1", "AttachmentCount": 0,
                        "Description": "agente-iam | solicitud=req-jose | huella=x"}}
    otro_doc = {"Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": ["*"]}]}
    _programar_lectura_del_principal(iam)
    iam.add_response("get_policy", ajena, {"PolicyArn": _POLITICA_ARN})
    iam.add_response("get_policy", ajena, {"PolicyArn": _POLITICA_ARN})
    iam.add_response("get_policy_version", {"PolicyVersion": {
        "Document": urllib.parse.quote(json.dumps(otro_doc)), "VersionId": "v1", "IsDefaultVersion": True,
    }}, {"PolicyArn": _POLITICA_ARN, "VersionId": "v1"})
    # Ni attach_user_policy ni create_policy programados: si se llamaran, el
    # Stubber reventaria.

    resultado, bloqueos, _ = aplicador.aplicar(_registro())

    assert resultado is None
    assert "DISTINTO" in bloqueos[0]


def test_el_nombre_ocupado_fuera_del_path_se_dice(iam):
    """Los nombres de politica son unicos en la cuenta, no por path: un
    EntityAlreadyExists que `observar` no encuentra es otra politica fuera
    de /agente-iam/. Tiene que decirse, no salir como "no existe todavia"."""
    iam.add_client_error("create_policy", service_error_code="EntityAlreadyExists")
    iam.add_client_error("get_policy", service_error_code="NoSuchEntity",
                         expected_params={"PolicyArn": _POLITICA_ARN})
    with pytest.raises(RuntimeError, match="NO bajo nuestro path"):
        aplicador.crear(_registro(), _DOC, _CUENTA)


def test_main_aplicador_escribe_condicionado_al_estado_leido(monkeypatch):
    """Como en aprobar: `aplicar` deja el registro en 'aplicada', asi que la
    escritura se condiciona con el estado LEIDO ('aprobada'). Con el nuevo,
    dos aplicadores a la vez no se verian."""
    from agente_iam import almacen

    def aplicar_falso(r):
        r["estado"] = "aplicada"
        r["aplicacion"] = {"policy_arn": _POLITICA_ARN, "decision": "crear", "motivo": "m",
                           "por": {"arn_canonico": "x"}}
        return r, [], []

    monkeypatch.setattr("sys.argv", ["aplicador", "req-jose"])
    monkeypatch.setattr(almacen, "leer", lambda sid: _registro())
    monkeypatch.setattr(aplicador, "aplicar", aplicar_falso)
    escrito = []
    monkeypatch.setattr(almacen, "guardar_decision",
                        lambda r, bloque, esperado, clave: escrito.append((bloque, r["estado"], esperado, clave))
                        or "disco://req-jose")
    aplicador.main()
    # La clave es el id que se pidio, no el que diga el registro (S1).
    assert escrito == [("aplicacion", "aplicada", "aprobada", "req-jose")]


# ---------------------------------------------------------------------------
# S4 (24-10-2026): el pre-vuelo exige los controles de `aprobar`, no solo la
# huella, y repite CheckNoNewAccess. Antes un UpdateItem directo del
# aprobador con `{"huella": ...}` y el estado a mano se aplicaba.
# ---------------------------------------------------------------------------


def _con_aprobacion(**bloque) -> dict:
    """Un registro con la aprobacion por defecto cambiada en `bloque`."""
    registro = _registro()
    registro["aprobacion"] = {**registro["aprobacion"], **bloque}
    return registro


@pytest.mark.parametrize("bloque,motivo", [
    ({"separacion_de_funciones": None}, "separacion de funciones"),
    ({"separacion_de_funciones": {"resultado": "SALTADO"}}, "AGENTE_IAM_PERMITIR_AUTOAPROBACION"),
    ({"techo": None}, "CheckNoNewAccess"),
    ({"techo": {"resultado": "FAIL"}}, "CheckNoNewAccess"),
])
def test_una_aprobacion_sin_sus_controles_no_se_aplica(iam, bloque, motivo):
    # Ninguna llamada a IAM programada: bloquea antes de leer al principal.
    _, bloqueos, _ = aplicador.prevuelo(_con_aprobacion(**bloque))
    assert any(motivo in b for b in bloqueos), bloqueos


def test_el_salto_de_la_separacion_solo_con_la_puerta_del_aplicador(iam, monkeypatch):
    monkeypatch.setattr(aplicador, "PERMITIR_AUTOAPROBACION", True)
    _programar_lectura_del_principal(iam)
    _, bloqueos, _ = aplicador.prevuelo(_con_aprobacion(separacion_de_funciones={"resultado": "SALTADO"}))
    assert bloqueos == []


def test_la_puerta_de_autoaprobacion_exige_el_valor_exacto(monkeypatch):
    import importlib

    from agente_iam import config

    for valor, abierta in (("si", True), ("Si", False), ("true", False), ("1", False)):
        monkeypatch.setenv("AGENTE_IAM_PERMITIR_AUTOAPROBACION", valor)
        assert importlib.reload(config).PERMITIR_AUTOAPROBACION is abierta, valor
    monkeypatch.delenv("AGENTE_IAM_PERMITIR_AUTOAPROBACION")
    assert importlib.reload(config).PERMITIR_AUTOAPROBACION is False


@pytest.mark.parametrize("cambio", [
    {"propuesta": {"nivel_riesgo": "alto"}},
    {"solicitud": {"campos": {"tipo_acceso": "administracion"}}},
])
def test_el_riesgo_alto_sin_confirmar_no_se_aplica(iam, cambio):
    """El riesgo se recalcula desde el registro (nivel del modelo o
    `riesgo_minimo`), igual que en `aprobar`; el campo guardado no lo baja."""
    registro = _registro()
    for clave, sub in cambio.items():
        destino = registro[clave]
        for k, v in sub.items():
            if isinstance(v, dict):
                destino[k] = {**destino[k], **v}
            else:
                destino[k] = v
    registro["aprobacion"]["huella"] = huella.calcular(registro)
    _, bloqueos, _ = aplicador.prevuelo(registro)
    assert any("riesgo alto" in b for b in bloqueos), bloqueos

    registro["aprobacion"]["riesgo_confirmado"] = True
    _programar_lectura_del_principal(iam)
    _, bloqueos, _ = aplicador.prevuelo(registro)
    assert bloqueos == []


def test_el_aplicador_repite_check_no_new_access(iam, monkeypatch):
    vistos = []
    monkeypatch.setattr(aplicador, "comprobar_techo",
                        lambda doc, cuenta: vistos.append((doc, cuenta)) or {"resultado": "FAIL", "mensaje": "s3:*"})
    _programar_lectura_del_principal(iam)
    _, bloqueos, _ = aplicador.prevuelo(_registro())
    assert vistos == [(_DOC, _CUENTA)]
    assert any("repetido por el aplicador" in b for b in bloqueos)


def test_no_poder_repetir_check_no_new_access_no_es_un_bloqueo(iam, monkeypatch):
    """Un control que no pudo correr (throttle, red) no es un control que fallo:
    se levanta `ControlNoEjecutable` y el que llama decide."""
    from botocore.exceptions import ClientError

    def revienta(doc, cuenta):
        raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "x"}}, "CheckNoNewAccess")

    monkeypatch.setattr(aplicador, "comprobar_techo", revienta)
    with pytest.raises(aplicador.ControlNoEjecutable, match="No se pudo ejecutar CheckNoNewAccess"):
        aplicador.prevuelo(_registro())
    with pytest.raises(aplicador.ControlNoEjecutable):
        aplicador.aplicar(_registro())


def test_el_manejador_deja_subir_un_control_no_ejecutable_y_no_escribe(entorno_lambda, monkeypatch):
    alm = _Almacen(monkeypatch, leido=_fila_lambda())

    def no_ejecutable(r):
        raise aplicador.ControlNoEjecutable("No se pudo ejecutar CheckNoNewAccess desde el aplicador: x")

    monkeypatch.setattr(aplicador, "aplicar", no_ejecutable)
    with pytest.raises(aplicador.ControlNoEjecutable):
        aplicador.manejador(_evento_stream(), None)
    assert alm.escrituras == []


def test_main_sale_con_1_y_no_escribe_si_un_control_no_se_pudo_ejecutar(monkeypatch, capsys):
    from agente_iam import almacen

    def no_ejecutable(r):
        raise aplicador.ControlNoEjecutable("No se pudo ejecutar CheckNoNewAccess desde el aplicador: x")

    monkeypatch.setattr("sys.argv", ["aplicador", "req-jose"])
    monkeypatch.setattr(almacen, "leer", lambda sid: _registro())
    monkeypatch.setattr(aplicador, "aplicar", no_ejecutable)
    monkeypatch.setattr(almacen, "guardar_decision", lambda *a, **k: pytest.fail("no deberia escribir"))
    with pytest.raises(SystemExit) as salida:
        aplicador.main()
    assert salida.value.code == 1
    assert "CheckNoNewAccess" in capsys.readouterr().out


def _analyzer_con_throttling(monkeypatch):
    """`validar_politica` de verdad, con Access Analyzer que devuelve throttling."""
    from botocore.exceptions import ClientError

    from agente_iam.herramientas import validacion

    class _AA:
        def validate_policy(self, **kw):
            raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}}, "ValidatePolicy")

    monkeypatch.setattr(validacion, "_analyzer", lambda: _AA())
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)


def test_validar_politica_marca_no_ejecutado_si_access_analyzer_falla(monkeypatch):
    from agente_iam.herramientas import validacion

    _analyzer_con_throttling(monkeypatch)
    r = validacion.validar_politica(json.dumps(_DOC))
    assert r["aprobable"] is False
    assert any("No se pudo ejecutar Access Analyzer" in b for b in r["bloqueos"])
    assert len(r["no_ejecutado"]) == 1
    assert "ThrottlingException" in r["no_ejecutado"][0]


def test_revalidar_deja_pasar_no_ejecutado(monkeypatch):
    from agente_iam import aprobar

    _analyzer_con_throttling(monkeypatch)
    monkeypatch.setattr(aprobar, "chequeos_formulario", lambda campos: [])
    monkeypatch.setattr(aprobar, "chequeos_posteriores", lambda *a: ([], []))
    assert aprobar.revalidar(_registro())["no_ejecutado"]


def test_un_throttling_de_access_analyzer_no_es_un_bloqueo_en_el_prevuelo(iam, monkeypatch):
    monkeypatch.setattr(
        aplicador, "revalidar",
        lambda r: {"aprobable": False, "bloqueos": ["No se pudo ejecutar Access Analyzer: x"],
                   "criticos": [], "menores": [], "no_ejecutado": ["ThrottlingException: x"]},
    )
    with pytest.raises(aplicador.ControlNoEjecutable, match="Access Analyzer"):
        aplicador.prevuelo(_registro())


def test_el_manejador_deja_subir_el_throttling_de_access_analyzer_y_no_escribe(entorno_lambda, monkeypatch):
    from agente_iam import aprobar

    # Una fila entera del modo rol por persona: aqui corre el `aplicar` de verdad.
    alm = _Almacen(monkeypatch, leido=_registro_persona())
    _analyzer_con_throttling(monkeypatch)
    monkeypatch.setattr(aprobar, "chequeos_formulario", lambda campos: [])
    monkeypatch.setattr(aprobar, "chequeos_posteriores", lambda *a: ([], []))
    monkeypatch.setattr(aplicador, "comprobar_techo", lambda doc, cuenta: {"resultado": "PASS"})
    with pytest.raises(aplicador.ControlNoEjecutable, match="Access Analyzer"):
        aplicador.manejador(_evento_stream(), None)
    assert alm.escrituras == []


def test_main_sale_con_1_y_no_escribe_si_access_analyzer_no_pudo_ejecutarse(monkeypatch, capsys):
    from agente_iam import almacen, aprobar

    _analyzer_con_throttling(monkeypatch)
    monkeypatch.setattr(aprobar, "chequeos_formulario", lambda campos: [])
    monkeypatch.setattr(aprobar, "chequeos_posteriores", lambda *a: ([], []))
    monkeypatch.setattr("sys.argv", ["aplicador", "req-jose"])
    monkeypatch.setattr(almacen, "leer", lambda sid: _registro())
    monkeypatch.setattr(almacen, "guardar_decision", lambda *a, **k: pytest.fail("no deberia escribir"))
    with pytest.raises(SystemExit) as salida:
        aplicador.main()
    assert salida.value.code == 1
    assert "Access Analyzer" in capsys.readouterr().out


def test_un_bloqueo_determinista_no_se_esconde_tras_la_llamada_de_pago(iam, monkeypatch):
    """Si las barandas ya bloquean, CheckNoNewAccess no se llama; y aunque
    reventara, el resultado son los bloqueos, no `ControlNoEjecutable`."""
    monkeypatch.setattr(
        aplicador, "revalidar",
        lambda r: {"aprobable": False, "bloqueos": ["la accion 's3:*' es un comodin"],
                   "criticos": [], "menores": []},
    )

    def revienta(doc, cuenta):
        raise RuntimeError("no deberia llamarse")

    monkeypatch.setattr(aplicador, "comprobar_techo", revienta)
    _, bloqueos, _ = aplicador.prevuelo(_registro())
    assert len(bloqueos) == 1
    assert "ya no pasa las barandas" in bloqueos[0]


def test_el_rol_del_aplicador_puede_repetir_check_no_new_access():
    """El fichero de infra/ (desplegarlo es de Mateo): sin el permiso, la
    compuerta nueva bloquearia todo con AccessDenied."""
    from pathlib import Path

    politica = json.loads((Path(__file__).resolve().parents[2] / "infra/rol-aplicador-permisos.json").read_text())
    permitidas = {
        a for st in politica["Statement"] if st["Effect"] == "Allow"
        for a in ([st["Action"]] if isinstance(st["Action"], str) else st["Action"])
    }
    assert {"access-analyzer:CheckNoNewAccess", "iam:GetPolicy", "iam:GetPolicyVersion"} <= permitidas
    assert any(st["Effect"] == "Deny" and st["Action"] == "bedrock:*" for st in politica["Statement"])


# ---------------------------------------------------------------------------
# S9 (24-10-2026): lo que se aplica es lo que se valido
# ---------------------------------------------------------------------------


def test_un_documento_con_claves_de_mas_no_se_aplica(iam):
    """Pydantic quitaba `NotResource` en silencio: `revalidar` juzgaba un
    documento y CreatePolicy recibia el crudo. Ahora no valida, y no se
    llega ni a leer al principal."""
    doc = json.loads(json.dumps(_DOC))
    doc["Statement"][0]["NotResource"] = ["arn:aws:s3:::finanzas-2026/*"]
    registro = _registro()
    registro["propuesta"]["policy_document"] = doc
    registro["aprobacion"]["huella"] = huella.calcular(registro)
    _, bloqueos, _ = aplicador.prevuelo(registro)
    assert any("no cumple el contrato" in b for b in bloqueos), bloqueos


def test_un_documento_distinto_de_su_version_validada_no_se_aplica():
    registro = _registro()
    registro["propuesta"]["policy_document"] = {k: v for k, v in _DOC.items() if k != "Version"}
    documento, motivo = aplicador.documento_validado(registro)
    assert documento is None
    assert "no es exactamente" in motivo
    documento, motivo = aplicador.documento_validado(_registro())
    assert documento == _DOC
    assert motivo is None


def test_aplicar_crea_la_politica_con_el_documento_validado(monkeypatch):
    """Aunque el pre-vuelo pasara (aqui un doble), `aplicar` no usa el crudo."""
    monkeypatch.setattr(aplicador, "prevuelo", lambda r: ({"principal_id": _ID}, [], []))
    registro = _registro()
    registro["propuesta"]["policy_document"] = {**_DOC, "Extra": True}
    resultado, bloqueos, _ = aplicador.aplicar(registro)
    assert resultado is None
    assert any("contrato" in b for b in bloqueos)



def test_main_aplica_y_escribe_en_el_id_pedido(monkeypatch):
    """S1: igual que en `aprobar`, la clave es el argumento."""
    from agente_iam import almacen

    def aplicar_falso(r):
        r = dict(r, id="victima", estado="aplicada")
        r["aplicacion"] = {"policy_arn": _POLITICA_ARN, "decision": "crear", "motivo": "m",
                           "por": {"arn_canonico": "x"}}
        return r, [], []

    monkeypatch.setattr("sys.argv", ["aplicador", "req-jose"])
    monkeypatch.setattr(almacen, "leer", lambda sid: _registro())
    monkeypatch.setattr(aplicador, "aplicar", aplicar_falso)
    claves = []
    monkeypatch.setattr(almacen, "guardar_decision", lambda r, b, e, clave: claves.append(clave) or "x")
    aplicador.main()
    assert claves == ["req-jose"]



def test_main_no_imprime_caracteres_de_control_en_motivos_ni_avisos(monkeypatch, capsys):
    """S7: los bloqueos y avisos citan partes del registro (acciones, ARN,
    motivos de riesgo que copian la justificacion)."""
    from agente_iam import almacen

    monkeypatch.setattr("sys.argv", ["aplicador", "req-jose"])
    monkeypatch.setattr(almacen, "leer", lambda sid: _registro())
    monkeypatch.setattr(aplicador, "aplicar", lambda r: (None, ["b\x1b[2J"], ["a\x1b[8m"]))
    with pytest.raises(SystemExit) as salida:
        aplicador.main()
    assert salida.value.code == 3
    assert "\x1b" not in capsys.readouterr().out


def test_una_fila_sin_documento_no_se_aplica_y_sale_con_3(monkeypatch, capsys):
    """Fase 18: un UpdateItem sobre un id inexistente crea una fila con solo el
    bloque escrito. Hasta el 24-10-2026 la lectura daba KeyError (salida 1, sin
    motivo); ahora es una fila inconsistente: el control, salida 3."""
    from agente_iam import almacen

    class _Tabla:
        def get_item(self, **_):
            return {"Item": {"id": "req-prueba", "estado": "aprobada", "aprobacion": '{"huella": "sha256:x"}'}}

    monkeypatch.setattr(almacen, "ALMACEN", "dynamodb")
    monkeypatch.setattr(almacen, "_tabla", _Tabla())
    monkeypatch.setattr("sys.argv", ["aplicador", "req-prueba"])
    with pytest.raises(SystemExit) as salida:
        aplicador.main()
    assert salida.value.code == 3
    assert "no tiene documento" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# El aplicador como Lambda disparada por el stream de la tabla (ESPECIFICACION
# §7). Sin red: `aplicar`, el almacen y los catalogos son dobles.
# ---------------------------------------------------------------------------


def _evento_stream(solicitud_id="req-jose", estado="aprobada", event_name="MODIFY"):
    """Un lote de un registro con la forma de DynamoDB Streams (NEW_IMAGE)."""
    registro = {
        "eventName": event_name,
        "dynamodb": {"Keys": {"id": {"S": solicitud_id}}},
    }
    if event_name != "REMOVE":
        registro["dynamodb"]["NewImage"] = {"id": {"S": solicitud_id}, "estado": {"S": estado}}
    return {"Records": [registro]}


class _Almacen:
    """Dobles de `leer` y `guardar_decision` que anotan lo que se hace."""

    def __init__(self, monkeypatch, leido=None, error_al_guardar=None):
        self.escrituras = []
        self.lecturas = []
        self.leido = leido
        self.error_al_guardar = error_al_guardar
        monkeypatch.setattr(aplicador.almacen, "leer", self._leer)
        monkeypatch.setattr(aplicador.almacen, "guardar_decision", self._guardar)

    def _leer(self, solicitud_id):
        self.lecturas.append(solicitud_id)
        if isinstance(self.leido, Exception):
            raise self.leido
        return self.leido

    def _guardar(self, registro, bloque, estado_esperado, *, clave):
        if self.error_al_guardar:
            raise self.error_al_guardar
        self.escrituras.append((bloque, registro["estado"], estado_esperado, clave, registro))
        return "dynamodb://solicitudes/" + clave


@pytest.fixture
def entorno_lambda(monkeypatch):
    """DynamoDB como almacen, catalogos cargables y la cache de arranque limpia."""
    monkeypatch.setattr(aplicador, "_problemas_entorno", None)
    monkeypatch.setattr(aplicador.almacen, "ALMACEN", "dynamodb")
    monkeypatch.setattr(aplicador.catalogo, "no_disponibles", lambda servicios: [])
    from tests.dobles import _APROBADOR, _aprobador

    monkeypatch.setattr(aplicador, "identificar_aprobador", lambda: _aprobador(_APROBADOR))


def _aplicar_devuelve(monkeypatch, bloqueos=None, avisos=None):
    llamadas = []

    def falso(r):
        llamadas.append(r["id"])
        if bloqueos:
            return None, bloqueos, avisos or []
        r["estado"] = "aplicada"
        r["aplicacion"] = {"policy_arn": _POLITICA_ARN, "decision": "crear", "motivo": "m", "avisos": []}
        return r, [], avisos or []

    monkeypatch.setattr(aplicador, "aplicar", falso)
    return llamadas


def _fila_lambda(**cambios) -> dict:
    """Una fila como las que llegan a la Lambda: del modo rol por persona (el
    unico que escribe el runtime). `aplicar` es un doble en estos tests, asi
    que basta con el modo."""
    fila = _registro(**cambios)
    fila["identidad_verificada"]["modo"] = "rol_por_persona"
    return fila


def test_la_lambda_no_aplica_una_fila_del_modo_principal_existente(entorno_lambda, monkeypatch):
    """Fase 33: adjuntar a un principal que ya existe es el modo del CLI de
    desarrollo. En la cuenta, una fila aprobada de ese modo dejaria adjuntar a
    cualquier principal con el techo; la Lambda la deja `bloqueada_al_aplicar`
    sin llegar a `aplicar` (ni a IAM)."""
    alm = _Almacen(monkeypatch, leido=_registro())
    llamadas = _aplicar_devuelve(monkeypatch)
    r = aplicador.manejador(_evento_stream(), None)
    assert llamadas == []
    assert len(alm.escrituras) == 1
    bloque, estado, esperado, clave, registro = alm.escrituras[0]
    assert (bloque, estado, esperado, clave) == ("aplicacion", "bloqueada_al_aplicar", "aprobada", "req-jose")
    assert "rol por persona" in registro["aplicacion"]["bloqueos"][0]
    assert r["procesados"][0]["resultado"] == "bloqueada_al_aplicar"


def test_el_manejador_aplica_y_escribe_la_aplicacion_condicionada_a_aprobada(entorno_lambda, monkeypatch):
    alm = _Almacen(monkeypatch, leido=_fila_lambda())
    _aplicar_devuelve(monkeypatch)
    r = aplicador.manejador(_evento_stream(), None)
    assert len(alm.escrituras) == 1
    bloque, estado, esperado, clave, _ = alm.escrituras[0]
    assert (bloque, estado, esperado, clave) == ("aplicacion", "aplicada", "aprobada", "req-jose")
    assert r["procesados"] == [{"id": "req-jose", "resultado": "aplicada", "policy_arn": _POLITICA_ARN}]


def test_un_bloqueo_del_prevuelo_se_escribe_una_vez_como_bloqueada_al_aplicar(entorno_lambda, monkeypatch):
    alm = _Almacen(monkeypatch, leido=_fila_lambda())
    _aplicar_devuelve(monkeypatch, bloqueos=["La huella NO cuadra"], avisos=["aviso"])
    r = aplicador.manejador(_evento_stream(), None)
    assert len(alm.escrituras) == 1
    bloque, estado, esperado, clave, registro = alm.escrituras[0]
    assert (bloque, estado, esperado, clave) == ("aplicacion", "bloqueada_al_aplicar", "aprobada", "req-jose")
    ap = registro["aplicacion"]
    assert ap["decision"] == "bloquear"
    assert ap["bloqueos"] == ["La huella NO cuadra"]
    assert ap["avisos"] == ["aviso"]
    assert ap["por"]["arn_canonico"]
    assert ap["cuando"]
    assert r["procesados"] == [
        {"id": "req-jose", "resultado": "bloqueada_al_aplicar", "bloqueos": ["La huella NO cuadra"]}
    ]


def test_si_la_fila_ya_no_esta_aprobada_no_se_aplica_ni_se_escribe(entorno_lambda, monkeypatch):
    """El evento puede ser viejo (7.2): se relee la fila y no se confia en el."""
    alm = _Almacen(monkeypatch, leido=_fila_lambda(estado="aplicada"))
    monkeypatch.setattr(aplicador, "aplicar", lambda r: pytest.fail("no deberia aplicar"))
    r = aplicador.manejador(_evento_stream(), None)
    assert alm.escrituras == []
    assert r["procesados"][0]["resultado"] == "omitida"
    assert "aplicada" in r["procesados"][0]["motivo"]


@pytest.mark.parametrize(
    "bloque",
    [{"aplicacion": {"decision": "crear", "policy_arn": _POLITICA_ARN}},
     {"rechazo": {"cuando": "ya", "motivo": "no"}}],
)
def test_una_fila_decidida_con_estado_reescrito_a_aprobada_no_se_aplica(entorno_lambda, monkeypatch, caplog, bloque):
    """Alguien reescribio `estado = aprobada` sobre una decision ya tomada: no
    se aplica ni se toca IAM; RuntimeError para que llegue a la cola de fallos."""
    alm = _Almacen(monkeypatch, leido=_fila_lambda(**bloque))
    monkeypatch.setattr(aplicador, "aplicar", lambda r: pytest.fail("no deberia aplicar"))
    with caplog.at_level("WARNING"), pytest.raises(RuntimeError, match="estado reescrito sobre una decision"):
        aplicador.manejador(_evento_stream(), None)
    assert alm.escrituras == []
    assert any("estado reescrito sobre una decision ya tomada" in m and "req-jose" in m for m in caplog.messages)


def test_una_imagen_que_no_es_aprobada_no_lee_la_tabla(entorno_lambda, monkeypatch):
    alm = _Almacen(monkeypatch, leido=_fila_lambda())
    monkeypatch.setattr(aplicador, "aplicar", lambda r: pytest.fail("no deberia aplicar"))
    r = aplicador.manejador(_evento_stream(estado="propuesta"), None)
    assert alm.lecturas == []
    assert r["procesados"][0]["resultado"] == "omitida"


def test_un_remove_se_omite_sin_leer(entorno_lambda, monkeypatch):
    alm = _Almacen(monkeypatch, leido=_fila_lambda())
    monkeypatch.setattr(aplicador, "aplicar", lambda r: pytest.fail("no deberia aplicar"))
    r = aplicador.manejador(_evento_stream(event_name="REMOVE"), None)
    assert alm.lecturas == []
    assert r["procesados"][0]["resultado"] == "omitida"


def test_una_fila_que_no_existe_se_omite(entorno_lambda, monkeypatch):
    alm = _Almacen(monkeypatch, leido=None)
    r = aplicador.manejador(_evento_stream(), None)
    assert alm.escrituras == []
    assert r["procesados"][0]["resultado"] == "omitida"
    assert "no existe" in r["procesados"][0]["motivo"]


def test_una_fila_con_forma_imposible_se_omite_sin_escribir(entorno_lambda, monkeypatch, caplog):
    from agente_iam import almacen

    alm = _Almacen(monkeypatch, leido=almacen.RegistroInconsistente("forma imposible"))
    monkeypatch.setattr(aplicador, "aplicar", lambda r: pytest.fail("no deberia aplicar"))
    with caplog.at_level("WARNING", logger="agente-iam.aplicador"):
        r = aplicador.manejador(_evento_stream(), None)
    assert alm.escrituras == []
    assert r["procesados"][0]["resultado"] == "omitida"
    assert any(x.levelname == "WARNING" for x in caplog.records)


def test_si_aplicar_rompe_la_excepcion_sube_y_no_se_escribe(entorno_lambda, monkeypatch):
    from botocore.exceptions import ClientError

    alm = _Almacen(monkeypatch, leido=_fila_lambda())

    def roto(r):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "CreatePolicy")

    monkeypatch.setattr(aplicador, "aplicar", roto)
    with pytest.raises(ClientError):
        aplicador.manejador(_evento_stream(), None)
    assert alm.escrituras == []


def test_si_el_guardado_falla_tras_aplicar_sube_runtime_error_con_el_arn(entorno_lambda, monkeypatch, caplog):
    from agente_iam import almacen

    _Almacen(monkeypatch, leido=_fila_lambda(), error_al_guardar=almacen.EstadoCambiado("otro decidio"))
    _aplicar_devuelve(monkeypatch)
    with caplog.at_level("ERROR", logger="agente-iam.aplicador"):
        with pytest.raises(RuntimeError, match=_POLITICA_ARN):
            aplicador.manejador(_evento_stream(), None)
    assert any(x.levelname == "ERROR" and _POLITICA_ARN in x.getMessage() for x in caplog.records)


def test_si_el_guardado_falla_por_inconsistencia_tras_aplicar_tambien_sube(entorno_lambda, monkeypatch):
    from agente_iam import almacen

    _Almacen(monkeypatch, leido=_fila_lambda(), error_al_guardar=almacen.RegistroInconsistente("forma"))
    _aplicar_devuelve(monkeypatch)
    with pytest.raises(RuntimeError, match=_POLITICA_ARN):
        aplicador.manejador(_evento_stream(), None)


def test_si_otro_decidio_mientras_se_escribia_un_bloqueo_se_omite(entorno_lambda, monkeypatch):
    from agente_iam import almacen

    _Almacen(monkeypatch, leido=_fila_lambda(), error_al_guardar=almacen.EstadoCambiado("otro decidio"))
    _aplicar_devuelve(monkeypatch, bloqueos=["x"])
    r = aplicador.manejador(_evento_stream(), None)
    assert r["procesados"][0]["resultado"] == "omitida"


def test_un_entorno_con_almacen_en_disco_no_lee_nada(entorno_lambda, monkeypatch):
    monkeypatch.setattr(aplicador.almacen, "ALMACEN", "disco")
    alm = _Almacen(monkeypatch, leido=_fila_lambda())
    with pytest.raises(RuntimeError, match="dynamodb"):
        aplicador.manejador(_evento_stream(), None)
    assert alm.lecturas == []


def test_un_entorno_sin_catalogos_no_lee_nada(entorno_lambda, monkeypatch):
    monkeypatch.setattr(aplicador.catalogo, "no_disponibles", lambda servicios: ["s3"])
    alm = _Almacen(monkeypatch, leido=_fila_lambda())
    with pytest.raises(RuntimeError, match="s3"):
        aplicador.manejador(_evento_stream(), None)
    assert alm.lecturas == []


def test_el_entorno_se_comprueba_una_vez_por_arranque(entorno_lambda, monkeypatch):
    llamadas = []
    monkeypatch.setattr(aplicador.catalogo, "no_disponibles", lambda servicios: llamadas.append(1) or [])
    _Almacen(monkeypatch, leido=None)
    for _ in range(3):
        aplicador.manejador(_evento_stream(), None)
    assert len(llamadas) == 1


def test_el_log_lleva_id_y_resultado_y_nunca_el_registro(entorno_lambda, monkeypatch, caplog):
    registro = _fila_lambda()
    registro["solicitud"]["texto"] = "TEXTO-SECRETO-DE-LA-SOLICITUD"
    _Almacen(monkeypatch, leido=registro)
    _aplicar_devuelve(monkeypatch)
    with caplog.at_level("INFO", logger="agente-iam.aplicador"):
        aplicador.manejador(_evento_stream(), None)
    lineas = [x.getMessage() for x in caplog.records if x.name == "agente-iam.aplicador"]
    assert len(lineas) == 1
    for esperado in ("req-jose", "aplicada", _POLITICA_ARN):
        assert esperado in lineas[0]
    assert "TEXTO-SECRETO" not in lineas[0]


def test_el_estado_bloqueada_al_aplicar_existe_y_tiene_explicacion():
    from typing import get_args

    from agente_iam import aprobar
    from agente_iam.models import Estado

    assert "bloqueada_al_aplicar" in get_args(Estado)
    assert aprobar._por_que_no("bloqueada_al_aplicar")


def test_el_aplicador_no_importa_lo_que_su_zip_excluye():
    """El zip de la Lambda no lleva identidad, simulacion, orquestador, agente,
    cli, servidor ni aprobar_cliente: importarlos la rompe al arrancar."""
    import ast
    import inspect

    arbol = ast.parse(inspect.getsource(aplicador))
    prohibidos = {"identidad", "simulacion", "orquestador", "agente", "cli", "servidor", "aprobar_cliente"}
    importados = set()
    for nodo in ast.walk(arbol):
        if isinstance(nodo, ast.ImportFrom) and nodo.module:
            importados.add(nodo.module.split(".")[-1])
            if nodo.module == "agente_iam":
                importados.update(a.name for a in nodo.names)
        elif isinstance(nodo, ast.Import):
            importados.update(a.name.split(".")[-1] for a in nodo.names)
    assert not (importados & prohibidos)


def test_cualquier_otro_fallo_del_guardado_tras_aplicar_deja_el_arn_en_el_log(entorno_lambda, monkeypatch, caplog):
    from botocore.exceptions import ClientError

    error = ClientError({"Error": {"Code": "ThrottlingException", "Message": "x"}}, "UpdateItem")
    _Almacen(monkeypatch, leido=_fila_lambda(), error_al_guardar=error)
    _aplicar_devuelve(monkeypatch)
    with caplog.at_level("ERROR", logger="agente-iam.aplicador"):
        with pytest.raises(ClientError):
            aplicador.manejador(_evento_stream(), None)
    assert any(x.levelname == "ERROR" and _POLITICA_ARN in x.getMessage() for x in caplog.records)


# ---------------------------------------------------------------------------
# Fase 23, tarea 8: el modo rol por persona. El aplicador crea el rol (techo,
# confianza, vida) ademas de la politica, y la adjunta. Sin red: Stubber unico.
# ---------------------------------------------------------------------------

_POOL = "us-east-1_AbC123"
_CLIENTE = "a" * 26
_ID_P = "req-20261026-ab12cd34"
_USUARIO = "solicitante.demo"
_SUB = "sub-1234"
_VENCE = "2026-10-26T15:00:00Z"  # 11:00 UTC de _ahora_utc fijada, mas 4 horas
_NOMBRE_ROL = personas.nombre_de_rol(_USUARIO, _ID_P)
_ARN_ROL = personas.arn_de_rol(_CUENTA, _USUARIO, _ID_P)
_ROL_ID = "AROAPERSONA1234567"
_POLITICA_P = f"arn:aws:iam::{_CUENTA}:policy/agente-iam/agente-iam-{_ID_P}"


def _registro_persona(*, sub=_SUB, sub_token=None, client_id=_CLIENTE, horas=4, **cambios) -> dict:
    """Un registro aprobado del modo rol por persona (lo que deja el servidor y `aprobar`).

    `sub` es el de la identidad congelada; `sub_token` el de `ejecutado_por`
    (por defecto el mismo). La huella se calcula al final, con todo puesto.
    """
    base = _registro_base(id=_ID_P, creada="2026-10-26T10:00:00+00:00", estado="aprobada")
    base["solicitud"] = _solicitud_persona(solicitud_id=_ID_P, usuario=_USUARIO, sub=sub, horas=horas if 1 <= horas <= 12 else 4).model_dump(
        exclude_none=True
    )
    # Una hora fuera de rango no la admite el contrato: se escribe a mano para
    # que la coherencia de modo pase y el pre-vuelo llegue a mirar el rango.
    base["solicitud"]["horas"] = horas
    base["solicitante"] = {"persona": _USUARIO, "como_se_verifico": "JWT validado por el autorizador"}
    base["identidad_verificada"] = {
        "principal_arn": _ARN_ROL,
        "tipo": "role",
        "existe": False,
        "cuenta": _CUENTA,
        "modo": "rol_por_persona",
        "persona": {"usuario": _USUARIO, "sub": sub, "client_id": _CLIENTE},
        "horas": horas,
    }
    base["propuesta"]["principal_arn"] = _ARN_ROL
    base["propuesta"]["policy_document"] = _DOC
    base["ejecutado_por"] = {
        "determinable": True,
        "sub": sub_token or sub,
        "usuario": "IdentityCenter_" + _USUARIO,
        "client_id": client_id,
    }
    base.update(cambios)
    base["aprobacion"] = {
        "cuando": "2026-10-26T11:00:00+00:00",
        "huella": huella.calcular(base),
        "por": {"arn_canonico": f"arn:aws:iam::{_CUENTA}:user/Mateo"},
        "separacion_de_funciones": {"beneficiario": _ARN_ROL, "resultado": "cumplido"},
        "techo": {"resultado": "PASS"},
        "riesgo_confirmado": False,
    }
    return base


_ROLES_VIGENTES_REAL = personas.roles_vigentes


@pytest.fixture
def entorno_persona(monkeypatch):
    """El entorno de la Lambda en modo persona y la hora de aplicacion fija.

    Devuelve un objeto con `vigentes` (lo que ve el tope por persona; vacio por
    defecto) y `llamadas` (con que se pidieron). La lectura real de los roles
    vigentes tiene su propio test con Stubber.
    """
    from datetime import datetime, timezone
    from types import SimpleNamespace

    monkeypatch.setattr(config, "POOL_ID", _POOL)
    monkeypatch.setattr(config, "CLIENTES_COGNITO", (_CLIENTE,))
    monkeypatch.setattr(aplicador, "_ahora_utc", lambda: datetime(2026, 10, 26, 11, 0, 0, tzinfo=timezone.utc))
    monkeypatch.setattr(aplicador.time, "sleep", lambda s: None)
    entorno = SimpleNamespace(vigentes=[], llamadas=[])

    def roles_vigentes(usuario, ahora, iam=None, sub=None):
        entorno.llamadas.append({"usuario": usuario, "ahora": ahora, "iam": iam, "sub": sub})
        return list(entorno.vigentes)

    monkeypatch.setattr(personas, "roles_vigentes", roles_vigentes)
    return entorno


def _rol_en_aws(stub, *, solicitud=_ID_P, boundary=_TECHO, tags=None):
    """Programa GetRole + ListRoleTags de un rol que ya existe."""
    rol = {
        "Path": personas.PATH_PERSONAS,
        "RoleName": _NOMBRE_ROL,
        "RoleId": _ROL_ID,
        "Arn": _ARN_ROL,
        "CreateDate": "2026-10-26T11:00:00Z",
        "MaxSessionDuration": 14400,
    }
    if boundary:
        rol["PermissionsBoundary"] = {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": boundary}
    stub.add_response("get_role", {"Role": rol}, {"RoleName": _NOMBRE_ROL})
    etiquetas = tags if tags is not None else [{"Key": personas.TAG_SOLICITUD, "Value": solicitud}]
    stub.add_response("list_role_tags", {"Tags": etiquetas}, {"RoleName": _NOMBRE_ROL})


def _sin_rol(stub):
    stub.add_client_error("get_role", service_error_code="NoSuchEntity", expected_params={"RoleName": _NOMBRE_ROL})


def _documento_p(vence=_VENCE) -> dict:
    return personas.documento_con_vencimiento(_DOC, vence)


def _politica_en_aws(stub, *, vence=_VENCE, descripcion=None):
    """Programa lo que lee `observar` de una politica que ya existe (tres llamadas)."""
    politica = {"Policy": {
        "PolicyName": f"agente-iam-{_ID_P}", "Arn": _POLITICA_P, "DefaultVersionId": "v1", "AttachmentCount": 0,
        "Description": descripcion or f"agente-iam | solicitud={_ID_P} | huella=x | aprobada=y | vence={vence}",
    }}
    stub.add_response("get_policy", politica, {"PolicyArn": _POLITICA_P})
    stub.add_response("get_policy", politica, {"PolicyArn": _POLITICA_P})
    stub.add_response("get_policy_version", {"PolicyVersion": {
        "Document": urllib.parse.quote(json.dumps(_documento_p(vence))), "VersionId": "v1", "IsDefaultVersion": True,
    }}, {"PolicyArn": _POLITICA_P, "VersionId": "v1"})


def _confianza_esperada(vence=_VENCE) -> str:
    return json.dumps(personas.confianza(_CUENTA, _POOL, (_CLIENTE,), _SUB, vence))


def _crear_rol_esperado(vence=_VENCE, horas=4) -> dict:
    return {
        "RoleName": _NOMBRE_ROL,
        "Path": personas.PATH_PERSONAS,
        "AssumeRolePolicyDocument": _confianza_esperada(vence),
        "PermissionsBoundary": _TECHO,
        "MaxSessionDuration": horas * 3600,
        "Description": f"agente-iam | solicitud={_ID_P} | persona={_USUARIO} | vence={vence}",
        "Tags": [
            {"Key": personas.TAG_SOLICITUD, "Value": _ID_P},
            {"Key": personas.TAG_PERSONA, "Value": _USUARIO},
            {"Key": personas.TAG_SUB, "Value": _SUB},
            {"Key": personas.TAG_VENCE, "Value": vence},
        ],
    }


def _respuesta_crear_rol() -> dict:
    return {"Role": {"Path": personas.PATH_PERSONAS, "RoleName": _NOMBRE_ROL, "RoleId": _ROL_ID,
                     "Arn": _ARN_ROL, "CreateDate": "2026-10-26T11:00:00Z"}}


def _programar_creacion(stub, registro, *, attach_antes=()):
    """GetRole (pre-vuelo) y la escritura completa: politica, rol y attach."""
    _sin_rol(stub)
    stub.add_client_error("get_policy", service_error_code="NoSuchEntity", expected_params={"PolicyArn": _POLITICA_P})
    stub.add_response(
        "create_policy",
        {"Policy": {"PolicyName": f"agente-iam-{_ID_P}", "Arn": _POLITICA_P}},
        {
            "PolicyName": f"agente-iam-{_ID_P}",
            "Path": "/agente-iam/",
            "PolicyDocument": json.dumps(_documento_p()),
            "Description": (
                f"agente-iam | solicitud={_ID_P} | huella={registro['aprobacion']['huella']} | "
                f"aprobada={registro['aprobacion']['cuando']} | vence={_VENCE}"
            ),
            "Tags": [{"Key": "agente-iam-solicitud", "Value": _ID_P}],
        },
    )
    stub.add_response("create_role", _respuesta_crear_rol(), _crear_rol_esperado())
    for codigo in attach_antes:
        stub.add_client_error(
            "attach_role_policy", service_error_code=codigo,
            expected_params={"RoleName": _NOMBRE_ROL, "PolicyArn": _POLITICA_P},
        )
    stub.add_response("attach_role_policy", {}, {"RoleName": _NOMBRE_ROL, "PolicyArn": _POLITICA_P})


def test_en_modo_persona_el_prevuelo_no_relee_ningun_principal_y_exige_sub_y_client_id(iam, entorno_persona, monkeypatch):
    monkeypatch.setattr(aplicador, "_identidad_actual", lambda c: pytest.fail("no hay principal que releer"))

    # Limpio: solo se mira el rol (que no existe todavia), ni usuario ni cuota.
    _sin_rol(iam)
    actual, bloqueos, avisos = aplicador.prevuelo(_registro_persona())
    assert (bloqueos, avisos) == ([], [])
    assert actual == {"principal_arn": _ARN_ROL, "principal_id": "", "rol": {"existe": False}}

    # El `sub` del token no es el de la identidad congelada; ninguna llamada a IAM.
    _, bloqueos, _ = aplicador.prevuelo(_registro_persona(sub_token="sub-de-otro"))
    assert any("`sub`" in b and "ejecutado_por.sub" in b for b in bloqueos), bloqueos

    # Sin `sub` en la identidad.
    registro = _registro_persona()
    registro["identidad_verificada"]["persona"].pop("sub")
    registro["aprobacion"]["huella"] = huella.calcular(registro)
    _, bloqueos, _ = aplicador.prevuelo(registro)
    assert any("no lleva el `sub`" in b for b in bloqueos), bloqueos

    # Sin client_id en el token.
    _, bloqueos, _ = aplicador.prevuelo(_registro_persona(client_id=None))
    assert any("client_id" in b for b in bloqueos), bloqueos

    # Horas fuera de 1..12.
    for horas in (0, 13):
        _, bloqueos, _ = aplicador.prevuelo(_registro_persona(horas=horas))
        assert any("horas" in b.lower() for b in bloqueos), (horas, bloqueos)


def test_un_client_id_fuera_de_la_lista_bloquea_antes_de_escribir(iam, entorno_persona, monkeypatch):
    # Ni lee el rol, ni identifica al ejecutor, ni escribe: el Stubber no tiene nada programado.
    monkeypatch.setattr(aplicador, "identificar_aprobador", lambda: pytest.fail("no debe llegar a escribir"))
    resultado, bloqueos, _ = aplicador.aplicar(_registro_persona(client_id="b" * 26))
    assert resultado is None
    assert any("client_id" in b and "clientes admitidos" in b for b in bloqueos), bloqueos


@pytest.mark.parametrize("pool,clientes", [("", (_CLIENTE,)), (_POOL, ())])
def test_sin_pool_id_el_control_no_es_ejecutable(iam, entorno_persona, monkeypatch, pool, clientes):
    monkeypatch.setattr(config, "POOL_ID", pool)
    monkeypatch.setattr(config, "CLIENTES_COGNITO", clientes)
    with pytest.raises(aplicador.ControlNoEjecutable, match="AGENTE_IAM_POOL_ID"):
        aplicador.prevuelo(_registro_persona())
    with pytest.raises(aplicador.ControlNoEjecutable):
        aplicador.aplicar(_registro_persona())


def test_un_cliente_de_cognito_mal_formado_en_el_entorno_no_es_ejecutable(iam, entorno_persona, monkeypatch):
    """`config.CLIENTES_COGNITO_INVALIDOS` no vacio es entorno roto: un id asi entraria en el `aud`."""
    monkeypatch.setattr(config, "CLIENTES_COGNITO", (_CLIENTE, "mal formado"))
    monkeypatch.setattr(config, "CLIENTES_COGNITO_INVALIDOS", ("mal formado",))
    with pytest.raises(aplicador.ControlNoEjecutable, match="forma de cliente"):
        aplicador.prevuelo(_registro_persona())


def test_el_orden_es_politica_rol_adjuntar_y_el_bloque_lleva_rol_y_vence(iam, entorno_persona, ejecutor):
    registro = _registro_persona()
    # El Stubber fija el orden: GetRole (pre-vuelo), GetPolicy, CreatePolicy con el
    # Allow ya con DateLessThan y la Description con vence=, CreateRole con la
    # confianza exacta de `personas.confianza`, el techo y las horas del registro
    # en segundos, AttachRolePolicy.
    _programar_creacion(iam, registro)
    enviados = []
    iam.client.meta.events.register("provide-client-params.iam.CreateRole", lambda params, **kw: enviados.append(dict(params)))

    resultado, bloqueos, avisos = aplicador.aplicar(registro)

    assert (bloqueos, avisos) == ([], [])
    assert _documento_p()["Statement"][0]["Condition"] == {"DateLessThan": {"aws:CurrentTime": _VENCE}}
    assert resultado["estado"] == "aplicada"
    ap = resultado["aplicacion"]
    assert ap["policy_arn"] == _POLITICA_P
    assert ap["decision"] == "crear"
    assert ap["rol_arn"] == _ARN_ROL
    assert ap["rol_id"] == _ROL_ID
    assert ap["vence"] == _VENCE
    assert ap["documento_aplicado"] == _documento_p()
    assert ap["principal_id_confirmado"] == _ROL_ID
    assert ap["por"]["arn_canonico"] == ejecutor
    # Lo que salio hacia IAM (no la constante del helper): el maximo de sesion
    # es el de las horas del registro, en segundos.
    assert registro["identidad_verificada"]["horas"] == 4
    [creado] = enviados
    assert creado["MaxSessionDuration"] == 14400
    assert creado["AssumeRolePolicyDocument"] == _confianza_esperada()


def test_el_reintento_toma_el_vence_de_la_politica_ya_creada(iam, entorno_persona, ejecutor, monkeypatch):
    """La corrida anterior creo la politica y murio antes del rol. Ahora son otras
    las 11:30: recalcular `vence` daria otra hora, otro documento y un "parar por
    documento distinto". Sale de la Description, y solo se crea el rol."""
    from datetime import datetime, timezone

    monkeypatch.setattr(aplicador, "_ahora_utc", lambda: datetime(2026, 10, 26, 11, 30, 0, tzinfo=timezone.utc))
    _sin_rol(iam)  # pre-vuelo
    _politica_en_aws(iam)  # observar en aplicar
    iam.add_response("create_role", _respuesta_crear_rol(), _crear_rol_esperado(_VENCE))
    iam.add_response("attach_role_policy", {}, {"RoleName": _NOMBRE_ROL, "PolicyArn": _POLITICA_P})

    resultado, bloqueos, _ = aplicador.aplicar(_registro_persona())

    assert bloqueos == []
    ap = resultado["aplicacion"]
    assert ap["decision"] == "adjuntar"
    assert ap["vence"] == _VENCE
    assert ap["documento_aplicado"] == _documento_p(_VENCE)


def test_una_politica_ya_creada_sin_vence_en_la_descripcion_no_se_adjunta(iam, entorno_persona, monkeypatch):
    monkeypatch.setattr(aplicador, "identificar_aprobador", lambda: pytest.fail("parar no llega a escribir"))
    _sin_rol(iam)
    _politica_en_aws(iam, descripcion=f"agente-iam | solicitud={_ID_P} | huella=x")
    resultado, bloqueos, _ = aplicador.aplicar(_registro_persona())
    assert resultado is None
    assert any("vence=" in b for b in bloqueos), bloqueos


def test_un_rol_con_el_mismo_nombre_pero_otra_solicitud_bloquea(iam, entorno_persona, monkeypatch):
    monkeypatch.setattr(aplicador, "identificar_aprobador", lambda: pytest.fail("bloquear no llega a escribir"))
    _rol_en_aws(iam, solicitud="req-20261026-00000000")
    _, bloqueos, _ = aplicador.prevuelo(_registro_persona())
    assert any("ocupa otra solicitud" in b for b in bloqueos), bloqueos

    # Sin ninguna etiqueta tampoco es nuestro.
    _rol_en_aws(iam, tags=[])
    _, bloqueos, _ = aplicador.prevuelo(_registro_persona())
    assert any("ocupa otra solicitud" in b for b in bloqueos), bloqueos

    # Nuestro, pero sin el techo (o con otro): bloquea.
    _rol_en_aws(iam, boundary=None)
    _, bloqueos, _ = aplicador.prevuelo(_registro_persona())
    assert any("permission boundary" in b for b in bloqueos), bloqueos
    _rol_en_aws(iam, boundary=f"arn:aws:iam::{_CUENTA}:policy/Otro")
    _, bloqueos, _ = aplicador.prevuelo(_registro_persona())
    assert any("permission boundary" in b for b in bloqueos), bloqueos

    # Nuestro y con el techo: se reanuda (idempotencia), con su id para confirmar.
    _rol_en_aws(iam)
    actual, bloqueos, _ = aplicador.prevuelo(_registro_persona())
    assert bloqueos == []
    assert actual["principal_id"] == _ROL_ID
    assert actual["rol"]["tags"] == {personas.TAG_SOLICITUD: _ID_P}
    assert actual["rol"]["boundary"] == _TECHO
    assert actual["rol"]["max_session"] == 14400


def test_si_el_rol_ya_existe_y_es_nuestro_solo_se_crea_la_politica_y_se_adjunta(iam, entorno_persona, ejecutor):
    registro = _registro_persona()
    _rol_en_aws(iam)  # pre-vuelo
    iam.add_client_error("get_policy", service_error_code="NoSuchEntity", expected_params={"PolicyArn": _POLITICA_P})
    iam.add_response(
        "create_policy",
        {"Policy": {"PolicyName": f"agente-iam-{_ID_P}", "Arn": _POLITICA_P}},
        {
            "PolicyName": f"agente-iam-{_ID_P}",
            "Path": "/agente-iam/",
            "PolicyDocument": json.dumps(_documento_p()),
            "Description": (
                f"agente-iam | solicitud={_ID_P} | huella={registro['aprobacion']['huella']} | "
                f"aprobada={registro['aprobacion']['cuando']} | vence={_VENCE}"
            ),
            "Tags": [{"Key": "agente-iam-solicitud", "Value": _ID_P}],
        },
    )
    # Ningun create_role programado: si se llamara, el Stubber reventaria.
    iam.add_response("attach_role_policy", {}, {"RoleName": _NOMBRE_ROL, "PolicyArn": _POLITICA_P})
    resultado, bloqueos, _ = aplicador.aplicar(registro)
    assert bloqueos == []
    assert resultado["aplicacion"]["rol_id"] == _ROL_ID
    assert resultado["aplicacion"]["principal_id_confirmado"] == _ROL_ID


def test_crear_rol_ante_entity_already_exists_acepta_solo_el_propio(iam, entorno_persona):
    registro = _registro_persona()
    congelada = registro["identidad_verificada"]
    confianza = personas.confianza(_CUENTA, _POOL, (_CLIENTE,), _SUB, _VENCE)

    iam.add_client_error("create_role", service_error_code="EntityAlreadyExists", expected_params=_crear_rol_esperado())
    _rol_en_aws(iam)
    assert aplicador.crear_rol(registro, congelada, _VENCE, _CUENTA, confianza) == {"arn": _ARN_ROL, "role_id": _ROL_ID}

    iam.add_client_error("create_role", service_error_code="EntityAlreadyExists", expected_params=_crear_rol_esperado())
    _rol_en_aws(iam, solicitud="req-20261026-00000000")
    with pytest.raises(RuntimeError, match="no es de la solicitud"):
        aplicador.crear_rol(registro, congelada, _VENCE, _CUENTA, confianza)


def test_el_attach_tras_crear_el_rol_reintenta_un_access_denied_y_el_attach_de_hoy_no(iam, entorno_persona, ejecutor, monkeypatch):
    esperas = []
    monkeypatch.setattr(aplicador.time, "sleep", esperas.append)

    # 1. Tras CreateRole de esta corrida: un AccessDenied y luego el Attach pasa.
    registro = _registro_persona()
    _programar_creacion(iam, registro, attach_antes=("AccessDenied",))
    resultado, bloqueos, _ = aplicador.aplicar(registro)
    assert bloqueos == []
    assert resultado["aplicacion"]["rol_arn"] == _ARN_ROL
    assert esperas == [1.0]

    # 2. Rol que ya existia (no lo creo esta corrida): AccessDenied sube, sin reintento.
    esperas.clear()
    registro = _registro_persona()
    _rol_en_aws(iam)
    iam.add_client_error("get_policy", service_error_code="NoSuchEntity", expected_params={"PolicyArn": _POLITICA_P})
    iam.add_response("create_policy", {"Policy": {"PolicyName": f"agente-iam-{_ID_P}", "Arn": _POLITICA_P}})
    iam.add_client_error(
        "attach_role_policy", service_error_code="AccessDenied",
        expected_params={"RoleName": _NOMBRE_ROL, "PolicyArn": _POLITICA_P},
    )
    with pytest.raises(aplicador.ClientError):
        aplicador.aplicar(registro)
    assert esperas == []

    # 3. El Attach de hoy (principal existente): AccessDenied tampoco se reintenta.
    iam.add_client_error(
        "attach_role_policy", service_error_code="AccessDenied",
        expected_params={"RoleName": "app-finanzas-demo", "PolicyArn": _POLITICA_ARN_P},
    )
    with pytest.raises(aplicador.ClientError):
        aplicador.adjuntar(_POLITICA_ARN_P, {"principal_arn": f"arn:aws:iam::{_CUENTA}:role/app-finanzas-demo", "tipo": "role"})
    assert esperas == []


_POLITICA_ARN_P = f"arn:aws:iam::{_CUENTA}:policy/agente-iam/agente-iam-req-x"


def test_con_reintento_tambien_solo_vale_para_su_llamada(monkeypatch):
    from botocore.exceptions import ClientError

    monkeypatch.setattr(aplicador.time, "sleep", lambda s: None)
    veces = []

    def falla_dos_veces():
        veces.append(1)
        if len(veces) < 3:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "AttachRolePolicy")
        return "ok"

    assert aplicador._con_reintento(falla_dos_veces, tambien=("AccessDenied",)) == "ok"
    assert len(veces) == 3
    veces.clear()
    with pytest.raises(ClientError):
        aplicador._con_reintento(falla_dos_veces)
    assert len(veces) == 1


def test_el_modo_principal_existente_no_cambia(iam, ejecutor, monkeypatch):
    """`req-022` de hoy: el modo principal lee al usuario (`_identidad_actual`), crea la
    politica SIN `vence`, adjunta al usuario y el bloque no trae nada del modo persona."""
    monkeypatch.setattr(config, "POOL_ID", "")
    monkeypatch.setattr(config, "CLIENTES_COGNITO", ())
    monkeypatch.setattr(aplicador, "_ahora_utc", lambda: pytest.fail("el modo principal no calcula vence"))
    registro = _registro()
    assert registro["identidad_verificada"].get("modo", "principal_existente") == "principal_existente"
    _programar_lectura_del_principal(iam)
    iam.add_client_error("get_policy", service_error_code="NoSuchEntity", expected_params={"PolicyArn": _POLITICA_ARN})
    iam.add_response(
        "create_policy",
        {"Policy": {"PolicyName": "agente-iam-req-jose", "Arn": _POLITICA_ARN}},
        {
            "PolicyName": "agente-iam-req-jose",
            "Path": "/agente-iam/",
            "PolicyDocument": json.dumps(_DOC),
            "Description": (
                f"agente-iam | solicitud=req-jose | huella={registro['aprobacion']['huella']} | "
                f"aprobada={registro['aprobacion']['cuando']}"
            ),
            "Tags": [{"Key": "agente-iam-solicitud", "Value": "req-jose"}],
        },
    )
    iam.add_response("attach_user_policy", {}, {"UserName": "jose.torres", "PolicyArn": _POLITICA_ARN})

    resultado, bloqueos, _ = aplicador.aplicar(registro)

    assert bloqueos == []
    ap = resultado["aplicacion"]
    assert ap["principal_id_confirmado"] == _ID
    assert not {"rol_arn", "rol_id", "vence", "documento_aplicado"} & set(ap)


def test_el_manejador_loguea_tambien_el_rol_cuando_existe(entorno_lambda, monkeypatch, caplog):
    import logging

    alm = _Almacen(monkeypatch, leido=_fila_lambda())

    def falso(r):
        r["estado"] = "aplicada"
        r["aplicacion"] = {"policy_arn": _POLITICA_ARN, "rol_arn": _ARN_ROL, "decision": "crear", "motivo": "m", "avisos": []}
        return r, [], []

    monkeypatch.setattr(aplicador, "aplicar", falso)
    with caplog.at_level(logging.INFO, logger="agente-iam.aplicador"):
        salida = aplicador.manejador(_evento_stream(), None)
    assert salida["procesados"] == [
        {"id": "req-jose", "resultado": "aplicada", "policy_arn": _POLITICA_ARN, "rol_arn": _ARN_ROL}
    ]
    assert f"rol_arn={_ARN_ROL}" in caplog.text
    assert len(alm.escrituras) == 1


# ---------------------------------------------------------------------------
# Fase 23, revision: el tope tambien al aplicar, la coherencia de modo, el
# `vence` del reintento validado y la convergencia ante dos corridas a la vez.
# ---------------------------------------------------------------------------


def _vigente(n: int, solicitud: str | None = None) -> dict:
    sid = solicitud or f"req-20261026-0000000{n}"
    return {
        "arn": personas.arn_de_rol(_CUENTA, _USUARIO, sid),
        "nombre": personas.nombre_de_rol(_USUARIO, sid),
        "vence": _VENCE,
        "solicitud_id": sid,
    }


def test_el_tope_de_roles_vigentes_tambien_bloquea_al_aplicar(iam, entorno_persona, monkeypatch):
    """Con el tope ya alcanzado por roles de otras solicitudes: bloqueada, sin leer el rol ni escribir."""
    monkeypatch.setattr(aplicador, "identificar_aprobador", lambda: pytest.fail("bloquear no llega a escribir"))
    tope = config.MAX_ROLES_VIGENTES_POR_PERSONA
    entorno_persona.vigentes = [_vigente(i) for i in range(tope)]

    resultado, bloqueos, _ = aplicador.aplicar(_registro_persona())

    assert resultado is None
    assert len(bloqueos) == 1
    assert f"ya tiene {tope} roles de persona vigentes (tope {tope})" in bloqueos[0]
    assert "se aprobo pero no se aplica" in bloqueos[0]
    # Se pidio con el usuario y el `sub` de la identidad congelada, con la hora de
    # aplicacion y con el cliente del propio aplicador (un solo Stubber).
    [llamada] = entorno_persona.llamadas
    assert llamada["usuario"] == _USUARIO
    assert llamada["sub"] == _SUB
    assert llamada["ahora"] == aplicador._ahora_utc()
    assert llamada["iam"] is aplicador._cliente


def test_el_tope_no_bloquea_la_reanudacion_de_la_propia_solicitud(iam, entorno_persona):
    """El rol de ESTA solicitud cuenta entre los vigentes: si ya esta, la corrida sigue."""
    tope = config.MAX_ROLES_VIGENTES_POR_PERSONA
    entorno_persona.vigentes = [_vigente(i) for i in range(tope - 1)] + [_vigente(0, solicitud=_ID_P)]
    assert len(entorno_persona.vigentes) == tope
    _rol_en_aws(iam)

    actual, bloqueos, _ = aplicador.prevuelo(_registro_persona())

    assert bloqueos == []
    assert actual["principal_id"] == _ROL_ID

    # Y por debajo del tope, sin rol propio, tampoco bloquea.
    entorno_persona.vigentes = [_vigente(i) for i in range(tope - 1)]
    _sin_rol(iam)
    _, bloqueos, _ = aplicador.prevuelo(_registro_persona())
    assert bloqueos == []


def test_el_tope_lee_los_roles_de_la_persona_con_list_roles(iam, entorno_persona, monkeypatch):
    """Sin doble: la funcion real de `personas`, con el cliente del aplicador y un Stubber."""
    monkeypatch.setattr(personas, "roles_vigentes", _ROLES_VIGENTES_REAL)
    monkeypatch.setattr(aplicador, "identificar_aprobador", lambda: pytest.fail("bloquear no llega a escribir"))
    ajenos = [_vigente(i) for i in range(config.MAX_ROLES_VIGENTES_POR_PERSONA)]
    iam.add_response(
        "list_roles",
        {"Roles": [
            {"Path": personas.PATH_PERSONAS, "RoleName": v["nombre"], "RoleId": f"AROA{i:016d}", "Arn": v["arn"],
             "CreateDate": "2026-10-26T10:00:00Z"}
            for i, v in enumerate(ajenos)
        ], "IsTruncated": False},
        {"PathPrefix": personas.PATH_PERSONAS},
    )
    for v in ajenos:
        iam.add_response(
            "list_role_tags",
            {"Tags": [
                {"Key": personas.TAG_SOLICITUD, "Value": v["solicitud_id"]},
                {"Key": personas.TAG_PERSONA, "Value": _USUARIO},
                {"Key": personas.TAG_SUB, "Value": _SUB},
                {"Key": personas.TAG_VENCE, "Value": "2026-10-26T15:00:00Z"},
            ]},
            {"RoleName": v["nombre"]},
        )

    resultado, bloqueos, _ = aplicador.aplicar(_registro_persona())

    assert resultado is None
    assert "roles de persona vigentes" in bloqueos[0]


# --- Coherencia de modo -----------------------------------------------------


def _con_huella(registro: dict) -> dict:
    """La huella recalculada: el bloqueo que se prueba es el de coherencia, no el de huella."""
    registro["aprobacion"]["huella"] = huella.calcular(registro)
    return registro


_OTRA_PERSONA = {"usuario": "otra.persona", "sub": _SUB, "client_id": _CLIENTE}

_INCOHERENCIAS_DE_PERSONA = {
    "la solicitud no trae persona": (
        lambda r: r["solicitud"].pop("persona"), "no trae `persona`"),
    "la solicitud declara un principal": (
        lambda r: r["solicitud"].update(principal_arn_declarado=_ARN), "`principal_arn_declarado`"),
    "otro usuario en la solicitud": (
        lambda r: r["solicitud"].update(persona=_OTRA_PERSONA), "no es el de la solicitud guardada"),
    "otro solicitante": (
        lambda r: r["solicitante"].update(persona="otra.persona"), "`solicitante.persona`"),
    "sin bloque de solicitante": (
        lambda r: r.pop("solicitante"), "`solicitante.persona`"),
    "otro usuario en ejecutado_por": (
        lambda r: r["ejecutado_por"].update(usuario="IdentityCenter_otra.persona"), "`ejecutado_por.usuario`"),
    "ejecutado_por sin el prefijo": (
        lambda r: r["ejecutado_por"].update(usuario=_USUARIO), "`ejecutado_por.usuario`"),
    "otras horas en la solicitud": (
        lambda r: r["solicitud"].update(horas=5), "horas de la identidad congelada"),
    "otro rol previsto": (
        lambda r: r["identidad_verificada"].update(principal_arn=personas.arn_de_rol(_CUENTA, _USUARIO, "req-20261026-00000000")),
        "ARN del rol previsto"),
    "otra cuenta en el rol previsto": (
        lambda r: r["identidad_verificada"].update(principal_arn=personas.arn_de_rol("999988887777", _USUARIO, _ID_P)),
        "ARN del rol previsto"),
}


@pytest.mark.parametrize("mutar,texto", _INCOHERENCIAS_DE_PERSONA.values(), ids=_INCOHERENCIAS_DE_PERSONA.keys())
def test_un_registro_de_persona_incoherente_se_bloquea_antes_de_tocar_iam(iam, entorno_persona, mutar, texto):
    registro = _registro_persona()
    mutar(registro)
    _con_huella(registro)

    actual, bloqueos, _ = aplicador.prevuelo(registro)

    assert actual == {}
    assert any(texto in b for b in bloqueos), bloqueos
    assert entorno_persona.llamadas == []  # ni el tope ni el rol: el Stubber no tiene nada programado


def test_el_registro_de_persona_coherente_pasa_la_coherencia(iam, entorno_persona):
    assert aplicador._coherencia_de_modo(_registro_persona()) == []


def test_un_registro_de_principal_existente_con_persona_en_la_solicitud_se_bloquea(iam):
    registro = _registro()
    registro["solicitud"]["persona"] = dict(_OTRA_PERSONA)
    _con_huella(registro)

    _, bloqueos, _ = aplicador.prevuelo(registro)

    assert any("principal existente" in b and "`persona`" in b for b in bloqueos), bloqueos


def test_la_coherencia_corre_tras_los_controles_y_antes_de_revalidar(iam, entorno_persona, monkeypatch):
    """Si la coherencia bloquea, `revalidar` (que lee la cuenta) no llega a correr."""
    monkeypatch.setattr(aplicador, "revalidar", lambda r: pytest.fail("la coherencia va antes de revalidar"))
    registro = _registro_persona()
    registro["solicitud"].pop("persona")
    _con_huella(registro)
    _, bloqueos, _ = aplicador.prevuelo(registro)
    assert bloqueos


# --- `vence` del reintento ---------------------------------------------------


@pytest.mark.parametrize(
    "vence",
    [
        "2026-10-26T10:59:59Z",  # ya paso (ahora son las 11:00)
        "2026-10-26T11:00:00Z",  # justo ahora: ya no es futuro
        "2026-10-26T15:00:01Z",  # mas alla de ahora mas 4 horas
        "2026-10-27T11:00:00Z",  # un dia: nadie lo pidio asi
        "manana por la tarde",   # ilegible
        "2026-10-26 15:00:00",   # otro formato
    ],
)
def test_un_vence_de_la_politica_ya_creada_fuera_de_rango_no_se_adjunta(iam, entorno_persona, monkeypatch, vence):
    monkeypatch.setattr(aplicador, "identificar_aprobador", lambda: pytest.fail("bloquear no llega a escribir"))
    _sin_rol(iam)
    _politica_en_aws(iam, vence=vence)

    resultado, bloqueos, _ = aplicador.aplicar(_registro_persona())

    assert resultado is None
    assert len(bloqueos) == 1
    assert "vencimiento de la politica ya creada no es valido o ya paso" in bloqueos[0]
    assert "tramita otra solicitud" in bloqueos[0]


def test_un_vence_de_la_politica_ya_creada_dentro_de_rango_se_acepta(iam, entorno_persona, ejecutor):
    """El limite superior es inclusivo: ahora mas las horas de la identidad."""
    _sin_rol(iam)
    _politica_en_aws(iam, vence="2026-10-26T15:00:00Z")
    iam.add_response("create_role", _respuesta_crear_rol(), _crear_rol_esperado("2026-10-26T15:00:00Z"))
    iam.add_response("attach_role_policy", {}, {"RoleName": _NOMBRE_ROL, "PolicyArn": _POLITICA_P})

    resultado, bloqueos, _ = aplicador.aplicar(_registro_persona())

    assert bloqueos == []
    assert resultado["aplicacion"]["vence"] == "2026-10-26T15:00:00Z"


# --- Dos corridas casi a la vez ----------------------------------------------


def test_si_otra_corrida_crea_la_politica_con_otro_vence_se_converge_a_ese_vence(iam, entorno_persona, ejecutor):
    """EntityAlreadyExists con `vence=` distinto del nuestro: se rehace el documento con el suyo.

    Nuestra corrida calculo 15:00; la otra llego un rato antes con 14:30. Si se
    comparara el documento nuestro con el suyo saldria "parar"; converger es
    tomar su `vence` y seguir con el rol y el attach.
    """
    suyo = "2026-10-26T14:30:00Z"
    _sin_rol(iam)  # pre-vuelo
    iam.add_client_error("get_policy", service_error_code="NoSuchEntity", expected_params={"PolicyArn": _POLITICA_P})
    iam.add_client_error("create_policy", service_error_code="EntityAlreadyExists")
    _politica_en_aws(iam, vence=suyo)  # observar tras el conflicto
    iam.add_response("create_role", _respuesta_crear_rol(), _crear_rol_esperado(suyo))
    iam.add_response("attach_role_policy", {}, {"RoleName": _NOMBRE_ROL, "PolicyArn": _POLITICA_P})

    resultado, bloqueos, _ = aplicador.aplicar(_registro_persona())

    assert bloqueos == []
    ap = resultado["aplicacion"]
    assert ap["policy_arn"] == _POLITICA_P
    assert ap["vence"] == suyo
    assert ap["documento_aplicado"] == _documento_p(suyo)
    assert ap["decision"] == "adjuntar"


def test_la_convergencia_ante_el_conflicto_tambien_exige_un_vence_valido(iam, entorno_persona, ejecutor):
    """Se adopta el `vence` de la otra corrida solo si es uno que esta corrida habria aceptado."""
    suyo = "2026-10-26T20:00:00Z"  # mas de 4 horas desde ahora
    _sin_rol(iam)
    iam.add_client_error("get_policy", service_error_code="NoSuchEntity", expected_params={"PolicyArn": _POLITICA_P})
    iam.add_client_error("create_policy", service_error_code="EntityAlreadyExists")
    _politica_en_aws(iam, vence=suyo)  # ni create_role ni attach: el Stubber no los tiene

    resultado, bloqueos, _ = aplicador.aplicar(_registro_persona())

    assert resultado is None
    assert "vencimiento de la politica ya creada no es valido o ya paso" in bloqueos[0]


def test_si_otra_corrida_crea_la_politica_sin_vence_en_la_descripcion_no_se_adopta(iam, entorno_persona):
    registro = _registro_persona()
    iam.add_client_error("create_policy", service_error_code="EntityAlreadyExists")
    _politica_en_aws(iam, descripcion=f"agente-iam | solicitud={_ID_P} | huella=x")

    with pytest.raises(RuntimeError, match="vence="):
        aplicador.crear(registro, _documento_p(), _CUENTA, vence=_VENCE)


def test_crear_en_modo_principal_ante_un_conflicto_devuelve_sin_vence(iam):
    iam.add_client_error("create_policy", service_error_code="EntityAlreadyExists")
    politica = {"Policy": {"PolicyName": "agente-iam-req-jose", "Arn": _POLITICA_ARN, "DefaultVersionId": "v1",
                           "AttachmentCount": 0, "Description": "agente-iam | solicitud=req-jose | huella=x"}}
    iam.add_response("get_policy", politica, {"PolicyArn": _POLITICA_ARN})
    iam.add_response("get_policy", politica, {"PolicyArn": _POLITICA_ARN})
    iam.add_response("get_policy_version", {"PolicyVersion": {
        "Document": urllib.parse.quote(json.dumps(_DOC)), "VersionId": "v1", "IsDefaultVersion": True,
    }}, {"PolicyArn": _POLITICA_ARN, "VersionId": "v1"})

    assert aplicador.crear(_registro(), _DOC, _CUENTA) == (_POLITICA_ARN, None)
