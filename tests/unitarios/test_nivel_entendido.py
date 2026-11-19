"""Fase 28, punto 1: sin "Tipo de acceso" en el formulario, la barrera de nivel sigue.

El modelo declara `nivel_entendido` y `coherencia.chequeos_posteriores` bloquea
la politica que vaya mas alla; el codigo calcula ademas lo que concede de verdad
(`coherencia.nivel_real`) y con eso sube el riesgo minimo. Los registros
anteriores traen `tipo_acceso` y se siguen revalidando con el. Se pone en rojo
si una escritura pasa bajo `lectura`, si una propuesta sin nivel pasa, si el
nivel calculado sale mal o si modificar o borrar no exige confirmar el riesgo.
Sin red: el catalogo de s3 es falso y esta en memoria.
"""

import pytest

from agente_iam import coherencia
from agente_iam.herramientas import catalogo
from agente_iam.orquestador import _prompt
from tests.dobles import _ANA, _propuesta, _solicitud

_PROPS = {"IsList": False, "IsWrite": False, "IsPermissionManagement": False, "IsTaggingOnly": False}
_IDENTIDAD = {"principal_arn": _ANA, "tipo": "user", "existe": True, "cuenta": "111122223333"}
_CUENTA_DEL_RECURSO = {"StringEquals": {"aws:ResourceAccount": "${aws:PrincipalAccount}"}}


@pytest.fixture(autouse=True)
def catalogo_s3(monkeypatch):
    monkeypatch.setitem(
        catalogo._MEMORIA,
        "s3",
        {
            "getobject": {"recursos": [{"Name": "object"}], "propiedades": dict(_PROPS)},
            "listbucket": {"recursos": [{"Name": "bucket"}], "propiedades": dict(_PROPS, IsList=True)},
            "putobject": {"recursos": [{"Name": "object"}], "propiedades": dict(_PROPS, IsWrite=True)},
            "deleteobject": {"recursos": [{"Name": "object"}], "propiedades": dict(_PROPS, IsWrite=True)},
        },
    )


def _con_nivel(acciones, nivel):
    p = _propuesta(acciones, condicion=_CUENTA_DEL_RECURSO)
    return p.model_copy(update={"nivel_entendido": nivel})


def _bloqueos(propuesta, tipo=None):
    bloqueos, _ = coherencia.chequeos_posteriores(propuesta, _solicitud(tipo=tipo), _IDENTIDAD)
    return bloqueos


def test_una_escritura_bajo_lectura_entendida_se_bloquea():
    bloqueos = _bloqueos(_con_nivel(["s3:PutObject"], "lectura"))
    assert len(bloqueos) == 1
    assert "excede el nivel 'lectura'" in bloqueos[0]


def test_una_escritura_con_modificacion_entendida_pasa():
    assert _bloqueos(_con_nivel(["s3:GetObject", "s3:PutObject"], "modificacion")) == []


def test_una_propuesta_sin_nivel_y_sin_tipo_se_bloquea_para_repararla():
    bloqueos = _bloqueos(_con_nivel(["s3:GetObject"], None))
    assert bloqueos == [
        "Falta 'nivel_entendido': declara 'lectura' si la solicitud solo pide ver, "
        "listar o descargar, o 'modificacion' si pide subir, cambiar o borrar."
    ]


def test_un_registro_anterior_con_tipo_acceso_manda_sobre_lo_que_diga_el_modelo():
    """Se revalida con lo que pidio la persona entonces: un `modificacion` del modelo no lo sube."""
    bloqueos = _bloqueos(_con_nivel(["s3:PutObject"], "modificacion"), tipo="lectura")
    assert len(bloqueos) == 1
    assert "excede el nivel 'lectura'" in bloqueos[0]


@pytest.mark.parametrize(
    ("acciones", "esperado"),
    [
        (["s3:GetObject", "s3:ListBucket"], "lectura"),
        (["s3:GetObject", "s3:PutObject"], "modifica"),
        (["s3:GetObject", "s3:DeleteObject"], "borra"),
        (["s3:Get*"], "lectura"),
        (["s3:*Object"], "borra"),
        (["s3:NoExiste"], None),
    ],
)
def test_el_nivel_real_lo_calcula_el_codigo(acciones, esperado):
    documento = _propuesta(acciones).policy_document.model_dump(exclude_none=True)
    assert coherencia.nivel_real(documento) == esperado


def test_un_deny_no_cuenta_para_el_nivel():
    documento = {"Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["*"]},
        {"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": ["*"]},
    ]}
    assert coherencia.nivel_real(documento) == "lectura"


def test_sin_catalogo_en_memoria_el_nivel_no_se_adivina(monkeypatch):
    monkeypatch.delitem(catalogo._MEMORIA, "s3")
    assert coherencia.nivel_real({"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"]}]}) is None


@pytest.mark.parametrize(
    ("nivel", "motivo"),
    [("modifica", "la propuesta modifica datos"), ("borra", "la propuesta puede borrar datos")],
)
def test_modificar_o_borrar_sube_el_riesgo_minimo(nivel, motivo):
    solicitud = _solicitud(tipo=None).model_dump()
    assert coherencia.riesgo_minimo(solicitud, _ANA, [], nivel) == [motivo]
    assert coherencia.riesgo_minimo(solicitud, _ANA, [], "lectura") == []
    assert coherencia.riesgo_minimo(solicitud, _ANA, []) == []


def test_el_prompt_ya_no_trae_tipo_de_acceso_si_el_formulario_no_lo_manda():
    sol = _solicitud(tipo=None)
    texto = _prompt(sol, _IDENTIDAD)
    assert "tipo_acceso" not in texto
    assert "recurso_arn" not in texto
