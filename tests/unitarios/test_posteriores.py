"""Fase 2: chequeos deterministas sobre la PROPUESTA del modelo.

Dos piezas bajo prueba, sin red ni cuenta AWS:

  - catalogo.excede_tipo_acceso, con un servicio falso inyectado en la
    memoria del catalogo (probamos NUESTRA logica de niveles, no el JSON
    de AWS).
  - orquestador.chequeos_posteriores, con el nivel monkeypatcheado.
"""

import pytest

from agente_iam.herramientas import catalogo
from agente_iam import coherencia, orquestador
from tests.dobles import _ANA, _CUENTA
from tests.dobles import _propuesta as _propuesta_base
from tests.dobles import _solicitud as _solicitud_base

# ---------------------------------------------------------------------------
# catalogo.excede_tipo_acceso con un catalogo falso.
# ---------------------------------------------------------------------------

_PROPS = {"IsList": False, "IsWrite": False, "IsPermissionManagement": False, "IsTaggingOnly": False}


@pytest.fixture
def catalogo_falso(monkeypatch):
    monkeypatch.setitem(
        catalogo._MEMORIA,
        "fakesvc",
        {
            "getthing": {"recursos": [{"Name": "thing"}], "propiedades": dict(_PROPS)},
            "putthing": {
                "recursos": [{"Name": "thing"}],
                "propiedades": dict(_PROPS, IsWrite=True),
            },
            "tagthing": {
                "recursos": [],
                "propiedades": dict(_PROPS, IsTaggingOnly=True),
            },
            "grantthing": {
                "recursos": [],
                "propiedades": dict(_PROPS, IsPermissionManagement=True),
            },
        },
    )


def test_lectura_acepta_lectura(catalogo_falso):
    assert catalogo.excede_tipo_acceso("fakesvc:GetThing", "lectura") is False


def test_lectura_rechaza_escritura(catalogo_falso):
    assert catalogo.excede_tipo_acceso("fakesvc:PutThing", "lectura") is True


def test_lectura_rechaza_tagging(catalogo_falso):
    # Etiquetar modifica el recurso y, con ABAC, puede cambiar quien
    # accede a que: no es lectura.
    assert catalogo.excede_tipo_acceso("fakesvc:TagThing", "lectura") is True


def test_escritura_acepta_escritura(catalogo_falso):
    assert catalogo.excede_tipo_acceso("fakesvc:PutThing", "escritura") is False


def test_escritura_rechaza_gestion_de_permisos(catalogo_falso):
    assert catalogo.excede_tipo_acceso("fakesvc:GrantThing", "escritura") is True


def test_administracion_tampoco_concede_gestion_de_permisos(catalogo_falso):
    # Revision 2026-10: ningun nivel concede IsPermissionManagement, porque
    # escribir politicas de recurso reparte acceso fuera del sistema.
    assert catalogo.excede_tipo_acceso("fakesvc:GrantThing", "administracion") is True
    assert catalogo.excede_tipo_acceso("fakesvc:PutThing", "administracion") is False


def test_prefijo_se_expande_contra_el_catalogo(catalogo_falso):
    # 'Get*' solo cubre lecturas -> cabe en lectura.
    assert catalogo.excede_tipo_acceso("fakesvc:Get*", "lectura") is False
    # 'fakesvc:*' cubre tambien PutThing -> excede lectura.
    assert catalogo.excede_tipo_acceso("fakesvc:*", "lectura") is True


def test_accion_desconocida_es_duda_no_veredicto(catalogo_falso):
    assert catalogo.excede_tipo_acceso("fakesvc:NoExiste", "lectura") is None


def test_soporta_recursos_con_el_indice_nuevo(catalogo_falso):
    # La Fase 2 cambio la forma del indice del catalogo; esta funcion
    # anterior debe seguir leyendo bien la parte de recursos.
    assert catalogo.soporta_recursos("fakesvc:GetThing") is True
    assert catalogo.soporta_recursos("fakesvc:TagThing") is False
    assert catalogo.soporta_recursos("fakesvc:NoExiste") is None


# ---------------------------------------------------------------------------
# orquestador.chequeos_posteriores
# ---------------------------------------------------------------------------

_ARN = _ANA

_IDENTIDAD = {
    "principal_arn": _ARN,
    "tipo": "user",
    "existe": True,
    "cuenta": _CUENTA,
    "politicas_actuales": [],
}

_solicitud = _solicitud_base


def _propuesta(principal=_ARN, acciones=None, effect="Allow"):
    # En s3 toda concesion lleva la cuenta del recurso (S5, 24-10-2026); sus
    # tests estan en test_revision_2026_10.
    return _propuesta_base(
        acciones, principal=principal, effect=effect,
        condicion={"StringEquals": {"aws:ResourceAccount": "${aws:PrincipalAccount}"}},
    )


def test_propuesta_coherente_pasa(monkeypatch):
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: False)
    bloqueos, advertencias = orquestador.chequeos_posteriores(
        _propuesta(), _solicitud(), _IDENTIDAD
    )
    assert bloqueos == []
    assert advertencias == []


def test_destinatario_cambiado_se_bloquea(monkeypatch):
    # El vector: la inyeccion no cambia las acciones, cambia a QUIEN.
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: False)
    otro = "arn:aws:iam::111122223333:user/Mateo"
    bloqueos, _ = orquestador.chequeos_posteriores(
        _propuesta(principal=otro), _solicitud(), _IDENTIDAD
    )
    assert len(bloqueos) == 1
    assert "destinatario" in bloqueos[0]


def test_accion_de_otro_servicio_se_bloquea(monkeypatch):
    # Solicitud de s3 con una accion de dynamodb colada.
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: False)
    bloqueos, _ = orquestador.chequeos_posteriores(
        _propuesta(acciones=["s3:GetObject", "dynamodb:GetItem"]),
        _solicitud(),
        _IDENTIDAD,
    )
    assert len(bloqueos) == 1
    assert "dynamodb" in bloqueos[0]


def test_nivel_excedido_se_bloquea(monkeypatch):
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: True)
    bloqueos, _ = orquestador.chequeos_posteriores(
        _propuesta(acciones=["s3:PutObject"]), _solicitud(), _IDENTIDAD
    )
    assert len(bloqueos) == 1
    assert "excede el nivel" in bloqueos[0]


def test_nivel_desconocido_es_advertencia_no_bloqueo(monkeypatch):
    # La duda del catalogo no debe ser falso positivo (leccion del
    # CONTEXTO §9), pero tampoco pasar en silencio: va a `menores`.
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: None)
    bloqueos, advertencias = orquestador.chequeos_posteriores(
        _propuesta(), _solicitud(), _IDENTIDAD
    )
    assert bloqueos == []
    assert len(advertencias) == 1
    assert advertencias[0]["codigo"] == "NIVEL_DE_ACCESO_DESCONOCIDO"


def test_statement_deny_no_se_chequea(monkeypatch):
    # Un Deny extra (p.ej. de refuerzo) no concede: no debe generar
    # bloqueos aunque mencione otro servicio.
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: False)
    bloqueos, advertencias = orquestador.chequeos_posteriores(
        _propuesta(acciones=["iam:CreateUser"], effect="Deny"),
        _solicitud(),
        _IDENTIDAD,
    )
    assert bloqueos == []
    assert advertencias == []


def test_una_region_fuera_de_la_lista_se_rechaza_en_el_formulario():
    # La SCP de la cuenta solo deja us-east-1: una solicitud de otra region
    # se corta antes del modelo, con el motivo en el registro.
    from agente_iam.models import CamposEstructurados

    fuera = CamposEstructurados(
        servicio="s3", recurso="b", tipo_acceso="lectura", region="eu-west-1"
    )
    motivos = coherencia.chequeos_formulario(fuera)
    assert any("eu-west-1" in m and "regiones permitidas" in m for m in motivos)

    dentro = CamposEstructurados(
        servicio="s3", recurso="b", tipo_acceso="lectura", region="us-east-1"
    )
    assert not any("regiones permitidas" in m for m in coherencia.chequeos_formulario(dentro))
