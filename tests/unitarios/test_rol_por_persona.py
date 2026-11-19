"""El orquestador en sus dos modos (Fase 23, tarea 5), sin red.

Lo que se prueba es que el modo rol por persona NO pasa por `verificar` (no
hay ARN que verificar: el rol se crea al aplicar), que el tope de roles
vigentes corta antes de gastar el modelo, que la redundancia se mide contra
los roles de la persona y que el modo de principal existente sigue igual.
Todo lo que sale a la red se sustituye aqui: si un test llamara a AWS,
`tests/conftest.py` lo haria fallar.
"""

from datetime import datetime, timezone

import pytest

from agente_iam import orquestador, personas
from agente_iam.config import MAX_ROLES_VIGENTES_POR_PERSONA
from agente_iam.models import IdentidadVerificada
from tests.dobles import _ANA, _propuesta, _solicitud, _solicitud_persona

_CUENTA = "111122223333"
_TECHO = f"arn:aws:iam::{_CUENTA}:policy/AgenteIAM-Techo"


class _AgenteFalso:
    def __init__(self):
        self.llamadas = 0
        self.mensajes: list[str] = []

    def __call__(self, mensaje, structured_output_model=None):
        self.llamadas += 1
        self.mensajes.append(mensaje)
        return type("R", (), {"structured_output": _propuesta()})()


class _Espia:
    """Una funcion que cuenta sus llamadas y devuelve lo que se le diga."""

    def __init__(self, devuelve):
        self.devuelve = devuelve
        self.llamadas = 0
        self.args: tuple = ()
        self.kwargs: dict = {}

    def __call__(self, *args, **kwargs):
        self.llamadas += 1
        self.args, self.kwargs = args, kwargs
        return self.devuelve


def _delta(redundante: bool = False, **extra) -> dict:
    return {
        "ya_tenia": ["s3:GetObject"] if redundante else [],
        "acceso_nuevo": [] if redundante else ["s3:GetObject"],
        "es_totalmente_redundante": redundante,
        **extra,
    }


@pytest.fixture
def entorno(monkeypatch):
    """Todo lo que sale a la red, sustituido; cada test ajusta lo suyo."""
    agente = _AgenteFalso()
    entorno = type("E", (), {})()
    entorno.agente = agente
    entorno.construir = _Espia(agente)
    entorno.verificar = _Espia(
        IdentidadVerificada(
            principal_arn=_ANA,
            tipo="user",
            existe=True,
            cuenta=_CUENTA,
            permissions_boundary=_TECHO,
        )
    )
    entorno.roles_vigentes = _Espia([])
    entorno.redundancia = _Espia(_delta())
    entorno.redundancia_persona = _Espia(_delta())

    monkeypatch.setattr(orquestador, "verificar", entorno.verificar)
    monkeypatch.setattr(orquestador, "construir_agente", entorno.construir)
    monkeypatch.setattr(orquestador, "redundancia", entorno.redundancia)
    monkeypatch.setattr(orquestador, "redundancia_persona", entorno.redundancia_persona)
    monkeypatch.setattr(personas, "roles_vigentes", entorno.roles_vigentes)
    monkeypatch.setattr(personas, "cuenta_actual", lambda sts=None: _CUENTA)
    monkeypatch.setattr(orquestador, "chequeos_posteriores", lambda p, s, i: ([], []))
    monkeypatch.setattr(orquestador, "documento_de_politica", lambda arn: {"Statement": []})
    monkeypatch.setattr(
        orquestador,
        "validar_politica",
        lambda doc: {"aprobable": True, "bloqueos": [], "criticos": [], "menores": []},
    )
    monkeypatch.setattr(
        orquestador,
        "eficacia",
        lambda doc, ctx=None, boundary=None: {
            "acciones_efectivas": ["s3:GetObject"],
            "acciones_condicionales": [],
            "acciones_sin_efecto": [],
            "claves_sin_resolver": [],
            "concede_algo": True,
            "no_evaluable": False,
        },
    )
    return entorno


def test_en_modo_persona_no_se_verifica_ningun_arn_y_la_identidad_es_el_rol_previsto(entorno):
    sol = _solicitud_persona()

    registro = orquestador.procesar(sol)

    assert entorno.verificar.llamadas == 0
    identidad = registro["identidad_verificada"]
    assert identidad["modo"] == "rol_por_persona"
    assert identidad["principal_arn"] == personas.arn_de_rol(
        _CUENTA, sol.persona.usuario, sol.solicitud_id
    )
    assert identidad["tipo"] == "role"
    assert identidad["existe"] is True  # "beneficiario verificado": lo verifico el token
    assert identidad["principal_id"] == ""
    assert identidad["permissions_boundary"] == _TECHO
    assert identidad["horas"] == sol.horas
    assert identidad["persona"]["sub"] == sol.persona.sub
    assert registro["estado"] == "propuesta"


def test_el_tope_de_roles_vigentes_rechaza_antes_del_modelo(entorno):
    ahora = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entorno.roles_vigentes.devuelve = [
        {"arn": f"arn:{i}", "nombre": f"n{i}", "vence": ahora, "solicitud_id": f"req-{i}"}
        for i in range(MAX_ROLES_VIGENTES_POR_PERSONA)
    ]

    registro = orquestador.procesar(_solicitud_persona())

    assert registro["estado"] == "rechazada_en_chequeos_previos"
    assert any(
        f"ya tiene {MAX_ROLES_VIGENTES_POR_PERSONA} roles" in m and "5" in m
        for m in registro["motivos"]
    )
    assert entorno.construir.llamadas == 0
    assert entorno.agente.llamadas == 0


def test_un_rol_menos_que_el_tope_deja_pasar_al_modelo(entorno):
    entorno.roles_vigentes.devuelve = [{"arn": "a"}] * (MAX_ROLES_VIGENTES_POR_PERSONA - 1)

    registro = orquestador.procesar(_solicitud_persona())

    assert registro["estado"] == "propuesta"
    assert entorno.agente.llamadas == 1


def test_la_redundancia_por_persona_decide_el_estado(entorno):
    entorno.redundancia_persona.devuelve = _delta(redundante=True)

    registro = orquestador.procesar(_solicitud_persona())

    assert registro["estado"] == "redundante_no_requiere_cambio"
    assert entorno.redundancia_persona.llamadas == 1
    assert entorno.redundancia.llamadas == 0

    # Si no se pudo comprobar: sigue como propuesta, con el aviso en la validacion.
    entorno.redundancia_persona.devuelve = _delta(no_comprobada="ClientError: AccessDenied")

    registro = orquestador.procesar(_solicitud_persona())

    assert registro["estado"] == "propuesta"
    avisos = [m for m in registro["validacion"]["menores"] if m["codigo"] == "REDUNDANCIA_NO_COMPROBADA"]
    assert len(avisos) == 1
    assert avisos[0]["tipo"] == "WARNING"
    assert "AccessDenied" in avisos[0]["detalle"]
    assert entorno.redundancia.llamadas == 0


def test_el_prompt_en_modo_persona_avisa_del_rol_previsto(entorno):
    orquestador.procesar(_solicitud_persona())

    mensaje = entorno.agente.mensajes[0]
    assert (
        "El beneficiario es un rol que se creara al aplicar; su ARN es el de arriba "
        "y no debes nombrarlo en la politica."
    ) in mensaje
    # El ARN previsto va en los datos verificados, antes del aviso.
    arn = personas.arn_de_rol(_CUENTA, "solicitante.demo", "req-20261026-ab12cd34")
    assert mensaje.index(arn) < mensaje.index("El beneficiario es un rol")


def test_los_roles_se_listan_una_sola_vez_con_el_sub_y_se_pasan_a_la_redundancia(entorno):
    sol = _solicitud_persona()
    rol = {"arn": "arn:uno", "nombre": "n", "vence": "2099-01-01T00:00:00Z", "solicitud_id": "req-1"}
    entorno.roles_vigentes.devuelve = [rol]

    registro = orquestador.procesar(sol)

    assert registro["estado"] == "propuesta"
    # Una sola lectura de IAM por solicitud: el tope y la redundancia comparten la lista.
    assert entorno.roles_vigentes.llamadas == 1
    assert entorno.roles_vigentes.kwargs == {"sub": sol.persona.sub}
    kw = entorno.redundancia_persona.kwargs
    assert kw["roles"] == [rol]
    # El permiso pedido vence `horas` despues de ahora: un rol que vence antes no lo cubre.
    vence = personas.vence_como_fecha(kw["vence_nuevo"])
    assert vence is not None
    assert abs((vence - datetime.now(timezone.utc)).total_seconds() - sol.horas * 3600) < 120
    # La lista de roles no se cuela en el registro ni en el prompt.
    assert "roles" not in registro["identidad_verificada"]
    assert "arn:uno" not in entorno.agente.mensajes[0]


def test_el_prompt_no_lleva_el_sub_ni_el_cliente_de_la_persona(entorno):
    sol = _solicitud_persona(sub="sub-secreto-9876", client_id="z" * 26)

    registro = orquestador.procesar(sol)

    mensaje = entorno.agente.mensajes[0]
    assert "sub-secreto-9876" not in mensaje
    assert "z" * 26 not in mensaje
    assert sol.persona.usuario in mensaje
    # El registro, que es auditoria, si conserva quien fue.
    assert registro["identidad_verificada"]["persona"]["sub"] == "sub-secreto-9876"


def test_el_modo_principal_existente_sigue_igual(entorno):
    registro = orquestador.procesar(_solicitud())

    assert entorno.verificar.llamadas == 1
    assert entorno.roles_vigentes.llamadas == 0
    assert entorno.redundancia_persona.llamadas == 0
    assert entorno.redundancia.llamadas == 1
    assert registro["identidad_verificada"]["modo"] == "principal_existente"
    assert registro["estado"] == "propuesta"
    assert "El beneficiario es un rol" not in entorno.agente.mensajes[0]


def test_identidad_de_persona_exige_el_modo_persona():
    with pytest.raises(ValueError):
        orquestador.identidad_de_persona(_solicitud(), _CUENTA)


# --- Fase 28: el recurso se busca antes del modelo ----------------------------


def test_un_recurso_que_no_existe_se_rechaza_sin_llamar_al_modelo(entorno, monkeypatch):
    monkeypatch.setenv("AGENTE_IAM_COMPROBAR_EXISTENCIA", "1")
    llamadas = []
    monkeypatch.setattr(
        orquestador.existencia, "comprobar", lambda *a, **k: llamadas.append(a) or ("no_existe", "")
    )
    registro = orquestador.procesar(_solicitud_persona())
    assert registro["estado"] == "rechazada_en_chequeos_previos"
    assert registro["motivos_codigos"] == ["recurso_no_encontrado"]
    assert registro["recurso_comprobado"] == {"resultado": "no_existe", "detalle": ""}
    assert entorno.agente.llamadas == 0
    assert llamadas == [("s3", "finanzas-demo-111122223333", "us-east-1", _CUENTA)]


def test_si_no_se_pudo_comprobar_se_sigue_y_el_aprobador_lo_ve(entorno, monkeypatch):
    monkeypatch.setenv("AGENTE_IAM_COMPROBAR_EXISTENCIA", "1")
    monkeypatch.setattr(orquestador.existencia, "comprobar", lambda *a, **k: ("no_comprobado", "AccessDenied"))
    registro = orquestador.procesar(_solicitud_persona())
    assert registro["estado"] == "propuesta"
    assert entorno.agente.llamadas == 1
    assert any(m["codigo"] == "RECURSO_NO_COMPROBADO" for m in registro["validacion"]["menores"])


def test_con_otro_motivo_no_se_gasta_la_comprobacion(entorno, monkeypatch):
    monkeypatch.setenv("AGENTE_IAM_COMPROBAR_EXISTENCIA", "1")
    llamadas = []
    monkeypatch.setattr(orquestador.existencia, "comprobar", lambda *a, **k: llamadas.append(a) or ("existe", ""))
    entorno.roles_vigentes.devuelve = [{"arn": "a"}] * MAX_ROLES_VIGENTES_POR_PERSONA
    registro = orquestador.procesar(_solicitud_persona())
    assert registro["motivos_codigos"] == ["tope_de_roles"]
    assert llamadas == []
