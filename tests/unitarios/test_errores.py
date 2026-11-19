"""Fase 4: toda corrida deja registro, incluida la que falla.

La regla bajo prueba: `procesar` no deja escapar ninguna excepcion, porque
`guardar()` corre despues y una excepcion en vuelo dejaria la solicitud sin
rastro en disco — justo las corridas que fallan son las que mas necesitan
auditarse.
"""

import json
from pathlib import Path

import pytest

from agente_iam import almacen, cli, orquestador
from tests.dobles import _ANA as _ARN
from tests.dobles import _propuesta, _solicitud as _solicitud_base

_IDENTIDAD = {
    "principal_arn": _ARN,
    "tipo": "user",
    "existe": True,
    "cuenta": "111122223333",
    "permissions_boundary": "arn:aws:iam::111122223333:policy/AgenteIAM-Techo",
    "politicas_actuales": [],
    "detalle": None,
}


def _solicitud():
    # El id lo comprueban los tests de registro de abajo.
    return _solicitud_base(solicitud_id="req-error", justificacion="Necesito leer el bucket.")


class _AgenteFalso:
    """Devuelve una propuesta y, en la llamada `revienta_en`, lanza."""

    def __init__(self, revienta_en=None):
        self.llamadas = 0
        self.revienta_en = revienta_en

    def __call__(self, mensaje, structured_output_model=None):
        self.llamadas += 1
        if self.llamadas == self.revienta_en:
            raise RuntimeError("Bedrock no respondio")
        return type("R", (), {"structured_output": _propuesta()})()


@pytest.fixture
def sin_aws(monkeypatch):
    """Neutraliza todo lo que sale a la red; cada test rompe lo suyo."""
    monkeypatch.setattr(orquestador, "verificar", lambda arn: _identidad_obj())
    monkeypatch.setattr(orquestador, "chequeos_posteriores", lambda p, s, i: ([], []))
    monkeypatch.setattr(orquestador, "documento_de_politica", lambda arn: {"Statement": []})
    monkeypatch.setattr(
        orquestador,
        "validar_politica",
        lambda doc: {"aprobable": True, "bloqueos": [], "criticos": [], "menores": []},
    )
    # Los dobles siguen el contrato de la Fase 5: si `simulacion` cambia
    # de forma, estos tests fallan y hay que actualizarlos a proposito.
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
    monkeypatch.setattr(
        orquestador,
        "redundancia",
        # Contrato de la Fase 5c: dos cubos y ninguno intermedio.
        lambda arn, doc, ctx=None: {
            "ya_tenia": [],
            "acceso_nuevo": ["s3:GetObject"],
            "es_totalmente_redundante": False,
        },
    )


def _identidad_obj():
    from agente_iam.models import IdentidadVerificada

    return IdentidadVerificada(**_IDENTIDAD)


# ---------------------------------------------------------------------------
# Cada fase falla por su lado y deja su registro.
# ---------------------------------------------------------------------------


def test_error_en_chequeos_previos_deja_registro(sin_aws, monkeypatch):
    def revienta(arn):
        raise RuntimeError("Throttling: rate exceeded")

    monkeypatch.setattr(orquestador, "verificar", revienta)

    registro = orquestador.procesar(_solicitud())

    assert registro["estado"] == "error"
    assert registro["error"]["fase"] == "chequeos_previos"
    assert registro["error"]["tipo"] == "RuntimeError"
    assert "Throttling" in registro["error"]["detalle"]
    assert registro["identidad_verificada"] is None
    assert registro["id"] == "req-error"  # el registro sigue siendo auditable


def test_error_en_el_agente_conserva_los_intentos(sin_aws, monkeypatch):
    # Intento 1 valida mal (el loop sigue), intento 2 revienta. El primer
    # intento no puede perderse: sin el no se audita por que fallo.
    monkeypatch.setattr(
        orquestador,
        "validar_politica",
        lambda doc: {
            "aprobable": False,
            "bloqueos": ["algo"],
            "criticos": [],
            "menores": [],
        },
    )
    agente = _AgenteFalso(revienta_en=2)
    monkeypatch.setattr(orquestador, "construir_agente", lambda: agente)

    registro = orquestador.procesar(_solicitud())

    assert registro["estado"] == "error"
    assert registro["error"]["fase"] == "agente"
    assert registro["intentos"] == 1
    assert len(registro["historial_validacion"]) == 1
    assert registro["historial_validacion"][0]["intento"] == 1


def test_error_en_el_delta_conserva_la_propuesta(sin_aws, monkeypatch):
    monkeypatch.setattr(orquestador, "construir_agente", lambda: _AgenteFalso())

    def revienta(arn, doc, ctx=None):
        raise RuntimeError("SimulatePrincipalPolicy fallo")

    monkeypatch.setattr(orquestador, "redundancia", revienta)

    registro = orquestador.procesar(_solicitud())

    assert registro["estado"] == "error"
    assert registro["error"]["fase"] == "delta"
    # La propuesta era valida: no se tira a la basura por un fallo del
    # contraste, pero tampoco se presenta como si el delta estuviera vacio.
    assert registro["propuesta"]["nombre_politica"] == "Prueba"
    assert registro["intentos"] == 1


def test_corrida_feliz_sigue_igual(sin_aws, monkeypatch):
    # La red de la Fase 4 no debe cambiar el camino normal.
    monkeypatch.setattr(orquestador, "construir_agente", lambda: _AgenteFalso())

    registro = orquestador.procesar(_solicitud())

    assert registro["estado"] == "propuesta"
    assert registro["intentos"] == 1
    assert "error" not in registro
    assert registro["acceso_nuevo"]["acceso_nuevo"] == ["s3:GetObject"]


def test_ctrl_c_no_queda_atrapado(sin_aws, monkeypatch):
    # Se captura Exception, NO BaseException: una interrupcion tuya debe
    # interrumpir de verdad, no archivarse como fallo del sistema.
    def interrumpe(arn):
        raise KeyboardInterrupt

    monkeypatch.setattr(orquestador, "verificar", interrumpe)

    with pytest.raises(KeyboardInterrupt):
        orquestador.procesar(_solicitud())


# ---------------------------------------------------------------------------
# El registro de error llega a disco y se puede mostrar sin reventar.
# ---------------------------------------------------------------------------


def test_el_registro_de_error_se_guarda(tmp_path, monkeypatch):
    monkeypatch.setattr(almacen, "DIR_SOLICITUDES", str(tmp_path / "solicitudes"))
    monkeypatch.setattr(almacen, "ALMACEN", "disco")
    registro = {
        "id": "req-error",
        "creada": "2026-08-28T00:00:00+00:00",
        "estado": "error",
        "intentos": 0,
        "solicitud": {},
        "identidad_verificada": None,
        "error": {
            "fase": "agente",
            "tipo": "RuntimeError",
            "detalle": "x",
            "traza": "...",
        },
    }

    donde = almacen.guardar_propuesta(registro)

    ruta = Path(donde)
    assert ruta.exists()
    assert json.loads(ruta.read_text())["error"]["fase"] == "agente"


def test_mostrar_no_revienta_con_un_registro_de_error(capsys):
    # El bug que la Fase 4 tenia que evitar: mostrar() accedia a
    # registro["propuesta"] sin comprobar, asi que fallaba al mostrar el
    # error — el manejo de errores rompiendose justo cuando importa.
    cli.mostrar(
        {
            "id": "req-error",
            "estado": "error",
            "intentos": 0,
            "identidad_verificada": None,
            "propuesta": None,
            "error": {
                "fase": "chequeos_previos",
                "tipo": "RuntimeError",
                "detalle": "Throttling",
                "traza": "...",
            },
        }
    )
    salida = capsys.readouterr().out
    assert "[ERROR]" in salida
    assert "chequeos_previos" in salida


# --- Fase 13: contratos que antes eran implicitos (los marco mypy) ----------


def test_salida_del_agente_que_no_es_una_propuesta(sin_aws, monkeypatch):
    # Strands tipa la salida como "BaseModel | None". Si llegara None, el
    # fallo tiene que nombrar la causa, no ser un AttributeError tres lineas
    # mas abajo ('NoneType' has no attribute 'policy_document').
    sin_salida = type("R", (), {"structured_output": None})()
    monkeypatch.setattr(orquestador, "construir_agente", lambda: (lambda *a, **k: sin_salida))

    registro = orquestador.procesar(_solicitud())

    assert registro["estado"] == "error"
    assert registro["error"]["fase"] == "agente"
    assert registro["error"]["tipo"] == "TypeError"
    assert "PropuestaPolitica" in registro["error"]["detalle"]
