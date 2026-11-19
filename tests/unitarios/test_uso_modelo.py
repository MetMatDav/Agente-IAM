"""El registro dice que modelo trabajo y cuanto gasto (22-10-2026).

Sin esto no se puede comparar un modelo con otro (Haiku frente a Sonnet)
ni saber el coste por solicitud. Lo que se comprueba:

  - la forma: todo registro lleva `uso_modelo`, tambien el rechazo previo,
    que no llama al modelo y declara 0 tokens;
  - el total: con varias vueltas del loop, el registro guarda lo
    acumulado al final, no lo de la primera vuelta;
  - el error: si el loop revienta, el registro conserva lo gastado hasta
    ahi, porque las corridas que fallan tambien cuestan.

Los dobles imitan `AgentResult.metrics` de Strands: `accumulated_usage`
y `accumulated_metrics` son acumulados de la instancia, que es una por
solicitud.
"""

from types import SimpleNamespace

from agente_iam import orquestador
from tests.unitarios.test_errores import _identidad_obj, _propuesta, _solicitud


def _resultado(entrada: int, salida: int, ms: int):
    metricas = SimpleNamespace(
        accumulated_usage={"inputTokens": entrada, "outputTokens": salida, "totalTokens": entrada + salida},
        accumulated_metrics={"latencyMs": ms},
    )
    return SimpleNamespace(structured_output=_propuesta(), metrics=metricas)


class _AgenteConUso:
    """Cada llamada acumula 1000 de entrada, 100 de salida y 500 ms, como
    hace Strands con una misma instancia; en `revienta_en` lanza."""

    def __init__(self, revienta_en=None):
        self.llamadas = 0
        self.revienta_en = revienta_en

    def __call__(self, mensaje, structured_output_model=None):
        self.llamadas += 1
        if self.llamadas == self.revienta_en:
            raise RuntimeError("Bedrock no respondio")
        n = self.llamadas
        return _resultado(1000 * n, 100 * n, 500 * n)


def _preparar(monkeypatch, agente, aprobable_en=1):
    monkeypatch.setattr(orquestador, "verificar", lambda arn: _identidad_obj())
    monkeypatch.setattr(orquestador, "construir_agente", lambda: agente)
    monkeypatch.setattr(orquestador, "chequeos_posteriores", lambda p, s, i: ([], []))
    vueltas = {"n": 0}

    def validar(doc):
        vueltas["n"] += 1
        ok = vueltas["n"] >= aprobable_en
        return {"aprobable": ok, "bloqueos": [] if ok else ["falta algo"], "criticos": [], "menores": []}

    monkeypatch.setattr(orquestador, "validar_politica", validar)
    monkeypatch.setattr(
        orquestador,
        "eficacia",
        lambda d, c, boundary=None: {
            "concede_algo": True, "acciones_condicionales": [], "acciones_sin_efecto": [], "claves_sin_resolver": []
        },
    )
    monkeypatch.setattr(orquestador, "redundancia", lambda arn, d, c: {"es_totalmente_redundante": False})
    # La identidad de prueba lleva techo: sin esto el loop leeria su
    # documento en IAM de verdad.
    monkeypatch.setattr(orquestador, "documento_de_politica", lambda arn: {"Version": "2012-10-17", "Statement": []})


def test_el_registro_lleva_el_modelo_y_el_total_de_varias_vueltas(monkeypatch):
    _preparar(monkeypatch, _AgenteConUso(), aprobable_en=2)
    registro = orquestador.procesar(_solicitud())
    assert registro["intentos"] == 2
    assert registro["uso_modelo"] == {
        "modelo": orquestador.MODEL_ID,
        "tokens_entrada": 2000,
        "tokens_salida": 200,
        "latencia_ms": 1000,
    }


def test_si_el_loop_revienta_conserva_lo_gastado(monkeypatch):
    _preparar(monkeypatch, _AgenteConUso(revienta_en=2), aprobable_en=99)
    registro = orquestador.procesar(_solicitud())
    assert registro["estado"] == "error"
    assert registro["uso_modelo"]["tokens_entrada"] == 1000
    assert registro["uso_modelo"]["tokens_salida"] == 100


def test_el_rechazo_previo_declara_cero_tokens(monkeypatch):
    monkeypatch.setattr(
        orquestador,
        "_chequeos_con_codigo",
        lambda sol: ([("principal_sin_techo", "sin techo")], {"principal_arn": "x"}, None, None),
    )
    registro = orquestador.procesar(_solicitud())
    assert registro["estado"] == "rechazada_en_chequeos_previos"
    assert registro["uso_modelo"] == orquestador._uso_vacio()
