"""Fase 18, tarea 6: la sonda de `dynamodb:Attributes` clasifica bien y no toca filas reales.

`scripts/sonda_atributos.py` mide, con llamadas reales del permission set
`AgenteIAM-Aprobador` contra la tabla `agente-iam-solicitudes`, que la lista de
atributos de IAM frena lo que tiene que frenar. Lo que aqui se fija es lo que,
si se rompiera, daria una medicion que miente o tocaria una solicitud de verdad:

  - una denegacion solo cuenta si es `AccessDeniedException`; un
    `ConditionalCheckFailedException` es otra cosa (paso IAM y fallo la
    condicion) y nunca cuenta como "cumple";
  - el caso 5 (atributo solo en la condicion) no tiene resultado esperado:
    su resultado ES la medicion;
  - todos los casos escriben en la fila de la sonda, nunca en otra, y ninguno
    pone `estado = aprobada` (la futura Lambda del aplicador la tomaria);
  - sin `--ejecutar` no se crea ninguna sesion, y con `--ejecutar` hace falta
    `--perfil`.
"""

import importlib.util
import sys
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

_RAIZ = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("sonda_atributos", _RAIZ / "scripts" / "sonda_atributos.py")
assert _spec
assert _spec.loader
sonda = importlib.util.module_from_spec(_spec)
sys.modules["sonda_atributos"] = sonda  # los dataclass buscan su modulo aqui
_spec.loader.exec_module(sonda)


def _caso(nombre: str):
    return next(c for c in sonda.casos("sonda-atributos-20261024") if c.nombre == nombre)


def test_veredicto():
    denegado = _caso("documento")
    assert sonda.veredicto(denegado, "AccessDeniedException") == "cumple"
    assert sonda.veredicto(denegado, None) == "no_cumple"
    permitido = _caso("aprobacion")
    assert sonda.veredicto(permitido, None) == "cumple"
    assert sonda.veredicto(permitido, "AccessDeniedException") == "no_cumple"


def test_una_condicion_fallida_nunca_cumple():
    for caso in sonda.casos("sonda-atributos-20261024"):
        assert sonda.veredicto(caso, "ConditionalCheckFailedException") == "condicion_fallida"


def test_el_caso_de_la_condicion_no_tiene_esperado_fijo():
    caso = _caso("aprobacion con documento en la condicion")
    assert caso.esperado is None
    assert sonda.veredicto(caso, "AccessDeniedException") == "denegado"
    assert sonda.veredicto(caso, None) == "permitido"


def test_todos_los_casos_usan_la_fila_de_la_sonda():
    clave = "sonda-atributos-20261024"
    for caso in sonda.casos(clave):
        assert caso.params["TableName"] == "agente-iam-solicitudes", caso.nombre
        fila = caso.params.get("Key") or {"id": caso.params["Item"]["id"]}
        assert fila == {"id": {"S": clave}}, caso.nombre


def test_ningun_caso_pone_estado_aprobada():
    for caso in sonda.casos("sonda-atributos-20261024"):
        valores = {**caso.params.get("ExpressionAttributeValues", {}), **caso.params.get("Item", {})}
        assert {"S": "aprobada"} not in valores.values(), caso.nombre


def test_la_clave_lleva_la_fecha_y_el_prefijo():
    assert sonda.clave_de_hoy().startswith("sonda-atributos-")
    assert len(sonda.clave_de_hoy()) == len("sonda-atributos-20261024")


def test_ejecutar_contra_un_cliente_clasifica_cada_caso():
    cliente = boto3.client("dynamodb", region_name="us-east-1")
    casos = sonda.casos("sonda-atributos-20261024")
    with Stubber(cliente) as stub:
        for caso in casos:
            if caso.esperado == "denegado":
                stub.add_client_error(caso.operacion, "AccessDeniedException",
                                      "User ... with an explicit deny in an identity-based policy")
            else:
                stub.add_response(caso.operacion, {} if caso.operacion != "get_item" else {"Item": {}})
        filas = sonda.ejecutar(cliente, casos)
    assert [f["veredicto"] for f in filas if f["esperado"]] == ["cumple"] * sum(1 for c in casos if c.esperado)
    denegada = next(f for f in filas if f["esperado"] == "denegado")
    assert "explicit deny" in denegada["mensaje"]


def test_sin_ejecutar_no_se_crea_ninguna_sesion(monkeypatch, tmp_path, capsys):
    def prohibida(*a, **k):
        raise AssertionError("sin --ejecutar no se debe crear una sesion de boto3")

    monkeypatch.setattr(boto3, "Session", prohibida)
    monkeypatch.setattr(boto3, "client", prohibida)
    monkeypatch.setattr(sonda, "RAIZ", tmp_path)
    assert sonda.main([]) == 0
    assert "Solo el plan" in capsys.readouterr().out
    assert not (tmp_path / "evidencias").exists()


def test_ejecutar_exige_perfil(monkeypatch):
    monkeypatch.setattr(boto3, "Session", lambda *a, **k: pytest.fail("no debe crear sesion"))
    with pytest.raises(SystemExit):
        sonda.main(["--ejecutar"])


def test_un_error_de_credenciales_es_error_de_corrida():
    error = ClientError({"Error": {"Code": "ExpiredTokenException", "Message": "x"}}, "UpdateItem")
    assert sonda.veredicto(_caso("aprobacion"), error.response["Error"]["Code"]) == "error:ExpiredTokenException"


# --- ADR-003 (24-10-2026): el aprobador ya no escribe; la sonda mide el Deny -----


def test_en_solo_lectura_solo_leer_se_espera_permitido():
    """Desde ADR-003 el permission set del aprobador no tiene UpdateItem y lleva
    un Deny explicito de toda escritura: con `--solo-lectura` la sonda espera
    `leer` permitido y las seis escrituras denegadas, tambien la de la condicion."""
    lista = sonda.casos("sonda-atributos-20261024", solo_lectura=True)
    assert [c.nombre for c in lista] == [c.nombre for c in sonda.casos("sonda-atributos-20261024")]
    assert [c.esperado for c in lista] == ["permitido"] + ["denegado"] * 6


def test_ejecutar_anota_que_capa_denego():
    """"explicit deny" frente a "no identity-based policy allows": la medicion
    de ADR-003 es que el Deny del permission set gana, no que falte un Allow."""
    cliente = boto3.client("dynamodb", region_name="us-east-1")
    casos = sonda.casos("sonda-atributos-20261024", solo_lectura=True)
    with Stubber(cliente) as stub:
        stub.add_response("get_item", {"Item": {}})
        for caso in casos[1:]:
            mensaje = "with an explicit deny in an identity-based policy" if caso.nombre != "putitem" else "because no identity-based policy allows"
            stub.add_client_error(caso.operacion, "AccessDeniedException", mensaje)
        filas = sonda.ejecutar(cliente, casos)
    assert [f["veredicto"] for f in filas] == ["cumple"] * 7
    assert filas[0]["capa"] is None
    assert [f["capa"] for f in filas[1:]] == ["explicita", "explicita", "explicita", "implicita", "explicita", "explicita"]


def test_solo_lectura_se_elige_en_la_linea_de_ordenes(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(boto3, "Session", lambda *a, **k: pytest.fail("sin --ejecutar no hay sesion"))
    monkeypatch.setattr(sonda, "RAIZ", tmp_path)
    assert sonda.main(["--solo-lectura"]) == 0
    salida = capsys.readouterr().out
    assert "esperado permitido" in salida
    assert salida.count("esperado denegado") == 6
