"""Fase 18: la sonda de `aws:ResourceAccount` clasifica bien, y sin --ejecutar no toca AWS.

`scripts/sonda_cuenta.py` mide, con llamadas reales, si cada llamada tipica de
los ocho servicios lleva la clave `aws:ResourceAccount` y si el Deny
`SoloRecursosDeLaPropiaCuenta` del techo la negaria. Lo que aqui se fija es lo
que, si se rompiera, daria una medicion que miente:

  - sin la sesion de control en verde no se concluye nada (la llamada pudo
    fallar por otra causa: un recurso que no existe, una politica ajena);
  - el estado de la clave sale de las sesiones `ausente` y `propia`, y la
    columna `techo` es la que se mide, no la que se deduce;
  - la sesion `techo` es la sentencia S5 del techo del repositorio, tal cual;
  - las politicas de sesion caben en el limite de STS;
  - si la tabla propia no sale `propia`, la sonda esta rota y lo dice;
  - sin `--ejecutar` no se crea ninguna sesion de boto3.
"""

import importlib.util
import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

_RAIZ = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("sonda_cuenta", _RAIZ / "scripts" / "sonda_cuenta.py")
assert _spec
assert _spec.loader
sonda = importlib.util.module_from_spec(_spec)
sys.modules["sonda_cuenta"] = sonda  # los dataclass buscan su modulo aqui
_spec.loader.exec_module(sonda)

clasificar = sonda.clasificar


def _r(control="ok", techo="ok", ausente="ok", propia="ok") -> dict:
    return {"control": control, "techo": techo, "ausente": ausente, "propia": propia}


# --- clasificar -------------------------------------------------------------

def test_sin_control_en_verde_no_concluye():
    assert clasificar(_r(control="error:NoSuchBucket", techo="denegado")) == {"clave": "no_concluyente", "techo": None}


def test_un_error_que_no_es_denegacion_en_una_sonda_no_concluye():
    assert clasificar(_r(ausente="error:Throttling")) == {"clave": "no_concluyente", "techo": None}


def test_la_clave_sale_de_ausente_y_propia():
    assert clasificar(_r(propia="denegado")) == {"clave": "propia", "techo": "pasa"}
    assert clasificar(_r(techo="denegado")) == {"clave": "ajena", "techo": "niega"}


def test_sin_la_clave_la_columna_techo_es_la_medicion():
    assert clasificar(_r(techo="denegado", ausente="denegado")) == {"clave": "ausente", "techo": "niega"}
    assert clasificar(_r(ausente="denegado")) == {"clave": "ausente", "techo": "pasa"}


def test_lo_imposible_es_inconsistente():
    assert clasificar(_r(ausente="denegado", propia="denegado"))["clave"] == "inconsistente"
    # la clave llega con la cuenta propia y aun asi el techo niega
    assert clasificar(_r(techo="denegado", propia="denegado"))["clave"] == "inconsistente"
    # ninguna sonda niega: llegaria con otra cuenta, pero el techo la deja pasar
    assert clasificar(_r())["clave"] == "inconsistente"


# --- politicas de sesion ----------------------------------------------------

def _s5() -> dict:
    techo = json.loads((_RAIZ / "infra" / "boundary-agente-iam-techo.json").read_text(encoding="utf-8"))
    return next(s for s in techo["Statement"] if s["Sid"] == "SoloRecursosDeLaPropiaCuenta")


def _deny(nombre: str) -> dict:
    return next(s for s in sonda.politica_de_sesion(nombre)["Statement"] if s["Effect"] == "Deny")


def test_la_sesion_techo_es_la_s5_del_techo():
    s5, prueba = _s5(), _deny("techo")
    assert {k: prueba[k] for k in ("Action", "Resource", "Condition")} == {k: s5[k] for k in ("Action", "Resource", "Condition")}


def test_las_sondas_niegan_lo_mismo_que_la_s5_con_otra_condicion():
    s5 = _s5()
    assert _deny("ausente")["Condition"] == {"Null": {"aws:ResourceAccount": "true"}}
    assert _deny("propia")["Condition"] == {"StringEquals": {"aws:ResourceAccount": "${aws:PrincipalAccount}"}}
    for n in ("ausente", "propia"):
        assert _deny(n)["Action"] == s5["Action"]
        assert _deny(n)["Resource"] == s5["Resource"]


def test_el_control_no_niega_nada():
    assert [s["Effect"] for s in sonda.politica_de_sesion("control")["Statement"]] == ["Allow"]


def test_la_sesion_solo_permite_lo_que_la_sonda_llama():
    # Un Allow */* no concede nada en una politica de sesion (solo recorta el
    # rol), pero Access Analyzer lo marca (PassRole, rol vinculado) y no hay
    # por que pedir mas de lo que se usa.
    for n in sonda.SESIONES:
        [permitir] = [s for s in sonda.politica_de_sesion(n)["Statement"] if s["Effect"] == "Allow"]
        assert sorted(permitir["Action"]) == sorted({ll.accion_iam for ll in sonda.LLAMADAS})


def test_las_politicas_de_sesion_caben():
    # STS limita la politica de sesion a 2048 caracteres (sin espacios).
    for n in sonda.SESIONES:
        assert len(json.dumps(sonda.politica_de_sesion(n), separators=(",", ":"))) <= 2048


# --- resultado de una llamada -----------------------------------------------

def _error(codigo: str) -> ClientError:
    return ClientError({"Error": {"Code": codigo, "Message": "x"}}, "Op")


def test_cada_servicio_tiene_su_codigo_de_denegacion():
    for codigo in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError"):
        assert sonda.resultado(_error(codigo)) == "denegado"
    assert sonda.resultado(_error("ResourceNotFoundException")) == "error:ResourceNotFoundException"
    assert sonda.resultado(None) == "ok"


# --- la sonda en conjunto ---------------------------------------------------

def test_la_sonda_aborta_si_su_tabla_no_sale_propia():
    filas = [{"llamada": sonda.LLAMADA_DE_CONTROL, "clave": "ausente", "techo": "niega"}]
    assert sonda.sonda_rota(filas)
    assert not sonda.sonda_rota([{"llamada": sonda.LLAMADA_DE_CONTROL, "clave": "propia", "techo": "pasa"}])


def test_los_ocho_servicios_estan_en_la_sonda():
    assert {ll.servicio for ll in sonda.LLAMADAS} == {"s3", "dynamodb", "sqs", "sns", "logs", "cloudwatch", "ec2", "lambda"}
    assert sonda.LLAMADA_DE_CONTROL in {ll.nombre for ll in sonda.LLAMADAS}


def test_enmascarar_deja_los_cuatro_ultimos_digitos():
    assert sonda.enmascarar({"arn": "arn:aws:iam::123456789012:role/x"}) == {"arn": "arn:aws:iam::********9012:role/x"}


def test_sin_ejecutar_no_se_crea_ninguna_sesion(monkeypatch, tmp_path, capsys):
    def prohibida(*a, **k):
        raise AssertionError("sin --ejecutar no se debe crear una sesion de boto3")

    monkeypatch.setattr(boto3, "Session", prohibida)
    monkeypatch.setattr(boto3, "client", prohibida)
    monkeypatch.setattr(sonda, "RAIZ", tmp_path)
    assert sonda.main([]) == 0
    salida = capsys.readouterr().out
    assert "Solo el plan" in salida
    assert not (tmp_path / "evidencias").exists()
