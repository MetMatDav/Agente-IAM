"""Fase 15: la matriz de regiones clasifica bien, y sin --ejecutar no toca AWS.

`scripts/matriz_regiones.py` es una herramienta de medicion contra la cuenta
real. Lo que aqui se fija es lo que no necesita la cuenta y, si se rompiera,
daria una matriz que miente:

  - un AccessDenied solo es DENY_SCP si el mensaje nombra una "service
    control policy"; sin ella es DENY_OTRO (falta un permiso IAM, y eso no
    demuestra que la SCP funcione);
  - la regla de pasa/no pasa, con `NO_DENY_SCP` aceptando todo menos una SCP;
  - el numero de cuenta no sale entero ni en consola ni en el JSON;
  - sin `--ejecutar` no se crea ninguna sesion de boto3;
  - el codigo de salida: 0 todo pasa, 3 algun caso no pasa, 1 credenciales.

Las llamadas se sustituyen por dobles (el guardian de tests/conftest.py corta
el HTTP): nada de esto sale a la red.
"""

import importlib.util
import json
import sys
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError, ProfileNotFound

_RUTA = Path(__file__).resolve().parents[2] / "scripts" / "matriz_regiones.py"
_spec = importlib.util.spec_from_file_location("matriz_regiones", _RUTA)
assert _spec
assert _spec.loader
matriz = importlib.util.module_from_spec(_spec)
sys.modules["matriz_regiones"] = matriz  # los dataclass buscan su modulo aqui
_spec.loader.exec_module(matriz)

MENSAJE_SCP = (
    "User: arn:aws:sts::111122223333:assumed-role/X/y is not authorized to perform: "
    "bedrock:InvokeModel on resource: arn:aws:bedrock:::foundation-model/"
    "anthropic.claude-haiku-4-5-20251001-v1:0 with an explicit deny in a service control "
    "policy: arn:aws:organizations::111122223333:policy/o-abcdefghij/service_control_policy/p-sj8zyyiw"
)


def _error(codigo: str, mensaje: str, operacion: str = "Converse") -> ClientError:
    return ClientError({"Error": {"Code": codigo, "Message": mensaje}}, operacion)


# --- clasificar -------------------------------------------------------------

def test_una_respuesta_sin_excepcion_es_ok():
    r = matriz.clasificar(None)
    assert r["clase"] == "OK"
    assert r["politica"] is None
    assert r["recurso"] is None


def test_accessdenied_con_scp_es_deny_scp_y_extrae_politica_y_recurso():
    r = matriz.clasificar(_error("AccessDeniedException", MENSAJE_SCP))
    assert r["clase"] == "DENY_SCP"
    assert r["politica"] == "p-sj8zyyiw"
    assert r["recurso"] == "arn:aws:bedrock:::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0"


def test_la_denegacion_de_ec2_tambien_se_reconoce():
    # EC2 no dice AccessDenied sino UnauthorizedOperation.
    r = matriz.clasificar(_error("UnauthorizedOperation", "You are not authorized. " + MENSAJE_SCP, "DescribeVpcs"))
    assert r["clase"] == "DENY_SCP"


def test_accessdenied_sin_scp_es_deny_otro():
    r = matriz.clasificar(_error("AccessDeniedException", "User: arn:aws:sts::111122223333:assumed-role/X/y is not authorized to perform: bedrock:InvokeModel because no identity-based policy allows the bedrock:InvokeModel action"))
    assert r["clase"] == "DENY_OTRO"
    assert r["politica"] is None


@pytest.mark.parametrize("error", [
    _error("ThrottlingException", "Too many requests"),
    _error("ValidationException", "The provided model identifier is invalid"),
    EndpointConnectionError(endpoint_url="https://bedrock-runtime.us-west-2.amazonaws.com"),
    RuntimeError("algo raro"),
])
def test_cualquier_otro_fallo_es_error_con_tipo_y_mensaje(error):
    r = matriz.clasificar(error)
    assert r["clase"] == "ERROR"
    assert r["detalle"]


def test_el_detalle_de_un_clienterror_lleva_su_codigo():
    assert matriz.clasificar(_error("ThrottlingException", "Too many requests"))["detalle"].startswith("ThrottlingException: ")


def test_un_error_de_marketplace_se_avisa_aparte():
    r = matriz.clasificar(_error("AccessDeniedException", "Model access is denied due to AWS Marketplace subscription"))
    assert r["clase"] == "DENY_OTRO"
    assert r["aviso_marketplace"] is True
    assert matriz.clasificar(_error("AccessDeniedException", MENSAJE_SCP))["aviso_marketplace"] is False


# --- pasa -------------------------------------------------------------------

@pytest.mark.parametrize("esperado,obtenido,debe", [
    ("OK", "OK", True),
    ("OK", "DENY_SCP", False),
    ("DENY_SCP", "DENY_SCP", True),
    ("DENY_SCP", "DENY_OTRO", False),  # la SCP no se ha demostrado
    ("DENY_SCP", "OK", False),
    ("NO_DENY_SCP", "OK", True),
    ("NO_DENY_SCP", "ERROR", True),
    ("NO_DENY_SCP", "DENY_OTRO", True),
    ("NO_DENY_SCP", "DENY_SCP", False),
])
def test_regla_de_pasa(esperado, obtenido, debe):
    assert matriz.pasa(esperado, obtenido) is debe


# --- enmascarar -------------------------------------------------------------

def test_enmascarar_deja_los_cuatro_ultimos_digitos():
    assert matriz.enmascarar("arn:aws:iam::111122223333:role/X") == "arn:aws:iam::********3333:role/X"


def test_enmascarar_recorre_estructuras_y_no_toca_otros_numeros():
    datos = {"a": ["111122223333", {"b": "cuenta 999988887777 y 12345 y 1234567890123"}], "n": 7}
    salida = json.dumps(matriz.enmascarar(datos))
    assert "111122223333" not in salida
    assert "999988887777" not in salida
    assert "********3333" in salida
    assert "********7777" in salida
    assert "12345" in salida
    assert "1234567890123" in salida


# --- ejecutar_caso ----------------------------------------------------------

def _caso(id_: int):
    return next(c for c in matriz.construir_casos(matriz.MODELO_POR_DEFECTO) if c.id == id_)


def _fabrica(fallo: Exception | None = None, solo: str | None = None):
    """Clientes falsos: cada metodo responde, o lanza `fallo` (en `solo`, si se indica)."""
    class Cliente:
        def __init__(self, servicio):
            self.servicio = servicio

        def __getattr__(self, nombre):
            def llamar(**_):
                if fallo is not None and solo in (None, self.servicio):
                    raise fallo
                return {"stream": iter([{}]), "body": type("B", (), {"read": lambda s: b"{}"})()}
            return llamar
    return lambda perfil, servicio, region: Cliente(servicio)


def test_un_caso_con_dos_llamadas_manda_la_primera_que_falla():
    r = matriz.ejecutar_caso(_caso(9), _fabrica(_error("AccessDenied", MENSAJE_SCP), solo="sts"))
    assert [p["clase"] for p in r["pasos"]] == ["OK", "DENY_SCP"]
    assert r["obtenido"] == "DENY_SCP"
    assert r["pasa"] is False


def test_el_stream_se_consume_y_un_caso_ok_pasa():
    r = matriz.ejecutar_caso(_caso(2), _fabrica())
    assert r["obtenido"] == "OK"
    assert r["pasa"] is True


def test_un_stream_que_falla_a_mitad_se_detecta_porque_se_consume_entero():
    def stream():
        yield {"contentBlockDelta": {}}
        raise _error("AccessDeniedException", MENSAJE_SCP, "ConverseStream")

    class Cliente:
        def converse_stream(self, **_):
            return {"stream": stream()}

    r = matriz.ejecutar_caso(_caso(2), lambda perfil, servicio, region: Cliente())
    assert r["obtenido"] == "DENY_SCP"
    assert r["pasa"] is False


def test_el_caso_de_haiku_5_5_pasa_con_error_de_cuota_pero_no_con_scp():
    cuota = _error("ServiceQuotaExceededException", "quota is 0")
    assert matriz.ejecutar_caso(_caso(12), _fabrica(cuota))["pasa"] is True
    assert matriz.ejecutar_caso(_caso(12), _fabrica(_error("AccessDeniedException", MENSAJE_SCP)))["pasa"] is False


def test_sin_credenciales_el_caso_se_marca_como_error_de_corrida():
    r = matriz.ejecutar_caso(_caso(1), _fabrica(NoCredentialsError()))
    assert r["credenciales"] is True
    assert r["pasa"] is False


# --- main -------------------------------------------------------------------

def test_sin_ejecutar_no_se_crea_ninguna_sesion_de_boto3(monkeypatch, tmp_path, capsys):
    def prohibida(*a, **k):
        raise AssertionError("sin --ejecutar no se debe crear una sesion de boto3")

    monkeypatch.setattr(boto3, "Session", prohibida)
    monkeypatch.setattr(boto3, "client", prohibida)
    monkeypatch.setattr(matriz, "RAIZ", tmp_path)
    assert matriz.main([]) == 0
    salida = capsys.readouterr().out
    assert "esperado DENY_SCP" in salida
    assert "Solo el plan" in salida
    assert not (tmp_path / "evidencias").exists()


def test_el_plan_respeta_los_perfiles_y_el_modelo_pedidos(capsys):
    matriz.main(["--modelo", "us.anthropic.claude-haiku-5-5", "--perfil-agente", "p1", "--perfil-gestion", "p2", "--perfil-audit", "p3"])
    salida = capsys.readouterr().out
    assert "agente=p1, gestion=p2, audit=p3" in salida
    assert "Converse us.anthropic.claude-haiku-5-5 con el cliente en us-west-2" in salida


class _SesionFalsa:
    """boto3.Session que contesta con la clase de error pedida por servicio y region."""
    def __init__(self, profile_name=None, **_):
        self.perfil = profile_name

    def client(self, servicio, region_name=None, config=None):
        class C:
            def __getattr__(self, nombre):
                def llamar(**_):
                    if region_name == "us-east-1":
                        return {"stream": iter([]), "body": type("B", (), {"read": lambda s: b"{}"})()}
                    raise _error("AccessDenied", MENSAJE_SCP, nombre)
                return llamar
        return C()


def _preparar_main(monkeypatch, tmp_path, sesion=_SesionFalsa):
    monkeypatch.setattr(boto3, "Session", sesion)
    monkeypatch.setattr(matriz, "RAIZ", tmp_path)


def test_ejecutar_escribe_el_json_enmascarado_y_sale_con_3_si_un_caso_no_pasa(monkeypatch, tmp_path, capsys):
    # En us-east-1 todo responde, en us-west-2 todo es SCP: el caso 4
    # (global. en us-east-1, esperado DENY_SCP) no pasa, el resto si.
    _preparar_main(monkeypatch, tmp_path)
    assert matriz.main(["--ejecutar"]) == 3
    jsons = list((tmp_path / "evidencias" / "matriz-regiones").glob("*/resultado.json"))
    assert len(jsons) == 1
    texto = jsons[0].read_text(encoding="utf-8")
    datos = json.loads(texto)
    assert "111122223333" not in texto
    assert "********3333" in texto
    assert "111122223333" not in capsys.readouterr().out
    assert datos["total"] == 12
    assert [r["id"] for r in datos["resultados"] if not r["pasa"]] == [4]


def test_ejecutar_sale_con_0_si_todos_pasan(monkeypatch, tmp_path):
    class Sesion(_SesionFalsa):
        def client(self, servicio, region_name=None, config=None):
            sesion = self

            class C:
                def __getattr__(self, nombre):
                    def llamar(**kw):
                        # Solo responde (sin SCP) donde la matriz espera OK.
                        modelo = kw.get("modelId", "")
                        if region_name == "us-east-1" and not modelo.startswith("global.") or sesion.perfil == "org-gestion":
                            return {"stream": iter([]), "body": type("B", (), {"read": lambda s: b"{}"})()}
                        raise _error("AccessDenied", MENSAJE_SCP, nombre)
                    return llamar
            return C()

    _preparar_main(monkeypatch, tmp_path, Sesion)
    assert matriz.main(["--ejecutar"]) == 0


def test_un_perfil_inexistente_es_error_de_corrida_y_no_escribe_nada(monkeypatch, tmp_path):
    def sesion(profile_name=None, **_):
        raise ProfileNotFound(profile=profile_name)

    _preparar_main(monkeypatch, tmp_path, sesion)
    assert matriz.main(["--ejecutar"]) == 1
    assert not (tmp_path / "evidencias").exists()


def test_credenciales_caducadas_son_error_de_corrida_aunque_se_escriba_el_json(monkeypatch, tmp_path):
    class Sesion(_SesionFalsa):
        def client(self, servicio, region_name=None, config=None):
            raise NoCredentialsError()

    _preparar_main(monkeypatch, tmp_path, Sesion)
    assert matriz.main(["--ejecutar"]) == 1
    assert list((tmp_path / "evidencias" / "matriz-regiones").glob("*/resultado.json"))
