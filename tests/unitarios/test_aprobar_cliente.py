"""El cliente de la persona (`aprobar_cliente`, ADR-003, A2): lee, ensena y firma.

Lo que importa de este comando es lo que NO hace: en DynamoDB no decide, no
escribe y no importa el servidor. Solo lee el registro, pinta la propuesta con
su huella y manda la peticion firmada con SigV4 a la URL de la Lambda. Todo
con dobles: ni red, ni STS, ni tabla.
"""

import hashlib
import io
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from agente_iam import almacen, aprobar_cliente, huella, models

from tests.dobles import _aprobador_sso, _propuesta, _registro, _solicitante, _solicitud_persona

_RAIZ = Path(__file__).resolve().parents[2]
_URL = "https://abc123.lambda-url.us-east-1.on.aws/"
_ESC = "\x1b"


def _peticion(**campos) -> models.PeticionAprobacion:
    base = {"id": "req-prueba", "accion": "aprobar", "huella": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
    base.update(campos)
    return models.PeticionAprobacion.model_validate(base)


def _salida(argv: list[str], monkeypatch) -> int:
    """El codigo de salida de `main()` con esos argumentos (0 si no sale)."""
    monkeypatch.setattr("sys.argv", ["aprobar_cliente", *argv])
    try:
        aprobar_cliente.main()
    except SystemExit as e:
        return e.code
    return 0


def _cuerpo_200() -> dict:
    return {
        "id": "req-prueba",
        "resultado": "aprobada",
        "aprobador": _aprobador_sso().model_dump(),
        "estado": "aprobada",
        "decision": {
            "cuando": "2026-10-24T12:00:00+00:00",
            "por": _aprobador_sso().model_dump(),
            "huella": "sha256:abababababababababababababababababababababababababababababababab",
            "separacion_de_funciones": {
                "resultado": "cumplido",
                "beneficiario": "arn:aws:iam::111122223333:user/jose.torres",
                "aprobador": "aprobador.demo",
                "solicitante": "solicitante.demo",
            },
            "techo": {"resultado": "PASS", "origen_del_techo": "cuenta"},
            "riesgo_confirmado": False,
        },
        "guardado_en": "dynamodb://solicitudes/req-prueba",
    }


@pytest.fixture
def dynamodb(monkeypatch):
    """Modo desplegado: lee la tabla y manda a la URL. Nada mas."""
    monkeypatch.setattr(aprobar_cliente, "ALMACEN", "dynamodb")
    monkeypatch.setattr(aprobar_cliente, "URL_APROBACION", _URL)
    monkeypatch.setattr(almacen, "leer", lambda sid: _registro(solicitante=_solicitante()))
    monkeypatch.setattr(
        almacen, "guardar_decision", lambda *a, **k: pytest.fail("el cliente no escribe en la tabla")
    )


def _enviado(monkeypatch, respuesta: tuple[int, dict] | None = None) -> list:
    """Sustituye `enviar` y devuelve la lista de peticiones que le llegan."""
    llegadas: list = []

    def falso(url, peticion):
        llegadas.append((url, peticion))
        return respuesta or (200, _cuerpo_200())

    monkeypatch.setattr(aprobar_cliente, "enviar", falso)
    return llegadas


# ---------------------------------------------------------------------------
# enviar: la firma y la forma de la respuesta
# ---------------------------------------------------------------------------


class _Respuesta:
    def __init__(self, estado: int, cuerpo: bytes):
        self.status = estado
        self._cuerpo = cuerpo

    def read(self, n: int = -1) -> bytes:
        return self._cuerpo

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _OpenerFalso:
    """Lo que devuelve `build_opener`: guarda el pedido y el timeout, y responde o falla."""

    def __init__(self, visto: dict, respuesta, error):
        self._visto, self._respuesta, self._error = visto, respuesta, error

    def open(self, pedido, data=None, timeout=None):
        self._visto["pedido"], self._visto["timeout"] = pedido, timeout
        if self._error is not None:
            raise self._error
        return self._respuesta or _Respuesta(200, json.dumps(_cuerpo_200()).encode())


def _urlopen_captura(monkeypatch, respuesta=None, error=None):
    """Sustituye el opener (el cliente no usa `urlopen` a secas: no sigue
    redirecciones): guarda los manejadores, el pedido y el timeout."""
    visto: dict = {}

    def construir(*manejadores):
        visto["manejadores"] = manejadores
        return _OpenerFalso(visto, respuesta, error)

    monkeypatch.setattr("urllib.request.build_opener", construir)
    return visto


def _nada_sale(monkeypatch, motivo: str):
    """Ni `urlopen` ni un opener: si algo intenta enviar, el test cae."""
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: pytest.fail(motivo))
    monkeypatch.setattr("urllib.request.build_opener", lambda *a, **k: pytest.fail(motivo))


def _credenciales_falsas(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAFALSA")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secreto-falso")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "token-falso")


def test_la_firma_es_sigv4_de_lambda_en_la_region(monkeypatch):
    _credenciales_falsas(monkeypatch)
    visto = _urlopen_captura(monkeypatch)
    peticion = _peticion()
    codigo, cuerpo = aprobar_cliente.enviar(_URL, peticion)

    pedido = visto["pedido"]
    cabeceras = {k.lower(): v for k, v in pedido.header_items()}
    assert "/us-east-1/lambda/aws4_request" in cabeceras["authorization"]
    assert cabeceras["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIAFALSA/")
    assert "x-amz-security-token" in cabeceras["authorization"]
    assert cabeceras["x-amz-security-token"] == "token-falso"
    assert cabeceras["content-type"] == "application/json"
    # La huella del cuerpo viaja en cabecera Y entra en lo firmado (supuesto,
    # sin medir hasta la primera llamada real, M1: que la URL de funcion con
    # AWS_IAM la pida en POST; la SigV4Auth generica de botocore solo la pone
    # en la peticion canonica, no como cabecera).
    assert cabeceras["x-amz-content-sha256"] == hashlib.sha256(pedido.data).hexdigest()
    firmadas = cabeceras["authorization"].split("SignedHeaders=", 1)[1].split(",", 1)[0].split(";")
    assert "x-amz-content-sha256" in firmadas
    assert pedido.get_method() == "POST"
    assert pedido.full_url == _URL
    assert pedido.data == peticion.model_dump_json().encode()
    assert visto["timeout"] == 90
    assert (codigo, cuerpo["resultado"]) == (200, "aprobada")


def test_la_firma_cubre_el_cuerpo(monkeypatch):
    """Dos cuerpos distintos no pueden compartir firma: SigV4 mete el hash del
    cuerpo en lo firmado, asi que nadie cambia la peticion por el camino."""
    _credenciales_falsas(monkeypatch)
    firmas = []
    for motivo in ("uno", "dos"):
        visto = _urlopen_captura(monkeypatch)
        aprobar_cliente.enviar(_URL, _peticion(accion="rechazar", motivo=motivo, huella=None))
        cabeceras = {k.lower(): v for k, v in visto["pedido"].header_items()}
        firmas.append(cabeceras["authorization"].rsplit("Signature=", 1)[1])
    assert firmas[0] != firmas[1]


def test_sin_credenciales_no_envia_nada(monkeypatch):
    class SinCredenciales:
        def get_credentials(self):
            return None

    monkeypatch.setattr("boto3.Session", lambda *a, **k: SinCredenciales())
    _nada_sale(monkeypatch, "no habia con que firmar")
    codigo, cuerpo = aprobar_cliente.enviar(_URL, _peticion())
    assert codigo == 0
    assert cuerpo["resultado"] == "sin_credenciales"


@pytest.mark.parametrize("url", ["http://abc.lambda-url.us-east-1.on.aws/", "file:///etc/passwd", ""])
def test_solo_se_envia_por_https(monkeypatch, url):
    _nada_sale(monkeypatch, "no se envia")
    codigo, cuerpo = aprobar_cliente.enviar(url, _peticion())
    assert codigo == 0
    assert cuerpo["resultado"] == "url_no_valida"


def test_un_409_con_json_llega_tal_cual(monkeypatch):
    _credenciales_falsas(monkeypatch)
    cuerpo = {"id": "req-prueba", "resultado": "bloqueada", "bloqueos": ["Falta la huella"]}
    error = urllib.error.HTTPError(_URL, 409, "Conflict", {}, io.BytesIO(json.dumps(cuerpo).encode()))
    _urlopen_captura(monkeypatch, error=error)
    assert aprobar_cliente.enviar(_URL, _peticion()) == (409, cuerpo)


def test_un_403_de_la_url_es_sin_permiso(monkeypatch):
    _credenciales_falsas(monkeypatch)
    error = urllib.error.HTTPError(
        _URL, 403, "Forbidden", {}, io.BytesIO(b'{"Message":"User is not authorized"}')
    )
    _urlopen_captura(monkeypatch, error=error)
    codigo, cuerpo = aprobar_cliente.enviar(_URL, _peticion())
    assert codigo == 403
    assert cuerpo["resultado"] == "sin_permiso"
    assert "not authorized" in cuerpo["detalle"]


def test_el_cliente_envia_con_un_opener_que_no_sigue_redirecciones(monkeypatch):
    _credenciales_falsas(monkeypatch)
    visto = _urlopen_captura(monkeypatch)
    aprobar_cliente.enviar(_URL, _peticion())
    assert len(visto["manejadores"]) == 1
    manejador = visto["manejadores"][0]
    clase = manejador if isinstance(manejador, type) else type(manejador)
    assert issubclass(clase, urllib.request.HTTPRedirectHandler)


@pytest.mark.parametrize("codigo", [301, 302, 303, 307, 308])
def test_un_opener_real_con_ese_manejador_no_sigue_la_redireccion(codigo):
    """El comportamiento de verdad, sin red: `redirect_request` devuelve None y
    urllib convierte el 3xx en `HTTPError`, en vez de repetir el POST (con la
    firma y el cuerpo) contra el `Location` que diga quien contesta."""
    opener = urllib.request.build_opener(aprobar_cliente._SinRedirecciones)
    pedido = urllib.request.Request(_URL, data=b"{}", method="POST")
    cabeceras = {"Location": "https://otro.example/"}
    with pytest.raises(urllib.error.HTTPError) as e:
        opener.error("https", pedido, io.BytesIO(b""), codigo, "Redirect", cabeceras)
    assert e.value.code == codigo


@pytest.mark.parametrize("codigo", [301, 307, 308])
def test_una_redireccion_es_un_error_y_no_se_sigue(monkeypatch, codigo):
    _credenciales_falsas(monkeypatch)
    error = urllib.error.HTTPError(_URL, codigo, "Redirect", {"Location": "https://otro.example/"}, io.BytesIO(b""))
    _urlopen_captura(monkeypatch, error=error)
    resultado, cuerpo = aprobar_cliente.enviar(_URL, _peticion())
    assert resultado == codigo
    assert cuerpo["resultado"] == "redireccion"
    assert "otro.example" not in cuerpo["detalle"]


def test_una_redireccion_sale_con_1(dynamodb, monkeypatch, capsys):
    _enviado(monkeypatch, (307, {"resultado": "redireccion", "detalle": "la URL contesto con una redireccion"}))
    assert _salida(["req-prueba", "--huella", "sha256:" + "ab" * 32], monkeypatch) == 1
    assert "redireccion" in capsys.readouterr().out


def test_un_error_que_no_es_json_lleva_su_codigo_corto_y_el_texto(monkeypatch):
    _credenciales_falsas(monkeypatch)
    error = urllib.error.HTTPError(_URL, 502, "Bad Gateway", {}, io.BytesIO(b"<html>mal</html>"))
    _urlopen_captura(monkeypatch, error=error)
    codigo, cuerpo = aprobar_cliente.enviar(_URL, _peticion())
    assert codigo == 502
    assert cuerpo == {"resultado": "http_502", "detalle": "<html>mal</html>"}


@pytest.mark.parametrize(
    "fallo",
    [urllib.error.URLError("Name or service not known"), TimeoutError("timed out"), ConnectionResetError("reset")],
)
def test_sin_respuesta_es_codigo_cero(monkeypatch, fallo):
    _credenciales_falsas(monkeypatch)
    _urlopen_captura(monkeypatch, error=fallo)
    codigo, cuerpo = aprobar_cliente.enviar(_URL, _peticion())
    assert codigo == 0
    assert cuerpo["resultado"] == "sin_respuesta"
    assert cuerpo["detalle"]


def test_una_respuesta_que_no_es_un_objeto_json_no_se_da_por_buena(monkeypatch):
    _credenciales_falsas(monkeypatch)
    _urlopen_captura(monkeypatch, respuesta=_Respuesta(200, b"[1, 2]"))
    codigo, cuerpo = aprobar_cliente.enviar(_URL, _peticion())
    assert codigo == 200
    assert cuerpo["resultado"] == "respuesta_ilegible"


# ---------------------------------------------------------------------------
# main: lo que lee, lo que ensena y lo que manda
# ---------------------------------------------------------------------------


def test_sin_huella_solo_pinta_y_no_envia(dynamodb, monkeypatch, capsys):
    monkeypatch.setattr(aprobar_cliente, "enviar", lambda *a: pytest.fail("sin huella no se envia"))
    registro = _registro(solicitante=_solicitante())
    monkeypatch.setattr(almacen, "leer", lambda sid: registro)
    assert _salida(["req-prueba"], monkeypatch) == 3
    salida = capsys.readouterr().out
    assert "REVISION de req-prueba" in salida
    assert huella.calcular(registro) in salida
    assert f"repite con --huella {huella.calcular(registro)}" in salida.replace("\n", " ")


def test_con_huella_envia_id_y_huella(dynamodb, monkeypatch):
    llegadas = _enviado(monkeypatch)
    assert _salida(["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab"], monkeypatch) == 0
    (url, peticion), = llegadas
    assert url == _URL
    assert peticion.id == "req-prueba"
    assert peticion.accion == "aprobar"
    assert peticion.huella == "sha256:abababababababababababababababababababababababababababababababab"
    assert peticion.motivo is None
    assert peticion.autoaprobacion_demo is False
    assert peticion.riesgo_alto_confirmado is False


def test_las_dos_puertas_viajan_en_la_peticion(dynamodb, monkeypatch):
    llegadas = _enviado(monkeypatch)
    argv = ["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab", "--autoaprobacion-demo", "--riesgo-alto-confirmado"]
    assert _salida(argv, monkeypatch) == 0
    peticion = llegadas[0][1]
    assert peticion.autoaprobacion_demo is True
    assert peticion.riesgo_alto_confirmado is True


def test_rechazar_envia_sin_huella_y_con_motivo(dynamodb, monkeypatch):
    llegadas = _enviado(monkeypatch, (200, {**_cuerpo_200(), "estado": "rechazada_por_aprobador"}))
    assert _salida(["req-prueba", "--rechazar", "no procede"], monkeypatch) == 0
    (_, peticion), = llegadas
    assert peticion.accion == "rechazar"
    assert peticion.motivo == "no procede"
    assert peticion.huella is None


def test_lee_el_registro_una_sola_vez(dynamodb, monkeypatch):
    lecturas = []
    monkeypatch.setattr(almacen, "leer", lambda sid: lecturas.append(sid) or _registro())
    _enviado(monkeypatch)
    _salida(["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab"], monkeypatch)
    assert lecturas == ["req-prueba"]


def test_dynamodb_sin_url_no_escribe_nada(dynamodb, monkeypatch, capsys):
    monkeypatch.setattr(aprobar_cliente, "URL_APROBACION", "")
    monkeypatch.setattr(aprobar_cliente, "enviar", lambda *a: pytest.fail("no hay a donde enviar"))
    from agente_iam import aprobar

    monkeypatch.setattr(aprobar, "decidir", lambda *a: pytest.fail("en DynamoDB no se decide aqui"))
    assert _salida(["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab"], monkeypatch) == 1
    assert "AGENTE_IAM_URL_APROBACION" in capsys.readouterr().out


def test_en_dynamodb_nunca_llama_a_guardar_decision_ni_a_decidir(dynamodb, monkeypatch):
    from agente_iam import aprobar

    monkeypatch.setattr(aprobar, "decidir", lambda *a: pytest.fail("en DynamoDB no se decide aqui"))
    monkeypatch.setattr(
        aprobar, "identificar_aprobador", lambda: pytest.fail("quien firma lo dice la URL, no el cliente")
    )
    _enviado(monkeypatch)
    assert _salida(["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab"], monkeypatch) == 0
    assert _salida(["req-prueba", "--rechazar", "no procede"], monkeypatch) == 0


def test_importar_el_cliente_no_importa_el_servidor():
    """El cliente es lo que corre la persona; el servidor es la Lambda. En
    DynamoDB el segundo ni se carga (se importa solo en la rama de disco)."""
    codigo = (
        "import sys, agente_iam.aprobar_cliente;"
        "sys.exit(1 if 'agente_iam.aprobar' in sys.modules else 0)"
    )
    resultado = subprocess.run(
        [sys.executable, "-c", codigo], cwd=_RAIZ, env={"PYTHONPATH": str(_RAIZ)}, capture_output=True, text=True
    )
    assert resultado.returncode == 0, resultado.stderr


def test_en_disco_decide_aqui_y_lo_dice(monkeypatch, capsys):
    from agente_iam import aprobar

    monkeypatch.setattr(aprobar_cliente, "ALMACEN", "disco")
    monkeypatch.setattr(aprobar_cliente, "URL_APROBACION", "")
    monkeypatch.setattr(almacen, "leer", lambda sid: _registro(solicitante=_solicitante()))
    monkeypatch.setattr(aprobar_cliente, "enviar", lambda *a: pytest.fail("en disco no hay URL"))
    aprobador = _aprobador_sso()
    monkeypatch.setattr(aprobar, "identificar_aprobador", lambda: aprobador)
    llamadas = []

    def decidir(peticion, quien):
        llamadas.append((peticion, quien))
        return 200, _cuerpo_200()

    monkeypatch.setattr(aprobar, "decidir", decidir)
    assert _salida(["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab"], monkeypatch) == 0
    assert "sin servidor" in capsys.readouterr().out
    (peticion, quien), = llamadas
    assert (peticion.id, peticion.accion, peticion.huella) == ("req-prueba", "aprobar", "sha256:abababababababababababababababababababababababababababababababab")
    assert quien is aprobador


@pytest.mark.parametrize(
    ("codigo", "salida"), [(200, 0), (409, 3), (404, 1), (400, 1), (403, 1), (500, 1)]
)
def test_codigo_de_la_url_a_codigo_de_salida(dynamodb, monkeypatch, codigo, salida):
    cuerpos = {
        200: _cuerpo_200(),
        409: {"id": "req-prueba", "resultado": "bloqueada", "bloqueos": ["Falta la huella"]},
        404: {"id": "req-prueba", "resultado": "no_existe"},
        400: {"error": "la peticion no cumple el contrato: huella"},
        403: {"resultado": "sin_permiso", "detalle": "no autorizado"},
        500: {"error": "error inesperado", "tipo": "RuntimeError"},
    }
    _enviado(monkeypatch, (codigo, cuerpos[codigo]))
    assert _salida(["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab"], monkeypatch) == salida


def test_un_200_guarda_y_muestra_a_quien_se_atribuyo(dynamodb, monkeypatch, capsys):
    _enviado(monkeypatch)
    assert _salida(["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab"], monkeypatch) == 0
    salida = capsys.readouterr().out
    assert "req-prueba  ->  aprobada" in salida
    assert "Aprobador (persona): aprobador.demo" in salida
    assert "solicitante (persona): solicitante.demo" in salida
    assert "Guardado en: dynamodb://solicitudes/req-prueba" in salida


def test_un_409_lista_los_motivos(dynamodb, monkeypatch, capsys):
    _enviado(monkeypatch, (409, {"resultado": "bloqueada", "bloqueos": ["Autoaprobacion: la misma persona"]}))
    assert _salida(["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab"], monkeypatch) == 3
    salida = capsys.readouterr().out
    assert "NO se aprueba req-prueba" in salida
    assert "Autoaprobacion: la misma persona" in salida


def test_un_403_no_culpa_solo_al_permiso(dynamodb, monkeypatch, capsys):
    _enviado(monkeypatch, (403, {"resultado": "sin_permiso", "detalle": "no autorizado"}))
    assert _salida(["req-prueba", "--huella", "sha256:" + "ab" * 32], monkeypatch) == 1
    salida = capsys.readouterr().out
    assert "sin_permiso" in salida
    # Se imprime lo que la URL dijo, y el aviso da las tres causas posibles.
    assert "no autorizado" in salida
    assert "lambda:InvokeFunctionUrl" in salida
    assert "aws sso login" in salida
    assert "firma" in salida


@pytest.mark.parametrize(
    "respuesta",
    [(500, {"error": "error inesperado", "tipo": "RuntimeError"}), (0, {"resultado": "sin_respuesta", "detalle": "t"})],
)
def test_tras_un_500_o_sin_respuesta_hay_que_releer_antes_de_reintentar(
    dynamodb, monkeypatch, capsys, respuesta
):
    """La decision pudo escribirse aunque la respuesta no llegara (la Lambda
    escribe y despues contesta). Reintentar a ciegas daria un 409 que parece
    un fallo del primer intento."""
    _enviado(monkeypatch, respuesta)
    assert _salida(["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab"], monkeypatch) == 1
    salida = " ".join(capsys.readouterr().out.split())
    assert "puede que la decision SI se haya escrito" in salida
    assert "python -m agente_iam.aprobar_cliente req-prueba" in salida


def test_un_404_no_pide_releer(dynamodb, monkeypatch, capsys):
    _enviado(monkeypatch, (404, {"id": "req-prueba", "resultado": "no_existe"}))
    assert _salida(["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab"], monkeypatch) == 1
    assert "puede que la decision" not in capsys.readouterr().out


def test_sin_credenciales_no_dice_que_pudo_escribirse(dynamodb, monkeypatch, capsys):
    """Si ni se firmo, nada salio: el aviso de 'puede que se haya escrito' seria falso."""
    _enviado(monkeypatch, (0, {"resultado": "sin_credenciales", "detalle": "no hay"}))
    assert _salida(["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab"], monkeypatch) == 1
    assert "puede que la decision" not in capsys.readouterr().out


def test_la_solicitud_que_no_existe_sale_con_1(dynamodb, monkeypatch, capsys):
    monkeypatch.setattr(almacen, "leer", lambda sid: None)
    monkeypatch.setattr(aprobar_cliente, "enviar", lambda *a: pytest.fail("no hay nada que enviar"))
    assert _salida(["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab"], monkeypatch) == 1
    assert "No encuentro la solicitud 'req-prueba'" in capsys.readouterr().out


def test_sale_con_3_si_la_fila_es_inconsistente(dynamodb, monkeypatch, capsys):
    def inconsistente(sid):
        raise almacen.RegistroInconsistente("el documento trae aprobacion")

    monkeypatch.setattr(almacen, "leer", inconsistente)
    monkeypatch.setattr(aprobar_cliente, "enviar", lambda *a: pytest.fail("fila imposible: no se envia"))
    assert _salida(["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab"], monkeypatch) == 3
    assert "trae aprobacion" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["req-prueba", "--huella"],
        ["req-prueba", "--rechazar"],
        ["req-prueba", "--rechazar", "   "],
        ["../x", "--huella", "sha256:abababababababababababababababababababababababababababababababab"],
    ],
)
def test_argumentos_mal_formados_salen_con_1_sin_enviar(dynamodb, monkeypatch, capsys, argv):
    monkeypatch.setattr(aprobar_cliente, "enviar", lambda *a: pytest.fail("no se envia"))
    assert _salida(argv, monkeypatch) == 1
    assert capsys.readouterr().out


# ---------------------------------------------------------------------------
# S7 (24-10-2026): lo no confiable no llega crudo a la terminal
# ---------------------------------------------------------------------------

_CARGA = f"ok{_ESC}[3A{_ESC}[2KBeneficiario: arn:aws:iam::111122223333:user/otro{_ESC}[3B{_ESC}[8m"


def _registro_con_carga() -> dict:
    registro = _registro()
    registro["solicitud"]["justificacion"] = _CARGA + "\nBeneficiario: falso\u202e\x9b"
    registro["propuesta"]["supuestos"] = [f"{_ESC}[8m oculto"]
    registro["propuesta"]["policy_document"]["Statement"][0]["Sid"] = "x\u202ey\x7f"
    registro["validacion"] = {"menores": [{"codigo": f"{_ESC}[2J", "detalle": "\r\x07"}]}
    return registro


def test_la_revision_no_imprime_caracteres_de_control(capsys):
    aprobar_cliente._mostrar_propuesta(_registro_con_carga())
    salida = capsys.readouterr().out
    for crudo in (_ESC, "\u202e", "\x9b", "\x7f", "\r", "\x07"):
        assert crudo not in salida, repr(crudo)
    # Se ven escapados, no desaparecen: el aprobador tiene que saber que estaban.
    assert "\\x1b[3A" in salida
    assert "\\nBeneficiario: falso" in salida


def test_lo_que_responde_el_servidor_tampoco(dynamodb, capsys, monkeypatch):
    # Una decision tomada, con carga en cada campo que se pinta.
    cuerpo = _cuerpo_200()
    cuerpo["id"] = f"req{_ESC}[2J"
    cuerpo["decision"]["por"]["arn_llamante"] = f"a{_ESC}"
    cuerpo["decision"]["separacion_de_funciones"]["solicitante"] = f"s\u202e{_ESC}"
    cuerpo["aprobador"]["persona"] = f"p{_ESC}[8m"
    cuerpo["guardado_en"] = f"dynamodb://{_ESC}"
    aprobar_cliente._mostrar(cuerpo)

    # Un rechazo.
    rechazo = _cuerpo_200()
    rechazo["estado"] = "rechazada_por_aprobador"
    rechazo["decision"] = {**rechazo["decision"], "motivo": f"no{_ESC}[2J"}
    aprobar_cliente._mostrar(rechazo)

    # Bloqueos y errores, que citan lo que escribieron otros.
    for respuesta in (
        (409, {"resultado": "bloqueada", "bloqueos": [f"hay {_ESC}[2J en el motivo"]}),
        (400, {"error": f"mal{_ESC}[2J"}),
        (500, {"error": f"x{_ESC}", "tipo": f"T{_ESC}"}),
        (403, {"resultado": "sin_permiso", "detalle": f"d{_ESC}"}),
    ):
        _enviado(monkeypatch, respuesta)
        _salida(["req-prueba", "--huella", "sha256:abababababababababababababababababababababababababababababababab"], monkeypatch)

    salida = capsys.readouterr().out
    assert _ESC not in salida
    assert "\\x1b[2J" in salida


# ---------------------------------------------------------------------------
# python -m agente_iam.aprobar ya no es el comando
# ---------------------------------------------------------------------------


def test_python_m_aprobar_apunta_al_cliente():
    """En un proceso aparte: es lo que hace `python -m`, y asi tampoco hay
    `aprobar` ya importado por otros tests. No importa el cliente."""
    resultado = subprocess.run(
        [sys.executable, "-m", "agente_iam.aprobar"],
        cwd=_RAIZ, env={"PYTHONPATH": str(_RAIZ)}, capture_output=True, text=True,
    )
    assert resultado.returncode == 1
    assert resultado.stdout.strip() == "Para aprobar: python -m agente_iam.aprobar_cliente <id> (ADR-003)"


def test_python_m_aprobar_no_carga_el_cliente():
    codigo = (
        "import runpy, sys\n"
        "try:\n"
        "    runpy.run_module('agente_iam.aprobar', run_name='__main__')\n"
        "except SystemExit:\n"
        "    pass\n"
        "sys.exit(1 if 'agente_iam.aprobar_cliente' in sys.modules else 0)\n"
    )
    resultado = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", codigo],
        cwd=_RAIZ, env={"PYTHONPATH": str(_RAIZ)}, capture_output=True, text=True,
    )
    assert resultado.returncode == 0, resultado.stderr


def test_aprobar_ya_no_tiene_main():
    from agente_iam import aprobar

    assert not hasattr(aprobar, "main")
    assert not hasattr(aprobar, "_mostrar")
    assert not hasattr(aprobar, "_mostrar_propuesta")


def test_una_huella_con_otra_forma_sale_con_1_sin_leer_ni_enviar(dynamodb, monkeypatch, capsys):
    """La peticion se arma antes de leer: una huella que no es `sha256:` mas 64
    hex (el contrato de `PeticionAprobacion`) no toca la tabla ni la URL."""
    monkeypatch.setattr(almacen, "leer", lambda sid: pytest.fail("no deberia leer"))
    _enviado_ninguno = _enviado(monkeypatch)
    assert _salida(["req-prueba", "--huella", "sha256:abc"], monkeypatch) == 1
    assert "huella" in capsys.readouterr().out
    assert _enviado_ninguno == []


# ---------------------------------------------------------------------------
# Fase 23: lo que ve el aprobador de un rol por persona
# ---------------------------------------------------------------------------

_ROL_PERSONA = "arn:aws:iam::111122223333:role/agente-iam/personas/agente-iam-persona-solicitante-demo-req-1"


def _registro_persona() -> dict:
    solicitud = _solicitud_persona(horas=4, correo="persona@example.com")
    ident = models.IdentidadVerificada(
        principal_arn=_ROL_PERSONA,
        tipo="role",
        existe=False,
        cuenta="111122223333",
        modo="rol_por_persona",
        persona=solicitud.persona,
        horas=solicitud.horas,
    )
    return _registro(
        solicitud=solicitud.model_dump(mode="json", exclude_none=True),
        identidad_verificada=ident.model_dump(mode="json"),
        propuesta=_propuesta(principal=_ROL_PERSONA).model_dump(mode="json", exclude_none=True),
    )


def test_la_revision_de_un_rol_por_persona_muestra_horas_vence_y_rol(capsys):
    aprobar_cliente._mostrar_propuesta(_registro_persona())
    salida = capsys.readouterr().out
    assert f"Beneficiario: rol por persona {_ROL_PERSONA} (se crea al aplicar)" in salida
    assert "Persona: solicitante.demo (sub sub-1234)" in salida
    assert re.search(
        r"Horas: 4; venceria el \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z si se aplicara ahora", salida
    )
    assert "Correo de aviso: persona@example.com" in salida


def test_la_revision_de_un_rol_por_persona_escapa_lo_no_imprimible(capsys):
    registro = _registro_persona()
    registro["identidad_verificada"]["persona"]["usuario"] = f"x{_ESC}[2Jy"
    registro["solicitud"]["correo_aviso"] = "a\u202e@example.com"
    aprobar_cliente._mostrar_propuesta(registro)
    salida = capsys.readouterr().out
    assert _ESC not in salida
    assert "\u202e" not in salida


def test_la_revision_de_un_rol_por_persona_con_horas_rotas_no_cae(capsys):
    registro = _registro_persona()
    registro["identidad_verificada"]["horas"] = 99
    aprobar_cliente._mostrar_propuesta(registro)
    assert "Horas: 99; venceria el (horas invalidas: no se puede calcular) si se aplicara ahora" in capsys.readouterr().out


def test_la_revision_de_un_principal_existente_no_cambia(capsys):
    aprobar_cliente._mostrar_propuesta(_registro())
    salida = capsys.readouterr().out
    assert "Beneficiario: arn:aws:iam::111122223333:user/jose.torres  [" in salida
    for ausente in ("rol por persona", "Persona:", "Horas:", "Correo de aviso:"):
        assert ausente not in salida
