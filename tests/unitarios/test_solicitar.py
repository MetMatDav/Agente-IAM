"""scripts/solicitar.py: el cliente del solicitante, sin red.

Maneja un token de acceso real. Estos tests fijan lo que no puede fallar en
silencio: que el token nunca se imprima (ni con 200 ni con 401), que la URL
lleve el ARN codificado y el qualifier, que el id de sesion cumpla el minimo
de AgentCore, los codigos de salida, y que no se guarde un token cuyo `sub`
ya es de otra persona.
"""

import base64
import importlib.util
import io
import json
import stat
import uuid
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import botocore
import pytest
from botocore.stub import Stubber

from tests.dobles import _cliente

_RUTA = Path(__file__).resolve().parents[2] / "scripts" / "solicitar.py"
_spec = importlib.util.spec_from_file_location("solicitar", _RUTA)
assert _spec
assert _spec.loader
solicitar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(solicitar)

ARN = "arn:aws:bedrock-agentcore:us-east-1:111122223333:runtime/agente_iam-AbC123"


def _jwt(carga: dict) -> str:
    def b64(d: bytes) -> str:
        return base64.urlsafe_b64encode(d).decode().rstrip("=")

    return f"{b64(b'{\"alg\":\"RS256\"}')}.{b64(json.dumps(carga).encode())}.{b64(b'firma-de-prueba-123')}"


TOKEN = _jwt({"sub": "sub-ana", "token_use": "access"})


class _Respuesta:
    def __init__(self, cuerpo: object, status: int = 200):
        self.status = status
        self._cuerpo = json.dumps(cuerpo).encode()

    def read(self) -> bytes:
        return self._cuerpo

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def entorno(tmp_path, monkeypatch):
    """Tokens en tmp, ARN fijo y un urlopen falso que captura la Request."""
    monkeypatch.setattr(solicitar, "LOCAL_TOKENS", tmp_path / "tokens")
    monkeypatch.setattr(solicitar, "_salidas", lambda perfil, pila: {"RuntimeArn": ARN})
    solicitar.guardar_token(tmp_path / "tokens" / "ana.json", TOKEN)
    capturado: dict = {"llamadas": 0}

    def hacer(respuesta):
        def falso(peticion, timeout=None):
            capturado["peticion"] = peticion
            capturado["timeout"] = timeout
            capturado["llamadas"] += 1
            if isinstance(respuesta, Exception):
                raise respuesta
            return respuesta

        monkeypatch.setattr(solicitar, "_abrir", falso)

    capturado["responder"] = hacer
    capturado["dir"] = tmp_path
    return capturado


def _fichero(tmp_path, contenido: str) -> str:
    ruta = tmp_path / "solicitud.json"
    ruta.write_text(contenido)
    return str(ruta)


def _procesada() -> dict:
    return {"resultado": "procesada", "guardado_en": "solicitudes/x.json",
            "registro": {"estado": "pendiente", "solicitante": "ana"}}


def _http_error(codigo: int, cuerpo: object) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://x", codigo, "err", {}, io.BytesIO(json.dumps(cuerpo).encode()))  # type: ignore[arg-type]


def test_id_de_sesion_cumple_el_minimo_y_cambia():
    a, b = solicitar.id_de_sesion(), solicitar.id_de_sesion()
    assert len(a) >= 33
    assert a != b


def test_enviar_construye_url_cabeceras_y_cuerpo(entorno, capsys):
    entorno["responder"](_Respuesta(_procesada()))
    fichero = _fichero(entorno["dir"], '{"a": 1}')
    assert solicitar.main(["enviar", fichero, "--usuario", "ana"]) == 0
    p = entorno["peticion"]
    assert p.full_url.startswith("https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/arn%3Aaws%3Abedrock-agentcore")
    assert "%3A" in p.full_url
    assert "%2F" in p.full_url
    assert "runtime/" not in p.full_url
    assert p.full_url.endswith("/invocations?qualifier=DEFAULT")
    assert p.get_header("Authorization") == f"Bearer {TOKEN}"
    assert p.get_header("Content-type") == "application/json"
    assert len(p.get_header("X-amzn-bedrock-agentcore-runtime-session-id")) >= 33
    enviado = json.loads(p.data)
    assert enviado["a"] == 1
    assert set(enviado) == {"a", "clave_envio"}  # el script anade la clave de envio
    assert entorno["timeout"] == 180


def test_imprime_el_resultado_y_no_el_token_con_200(entorno, capsys):
    entorno["responder"](_Respuesta(_procesada()))
    solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "ana"])
    salida = capsys.readouterr()
    for esperado in ("200", "procesada", "pendiente", "solicitudes/x.json", "ana"):
        assert esperado in salida.out
    assert TOKEN not in salida.out + salida.err


def test_el_token_no_aparece_con_401_aunque_el_cuerpo_lo_repita(entorno, capsys):
    entorno["responder"](_http_error(401, {"message": f"token invalido {TOKEN}"}))
    codigo = solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "ana"])
    salida = capsys.readouterr()
    assert codigo == 1
    assert "401" in salida.out
    assert TOKEN not in salida.out + salida.err


def test_forma_invalida_y_registro_existente_salen_con_2(entorno, capsys):
    for motivo in ("forma_invalida", "registro_existente"):
        entorno["responder"](_Respuesta({"resultado": "error", "codigo": motivo, "detalle": "falta algo"}))
        assert solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "ana"]) == 2
        salida = capsys.readouterr().out
        assert motivo in salida
        assert "falta algo" in salida


def test_registro_no_almacenable_y_otros_fallos_salen_con_1(entorno):
    entorno["responder"](_Respuesta({"resultado": "error", "codigo": "registro_no_almacenable", "detalle": "x"}))
    assert solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "ana"]) == 1
    for codigo in (403, 424):
        entorno["responder"](_http_error(codigo, {"message": "no"}))
        assert solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "ana"]) == 1


def test_error_de_red_sale_con_1(entorno, capsys):
    entorno["responder"](urllib.error.URLError("sin red"))
    assert solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "ana"]) == 1
    assert TOKEN not in capsys.readouterr().out


def test_lo_impreso_escapa_caracteres_de_control(entorno, capsys):
    entorno["responder"](_Respuesta({"resultado": "error", "codigo": "forma_invalida", "detalle": "x\x1b[31mrojo\nBeneficiario: yo"}))
    solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "ana"])
    salida = capsys.readouterr().out
    assert "\x1b" not in salida
    assert "\\x1b" in salida
    assert "\nBeneficiario" not in salida


@pytest.mark.parametrize("contenido", ["[1, 2]", '"texto"', "42", "null", "no es json", ""])
def test_un_fichero_que_no_es_un_objeto_json_sale_con_2_sin_red(entorno, contenido):
    entorno["responder"](_Respuesta(_procesada()))
    assert solicitar.main(["enviar", _fichero(entorno["dir"], contenido), "--usuario", "ana"]) == 2
    assert entorno["llamadas"] == 0


def test_enviar_sin_token_guardado_sale_con_1_sin_red(entorno):
    entorno["responder"](_Respuesta(_procesada()))
    assert solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "nadie"]) == 1
    assert entorno["llamadas"] == 0


def test_enviar_se_niega_si_el_token_es_de_otra_persona(entorno):
    solicitar.guardar_token(entorno["dir"] / "tokens" / "luis.json", TOKEN)  # mismo sub que ana
    entorno["responder"](_Respuesta(_procesada()))
    assert solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "luis"]) == 1
    assert entorno["llamadas"] == 0


def test_sub_de_otro_usuario_con_nombres_libres(tmp_path):
    solicitar.guardar_token(tmp_path / "ana.json", _jwt({"sub": "sub-ana"}))
    assert solicitar.sub_de_otro(tmp_path, "luis", "sub-ana") == "ana"
    assert solicitar.sub_de_otro(tmp_path, "luis", "sub-luis") is None
    assert solicitar.sub_de_otro(tmp_path, "ana", "sub-ana") is None  # su propio fichero no cuenta
    assert solicitar.sub_de_otro(tmp_path / "no-existe", "luis", "sub-ana") is None


def _preparar_token(monkeypatch, tmp_path, token: str):
    """Doble del PKCE: sin servidor local ni red, canje devuelve `token`."""
    monkeypatch.setattr(solicitar, "LOCAL_TOKENS", tmp_path / "tokens")
    monkeypatch.setattr(solicitar, "_salidas", lambda perfil, pila: {"UrlDominio": "https://d.auth.us-east-1.amazoncognito.com", "ClienteId": "cli"})
    monkeypatch.setattr(solicitar, "_esperar_codigo", lambda state, segundos=300: "codigo-falso")
    monkeypatch.setattr(solicitar, "_abrir", lambda p, timeout=None: _Respuesta({"access_token": token}))


def test_token_guarda_con_600_y_no_imprime_el_token(tmp_path, monkeypatch, capsys):
    _preparar_token(monkeypatch, tmp_path, TOKEN)
    assert solicitar.main(["token", "--usuario", "ana"]) == 0
    ruta = tmp_path / "tokens" / "ana.json"
    assert stat.S_IMODE(ruta.stat().st_mode) == 0o600
    assert json.loads(ruta.read_text())["access_token"] == TOKEN
    salida = capsys.readouterr()
    assert TOKEN not in salida.out + salida.err
    assert "sub-ana" in salida.out  # los claims visibles si


def test_token_guarda_tambien_el_id_token_cuando_cognito_lo_devuelve(tmp_path, monkeypatch, capsys):
    """Fase 23: AssumeRoleWithWebIdentity exige `aud`, que solo trae el token de identidad."""
    _preparar_token(monkeypatch, tmp_path, TOKEN)
    monkeypatch.setattr(solicitar, "_abrir", lambda p, timeout=None: _Respuesta({"access_token": TOKEN, "id_token": "i.d.tok"}))
    assert solicitar.main(["token", "--usuario", "ana"]) == 0
    guardado = json.loads((tmp_path / "tokens" / "ana.json").read_text())
    assert guardado["access_token"] == TOKEN
    assert guardado["id_token"] == "i.d.tok"
    salida = capsys.readouterr()
    assert "i.d.tok" not in salida.out + salida.err


def test_token_no_guarda_si_el_sub_ya_es_de_otro_usuario(tmp_path, monkeypatch, capsys):
    solicitar.guardar_token(tmp_path / "tokens" / "ana.json", TOKEN)
    _preparar_token(monkeypatch, tmp_path, TOKEN)  # el navegador reutilizo la sesion de ana
    assert solicitar.main(["token", "--usuario", "luis"]) == 1
    assert not (tmp_path / "tokens" / "luis.json").exists()
    assert "ana" in capsys.readouterr().err


def test_nada_se_ejecuta_al_importar_y_la_ayuda_no_toca_la_red(capsys):
    with pytest.raises(SystemExit) as e:
        solicitar.main(["--help"])
    assert e.value.code == 0
    assert "token" in capsys.readouterr().out


def test_un_cuerpo_largo_no_json_no_deja_ver_el_token_ni_cruzando_el_limite(entorno, capsys):
    """El token cruza el byte 500 del cuerpo: recortar antes de quitarlo
    dejaria su comienzo a la vista."""
    cuerpo = "x" * 470 + TOKEN + "y" * 200
    assert len(cuerpo) > 500
    assert 470 < 500 < 470 + len(TOKEN)
    entorno["responder"](_http_error_texto(502, cuerpo))
    assert solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "ana"]) == 1
    salida = capsys.readouterr()
    todo = salida.out + salida.err
    for i in range(len(TOKEN) - 39):
        assert TOKEN[i:i + 40] not in todo
    assert TOKEN[:20] not in todo


def test_un_mensaje_largo_de_un_json_tampoco_deja_ver_el_token(entorno, capsys):
    entorno["responder"](_http_error(403, {"message": "x" * 470 + TOKEN}))
    assert solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "ana"]) == 1
    todo = "".join(capsys.readouterr())
    assert TOKEN[:20] not in todo


def _http_error_texto(codigo: int, texto: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://x", codigo, "err", {}, io.BytesIO(texto.encode()))  # type: ignore[arg-type]


@pytest.mark.parametrize("codigo", [301, 302, 303, 307, 308])
def test_una_redireccion_sale_con_1_sin_segunda_peticion(entorno, capsys, codigo):
    error = urllib.error.HTTPError("https://x", codigo, "Redirect", {"Location": "https://otro.example/"}, io.BytesIO(b""))  # type: ignore[arg-type]
    entorno["responder"](error)
    assert solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "ana"]) == 1
    assert entorno["llamadas"] == 1
    salida = capsys.readouterr()
    assert str(codigo) in salida.out
    assert "otro.example" not in salida.out + salida.err
    assert TOKEN not in salida.out + salida.err


@pytest.mark.parametrize("codigo", [301, 302, 303, 307, 308])
def test_el_abridor_real_no_sigue_la_redireccion(codigo):
    """El comportamiento de verdad, sin red: `redirect_request` devuelve None
    y urllib convierte el 3xx en HTTPError en vez de repetir la peticion (con
    su `Authorization`) contra el `Location`."""
    abridor = urllib.request.build_opener(solicitar._SinRedirecciones)
    pedido = urllib.request.Request("https://x", data=b"{}", headers={"Authorization": "Bearer t"})
    with pytest.raises(urllib.error.HTTPError) as e:
        abridor.error("https", pedido, io.BytesIO(b""), codigo, "Redirect", {"Location": "https://otro.example/"})
    assert e.value.code == codigo


def test_abrir_construye_el_abridor_con_el_manejador_sin_redirecciones(monkeypatch):
    visto: dict = {}

    class Abridor:
        def open(self, peticion, timeout=None):
            visto["timeout"] = timeout
            return "respuesta"

    def construir(*manejadores):
        visto["manejadores"] = manejadores
        return Abridor()

    monkeypatch.setattr(solicitar.urllib.request, "build_opener", construir)
    assert solicitar._abrir(urllib.request.Request("https://x"), 7) == "respuesta"
    assert visto["timeout"] == 7
    assert len(visto["manejadores"]) == 1
    manejador = visto["manejadores"][0]
    clase = manejador if isinstance(manejador, type) else type(manejador)
    assert issubclass(clase, urllib.request.HTTPRedirectHandler)


@pytest.mark.parametrize("orden", ["token", "enviar"])
@pytest.mark.parametrize("usuario", ["../x", "a/b", "", ".." + "/" * 3, "x" * 65, "con espacio", "a\nb"])
def test_usuario_que_no_es_un_nombre_simple_sale_con_2_sin_tocar_nada(entorno, orden, usuario):
    entorno["responder"](_Respuesta(_procesada()))
    argv = [orden, "--usuario", usuario] if orden == "token" else [orden, _fichero(entorno["dir"], "{}"), "--usuario", usuario]
    assert solicitar.main(argv) == 2
    assert entorno["llamadas"] == 0
    assert not (entorno["dir"] / "x.json").exists()


# --- Fase 23: clave de envio, id y rol previsto --------------------------------


def _procesada_con_rol() -> dict:
    return {**_procesada(), "solicitud_id": "req-20261026-0123abcd",
            "rol_previsto": "arn:aws:iam::111122223333:role/agente-iam-persona-ana-req-20261026-0123abcd"}


def test_enviar_genera_la_clave_de_envio_si_falta_y_la_imprime(entorno, capsys):
    entorno["responder"](_Respuesta(_procesada()))
    assert solicitar.main(["enviar", _fichero(entorno["dir"], '{"a": 1}'), "--usuario", "ana"]) == 0
    clave = json.loads(entorno["peticion"].data)["clave_envio"]
    assert str(uuid.UUID(clave)) == clave
    salida = capsys.readouterr().out
    assert f"clave_envio: {clave}" in salida
    assert "--clave" in salida
    # un envio nuevo, una clave nueva
    solicitar.main(["enviar", _fichero(entorno["dir"], '{"a": 1}'), "--usuario", "ana"])
    assert json.loads(entorno["peticion"].data)["clave_envio"] != clave


def test_enviar_con_clave_la_repite_tal_cual(entorno, capsys):
    entorno["responder"](_Respuesta(_procesada()))
    clave = "0f8fad5b-d9cb-469f-a165-70867728950e"
    fichero = _fichero(entorno["dir"], '{"a": 1, "clave_envio": "11111111-1111-4111-8111-111111111111"}')
    assert solicitar.main(["enviar", fichero, "--usuario", "ana", "--clave", clave]) == 0
    assert json.loads(entorno["peticion"].data)["clave_envio"] == clave
    assert f"clave_envio: {clave}" in capsys.readouterr().out
    # sin --clave, la que trae el fichero se respeta
    assert solicitar.main(["enviar", fichero, "--usuario", "ana"]) == 0
    assert json.loads(entorno["peticion"].data)["clave_envio"] == "11111111-1111-4111-8111-111111111111"


def test_enviar_con_clave_que_no_es_uuid_sale_con_2_sin_red(entorno):
    entorno["responder"](_Respuesta(_procesada()))
    assert solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "ana", "--clave", "no-es-uuid"]) == 2
    assert entorno["llamadas"] == 0


def test_enviar_imprime_id_y_rol_previsto(entorno, capsys):
    entorno["responder"](_Respuesta(_procesada_con_rol()))
    assert solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "ana"]) == 0
    salida = capsys.readouterr().out
    assert "solicitud_id: req-20261026-0123abcd" in salida
    assert "rol_previsto: arn:aws:iam::111122223333:role/agente-iam-persona-ana-req-20261026-0123abcd" in salida


def test_enviar_imprime_las_horas_si_vienen_y_nada_de_lo_que_ya_no_llega(entorno, capsys):
    """La respuesta del servidor es una vista publica: `enviar` imprime de ella
    estado, guardado_en, solicitante, id, rol e `horas`, y no vuelca el resto."""
    respuesta = _procesada_con_rol()
    respuesta["registro"] = {**respuesta["registro"], "horas": 4, "propuesta": {"x": "no-debe-salir"}}
    entorno["responder"](_Respuesta(respuesta))
    assert solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "ana"]) == 0
    salida = capsys.readouterr().out
    assert "horas: 4" in salida
    assert "no-debe-salir" not in salida

    entorno["responder"](_Respuesta(_procesada_con_rol()))  # sin horas en el registro
    solicitar.main(["enviar", _fichero(entorno["dir"], "{}"), "--usuario", "ana"])
    assert "horas:" not in capsys.readouterr().out


# --- Fase 23: asumir ----------------------------------------------------------

ROL = "arn:aws:iam::111122223333:role/agente-iam/personas/agente-iam-persona-ana-req-20261026-0123abcd"
NOMBRE_ROL = "agente-iam-persona-ana-req-20261026-0123abcd"
ID_TOKEN = _jwt({"sub": "sub-ana", "aud": "cliente-cli", "token_use": "id"})
CREDENCIALES = {
    "AccessKeyId": "ASIAEJEMPLO0000000",
    "SecretAccessKey": "secreto-que-no-debe-salir-0123456789",  # gitleaks:allow (valor inventado del test)
    "SessionToken": "sesion-que-no-debe-salir-9876543210",  # gitleaks:allow (valor inventado del test)
    "Expiration": datetime(2026, 10, 27, 4, 0, 0, tzinfo=timezone.utc),
}


@pytest.fixture
def canje(tmp_path, monkeypatch):
    """Tokens y credenciales en tmp, con un cliente STS de Stubber. Sin red."""
    monkeypatch.setattr(solicitar, "LOCAL_TOKENS", tmp_path / "tokens")
    monkeypatch.setattr(solicitar, "LOCAL_CREDENCIALES", tmp_path / "credenciales")
    solicitar.guardar_token(tmp_path / "tokens" / "ana.json", TOKEN, ID_TOKEN)
    sts = _cliente("sts")
    stub = Stubber(sts)
    monkeypatch.setattr(solicitar, "_sts", lambda: sts)
    stub.activate()
    yield {"dir": tmp_path, "stub": stub, "sts": sts}
    stub.deactivate()


def _esperado(horas: int = 1) -> dict:
    return {"RoleArn": ROL, "RoleSessionName": "agente-iam-ana", "WebIdentityToken": ID_TOKEN,
            "DurationSeconds": horas * 3600}


def test_asumir_llama_a_sts_sin_firmar_y_guarda_con_600_sin_imprimir_claves(canje, capsys):
    canje["stub"].add_response("assume_role_with_web_identity", {"Credentials": CREDENCIALES}, _esperado(4))
    assert solicitar.main(["asumir", ROL, "--usuario", "ana", "--horas", "4"]) == 0
    canje["stub"].assert_no_pending_responses()
    ruta = canje["dir"] / "credenciales" / f"ana-{NOMBRE_ROL}.json"
    assert stat.S_IMODE(ruta.stat().st_mode) == 0o600
    assert stat.S_IMODE(ruta.parent.stat().st_mode) == 0o700
    guardado = json.loads(ruta.read_text())
    assert guardado["AccessKeyId"] == CREDENCIALES["AccessKeyId"]
    assert guardado["SecretAccessKey"] == CREDENCIALES["SecretAccessKey"]
    assert guardado["SessionToken"] == CREDENCIALES["SessionToken"]
    assert guardado["Expiration"] == "2026-10-27T04:00:00+00:00"
    salida = capsys.readouterr()
    todo = salida.out + salida.err
    assert "2026-10-27T04:00:00+00:00" in salida.out
    for secreto in (CREDENCIALES["SecretAccessKey"], CREDENCIALES["SessionToken"], ID_TOKEN, TOKEN,
                    "SecretAccessKey", "SessionToken"):
        assert secreto not in todo


def test_asumir_por_defecto_pide_una_hora(canje):
    canje["stub"].add_response("assume_role_with_web_identity", {"Credentials": CREDENCIALES}, _esperado(1))
    assert solicitar.main(["asumir", ROL, "--usuario", "ana"]) == 0
    canje["stub"].assert_no_pending_responses()


def test_el_cliente_sts_real_se_crea_sin_firmar():
    """Quien llama no tiene credenciales de AWS: si el cliente firmara, el
    canje fallaria con `NoCredentialsError`. Se crea el cliente real (sin red)."""
    cliente = solicitar._sts()
    assert cliente.meta.config.signature_version is botocore.UNSIGNED
    assert cliente.meta.region_name == "us-east-1"


def test_el_nombre_de_sesion_se_normaliza_y_se_recorta_a_64(canje):
    solicitar.guardar_token(canje["dir"] / "tokens" / "Ana Perez.json", TOKEN, ID_TOKEN)  # no valido como --usuario
    largo = "u" * 64
    solicitar.guardar_token(canje["dir"] / "tokens" / f"{largo}.json", _jwt({"sub": "otro"}), _jwt({"sub": "otro"}))
    canje["stub"].add_response(
        "assume_role_with_web_identity", {"Credentials": CREDENCIALES},
        {**_esperado(), "RoleSessionName": ("agente-iam-" + largo)[:64], "WebIdentityToken": _jwt({"sub": "otro"})})
    assert solicitar.main(["asumir", ROL, "--usuario", largo]) == 0
    canje["stub"].assert_no_pending_responses()


def test_asumir_sin_id_token_sale_con_1(canje, capsys):
    solicitar.guardar_token(canje["dir"] / "tokens" / "luis.json", _jwt({"sub": "sub-luis"}))  # sin id_token
    assert solicitar.main(["asumir", ROL, "--usuario", "luis"]) == 1
    assert "vuelve a entrar con `token`" in capsys.readouterr().err
    assert solicitar.main(["asumir", ROL, "--usuario", "nadie"]) == 1  # ni siquiera hay fichero
    assert not (canje["dir"] / "credenciales").exists()


def test_asumir_se_niega_si_el_id_token_es_de_otra_persona(canje):
    solicitar.guardar_token(canje["dir"] / "tokens" / "luis.json", TOKEN, ID_TOKEN)  # mismo sub que ana
    assert solicitar.main(["asumir", ROL, "--usuario", "luis"]) == 1
    assert not (canje["dir"] / "credenciales").exists()


def test_asumir_access_denied_sale_con_1_y_no_escribe(canje, capsys):
    canje["stub"].add_client_error("assume_role_with_web_identity", "AccessDenied",
                                   f"Not authorized to perform sts:AssumeRoleWithWebIdentity {ID_TOKEN}")
    assert solicitar.main(["asumir", ROL, "--usuario", "ana"]) == 1
    salida = capsys.readouterr()
    assert "espera unos segundos y repite" in salida.err
    assert ID_TOKEN not in salida.out + salida.err
    assert not (canje["dir"] / "credenciales").exists()
    assert "--horas no puede superar las horas que pediste en la solicitud (MaxSessionDuration del rol)" in salida.err


def test_asumir_validation_error_tambien_recuerda_el_tope_de_horas(canje, capsys):
    canje["stub"].add_client_error("assume_role_with_web_identity", "ValidationError",
                                   "The requested DurationSeconds exceeds the MaxSessionDuration set for this role.")
    assert solicitar.main(["asumir", ROL, "--usuario", "ana", "--horas", "12"]) == 1
    salida = capsys.readouterr()
    assert "--horas no puede superar las horas que pediste en la solicitud (MaxSessionDuration del rol)" in salida.err
    assert not (canje["dir"] / "credenciales").exists()


@pytest.mark.parametrize("codigo", ["ExpiredTokenException", "InvalidIdentityToken"])
def test_asumir_con_token_caducado_dice_que_vuelva_a_entrar(canje, capsys, codigo):
    canje["stub"].add_client_error("assume_role_with_web_identity", codigo, "malo")
    assert solicitar.main(["asumir", ROL, "--usuario", "ana"]) == 1
    assert "vuelve a entrar con `token`" in capsys.readouterr().err
    assert not (canje["dir"] / "credenciales").exists()


def test_asumir_con_listar_cuenta_objetos(canje, monkeypatch, capsys):
    canje["stub"].add_response("assume_role_with_web_identity", {"Credentials": CREDENCIALES}, _esperado())
    s3 = _cliente("s3")
    stub_s3 = Stubber(s3)
    stub_s3.add_response("list_objects_v2", {"KeyCount": 2, "Contents": [{"Key": "a"}, {"Key": "b"}]},
                         {"Bucket": "finanzas-demo-111122223333", "MaxKeys": 5})
    vistas: list = []
    monkeypatch.setattr(solicitar, "_s3", lambda credenciales: (vistas.append(credenciales), s3)[1])
    with stub_s3:
        assert solicitar.main(["asumir", ROL, "--usuario", "ana", "--listar", "finanzas-demo-111122223333"]) == 0
    stub_s3.assert_no_pending_responses()
    assert vistas[0]["SessionToken"] == CREDENCIALES["SessionToken"]
    salida = capsys.readouterr()
    assert "objetos listados: 2" in salida.out
    assert CREDENCIALES["SecretAccessKey"] not in salida.out + salida.err


def test_asumir_listar_con_error_sale_con_1_sin_imprimir_claves(canje, monkeypatch, capsys):
    canje["stub"].add_response("assume_role_with_web_identity", {"Credentials": CREDENCIALES}, _esperado())
    s3 = _cliente("s3")
    stub_s3 = Stubber(s3)
    stub_s3.add_client_error("list_objects_v2", "AccessDenied", f"no {CREDENCIALES['SessionToken']}")
    monkeypatch.setattr(solicitar, "_s3", lambda credenciales: s3)
    with stub_s3:
        assert solicitar.main(["asumir", ROL, "--usuario", "ana", "--listar", "otro-bucket"]) == 1
    salida = capsys.readouterr()
    assert CREDENCIALES["SessionToken"] not in salida.out + salida.err


@pytest.mark.parametrize("horas", ["0", "13", "-1", "100"])
def test_asumir_horas_fuera_de_rango_sale_con_2_sin_red(canje, horas):
    # el Stubber no tiene respuestas preparadas: cualquier llamada a STS fallaria
    assert solicitar.main(["asumir", ROL, "--usuario", "ana", "--horas", horas]) == 2
    assert not (canje["dir"] / "credenciales").exists()


def test_asumir_con_horas_que_no_son_un_entero_sale_con_2(canje):
    with pytest.raises(SystemExit) as e:
        solicitar.main(["asumir", ROL, "--usuario", "ana", "--horas", "4.5"])
    assert e.value.code == 2


@pytest.mark.parametrize("arn", ["agente-iam-persona-ana", "arn:aws:s3:::bucket", "arn:aws:iam::111122223333:user/ana",
                                 "arn:aws:iam::111122223333:role/../x"])
def test_asumir_con_algo_que_no_es_un_arn_de_rol_sale_con_2_sin_red(canje, arn):
    assert solicitar.main(["asumir", arn, "--usuario", "ana"]) == 2
