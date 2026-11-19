"""El entrypoint de AgentCore: la puerta HTTP del analista.

Estos tests NO levantan un servidor ni necesitan el SDK `bedrock-agentcore`
instalado. Prueban `manejar`, que es donde esta todo lo que puede fallar; el
servidor en si es del SDK y probarlo seria probar codigo de AWS.
"""

import base64
import inspect
import json
import re
from datetime import datetime, timezone

import pytest

from agente_iam import almacen, servidor
from agente_iam.models import SolicitudEstructurada


class _Contexto:
    """El doble del `RequestContext` del SDK: solo lo que se le lee."""

    def __init__(self, session_id="s" * 33, request_headers=None):
        self.session_id = session_id
        self.request_headers = request_headers


def _jwt(carga: dict) -> str:
    """Un JWT con la forma correcta y una firma que nadie va a mirar: el
    servidor no la verifica (lo hizo el autorizador de AgentCore)."""

    def b64(d: bytes) -> str:
        return base64.urlsafe_b64encode(d).decode().rstrip("=")

    cabecera = b64(b'{"alg":"RS256"}')
    return f"{cabecera}.{b64(json.dumps(carga).encode())}.{b64(b'firma-de-prueba-123')}"


CLAIMS_OK = {
    "sub": "sub-1234",
    "username": "IdentityCenter_solicitante.demo",
    "jti": "jti-5678",
    "client_id": "a" * 26,
    "email": "no-debe-pasar@example.com",
}

CLAVE = "1b4e28ba-2fa1-41d2-883f-0016d3cca427"


class _RelojFijo:
    """Sustituye a `servidor.datetime`: `now()` devuelve siempre el mismo instante."""

    @staticmethod
    def now(tz=None):
        return datetime(2026, 10, 26, 23, 59, 59, tzinfo=timezone.utc)


PATRON_ID = r"^req-\d{8}-[0-9a-f]{8}$"


def _payload(**extra) -> dict:
    base = {
        "clave_envio": CLAVE,
        "campos": {
            "servicio": "s3",
            "recurso": "finanzas-2026",
            "tipo_acceso": "lectura",
            "region": "us-east-1",
        },
        "horas": 4,
        "correo_aviso": "solicitante.demo@example.com",
        "justificacion": "Necesito leer los informes del cierre.",
    }
    base.update(extra)
    return base


def _con_token(claims=CLAIMS_OK, **kw) -> _Contexto:
    """Un contexto con `Authorization: Bearer <jwt>` de esos claims."""
    return _Contexto(request_headers={"Authorization": f"Bearer {_jwt(claims)}"}, **kw)


@pytest.fixture
def sin_efectos(monkeypatch):
    """Corta las dos salidas reales: el modelo y el almacen."""
    guardados = []
    monkeypatch.setattr(
        servidor.almacen,
        "guardar_propuesta",
        lambda r: guardados.append(r) or "dynamodb://tabla/req-web",
    )
    return guardados


# ---------------------------------------------------------------------------
# El contrato del SDK que no da error al incumplirse
# ---------------------------------------------------------------------------


def test_el_segundo_parametro_se_llama_context():
    """`BedrockAgentCoreApp._takes_context` hace `params[1] == "context"`.

    Si alguien lo renombra a `contexto` —que es lo que pide el resto de
    este codigo, escrito en espanol— el SDK decide que el handler no quiere
    contexto y lo deja a None PARA SIEMPRE, sin lanzar nada. El registro
    perderia el session_id y con el la correlacion con CloudTrail, y no
    habria ni un error que lo delatase. Este test es la unica senal.
    """
    parametros = list(inspect.signature(servidor.manejar).parameters)
    assert parametros[1] == "context"


# ---------------------------------------------------------------------------
# La forma invalida se corta antes de que nada la interprete
# ---------------------------------------------------------------------------


def test_forma_invalida_no_llega_al_modelo_ni_al_almacen(monkeypatch, sin_efectos):
    def explota(*a, **k):
        raise AssertionError("no se debe invocar al modelo con forma invalida")

    monkeypatch.setattr(servidor, "procesar", explota)

    # `recurso` con espacios y comillas: el alfabeto cerrado de la Fase 1.
    respuesta = servidor.manejar(
        _payload(campos={**_payload()["campos"], "recurso": 'no "valido" con espacios'}),
        _Contexto(),
    )

    assert respuesta["resultado"] == "error"
    assert respuesta["codigo"] == "forma_invalida"
    assert any("recurso" in d["campo"] for d in respuesta["detalle"])
    assert sin_efectos == []  # equivalente del exit 2: no deja registro


def test_el_detalle_nombra_los_campos_para_poder_corregir(sin_efectos):
    respuesta = servidor.manejar({}, _Contexto())
    campos = {d["campo"] for d in respuesta["detalle"]}
    assert {"horas", "correo_aviso", "clave_envio", "campos", "justificacion"} <= campos


@pytest.mark.parametrize(
    "extra, campo",
    [
        (
            {"principal_arn_declarado": "arn:aws:iam::111122223333:user/otra.persona"},
            "principal_arn_declarado",
        ),
        ({"solicitud_id": "req-elegido-por-mi"}, "solicitud_id"),
        ({"persona": {"usuario": "otra.persona", "sub": "sub-ajeno"}}, "persona"),
    ],
)
def test_el_arn_declarado_y_el_id_se_rechazan_por_forma(
    extra, campo, monkeypatch, sin_efectos
):
    """Nadie elige beneficiario ni id: el ARN, el id y la persona del cuerpo
    son campos extra y la forma los rechaza, con token valido y todo."""

    def explota(*a, **k):
        raise AssertionError("no se debe invocar al modelo con forma invalida")

    monkeypatch.setattr(servidor, "procesar", explota)

    respuesta = servidor.manejar(_payload(**extra), _con_token())

    assert respuesta["resultado"] == "error"
    assert respuesta["codigo"] == "forma_invalida"
    assert campo in {d["campo"] for d in respuesta["detalle"]}
    assert sin_efectos == []


# ---------------------------------------------------------------------------
# El camino normal
# ---------------------------------------------------------------------------


def test_una_solicitud_valida_se_procesa_y_se_guarda(monkeypatch, sin_efectos):
    monkeypatch.setattr(
        servidor,
        "procesar",
        lambda sol: {"id": sol.solicitud_id, "estado": "propuesta", "intentos": 1},
    )

    respuesta = servidor.manejar(_payload(), _con_token())

    assert respuesta["resultado"] == "procesada"
    assert respuesta["registro"]["estado"] == "propuesta"
    assert respuesta["guardado_en"] == "dynamodb://tabla/req-web"
    assert len(sin_efectos) == 1


def test_sin_jwt_no_hay_persona_ni_registro_ni_modelo(monkeypatch, sin_efectos):
    """ADR-003 B2 llevado al final: con SigV4 no hay JWT, luego no hay persona
    verificada, y sin persona ya no se guarda un registro que la aprobacion
    bloquee: la solicitud no entra."""

    def explota(*a, **k):
        raise AssertionError("sin persona no se invoca al modelo")

    monkeypatch.setattr(servidor, "procesar", explota)

    respuesta = servidor.manejar(_payload(), _Contexto(session_id="sesion-" + "x" * 27))

    assert respuesta["resultado"] == "error"
    assert respuesta["codigo"] == "sin_persona"
    assert respuesta["detalle"] == servidor.SIN_JWT
    assert "sin JWT" in respuesta["detalle"]
    assert sin_efectos == []


# ---------------------------------------------------------------------------
# Con JWT: la persona sale de los claims que el autorizador ya valido
# ---------------------------------------------------------------------------


@pytest.fixture
def procesar_falso(monkeypatch):
    monkeypatch.setattr(
        servidor, "procesar", lambda sol: {"id": sol.solicitud_id, "estado": "propuesta"}
    )


def test_con_jwt_el_registro_lleva_la_persona_y_quien_invoco(procesar_falso, sin_efectos):
    token = _jwt(CLAIMS_OK)
    contexto = _Contexto(
        session_id="sesion-" + "y" * 27,
        request_headers={"Authorization": f"Bearer {token}"},
    )

    resultado = servidor.manejar(_payload(), contexto)

    registro = sin_efectos[0]
    assert registro["solicitante"]["persona"] == "solicitante.demo"
    assert "autorizador de AgentCore" in registro["solicitante"]["como_se_verifico"]
    quien = registro["ejecutado_por"]
    assert quien["determinable"] is True
    assert quien["sub"] == "sub-1234"
    assert quien["usuario"] == "IdentityCenter_solicitante.demo"
    assert quien["jti"] == "jti-5678"
    assert quien["sesion_runtime"] == "sesion-" + "y" * 27
    assert quien["como_se_verifico"] == servidor.COMO_SE_VERIFICO_JWT
    # El token y los claims fuera de la lista cerrada no llegan al registro
    # ni a la respuesta: un token en un registro es una credencial guardada.
    for salida in (registro, resultado):
        volcado = json.dumps(salida)
        assert token not in volcado
        assert "no-debe-pasar@example.com" not in volcado


def test_el_client_id_se_graba_en_ejecutado_por(procesar_falso, sin_efectos):
    """El aplicador lo repite contra los clientes admitidos antes de escribir
    la confianza; para eso tiene que estar en el registro."""
    servidor.manejar(_payload(), _con_token())

    assert sin_efectos[0]["ejecutado_por"]["client_id"] == "a" * 26


def test_la_persona_del_token_llega_a_procesar_y_el_cuerpo_no_la_elige(monkeypatch, sin_efectos):
    vistas = []

    def procesar(sol):
        vistas.append(sol)
        return {"id": sol.solicitud_id, "estado": "propuesta"}

    monkeypatch.setattr(servidor, "procesar", procesar)

    servidor.manejar(_payload(), _con_token())

    sol = vistas[0]
    assert isinstance(sol, SolicitudEstructurada)
    assert sol.modo == "rol_por_persona"
    assert sol.principal_arn_declarado is None
    assert (sol.persona.usuario, sol.persona.sub, sol.persona.client_id) == (
        "solicitante.demo",
        "sub-1234",
        "a" * 26,
    )
    assert (sol.horas, sol.correo_aviso, sol.clave_envio) == (
        4,
        "solicitante.demo@example.com",
        CLAVE,
    )


def test_la_cabecera_authorization_en_minusculas_tambien_vale(procesar_falso, sin_efectos):
    contexto = _Contexto(request_headers={"authorization": f"bearer {_jwt(CLAIMS_OK)}"})

    servidor.manejar(_payload(), contexto)

    assert sin_efectos[0]["solicitante"]["persona"] == "solicitante.demo"
    assert sin_efectos[0]["ejecutado_por"]["determinable"] is True


def test_sin_cabecera_no_hay_persona_y_se_nombra_el_jwt_ausente(procesar_falso, sin_efectos):
    for cabeceras in (None, {}, {"X-Otra": "cosa"}):
        respuesta = servidor.manejar(_payload(), _Contexto(request_headers=cabeceras))

        assert respuesta["codigo"] == "sin_persona"
        assert respuesta["detalle"] == servidor.SIN_JWT
        assert "sin JWT" in respuesta["detalle"]
    assert sin_efectos == []


@pytest.mark.parametrize(
    "valor",
    [
        "Basic dXNlcjpwYXNz",  # no es Bearer
        _jwt(CLAIMS_OK),  # token sin el prefijo Bearer
        "Bearer aaa.bbb",  # dos partes
        "Bearer aaa.bbb.ccc.ddd",  # cuatro partes
        "Bearer " + ".".join(["aaa", "bm8gZXMganNvbg", "ccc"]),  # carga que no es JSON
        "Bearer " + ".".join(["aaa", "WzEsMl0", "ccc"]),  # JSON que no es objeto
        "Bearer aaa.%%%.ccc",  # base64 invalido
        "Bearer",  # sin token
    ],
)
def test_una_cabecera_que_no_es_un_jwt_cuenta_como_sin_cabecera(
    valor, procesar_falso, sin_efectos
):
    respuesta = servidor.manejar(_payload(), _Contexto(request_headers={"Authorization": valor}))

    assert respuesta["codigo"] == "sin_persona"
    assert respuesta["detalle"] == servidor.SIN_JWT
    assert sin_efectos == []


def test_una_cabecera_que_no_es_texto_cuenta_como_sin_cabecera(procesar_falso, sin_efectos):
    respuesta = servidor.manejar(_payload(), _Contexto(request_headers={"Authorization": 12345}))

    assert respuesta["codigo"] == "sin_persona"
    assert respuesta["detalle"] == servidor.SIN_JWT
    assert sin_efectos == []


def test_username_sin_el_prefijo_de_identity_center_no_da_persona(procesar_falso, sin_efectos):
    respuesta = servidor.manejar(
        _payload(), _con_token({**CLAIMS_OK, "username": "solicitante.demo"})
    )

    assert respuesta["codigo"] == "sin_persona"
    assert respuesta["detalle"] == servidor.USERNAME_SIN_PREFIJO
    assert servidor.PREFIJO_USERNAME in respuesta["detalle"]
    assert sin_efectos == []


def test_jwt_sin_claim_username_no_da_persona(procesar_falso, sin_efectos):
    carga = {k: v for k, v in CLAIMS_OK.items() if k != "username"}

    respuesta = servidor.manejar(_payload(), _con_token(carga))

    assert respuesta["codigo"] == "sin_persona"
    assert respuesta["detalle"] == servidor.SIN_USERNAME
    assert "username" in respuesta["detalle"]
    assert sin_efectos == []


@pytest.mark.parametrize("sub", [None, "", 123, ["x"]])
def test_sin_sub_o_sin_persona_no_hay_registro_ni_modelo(sub, monkeypatch, sin_efectos):
    """Sin beneficiario atribuible ninguna entrada llega al modelo ni deja
    registro. Sin `sub` la confianza del rol no tiene a quien atarse."""

    def explota(*a, **k):
        raise AssertionError("sin persona o sin sub no se invoca al modelo")

    monkeypatch.setattr(servidor, "procesar", explota)

    # Sin `sub` (ausente, o un valor que no es texto no vacio).
    carga = {k: v for k, v in CLAIMS_OK.items() if k != "sub"}
    if sub is not None:
        carga["sub"] = sub
    respuesta = servidor.manejar(_payload(), _con_token(carga))
    assert respuesta["resultado"] == "error"
    assert respuesta["codigo"] == "sin_persona"
    assert respuesta["detalle"] == servidor.SIN_SUB

    # Sin persona (username sin el prefijo), con `sub` correcto.
    respuesta = servidor.manejar(_payload(), _con_token({**CLAIMS_OK, "username": "otra"}))
    assert respuesta["codigo"] == "sin_persona"
    assert respuesta["detalle"] == servidor.USERNAME_SIN_PREFIJO

    # Sin token.
    assert servidor.manejar(_payload(), _Contexto())["codigo"] == "sin_persona"
    assert sin_efectos == []


def test_un_sub_con_forma_rara_responde_sin_persona_con_el_detalle(monkeypatch, sin_efectos):
    """El `sub` es texto no vacio pero no cabe en `PersonaDelToken` (alfabeto
    cerrado): el servidor responde `sin_persona` en vez de dejar subir la
    excepcion, y no repite el valor en el detalle."""

    def explota(*a, **k):
        raise AssertionError("una persona invalida no llega al modelo")

    monkeypatch.setattr(servidor, "procesar", explota)

    respuesta = servidor.manejar(_payload(), _con_token({**CLAIMS_OK, "sub": "con espacios!"}))

    assert respuesta["resultado"] == "error"
    assert respuesta["codigo"] == "sin_persona"
    assert servidor.PERSONA_INVALIDA in respuesta["detalle"]
    assert "sub:" in respuesta["detalle"]
    assert "con espacios!" not in respuesta["detalle"]
    assert sin_efectos == []


def test_un_token_sin_jti_graba_none_en_jti_y_el_resto_se_conserva(procesar_falso, sin_efectos):
    carga = {k: v for k, v in CLAIMS_OK.items() if k != "jti"}

    servidor.manejar(_payload(), _con_token(carga))

    quien = sin_efectos[0]["ejecutado_por"]
    assert quien["jti"] is None
    assert quien["sub"] == "sub-1234"
    assert quien["usuario"] == "IdentityCenter_solicitante.demo"
    assert sin_efectos[0]["solicitante"]["persona"] == "solicitante.demo"


def test_claims_validados_solo_devuelve_la_lista_cerrada():
    contexto = _Contexto(request_headers={"Authorization": f"Bearer {_jwt(CLAIMS_OK)}"})

    assert servidor.claims_validados(contexto) == {
        "sub": "sub-1234",
        "username": "IdentityCenter_solicitante.demo",
        "jti": "jti-5678",
        "client_id": "a" * 26,
    }
    assert servidor.claims_validados(None) is None
    assert servidor.claims_validados(object()) is None  # sin atributo request_headers


def test_persona_de_quita_el_prefijo_y_no_normaliza():
    assert servidor.persona_de({"username": "IdentityCenter_Solicitante.Demo"}) == "Solicitante.Demo"
    assert servidor.persona_de({"username": "otra_cosa"}) is None
    assert servidor.persona_de({"sub": "x"}) is None
    assert servidor.persona_de(None) is None


def test_persona_de_no_devuelve_una_persona_vacia_ni_de_un_username_que_no_es_cadena():
    """Un prefijo sin nada detras, o un username que no es str, no es una
    persona: el registro no debe anotar CON_PERSONA con una persona vacia."""
    assert servidor.persona_de({"username": "IdentityCenter_"}) is None
    for raro in (None, 123, ["IdentityCenter_x"], {"a": "b"}):
        assert servidor.persona_de({"username": raro}) is None


def test_el_token_no_se_escribe_en_el_log(procesar_falso, sin_efectos, caplog):
    token = _jwt(CLAIMS_OK)
    contexto = _Contexto(request_headers={"Authorization": f"Bearer {token}"})

    with caplog.at_level("DEBUG", logger="agente-iam"):
        servidor.manejar(_payload(), contexto)

    assert token not in caplog.text
    assert "persona=solicitante.demo" in caplog.text


def test_un_registro_de_error_tambien_se_guarda(monkeypatch, sin_efectos):
    """Fase 4 vista desde HTTP: `procesar` no lanza, devuelve estado
    'error'. Ese registro se guarda igual, porque justo las corridas que
    fallan son las que mas necesitan auditarse."""
    monkeypatch.setattr(
        servidor,
        "procesar",
        lambda sol: {"id": sol.solicitud_id, "estado": "error", "error": {"fase": "agente"}},
    )

    respuesta = servidor.manejar(_payload(), _con_token())

    assert respuesta["resultado"] == "procesada"
    assert respuesta["registro"]["estado"] == "error"
    assert respuesta["rol_previsto"] is None  # el registro de error no trae identidad
    assert len(sin_efectos) == 1


def test_la_respuesta_lleva_el_id_y_el_rol_previsto(monkeypatch, sin_efectos):
    """La pagina ensena a la persona el id de su solicitud y el rol que se
    creara para ella: salen de la respuesta, no del cuerpo que envio."""
    rol = "arn:aws:iam::111122223333:role/agente-iam/personas/agente-iam-persona-x-req"
    monkeypatch.setattr(
        servidor,
        "procesar",
        lambda sol: {
            "id": sol.solicitud_id,
            "estado": "propuesta",
            "identidad_verificada": {"principal_arn": rol},
        },
    )

    respuesta = servidor.manejar(_payload(), _con_token())

    assert respuesta["resultado"] == "procesada"
    assert re.fullmatch(PATRON_ID, respuesta["solicitud_id"])
    assert respuesta["solicitud_id"] == respuesta["registro"]["id"]
    assert respuesta["rol_previsto"] == rol


def test_el_id_lo_forma_el_servidor_desde_la_clave_y_se_repite(monkeypatch, tmp_path):
    """Doble clic o reintento: la misma `clave_envio` da el mismo id, y la
    segunda llamada cae en `registro_existente` con ese id. Se usa el almacen
    en disco de verdad, no un doble: lo que se prueba es el cierre entre el id
    determinista y la creacion exclusiva del fichero.

    La hora se fija: el id lleva la fecha UTC, y sin fijarla el test fallaria
    si las dos llamadas cruzaran las 00:00 UTC."""
    monkeypatch.setattr(servidor, "datetime", _RelojFijo)
    monkeypatch.setattr(almacen, "ALMACEN", "disco")
    monkeypatch.setattr(almacen, "DIR_SOLICITUDES", str(tmp_path))
    monkeypatch.setattr(
        servidor, "procesar", lambda sol: {"id": sol.solicitud_id, "estado": "propuesta"}
    )

    primera = servidor.manejar(_payload(), _con_token())
    segunda = servidor.manejar(_payload(), _con_token())

    assert primera["resultado"] == "procesada"
    assert re.fullmatch(PATRON_ID, primera["solicitud_id"])
    assert segunda["resultado"] == "error"
    assert segunda["codigo"] == "registro_existente"
    assert segunda["id"] == primera["solicitud_id"]
    assert [f.name for f in tmp_path.iterdir()] == [f"{primera['solicitud_id']}.json"]

    # Otra clave, otro id: la clave es lo unico que decide el id.
    otra = servidor.manejar(
        _payload(clave_envio="2c5f39cb-3ab2-42e2-994a-1127e4dda538"), _con_token()
    )
    assert otra["resultado"] == "procesada"
    assert otra["solicitud_id"] != primera["solicitud_id"]


# ---------------------------------------------------------------------------
# El client_id es obligatorio: la confianza del rol lleva el `aud` del cliente
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "client_id", [None, "", "A" * 26, "a" * 25, "a" * 27, "a-" * 13, 12345, ["a" * 26]]
)
def test_sin_client_id_valido_no_hay_registro_ni_modelo(client_id, monkeypatch, sin_efectos):
    """Sin `client_id` la solicitud se aprobaria pero nunca podria aplicarse
    (la confianza del rol lleva el `aud` del cliente): no entra."""

    def explota(*a, **k):
        raise AssertionError("sin client_id no se invoca al modelo")

    monkeypatch.setattr(servidor, "procesar", explota)
    carga = {k: v for k, v in CLAIMS_OK.items() if k != "client_id"}
    if client_id is not None:
        carga["client_id"] = client_id

    respuesta = servidor.manejar(_payload(), _con_token(carga))

    assert respuesta["resultado"] == "error"
    assert respuesta["codigo"] == "sin_persona"
    assert respuesta["detalle"] == servidor.SIN_CLIENT_ID
    assert "client_id" in respuesta["detalle"]
    assert sin_efectos == []


def test_como_se_verifico_nombra_el_client_ausente():
    claims = {k: v for k, v in CLAIMS_OK.items() if k != "client_id"}
    assert servidor._como_se_verifico_solicitante(claims, "solicitante.demo") == servidor.SIN_CLIENT_ID
    assert servidor._como_se_verifico_solicitante(CLAIMS_OK, "solicitante.demo") == servidor.CON_PERSONA


# ---------------------------------------------------------------------------
# La respuesta al navegador es una vista publica, no el registro entero
# ---------------------------------------------------------------------------

_REGISTRO_COMPLETO = {
    "id": "req-20261026-0123abcd",
    "creada": "2026-10-26T10:00:00+00:00",
    "estado": "propuesta",
    "intentos": 2,
    "uso_modelo": {"modelo": "m", "tokens_entrada": 1, "tokens_salida": 2, "latencia_ms": 3},
    "solicitud": {
        "solicitud_id": "req-20261026-0123abcd",
        "justificacion": "Necesito leer los informes del cierre.",
        "horas": 4,
        "correo_aviso": "solicitante.demo@example.com",
        "persona": {"usuario": "solicitante.demo", "sub": "sub-1234", "client_id": "a" * 26},
    },
    "identidad_verificada": {
        "principal_arn": "arn:aws:iam::111122223333:role/agente-iam/personas/x",
        "principal_id": "AROAXXXX",
    },
    "motivos": ["uno"],
    "acceso_nuevo": {"es_totalmente_redundante": False},
    "propuesta": {"statements": []},
    "exige_confirmacion_de_riesgo": True,
    "riesgo_minimo": ["x"],
    "validacion": {"ok": True},
    "historial_validacion": [{"intento": 1}],
    "ejecutado_por": {"jti": "jti-5678", "sub": "sub-1234"},
}

# Claves que no pueden aparecer en NINGUN nivel de la respuesta, y textos que
# no pueden aparecer en ningun valor. Se miran las claves y no el volcado en
# bruto porque `estado: "propuesta"` es un valor legitimo.
_CLAVES_PROHIBIDAS = (
    "traza", "historial_validacion", "propuesta", "ejecutado_por", "jti", "justificacion",
    "uso_modelo", "validacion", "riesgo_minimo", "identidad_verificada", "solicitud", "detalle",
)
_TEXTOS_PROHIBIDOS = ("Necesito leer", "jti-5678", "AROAXXXX")


def _claves_de(obj) -> set[str]:
    """Todas las claves de dict, a cualquier profundidad."""
    if isinstance(obj, dict):
        return set(obj) | {k for v in obj.values() for k in _claves_de(v)}
    if isinstance(obj, list):
        return {k for v in obj for k in _claves_de(v)}
    return set()


def _sin_lo_prohibido(respuesta: dict, textos_extra: tuple = ()) -> None:
    assert _claves_de(respuesta["registro"]) & set(_CLAVES_PROHIBIDAS) == set()
    volcado = json.dumps(respuesta)
    for texto in _TEXTOS_PROHIBIDOS + textos_extra:
        assert texto not in volcado, texto


def test_vista_publica_tiene_exactamente_estas_claves():
    vista = servidor.vista_publica(_REGISTRO_COMPLETO | {"solicitante": {"persona": "solicitante.demo"}})

    assert vista == {
        "id": "req-20261026-0123abcd",
        "estado": "propuesta",
        "creada": "2026-10-26T10:00:00+00:00",
        "motivos": ["uno"],
        "solicitante": {"persona": "solicitante.demo"},
        "exige_confirmacion_de_riesgo": True,
        "acceso_nuevo": {"es_totalmente_redundante": False},
        "rol_previsto": "arn:aws:iam::111122223333:role/agente-iam/personas/x",
        "horas": 4,
        "correo_aviso": "solicitante.demo@example.com",
        "motivo": {"codigo": "confirmar_riesgo", "texto": "El aprobador tendra que confirmar el riesgo."},
    }


def test_vista_publica_omite_motivos_y_acceso_nuevo_si_no_hay_y_tolera_un_registro_pobre():
    vista = servidor.vista_publica({"id": "req-1", "estado": "error", "error": {"fase": "agente"}})

    assert "motivos" not in vista
    assert "acceso_nuevo" not in vista
    assert vista["rol_previsto"] is None
    assert vista["horas"] is None
    assert vista["error"] == {"fase": "agente", "tipo": None}


def test_vista_publica_de_un_error_lleva_fase_y_tipo_pero_no_detalle_ni_traza():
    registro = {
        **_REGISTRO_COMPLETO,
        "estado": "error",
        "error": {
            "fase": "agente",
            "tipo": "ValueError",
            "detalle": "arn:aws:iam::111122223333:role/interno dijo no",
            "traza": "Traceback (most recent call last): ...",
        },
    }

    vista = servidor.vista_publica(registro)

    assert vista["error"] == {"fase": "agente", "tipo": "ValueError"}
    volcado = json.dumps(vista)
    assert "interno" not in volcado
    assert "Traceback" not in volcado


def test_la_respuesta_no_devuelve_el_registro_entero(monkeypatch, sin_efectos):
    """La ve cualquier persona con token desde la web; el registro completo
    vive en la tabla, con su control de acceso."""
    monkeypatch.setattr(
        servidor, "procesar", lambda sol: {**_REGISTRO_COMPLETO, "id": sol.solicitud_id}
    )

    respuesta = servidor.manejar(_payload(), _con_token())

    assert respuesta["resultado"] == "procesada"
    _sin_lo_prohibido(respuesta)
    vista = respuesta["registro"]
    assert vista["id"] == respuesta["solicitud_id"]
    assert vista["estado"] == "propuesta"
    assert vista["rol_previsto"] == respuesta["rol_previsto"]
    assert vista["solicitante"]["persona"] == "solicitante.demo"
    # El registro que se guarda sigue siendo el entero.
    assert "historial_validacion" in sin_efectos[0]
    assert "ejecutado_por" in sin_efectos[0]


def test_la_respuesta_de_un_registro_de_error_tampoco_filtra_detalle_ni_traza(
    monkeypatch, sin_efectos
):
    monkeypatch.setattr(
        servidor,
        "procesar",
        lambda sol: {
            "id": sol.solicitud_id,
            "estado": "error",
            "propuesta": {"statements": []},
            "historial_validacion": [{"intento": 1}],
            "error": {"fase": "agente", "tipo": "KeyError", "detalle": "secreto", "traza": "Traceback"},
        },
    )

    respuesta = servidor.manejar(_payload(), _con_token())

    _sin_lo_prohibido(respuesta, ("secreto", "Traceback"))
    assert respuesta["registro"]["error"] == {"fase": "agente", "tipo": "KeyError"}
    assert respuesta["registro"]["estado"] == "error"
    assert "traza" in sin_efectos[0]["error"]  # en la tabla si queda


# ---------------------------------------------------------------------------
# Los fallos del almacen se traducen, no se filtran
# ---------------------------------------------------------------------------


def test_no_pisar_un_registro_existente_sale_como_codigo_propio(monkeypatch):
    """Hasta el 24-10-2026 el codigo era `ya_aprobada`. Desde S6 sale con
    cualquier registro previo, y el codigo dice eso: `registro_existente`."""
    monkeypatch.setattr(
        servidor, "procesar", lambda sol: {"id": sol.solicitud_id, "estado": "propuesta"}
    )

    def ya_existe(_registro):
        raise almacen.RegistroExistente("ya existe")

    monkeypatch.setattr(servidor.almacen, "guardar_propuesta", ya_existe)

    respuesta = servidor.manejar(_payload(), _con_token())
    assert respuesta["codigo"] == "registro_existente"
    assert re.fullmatch(PATRON_ID, respuesta["id"])


# ---------------------------------------------------------------------------
# La compuerta de arranque
# ---------------------------------------------------------------------------


def test_el_servidor_se_niega_a_arrancar_con_almacen_efimero(monkeypatch):
    """El fallo que esto evita es el que NO se nota: desplegado con
    ALMACEN=disco todo parece funcionar y el registro muere con el microVM.
    Un sistema cuyo argumento es la auditabilidad perderia su rastro entero
    sin un solo error."""
    monkeypatch.setattr(servidor, "ALMACEN", "disco")
    monkeypatch.delenv("PERMITIR_ALMACEN_EFIMERO", raising=False)

    with pytest.raises(RuntimeError, match="efimero"):
        servidor._comprobar_almacen()


def test_la_puerta_explicita_deja_arrancar_en_local(monkeypatch):
    monkeypatch.setattr(servidor, "ALMACEN", "disco")
    monkeypatch.setenv("PERMITIR_ALMACEN_EFIMERO", "si")
    servidor._comprobar_almacen()  # no lanza


def test_con_dynamodb_no_hace_falta_ninguna_puerta(monkeypatch):
    monkeypatch.setattr(servidor, "ALMACEN", "dynamodb")
    monkeypatch.delenv("PERMITIR_ALMACEN_EFIMERO", raising=False)
    servidor._comprobar_almacen()  # no lanza


def test_sin_catalogo_el_servidor_no_arranca(monkeypatch):
    """La otra compuerta, y protege del mismo tipo de fallo: sin catalogo
    el sistema NO revienta, se degrada. `excede_tipo_acceso` empieza a
    devolver 'no se pudo determinar', el orquestador lo trata como
    advertencia, y el chequeo de nivel de acceso deja de bloquear mientras
    el registro sigue afirmando que se comprobo."""
    monkeypatch.setattr(
        servidor.catalogo, "no_disponibles", lambda servicios: ["sqs", "sns"]
    )
    with pytest.raises(RuntimeError, match="sqs, sns"):
        servidor._comprobar_catalogo()


def test_con_el_catalogo_completo_arranca(monkeypatch):
    monkeypatch.setattr(servidor.catalogo, "no_disponibles", lambda servicios: [])
    servidor._comprobar_catalogo()  # no lanza


# ---------------------------------------------------------------------------
# El catalogo en un directorio de SOLO LECTURA, que es el caso del paquete
# desplegado. Antes de esto, `_cargar` hacia mkdir+write en el camino
# critico y un directorio no escribible apagaba el chequeo de nivel.
# ---------------------------------------------------------------------------


def test_el_catalogo_se_lee_de_un_directorio_no_escribible(tmp_path, monkeypatch):
    from agente_iam.herramientas import catalogo

    cache = tmp_path / "servicereference"
    cache.mkdir()
    (cache / "fakesvc.json").write_text(
        json.dumps(
            {
                "Actions": [
                    {
                        "Name": "PutThing",
                        "Resources": [],
                        "Annotations": {"Properties": {"IsWrite": True}},
                    }
                ]
            }
        )
    )
    cache.chmod(0o555)  # solo lectura, como en /var/task
    monkeypatch.setattr(catalogo, "_CACHE", cache)
    monkeypatch.setattr(catalogo, "_MEMORIA", {})

    try:
        # Se carga sin intentar escribir, y el chequeo de nivel SIGUE
        # bloqueando: es justo lo que se apagaba antes.
        assert catalogo.excede_tipo_acceso("fakesvc:PutThing", "lectura") is True
        assert catalogo.no_disponibles(["fakesvc"]) == []
    finally:
        cache.chmod(0o755)  # para que pytest pueda limpiar tmp_path


def test_un_servicio_que_no_esta_ni_se_puede_bajar_se_reporta(tmp_path, monkeypatch):
    from agente_iam.herramientas import catalogo

    def sin_red(*a, **k):
        raise OSError("sin red")

    monkeypatch.setattr(catalogo, "_CACHE", tmp_path)
    monkeypatch.setattr(catalogo, "_MEMORIA", {})
    monkeypatch.setattr(catalogo.urllib.request, "urlopen", sin_red)

    assert catalogo.no_disponibles(["fakesvc"]) == ["fakesvc"]
