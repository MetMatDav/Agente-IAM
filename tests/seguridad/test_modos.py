"""Un modo en produccion, dos en el repositorio (diseno de la Fase 23, 5.5).

`SolicitudEstructurada` tiene dos modos: `rol_por_persona` (el del servidor,
con el beneficiario sacado del JWT) y `principal_existente` (el del CLI de
desarrollo, que adjunta a un ARN declarado). El segundo existe porque el
corpus de `ejemplos/` y las mediciones M.4 y M.5 lo usan, pero en produccion
NADIE puede declarar un ARN ni un beneficiario: eso seria elegir a quien se
le da el permiso sin pasar por el token. Estos tests fijan las fronteras
entre los dos modos y lo que cierra el resto de rutas (lista negra, recursos
del sistema, techo de los roles de persona).

Sin red: nada de esto llama a AWS.
"""

import json
from pathlib import Path

import pytest

from agente_iam import cli, coherencia, servidor
from agente_iam.coherencia import chequeos_posteriores
from agente_iam.config import ACCIONES_PROHIBIDAS
from tests.dobles import _propuesta, _solicitud

_RAIZ = Path(__file__).resolve().parents[2]
_TECHO = _RAIZ / "infra" / "boundary-agente-iam-techo.json"

_ARN_ANA = "arn:aws:iam::111122223333:user/ana.gomez"


class _Contexto:
    """Lo minimo de un contexto de AgentCore; la forma se valida antes de leerlo."""

    session_id = "sesion-" + "x" * 27
    request_headers: dict = {}


def _payload_web(**cambios) -> dict:
    base = {
        "solicitud_id": "req-20261026-ab12cd34",
        "campos": {
            "servicio": "s3", "recurso": "finanzas-demo-111122223333",
            "tipo_acceso": "lectura", "region": "us-east-1",
        },
        "justificacion": "prueba",
    }
    base.update(cambios)
    return base


@pytest.fixture
def nada_se_procesa(monkeypatch):
    """Una forma invalida no llega al orquestador ni deja registro."""
    def bomba(*a, **k):
        raise AssertionError("una forma invalida no debe procesarse")

    monkeypatch.setattr(servidor, "procesar", bomba)


def _campos_rechazados(respuesta: dict) -> set[str]:
    assert respuesta["resultado"] == "error"
    assert respuesta["codigo"] == "forma_invalida"
    return {d["campo"] for d in respuesta["detalle"]}


def test_el_servidor_rechaza_el_arn_declarado_por_forma(nada_se_procesa):
    """Quien llama al servidor no elige el principal: el campo ni existe."""
    respuesta = servidor.manejar(_payload_web(principal_arn_declarado=_ARN_ANA), _Contexto())
    assert "principal_arn_declarado" in _campos_rechazados(respuesta)


def test_el_servidor_nunca_toma_el_beneficiario_del_payload(nada_se_procesa):
    """`persona` sale del JWT; si viene en el payload, la forma no vale."""
    persona = {"usuario": "otra.persona", "sub": "sub-ajeno", "client_id": "a" * 26}
    respuesta = servidor.manejar(_payload_web(persona=persona, horas=4), _Contexto())
    assert any(c.startswith("persona") for c in _campos_rechazados(respuesta))


def test_el_cli_no_tramita_el_modo_del_servidor(tmp_path, monkeypatch, capsys):
    """El CLI no tiene token, asi que un fichero con `persona` sale con 2 sin procesar."""
    def no_debe_llamarse(*a, **k):
        raise AssertionError("el CLI no debe procesar el modo del servidor")

    monkeypatch.setattr(cli, "procesar", no_debe_llamarse)
    monkeypatch.setattr(cli, "guardar_propuesta", no_debe_llamarse)
    ruta = tmp_path / "persona.json"
    ruta.write_text(json.dumps(_payload_web(
        persona={"usuario": "solicitante.demo", "sub": "sub-1234", "client_id": "a" * 26},
        horas=4,
    )))
    monkeypatch.setattr("sys.argv", ["cli", str(ruta)])
    with pytest.raises(SystemExit) as salida:
        cli.main()
    assert salida.value.code == 2
    assert "principal_arn_declarado" in capsys.readouterr().out


@pytest.mark.parametrize("recurso", [
    # La ruta de los roles por persona.
    "arn:aws:iam::111122223333:role/agente-iam/personas/x",
    # Un rol de persona con el nombre real (prefijo `agente-iam-persona-`).
    "arn:aws:iam::111122223333:role/agente-iam/personas/agente-iam-persona-x-req-1",
])
def test_una_propuesta_sobre_la_ruta_de_personas_se_bloquea(recurso, monkeypatch):
    """Los roles por persona viven en /agente-iam/personas/: son del sistema.

    Lo frena el prefijo del sistema (`PREFIJOS_DEL_SISTEMA`: "agente-iam",
    "agente_iam", "agenteiam"), que se busca en cada trozo del ARN separado por
    `:` y `/`. Como la ruta entera empieza por `agente-iam`, cubre tanto el
    directorio como cualquier nombre de rol dentro de el; no hay una regla
    aparte para "personas".
    """
    # Sin cache del catalogo (el CI) el nivel de acceso saldria a internet.
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: False)
    propuesta = _propuesta(recursos=[recurso])
    identidad = {"principal_arn": _ARN_ANA, "cuenta": "111122223333"}
    bloqueos, _ = chequeos_posteriores(propuesta, _solicitud(), identidad)
    # Tambien salta el bloqueo de servicio (la propuesta es de s3 y el recurso
    # de iam); aqui importa que el del sistema este.
    assert any("recurso del propio sistema" in b for b in bloqueos)


@pytest.mark.parametrize("accion", [
    "sts:AssumeRole",
    "sts:AssumeRoleWithSAML",
    "sts:AssumeRoleWithWebIdentity",
    "sts:GetFederationToken",
])
def test_la_lista_negra_cierra_toda_asuncion_de_roles(accion):
    assert accion in ACCIONES_PROHIBIDAS


# Lo unico de IAM que el techo concede, y por que es inocuo: el autoservicio
# del usuario sobre SI MISMO (lectura de su usuario, de la politica de
# contrasenas y de sus MFA, y cambiar su contrasena). Ninguna escribe roles,
# politicas ni confianza. Si el techo gana otra accion `iam:*`, este test
# falla y hay que decidirlo a proposito. Medido en el JSON del 26-10-2026.
_IAM_PERMITIDO_EN_EL_TECHO = {
    "iam:ChangePassword",
    "iam:GetUser",
    "iam:GetAccountPasswordPolicy",
    "iam:ListMFADevices",
}


def _acciones_allow_del_techo() -> list[tuple[str, str]]:
    techo = json.loads(_TECHO.read_text())
    salida = []
    for st in techo["Statement"]:
        if st["Effect"] != "Allow":
            continue
        assert "NotAction" not in st, f"{st.get('Sid')}: un Allow con NotAction concede todo lo demas"
        acciones = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
        salida.extend((st.get("Sid", "?"), a) for a in acciones)
    return salida


def test_el_techo_no_deja_a_un_rol_de_persona_tocar_roles_ni_asumir_otros():
    """Un rol de persona tiene el techo como boundary: ni iam de escritura ni sts:AssumeRole*."""
    acciones = _acciones_allow_del_techo()
    assert acciones, "el techo no concede nada: el test no mira lo que debe"

    iam = {a for _, a in acciones if a.lower().startswith("iam:")}
    assert iam <= _IAM_PERMITIDO_EN_EL_TECHO, f"iam inesperado en el techo: {sorted(iam - _IAM_PERMITIDO_EN_EL_TECHO)}"
    # Los comodines de servicio o de prefijo tambien cubririan PassRole y CreateRole.
    assert not any(a in ("*", "iam:*", "sts:*") for _, a in acciones)

    for sid, accion in acciones:
        minus = accion.lower()
        assert minus != "iam:passrole", f"{sid}: {accion}"
        assert not minus.startswith("sts:assumerole"), f"{sid}: {accion}"
        assert minus not in ("sts:getfederationtoken", "sts:*"), f"{sid}: {accion}"
