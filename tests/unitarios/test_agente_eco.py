"""El agente eco de las pruebas de AgentCore (`infra/pruebas-agentcore/`).

No es parte del sistema, pero se despliega en una cuenta real, asi que
vale lo de siempre: lo que no se ha ejecutado no funciona. Se arranca como
lo haria AgentCore (un proceso que escucha HTTP) y se comprueba el
contrato (`/ping`, `/invocations`) y las dos promesas de su docstring:
devuelve los claims y nunca el token.
"""

import base64
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

_ECO = Path(__file__).resolve().parents[2] / "infra" / "pruebas-agentcore" / "agente_eco.py"


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


def _jwt_falso(carga: dict) -> str:
    return f"{_b64({'alg': 'RS256', 'kid': 'x'})}.{_b64(carga)}.firma-que-nadie-verifica"


def _puerto_libre() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def eco():
    puerto = _puerto_libre()
    # Sin credenciales ni metadatos: GetCallerIdentity debe fallar rapido y
    # el eco debe seguir contestando.
    entorno = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    entorno |= {
        "PUERTO": str(puerto),
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_DEFAULT_REGION": "us-east-1",
    }
    proceso = subprocess.Popen([sys.executable, str(_ECO)], env=entorno)
    base = f"http://127.0.0.1:{puerto}"
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{base}/ping", timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("el eco no arranco")
        yield base
    finally:
        proceso.terminate()
        proceso.wait(timeout=5)


def _invocar(base: str, cabeceras: dict) -> dict:
    peticion = urllib.request.Request(
        f"{base}/invocations",
        data=json.dumps({"prompt": "hola"}).encode(),
        headers={"Content-Type": "application/json", **cabeceras},
        method="POST",
    )
    with urllib.request.urlopen(peticion, timeout=10) as r:
        return json.loads(r.read())


def test_ping_cumple_el_contrato(eco):
    with urllib.request.urlopen(f"{eco}/ping", timeout=2) as r:
        assert r.status == 200
        assert json.loads(r.read())["status"] == "Healthy"


def test_devuelve_los_claims_y_nunca_el_token(eco):
    token = _jwt_falso({
        "sub": "abc-123", "username": "identitycenter_ana", "client_id": "cliente1",
        "token_use": "access", "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Ejemplo",
        "secreto_que_no_debe_salir": "x",
    })
    r = _invocar(eco, {"Authorization": f"Bearer {token}"})
    assert r["claims"]["username"] == "identitycenter_ana"
    assert r["claims"]["client_id"] == "cliente1"
    assert "secreto_que_no_debe_salir" not in r["claims"]
    assert token not in json.dumps(r)
    assert r["payload_recibido"] == {"prompt": "hola"}


def test_un_token_que_no_es_jwt_se_describe_sin_romper(eco):
    r = _invocar(eco, {"Authorization": "Bearer aoaOpacoSinPuntos"})
    assert r["claims"] == {"_formato": "no es un JWT: 1 partes"}


def test_sin_cabecera_ni_credenciales_contesta_igual(eco):
    r = _invocar(eco, {})
    assert r["claims"] is None
    assert r["cabecera_authorization_presente"] is False
    # Sin credenciales (la fixture las quita) informa el error y sigue.
    assert "error" in r["identidad_aws"]
