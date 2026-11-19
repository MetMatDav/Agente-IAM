"""scripts/prueba_b.py: las piezas puras de la Prueba B, sin red.

El script maneja un token de acceso real. Estos tests fijan lo que no puede
fallar en silencio: el PKCE (si el challenge no corresponde al verifier,
Cognito rechaza el canje), el enlace (que mande directo a Identity Center
con S256 y state, y sin secreto), la firma alterada (que de verdad cambie),
y que el token se guarde con permisos 600 y no aparezca en lo que se
imprime.
"""

import base64
import importlib.util
import json
import stat
import urllib.parse
from pathlib import Path

_RUTA = Path(__file__).resolve().parents[2] / "scripts" / "prueba_b.py"
_spec = importlib.util.spec_from_file_location("prueba_b", _RUTA)
assert _spec
assert _spec.loader
prueba_b = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(prueba_b)


def _jwt(carga: dict) -> str:
    def b64(d: bytes) -> str:
        return base64.urlsafe_b64encode(d).decode().rstrip("=")

    return f"{b64(b'{\"alg\":\"RS256\"}')}.{b64(json.dumps(carga).encode())}.{b64(b'firma-de-prueba-123')}"


def test_challenge_del_ejemplo_del_rfc_7636():
    """Apendice B del RFC 7636: el verifier de ejemplo y su challenge S256."""
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert prueba_b.challenge_de(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_pkce_es_aleatorio_y_coherente():
    v1, c1 = prueba_b.pkce()
    v2, _ = prueba_b.pkce()
    assert v1 != v2
    assert 43 <= len(v1) <= 128  # longitud que exige el RFC
    assert c1 == prueba_b.challenge_de(v1)


def test_el_enlace_va_directo_a_identity_center_con_s256_y_state():
    url = prueba_b.url_autorizacion("https://x.auth.us-east-1.amazoncognito.com", "cliente123", "reto", "estado")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert url.startswith("https://x.auth.us-east-1.amazoncognito.com/oauth2/authorize?")
    assert q["identity_provider"] == ["IdentityCenter"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["code_challenge"] == ["reto"]
    assert q["state"] == ["estado"]
    assert q["redirect_uri"] == ["http://localhost:8080/callback"]
    assert q["response_type"] == ["code"]
    assert "client_secret" not in q


def test_alterar_firma_cambia_el_primer_caracter_y_nada_mas():
    token = _jwt({"sub": "x"})
    alterado = prueba_b.alterar_firma(token)
    cuerpo, firma = token.rsplit(".", 1)
    cuerpo2, firma2 = alterado.rsplit(".", 1)
    assert cuerpo2 == cuerpo
    assert firma2 != firma
    assert firma2[1:] == firma[1:]


def test_alterar_firma_cuando_ya_empieza_por_b():
    assert prueba_b.alterar_firma("a.b.Bxyz").endswith(".Cxyz")


def test_claims_lee_la_carga_y_visibles_no_saca_el_token():
    token = _jwt({"iss": "https://cognito-idp.us-east-1.amazonaws.com/p", "client_id": "c", "token_use": "access", "secreto": "no"})
    visibles = prueba_b.visibles(prueba_b.claims(token))
    assert visibles["token_use"] == "access"
    assert visibles["client_id"] == "c"
    assert "secreto" not in visibles
    assert token not in json.dumps(visibles)


def test_el_token_se_guarda_con_permisos_600(tmp_path):
    ruta = tmp_path / "sub" / "token-mateo.json"
    prueba_b.guardar_token(ruta, "tok.en.uno")
    assert stat.S_IMODE(ruta.stat().st_mode) == 0o600
    prueba_b.guardar_token(ruta, "tok.en.dos")  # se reescribe sin quedar abierto
    assert stat.S_IMODE(ruta.stat().st_mode) == 0o600
    assert json.loads(ruta.read_text())["access_token"] == "tok.en.dos"
    assert "id_token" not in json.loads(ruta.read_text())


def test_guardar_token_guarda_el_id_token_si_lo_hay(tmp_path):
    """AssumeRoleWithWebIdentity exige `aud`, que solo lleva el token de identidad (Fase 23)."""
    ruta = tmp_path / "t.json"
    prueba_b.guardar_token(ruta, "acc.e.so", "i.d.token")
    guardado = json.loads(ruta.read_text())
    assert guardado["access_token"] == "acc.e.so"
    assert guardado["id_token"] == "i.d.token"
    assert oct(ruta.stat().st_mode)[-3:] == "600"


def test_enmascara_numeros_de_cuenta():
    assert prueba_b.enmascarar("arn:aws:sts::111122223333:assumed-role/x") == "arn:aws:sts::********3333:assumed-role/x"


def _evento(rol: str) -> dict:
    return {"CloudTrailEvent": json.dumps({"eventName": "AssumeRole", "requestParameters": {"roleArn": f"arn:aws:iam::111122223333:role/{rol}"}})}


def test_cloudtrail_recorre_todas_las_paginas():
    """El AssumeRole del eco en la SEGUNDA pagina tiene que aparecer: con una
    sola llamada (como estaba el 23-10-2026) se perdia."""
    import boto3
    from botocore.stub import Stubber
    from datetime import datetime, timezone

    cliente = boto3.client("cloudtrail", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    stub = Stubber(cliente)
    stub.add_response("lookup_events", {"Events": [_evento("AWSControlTowerExecution")] * 50, "NextToken": "t2"})
    stub.add_response("lookup_events", {"Events": [_evento(prueba_b.ROL_ECO), _evento("Otro")]})
    with stub:
        encontrados = prueba_b.assume_roles_del_eco(cliente, datetime(2026, 10, 23, tzinfo=timezone.utc))
    stub.assert_no_pending_responses()
    assert len(encontrados) == 1
    assert prueba_b.ROL_ECO in encontrados[0]["requestParameters"]["roleArn"]


def test_el_mismo_sub_en_los_dos_usuarios_se_detecta(tmp_path):
    """El 23-10-2026 el token "del aprobador" salio con el sub de Mateo: el
    navegador reutilizo la sesion. Eso no puede pasar como evidencia."""
    prueba_b.guardar_token(tmp_path / "token-mateo.json", _jwt({"sub": "sub-mateo"}))
    assert prueba_b.sub_repetido(tmp_path, "aprobador", "sub-mateo") == "mateo"
    assert prueba_b.sub_repetido(tmp_path, "aprobador", "sub-aprobador") is None
    assert prueba_b.sub_repetido(tmp_path, "mateo", "sub-mateo") is None  # su propio fichero no cuenta


def test_solo_lee_registros_de_eventos_y_no_los_digest():
    """Los digest de la validacion de integridad no traen `Records`: leerlos
    rompia `cloudtrail` con KeyError (23-10-2026)."""
    base = "AWSLogs/111122223333/"
    assert prueba_b.es_registro_de_eventos(base + "CloudTrail/us-east-1/2026/10/23/x_CloudTrail_us-east-1_20261023T1705Z_a.json.gz")
    assert not prueba_b.es_registro_de_eventos(base + "CloudTrail-Digest/us-east-1/2026/10/23/x_CloudTrail-Digest_us-east-1_t.json.gz")
    assert not prueba_b.es_registro_de_eventos(base + "CloudTrail/")
