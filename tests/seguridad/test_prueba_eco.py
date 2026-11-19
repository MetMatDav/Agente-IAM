"""Prueba B (pila temporal `infra/cfn/prueba-eco.yaml`): que no abra nada.

La pila monta Cognito federado con Identity Center y un runtime eco con
autorizador JWT para medir donde queda la identidad del usuario (Fase 15,
23-10-2026). Es temporal, pero vive en la cuenta donde ira el sistema, asi
que sus controles se comprueban como los del sistema: estos tests se ponen en
rojo si el cliente gana un secreto o un flujo de contrasena, si el pool
admite registros o usuarios propios, si el rol del eco gana permisos que el
runtime real no tiene o pierde la proteccion contra el confused deputy, o si
el runtime deja pasar mas cabeceras que `Authorization`.
"""

from fnmatch import fnmatchcase
from pathlib import Path

import yaml

from tests.dobles import sentencias_de_rol

RAIZ = Path(__file__).resolve().parents[2]
PLANTILLA = RAIZ / "infra" / "cfn" / "prueba-eco.yaml"


def _recursos() -> dict:
    return yaml.safe_load(PLANTILLA.read_text(encoding="utf-8"))["Resources"]


def _props(nombre: str) -> dict:
    return _recursos()[nombre]["Properties"]


# --- Cognito -----------------------------------------------------------------


def test_el_pool_no_admite_registros_propios():
    assert _props("UserPool")["AdminCreateUserConfig"] == {"AllowAdminCreateUserOnly": True}


def test_el_cliente_es_publico_con_pkce_y_sin_contrasenas():
    c = _props("ClienteCli")
    assert c["GenerateSecret"] is False
    assert c["AllowedOAuthFlows"] == ["code"]
    assert c["AllowedOAuthFlowsUserPoolClient"] is True
    # Ningun ALLOW_USER_PASSWORD_AUTH, ALLOW_USER_SRP_AUTH ni ALLOW_CUSTOM_AUTH:
    # si no se pone la lista, Cognito activa SRP y custom por defecto.
    assert c["ExplicitAuthFlows"] == ["ALLOW_REFRESH_TOKEN_AUTH"]


def test_solo_se_entra_por_identity_center():
    assert _props("ClienteCli")["SupportedIdentityProviders"] == ["IdentityCenter"]
    assert _props("ProveedorIdentityCenter")["ProviderName"] == "IdentityCenter"
    assert _props("ProveedorIdentityCenter")["ProviderType"] == "SAML"


def test_la_unica_url_de_retorno_es_localhost():
    assert _props("ClienteCli")["CallbackURLs"] == ["http://localhost:8080/callback"]


def test_el_dominio_no_lleva_la_cuenta():
    """El dominio de Cognito es publico: con el numero de cuenta dentro, la
    cuenta quedaria expuesta en una URL."""
    assert _props("Dominio")["Domain"] == {"Ref": "PrefijoDominio"}
    patron = yaml.safe_load(PLANTILLA.read_text(encoding="utf-8"))["Parameters"]["PrefijoDominio"]["AllowedPattern"]
    assert "AccountId" not in patron
    assert "[0-9a-f]{6}" in patron


# --- Runtime ---------------------------------------------------------------


def test_el_runtime_solo_acepta_el_cliente_de_esta_pila():
    jwt = _props("RuntimeEco")["AuthorizerConfiguration"]["CustomJWTAuthorizer"]
    assert jwt["AllowedClients"] == [{"Ref": "ClienteCli"}]
    assert "AllowedAudience" not in jwt  # el token de acceso de Cognito no lleva aud
    assert jwt["DiscoveryUrl"]["Fn::Sub"].endswith("/${UserPool}/.well-known/openid-configuration")


def test_el_runtime_solo_deja_pasar_authorization():
    assert _props("RuntimeEco")["RequestHeaderConfiguration"] == {"RequestHeaderAllowlist": ["Authorization"]}


# --- El rol del eco ----------------------------------------------------------


def test_la_confianza_tiene_proteccion_contra_confused_deputy():
    [s] = _props("RolEco")["AssumeRolePolicyDocument"]["Statement"]
    assert s["Principal"] == {"Service": "bedrock-agentcore.amazonaws.com"}
    assert s["Action"] == "sts:AssumeRole"
    assert s["Condition"]["StringEquals"] == {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}
    assert "aws:SourceArn" in s["Condition"]["ArnLike"]


def test_el_eco_no_puede_mas_que_el_runtime_real():
    """Cada accion del eco esta permitida tambien en
    el rol del runtime de la pila base (`infra/cfn/base.yaml`). Nada de Bedrock, IAM ni DynamoDB."""
    base = yaml.safe_load((RAIZ / "infra" / "cfn" / "base.yaml").read_text(encoding="utf-8"))
    permitidas_reales = [
        a for s in sentencias_de_rol(base, "RolRuntime") if s["Effect"] == "Allow"
        for a in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])
    ]
    [politica] = _props("RolEco")["Policies"]
    for s in politica["PolicyDocument"]["Statement"]:
        assert s["Effect"] == "Allow"
        for accion in [s["Action"]] if isinstance(s["Action"], str) else s["Action"]:
            assert accion.split(":")[0] not in {"bedrock", "iam", "dynamodb", "sts"}, accion
            assert accion in permitidas_reales or accion.startswith("s3:Get"), accion


def test_el_eco_solo_lee_su_paquete():
    [politica] = _props("RolEco")["Policies"]
    [s3] = [s for s in politica["PolicyDocument"]["Statement"] if any(a.startswith("s3:") for a in s["Action"])]
    assert sorted(s3["Action"]) == ["s3:GetObject", "s3:GetObjectVersion"]
    assert s3["Resource"] == {"Fn::Sub": "${BucketPaquete.Arn}/agente-eco/*"}


# --- Buckets y trail ---------------------------------------------------------


def test_los_buckets_son_privados_cifrados_y_solo_tls():
    for bucket, politica in [("BucketPaquete", "PoliticaBucketPaquete"), ("BucketTrail", "PoliticaBucketTrail")]:
        p = _props(bucket)
        assert all(p["PublicAccessBlockConfiguration"].values()), bucket
        assert p["BucketEncryption"]["ServerSideEncryptionConfiguration"][0]["ServerSideEncryptionByDefault"]
        deny = [s for s in _props(politica)["PolicyDocument"]["Statement"] if s["Effect"] == "Deny"]
        assert deny, politica
        assert deny[0]["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}, politica


def test_cloudtrail_solo_escribe_desde_su_trail():
    for s in _props("PoliticaBucketTrail")["PolicyDocument"]["Statement"]:
        if s["Effect"] == "Allow":
            assert s["Principal"] == {"Service": "cloudtrail.amazonaws.com"}
            arn = s["Condition"]["StringEquals"]["aws:SourceArn"]["Fn::Sub"]
            assert fnmatchcase(arn, "arn:aws:cloudtrail:*:trail/agente-iam-prueba-datos")


def test_el_trail_solo_registra_eventos_de_datos_de_agentcore():
    [selector] = _props("TrailDatos")["AdvancedEventSelectors"]
    campos = {f["Field"]: f["Equals"] for f in selector["FieldSelectors"]}
    assert campos == {"eventCategory": ["Data"], "resources.type": ["AWS::BedrockAgentCore::Runtime"]}


def test_lo_federado_solo_existe_en_el_segundo_despliegue():
    recursos = _recursos()
    for nombre in ["ProveedorIdentityCenter", "ClienteCli", "RuntimeEco"]:
        assert recursos[nombre]["Condition"] == "Federado", nombre
    for nombre in ["BucketTrail", "PoliticaBucketTrail", "TrailDatos"]:
        assert recursos[nombre]["Condition"] == "TrailDeDatos", nombre
