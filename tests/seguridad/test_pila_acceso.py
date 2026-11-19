"""Pila de acceso (`infra/cfn/acceso.yaml`): que no abra nada.

Es la version definitiva de la parte de Cognito de la Prueba B (ADR-001,
MEDICIONES D.2): Cognito traduce la asercion SAML de Identity Center a un JWT
y nada mas. Estos tests se ponen en rojo si el pool admite registros o
usuarios propios, si pierde la proteccion contra borrado, si el cliente gana
un secreto o un flujo de contrasena, si aparece otro proveedor o otra URL de
retorno, si el dominio lleva la cuenta, si los tokens duran mas de una hora, si
lo federado existe sin `MetadataUrl` o si la pila crea algo que no sea de
Cognito (salvo, desde la Fase 23, el proveedor OIDC del propio pool en IAM, con el que la persona
canjea su token con `AssumeRoleWithWebIdentity`).

Tambien desde la Fase 23 (bloque 2), con la pila `web` desplegada, hay un segundo
cliente publico para la pagina (`ClienteWeb`): mismas reglas que el de la CLI,
pero su unica URL de retorno es la de la pagina y solo existe si
`UrlRetornoWeb` no esta vacio. Los tests lo fijan igual de estricto. Desde la
Fase 27 (ADR-005) esa URL puede ser la de CloudFront o, exactamente,
`https://agente-iam.mateo.solutions/`: ningun otro dominio, para que un error
o un rol de despliegue comprometido no pueda mandar el codigo de login a otro sitio.
"""

import re
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parents[2]
PLANTILLA = RAIZ / "infra" / "cfn" / "acceso.yaml"


def _plantilla() -> dict:
    return yaml.safe_load(PLANTILLA.read_text(encoding="utf-8"))


def _recursos() -> dict:
    return _plantilla()["Resources"]


def _props(nombre: str) -> dict:
    return _recursos()[nombre]["Properties"]


# --- El pool -----------------------------------------------------------------


def test_el_pool_no_admite_registros_propios():
    assert _props("UserPool")["AdminCreateUserConfig"] == {"AllowAdminCreateUserOnly": True}


def test_el_pool_tiene_proteccion_contra_borrado_y_se_conserva():
    pool = _recursos()["UserPool"]
    assert pool["Properties"]["DeletionProtection"] == "ACTIVE"
    assert pool["DeletionPolicy"] == "Retain"
    assert pool["UpdateReplacePolicy"] == "Retain"


def test_el_pool_es_del_proyecto_y_del_plan_lite():
    p = _props("UserPool")
    assert p["UserPoolName"] == "agente-iam-acceso"
    assert p["UserPoolTier"] == "LITE"
    assert p["UserPoolTags"] == {"proyecto": "agente-iam"}


def test_el_dominio_no_lleva_la_cuenta():
    """El dominio de Cognito es publico: con el numero de cuenta dentro, la
    cuenta quedaria expuesta en una URL."""
    assert _props("Dominio")["Domain"] == {"Ref": "PrefijoDominio"}
    assert _props("Dominio")["ManagedLoginVersion"] == 1
    patron = _plantilla()["Parameters"]["PrefijoDominio"]["AllowedPattern"]
    assert patron == "^agente-iam-[0-9a-f]{6}$"
    assert "AccountId" not in patron


# --- El proveedor y el cliente -----------------------------------------------


def test_el_cliente_es_publico_con_pkce_y_sin_contrasenas():
    c = _props("ClienteCli")
    assert c["ClientName"] == "agente-iam-cli"
    assert c["GenerateSecret"] is False
    assert c["AllowedOAuthFlows"] == ["code"]
    assert c["AllowedOAuthFlowsUserPoolClient"] is True
    assert c["AllowedOAuthScopes"] == ["openid", "email"]
    # Si no se pone la lista, Cognito activa SRP y custom por defecto.
    assert c["ExplicitAuthFlows"] == ["ALLOW_REFRESH_TOKEN_AUTH"]
    for prohibido in ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH"]:
        assert prohibido not in c["ExplicitAuthFlows"], prohibido
    assert c["PreventUserExistenceErrors"] == "ENABLED"
    assert c["EnableTokenRevocation"] is True


def test_solo_se_entra_por_identity_center():
    assert _props("ClienteCli")["SupportedIdentityProviders"] == ["IdentityCenter"]
    proveedor = _props("ProveedorIdentityCenter")
    assert proveedor["ProviderName"] == "IdentityCenter"
    assert proveedor["ProviderType"] == "SAML"
    assert proveedor["ProviderDetails"] == {"MetadataURL": {"Ref": "MetadataUrl"}}
    assert proveedor["AttributeMapping"] == {"email": "email"}
    assert _recursos()["ClienteCli"]["DependsOn"] == "ProveedorIdentityCenter"


def test_la_unica_url_de_retorno_de_la_cli_es_localhost():
    c = _props("ClienteCli")
    assert c["CallbackURLs"] == ["http://localhost:8080/callback"]
    assert "LogoutURLs" not in c


def test_el_cliente_web_es_publico_pkce_y_solo_vuelve_a_su_pagina():
    """Misma forma que el de la CLI (sin secreto, solo `code` con PKCE, solo Identity Center, sin flujos de
    contrasena, tokens de una hora); cambian el nombre y la URL de retorno, que es la de la pagina y nada mas."""
    recurso = _recursos()["ClienteWeb"]
    assert recurso["Type"] == "AWS::Cognito::UserPoolClient"
    assert recurso["Condition"] == "ConWeb"
    assert recurso["DependsOn"] == "ProveedorIdentityCenter"
    web = recurso["Properties"]
    assert web["ClientName"] == "agente-iam-web"
    assert web["CallbackURLs"] == [{"Ref": "UrlRetornoWeb"}]
    assert web["LogoutURLs"] == [{"Ref": "UrlRetornoWeb"}]
    assert web["GenerateSecret"] is False
    assert web["AllowedOAuthFlows"] == ["code"]
    assert web["AllowedOAuthFlowsUserPoolClient"] is True
    assert web["SupportedIdentityProviders"] == ["IdentityCenter"]
    assert web["ExplicitAuthFlows"] == ["ALLOW_REFRESH_TOKEN_AUTH"]
    assert web["PreventUserExistenceErrors"] == "ENABLED"
    assert web["EnableTokenRevocation"] is True
    # Todo lo demas es identico al de la CLI: si alguien afloja uno, el otro no queda atras.
    cli = dict(_props("ClienteCli"))
    for clave in ("ClientName", "CallbackURLs"):
        cli.pop(clave)
    resto = {k: v for k, v in web.items() if k not in ("ClientName", "CallbackURLs", "LogoutURLs")}
    assert resto == cli


def test_sin_url_de_retorno_no_hay_cliente_web():
    plantilla = _plantilla()
    assert plantilla["Conditions"]["ConWeb"] == {
        "Fn::And": [
            {"Condition": "Federado"},
            {"Fn::Not": [{"Fn::Equals": [{"Ref": "UrlRetornoWeb"}, ""]}]},
        ]
    }
    parametro = plantilla["Parameters"]["UrlRetornoWeb"]
    assert parametro["Type"] == "String"
    assert parametro["Default"] == ""
    patron = parametro["AllowedPattern"]
    assert patron == r"^(https://[a-z0-9]+\.cloudfront\.net/|https://agente-iam\.mateo\.solutions/)?$"
    assert re.fullmatch(patron, "")
    assert re.fullmatch(patron, "https://d111111abcdef8.cloudfront.net/")
    assert re.fullmatch(patron, "https://agente-iam.mateo.solutions/")
    # Ni HTTP, ni otro dominio, ni sin barra final, ni con ruta, ni con subdominio extra, ni otro nombre del dominio.
    for rechazada in (
        "http://d111111abcdef8.cloudfront.net/",
        "https://d111111abcdef8.cloudfront.net",
        "https://d111111abcdef8.cloudfront.net/index.html",
        "https://evil.example.org/",
        "https://a.b.cloudfront.net/",
        "http://localhost:8080/callback",
        "http://agente-iam.mateo.solutions/",
        "https://agente-iam.mateo.solutions",
        "https://agente-iam.mateo.solutions/index.html",
        "https://mateo.solutions/",
        "https://www.mateo.solutions/",
        "https://x.agente-iam.mateo.solutions/",
        "https://agente-iamXmateo.solutions/",
    ):
        assert not re.fullmatch(patron, rechazada), rechazada


def test_los_tokens_duran_una_hora():
    c = _props("ClienteCli")
    assert c["AccessTokenValidity"] == 60
    assert c["IdTokenValidity"] == 60
    assert c["TokenValidityUnits"] == {"AccessToken": "minutes", "IdToken": "minutes"}


# --- Dos despliegues ---------------------------------------------------------


def test_lo_federado_solo_existe_con_metadata_url():
    plantilla = _plantilla()
    assert plantilla["Parameters"]["MetadataUrl"]["Default"] == ""
    assert plantilla["Conditions"]["Federado"] == {"Fn::Not": [{"Fn::Equals": [{"Ref": "MetadataUrl"}, ""]}]}
    recursos = plantilla["Resources"]
    for nombre in ["ProveedorIdentityCenter", "ClienteCli", "ProveedorOidc"]:
        assert recursos[nombre]["Condition"] == "Federado", nombre
    # El cliente de la web ademas necesita la URL de retorno, y esa condicion ya exige `Federado`.
    assert recursos["ClienteWeb"]["Condition"] == "ConWeb"
    assert {"Condition": "Federado"} in plantilla["Conditions"]["ConWeb"]["Fn::And"]
    # Lo del primer despliegue no depende de la condicion.
    for nombre in ["UserPool", "Dominio"]:
        assert "Condition" not in recursos[nombre], nombre
    assert plantilla["Outputs"]["ClienteId"]["Condition"] == "Federado"
    assert plantilla["Outputs"]["ProveedorOidcArn"]["Condition"] == "Federado"
    assert plantilla["Outputs"]["ClienteWebId"]["Condition"] == "ConWeb"


# --- El proveedor OIDC del pool (Fase 23) -------------------------------------


def test_el_proveedor_oidc_apunta_al_pool_y_lista_a_los_clientes():
    """La persona canjea su token de identidad de Cognito con `AssumeRoleWithWebIdentity` (MEDICIONES N): IAM necesita
    el pool como proveedor OIDC y los clientes admitidos (`aud`): el de la CLI siempre y el de la web solo si existe
    (`ConWeb`); un cliente fuera de la lista no podria canjear nada. Sin `ThumbprintList`: IAM valida la cadena de
    certificados de Cognito con las CA de confianza y la propiedad no es obligatoria (cfn-lint 1.57.2)."""
    recurso = _recursos()["ProveedorOidc"]
    assert recurso["Type"] == "AWS::IAM::OIDCProvider"
    assert recurso["Condition"] == "Federado"
    p = recurso["Properties"]
    assert p["Url"] == {"Fn::Sub": "https://cognito-idp.${AWS::Region}.amazonaws.com/${UserPool}"}
    assert p["ClientIdList"] == {
        "Fn::If": ["ConWeb", [{"Ref": "ClienteCli"}, {"Ref": "ClienteWeb"}], [{"Ref": "ClienteCli"}]]
    }
    assert "ThumbprintList" not in p
    assert p["Tags"] == [{"Key": "proyecto", "Value": "agente-iam"}]
    salida = _plantilla()["Outputs"]["ProveedorOidcArn"]
    assert salida["Condition"] == "Federado"
    assert salida["Value"] == {"Fn::GetAtt": ["ProveedorOidc", "Arn"]}


def test_el_proveedor_oidc_lista_a_los_dos_clientes_solo_con_web():
    """Con `ConWeb` falso la lista no puede nombrar a `ClienteWeb`, que no existe: seria un fallo de despliegue."""
    lista = _props("ProveedorOidc")["ClientIdList"]
    condicion, con_web, sin_web = lista["Fn::If"]
    assert condicion == "ConWeb"
    assert con_web == [{"Ref": "ClienteCli"}, {"Ref": "ClienteWeb"}]
    assert sin_web == [{"Ref": "ClienteCli"}]


# --- Solo Cognito (y su proveedor OIDC) ---------------------------------------


def test_la_pila_solo_tiene_recursos_de_cognito_y_ningun_usuario():
    tipos = {r["Type"] for r in _recursos().values()}
    assert tipos == {
        "AWS::Cognito::UserPool",
        "AWS::Cognito::UserPoolDomain",
        "AWS::Cognito::UserPoolIdentityProvider",
        "AWS::Cognito::UserPoolClient",
        "AWS::IAM::OIDCProvider",
    }
    assert "AWS::Cognito::UserPoolUser" not in tipos
    # Del lado de IAM, el unico recurso es ese proveedor: ni roles, ni usuarios, ni politicas.
    assert [n for n, r in _recursos().items() if r["Type"].startswith("AWS::IAM::")] == ["ProveedorOidc"]


# --- Salidas -----------------------------------------------------------------


def test_las_salidas_son_las_que_espera_el_resto():
    salidas = _plantilla()["Outputs"]
    assert set(salidas) == {
        "UserPoolId",
        "DiscoveryUrl",
        "UrlDominio",
        "AcsUrlParaIdentityCenter",
        "AudienceParaIdentityCenter",
        "ClienteId",
        "ClienteWebId",
        "ProveedorOidcArn",
    }
    assert salidas["ClienteWebId"]["Value"] == {"Ref": "ClienteWeb"}
    assert salidas["DiscoveryUrl"]["Value"]["Fn::Sub"] == (
        "https://cognito-idp.${AWS::Region}.amazonaws.com/${UserPool}/.well-known/openid-configuration"
    )
    assert salidas["AcsUrlParaIdentityCenter"]["Value"]["Fn::Sub"].endswith(".amazoncognito.com/saml2/idpresponse")
    assert salidas["AudienceParaIdentityCenter"]["Value"] == {"Fn::Sub": "urn:amazon:cognito:sp:${UserPool}"}
