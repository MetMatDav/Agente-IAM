"""Pila web (`infra/cfn/web.yaml`): la pagina estatica tras CloudFront (Fase 23, bloque 2).

La pagina es estatica y vive en un bucket privado que solo lee CloudFront con
OAC, y solo la distribucion de esta pila. Las cabeceras de seguridad las pone
CloudFront (S3 no puede) y la CSP es lo que limita a donde puede llamar la
pagina: solo el dominio de Cognito, el endpoint de AgentCore y el de STS.
Estos tests se ponen en rojo si el bucket deja de ser privado, cifrado o sin
TLS, si otro principal o otra distribucion puede leerlo, si la distribucion
admite HTTP o metodos de escritura, si la CSP admite codigo en linea o
destinos de mas, si falta alguna cabecera de seguridad, si la pila crea algo
que no sea S3 o CloudFront, si un nombre pierde el prefijo del proyecto o si
`DominioCognito` gana un valor por defecto (la pila no lleva ids reales).

Desde la Fase 27 (ADR-005) la pagina puede servirse en `agente-iam.mateo.solutions`
con un certificado de ACM propio, para que rija TLS 1.2 como minimo (con el
certificado por defecto CloudFront aplica TLSv1, MEDICIONES O.4). Es condicional:
sin `DominioWeb` ni `CertificadoArn` la distribucion queda como se desplego en la
Fase 23. Los tests se ponen en rojo si el dominio o el certificado admiten otro
valor, si uno puede ir sin el otro, si el certificado propio pierde `sni-only` o
TLS 1.2, o si la pila gana registros DNS (los pone Mateo en la zona de gestion).
"""

import re
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parents[2]
PLANTILLA = RAIZ / "infra" / "cfn" / "web.yaml"

POLITICA_DE_CACHE_OPTIMIZADA = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _plantilla() -> dict:
    return yaml.safe_load(PLANTILLA.read_text(encoding="utf-8"))


def _recursos() -> dict:
    return _plantilla()["Resources"]


def _props(nombre: str) -> dict:
    return _recursos()[nombre]["Properties"]


def _config() -> dict:
    return _props("Distribucion")["DistributionConfig"]


def _csp() -> dict:
    return _props("CabecerasSeguridad")["ResponseHeadersPolicyConfig"]["SecurityHeadersConfig"]["ContentSecurityPolicy"]


def _directivas() -> dict[str, list[str]]:
    """La CSP como {directiva: [fuentes]}, con el parametro sin resolver."""
    texto = _csp()["ContentSecurityPolicy"]["Fn::Sub"]
    resultado = {}
    for parte in texto.split(";"):
        trozos = parte.split()
        if trozos:
            resultado[trozos[0]] = trozos[1:]
    return resultado


def _sentencia(sid: str) -> dict:
    for s in _props("PoliticaBucketWeb")["PolicyDocument"]["Statement"]:
        if s["Sid"] == sid:
            return s
    raise AssertionError(f"no hay sentencia {sid}")


# --- El bucket ----------------------------------------------------------------


def test_el_bucket_es_privado_cifrado_versionado_y_sin_acls():
    b = _props("BucketWeb")
    assert b["PublicAccessBlockConfiguration"] == {
        "BlockPublicAcls": True,
        "BlockPublicPolicy": True,
        "IgnorePublicAcls": True,
        "RestrictPublicBuckets": True,
    }
    assert b["BucketEncryption"]["ServerSideEncryptionConfiguration"] == [
        {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
    ]
    assert b["OwnershipControls"]["Rules"] == [{"ObjectOwnership": "BucketOwnerEnforced"}]
    assert b["VersioningConfiguration"] == {"Status": "Enabled"}


def test_el_nombre_del_bucket_lleva_la_cuenta_por_pseudoparametro_y_no_literal():
    nombre = _props("BucketWeb")["BucketName"]
    assert nombre == {"Fn::Sub": "agente-iam-web-${AWS::AccountId}"}
    assert not re.search(r"\d{12}", PLANTILLA.read_text(encoding="utf-8"))


def test_el_bucket_y_su_politica_se_conservan_al_borrar_la_pila():
    """Como los demas buckets del proyecto: el Deny de TLS y las versiones no se pierden con la pila."""
    for nombre in ("BucketWeb", "PoliticaBucketWeb"):
        recurso = _recursos()[nombre]
        assert recurso["DeletionPolicy"] == "Retain", nombre
        assert recurso["UpdateReplacePolicy"] == "Retain", nombre


# --- La politica del bucket ---------------------------------------------------


def test_solo_cloudfront_lee_y_solo_esta_distribucion():
    politica = _props("PoliticaBucketWeb")
    assert politica["Bucket"] == {"Ref": "BucketWeb"}
    permitidas = [s for s in politica["PolicyDocument"]["Statement"] if s["Effect"] == "Allow"]
    assert len(permitidas) == 1
    s = permitidas[0]
    assert s["Principal"] == {"Service": "cloudfront.amazonaws.com"}
    assert s["Action"] == "s3:GetObject"
    assert s["Resource"] == {"Fn::Sub": "${BucketWeb.Arn}/*"}
    assert s["Condition"] == {
        "StringEquals": {
            "aws:SourceArn": {"Fn::Sub": "arn:aws:cloudfront::${AWS::AccountId}:distribution/${Distribucion}"}
        }
    }


def test_el_bucket_niega_todo_sin_tls():
    deniegadas = [s for s in _props("PoliticaBucketWeb")["PolicyDocument"]["Statement"] if s["Effect"] == "Deny"]
    assert len(deniegadas) == 1
    s = deniegadas[0]
    assert s["Principal"] == "*"
    assert s["Action"] == "s3:*"
    assert s["Resource"] == [{"Fn::GetAtt": ["BucketWeb", "Arn"]}, {"Fn::Sub": "${BucketWeb.Arn}/*"}]
    assert s["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}


# --- El control de acceso al origen --------------------------------------------


def test_el_acceso_al_origen_firma_siempre_con_sigv4_hacia_s3():
    oac = _props("AccesoOrigen")["OriginAccessControlConfig"]
    assert oac["Name"] == "agente-iam-web"
    assert oac["OriginAccessControlOriginType"] == "s3"
    assert oac["SigningBehavior"] == "always"
    assert oac["SigningProtocol"] == "sigv4"


# --- La distribucion -----------------------------------------------------------


def test_la_distribucion_obliga_a_https_y_solo_deja_leer():
    c = _config()
    assert c["Enabled"] is True
    assert c["DefaultRootObject"] == "index.html"
    assert c["HttpVersion"] == "http2"
    assert c["PriceClass"] == "PriceClass_100"
    d = c["DefaultCacheBehavior"]
    assert d["ViewerProtocolPolicy"] == "redirect-to-https"
    assert d["AllowedMethods"] == ["GET", "HEAD"]
    assert d["CachedMethods"] == ["GET", "HEAD"]
    assert d["Compress"] is True
    assert d["CachePolicyId"] == POLITICA_DE_CACHE_OPTIMIZADA


def test_la_distribucion_lee_solo_del_bucket_por_oac_y_pone_las_cabeceras():
    c = _config()
    [origen] = c["Origins"]
    assert origen["DomainName"] == {"Fn::GetAtt": ["BucketWeb", "RegionalDomainName"]}
    assert origen["OriginAccessControlId"] == {"Ref": "AccesoOrigen"}
    # Un origen S3 con OAC lleva la identidad de origen vacia (la antigua OAI no se usa).
    assert origen["S3OriginConfig"] == {"OriginAccessIdentity": ""}
    d = c["DefaultCacheBehavior"]
    assert d["TargetOriginId"] == origen["Id"]
    assert d["ResponseHeadersPolicyId"] == {"Ref": "CabecerasSeguridad"}
    assert "CacheBehaviors" not in c


def test_sin_dominio_usa_el_certificado_de_cloudfront_y_con_dominio_el_de_acm_con_sni_y_tls_12():
    """Con el certificado por defecto CloudFront fija TLSv1 aunque se pida otra cosa (MEDICIONES O.4); con uno
    propio en `sni-only` la politica TLSv1.2_2021 si rige (ADR-005 F). La rama sin dominio es la de la Fase 23,
    sin cambios: una actualizacion sin parametros no toca la distribucion."""
    v = _config()["ViewerCertificate"]
    condicion, con_dominio, sin_dominio = v["Fn::If"]
    assert condicion == "ConDominio"
    assert con_dominio == {
        "AcmCertificateArn": {"Ref": "CertificadoArn"},
        "SslSupportMethod": "sni-only",
        "MinimumProtocolVersion": "TLSv1.2_2021",
    }
    assert sin_dominio == {"CloudFrontDefaultCertificate": True, "MinimumProtocolVersion": "TLSv1.2_2021"}


def test_el_alias_de_la_distribucion_es_el_dominio_y_solo_con_dominio():
    assert _config()["Aliases"] == {"Fn::If": ["ConDominio", [{"Ref": "DominioWeb"}], {"Ref": "AWS::NoValue"}]}


def test_el_dominio_y_el_certificado_van_juntos_o_ninguno():
    plantilla = _plantilla()
    vacio_d = {"Fn::Equals": [{"Ref": "DominioWeb"}, ""]}
    vacio_c = {"Fn::Equals": [{"Ref": "CertificadoArn"}, ""]}
    assert plantilla["Conditions"]["ConDominio"] == {
        "Fn::And": [{"Fn::Not": [vacio_d]}, {"Fn::Not": [vacio_c]}]
    }
    [regla] = plantilla["Rules"].values()
    assert regla["Assertions"][0]["Assert"] == {
        "Fn::Or": [
            {"Fn::And": [vacio_d, vacio_c]},
            {"Fn::And": [{"Fn::Not": [vacio_d]}, {"Fn::Not": [vacio_c]}]},
        ]
    }


def test_el_dominio_solo_admite_el_subdominio_del_agente():
    p = _plantilla()["Parameters"]["DominioWeb"]
    assert p["Default"] == ""
    patron = p["AllowedPattern"]
    assert re.fullmatch(patron, "")
    assert re.fullmatch(patron, "agente-iam.mateo.solutions")
    for rechazado in ("mateo.solutions", "www.mateo.solutions", "otro.mateo.solutions", "agente-iam.example.org",
                      "https://agente-iam.mateo.solutions", "agente-iam.mateo.solutions/", "AGENTE-IAM.MATEO.SOLUTIONS"):
        assert not re.fullmatch(patron, rechazado), rechazado


def test_el_certificado_es_de_acm_en_us_east_1_y_sin_valor_por_defecto_real():
    p = _plantilla()["Parameters"]["CertificadoArn"]
    assert p["Default"] == ""
    patron = p["AllowedPattern"]
    assert re.fullmatch(patron, "")
    assert re.fullmatch(patron, "arn:aws:acm:us-east-1:111122223333:certificate/0a1b2c3d-0a1b-0a1b-0a1b-0a1b2c3d4e5f")
    for rechazado in (
        "arn:aws:acm:us-west-2:111122223333:certificate/0a1b2c3d-0a1b-0a1b-0a1b-0a1b2c3d4e5f",
        "arn:aws:iam::111122223333:server-certificate/x",
        "arn:aws:acm:us-east-1:111122223333:certificate/*",
    ):
        assert not re.fullmatch(patron, rechazado), rechazado


# --- La politica de cabeceras ---------------------------------------------------


def test_la_csp_no_admite_codigo_en_linea_ni_eval():
    texto = _csp()["ContentSecurityPolicy"]["Fn::Sub"]
    assert _csp()["Override"] is True
    assert "unsafe-inline" not in texto
    assert "unsafe-eval" not in texto
    assert "*" not in texto.replace("'self'", "")


def test_la_csp_lo_cierra_todo_menos_lo_que_la_pagina_necesita():
    d = _directivas()
    assert d["default-src"] == ["'none'"]
    assert d["script-src"] == ["'self'"]
    assert d["style-src"] == ["'self'"]
    assert d["img-src"] == ["'self'"]
    assert d["base-uri"] == ["'none'"]
    assert d["form-action"] == ["'none'"]
    assert d["frame-ancestors"] == ["'none'"]
    assert set(d) == {
        "default-src", "script-src", "style-src", "connect-src", "img-src", "base-uri", "form-action", "frame-ancestors",
    }


def test_la_csp_solo_deja_llamar_a_cognito_agentcore_y_sts():
    """`connect-src` es lo que limita a donde puede mandar datos la pagina: el dominio de Cognito (parametro, sin
    barra final), el endpoint de AgentCore y el de STS, los tres de us-east-1, y nada mas."""
    assert _directivas()["connect-src"] == [
        "${DominioCognito}",
        "https://bedrock-agentcore.us-east-1.amazonaws.com",
        "https://sts.us-east-1.amazonaws.com",
    ]


def test_las_cabeceras_de_seguridad_estan_todas_y_se_imponen():
    s = _props("CabecerasSeguridad")["ResponseHeadersPolicyConfig"]["SecurityHeadersConfig"]
    assert s["StrictTransportSecurity"] == {
        "AccessControlMaxAgeSec": 31536000,
        "IncludeSubdomains": True,
        "Override": True,
    }
    assert s["ContentTypeOptions"] == {"Override": True}
    assert s["ReferrerPolicy"] == {"ReferrerPolicy": "no-referrer", "Override": True}
    assert s["FrameOptions"] == {"FrameOption": "DENY", "Override": True}
    assert _props("CabecerasSeguridad")["ResponseHeadersPolicyConfig"]["Name"] == "agente-iam-web-cabeceras"


# --- Hechos de la pila ----------------------------------------------------------


def test_la_pila_solo_tiene_recursos_de_s3_y_cloudfront():
    tipos = {r["Type"] for r in _recursos().values()}
    assert tipos == {
        "AWS::S3::Bucket",
        "AWS::S3::BucketPolicy",
        "AWS::CloudFront::OriginAccessControl",
        "AWS::CloudFront::ResponseHeadersPolicy",
        "AWS::CloudFront::Distribution",
    }
    for tipo in tipos:
        assert tipo.startswith(("AWS::S3::", "AWS::CloudFront::")), tipo


def test_los_nombres_fisicos_llevan_el_prefijo_del_proyecto():
    assert _props("BucketWeb")["BucketName"]["Fn::Sub"].startswith("agente-iam-")
    assert _props("AccesoOrigen")["OriginAccessControlConfig"]["Name"].startswith("agente-iam-")
    assert _props("CabecerasSeguridad")["ResponseHeadersPolicyConfig"]["Name"].startswith("agente-iam-")
    assert _config()["Comment"].startswith("agente-iam-")


def test_lo_que_admite_etiquetas_lleva_la_del_proyecto():
    etiqueta = {"Key": "proyecto", "Value": "agente-iam"}
    assert etiqueta in _props("BucketWeb")["Tags"]
    assert etiqueta in _props("Distribucion")["Tags"]


def test_el_dominio_de_cognito_es_un_parametro_sin_valor_por_defecto():
    p = _plantilla()["Parameters"]["DominioCognito"]
    assert p["Type"] == "String"
    assert "Default" not in p
    assert p["AllowedPattern"] == r"^https://agente-iam-[0-9a-f]{6}\.auth\.us-east-1\.amazoncognito\.com$"
    assert re.fullmatch(p["AllowedPattern"], "https://agente-iam-0a1b2c.auth.us-east-1.amazoncognito.com")
    # Sin barra final ni otro host: la CSP se escribe con el valor tal cual.
    assert not re.fullmatch(p["AllowedPattern"], "https://agente-iam-0a1b2c.auth.us-east-1.amazoncognito.com/")
    assert not re.fullmatch(p["AllowedPattern"], "https://otro.example.org")


def test_las_salidas_son_las_que_espera_el_resto():
    """`UrlWeb` es la URL con la que se rellena `UrlRetornoWeb` de la pila de acceso: con dominio, el dominio.
    `DominioCloudFront` es el destino de los alias A y AAAA que Mateo crea en la zona de gestion."""
    salidas = _plantilla()["Outputs"]
    assert set(salidas) == {"UrlWeb", "BucketWeb", "DistribucionId", "DominioCloudFront"}
    assert salidas["UrlWeb"]["Value"] == {
        "Fn::If": ["ConDominio", {"Fn::Sub": "https://${DominioWeb}"}, {"Fn::Sub": "https://${Distribucion.DomainName}"}]
    }
    assert salidas["DominioCloudFront"]["Value"] == {"Fn::GetAtt": ["Distribucion", "DomainName"]}
    assert salidas["BucketWeb"]["Value"] == {"Ref": "BucketWeb"}
    assert salidas["DistribucionId"]["Value"] == {"Ref": "Distribucion"}
