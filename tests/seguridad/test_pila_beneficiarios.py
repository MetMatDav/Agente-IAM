"""Pila de beneficiarios de demo (`infra/cfn/beneficiarios.yaml`).

Un rol de aplicacion que recibe permisos del agente y un bucket de prueba.
Lo que fijan estos tests:

  - El rol lleva `AgenteIAM-Techo` como boundary: el aplicador solo adjunta a
    quien lo lleva (su `Attach*` exige `iam:PermissionsBoundary`).
  - El rol nace sin permisos: ni `Policies` ni `ManagedPolicyArns`. Lo que
    tenga se lo da el aplicador.
  - Ningun nombre de recurso empieza por un prefijo del sistema: el chequeo 6
    y el techo rechazarian darle permisos sobre algo con ese nombre.
  - El bucket es privado, cifrado y solo TLS, y la confianza del rol lleva
    `aws:SourceAccount`.
"""

from pathlib import Path

import yaml

from agente_iam.coherencia import del_sistema
from agente_iam.config import NOMBRE_TECHO, PREFIJOS_DEL_SISTEMA
from tests.dobles import resolver_sub

RAIZ = Path(__file__).resolve().parents[2]
CUENTA = "111122223333"


def _plantilla() -> dict:
    return yaml.safe_load((RAIZ / "infra" / "cfn" / "beneficiarios.yaml").read_text(encoding="utf-8"))


def _recursos(tipo: str) -> dict:
    return {n: r for n, r in _plantilla()["Resources"].items() if r["Type"] == tipo}


def _rol() -> dict:
    return resolver_sub(_plantilla()["Resources"]["RolDemo"]["Properties"])


def test_el_rol_lleva_el_techo_como_boundary():
    assert _rol()["PermissionsBoundary"] == f"arn:aws:iam::{CUENTA}:policy/{NOMBRE_TECHO}"
    assert NOMBRE_TECHO == "AgenteIAM-Techo"


def test_el_rol_nace_sin_permisos():
    p = _rol()
    assert "Policies" not in p
    assert "ManagedPolicyArns" not in p
    assert p["RoleName"] == "app-finanzas-demo"
    assert "demo" in p["Description"]


def test_ningun_nombre_empieza_por_un_prefijo_del_sistema():
    nombres = [_rol()["RoleName"]]
    [bucket] = _recursos("AWS::S3::Bucket").values()
    nombres.append(resolver_sub(bucket["Properties"])["BucketName"])
    assert nombres == ["app-finanzas-demo", f"finanzas-demo-{CUENTA}"]
    for nombre in nombres:
        assert not nombre.lower().startswith(PREFIJOS_DEL_SISTEMA), nombre
        assert del_sistema(f"arn:aws:s3:::{nombre}/*") is None, nombre
        assert del_sistema(f"arn:aws:iam::{CUENTA}:role/{nombre}") is None, nombre


def test_la_confianza_lleva_la_cuenta_de_origen():
    [s] = resolver_sub(_plantilla()["Resources"]["RolDemo"]["Properties"]["AssumeRolePolicyDocument"])["Statement"]
    assert s["Effect"] == "Allow"
    assert s["Principal"] == {"Service": "lambda.amazonaws.com"}
    assert s["Action"] == "sts:AssumeRole"
    assert s["Condition"] == {"StringEquals": {"aws:SourceAccount": CUENTA}}


def test_el_bucket_es_privado_cifrado_y_solo_tls():
    [bucket] = _recursos("AWS::S3::Bucket").values()
    p = bucket["Properties"]
    assert p["BucketEncryption"]["ServerSideEncryptionConfiguration"] == [
        {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
    assert p["PublicAccessBlockConfiguration"] == {
        "BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True, "RestrictPublicBuckets": True}
    assert p["OwnershipControls"]["Rules"] == [{"ObjectOwnership": "BucketOwnerEnforced"}]
    [politica] = _recursos("AWS::S3::BucketPolicy").values()
    assert politica["Properties"]["Bucket"] == {"Ref": "BucketDemo"}
    [s] = resolver_sub(politica["Properties"]["PolicyDocument"])["Statement"]
    assert s["Effect"] == "Deny"
    assert s["Principal"] == "*"
    assert s["Action"] == "s3:*"
    assert s["Resource"] == [f"arn:aws:s3:::finanzas-demo-{CUENTA}", f"arn:aws:s3:::finanzas-demo-{CUENTA}/*"]
    assert s["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}


def test_es_de_demo_nada_se_retiene_y_solo_hay_rol_bucket_y_politica():
    plantilla = _plantilla()
    assert {r["Type"] for r in plantilla["Resources"].values()} == {
        "AWS::IAM::Role", "AWS::S3::Bucket", "AWS::S3::BucketPolicy"}
    for nombre, r in plantilla["Resources"].items():
        assert "DeletionPolicy" not in r, nombre
    assert set(plantilla["Outputs"]) == {"RolDemoArn", "BucketDemo"}
