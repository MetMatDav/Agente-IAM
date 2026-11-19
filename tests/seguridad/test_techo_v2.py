"""El techo v2 de los beneficiarios y su reflejo en el codigo (ADR-002).

Mateo eligio el 23-10-2026 cuatro cambios a la vez. Cada bloque fija uno:

  - B:  EC2 solo inventario. En el techo, `ec2:Describe*`; en el codigo,
        solo `lectura` antes del modelo y solo `Describe*` despues. Las
        Describe que devuelven user data o un secreto, prohibidas en las
        dos capas.
  - D1: el techo niega la gestion de permisos de todo lo que su Allow deja
        pasar. La lista sale de la referencia de autorizacion
        (`scripts/generar_techo.py`); aqui se prueba la regla con un
        catalogo de juguete, y el funcional `test_techo_en_vivo.py` la
        compara con la referencia del dia.
  - D2: el techo niega todo sobre los recursos del sistema, con patrones
        que cubren cada recurso que el rol de despliegue puede crear.
  - D3: el codigo rechaza lo mismo, antes y despues del modelo.

Lo que se comprueba contra la cuenta (ValidatePolicy y simulador) no esta
aqui: va en PLAN-CORRECCIONES, Fase 15, con su fecha.
"""

import json
import re
import sys
from fnmatch import fnmatchcase
from pathlib import Path

import botocore.session
import pytest
import yaml

from agente_iam import coherencia, orquestador
from agente_iam.config import ACCIONES_PROHIBIDAS, NOMBRE_TECHO, SERVICIOS_PERMITIDOS, SOLO_LECTURA
from agente_iam.herramientas import validacion
from agente_iam.herramientas.validacion import _revisar_lista_negra
from agente_iam.models import IdentidadVerificada, SolicitudEstructurada
from tests.dobles import _ANA, _CUENTA, _propuesta, _solicitud

_RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_RAIZ / "scripts"))
import generar_techo

_ARN = _ANA
_TECHO_ARN = f"arn:aws:iam::{_CUENTA}:policy/{NOMBRE_TECHO}"
_IDENTIDAD = {"principal_arn": _ARN, "tipo": "user", "existe": True, "cuenta": _CUENTA}


def _techo() -> dict:
    return json.loads((_RAIZ / "infra/boundary-agente-iam-techo.json").read_text())


def _sentencia(sid: str) -> dict:
    [st] = [s for s in _techo()["Statement"] if s.get("Sid") == sid]
    return st


@pytest.fixture
def con_techo(monkeypatch):
    """Un beneficiario que existe y lleva el techo: solo quedan los chequeos nuevos."""
    ident = IdentidadVerificada(**_IDENTIDAD, permissions_boundary=_TECHO_ARN)
    monkeypatch.setattr(orquestador, "verificar", lambda arn: ident)


# --- el documento entero -----------------------------------------------------


def test_el_json_es_lo_que_escribe_el_generador():
    """Nadie lo edita a mano: con sus propias listas de D1 y S3, se regenera igual."""
    gestion = _sentencia("SinGestionDePermisos")["Action"]
    escrituras = _sentencia("SinEscriturasDeAlcanceDeCuenta")["Action"]
    assert generar_techo.texto_json(generar_techo.construir_techo(gestion, escrituras)) == (
        _RAIZ / "infra/boundary-agente-iam-techo.json"
    ).read_text(encoding="utf-8")


def test_la_copia_de_arranque_es_lo_que_escribe_el_generador():
    texto = (_RAIZ / "infra/cfn/arranque.yaml").read_text(encoding="utf-8")
    assert generar_techo.arranque_con(_techo(), texto) == texto


def test_cabe_en_una_politica_gestionada():
    assert generar_techo.caracteres(_techo()) <= generar_techo.LIMITE_CARACTERES


# --- B: EC2 solo inventario --------------------------------------------------


def test_el_allow_es_el_de_los_servicios_permitidos_y_ec2_solo_describe():
    allow = _sentencia("AlcanceDelSistema")["Action"]
    assert allow == [f"{s}:{SOLO_LECTURA.get(s, '*')}" for s in SERVICIOS_PERMITIDOS]
    assert "ec2:Describe*" in allow
    assert "ec2:*" not in allow


def _describe_con_secretos() -> set[str]:
    """Las Describe de EC2 cuya respuesta trae `UserData` o un campo sensible.

    Recorre las formas de salida del modelo de servicio de botocore. Como
    botocore esta fijado en constraints.txt, una Describe nueva aparece
    justo al actualizarlo, y entonces este calculo cambia.
    """
    modelo = botocore.session.get_session().get_service_model("ec2")

    def tiene(forma, vistas) -> bool:
        if forma is None or forma.name in vistas:
            return False
        vistas = vistas | {forma.name}
        if forma.type_name == "structure":
            return any(
                nombre == "UserData" or getattr(m, "serialization", {}).get("sensitive")
                or m.metadata.get("sensitive") or tiene(m, vistas)
                for nombre, m in forma.members.items()
            )
        if forma.type_name == "list":
            return tiene(forma.member, vistas)
        if forma.type_name == "map":
            return tiene(forma.value, vistas)
        return bool(forma.metadata.get("sensitive"))

    return {
        f"ec2:{op}"
        for op in modelo.operation_names
        if op.startswith("Describe") and tiene(modelo.operation_model(op).output_shape, frozenset())
    }


def test_las_describe_con_secretos_son_exactamente_las_prohibidas():
    """Medido el 23-10-2026 con botocore 1.43.82: diez.

    Una primera medicion, que solo buscaba nombres de campo, dio cinco: se
    le escapaban las formas marcadas sensibles con otro nombre (la clave
    precompartida de una VPN, las URL prefirmadas de las importaciones).
    """
    prohibidas_ec2 = {a for a in ACCIONES_PROHIBIDAS if a.startswith("ec2:Describe")}
    assert _describe_con_secretos() == prohibidas_ec2
    assert len(prohibidas_ec2) == 10


def test_el_techo_niega_las_describe_con_secretos():
    gemela = _sentencia("GemelaDeAccionesProhibidasDelCodigo")["Action"]
    assert _describe_con_secretos() <= set(gemela)


@pytest.mark.parametrize("tipo", ["escritura", "administracion"])
def test_ec2_que_no_es_lectura_se_rechaza_antes_del_modelo(con_techo, tipo):
    motivos, _ = orquestador.chequeos_previos(_solicitud("ec2", "todas-las-instancias", tipo))
    assert any("solo se concede para lectura" in m for m in motivos)


@pytest.mark.parametrize("ejemplo", ["solicitud-ec2.json", "solicitud-ec2-ana.json"])
def test_los_ejemplos_de_inventario_pasan_los_chequeos_previos(con_techo, ejemplo):
    sol = SolicitudEstructurada.model_validate_json((_RAIZ / "ejemplos" / ejemplo).read_text())
    motivos, _ = orquestador.chequeos_previos(sol)
    assert motivos == []


def test_s3_con_escritura_sigue_pasando(con_techo):
    motivos, _ = orquestador.chequeos_previos(_solicitud("s3", "finanzas-2026", "escritura"))
    assert motivos == []


@pytest.mark.parametrize("accion", ["ec2:GetConsoleOutput", "ec2:GetPasswordData", "ec2:GetLaunchTemplateData"])
def test_una_lectura_de_ec2_que_no_es_describe_se_bloquea_despues(accion):
    bloqueos, _ = coherencia.chequeos_posteriores(
        _propuesta([accion], ["*"]), _solicitud("ec2", "todas-las-instancias"), _IDENTIDAD
    )
    assert any("solo concede inventario" in b for b in bloqueos)


def test_una_describe_de_inventario_pasa(monkeypatch):
    # Sin este doble el nivel salia del catalogo real, descargado o en duda
    # segun la maquina (lo destapo el guardian de urllib, O3, 24-10-2026).
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: False)
    bloqueos, _ = coherencia.chequeos_posteriores(
        _propuesta(["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"], ["*"]),
        _solicitud("ec2", "todas-las-instancias"), _IDENTIDAD,
    )
    assert bloqueos == []


@pytest.mark.parametrize("accion", ["ec2:Describe*", "ec2:DescribeInstance*", "ec2:DescribeInstanceAttribute"])
def test_un_comodin_que_cubre_una_describe_con_secretos_se_bloquea(monkeypatch, accion):
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    doc = {"Statement": [{"Effect": "Allow", "Action": [accion], "Resource": ["*"]}]}
    assert any("esta prohibida" in b for b in _revisar_lista_negra(doc))


# --- D1: sin gestion de permisos ---------------------------------------------


def _catalogo(acciones: dict[str, bool]) -> dict:
    return {"Actions": [
        {"Name": n, "Annotations": {"Properties": {"IsPermissionManagement": pm}}} for n, pm in acciones.items()
    ]}


def test_d1_toma_la_gestion_de_permisos_de_lo_que_el_allow_deja_pasar():
    catalogos = {s: _catalogo({}) for s in SERVICIOS_PERMITIDOS}
    catalogos["s3"] = _catalogo({"PutBucketPolicy": True, "GetObject": False, "PutBucketAcl": True})
    catalogos["lambda"] = _catalogo({"AddPermission": True, "AddLayerVersionPermission": True})
    # De ec2 el Allow solo deja Describe*: su gestion de permisos sobra.
    catalogos["ec2"] = _catalogo({"ModifySnapshotAttribute": True, "DescribeAlgoPermiso": True})
    assert generar_techo.gestion_de_permisos(catalogos) == [
        "s3:PutBucketAcl",
        "s3:PutBucketPolicy",
        "ec2:DescribeAlgoPermiso",
        # lambda:AddPermission ya lo niega la gemela: no se repite.
        "lambda:AddLayerVersionPermission",
    ]


def test_d1_cubre_los_ejemplos_del_adr():
    negadas = set(_sentencia("SinGestionDePermisos")["Action"]) | set(
        _sentencia("GemelaDeAccionesProhibidasDelCodigo")["Action"]
    )
    for accion in ["s3:PutBucketPolicy", "s3:PutBucketAcl", "lambda:AddPermission",
                   "sqs:AddPermission", "sns:SetTopicAttributes", "dynamodb:PutResourcePolicy"]:
        assert accion in negadas, accion


def test_d1_solo_niega_acciones_que_el_allow_deja_pasar():
    allow = _sentencia("AlcanceDelSistema")["Action"]
    for accion in _sentencia("SinGestionDePermisos")["Action"]:
        assert any(fnmatchcase(accion.lower(), p.lower()) for p in allow), accion


# --- D2: nada sobre los recursos del sistema ---------------------------------


def _patrones_del_despliegue() -> list[str]:
    """Los ARN de los Allow del rol de despliegue, en los 8 servicios."""
    plantilla = yaml.safe_load((_RAIZ / "infra/cfn/arranque.yaml").read_text())
    patrones = []
    for nombre in ("PoliticaAlmacen", "PoliticaComputo"):
        for st in plantilla["Resources"][nombre]["Properties"]["PolicyDocument"]["Statement"]:
            recursos = st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]
            for r in recursos:
                r = r["Fn::Sub"] if isinstance(r, dict) else r
                if r != "*" and r.split(":")[2] in SERVICIOS_PERMITIDOS:
                    patrones.append(r.replace("${AWS::AccountId}", _CUENTA))
    return patrones


def test_el_despliegue_tiene_patrones_que_comparar():
    assert len(_patrones_del_despliegue()) >= 9


def test_d2_cubre_todo_lo_que_el_rol_de_despliegue_puede_crear():
    """Si alguien anade un tipo de recurso al despliegue, esto se pone en rojo."""
    negados = _sentencia("NadaSobreLosRecursosDelSistema")
    assert negados["Action"] == "*"
    sin_cubrir = [
        p for p in _patrones_del_despliegue()
        if not p.endswith(":event-source-mapping:*")
        and not any(fnmatchcase(p, n) for n in negados["Resource"])
    ]
    assert sin_cubrir == []


def test_d2_los_disparadores_se_niegan_por_la_funcion_a_la_que_apuntan():
    """El despliegue crea `event-source-mapping:*`, que no lleva nombre."""
    assert any(p.endswith(":event-source-mapping:*") for p in _patrones_del_despliegue())
    st = _sentencia("NiLosDisparadoresDelSistema")
    assert st["Condition"] == {"ArnLike": {"lambda:FunctionArn": "arn:aws:lambda:*:*:function:agente-iam-*"}}
    assert {"lambda:CreateEventSourceMapping", "lambda:UpdateEventSourceMapping",
            "lambda:DeleteEventSourceMapping"} <= set(st["Action"])


@pytest.mark.parametrize("recurso", [
    "arn:aws:s3:::agente-iam-paquete-111122223333",
    "arn:aws:s3:::agente-iam-paquete-111122223333/agente.zip",
    "arn:aws:dynamodb:us-east-1:111122223333:table/agente-iam-solicitudes",
    "arn:aws:dynamodb:us-east-1:111122223333:table/agente-iam-solicitudes/stream/2026-10-23T00:00:00.000",
    "arn:aws:logs:us-east-1:111122223333:log-group:/aws/bedrock-agentcore/runtimes/agente_iam-abc:log-stream:x",
    "arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/agente-iam-aplicador",
])
def test_d2_el_patron_alcanza_los_recursos_reales(recurso):
    assert any(fnmatchcase(recurso, n) for n in _sentencia("NadaSobreLosRecursosDelSistema")["Resource"])


# --- D3: el mismo bloqueo en el codigo ---------------------------------------


@pytest.mark.parametrize("recurso", [
    "agente-iam-paquete-111122223333",
    "agente-iam-solicitudes",
    "AgenteIAM-Aplicador",
    "/aws/lambda/agente-iam-aplicador",
    "/aws/bedrock-agentcore/runtimes/agente_iam-abc",
])
def test_d3_un_recurso_del_sistema_se_rechaza_antes_del_modelo(con_techo, recurso):
    motivos, _ = orquestador.chequeos_previos(_solicitud("s3", recurso, "escritura"))
    assert any("es del propio sistema" in m for m in motivos)


@pytest.mark.parametrize("recurso", ["finanzas-2026", "mis-datos-agente-iam", "agente-ventas"])
def test_d3_lo_que_solo_se_parece_pasa(con_techo, recurso):
    motivos, _ = orquestador.chequeos_previos(_solicitud("s3", recurso, "escritura"))
    assert motivos == []


def test_d3_el_recurso_pedido_dentro_de_un_bucket_del_sistema_se_bloquea_despues(monkeypatch):
    """Hasta el 24-10-2026 la coherencia de recurso lo dejaba pasar
    (`finanzas-2026` era componente completo) y este test lo afirmaba. Con
    la regla de posicion (S2) ya la frena el chequeo 4: el bucket es otro.
    El D3 lo sigue frenando por su cuenta, que es lo que se fija aqui."""
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: False)
    recurso = "arn:aws:s3:::agente-iam-paquete-111122223333/finanzas-2026"
    assert coherencia.fuera_del_recurso(recurso, "s3", "finanzas-2026", "us-east-1", _CUENTA)
    bloqueos, _ = coherencia.chequeos_posteriores(
        _propuesta(["s3:PutObject"], [recurso]), _solicitud("s3", "finanzas-2026", "escritura"), _IDENTIDAD
    )
    assert any("recurso del propio sistema" in b for b in bloqueos)


def test_d3_un_bucket_ajeno_no_es_del_sistema():
    assert coherencia.del_sistema("arn:aws:s3:::finanzas-2026/agente/informe.csv") is None
    assert coherencia.del_sistema("arn:aws:s3:::mis-datos-agente-iam") is None


# --- S3 (24-10-2026): sin escrituras de alcance de cuenta --------------------


def _catalogo_completo(acciones: dict[str, dict]) -> dict:
    """Acciones con Resources y propiedades, como en la referencia."""
    return {"Actions": [
        {"Name": n, "Resources": [{"Name": "x"}] if d.get("recurso") else [],
         "Annotations": {"Properties": {k: v for k, v in d.items() if k != "recurso"}}}
        for n, d in acciones.items()
    ]}


def test_s3_toma_las_escrituras_sin_recurso_de_lo_que_el_allow_deja_pasar(monkeypatch):
    monkeypatch.setattr(generar_techo, "ESCRITURAS_SIN_RECURSO_PERMITIDAS", {"logs:PutPermitida": "prueba"})
    catalogos = {s: _catalogo_completo({}) for s in SERVICIOS_PERMITIDOS}
    catalogos["logs"] = _catalogo_completo({
        "PutAccountPolicy": {"IsWrite": True},                 # de cuenta: se niega
        "PutLogEvents": {"IsWrite": True, "recurso": True},    # tiene recurso: no
        "DescribeLogGroups": {"IsList": True},                 # lectura: no
        "TagAlgo": {"IsTaggingOnly": True},                    # etiquetado sin recurso: se niega
        "PutResourcePolicy": {"IsWrite": True, "IsPermissionManagement": True},  # es de D1
        "PutPermitida": {"IsWrite": True},                     # lista blanca de config
    })
    # De ec2 el Allow solo deja Describe*: su escritura sin recurso sobra.
    catalogos["ec2"] = _catalogo_completo({"RunInstances": {"IsWrite": True}})
    # lambda:UpdateFunctionCode es de la gemela: no se repite.
    catalogos["lambda"] = _catalogo_completo({"UpdateFunctionCode": {"IsWrite": True},
                                              "CreateEventSourceMapping": {"IsWrite": True}})
    assert generar_techo.escrituras_sin_recurso(catalogos, ["logs:PutResourcePolicy"]) == [
        "logs:PutAccountPolicy", "logs:TagAlgo", "lambda:CreateEventSourceMapping",
    ]


def test_s3_agrupa_por_prefijo_solo_si_todo_lo_que_cubre_ya_se_niega():
    todos = ["CreatePlatformApplication", "CreatePlatformEndpoint", "CreateTopic", "StartA", "StartB"]
    negadas = {"createplatformapplication", "createplatformendpoint", "starta"}
    # `Create*` cubriria CreateTopic, que no se niega; `CreatePlatform*` no.
    assert generar_techo._comprimir(
        ["CreatePlatformApplication", "CreatePlatformEndpoint", "StartA"], todos, negadas
    ) == ["CreatePlatform*", "StartA"]


def test_s3_cada_patron_del_techo_es_una_accion_o_un_prefijo_de_su_servicio():
    for accion in _sentencia("SinEscriturasDeAlcanceDeCuenta")["Action"]:
        servicio, nombre = accion.split(":", 1)
        assert servicio in SERVICIOS_PERMITIDOS, accion
        assert servicio != "ec2", accion
        assert "*" not in nombre[:-1], accion
        assert nombre != "*", accion


@pytest.mark.parametrize("accion", [
    "logs:PutAccountPolicy", "logs:DeleteAccountPolicy", "dynamodb:PurchaseReservedCapacityOfferings",
    "sns:SetSMSAttributes", "s3:PutStorageLensConfiguration", "cloudwatch:PutManagedInsightRules",
    "lambda:CreateCodeSigningConfig", "lambda:CreateEventSourceMapping",
])
def test_s3_las_acciones_de_cuenta_del_informe_estan_negadas(accion):
    """Las del informe del 24-10-2026, con el JSON generado desde la
    referencia de ese dia. Si AWS les da tipo de recurso, dejaran de salir
    al regenerar y esto lo dira."""
    negadas = _sentencia("SinEscriturasDeAlcanceDeCuenta")["Action"]
    assert any(fnmatchcase(accion.lower(), n.lower()) for n in negadas), accion


# --- S5 (24-10-2026): solo recursos de la propia cuenta ----------------------


def test_s5_el_techo_niega_los_recursos_de_otra_cuenta():
    st = _sentencia("SoloRecursosDeLaPropiaCuenta")
    assert st["Effect"] == "Deny"
    assert st["Resource"] == "*"
    assert st["Action"] == [f"{s}:*" for s in SERVICIOS_PERMITIDOS]
    # Variable de politica: el techo no lleva ninguna cuenta escrita.
    assert st["Condition"] == {"StringNotEqualsIfExists": {"aws:ResourceAccount": "${aws:PrincipalAccount}"}}
    assert not re.search(r"\d{12}", json.dumps(st))


def test_cfn_lint_solo_se_calla_w3037_y_solo_en_el_techo():
    """El techo sale de la referencia del dia y cfn-lint trae una lista de
    acciones mas vieja (W3037). Callar mas reglas, o en mas recursos,
    esconderia errores de verdad."""
    plantilla = yaml.safe_load((_RAIZ / "infra/cfn/arranque.yaml").read_text())
    con_metadatos = {n: r["Metadata"] for n, r in plantilla["Resources"].items() if "Metadata" in r}
    assert con_metadatos == {"Techo": {"cfn-lint": {"config": {"ignore_checks": ["W3037"]}}}}
