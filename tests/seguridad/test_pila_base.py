"""Pila base (`infra/cfn/base.yaml`, Fase 18): la tabla y quien escribe en ella.

Lo que fijan estos tests es el reparto del mapa del flujo
(`local/mapas/solicitud-por-la-tabla.md`): un atributo por actor, y cada rol
solo puede tocar los suyos.

  - Nadie reemplaza ni borra filas: ni `PutItem` (reemplaza la fila entera y
    `dynamodb:Attributes` no lo limita), ni `DeleteItem`, ni `BatchWriteItem`.
  - Cada `UpdateItem` lleva su lista exacta y el `Null` en falso (sin el,
    `ForAllValues` con la clave ausente da verdadero y la condicion no frena).
  - Lo que el codigo escribe cabe en esa lista: si `almacen` nombrara otro
    atributo, en la cuenta seria un AccessDenied.
  - Solo el rol de la Lambda de aprobacion (ADR-003) escribe `aprobacion` y
    `rechazo`; ni el runtime ni el aplicador.
  - La URL de esa Lambda exige firma (`AWS_IAM`) y no hay ningun
    `AWS::Lambda::Permission`: la persona y la funcion estan en la misma
    cuenta y basta su politica de identidad.
  - Lo que concede el rol de la aprobacion cabe en `AgenteIAM-LimiteSistema`.
  - La tabla sobrevive a la pila, y los roles nacen con su limite.
  - El aplicador de la pila es el de `infra/rol-aplicador-permisos.json`: mismos
    permisos de IAM, mas los de la tabla.
  - Fase 23 (26-10-2026): el aplicador crea roles de persona, y solo en la ruta
    `/agente-iam/personas/` y solo con el techo como boundary.
"""

import json
import re
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

from agente_iam import almacen
from tests.dobles import resolver_sub, sentencias_de_rol

RAIZ = Path(__file__).resolve().parents[2]
CUENTA = "111122223333"
TABLA = f"arn:aws:dynamodb:us-east-1:{CUENTA}:table/agente-iam-solicitudes"
ROLES = ("RolRuntime", "RolAplicador", "RolAprobacion")
# El rol de los avisos (Fase 23, bloque 3) no toca la tabla: no tiene UpdateItem, asi que no entra en ROLES (que
# alimenta `_update`), pero si en lo que vale para todo rol del sistema: el Deny de filas, el limite y el boundary.
ROLES_SIN_TABLA = ("RolAvisos",)
# identity/* y no la del remitente: SES autoriza SendEmail tambien contra la identidad del destinatario (MEDICIONES O.5).
IDENTIDADES_SES = f"arn:aws:ses:us-east-1:{CUENTA}:identity/*"
RUTA_PERSONAS = f"arn:aws:iam::{CUENTA}:role/agente-iam/personas/*"
TECHO = f"arn:aws:iam::{CUENTA}:policy/AgenteIAM-Techo"
ATRIBUTOS = {
    "RolRuntime": ["id", "documento", "estado"],
    "RolAplicador": ["id", "estado", "aplicacion"],
    "RolAprobacion": ["id", "estado", "aprobacion", "rechazo"],
}


def _base() -> dict:
    return yaml.safe_load((RAIZ / "infra" / "cfn" / "base.yaml").read_text(encoding="utf-8"))


def _acciones(s: dict) -> list[str]:
    return [s["Action"]] if isinstance(s["Action"], str) else s["Action"]


def _permitidas(recurso: str) -> set[str]:
    return {a for s in sentencias_de_rol(_base(), recurso) if s["Effect"] == "Allow" for a in _acciones(s)}


def _denegadas(recurso: str) -> set[str]:
    return {a for s in sentencias_de_rol(_base(), recurso) if s["Effect"] == "Deny" for a in _acciones(s)}


def _update(recurso: str) -> dict:
    [s] = [s for s in sentencias_de_rol(_base(), recurso) if s["Effect"] == "Allow" and "dynamodb:UpdateItem" in _acciones(s)]
    return s


def test_ningun_rol_puede_reemplazar_ni_borrar_filas():
    prohibidas = {"dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem"}
    # PartiQL (ExecuteStatement) escribe filas por otro camino, y los cambios de tabla (TTL, backups
    # continuos) borran o dejan sin rastro: mismo Deny que PutItem (ruling de la Tarea 7, 24-10-2026).
    por_otros_caminos = {"dynamodb:PartiQL*", "dynamodb:UpdateTimeToLive", "dynamodb:UpdateContinuousBackups"}
    for rol in ROLES + ROLES_SIN_TABLA:
        assert not prohibidas & _permitidas(rol), rol
        assert prohibidas | {"dynamodb:DeleteTable", "dynamodb:UpdateTable"} | por_otros_caminos <= _denegadas(rol), rol


def test_cada_update_lleva_su_lista_de_atributos():
    for rol, atributos in ATRIBUTOS.items():
        s = _update(rol)
        assert s["Resource"] == TABLA, rol
        assert s["Condition"]["ForAllValues:StringEquals"]["dynamodb:Attributes"] == atributos, rol
        assert s["Condition"]["Null"] == {"dynamodb:Attributes": "false"}, rol
        # Sin esto, ReturnValues ALL_NEW o ALL_OLD devuelve la fila entera, bloques ajenos incluidos.
        assert s["Condition"]["StringEqualsIfExists"] == {"dynamodb:ReturnValues": ["NONE", "UPDATED_OLD", "UPDATED_NEW"]}, rol
        assert set(s["Condition"]) == {"ForAllValues:StringEquals", "Null", "StringEqualsIfExists"}, rol
        assert _acciones(s) == ["dynamodb:UpdateItem"], rol


# Toda accion que escribe filas. Un Allow que cubra cualquiera de ellas, con
# comodin o sin el, fuera de la unica sentencia condicionada, se salta la lista.
_ESCRITURAS_DE_FILAS = [
    "dynamodb:UpdateItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem",
    "dynamodb:PartiQLInsert", "dynamodb:PartiQLUpdate", "dynamodb:PartiQLDelete", "dynamodb:TransactWriteItems",
]


def test_ninguna_otra_sentencia_escribe_filas():
    for rol in ROLES:
        for s in sentencias_de_rol(_base(), rol):
            if s["Effect"] != "Allow" or s.get("Sid") in ("EscribirSoloSusAtributos", "EscribirSoloLaDecision"):
                continue
            for patron in _acciones(s):
                cubiertas = [w for w in _ESCRITURAS_DE_FILAS if fnmatchcase(w, patron)]
                assert not cubiertas, (rol, s.get("Sid"), patron, cubiertas)


_PALABRAS_DE_CONDICION = {"attribute_not_exists", "attribute_exists", "and", "or", "not"}


def test_lo_que_escribe_el_codigo_cabe_en_su_rol(monkeypatch):
    """El intake (runtime), la aplicacion (aplicador), la aprobacion y el rechazo (Lambda de aprobacion), con la llamada real de `almacen`."""
    llamadas: list[dict] = []

    class _Tabla:
        def update_item(self, **kw):
            llamadas.append(kw)
            return {}

    monkeypatch.setattr(almacen, "ALMACEN", "dynamodb")
    monkeypatch.setattr(almacen, "_tabla", _Tabla())
    almacen.guardar_propuesta({"id": "req-x", "estado": "propuesta"})
    almacen.guardar_decision({"id": "req-x", "estado": "aplicada", "aplicacion": {"cuando": "ya"}},
                             "aplicacion", "aprobada", clave="req-x")
    almacen.guardar_decision({"id": "req-x", "estado": "aprobada", "aprobacion": {"quien": "ana"}},
                             "aprobacion", "propuesta", clave="req-x")
    almacen.guardar_decision({"id": "req-x", "estado": "rechazada", "rechazo": {"motivo": "no"}},
                             "rechazo", "propuesta", clave="req-x")
    duenos = ("RolRuntime", "RolAplicador", "RolAprobacion", "RolAprobacion")
    for kw, rol in zip(llamadas, duenos, strict=True):
        nombres = {p.split(" = ")[0] for p in kw["UpdateExpression"].removeprefix("SET ").split(", ")} | set(kw["Key"])
        # dynamodb:Attributes cuenta tambien los atributos de la condicion (medido el 24-10-2026, MEDICIONES F.6).
        nombres |= set(re.findall(r"(?<![:\w])([a-z_]+)\b", kw["ConditionExpression"])) - _PALABRAS_DE_CONDICION
        assert nombres <= set(_update(rol)["Condition"]["ForAllValues:StringEquals"]["dynamodb:Attributes"]), (rol, nombres)
        assert "ReturnValues" not in kw
    # Los dos bloques de la Lambda tocan los dos atributos excluyentes: la lista tiene que traer ambos.
    assert {"aprobacion", "rechazo"} <= set(ATRIBUTOS["RolAprobacion"])


def test_solo_la_lambda_de_aprobacion_escribe_la_decision():
    listas = {rol: set(_update(rol)["Condition"]["ForAllValues:StringEquals"]["dynamodb:Attributes"]) for rol in ROLES}
    assert {"aprobacion", "rechazo"} <= listas["RolAprobacion"]
    assert not {"documento", "aplicacion"} & listas["RolAprobacion"]
    assert not {"aprobacion", "rechazo"} & (listas["RolRuntime"] | listas["RolAplicador"])
    assert "aplicacion" not in listas["RolRuntime"]
    assert "documento" not in listas["RolAplicador"]


def test_la_tabla_sobrevive_a_la_pila():
    [tabla] = [r for r in _base()["Resources"].values() if r["Type"] == "AWS::DynamoDB::Table"]
    p = tabla["Properties"]
    assert tabla["DeletionPolicy"] == "Retain"
    assert tabla["UpdateReplacePolicy"] == "Retain"
    assert p["TableName"] == "agente-iam-solicitudes"
    assert p["DeletionProtectionEnabled"] is True
    assert p["PointInTimeRecoverySpecification"]["PointInTimeRecoveryEnabled"] is True
    assert p["StreamSpecification"]["StreamViewType"] == "NEW_AND_OLD_IMAGES"
    assert p["KeySchema"] == [{"AttributeName": "id", "KeyType": "HASH"}]


def test_el_bucket_no_es_publico_y_exige_tls():
    recursos = _base()["Resources"]
    [bucket] = [r for r in recursos.values() if r["Type"] == "AWS::S3::Bucket"]
    p = bucket["Properties"]
    assert bucket["DeletionPolicy"] == "Retain"
    assert p["VersioningConfiguration"] == {"Status": "Enabled"}
    assert all(p["PublicAccessBlockConfiguration"].values())
    assert len(p["PublicAccessBlockConfiguration"]) == 4
    assert p["OwnershipControls"]["Rules"] == [{"ObjectOwnership": "BucketOwnerEnforced"}]
    [politica] = [r for r in recursos.values() if r["Type"] == "AWS::S3::BucketPolicy"]
    [s] = politica["Properties"]["PolicyDocument"]["Statement"]
    assert s["Effect"] == "Deny"
    assert s["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}


def test_los_roles_nacen_con_el_limite_del_sistema():
    for rol in ROLES + ROLES_SIN_TABLA:
        p = resolver_sub(_base()["Resources"][rol]["Properties"])
        assert p["PermissionsBoundary"] == f"arn:aws:iam::{CUENTA}:policy/AgenteIAM-LimiteSistema", rol
        assert p["RoleName"].startswith("AgenteIAM-"), rol
        assert "ManagedPolicyArns" not in p, rol


def test_el_runtime_no_escribe_en_iam_ni_tiene_check_no_new_access():
    permitidas = _permitidas("RolRuntime")
    assert not [a for a in permitidas if a.startswith("iam:") and not a.startswith(("iam:Get", "iam:List", "iam:Simulate"))]
    assert "access-analyzer:CheckNoNewAccess" not in permitidas
    assert {"iam:Create*", "iam:Attach*", "iam:Put*", "iam:PassRole", "sts:AssumeRole"} <= _denegadas("RolRuntime")
    assert "dynamodb:GetItem" not in permitidas  # el intake no lee: crea con condicion


def test_el_aplicador_no_habla_con_el_modelo():
    assert "bedrock:*" in _denegadas("RolAplicador")
    assert not [a for a in _permitidas("RolAplicador") if a.startswith("bedrock")]


def test_el_aplicador_es_el_de_su_json_mas_la_tabla():
    """Mismas sentencias de IAM que `infra/rol-aplicador-permisos.json` (en esta cuenta no hay `user/Mateo`)."""
    json_ = json.loads((RAIZ / "infra" / "rol-aplicador-permisos.json").read_text(encoding="utf-8"))["Statement"]
    for s in json_:
        # Las sentencias con NotResource (Fase 23) no tienen Resource.
        if isinstance(s.get("Resource"), list):
            s["Resource"] = [r for r in s["Resource"] if not r.endswith(":user/Mateo")]
    de_la_pila = {s["Sid"]: s for s in sentencias_de_rol(_base(), "RolAplicador")}
    for s in json_:
        assert de_la_pila.get(s["Sid"]) == s, s["Sid"]
    de_la_tabla = {"LeerLaSolicitud", "EscribirSoloSusAtributos", "LeerElStreamDeLaTabla",
                   "ListarStreamsNoTieneRecurso", "EscribirEnSuColaDeFallos", "LogsDeSuLambda",
                   "NuncaReemplazarNiBorrarFilas"}
    assert set(de_la_pila) == {s["Sid"] for s in json_} | de_la_tabla


def test_el_aplicador_crea_roles_solo_en_la_ruta_de_personas_y_solo_con_el_techo():
    """Fase 23: el aplicador crea el rol de la persona. Dos Allow (crear y etiquetar) y dos Deny.

    Los Deny: fuera de la ruta de personas (`NotResource`) y sin el techo como boundary
    (`StringNotEquals`: con la clave ausente da verdadero y deniega; MEDICIONES H 11 y 30, nunca `...IfExists`).
    Sin `UpdateAssumeRolePolicy`, `DeleteRole` ni `PassRole` en ningun Allow: el rol nace con su confianza y no se cambia.
    """
    sentencias = {s["Sid"]: s for s in sentencias_de_rol(_base(), "RolAplicador")}
    crear = sentencias["CrearRolesDePersonaSoloConElTecho"]
    assert crear["Effect"] == "Allow"
    assert _acciones(crear) == ["iam:CreateRole"]
    assert crear["Resource"] == RUTA_PERSONAS
    assert crear["Condition"] == {"StringEquals": {"iam:PermissionsBoundary": TECHO}}
    etiquetar = sentencias["EtiquetarYLeerRolesDePersona"]
    assert etiquetar["Effect"] == "Allow"
    assert set(_acciones(etiquetar)) == {"iam:TagRole", "iam:ListRoleTags"}
    assert etiquetar["Resource"] == RUTA_PERSONAS
    assert "Condition" not in etiquetar
    fuera = sentencias["NuncaUnRolFueraDeLaRutaDePersonas"]
    assert fuera["Effect"] == "Deny"
    assert _acciones(fuera) == ["iam:CreateRole"]
    assert fuera["NotResource"] == RUTA_PERSONAS
    assert "Resource" not in fuera
    sin_techo = sentencias["NuncaUnRolDePersonaSinElTecho"]
    assert sin_techo["Effect"] == "Deny"
    assert _acciones(sin_techo) == ["iam:CreateRole"]
    assert sin_techo["Resource"] == "*"
    assert sin_techo["Condition"] == {"StringNotEquals": {"iam:PermissionsBoundary": TECHO}}
    for s in sentencias.values():
        if s["Effect"] == "Deny":
            assert not any(op.endswith("IfExists") for op in s.get("Condition", {})), s["Sid"]
    # El unico Allow de CreateRole es el de la ruta de personas; el Deny general ya no lo lista.
    assert [sid for sid, s in sentencias.items() if s["Effect"] == "Allow" and "iam:CreateRole" in _acciones(s)] == [
        "CrearRolesDePersonaSoloConElTecho"]
    assert "iam:CreateRole" not in _acciones(sentencias["NuncaCrearIdentidadesNiEscalar"])
    permitidas = _permitidas("RolAplicador")
    assert not {"iam:UpdateAssumeRolePolicy", "iam:DeleteRole", "iam:PassRole"} & permitidas
    # Lo demas de NuncaCrearIdentidadesNiEscalar se conserva.
    assert set(_acciones(sentencias["NuncaCrearIdentidadesNiEscalar"])) >= {
        "iam:CreateUser", "iam:CreateGroup", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
        "iam:AddUserToGroup", "iam:UpdateAssumeRolePolicy", "iam:CreateServiceLinkedRole", "iam:PassRole",
        "organizations:*", "sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity",
        "sts:GetFederationToken"}


def test_el_aplicador_lista_roles_para_el_tope_y_no_gana_ninguna_escritura_con_asterisco():
    """`iam:ListRoles` no admite recurso, asi que es un Allow con `*`; el tope por persona al aplicar lo necesita.

    Es la unica accion de IAM nueva con `*`: junto a las de lectura de `LeerYRevalidarEnElMomentoDeAplicar` y
    a Attach*, que ya llevan su condicion. Ninguna escritura de IAM se concede sin acotar.
    """
    sentencias = {s["Sid"]: s for s in sentencias_de_rol(_base(), "RolAplicador")}
    lista = sentencias["ListarRolesNoTieneRecurso"]
    assert lista["Effect"] == "Allow"
    assert _acciones(lista) == ["iam:ListRoles"]
    assert lista["Resource"] == "*"
    assert "Condition" not in lista
    # Lo que el aplicador puede hacer en IAM sobre `*` y sin condicion: solo lectura.
    sin_acotar = {
        a for s in sentencias.values()
        if s["Effect"] == "Allow" and s.get("Resource") == "*" and "Condition" not in s
        for a in _acciones(s) if a.startswith("iam:")
    }
    assert "iam:ListRoles" in sin_acotar
    assert all(a.startswith(("iam:Get", "iam:List", "iam:Simulate")) for a in sin_acotar), sin_acotar
    # Y los permisos de escritura de roles siguen acotados a la ruta de personas.
    for sid in ("CrearRolesDePersonaSoloConElTecho", "EtiquetarYLeerRolesDePersona"):
        assert sentencias[sid]["Resource"] == RUTA_PERSONAS


def test_el_rol_del_runtime_no_gana_nada_con_los_roles_de_persona():
    """`iam:List*` ya cubre `ListRoles` y `ListRoleTags`: el runtime lee la ruta de personas sin sentencia nueva."""
    assert {"iam:List*", "iam:Get*"} <= _permitidas("RolRuntime")
    assert not {a for a in _permitidas("RolRuntime") if a.startswith("iam:") and a not in {"iam:Get*", "iam:List*",
            "iam:SimulatePrincipalPolicy", "iam:SimulateCustomPolicy"}}


def test_el_aplicador_solo_escribe_en_su_cola_de_fallos():
    """El disparador manda a la cola los eventos que fallan tras 2 reintentos, con el rol de la funcion."""
    con_sqs = [s for s in sentencias_de_rol(_base(), "RolAplicador") if any(a.startswith("sqs:") for a in _acciones(s))]
    [s] = con_sqs
    assert s["Sid"] == "EscribirEnSuColaDeFallos"
    assert s["Effect"] == "Allow"
    assert s["Action"] == "sqs:SendMessage"
    assert s["Resource"] == f"arn:aws:sqs:us-east-1:{CUENTA}:agente-iam-aplicador-fallos"
    assert "Condition" not in s
    # Solo el aplicador: ni el runtime ni la aprobacion escriben en colas. El
    # runtime puede buscar una cola por nombre (Fase 28, sqs:GetQueueUrl).
    for rol in ("RolRuntime", "RolAprobacion"):
        assert not [a for a in _permitidas(rol) if a.startswith("sqs:") and a != "sqs:GetQueueUrl"], rol


def test_el_runtime_tiene_exactamente_sus_sentencias_y_su_deny_de_iam_entero():
    """Las del JSON de la Fase 8 (retirado el 24-10-2026), con DynamoDB acotado."""
    sids = [s["Sid"] for s in sentencias_de_rol(_base(), "RolRuntime")]
    assert sids == ["LeerIAM", "ValidarPoliticas", "InvocarModelo", "EscribirSoloSusAtributos",
                    "NuncaReemplazarNiBorrarFilas", "LeerElPaqueteDeCodigo", "LogsDeAgentCore",
                    "ComprobarQueElRecursoExiste", "ComprobarQueElRecursoExisteSinTipoDeRecurso",
                    "TrazasYMetricasDeAgentCore", "MetricasSoloEnElNamespaceDeAgentCore", "NuncaEscribirEnIAM"]
    [deny] = [s for s in sentencias_de_rol(_base(), "RolRuntime") if s["Sid"] == "NuncaEscribirEnIAM"]
    assert deny["Effect"] == "Deny"
    assert deny["Resource"] == "*"
    assert set(_acciones(deny)) == {
        "iam:Create*", "iam:Put*", "iam:Attach*", "iam:Detach*", "iam:Delete*", "iam:Update*", "iam:Add*",
        "iam:Remove*", "iam:Set*", "iam:Tag*", "iam:Untag*", "iam:Upload*", "iam:Change*", "iam:Enable*",
        "iam:Deactivate*", "iam:Reset*", "iam:Resync*", "iam:PassRole", "organizations:*", "sts:AssumeRole",
        "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity", "sts:GetFederationToken",
    }


def test_confianza_con_cuenta_de_origen():
    servicios = {"RolRuntime": "bedrock-agentcore.amazonaws.com", "RolAplicador": "lambda.amazonaws.com",
                 "RolAprobacion": "lambda.amazonaws.com", "RolAvisos": "lambda.amazonaws.com"}
    for rol, servicio in servicios.items():
        [s] = resolver_sub(_base()["Resources"][rol]["Properties"]["AssumeRolePolicyDocument"])["Statement"]
        assert s["Principal"] == {"Service": servicio}, rol
        assert s["Action"] == "sts:AssumeRole", rol
        assert s["Condition"]["StringEquals"] == {"aws:SourceAccount": CUENTA}, rol
    [s] = resolver_sub(_base()["Resources"]["RolRuntime"]["Properties"]["AssumeRolePolicyDocument"])["Statement"]
    assert s["Condition"]["ArnLike"] == {"aws:SourceArn": f"arn:aws:bedrock-agentcore:us-east-1:{CUENTA}:*"}
    # El rol de la aprobacion solo lo asume SU funcion, no cualquiera de agente-iam-*: es el unico que escribe la decision.
    [s] = resolver_sub(_base()["Resources"]["RolAprobacion"]["Properties"]["AssumeRolePolicyDocument"])["Statement"]
    assert s["Condition"]["ArnEquals"] == {"aws:SourceArn": f"arn:aws:lambda:us-east-1:{CUENTA}:function:agente-iam-aprobacion"}
    assert set(s["Condition"]) == {"StringEquals", "ArnEquals"}
    # El aplicador NO lleva aws:SourceArn: el event source mapping del stream valida la confianza sin
    # aportarlo y rechaza el rol si lo exige (medido el 25-10-2026, docs/MEDICIONES.md). No volver a ponerlo.
    [s] = resolver_sub(_base()["Resources"]["RolAplicador"]["Properties"]["AssumeRolePolicyDocument"])["Statement"]
    assert s["Condition"] == {"StringEquals": {"aws:SourceAccount": CUENTA}}
    # Igual el de los avisos: lo dispara un event source mapping, que no aporta aws:SourceArn.
    [s] = resolver_sub(_base()["Resources"]["RolAvisos"]["Properties"]["AssumeRolePolicyDocument"])["Statement"]
    assert s["Condition"] == {"StringEquals": {"aws:SourceAccount": CUENTA}}


# --- La Lambda de aprobacion (ADR-003, A) -----------------------------------


def _recursos(tipo: str) -> dict:
    return {n: r for n, r in _base()["Resources"].items() if r["Type"] == tipo}


def _funcion() -> dict:
    return _base()["Resources"]["FuncionAprobacion"]["Properties"]


def test_la_url_exige_firma_y_nadie_mas_la_abre():
    [(nombre, url)] = _recursos("AWS::Lambda::Url").items()
    p = url["Properties"]
    assert p["AuthType"] == "AWS_IAM"
    assert p["TargetFunctionArn"] == {"Fn::GetAtt": ["FuncionAprobacion", "Arn"]}
    assert "Cors" not in p, nombre  # la llama la CLI firmada, no un navegador
    # Persona y funcion estan en la misma cuenta: basta la politica de identidad del permission set.
    # Un Permission con Principal '*' o con el de otra cuenta abriria la URL.
    assert _recursos("AWS::Lambda::Permission") == {}
    salidas = _base()["Outputs"]
    assert salidas["UrlAprobacion"]["Value"] == {"Fn::GetAtt": ["UrlAprobacion", "FunctionUrl"]}
    assert salidas["FuncionAprobacionArn"]["Value"] == {"Fn::GetAtt": ["FuncionAprobacion", "Arn"]}
    assert salidas["RolAprobacionArn"]["Value"] == {"Fn::GetAtt": ["RolAprobacion", "Arn"]}


def test_la_funcion_es_la_que_espera_el_codigo():
    p = resolver_sub(_funcion())
    assert p["FunctionName"] == "agente-iam-aprobacion"
    assert p["Handler"] == "agente_iam.aprobar.manejador"
    assert p["Runtime"] == "python3.12"
    assert p["Architectures"] == ["arm64"]
    assert p["Timeout"] == 60
    assert p["MemorySize"] == 512
    assert p["Role"] == {"Fn::GetAtt": ["RolAprobacion", "Arn"]}
    assert p["Code"] == {"S3Bucket": f"agente-iam-despliegue-{CUENTA}", "S3Key": {"Ref": "ClaveCodigoAprobacion"}}
    # Sin AWS_REGION: la pone Lambda y es una variable reservada (el despliegue fallaria).
    assert p["Environment"]["Variables"] == {
        "ALMACEN": "dynamodb",
        "TABLA_SOLICITUDES": "agente-iam-solicitudes",
        "DIR_CACHE_CATALOGO": "/var/task/catalogo",
    }
    assert "VpcConfig" not in p  # revalida contra el catalogo de AWS: necesita internet
    parametro = _base()["Parameters"]["ClaveCodigoAprobacion"]
    assert parametro["Type"] == "String"
    assert "Default" not in parametro
    patron = parametro["AllowedPattern"]
    assert re.fullmatch(patron, "agente-iam/aprobacion-0123456789ab.zip")
    assert not re.fullmatch(patron, "agente-iam/aprobacion-0123456789ab.zip.evil")
    assert not re.fullmatch(patron, "otra/aprobacion-0123456789ab.zip")
    assert not re.fullmatch(patron, "agente-iam/aprobacion-0123456789AB.zip")


def test_los_logs_de_la_aprobacion_se_conservan_y_la_funcion_los_usa():
    recursos = _base()["Resources"]
    grupo = recursos["RegistroAprobacion"]
    assert grupo["Type"] == "AWS::Logs::LogGroup"
    assert grupo["DeletionPolicy"] == "Retain"
    assert grupo["UpdateReplacePolicy"] == "Retain"
    assert grupo["Properties"]["LogGroupName"] == "/aws/lambda/agente-iam-aprobacion"
    assert grupo["Properties"]["RetentionInDays"] == 365
    # Si la funcion corriera antes que el grupo, Lambda crearia el suyo, sin retencion y fuera de la pila.
    depende = recursos["FuncionAprobacion"].get("DependsOn", [])
    depende = [depende] if isinstance(depende, str) else depende
    registro = _funcion().get("LoggingConfig", {}).get("LogGroup")
    assert "RegistroAprobacion" in depende or registro == {"Ref": "RegistroAprobacion"}


def test_la_aprobacion_no_escribe_en_iam_ni_habla_con_el_modelo():
    permitidas = _permitidas("RolAprobacion")
    assert not [a for a in permitidas if a.startswith(("bedrock", "sts:", "organizations:"))]
    assert not [a for a in permitidas if a.startswith("iam:") and not a.startswith(("iam:Get", "iam:List"))]
    assert "bedrock:*" in _denegadas("RolAprobacion")
    [deny] = [s for s in sentencias_de_rol(_base(), "RolAprobacion") if s["Sid"] == "NuncaEscribirEnIAM"]
    [del_runtime] = [s for s in sentencias_de_rol(_base(), "RolRuntime") if s["Sid"] == "NuncaEscribirEnIAM"]
    assert deny == del_runtime  # la misma lista que el runtime, sin copia a mano que se desvie


def test_la_aprobacion_tiene_exactamente_sus_sentencias():
    sentencias = {s["Sid"]: s for s in sentencias_de_rol(_base(), "RolAprobacion")}
    assert list(sentencias) == ["LeerLaSolicitud", "EscribirSoloLaDecision", "RevalidarConLasReglasDeHoy",
                                "AccessAnalyzerNoTieneRecurso", "LogsDeSuLambda", "NuncaReemplazarNiBorrarFilas",
                                "NuncaEscribirEnIAM", "NuncaHablarConElModelo"]
    assert _acciones(sentencias["LeerLaSolicitud"]) == ["dynamodb:GetItem"]
    assert sentencias["LeerLaSolicitud"]["Resource"] == TABLA
    assert set(_acciones(sentencias["RevalidarConLasReglasDeHoy"])) == {
        "iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetRole", "iam:GetUser", "iam:ListAttachedRolePolicies",
        "iam:ListAttachedUserPolicies", "iam:ListRolePolicies", "iam:ListUserPolicies"}
    assert sentencias["RevalidarConLasReglasDeHoy"]["Resource"] == [
        f"arn:aws:iam::{CUENTA}:policy/*", f"arn:aws:iam::{CUENTA}:role/*", f"arn:aws:iam::{CUENTA}:user/*"]
    assert set(_acciones(sentencias["AccessAnalyzerNoTieneRecurso"])) == {
        "access-analyzer:ValidatePolicy", "access-analyzer:CheckNoNewAccess"}
    # Solo su grupo de logs (lo crea la pila): CreateLogGroup sobra y un comodin dejaria escribir en el de otro.
    logs = sentencias["LogsDeSuLambda"]
    assert set(_acciones(logs)) == {"logs:CreateLogStream", "logs:PutLogEvents"}
    assert logs["Resource"] == f"arn:aws:logs:us-east-1:{CUENTA}:log-group:/aws/lambda/agente-iam-aprobacion:*"


def _acciones_del_limite() -> list[str]:
    plantilla = yaml.safe_load((RAIZ / "infra" / "cfn" / "arranque.yaml").read_text(encoding="utf-8"))
    sentencias = plantilla["Resources"]["LimiteSistema"]["Properties"]["PolicyDocument"]["Statement"]
    return [a for s in sentencias if s["Effect"] == "Allow" for a in _acciones(s)]


def _sentencias_del_limite() -> list[dict]:
    plantilla = yaml.safe_load((RAIZ / "infra" / "cfn" / "arranque.yaml").read_text(encoding="utf-8"))
    sentencias = plantilla["Resources"]["LimiteSistema"]["Properties"]["PolicyDocument"]["Statement"]
    return [resolver_sub(s) for s in sentencias if s["Effect"] == "Allow"]


def test_todo_lo_que_concede_la_aprobacion_cabe_en_el_limite_del_sistema():
    """Un Allow del rol que el boundary no permite no hace nada en la cuenta: la funcion fallaria al llamarlo.

    Vale para los cuatro roles del sistema, el de los avisos incluido (Fase 23, bloque 3).
    """
    limite = _acciones_del_limite()
    assert limite  # el test no es vacuo
    for rol in ROLES + ROLES_SIN_TABLA:
        for accion in _permitidas(rol):
            assert any(fnmatchcase(accion, patron) for patron in limite), (rol, accion)


def test_lo_que_concede_el_rol_de_avisos_cabe_tambien_en_el_recurso_del_limite():
    """`ses:SendEmail` esta en `LimiteSistema` (Sid `AvisarPorCorreo`, 26-10-2026) solo sobre identidades de esta cuenta
    y de us-east-1: la identidad del remitente del rol tiene que caer dentro de ese recurso, o el limite la recortaria."""
    [aviso] = [s for s in _sentencias_del_limite() if s.get("Sid") == "AvisarPorCorreo"]
    assert _acciones(aviso) == ["ses:SendEmail"]
    assert "Condition" not in aviso  # si el limite pidiera condicion, el rol de avisos tendria que cumplirla tambien
    [envio] = [s for s in sentencias_de_rol(_base(), "RolAvisos") if s.get("Sid") == "EnviarSoloDesdeElRemitente"]
    recursos = [aviso["Resource"]] if isinstance(aviso["Resource"], str) else aviso["Resource"]
    assert any(fnmatchcase(envio["Resource"], patron) for patron in recursos), (envio["Resource"], recursos)
    # Y el resto de lo que concede el rol de avisos (stream, logs) tiene su accion en el limite, ya cubierto arriba.
    for s in sentencias_de_rol(_base(), "RolAvisos"):
        if s["Effect"] == "Allow" and s["Sid"] != "EnviarSoloDesdeElRemitente":
            assert not any(a.startswith("ses:") for a in _acciones(s)), s["Sid"]


def test_la_politica_del_bucket_sobrevive_a_la_pila():
    politica = _base()["Resources"]["PoliticaBucketPaquete"]
    assert politica["Type"] == "AWS::S3::BucketPolicy"
    assert politica["DeletionPolicy"] == "Retain"
    assert politica["UpdateReplacePolicy"] == "Retain"


# --- La Lambda de avisos (Fase 23, bloque 3, 26-10-2026) ----------------------


def test_el_correo_remitente_no_tiene_valor_por_defecto():
    """Es un dato personal: entra al desplegar, nunca va en el repositorio. Y tiene forma de correo."""
    parametro = _base()["Parameters"]["CorreoRemitente"]
    assert parametro["Type"] == "String"
    assert "Default" not in parametro
    assert re.fullmatch(parametro["AllowedPattern"], "avisos@ejemplo.org")
    assert not re.fullmatch(parametro["AllowedPattern"], "no-es-un-correo")
    assert not re.fullmatch(parametro["AllowedPattern"], "dos@@ejemplo.org")
    assert not re.fullmatch(parametro["AllowedPattern"], "con espacio@ejemplo.org")


def test_el_rol_de_avisos_solo_manda_desde_el_remitente_y_no_toca_tabla_ni_iam():
    """Manda correo desde una identidad y nada mas: ni lee la tabla ni la escribe, ni toca IAM ni habla con el modelo."""
    recurso = _base()["Resources"]["RolAvisos"]
    assert recurso["Type"] == "AWS::IAM::Role"
    p = resolver_sub(recurso["Properties"])
    assert p["RoleName"] == "AgenteIAM-Avisos"
    assert p["PermissionsBoundary"] == f"arn:aws:iam::{CUENTA}:policy/AgenteIAM-LimiteSistema"
    assert p["Tags"] == [{"Key": "proyecto", "Value": "agente-iam"}]
    [politica] = p["Policies"]
    assert politica["PolicyName"] == "AgenteIAM-Avisos-permisos"
    [s] = resolver_sub(_base()["Resources"]["RolAvisos"]["Properties"]["AssumeRolePolicyDocument"])["Statement"]
    assert s["Principal"] == {"Service": "lambda.amazonaws.com"}
    assert s["Condition"] == {"StringEquals": {"aws:SourceAccount": CUENTA}}  # sin aws:SourceArn, como el aplicador

    sentencias = {s["Sid"]: s for s in sentencias_de_rol(_base(), "RolAvisos")}
    assert list(sentencias) == ["EnviarSoloDesdeElRemitente", "LeerElStream", "ListarStreamsNoTieneRecurso", "Logs",
                                "NuncaLeerNiEscribirLaTabla", "NuncaReemplazarNiBorrarFilas", "NuncaEscribirEnIAM",
                                "NuncaHablarConElModelo"]
    # Una sola sentencia Allow habla de SES: ses:SendEmail sobre cualquier identidad (la del destinatario cuenta) y SOLO desde el remitente.
    con_ses = [s for s in sentencias.values() if s["Effect"] == "Allow" and any(a.startswith("ses:") for a in _acciones(s))]
    assert [s["Sid"] for s in con_ses] == ["EnviarSoloDesdeElRemitente"]
    envio = sentencias["EnviarSoloDesdeElRemitente"]
    assert _acciones(envio) == ["ses:SendEmail"]
    assert envio["Resource"] == IDENTIDADES_SES
    assert envio["Condition"] == {"StringEquals": {"ses:FromAddress": {"Ref": "CorreoRemitente"}}}
    # Los logs: solo su grupo (lo crea la pila runtime), sin CreateLogGroup.
    logs = sentencias["Logs"]
    assert logs["Effect"] == "Allow"
    assert set(_acciones(logs)) == {"logs:CreateLogStream", "logs:PutLogEvents"}
    assert logs["Resource"] == f"arn:aws:logs:us-east-1:{CUENTA}:log-group:/aws/lambda/agente-iam-avisos:*"
    # Nunca la tabla: ni leerla ni actualizarla, sobre cualquier recurso.
    tabla = sentencias["NuncaLeerNiEscribirLaTabla"]
    assert tabla["Effect"] == "Deny"
    assert set(_acciones(tabla)) == {"dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:UpdateItem"}
    assert tabla["Resource"] == "*"
    assert "Condition" not in tabla
    assert sentencias["NuncaReemplazarNiBorrarFilas"]["Effect"] == "Deny"
    assert sentencias["NuncaReemplazarNiBorrarFilas"] == next(
        s for s in sentencias_de_rol(_base(), "RolAplicador") if s["Sid"] == "NuncaReemplazarNiBorrarFilas")
    # IAM: la misma lista que la aprobacion, sin copia a mano que se desvie.
    assert sentencias["NuncaEscribirEnIAM"] == next(
        s for s in sentencias_de_rol(_base(), "RolAprobacion") if s["Sid"] == "NuncaEscribirEnIAM")
    assert sentencias["NuncaEscribirEnIAM"]["Effect"] == "Deny"
    modelo = sentencias["NuncaHablarConElModelo"]
    assert modelo["Effect"] == "Deny"
    assert modelo["Action"] == "bedrock:*"
    assert modelo["Resource"] == "*"
    # Y nada de IAM, STS, Organizations ni Bedrock entre lo permitido.
    assert not [a for a in _permitidas("RolAvisos") if a.startswith(("iam:", "sts:", "organizations:", "bedrock"))]
    assert "RolAvisosArn" in _base()["Outputs"]
    assert _base()["Outputs"]["RolAvisosArn"]["Value"] == {"Fn::GetAtt": ["RolAvisos", "Arn"]}


def test_el_rol_de_avisos_lee_el_stream_y_nada_mas_de_dynamodb():
    """Las unicas acciones de DynamoDB que concede son las cuatro del stream; la fila nunca se lee desde aqui."""
    dynamo = {a for a in _permitidas("RolAvisos") if a.startswith("dynamodb:")}
    assert dynamo == {"dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:ListStreams"}
    sentencias = {s["Sid"]: s for s in sentencias_de_rol(_base(), "RolAvisos")}
    assert set(_acciones(sentencias["LeerElStream"])) == {
        "dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator"}
    assert sentencias["LeerElStream"]["Resource"] == f"{TABLA}/stream/*"
    assert _acciones(sentencias["ListarStreamsNoTieneRecurso"]) == ["dynamodb:ListStreams"]
    assert sentencias["ListarStreamsNoTieneRecurso"]["Resource"] == "*"
    # El stream, tal y como lo lee el aplicador: misma forma, mismo recurso.
    del_aplicador = {s["Sid"]: s for s in sentencias_de_rol(_base(), "RolAplicador")}
    assert sentencias["LeerElStream"]["Resource"] == del_aplicador["LeerElStreamDeLaTabla"]["Resource"]
    assert not [a for a in _permitidas("RolAvisos") if a.startswith(("sqs:", "s3:", "sns:", "lambda:", "ses:")) and a != "ses:SendEmail"]


def test_el_runtime_busca_el_recurso_solo_con_lecturas_de_metadatos():
    """Fase 28 (agente_iam/existencia.py): ninguna de estas acciones devuelve contenido; Lambda va por
    etiquetas y no por la configuracion (variables de entorno). Las que admiten recurso, solo en esta
    cuenta y en us-east-1; S3 y Logs no tienen tipo de recurso. El limite del sistema las permite."""
    por_sid = {s["Sid"]: s for s in sentencias_de_rol(_base(), "RolRuntime")}
    con_recurso = por_sid["ComprobarQueElRecursoExiste"]
    assert con_recurso["Effect"] == "Allow"
    assert set(_acciones(con_recurso)) == {
        "dynamodb:DescribeTable", "sqs:GetQueueUrl", "sns:GetTopicAttributes", "cloudwatch:DescribeAlarms", "lambda:ListTags",
    }
    assert con_recurso["Resource"] == [
        f"arn:aws:dynamodb:us-east-1:{CUENTA}:table/*",
        f"arn:aws:sqs:us-east-1:{CUENTA}:*",
        f"arn:aws:sns:us-east-1:{CUENTA}:*",
        f"arn:aws:cloudwatch:us-east-1:{CUENTA}:alarm:*",
        f"arn:aws:lambda:us-east-1:{CUENTA}:function:*",
    ]
    sin_recurso = por_sid["ComprobarQueElRecursoExisteSinTipoDeRecurso"]
    assert set(_acciones(sin_recurso)) == {"s3:ListAllMyBuckets", "logs:DescribeLogGroups"}
    assert sin_recurso["Resource"] == "*"
    assert "lambda:GetFunction" not in _permitidas("RolRuntime")
    assert "lambda:GetFunctionConfiguration" not in _permitidas("RolRuntime")

    arranque = yaml.safe_load((Path(__file__).resolve().parents[2] / "infra" / "cfn" / "arranque.yaml").read_text())
    limite = arranque["Resources"]["LimiteSistema"]["Properties"]["PolicyDocument"]["Statement"]
    [del_limite] = [s for s in limite if s.get("Sid") == "ComprobarQueElRecursoExiste"]
    assert set(del_limite["Action"]) == set(_acciones(con_recurso)) | {"s3:ListAllMyBuckets"}
