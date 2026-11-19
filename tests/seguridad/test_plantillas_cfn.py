"""Plantillas de CloudFormation: higiene comun e identidades.

El repositorio esta en GitHub. Las plantillas de `infra/cfn/` no llevan la
cuenta real, ni ids de la organizacion, ni correos (datos personales): todo
eso entra como parametro al desplegar. Y se leen con `yaml.safe_load`, que no
entiende las etiquetas cortas (`!Ref`, `!Sub`...): si alguien las usa, los
tests de cada plantilla dejarian de poder leerla.

`identidades.yaml` (Fase 15, 23-10-2026) crea personas, grupos y permission
sets. Lo que fijan estos tests es el diseno del bloque 3 (PLAN, "Bloque 3:
diseno aprobado"), riesgo por riesgo: el acceso va solo a grupos y solo en
agente-iam; quien despliega no aprueba; el aprobador solo lee la fila e invoca la
Lambda de aprobacion por su URL (ADR-003, 24-10-2026): no escribe la tabla ni
asume el aplicador; el operador solo
despliega con el rol de despliegue y nunca toca la pila de arranque; la
lectura no lee datos. Personas y grupos con `Retain`. Hasta el 23-10-2026
habia aqui un test que exigia que la pila no diera acceso a ninguna cuenta:
era el estado de la Prueba B y se sustituyo a proposito por estos.

`arranque.yaml` (bloque 3, 23-10-2026) la despliega solo el administrador:
el rol con el que CloudFormation crea todo lo demas, el limite de los roles
del sistema y el techo. Sus tests fijan que nadie, ni el propio rol de
despliegue, puede ampliarse permisos por ahi.
"""

import re
from pathlib import Path

import pytest
import yaml

CFN = Path(__file__).resolve().parents[2] / "infra" / "cfn"
PLANTILLAS = sorted(CFN.glob("*.yaml"))


def test_hay_plantillas():
    assert {p.name for p in PLANTILLAS} >= {"arranque.yaml", "gobierno-regiones.yaml", "identidades.yaml", "prueba-eco.yaml"}


@pytest.mark.parametrize("plantilla", PLANTILLAS, ids=lambda p: p.name)
def test_sin_cuenta_ids_de_organizacion_ni_correos(plantilla):
    texto = plantilla.read_text(encoding="utf-8")
    assert re.findall(r"\b\d{12}\b", texto) == []
    assert re.findall(r"\bou-[a-z0-9]{4}-[a-z0-9]{8,}", texto) == []
    assert re.findall(r"\bo-[a-z0-9]{10,}", texto) == []
    assert re.findall(r"\bd-[0-9a-f]{10}\b", texto) == []  # id real del almacen de identidades
    assert re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", texto) == []


@pytest.mark.parametrize("plantilla", PLANTILLAS, ids=lambda p: p.name)
def test_sin_etiquetas_cortas(plantilla):
    texto = plantilla.read_text(encoding="utf-8")
    assert re.findall(r"(?m)^[^#]*\s!(?:Ref|Sub|Select|Split|GetAtt|Join|If|Not|Equals|And|Or)\b", texto) == []
    yaml.safe_load(texto)


@pytest.mark.parametrize("plantilla", PLANTILLAS, ids=lambda p: p.name)
def test_sin_guion_largo_en_nombres_ni_descripciones(plantilla):
    """Regla del proyecto (CLAUDE.md): nada de guiones largos en nombres o
    descripciones de recursos de AWS."""
    assert "—" not in plantilla.read_text(encoding="utf-8")


# --- identidades.yaml ------------------------------------------------------


def _identidades() -> dict:
    return yaml.safe_load((CFN / "identidades.yaml").read_text(encoding="utf-8"))


def _recursos(tipo: str) -> dict:
    return {n: r for n, r in _identidades()["Resources"].items() if r["Type"] == tipo}


def _politica(nombre: str) -> list[dict]:
    return _identidades()["Resources"][nombre]["Properties"]["InlinePolicy"]["Statement"]


def _acciones(sentencia: dict) -> list[str]:
    a = sentencia.get("Action", [])  # las de NotAction no tienen Action
    return [a] if isinstance(a, str) else a


def test_personas_y_grupos_se_retienen_al_borrar_la_pila():
    for tipo in ("AWS::IdentityStore::User", "AWS::IdentityStore::Group"):
        recursos = _recursos(tipo)
        assert recursos
        for nombre, r in recursos.items():
            assert r.get("DeletionPolicy") == "Retain", nombre
            assert r.get("UpdateReplacePolicy") == "Retain", nombre


def test_los_correos_son_parametros_sin_valor_por_defecto():
    plantilla = _identidades()
    for nombre, r in _recursos("AWS::IdentityStore::User").items():
        [correo] = r["Properties"]["Emails"]
        parametro = correo["Value"]["Ref"]
        assert "Default" not in plantilla["Parameters"][parametro], nombre


def test_el_acceso_va_solo_a_grupos_y_solo_en_agente_iam():
    for nombre, r in _recursos("AWS::SSO::Assignment").items():
        assert r["Properties"]["PrincipalType"] == "GROUP", nombre
        assert r["Properties"]["TargetType"] == "AWS_ACCOUNT", nombre
        assert r["Properties"]["TargetId"] == {"Ref": "CuentaAgenteIam"}, nombre
    for nombre, r in _recursos("AWS::SSO::ApplicationAssignment").items():
        assert r["Properties"]["PrincipalType"] == "GROUP", nombre


def test_los_solicitantes_no_entran_en_ninguna_cuenta():
    """Piden con el token de Cognito (ADR-001): no necesitan credenciales."""
    for nombre, r in _recursos("AWS::SSO::Assignment").items():
        assert r["Properties"]["PrincipalId"] != {"Fn::GetAtt": ["GrupoSolicitantes", "GroupId"]}, nombre


def test_quien_despliega_no_aprueba():
    pertenencias = _recursos("AWS::IdentityStore::GroupMembership").values()
    en_aprobadores = [m["Properties"]["MemberId"]["UserId"] for m in pertenencias
                      if m["Properties"]["GroupId"] == {"Fn::GetAtt": ["GrupoAprobadores", "GroupId"]}]
    assert {"Ref": "MateoUserId"} not in en_aprobadores
    sets_por_grupo: dict[str, set] = {}
    for r in _recursos("AWS::SSO::Assignment").values():
        grupo = r["Properties"]["PrincipalId"]["Fn::GetAtt"][0]
        sets_por_grupo.setdefault(grupo, set()).add(r["Properties"]["PermissionSetArn"]["Fn::GetAtt"][0])
    for grupo, sets in sets_por_grupo.items():
        assert not {"PermisosAprobador", "PermisosOperador"} <= sets, grupo


_TABLA_DEL_APROBADOR = "arn:aws:dynamodb:us-east-1:${CuentaAgenteIam}:table/agente-iam-solicitudes"
_LAMBDA_DE_APROBACION = "arn:aws:lambda:us-east-1:${CuentaAgenteIam}:function:agente-iam-aprobacion"


def _permitidas_al_aprobador() -> set[str]:
    return {a for s in _politica("PermisosAprobador") if s["Effect"] == "Allow" for a in _acciones(s)}


def test_el_aprobador_no_escribe_la_tabla():
    """ADR-003: la persona solo lee la fila; quien escribe la decision es la
    Lambda. Ni UpdateItem acotado: un cliente modificado no puede ni intentarlo."""
    sentencias = _politica("PermisosAprobador")
    assert {a for a in _permitidas_al_aprobador() if a.startswith("dynamodb:")} == {"dynamodb:GetItem"}
    [leer] = [s for s in sentencias if s["Effect"] == "Allow" and "dynamodb:GetItem" in _acciones(s)]
    assert leer["Resource"] == {"Fn::Sub": _TABLA_DEL_APROBADOR}
    [nunca] = [s for s in sentencias if s["Effect"] == "Deny" and s["Sid"] == "NuncaEscribirLaTabla"]
    assert nunca["Resource"] == {"Fn::Sub": _TABLA_DEL_APROBADOR}
    assert {"dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem",
            "dynamodb:PartiQLInsert", "dynamodb:PartiQLUpdate", "dynamodb:PartiQLDelete"} <= set(_acciones(nunca))
    assert "Condition" not in nunca


def test_el_aprobador_solo_invoca_la_aprobacion_y_solo_por_la_url():
    """Dos sentencias porque en una las dos condiciones se exigirian a la vez
    para cada accion (AND): FunctionUrlAuthType solo existe en InvokeFunctionUrl
    e InvokedViaFunctionUrl solo en InvokeFunction. Sin la segunda condicion, la
    persona invocaria la funcion por la API y se saltaria la URL."""
    sentencias = [s for s in _politica("PermisosAprobador")
                  if s["Effect"] == "Allow" and any(a.startswith("lambda:") for a in _acciones(s))]
    assert len(sentencias) == 2
    [url] = [s for s in sentencias if _acciones(s) == ["lambda:InvokeFunctionUrl"]]
    [invocar] = [s for s in sentencias if _acciones(s) == ["lambda:InvokeFunction"]]
    assert url["Condition"] == {"StringEquals": {"lambda:FunctionUrlAuthType": "AWS_IAM"}}
    assert invocar["Condition"] == {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}}
    for s in sentencias:
        assert s["Resource"] == {"Fn::Sub": _LAMBDA_DE_APROBACION}


def test_el_aprobador_ya_no_revalida():
    """Decision 4 del ADR-003: revalidar con las reglas de hoy lo hace la
    Lambda con su rol; la persona no necesita leer IAM ni usar Access Analyzer."""
    assert not [a for a in _permitidas_al_aprobador() if a.startswith(("iam:", "access-analyzer:"))]
    assert [s["Sid"] for s in _politica("PermisosAprobador")] == [
        "LeerLaSolicitud", "InvocarLaAprobacionPorSuUrl", "InvocarLaAprobacionSoloViaUrl", "NuncaEscribirLaTabla"]


def test_el_operador_sube_al_bucket_de_la_pila_base():
    """El bucket lo crea `base.yaml`: el nombre sale de ahi, no se copia. El
    runtime lee el codigo bajo `agente-iam/`, y el operador sube solo ahi."""
    base = yaml.safe_load((CFN / "base.yaml").read_text(encoding="utf-8"))
    nombre = base["Resources"]["BucketPaquete"]["Properties"]["BucketName"]["Fn::Sub"]
    bucket = nombre.replace("${AWS::AccountId}", "${CuentaAgenteIam}")
    [subir] = [s for s in _politica("PermisosOperador") if s["Sid"] == "SubirElPaqueteDelCodigo"]
    assert subir["Effect"] == "Allow"
    assert _acciones(subir) == ["s3:PutObject"]
    assert subir["Resource"] == {"Fn::Sub": f"arn:aws:s3:::{bucket}/agente-iam/*"}


def test_ningun_permission_set_permite_asumir_roles():
    """Riesgo 1: el aplicador es una Lambda; ninguna persona asume su rol."""
    for nombre in _recursos("AWS::SSO::PermissionSet"):
        for s in _politica(nombre):
            if s["Effect"] == "Allow":
                assert not any(a.lower().startswith("sts:") for a in _acciones(s)), nombre


def test_el_operador_solo_despliega_con_el_rol_de_despliegue():
    sentencias = _politica("PermisosOperador")
    cambian = {"cloudformation:CreateStack", "cloudformation:UpdateStack",
               "cloudformation:CreateChangeSet", "cloudformation:DeleteStack"}
    for s in sentencias:
        if s["Effect"] == "Allow" and cambian & set(_acciones(s)):
            rol = s["Condition"]["StringEquals"]["cloudformation:RoleArn"]["Fn::Sub"]
            assert rol.endswith(":role/AgenteIAM-Despliegue")
    [pasar] = [s for s in sentencias if "iam:PassRole" in _acciones(s)]
    assert pasar["Resource"]["Fn::Sub"].endswith(":role/AgenteIAM-Despliegue")
    assert pasar["Condition"]["StringEquals"]["iam:PassedToService"] == "cloudformation.amazonaws.com"


def test_el_operador_no_puede_cambiar_la_pila_de_arranque():
    """La pila de arranque define AgenteIAM-Despliegue: si el operador la
    cambiara, podria ampliarse sus propios permisos."""
    [deny] = [s for s in _politica("PermisosOperador")
              if s["Effect"] == "Deny" and "agente-iam-arranque" in str(s["Resource"])]
    assert {"cloudformation:UpdateStack", "cloudformation:CreateChangeSet",
            "cloudformation:ExecuteChangeSet", "cloudformation:DeleteStack"} <= set(_acciones(deny))
    assert "Condition" not in deny


def test_la_lectura_no_lee_datos():
    lectura = _identidades()["Resources"]["PermisosLectura"]["Properties"]
    assert set(lectura["ManagedPolicies"]) == {"arn:aws:iam::aws:policy/SecurityAudit",
                                               "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"}
    assert all(s["Effect"] == "Deny" for s in _politica("PermisosLectura"))
    denegadas = {a for s in _politica("PermisosLectura") for a in _acciones(s)}
    assert {"s3:GetObject*", "dynamodb:GetItem", "secretsmanager:GetSecretValue", "sts:AssumeRole*"} <= denegadas


# --- arranque.yaml -----------------------------------------------------------


def _arranque() -> dict:
    return yaml.safe_load((CFN / "arranque.yaml").read_text(encoding="utf-8"))


def _sentencias_de(nombre: str) -> list[dict]:
    return _arranque()["Resources"][nombre]["Properties"]["PolicyDocument"]["Statement"]


_DEL_DESPLIEGUE = ("PoliticaAlmacen", "PoliticaCognito", "PoliticaComputo", "PoliticaIdentidad", "PoliticaBarreras")


def _sub(x) -> str:
    return x["Fn::Sub"] if isinstance(x, dict) else x


def test_el_techo_de_arranque_tiene_el_nombre_que_busca_aprobar():
    """Que su documento sea copia exacta del JSON lo vigila
    `test_techo_v2.py::test_la_copia_de_arranque_es_lo_que_escribe_el_generador`
    (O14, 24-10-2026: aqui se comprobaba dos veces). Lo propio de este es el
    nombre: `aprobar.techo` busca la politica por `NOMBRE_TECHO`."""
    assert _arranque()["Resources"]["Techo"]["Properties"]["ManagedPolicyName"] == "AgenteIAM-Techo"


def test_solo_cloudformation_asume_el_rol_de_despliegue():
    rol = _arranque()["Resources"]["RolDespliegue"]["Properties"]
    [confianza] = rol["AssumeRolePolicyDocument"]["Statement"]
    assert confianza["Principal"] == {"Service": "cloudformation.amazonaws.com"}
    assert confianza["Action"] == "sts:AssumeRole"
    assert sorted(r["Ref"] for r in rol["ManagedPolicyArns"]) == sorted(_DEL_DESPLIEGUE)


def test_el_despliegue_no_tiene_comodines_de_servicio():
    """Las acciones salen de los esquemas de recursos: nunca un servicio:*."""
    for nombre in _DEL_DESPLIEGUE:
        for st in _sentencias_de(nombre):
            if st["Effect"] == "Allow":
                for a in _acciones(st):
                    assert not a.endswith(":*"), (nombre, a)


def test_el_despliegue_puede_crear_urls_solo_del_proyecto():
    """`AWS::Lambda::Url` (ADR-003) pide las cinco acciones de sus manejadores
    (create, read, update, delete y list; leidas del esquema real con
    `cloudformation:DescribeType` el 24-10-2026), y solo sobre las funciones y
    mapeos del proyecto. El despliegue no recibe `lambda:AddPermission` ni
    ninguna accion de politica de recurso: la gemela del techo las niega y la
    URL con AWS_IAM no las necesita."""
    urls = {
        "lambda:CreateFunctionUrlConfig",
        "lambda:GetFunctionUrlConfig",
        "lambda:UpdateFunctionUrlConfig",
        "lambda:DeleteFunctionUrlConfig",
        "lambda:ListFunctionUrlConfigs",
    }
    sentencias = [s for n in _DEL_DESPLIEGUE for s in _sentencias_de(n)]
    [lambdas] = [s for s in sentencias if s.get("Sid") == "LambdaSoloRecursosDelProyecto"]
    assert urls <= set(_acciones(lambdas))
    recursos = [_sub(r) for r in lambdas["Resource"]]
    assert recursos
    assert all(
        r.endswith(":function:agente-iam-*") or r.endswith(":event-source-mapping:*") for r in recursos
    ), recursos
    for st in sentencias:
        if st["Effect"] == "Allow" and st["Resource"] == "*":
            assert not urls & set(_acciones(st)), st.get("Sid")
        if st["Effect"] == "Allow":
            for a in _acciones(st):
                assert a not in ("lambda:AddPermission", "lambda:RemovePermission", "lambda:*"), (st.get("Sid"), a)


def test_lo_que_va_con_recurso_estrella_no_lee_ni_escribe_datos_ni_iam():
    datos = ("s3:GetObject", "s3:PutObject", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:Scan")
    for nombre in _DEL_DESPLIEGUE:
        for st in _sentencias_de(nombre):
            if st["Effect"] == "Allow" and st["Resource"] == "*":
                for a in _acciones(st):
                    assert not a.startswith(datos), (nombre, a)
                    # ListRoles y ListOpenIDConnectProviders no admiten recurso en IAM.
                    assert not a.startswith("iam:") or a in ("iam:ListRoles", "iam:ListOpenIDConnectProviders"), (nombre, a)


def test_los_roles_del_sistema_nacen_con_su_limite_y_no_se_les_quita():
    limite = ":policy/AgenteIAM-LimiteSistema"
    [crear] = [st for st in _sentencias_de("PoliticaIdentidad") if "iam:CreateRole" in _acciones(st)]
    assert _sub(crear["Resource"]).endswith(":role/AgenteIAM-*")
    assert _sub(crear["Condition"]["StringEquals"]["iam:PermissionsBoundary"]).endswith(limite)
    barreras = _sentencias_de("PoliticaBarreras")
    [deny] = [st for st in barreras if st["Effect"] == "Deny" and "iam:CreateRole" in _acciones(st)]
    assert _sub(deny["Condition"]["StringNotEquals"]["iam:PermissionsBoundary"]).endswith(limite)
    quitar = {a for st in barreras if st["Effect"] == "Deny" for a in _acciones(st)}
    assert "iam:DeleteRolePermissionsBoundary" in quitar


def test_nadie_toca_lo_de_la_pila_de_arranque():
    """Si el rol de despliegue pudiera editar su propia politica, el limite
    o el techo, podria ampliarse cualquier permiso."""
    [deny] = [st for st in _sentencias_de("PoliticaBarreras") if st.get("NotAction")]
    assert deny["Effect"] == "Deny"
    assert sorted(deny["NotAction"]) == ["iam:Get*", "iam:List*"]
    protegidos = {_sub(r).split(":")[-1] for r in deny["Resource"]}
    assert protegidos == {"role/AgenteIAM-Despliegue", "policy/AgenteIAM-Despliegue-*",
                          "policy/AgenteIAM-LimiteSistema", "policy/AgenteIAM-Techo"}


def test_el_despliegue_solo_pasa_roles_del_sistema_a_sus_servicios():
    [pasar] = [st for st in _sentencias_de("PoliticaIdentidad") if "iam:PassRole" in _acciones(st)]
    assert _sub(pasar["Resource"]).endswith(":role/AgenteIAM-*")
    assert set(pasar["Condition"]["StringEquals"]["iam:PassedToService"]) <= {
        "bedrock-agentcore.amazonaws.com", "lambda.amazonaws.com"}
    [no_a_si_mismo] = [st for st in _sentencias_de("PoliticaBarreras")
                      if st["Effect"] == "Deny" and _acciones(st) == ["iam:PassRole"]]
    assert _sub(no_a_si_mismo["Resource"]).endswith(":role/AgenteIAM-Despliegue")


def test_el_despliegue_no_crea_usuarios_de_cognito_ni_de_iam():
    """Riesgo 3: usuarios con contrasena que se salten Identity Center."""
    denegadas = {a for st in _sentencias_de("PoliticaBarreras") if st["Effect"] == "Deny" for a in _acciones(st)}
    assert {"cognito-idp:AdminCreateUser", "cognito-idp:AdminSetUserPassword", "cognito-idp:SignUp",
            "iam:CreateUser", "iam:CreateAccessKey", "iam:CreatePolicy"} <= denegadas
    permitidas = {a for n in _DEL_DESPLIEGUE for st in _sentencias_de(n) if st["Effect"] == "Allow" for a in _acciones(st)}
    assert not {"cognito-idp:AdminCreateUser", "iam:CreateUser", "iam:CreatePolicy"} & permitidas


def test_el_limite_del_sistema_impide_escalar():
    sentencias = _sentencias_de("LimiteSistema")
    denegadas = {a for st in sentencias if st["Effect"] == "Deny" for a in _acciones(st)}
    assert {"iam:CreateRole", "iam:PutRolePolicy", "iam:PassRole", "iam:UpdateAssumeRolePolicy",
            "iam:CreatePolicyVersion", "iam:DeleteRolePermissionsBoundary", "sts:AssumeRole*"} <= denegadas
    [adjuntar] = [st for st in sentencias if "iam:AttachRolePolicy" in _acciones(st)]
    assert _sub(adjuntar["Condition"]["StringEquals"]["iam:PermissionsBoundary"]).endswith(":policy/AgenteIAM-Techo")
    assert _sub(adjuntar["Condition"]["ArnLike"]["iam:PolicyARN"]).endswith(":policy/agente-iam/*")


_RUTA_PERSONAS = "arn:aws:iam::${AWS::AccountId}:role/agente-iam/personas/*"
_TECHO = "arn:aws:iam::${AWS::AccountId}:policy/AgenteIAM-Techo"
_PATRON_OIDC_COGNITO = "arn:aws:iam::${AWS::AccountId}:oidc-provider/cognito-idp.us-east-1.amazonaws.com/*"


def test_el_limite_crea_roles_de_persona_solo_en_su_ruta_y_con_el_techo():
    """Fase 23: los roles del sistema (el aplicador) crean roles de persona, y solo asi.

    Todo Deny con `iam:CreateRole` lleva `NotResource` la ruta o `StringNotEquals iam:PermissionsBoundary` = techo
    (con la clave ausente deniega: MEDICIONES H 11 y 30), nunca un operador `...IfExists`. El unico Allow de
    `iam:CreateRole` lleva la ruta y `StringEquals` con el techo.
    """
    sentencias = _sentencias_de("LimiteSistema")
    con_crear = [st for st in sentencias if "iam:CreateRole" in _acciones(st)]
    permisos = [st for st in con_crear if st["Effect"] == "Allow"]
    denegaciones = [st for st in con_crear if st["Effect"] == "Deny"]
    [crear] = permisos
    assert crear["Sid"] == "CrearRolesDePersonaSoloConElTecho"
    assert _acciones(crear) == ["iam:CreateRole"]
    assert _sub(crear["Resource"]) == _RUTA_PERSONAS
    assert {k: _sub(v) for k, v in crear["Condition"]["StringEquals"].items()} == {"iam:PermissionsBoundary": _TECHO}
    assert set(crear["Condition"]) == {"StringEquals"}
    assert len(denegaciones) == 2
    for st in denegaciones:
        assert not any(op.endswith("IfExists") for op in st.get("Condition", {})), st["Sid"]
        fuera_de_ruta = _sub(st.get("NotResource", "")) == _RUTA_PERSONAS
        sin_techo = (st.get("Resource") == "*" and set(st.get("Condition", {})) == {"StringNotEquals"}
                     and {k: _sub(v) for k, v in st["Condition"]["StringNotEquals"].items()}
                     == {"iam:PermissionsBoundary": _TECHO})
        assert fuera_de_ruta or sin_techo, st["Sid"]
    assert {st["Sid"] for st in denegaciones} == {"NuncaUnRolFueraDeLaRutaDePersonas", "NuncaUnRolDePersonaSinElTecho"}
    [etiquetar] = [st for st in sentencias if st["Effect"] == "Allow" and "iam:TagRole" in _acciones(st)]
    assert etiquetar["Sid"] == "EtiquetarRolesDePersona"
    assert _acciones(etiquetar) == ["iam:TagRole"]
    assert _sub(etiquetar["Resource"]) == _RUTA_PERSONAS
    # Ningun Allow del limite deja cambiar la confianza, borrar roles ni pasarlos.
    permitidas = {a for st in sentencias if st["Effect"] == "Allow" for a in _acciones(st)}
    assert not {"iam:UpdateAssumeRolePolicy", "iam:DeleteRole", "iam:PassRole"} & permitidas


def test_el_limite_deja_avisar_por_correo_solo_con_identidades_de_la_cuenta():
    """Bloque 3: `ses:SendEmail` entra ahora para que el administrador despliegue arranque una sola vez."""
    [avisar] = [st for st in _sentencias_de("LimiteSistema") if st.get("Sid") == "AvisarPorCorreo"]
    assert avisar["Effect"] == "Allow"
    assert _acciones(avisar) == ["ses:SendEmail"]
    assert _sub(avisar["Resource"]) == "arn:aws:ses:us-east-1:${AWS::AccountId}:identity/*"
    assert "Condition" not in avisar
    # El rol de despliegue no recibe nada de SES: no crea identidades ni manda correo.
    for nombre in _DEL_DESPLIEGUE:
        for st in _sentencias_de(nombre):
            assert not [a for a in _acciones(st) if a.startswith("ses:")], (nombre, st.get("Sid"))


def test_el_despliegue_solo_crea_el_proveedor_oidc_de_cognito():
    """Fase 23: el proveedor OIDC del pool lo crea CloudFormation con el rol de despliegue, y ningun otro."""
    acciones_oidc = {
        "iam:CreateOpenIDConnectProvider", "iam:DeleteOpenIDConnectProvider", "iam:GetOpenIDConnectProvider",
        "iam:UpdateOpenIDConnectProviderThumbprint", "iam:AddClientIDToOpenIDConnectProvider",
        "iam:RemoveClientIDFromOpenIDConnectProvider", "iam:TagOpenIDConnectProvider",
        "iam:UntagOpenIDConnectProvider", "iam:ListOpenIDConnectProviderTags"}
    [permiso] = [st for st in _sentencias_de("PoliticaIdentidad") if st.get("Sid") == "ProveedorOidcSoloDelPoolDeCognito"]
    assert permiso["Effect"] == "Allow"
    assert set(_acciones(permiso)) == acciones_oidc
    assert _sub(permiso["Resource"]) == _PATRON_OIDC_COGNITO
    # El manejador list enumera los proveedores: esa accion no admite recurso y va sola con "*".
    [listar] = [st for st in _sentencias_de("PoliticaIdentidad") if st.get("Sid") == "ListarProveedoresOidcNoTieneRecurso"]
    assert listar["Effect"] == "Allow"
    assert _acciones(listar) == ["iam:ListOpenIDConnectProviders"]
    assert listar["Resource"] == "*"
    # En ninguna otra politica del despliegue hay un Allow de proveedores OIDC.
    for nombre in _DEL_DESPLIEGUE:
        for st in _sentencias_de(nombre):
            if st["Effect"] == "Allow" and st.get("Sid") not in ("ProveedorOidcSoloDelPoolDeCognito", "ListarProveedoresOidcNoTieneRecurso"):
                assert not [a for a in _acciones(st) if "OpenIDConnectProvider" in a], (nombre, st.get("Sid"))
    barreras = _sentencias_de("PoliticaBarreras")
    [otro] = [st for st in barreras if st.get("Sid") == "NuncaOtroProveedorOidc"]
    assert otro["Effect"] == "Deny"
    assert _acciones(otro) == ["iam:CreateOpenIDConnectProvider"]
    assert _sub(otro["NotResource"]) == _PATRON_OIDC_COGNITO
    assert "Resource" not in otro
    assert not any(op.endswith("IfExists") for op in otro.get("Condition", {}))
    # Ya no esta en el Deny incondicional (si siguiera, ganaria al Allow y el proveedor no se podria crear).
    [humanas] = [st for st in barreras if st.get("Sid") == "NuncaIdentidadesHumanasNiPoliticasNuevas"]
    assert "iam:CreateOpenIDConnectProvider" not in _acciones(humanas)
    assert "iam:CreateSAMLProvider" in _acciones(humanas)


def test_el_despliegue_puede_crear_cloudfront_solo_del_proyecto():
    """Bloque 2 (la pila web), en el mismo change set de arranque: CloudFront solo sobre distribuciones, controles de
    acceso al origen y politicas de cabeceras de esta cuenta. Las tres Create no admiten tipo de recurso (referencia
    de autorizacion, 26-10-2026) y, con las List de los manejadores, son las UNICAS acciones de CloudFront con recurso `*`."""
    esperadas = {
        "cloudfront:UpdateDistribution", "cloudfront:DeleteDistribution",
        "cloudfront:GetDistribution", "cloudfront:GetDistributionConfig", "cloudfront:TagResource",
        "cloudfront:UntagResource", "cloudfront:ListTagsForResource",
        "cloudfront:GetOriginAccessControl", "cloudfront:GetOriginAccessControlConfig",
        "cloudfront:UpdateOriginAccessControl", "cloudfront:DeleteOriginAccessControl",
        "cloudfront:GetResponseHeadersPolicy",
        "cloudfront:GetResponseHeadersPolicyConfig", "cloudfront:UpdateResponseHeadersPolicy",
        "cloudfront:DeleteResponseHeadersPolicy"}
    [st] = [st for st in _sentencias_de("PoliticaComputo") if st.get("Sid") == "CloudFrontSoloRecursosDelProyecto"]
    assert st["Effect"] == "Allow"
    assert set(_acciones(st)) == esperadas
    assert [_sub(r) for r in st["Resource"]] == [
        "arn:aws:cloudfront::${AWS::AccountId}:distribution/*",
        "arn:aws:cloudfront::${AWS::AccountId}:origin-access-control/*",
        "arn:aws:cloudfront::${AWS::AccountId}:response-headers-policy/*"]
    [crear] = [st for st in _sentencias_de("PoliticaComputo") if st.get("Sid") == "CloudFrontSinTipoDeRecurso"]
    assert crear["Effect"] == "Allow"
    assert crear["Resource"] == "*"
    assert set(_acciones(crear)) == {"cloudfront:CreateDistribution",
                                      "cloudfront:CreateOriginAccessControl", "cloudfront:CreateResponseHeadersPolicy",
                                      "cloudfront:ListDistributions", "cloudfront:ListOriginAccessControls",
                                      "cloudfront:ListResponseHeadersPolicies"}
    for nombre in _DEL_DESPLIEGUE:
        for otra in _sentencias_de(nombre):
            if otra.get("Sid") not in ("CloudFrontSoloRecursosDelProyecto", "CloudFrontSinTipoDeRecurso") and otra["Effect"] == "Allow":
                assert not [a for a in _acciones(otra) if a.startswith("cloudfront:")], (nombre, otra.get("Sid"))


# --- sonda-cuenta.yaml (Fase 18, temporal) --------------------------------
#
# La pila de la sonda de `aws:ResourceAccount` deja un rol asumible en la
# cuenta mientras existe. Lo que fijan estos tests: solo lee, y solo lo que la
# sonda llama; solo lo asume el administrador; y crea los recursos contra los
# que llama el script, con los mismos nombres.

_VERBOS_DE_ESCRITURA = re.compile(
    r":(Put|Create|Delete|Update|Set|Tag|Untag|Attach|Detach|Add|Remove|Invoke|Send|Publish|Subscribe|Run|Start|Modify)"
)


def _sonda() -> dict:
    return yaml.safe_load((CFN / "sonda-cuenta.yaml").read_text(encoding="utf-8"))


def _script_sonda():
    import importlib.util
    import sys

    ruta = CFN.parents[1] / "scripts" / "sonda_cuenta.py"
    spec = importlib.util.spec_from_file_location("sonda_cuenta", ruta)
    assert spec
    assert spec.loader
    modulo = importlib.util.module_from_spec(spec)
    sys.modules["sonda_cuenta"] = modulo
    spec.loader.exec_module(modulo)
    return modulo


def _rol_sonda() -> dict:
    [rol] = [r for r in _sonda()["Resources"].values() if r["Type"] == "AWS::IAM::Role"]
    return rol["Properties"]


def test_la_sonda_solo_lee_lo_que_llama():
    sentencias = [st for p in _rol_sonda()["Policies"] for st in p["PolicyDocument"]["Statement"]]
    assert all(st["Effect"] == "Allow" for st in sentencias)
    acciones = {a for st in sentencias for a in _acciones(st)}
    assert acciones == {ll.accion_iam for ll in _script_sonda().LLAMADAS}
    assert not [a for a in acciones if _VERBOS_DE_ESCRITURA.search(a) or "*" in a]
    assert "ManagedPolicyArns" not in _rol_sonda()


def test_la_sonda_solo_la_asume_el_administrador():
    [st] = _rol_sonda()["AssumeRolePolicyDocument"]["Statement"]
    assert st["Action"] == "sts:AssumeRole"
    assert _sub(st["Principal"]["AWS"]) == "arn:aws:iam::${AWS::AccountId}:root"
    assert _sub(st["Condition"]["ArnLike"]["aws:PrincipalArn"]) == (
        "arn:aws:iam::${AWS::AccountId}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AWSAdministratorAccess_*"
    )


def test_la_sonda_crea_lo_que_el_script_llama():
    sonda, recursos = _script_sonda(), _sonda()["Resources"].values()
    nombres = {
        "AWS::S3::Bucket": ("BucketName", "agente-iam-sonda-${AWS::AccountId}"),
        "AWS::DynamoDB::Table": ("TableName", sonda.NOMBRE),
        "AWS::SQS::Queue": ("QueueName", sonda.NOMBRE),
        "AWS::SNS::Topic": ("TopicName", sonda.NOMBRE),
        "AWS::Logs::LogGroup": ("LogGroupName", sonda.NOMBRE),
    }
    for tipo, (propiedad, valor) in nombres.items():
        [r] = [r for r in recursos if r["Type"] == tipo]
        assert _sub(r["Properties"][propiedad]) == valor, tipo
    assert "RolArn" in _sonda()["Outputs"]


def test_el_limite_del_sistema_no_permite_reemplazar_filas():
    """PutItem reemplaza la fila entera y `dynamodb:Attributes` no lo limita (Fase 18, mapa de la tabla).

    Las politicas de los roles no lo usan; el boundary tampoco debe dejarlo, para
    que una politica de rol mal escrita manana no lo abra.
    """
    permitidas = [a for st in _sentencias_de("LimiteSistema") if st["Effect"] == "Allow" for a in _acciones(st)]
    assert "dynamodb:PutItem" not in permitidas
    assert "dynamodb:BatchWriteItem" not in permitidas


def test_la_cabecera_de_identidades_no_dice_que_el_aprobador_escribe():
    """Revision final, F7: tras ADR-003 el aprobador no escribe la tabla (la
    escribe la Lambda). La cabecera de la plantilla no puede seguir diciendolo."""
    cabecera = "\n".join(
        linea for linea in (CFN / "identidades.yaml").read_text(encoding="utf-8").splitlines() if linea.startswith("#")
    )
    cabecera = re.sub(r"\s*\n#\s*", " ", cabecera)
    assert "escribir SOLO su decision" not in cabecera
    assert "invocar la Lambda de aprobacion por su URL; no escriben la tabla" in cabecera
