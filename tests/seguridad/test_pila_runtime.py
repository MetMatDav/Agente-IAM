"""Pila del runtime (`infra/cfn/runtime.yaml`): runtime con autorizador JWT,
Lambda del aplicador, Lambda de avisos, cola de fallos, alarma y trail de eventos de datos.

Lo que fijan estos tests (ESPECIFICACION 2.x, 5 y 7; decisiones D2, D3, D4,
D8): el runtime solo acepta JWT del cliente de Cognito del parametro, sin
`AllowedAudience` (el token de acceso no trae `aud`) y solo deja pasar la
cabecera `Authorization`; los roles viven en la pila base y aqui solo se
nombran; el aplicador no lleva el interruptor de autoaprobacion, corre de uno
en uno y se dispara solo con las filas aprobadas; lo que falla va a una cola
con alarma; el trail propio registra eventos de datos de exactamente dos
recursos; los buckets y grupos de logs no se pierden al borrar la pila.

Fase 23, bloque 3 (26-10-2026): la Lambda de avisos usa el mismo zip que el aplicador, su propio rol (de la base) y el
remitente por parametro; su disparador filtra los cuatro estados que siguen a una decision humana, sin reintentos ni cola:
un aviso que no sale no es un fallo del circuito.
"""

import json
import re
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parents[2]
PLANTILLA = RAIZ / "infra" / "cfn" / "runtime.yaml"

PATRON_FILTRO = (
    '{"eventName":["INSERT","MODIFY"],"dynamodb":{"NewImage":{"estado":{"S":["aprobada"]}}}}'
)
# Los cuatro estados que siguen a la decision de un aprobador (Fase 33). Los que decide el intake solo y
# `propuesta` no avisan: los da la respuesta del servidor, y el correo iria a una direccion que eligio quien pide.
ESTADOS_CON_AVISO = ["aprobada", "rechazada_por_aprobador", "aplicada", "bloqueada_al_aplicar"]


_POOL_DESDE_LA_DISCOVERY_URL = {"Fn::Select": [3, {"Fn::Split": ["/", {"Ref": "DiscoveryUrl"}]}]}
_CLIENTES_DEL_APLICADOR = {"Fn::If": ["ConWeb", {"Fn::Sub": "${ClienteId},${ClienteWebId}"}, {"Ref": "ClienteId"}]}


def _plantilla() -> dict:
    return yaml.safe_load(PLANTILLA.read_text(encoding="utf-8"))


def _recursos() -> dict:
    return _plantilla()["Resources"]


def _props(nombre: str) -> dict:
    return _recursos()[nombre]["Properties"]


def _por_tipo(tipo: str) -> dict:
    return {n: r for n, r in _recursos().items() if r["Type"] == tipo}


# --- Parametros ---------------------------------------------------------------


def test_correo_y_claves_de_codigo_no_tienen_valor_por_defecto():
    """El correo es un dato personal y las claves llevan el hash del zip que
    sube el operador: ninguno puede venir ya escrito en el repositorio."""
    parametros = _plantilla()["Parameters"]
    for nombre in ["CorreoAlarmas", "CorreoRemitente", "ClaveCodigoRuntime", "ClaveCodigoAplicador",
                   "DiscoveryUrl", "ClienteId", "StreamArn"]:
        assert "Default" not in parametros[nombre], nombre
    patron = parametros["CorreoRemitente"]["AllowedPattern"]
    assert patron == parametros["CorreoAlarmas"]["AllowedPattern"]
    assert re.fullmatch(patron, "avisos@ejemplo.org")
    assert not re.fullmatch(patron, "no-es-un-correo")


def test_las_claves_de_codigo_tienen_la_forma_del_empaquetado():
    parametros = _plantilla()["Parameters"]
    assert re.fullmatch(parametros["ClaveCodigoRuntime"]["AllowedPattern"], "agente-iam/runtime-0123456789ab.zip")
    assert re.fullmatch(parametros["ClaveCodigoAplicador"]["AllowedPattern"], "agente-iam/aplicador-0123456789ab.zip")
    assert not re.fullmatch(parametros["ClaveCodigoRuntime"]["AllowedPattern"], "agente-iam/aplicador-0123456789ab.zip")
    assert not re.fullmatch(parametros["ClaveCodigoRuntime"]["AllowedPattern"], "otro/runtime-0123456789ab.zip")


def test_el_modelo_por_defecto_es_un_perfil_us():
    """La SCP solo deja perfiles de inferencia `us.`."""
    modelo = _plantilla()["Parameters"]["ModelId"]
    assert modelo["Default"].startswith("us.anthropic.claude-")
    assert re.fullmatch(modelo["AllowedPattern"], modelo["Default"])
    assert not re.fullmatch(modelo["AllowedPattern"], "anthropic.claude-haiku-4-5-20251001-v1:0")


def test_la_discovery_url_solo_acepta_cognito_de_us_east_1():
    patron = _plantilla()["Parameters"]["DiscoveryUrl"]["AllowedPattern"]
    bueno = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbC123/.well-known/openid-configuration"
    assert re.fullmatch(patron, bueno)
    assert not re.fullmatch(patron, bueno.replace("us-east-1.amazonaws", "eu-west-1.amazonaws"))
    assert not re.fullmatch(patron, "https://ejemplo.com/.well-known/openid-configuration")


def test_el_stream_es_el_de_la_tabla_del_sistema():
    patron = _plantilla()["Parameters"]["StreamArn"]["AllowedPattern"]
    bueno = "arn:aws:dynamodb:us-east-1:111122223333:table/agente-iam-solicitudes/stream/2026-10-25T00:00:00.000"
    assert re.fullmatch(patron, bueno)
    assert not re.fullmatch(patron, bueno.replace("agente-iam-solicitudes", "otra-tabla"))


# --- Runtime ------------------------------------------------------------------


def test_el_runtime_solo_acepta_jwt_del_cliente_del_parametro():
    p = _props("Runtime")
    jwt = p["AuthorizerConfiguration"]["CustomJWTAuthorizer"]
    assert set(p["AuthorizerConfiguration"]) == {"CustomJWTAuthorizer"}
    # El cliente web (Fase 23) entra solo si llega su parametro: ver el test de ClienteWebId.
    assert jwt["AllowedClients"] == {
        "Fn::If": ["ConWeb", [{"Ref": "ClienteId"}, {"Ref": "ClienteWebId"}], [{"Ref": "ClienteId"}]]}
    assert jwt["DiscoveryUrl"] == {"Ref": "DiscoveryUrl"}
    assert "AllowedAudience" not in jwt  # el token de acceso de Cognito no lleva aud


def test_el_runtime_solo_deja_pasar_authorization():
    assert _props("Runtime")["RequestHeaderConfiguration"] == {"RequestHeaderAllowlist": ["Authorization"]}


def test_el_runtime_usa_el_rol_de_la_base_y_es_publico_http():
    p = _props("Runtime")
    assert p["RoleArn"] == {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:role/AgenteIAM-Runtime"}
    assert p["NetworkConfiguration"] == {"NetworkMode": "PUBLIC"}
    assert p["ProtocolConfiguration"] == "HTTP"
    assert p["AgentRuntimeName"] == "agente_iam_analista"


def test_el_runtime_arranca_main_py_desde_el_bucket_de_despliegue():
    codigo = _props("Runtime")["AgentRuntimeArtifact"]["CodeConfiguration"]
    assert codigo["EntryPoint"] == ["main.py"]
    assert codigo["Runtime"] == "PYTHON_3_12"
    assert codigo["Code"]["S3"] == {
        "Bucket": {"Fn::Sub": "agente-iam-despliegue-${AWS::AccountId}"},
        "Prefix": {"Ref": "ClaveCodigoRuntime"},
    }


def test_el_runtime_guarda_en_dynamodb_y_usa_el_modelo_del_parametro():
    env = _props("Runtime")["EnvironmentVariables"]
    assert env == {
        "ALMACEN": "dynamodb",
        "TABLA_SOLICITUDES": "agente-iam-solicitudes",
        "MODEL_ID": {"Ref": "ModelId"},
    }


def test_la_pila_no_declara_el_grupo_de_logs_del_runtime():
    """AgentCore crea ese grupo al crear el runtime: declararlo fallo con
    AlreadyExists el 25-10-2026 y la pila hizo rollback. La retencion la pone
    el administrador; la salida dice cual es el grupo."""
    grupos = _por_tipo("AWS::Logs::LogGroup")
    assert set(grupos) == {"RegistroAplicador", "RegistroAvisos"}
    for nombre, r in _recursos().items():
        assert "/aws/bedrock-agentcore/" not in json.dumps(r["Properties"]), nombre
    assert _plantilla()["Outputs"]["GrupoLogsRuntime"]["Value"] == {
        "Fn::Sub": "/aws/bedrock-agentcore/runtimes/${Runtime.AgentRuntimeId}-DEFAULT"
    }


# --- Aplicador ----------------------------------------------------------------


def test_los_roles_viven_en_la_base_y_aqui_solo_se_nombran():
    assert _por_tipo("AWS::IAM::Role") == {}
    assert _por_tipo("AWS::IAM::Policy") == {}
    assert _por_tipo("AWS::IAM::ManagedPolicy") == {}
    assert _props("FuncionAplicador")["Role"] == {
        "Fn::Sub": "arn:aws:iam::${AWS::AccountId}:role/AgenteIAM-Aplicador"
    }
    assert _props("FuncionAvisos")["Role"] == {
        "Fn::Sub": "arn:aws:iam::${AWS::AccountId}:role/AgenteIAM-Avisos"
    }


def test_la_funcion_del_aplicador_esta_acotada():
    p = _props("FuncionAplicador")
    assert p["FunctionName"] == "agente-iam-aplicador"
    assert p["Handler"] == "agente_iam.aplicador.manejador"
    assert p["Runtime"] == "python3.12"
    assert p["Architectures"] == ["arm64"]
    # Sin reserva: con la cuota por defecto de una cuenta nueva (10) la creacion
    # falla, y el aplicador es idempotente (ver el comentario de la plantilla).
    assert "ReservedConcurrentExecutions" not in p
    assert p["Timeout"] == 120
    assert p["MemorySize"] == 512
    assert p["Code"] == {
        "S3Bucket": {"Fn::Sub": "agente-iam-despliegue-${AWS::AccountId}"},
        "S3Key": {"Ref": "ClaveCodigoAplicador"},
    }
    assert p["LoggingConfig"] == {"LogGroup": {"Ref": "RegistroAplicador"}}


def test_el_aplicador_nunca_lleva_el_interruptor_de_autoaprobacion():
    """Decision D2: aprobar es de una persona; el aplicador no puede
    saltarse esa separacion ni con una variable."""
    # Ni el aplicador ni la Lambda de avisos: aprobar es de una persona.
    assert "AGENTE_IAM_PERMITIR_AUTOAPROBACION" not in _props("FuncionAvisos")["Environment"]["Variables"]
    variables = _props("FuncionAplicador")["Environment"]["Variables"]
    assert "AGENTE_IAM_PERMITIR_AUTOAPROBACION" not in variables
    assert variables == {
        "ALMACEN": "dynamodb",
        "TABLA_SOLICITUDES": "agente-iam-solicitudes",
        "DIR_CACHE_CATALOGO": "/var/task/catalogo",
        # Fase 23: el pool y los clientes de la confianza del rol de persona (ver el test siguiente).
        "AGENTE_IAM_POOL_ID": _POOL_DESDE_LA_DISCOVERY_URL,
        "AGENTE_IAM_CLIENTES": _CLIENTES_DEL_APLICADOR,
    }


def test_el_runtime_admite_el_cliente_web_solo_si_llega_el_parametro():
    """Fase 23: el cliente de la pagina (`agente-iam-web`) vive en la pila `web`; hasta que se despliega, el parametro
    va vacio y el autorizador solo conoce al de la CLI. Con el parametro, admite los dos."""
    plantilla = _plantilla()
    parametro = plantilla["Parameters"]["ClienteWebId"]
    assert parametro["Type"] == "String"
    assert parametro["Default"] == ""
    assert parametro["AllowedPattern"] == "^([a-z0-9]{26})?$"
    assert re.fullmatch(parametro["AllowedPattern"], "")
    assert re.fullmatch(parametro["AllowedPattern"], "a1b2c3d4e5f6g7h8i9j0k1l2m3")
    assert not re.fullmatch(parametro["AllowedPattern"], "a1b2c3d4e5f6g7h8i9j0k1l2m")  # 25
    assert not re.fullmatch(parametro["AllowedPattern"], "A1B2C3D4E5F6G7H8I9J0K1L2M3")  # mayusculas
    assert plantilla["Conditions"]["ConWeb"] == {"Fn::Not": [{"Fn::Equals": [{"Ref": "ClienteWebId"}, ""]}]}
    jwt = _props("Runtime")["AuthorizerConfiguration"]["CustomJWTAuthorizer"]
    assert jwt["AllowedClients"] == {
        "Fn::If": ["ConWeb", [{"Ref": "ClienteId"}, {"Ref": "ClienteWebId"}], [{"Ref": "ClienteId"}]]}
    # Sin ClienteWebId el resultado es exactamente el de antes: [ClienteId].
    assert jwt["AllowedClients"]["Fn::If"][2] == [{"Ref": "ClienteId"}]


def test_el_aplicador_recibe_el_pool_desde_la_discovery_url_y_los_clientes():
    """El id del pool es el cuarto trozo de la URL de descubrimiento partida por `/` (`https:`, vacio, host, pool):
    asi no hace falta un parametro mas. El runtime NO recibe variables nuevas (ver el test del runtime)."""
    variables = _props("FuncionAplicador")["Environment"]["Variables"]
    assert variables["AGENTE_IAM_POOL_ID"] == {"Fn::Select": [3, {"Fn::Split": ["/", {"Ref": "DiscoveryUrl"}]}]}
    assert variables["AGENTE_IAM_POOL_ID"] == _POOL_DESDE_LA_DISCOVERY_URL
    assert variables["AGENTE_IAM_CLIENTES"] == {
        "Fn::If": ["ConWeb", {"Fn::Sub": "${ClienteId},${ClienteWebId}"}, {"Ref": "ClienteId"}]}
    # La misma cuenta que hace CloudFormation, a mano, con una URL de descubrimiento valida.
    url = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbC123/.well-known/openid-configuration"
    assert url.split("/")[3] == "us-east-1_AbC123"
    # El runtime no gana variables: su dict exacto lo fija otro test.
    assert not [v for v in _props("Runtime")["EnvironmentVariables"] if v.startswith("AGENTE_IAM_")]


def test_el_registro_del_aplicador_se_retiene():
    r = _recursos()["RegistroAplicador"]
    assert r["Type"] == "AWS::Logs::LogGroup"
    assert r["DeletionPolicy"] == "Retain"
    assert r["UpdateReplacePolicy"] == "Retain"
    assert r["Properties"]["RetentionInDays"] == 365
    assert r["Properties"]["LogGroupName"] == "/aws/lambda/agente-iam-aplicador"


def test_el_disparador_solo_despierta_con_filas_aprobadas():
    p = _props("DisparadorAplicador")
    [filtro] = p["FilterCriteria"]["Filters"]
    assert json.loads(filtro["Pattern"]) == json.loads(PATRON_FILTRO)
    assert filtro["Pattern"] == PATRON_FILTRO
    assert p["EventSourceArn"] == {"Ref": "StreamArn"}
    assert p["FunctionName"] == {"Ref": "FuncionAplicador"}
    assert p["StartingPosition"] == "LATEST"
    assert p["Enabled"] is True


def test_el_disparador_va_de_uno_en_uno_con_dos_reintentos_y_cola_de_fallos():
    p = _props("DisparadorAplicador")
    assert p["BatchSize"] == 1
    assert p["MaximumRetryAttempts"] == 2
    assert p["BisectBatchOnFunctionError"] is False
    assert p["MaximumRecordAgeInSeconds"] == 3600
    assert p["DestinationConfig"] == {"OnFailure": {"Destination": {"Fn::GetAtt": ["ColaFallos", "Arn"]}}}


# --- Avisos por correo (Fase 23, bloque 3) -------------------------------------


def test_la_funcion_de_avisos_usa_el_zip_del_aplicador_su_rol_y_su_remitente():
    p = _props("FuncionAvisos")
    assert p["FunctionName"] == "agente-iam-avisos"
    assert p["Handler"] == "agente_iam.avisos.manejador"
    assert p["Runtime"] == "python3.12"
    assert p["Architectures"] == ["arm64"]
    # El mismo zip que el aplicador: avisos.py viaja con el (scripts/empaquetar.sh); ni clave ni parametro nuevo.
    assert p["Code"] == {
        "S3Bucket": {"Fn::Sub": "agente-iam-despliegue-${AWS::AccountId}"},
        "S3Key": {"Ref": "ClaveCodigoAplicador"},
    }
    assert p["Code"] == _props("FuncionAplicador")["Code"]
    assert p["Role"] == {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:role/AgenteIAM-Avisos"}
    assert p["Timeout"] == 30
    assert p["MemorySize"] == 256
    # Sin AWS_REGION (la pone Lambda) y sin el interruptor de autoaprobacion; el remitente entra por parametro.
    assert p["Environment"]["Variables"] == {
        "AGENTE_IAM_REMITENTE": {"Ref": "CorreoRemitente"},
        "AGENTE_IAM_URL_WEB": {"Ref": "UrlWebAvisos"},
    }
    assert p["LoggingConfig"] == {"LogGroup": {"Ref": "RegistroAvisos"}}
    assert "ReservedConcurrentExecutions" not in p
    assert "VpcConfig" not in p
    # El Ref del LoggingConfig ya ordena el grupo antes que la funcion (un DependsOn encima lo avisa cfn-lint W3005).
    assert p["Tags"] == [{"Key": "proyecto", "Value": "agente-iam"}]


def test_el_registro_de_avisos_se_retiene():
    r = _recursos()["RegistroAvisos"]
    assert r["Type"] == "AWS::Logs::LogGroup"
    assert r["DeletionPolicy"] == "Retain"
    assert r["UpdateReplacePolicy"] == "Retain"
    assert r["Properties"]["RetentionInDays"] == 365
    assert r["Properties"]["LogGroupName"] == "/aws/lambda/agente-iam-avisos"


def test_el_disparador_de_avisos_filtra_los_cuatro_estados_sin_reintentos():
    p = _props("DisparadorAvisos")
    [filtro] = p["FilterCriteria"]["Filters"]
    patron = json.loads(filtro["Pattern"])
    assert patron == {
        "eventName": ["INSERT", "MODIFY"],
        "dynamodb": {"NewImage": {"estado": {"S": ESTADOS_CON_AVISO}}},
    }
    assert len(set(patron["dynamodb"]["NewImage"]["estado"]["S"])) == 4
    assert "propuesta" not in patron["dynamodb"]["NewImage"]["estado"]["S"]
    # El filtro de Lambda no compara dos atributos: no mira OldImage. Evitar el aviso repetido es cosa del codigo.
    assert "OldImage" not in filtro["Pattern"]
    assert p["EventSourceArn"] == {"Ref": "StreamArn"}
    assert p["FunctionName"] == {"Ref": "FuncionAvisos"}
    assert p["StartingPosition"] == "LATEST"
    assert p["BatchSize"] == 1
    assert p["MaximumRetryAttempts"] == 0
    assert p["BisectBatchOnFunctionError"] is False
    assert p["Enabled"] is True
    # Sin cola ni destino: un aviso que no sale no es un fallo del circuito, queda en el log.
    assert "DestinationConfig" not in p


# --- Cola de fallos y alarma ---------------------------------------------------


def test_la_cola_de_fallos_esta_cifrada_y_guarda_dos_semanas():
    p = _props("ColaFallos")
    assert p["QueueName"] == "agente-iam-aplicador-fallos"
    assert p["MessageRetentionPeriod"] == 1209600
    assert p["SqsManagedSseEnabled"] is True


def test_la_alarma_mira_la_cola_y_avisa_al_tema():
    p = _props("AlarmaFallos")
    assert p["AlarmName"] == "agente-iam-aplicador-fallos"
    assert p["Period"] == 60
    assert p["EvaluationPeriods"] == 1
    assert p["Namespace"] == "AWS/SQS"
    assert p["MetricName"] == "ApproximateNumberOfMessagesVisible"
    assert p["Dimensions"] == [{"Name": "QueueName", "Value": {"Fn::GetAtt": ["ColaFallos", "QueueName"]}}]
    assert p["Statistic"] == "Maximum"
    assert p["Threshold"] == 0
    assert p["ComparisonOperator"] == "GreaterThanThreshold"
    assert p["TreatMissingData"] == "notBreaching"
    assert p["AlarmActions"] == [{"Ref": "TemaAlarmas"}]


def test_el_tema_envia_al_correo_del_parametro():
    assert _props("TemaAlarmas")["TopicName"] == "agente-iam-alarmas"
    s = _props("SuscripcionCorreo")
    assert s["Protocol"] == "email"
    assert s["Endpoint"] == {"Ref": "CorreoAlarmas"}
    assert s["TopicArn"] == {"Ref": "TemaAlarmas"}


# --- Trail ----------------------------------------------------------------------


def test_el_trail_solo_registra_eventos_de_datos_de_dos_recursos():
    selectores = _props("TrailDatos")["AdvancedEventSelectors"]
    campos = [{f["Field"]: f for f in s["FieldSelectors"]} for s in selectores]
    assert len(campos) == 2
    for c in campos:
        assert c["eventCategory"]["Equals"] == ["Data"]
    runtime, lambda_ = campos
    assert set(runtime) == {"eventCategory", "resources.type"}
    assert runtime["resources.type"]["Equals"] == ["AWS::BedrockAgentCore::Runtime"]
    assert set(lambda_) == {"eventCategory", "resources.type", "resources.ARN"}
    assert lambda_["resources.type"]["Equals"] == ["AWS::Lambda::Function"]
    assert lambda_["resources.ARN"]["Equals"] == [
        {"Fn::Sub": "arn:aws:lambda:us-east-1:${AWS::AccountId}:function:agente-iam-aprobacion"}
    ]


def test_el_trail_es_de_una_region_y_valida_sus_ficheros():
    p = _props("TrailDatos")
    assert p["TrailName"] == "agente-iam-datos"
    assert p["IsLogging"] is True
    assert p["IsMultiRegionTrail"] is False
    assert p["IncludeGlobalServiceEvents"] is False
    assert p["EnableLogFileValidation"] is True
    assert _recursos()["TrailDatos"]["DependsOn"] == "PoliticaBucketTrail"


def test_el_bucket_del_trail_es_privado_cifrado_con_caducidad_y_se_retiene():
    r = _recursos()["BucketTrail"]
    p = r["Properties"]
    assert p["BucketName"] == {"Fn::Sub": "agente-iam-trail-datos-${AWS::AccountId}"}
    assert all(p["PublicAccessBlockConfiguration"].values())
    assert p["PublicAccessBlockConfiguration"].keys() == {
        "BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"}
    [cifrado] = p["BucketEncryption"]["ServerSideEncryptionConfiguration"]
    assert cifrado["ServerSideEncryptionByDefault"] == {"SSEAlgorithm": "AES256"}
    assert p["OwnershipControls"] == {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}
    [regla] = p["LifecycleConfiguration"]["Rules"]
    assert regla["Status"] == "Enabled"
    assert regla["ExpirationInDays"] == 90
    assert r["DeletionPolicy"] == "Retain"
    assert r["UpdateReplacePolicy"] == "Retain"


def test_el_bucket_del_trail_solo_deja_escribir_a_su_trail_y_solo_por_tls():
    sentencias = _props("PoliticaBucketTrail")["PolicyDocument"]["Statement"]
    arn_trail = {"Fn::Sub": "arn:aws:cloudtrail:us-east-1:${AWS::AccountId}:trail/agente-iam-datos"}
    permitidas = [s for s in sentencias if s["Effect"] == "Allow"]
    assert sorted(s["Action"] for s in permitidas) == ["s3:GetBucketAcl", "s3:PutObject"]
    for s in permitidas:
        assert s["Principal"] == {"Service": "cloudtrail.amazonaws.com"}
        assert s["Condition"] == {"StringEquals": {"aws:SourceArn": arn_trail}}
    [put] = [s for s in permitidas if s["Action"] == "s3:PutObject"]
    assert put["Resource"] == {"Fn::Sub": "${BucketTrail.Arn}/AWSLogs/${AWS::AccountId}/*"}
    [deny] = [s for s in sentencias if s["Effect"] == "Deny"]
    assert deny["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}


# --- Generales ------------------------------------------------------------------


def test_nada_abre_la_puerta_a_todos():
    """Sin permisos de invocacion entre servicios ni principal comodin en un Allow."""
    assert _por_tipo("AWS::Lambda::Permission") == {}
    for nombre, r in _por_tipo("AWS::S3::BucketPolicy").items():
        for s in r["Properties"]["PolicyDocument"]["Statement"]:
            if s["Effect"] == "Allow":
                assert s["Principal"] != "*", nombre
                assert s["Principal"] != {"AWS": "*"}, nombre


def test_los_recursos_del_sistema_llevan_prefijo_agente_iam():
    nombres = {
        "ColaFallos": "QueueName",
        "RegistroAplicador": "LogGroupName",
        "FuncionAplicador": "FunctionName",
        "RegistroAvisos": "LogGroupName",
        "FuncionAvisos": "FunctionName",
        "TemaAlarmas": "TopicName",
        "AlarmaFallos": "AlarmName",
        "TrailDatos": "TrailName",
    }
    for recurso, campo in nombres.items():
        assert _props(recurso)[campo].startswith("agente-iam-") or _props(recurso)[campo].startswith("/aws/lambda/agente-iam-"), recurso
    assert _props("BucketTrail")["BucketName"]["Fn::Sub"].startswith("agente-iam-")
    # El runtime no admite guiones en el nombre: lleva el prefijo con guion bajo.
    assert _props("Runtime")["AgentRuntimeName"].startswith("agente_iam_")


def test_los_recursos_con_etiquetas_llevan_el_proyecto():
    for nombre, r in _recursos().items():
        etiquetas = r["Properties"].get("Tags")
        if etiquetas is None:
            continue
        if isinstance(etiquetas, dict):
            assert etiquetas == {"proyecto": "agente-iam"}, nombre
        else:
            assert {"Key": "proyecto", "Value": "agente-iam"} in etiquetas, nombre


def test_las_salidas_prometidas_existen():
    assert set(_plantilla()["Outputs"]) >= {
        "RuntimeArn", "RuntimeId", "FuncionAplicadorArn", "FuncionAvisosArn", "ColaFallosArn", "TrailArn", "TemaAlarmasArn",
        "GrupoLogsRuntime"}


def test_la_url_del_enlace_del_aviso_solo_admite_la_pagina_del_sistema():
    """Fase 28: el enlace va en un correo; un patron abierto dejaria mandar a la persona a otro sitio."""
    p = _plantilla()["Parameters"]["UrlWebAvisos"]
    assert p["Default"] == ""
    for buena in ("", "https://d111111abcdef8.cloudfront.net", "https://agente-iam.mateo.solutions"):
        assert re.fullmatch(p["AllowedPattern"], buena), buena
    for mala in ("https://evil.example.org", "http://agente-iam.mateo.solutions", "https://agente-iam.mateo.solutions/x"):
        assert not re.fullmatch(p["AllowedPattern"], mala), mala
