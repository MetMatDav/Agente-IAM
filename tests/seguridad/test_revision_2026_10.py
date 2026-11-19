"""Revision de octubre de 2026, contrastada con la logica de evaluacion de IAM.

Cada bloque cubre un hallazgo:

  - recurso: ninguna capa comparaba los Resource con el formulario.
  - nivel: 'administracion' concedia gestion de permisos de recurso.
  - escalada sin PassRole: dos vectores que faltaban en la lista negra.
  - techo: su Deny debe espejar la lista negra dentro de los servicios
    permitidos, porque es lo unico que recorta para este sistema.
  - alta: el beneficiario tiene que llevar el techo antes de pedir nada.
  - huella: el aprobador firma lo que vio, no lo que haya en el almacen.
  - aplicador: tres fallos de su flujo.
"""

import json
import subprocess
import sys
import urllib.parse
from fnmatch import fnmatch
from pathlib import Path

import pytest
from botocore.stub import Stubber

from agente_iam import aplicador, aprobar, coherencia, config, huella, identidad, orquestador, simulacion
from agente_iam.herramientas import catalogo, validacion
from agente_iam.config import ACCIONES_PROHIBIDAS, NOMBRE_TECHO, SERVICIOS_PERMITIDOS
from agente_iam.herramientas.validacion import _arn_demasiado_amplio, _revisar_lista_negra
from agente_iam.models import IdentidadVerificada, PropuestaPolitica
from tests.dobles import _ANA, _CUENTA, _cliente, _propuesta, _solicitud

_RAIZ = Path(__file__).resolve().parents[2]
_ARN = _ANA
_TECHO = f"arn:aws:iam::{_CUENTA}:policy/{NOMBRE_TECHO}"


_IDENTIDAD = {"principal_arn": _ARN, "tipo": "user", "existe": True, "cuenta": _CUENTA}


# --- recurso -----------------------------------------------------------------


@pytest.mark.parametrize("recurso", [
    "arn:aws:s3:::finanzas-2026",
    "arn:aws:s3:::finanzas-2026/*",
    "arn:aws:s3:::finanzas-2026/cierres/2026/*",
])
def test_el_recurso_del_formulario_y_lo_que_hay_dentro_pasa(recurso):
    assert coherencia.fuera_del_recurso(recurso, "s3", "finanzas-2026", "us-east-1", _CUENTA) is None


@pytest.mark.parametrize("recurso", [
    "arn:aws:s3:::*",                    # todos los buckets
    "arn:aws:s3:::*/*",                  # todos los objetos
    "arn:aws:s3:::finanzas-2026*",       # tambien finanzas-2026-rrhh
    "arn:aws:s3:::*/finanzas-2026",      # esa clave en cualquier bucket
    "arn:aws:s3:::finanzas-2026-rrhh",   # otro bucket que empieza igual
    "arn:aws:s3:::otro-bucket",
    "arn:aws:sqs:us-east-1:111122223333:finanzas-2026",  # otro servicio
    "arn:aws:s3:::copia-finanzas-2026",  # termina igual (22-10-2026)
    "finanzas-2026",                     # no es un ARN (22-10-2026)
])
def test_lo_que_imita_al_recurso_no_pasa(recurso):
    assert coherencia.fuera_del_recurso(recurso, "s3", "finanzas-2026", "us-east-1", _CUENTA)


# --- S2 (24-10-2026): el nombre, en la posicion que nombra el recurso -------


@pytest.mark.parametrize("servicio,nombre,recurso", [
    ("s3", "finanzas-2026", "arn:aws:s3:::nominas/finanzas-2026/*"),   # objetos de OTRO bucket
    ("s3", "finanzas-2026", "arn:aws:s3:::nominas/finanzas-2026"),     # un objeto de otro bucket
    ("s3", "finanzas-2026", "arn:aws:s3:us-east-1:111122223333:accesspoint/finanzas-2026"),
    ("s3", "finanzas-2026", "arn:aws:s3:us-east-1:111122223333:accesspoint/finanzas-2026/object/*"),
    ("s3", "finanzas-2026", "arn:aws:s3:::agente-iam-paquete-111122223333/finanzas-2026"),
    # Con region y cuenta no es el ARN de un bucket, aunque el nombre este en su sitio.
    ("s3", "finanzas-2026", "arn:aws:s3:us-east-1:111122223333:finanzas-2026/*"),
    ("dynamodb", "finanzas-2026", "arn:aws:dynamodb:us-east-1:111122223333:table/nominas/index/finanzas-2026"),
    ("dynamodb", "table", "arn:aws:dynamodb:us-east-1:111122223333:table/*"),
    ("dynamodb", "pedidos", "arn:aws:dynamodb:us-east-1:111122223333:global-table/pedidos"),
    ("lambda", "function", "arn:aws:lambda:us-east-1:111122223333:function:*"),
    ("lambda", "f", "arn:aws:lambda:us-east-1:111122223333:layer:f"),
    ("lambda", "f", "arn:aws:lambda:us-east-1:111122223333:function:otra:f"),
    ("logs", "log-group", "arn:aws:logs:us-east-1:111122223333:log-group:*"),
    ("logs", "g", "arn:aws:logs:us-east-1:111122223333:destination:g"),
    ("logs", "g", "arn:aws:logs:us-east-1:111122223333:log-group:otro:log-stream:g"),
    ("sqs", "cola", "arn:aws:sqs:us-east-1:111122223333:cola-otra"),
    ("sns", "tema", "arn:aws:sns:us-east-1:111122223333:tema:abcd-1234"),
    ("cloudwatch", "a", "arn:aws:cloudwatch:us-east-1:111122223333:alarm:otra"),
    ("cloudwatch", "a", "arn:aws:cloudwatch::111122223333:dashboard/a"),
    ("ec2", "todas-las-instancias", "arn:aws:ec2:us-east-1:111122223333:instance/todas-las-instancias"),
])
def test_el_nombre_fuera_de_su_sitio_no_es_el_recurso(servicio, nombre, recurso):
    assert coherencia.fuera_del_recurso(recurso, servicio, nombre, "us-east-1", _CUENTA)


@pytest.mark.parametrize("servicio,nombre,recurso", [
    ("dynamodb", "pedidos", "arn:aws:dynamodb:us-east-1:111122223333:table/pedidos/stream/*"),
    ("lambda", "f", "arn:aws:lambda:us-east-1:111122223333:function:f"),
    ("lambda", "f", "arn:aws:lambda:us-east-1:111122223333:function:f:prod"),
    ("logs", "/aws/x", "arn:aws:logs:us-east-1:111122223333:log-group:/aws/x"),
    ("logs", "/aws/x", "arn:aws:logs:us-east-1:111122223333:log-group:/aws/x:*"),
    ("logs", "/aws/x", "arn:aws:logs:us-east-1:111122223333:log-group:/aws/x:log-stream:s1"),
    ("sqs", "cola", "arn:aws:sqs:us-east-1:111122223333:cola"),
    ("sns", "tema", "arn:aws:sns:us-east-1:111122223333:tema"),
    ("cloudwatch", "a", "arn:aws:cloudwatch:us-east-1:111122223333:alarm:a"),
])
def test_el_nombre_en_su_sitio_es_el_recurso(servicio, nombre, recurso):
    assert coherencia.fuera_del_recurso(recurso, servicio, nombre, "us-east-1", _CUENTA) is None


@pytest.mark.parametrize("servicio,recurso", [
    ("dynamodb", "table"), ("dynamodb", "index"), ("lambda", "function"), ("lambda", "layer"),
    ("logs", "log-group"), ("s3", "accesspoint"), ("cloudwatch", "alarm"), ("s3", "Job"),
])
def test_un_recurso_que_es_una_palabra_del_arn_se_rechaza_antes_del_modelo(servicio, recurso):
    campos = _solicitud(servicio, recurso, "escritura").campos
    assert any("palabra del formato de ARN" in m for m in coherencia.chequeos_formulario(campos))


def test_una_palabra_de_otro_servicio_no_se_rechaza():
    # `table` es una palabra de dynamodb, no de sqs: una cola puede llamarse asi.
    assert coherencia.chequeos_formulario(_solicitud("sqs", "table", "escritura").campos) == []


# --- S5 (24-10-2026): en s3, la cuenta del recurso va en la condicion --------


def _propuesta_s3(condicion) -> PropuestaPolitica:
    return _propuesta(["s3:PutObject"], condicion=condicion)


_VARIABLE = "${aws:PrincipalAccount}"


@pytest.mark.parametrize("condicion", [
    None,
    {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
    {"StringEquals": {"aws:ResourceAccount": "999999999999"}},
    {"StringEquals": {"aws:ResourceAccount": [_VARIABLE, "999999999999"]}},
    {"StringEqualsIfExists": {"aws:ResourceAccount": _VARIABLE}},   # sin la clave pasaria
    {"StringLike": {"aws:ResourceAccount": "*"}},
    # Access Analyzer trata s3:ResourceAccount como otra clave y falla contra
    # el techo (medido el 25-10-2026), con variable o con literal.
    {"StringEquals": {"s3:ResourceAccount": _VARIABLE}},
    {"StringEquals": {"s3:ResourceAccount": _CUENTA}},
    # La literal tampoco: el techo lleva la variable (medido el 25-10-2026).
    {"StringEquals": {"aws:ResourceAccount": _CUENTA}},
])
def test_s3_sin_la_cuenta_del_recurso_se_bloquea(monkeypatch, condicion):
    """Un bucket de otra cuenta era "el recurso pedido": el ARN de S3 no
    lleva cuenta. Con s3:PutObject, el beneficiario copiaba fuera lo que ya
    podia leer."""
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: False)
    bloqueos, _ = coherencia.chequeos_posteriores(
        _propuesta_s3(condicion), _solicitud(tipo="escritura"), _IDENTIDAD)
    assert any(
        "condicion de cuenta del recurso" in b and "aws:ResourceAccount" in b and _VARIABLE in b
        for b in bloqueos
    ), bloqueos


@pytest.mark.parametrize("clave", ["aws:ResourceAccount", "AWS:resourceaccount"])
def test_s3_con_la_cuenta_del_recurso_pasa(monkeypatch, clave):
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: False)
    bloqueos, _ = coherencia.chequeos_posteriores(
        _propuesta_s3({"StringEquals": {clave: _VARIABLE}}), _solicitud(tipo="escritura"), _IDENTIDAD)
    assert bloqueos == []


def test_con_el_techo_literal_la_cuenta_literal_pasa_y_la_variable_no(monkeypatch):
    """Si el techo pasa a llevar la cuenta literal, la constante es None y
    S5 espera la cuenta verificada."""
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: False)
    monkeypatch.setattr(config, "VALOR_CUENTA_DEL_RECURSO", None)
    ok, _ = coherencia.chequeos_posteriores(
        _propuesta_s3({"StringEquals": {"aws:ResourceAccount": _CUENTA}}),
        _solicitud(tipo="escritura"), _IDENTIDAD)
    assert ok == []
    mal, _ = coherencia.chequeos_posteriores(
        _propuesta_s3({"StringEquals": {"aws:ResourceAccount": _VARIABLE}}),
        _solicitud(tipo="escritura"), _IDENTIDAD)
    assert any(_CUENTA in b and "aws:ResourceAccount" in b for b in mal), mal


def test_la_cuenta_del_recurso_solo_se_exige_en_s3(monkeypatch):
    """Los ARN de los otros siete servicios llevan cuenta, y el chequeo 4 ya
    la compara con la del beneficiario."""
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: False)
    bloqueos, _ = coherencia.chequeos_posteriores(
        _propuesta(["dynamodb:GetItem"], ["arn:aws:dynamodb:us-east-1:111122223333:table/finanzas-2026"]),
        _solicitud("dynamodb"), _IDENTIDAD)
    assert bloqueos == []


def test_el_agente_conoce_las_reglas_nuevas():
    """El loop de reparacion lo corrige igual, pero cada vuelta cuesta; la
    regla escrita en el prompt evita la primera."""
    from agente_iam.agente import SYSTEM_PROMPT

    # La condicion sale de la misma constante que usa S5: no pueden divergir.
    esperado = '"Condition": {"StringEquals": {"aws:ResourceAccount": "%s"}}' % config.VALOR_CUENTA_DEL_RECURSO
    assert esperado in SYSTEM_PROMPT
    assert '"s3:ResourceAccount"' not in SYSTEM_PROMPT
    assert "lectura o listado" in SYSTEM_PROMPT


def test_la_regla_2c_pide_copiar_la_variable_de_cuenta_sin_sustituirla():
    """MEDICIONES M.5 (25-10-2026): las siete solicitudes de s3 gastaron dos
    intentos porque el modelo cambiaba `${aws:PrincipalAccount}` por la cuenta
    literal de los datos verificados; S5 lo bloqueaba y el segundo intento
    ponia la variable. La regla 2c lo dice antes de la primera vuelta."""
    from agente_iam.agente import SYSTEM_PROMPT, aviso_variable_de_cuenta

    regla_2c = SYSTEM_PROMPT.split("\n2c. ")[1].split("\n2d. ")[0]
    assert config.VALOR_CUENTA_DEL_RECURSO == "${aws:PrincipalAccount}"
    assert "copiala tal cual" in regla_2c
    assert "No la sustituyas por el numero de cuenta" in regla_2c
    # Con el techo de cuenta literal (None) el modelo recibe `<cuenta>` y SI
    # debe sustituirlo: el aviso no aplica.
    assert aviso_variable_de_cuenta(None) == ""
    assert aviso_variable_de_cuenta("${aws:PrincipalAccount}") != ""


def test_todas_las_tablas_no_es_la_tabla_pedida():
    t = "arn:aws:dynamodb:us-east-1:111122223333:table/"
    assert coherencia.fuera_del_recurso(t + "pedidos", "dynamodb", "pedidos", "us-east-1", _CUENTA) is None
    assert coherencia.fuera_del_recurso(t + "pedidos/index/*", "dynamodb", "pedidos", "us-east-1", _CUENTA) is None
    assert coherencia.fuera_del_recurso(t + "*", "dynamodb", "pedidos", "us-east-1", _CUENTA)
    # Region y cuenta tienen que cuadrar cuando el ARN las lleva.
    otra_region = "arn:aws:dynamodb:eu-west-1:111122223333:table/pedidos"
    assert "region" in coherencia.fuera_del_recurso(otra_region, "dynamodb", "pedidos", "us-east-1", _CUENTA)
    otra_cuenta = "arn:aws:dynamodb:us-east-1:999999999999:table/pedidos"
    assert "cuenta" in coherencia.fuera_del_recurso(otra_cuenta, "dynamodb", "pedidos", "us-east-1", _CUENTA)


def test_resource_estrella_lo_juzga_la_baranda_no_la_coherencia():
    assert coherencia.fuera_del_recurso("*", "s3", "finanzas-2026", "us-east-1", _CUENTA) is None


def test_el_chequeo_posterior_bloquea_todos_los_buckets(monkeypatch):
    monkeypatch.setattr(coherencia, "excede_tipo_acceso", lambda a, t: False)
    bloqueos, _ = coherencia.chequeos_posteriores(
        _propuesta(["s3:GetObject"], ["arn:aws:s3:::*"]), _solicitud(), _IDENTIDAD
    )
    assert any("no se limita al recurso 'finanzas-2026'" in b for b in bloqueos)


def test_la_baranda_tambien_corta_el_comodin_como_recurso():
    assert _arn_demasiado_amplio("arn:aws:s3:::*")
    assert _arn_demasiado_amplio("arn:aws:sqs:us-east-1:111122223333:*")
    assert _arn_demasiado_amplio("arn:aws:s3:::finanzas-2026/*") is None


# --- nivel y escalada --------------------------------------------------------


def test_administracion_no_concede_politicas_de_recurso(monkeypatch):
    # Catalogo de juguete (O3, 24-10-2026): hasta esa fecha este test usaba
    # el catalogo real cacheado y, en un checkout limpio como el del CI, lo
    # descargaba de internet. Lo que prueba es la regla (IsPermissionManagement
    # excede todo tipo de acceso), no la clasificacion que AWS da hoy a
    # s3:PutBucketPolicy, que mide el funcional del techo.
    monkeypatch.setitem(catalogo._MEMORIA, "s3", {
        "putbucketpolicy": {"recursos": [{"Name": "bucket"}],
                            "propiedades": {"IsWrite": True, "IsPermissionManagement": True}},
    })
    bloqueos, _ = coherencia.chequeos_posteriores(
        _propuesta(["s3:PutBucketPolicy"], ["arn:aws:s3:::finanzas-2026"]),
        _solicitud(tipo="administracion"), _IDENTIDAD,
    )
    assert any("gestion de permisos" in b for b in bloqueos)


def test_los_tests_sin_red_no_descargan_el_catalogo(monkeypatch, sin_salida_a_aws):
    """El guardian de tests/conftest.py corta tambien `urllib` (O3): el
    catalogo traga la excepcion y lo convierte en duda, asi que solo
    anotarlo y fallar al final lo hace visible. Aqui se comprueba que lo
    anota, y se vacia la lista para que este test no falle por ello."""
    import urllib.request

    with pytest.raises(Exception, match="sin red"):
        urllib.request.urlopen("https://servicereference.us-east-1.amazonaws.com/v1/s3/s3.json")
    assert sin_salida_a_aws
    assert "servicereference" in sin_salida_a_aws[0]
    sin_salida_a_aws.clear()


def test_el_guardian_corta_tambien_un_opener_de_urllib(sin_salida_a_aws):
    """El cliente de aprobacion envia con un opener propio (no sigue
    redirecciones), que no pasa por `urlopen`: el guardian tiene que cortar
    tambien `OpenerDirector.open`, o ese camino saldria a la red sin avisar."""
    import urllib.request

    abridor = urllib.request.build_opener()
    with pytest.raises(Exception, match="sin red"):
        abridor.open("https://abc123.lambda-url.us-east-1.on.aws/")
    assert sin_salida_a_aws
    assert "lambda-url" in sin_salida_a_aws[0]
    sin_salida_a_aws.clear()


@pytest.mark.parametrize("accion,recurso", [
    ("lambda:UpdateFunctionConfiguration", "arn:aws:lambda:us-east-1:111122223333:function:f"),
    ("ec2:ModifyInstanceAttribute", "arn:aws:ec2:us-east-1:111122223333:instance/i-1"),
])
def test_escalada_sin_passrole_se_bloquea(monkeypatch, accion, recurso):
    # La lista negra no depende del catalogo; sin este doble lo descargaba
    # (lo destapo el guardian de urllib, O3, 24-10-2026).
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    doc = {"Statement": [{"Effect": "Allow", "Action": [accion], "Resource": [recurso]}]}
    assert any("esta prohibida" in b for b in _revisar_lista_negra(doc))


# --- el techo ----------------------------------------------------------------


def test_el_deny_del_techo_espeja_la_lista_negra_dentro_de_los_servicios_permitidos():
    """El Allow del techo deja enteros siete de los ocho servicios
    permitidos (EC2 solo `Describe*`, techo v2 del 23-10-2026), asi que para
    lo que este sistema concede su recorte de verdad son sus Deny. Toda accion
    prohibida que caiga dentro de esos servicios tiene que estar negada
    alli; las de iam/sts/organizations ya las niega implicitamente."""
    techo = json.loads((_RAIZ / "infra/boundary-agente-iam-techo.json").read_text())
    negadas = [a.lower() for st in techo["Statement"] if st["Effect"] == "Deny" for a in st["Action"]]
    dentro = [p for p in ACCIONES_PROHIBIDAS if p.split(":")[0] in SERVICIOS_PERMITIDOS]
    faltan = [p for p in dentro if not any(fnmatch(p.lower(), d) for d in negadas)]
    assert faltan == []


# --- requisito de alta -------------------------------------------------------


@pytest.mark.parametrize("boundary,rechazada", [
    (None, True),
    (f"arn:aws:iam::{_CUENTA}:policy/OtroTecho", True),
    (_TECHO, False),
])
def test_sin_el_techo_se_rechaza_antes_del_modelo(monkeypatch, boundary, rechazada):
    ident = IdentidadVerificada(**_IDENTIDAD, permissions_boundary=boundary)
    monkeypatch.setattr(orquestador, "verificar", lambda arn: ident)
    motivos, _ = orquestador.chequeos_previos(_solicitud())
    assert any(NOMBRE_TECHO in m for m in motivos) is rechazada


def test_la_identidad_trae_el_boundary_del_mismo_get_user(monkeypatch):
    cliente = _cliente("iam")
    monkeypatch.setattr(identidad, "_cliente", cliente)
    with Stubber(cliente) as stub:
        stub.add_response("get_user", {"User": {
            "Path": "/", "UserName": "ana.gomez", "UserId": "AIDAEXAMPLE123456789", "Arn": _ARN,
            "CreateDate": "2026-01-01T00:00:00Z",
            "PermissionsBoundary": {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": _TECHO},
        }}, {"UserName": "ana.gomez"})
        stub.add_response("list_attached_user_policies", {"AttachedPolicies": []}, {"UserName": "ana.gomez"})
        stub.add_response("list_user_policies", {"PolicyNames": []}, {"UserName": "ana.gomez"})
        r = identidad.verificar(_ARN)
        stub.assert_no_pending_responses()
    assert r.permissions_boundary == _TECHO


def test_eficacia_simula_bajo_el_boundary(monkeypatch):
    cliente = _cliente("iam")
    monkeypatch.setattr(simulacion, "_cliente", cliente)
    doc = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::finanzas-2026/*"]}]}
    techo = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    with Stubber(cliente) as stub:
        stub.add_response(
            "simulate_custom_policy",
            {"EvaluationResults": [{"EvalActionName": "s3:GetObject", "EvalDecision": "allowed"}]},
            {"PolicyInputList": [json.dumps(doc)], "ActionNames": ["s3:GetObject"],
             "ResourceArns": ["arn:aws:s3:::finanzas-2026/*"],
             "PermissionsBoundaryPolicyInputList": [json.dumps(techo)]},
        )
        r = simulacion.eficacia(doc, boundary=techo)
    assert r["acciones_efectivas"] == ["s3:GetObject"]


# --- la huella ata lo leido con lo firmado -----------------------------------


@pytest.fixture
def aprobacion_neutra(monkeypatch):
    monkeypatch.setattr(aprobar, "revalidar", lambda r: {"aprobable": True, "bloqueos": [], "criticos": [], "menores": []})
    monkeypatch.setattr(aprobar, "comprobar_techo", lambda doc, cuenta: {"resultado": "PASS"})


def test_sin_huella_no_se_aprueba_y_se_dice_cual_confirmar(aprobacion_neutra):
    from tests.dobles import _aprobador_sso, _registro, _solicitante

    leido = _registro(solicitante=_solicitante())
    registro, bloqueos = aprobar.aprobar(leido, _aprobador_sso())
    assert registro is None
    assert huella.calcular(leido) in bloqueos[0]


def test_si_el_registro_cambio_despues_de_revisarlo_no_se_aprueba(aprobacion_neutra):
    from tests.dobles import _aprobador_sso, _registro, _solicitante

    revisado = _registro(solicitante=_solicitante())
    vista = huella.calcular(revisado)
    # Alguien amplia el documento entre la revision y la aprobacion.
    revisado["propuesta"]["policy_document"]["Statement"][0]["Resource"] = ["arn:aws:s3:::*"]
    registro, bloqueos = aprobar.aprobar(revisado, _aprobador_sso(), huella_confirmada=vista)
    assert registro is None
    assert "cambio desde que lo revisaste" in bloqueos[0]


def test_el_techo_solo_cae_al_archivo_si_no_existe(monkeypatch):
    monkeypatch.chdir(_RAIZ)
    cliente = _cliente("iam")
    monkeypatch.setattr(aprobar, "_iam_cliente", cliente)
    with Stubber(cliente) as stub:
        stub.add_client_error("get_policy", service_error_code="AccessDenied")
        with pytest.raises(Exception, match="AccessDenied"):
            aprobar.techo(_CUENTA)
        stub.add_client_error("get_policy", service_error_code="NoSuchEntity")
        _, origen = aprobar.techo(_CUENTA)
    assert "DECLARADO" in origen


def test_el_techo_se_mide_en_la_cuenta_del_beneficiario(aprobacion_neutra, monkeypatch):
    from tests.dobles import _aprobador_sso, _registro, _solicitante

    vistas = []
    monkeypatch.setattr(aprobar, "comprobar_techo", lambda doc, cuenta: vistas.append(cuenta) or {"resultado": "PASS"})
    leido = _registro(solicitante=_solicitante())
    leido["identidad_verificada"]["cuenta"] = "111111111111"
    aprobar.aprobar(leido, _aprobador_sso(), huella_confirmada=huella.calcular(leido))
    assert vistas == ["111111111111"]


# --- aplicador ---------------------------------------------------------------


def test_el_aplicador_no_importa_el_agente():
    salida = subprocess.run(
        [sys.executable, "-c", "import sys, agente_iam.aplicador; print('agente_iam.agente' in sys.modules)"],
        cwd=_RAIZ, capture_output=True, text=True, check=True,
    )
    assert salida.stdout.strip() == "False"


def test_si_otro_crea_la_politica_en_medio_no_se_adjunta_lo_ajeno(monkeypatch):
    cliente = _cliente("iam")
    monkeypatch.setattr(aplicador, "_cliente", cliente)
    nuestro = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::finanzas-2026/*"]}]}
    ajeno = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::*"]}]}
    arn = aplicador.arn_de_politica(_CUENTA, "req-rev")
    politica = {"Policy": {"PolicyName": "agente-iam-req-rev", "Arn": arn, "DefaultVersionId": "v1",
                           "Description": "otra cosa", "AttachmentCount": 0}}
    registro = {"id": "req-rev", "aprobacion": {"huella": "sha256:x", "cuando": "2026-10-20T00:00:00+00:00"}}
    with Stubber(cliente) as stub:
        stub.add_client_error("create_policy", service_error_code="EntityAlreadyExists")
        stub.add_response("get_policy", politica, {"PolicyArn": arn})
        stub.add_response("get_policy", politica, {"PolicyArn": arn})
        stub.add_response("get_policy_version", {"PolicyVersion": {
            "Document": urllib.parse.quote(json.dumps(ajeno)), "VersionId": "v1", "IsDefaultVersion": True,
        }}, {"PolicyArn": arn, "VersionId": "v1"})
        with pytest.raises(RuntimeError, match="DISTINTO"):
            aplicador.crear(registro, nuestro, _CUENTA)


def test_main_del_aplicador_termina_sin_traza(monkeypatch, capsys):
    aplicado = {"id": "req-rev", "estado": "aplicada",
                "identidad_verificada": {"principal_arn": _ARN},
                "aplicacion": {"policy_arn": "arn:x", "decision": "crear", "motivo": "m",
                               "por": {"arn_canonico": "arn:y"}}}
    monkeypatch.setattr(sys, "argv", ["aplicador", "req-rev"])
    monkeypatch.setattr(aplicador.almacen, "leer", lambda i: {"estado": "aprobada"})
    monkeypatch.setattr(aplicador, "aplicar", lambda r: (aplicado, [], []))
    monkeypatch.setattr(aplicador.almacen, "guardar_decision", lambda r, b, e, clave: "disco://req-rev")
    aplicador.main()
    assert "Guardado en: disco://req-rev" in capsys.readouterr().out
