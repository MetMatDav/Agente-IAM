"""Fase 0: congelar el comportamiento de las barandas deterministas.

Estos tests NO tocan la red ni la cuenta AWS. La unica dependencia externa
de `_revisar_lista_negra` es el catalogo (todas_exigen_wildcard) y se
reemplaza con monkeypatch: un test unitario debe ser determinista y poder
correr sin credenciales.

Cada bug corregido en el pasado (CONTEXTO §9) tiene aqui el test que lo
habria atrapado, para que ninguno regrese.
"""

import re

import pytest

from agente_iam.herramientas import catalogo, validacion
from agente_iam.herramientas.validacion import (
    _arn_demasiado_amplio,
    _concede,
    _es_comodin_amplio,
    _revisar_lista_negra,
)

# ---------------------------------------------------------------------------
# _concede: la DIRECCION del fnmatch (bug #1 del CONTEXTO: lista negra
# bidireccional). Se bloquea si la accion propuesta CUBRE una prohibida.
# ---------------------------------------------------------------------------


def test_comodin_de_servicio_cubre_prohibida():
    assert _concede("iam:*", "iam:CreateUser")


def test_comodin_de_prefijo_cubre_prohibida():
    assert _concede("iam:Create*", "iam:CreateUser")


def test_accion_inocua_no_cubre_prohibida():
    assert not _concede("s3:GetObject", "iam:CreateUser")


def test_prohibida_exacta_sin_importar_mayusculas():
    assert _concede("iam:createuser", "iam:CreateUser")


def test_direccion_no_es_bidireccional():
    # Bug #1 del CONTEXTO: con "*" en la lista, comparar en los dos sentidos
    # bloqueaba TODA politica. La prohibida NO debe "cubrir" a la propuesta.
    # (Hasta el 22-10-2026 este test usaba `s3:Get*` contra `iam:PassRole`,
    # que da False en cualquier direccion: no podia ponerse en rojo.)
    assert not _concede("s3:GetObject", "*")


def test_la_lista_negra_son_acciones_exactas():
    """`_concede` solo mira si la PROPUESTA cubre a la prohibida, asi que un
    comodin en la lista no bloquearia las acciones que nombra:
    `_concede("iam:UploadSSHPublicKey", "iam:Upload*")` es False. El diseno
    (config.py: "toda accion propuesta que CUBRA alguna de estas") es una
    lista de acciones concretas; esto impide que alguien anada un comodin
    creyendo que bloquea una familia entera."""
    from agente_iam.config import ACCIONES_PROHIBIDAS

    assert ACCIONES_PROHIBIDAS
    con_comodin = [p for p in ACCIONES_PROHIBIDAS if any(c in p for c in "*?[")]
    assert con_comodin == []
    assert all(re.fullmatch(r"[a-z0-9-]+:[A-Za-z0-9]+", p) for p in ACCIONES_PROHIBIDAS)


# ---------------------------------------------------------------------------
# _es_comodin_amplio
# ---------------------------------------------------------------------------


def test_asterisco_es_amplio():
    assert _es_comodin_amplio("*")


def test_servicio_completo_es_amplio():
    assert _es_comodin_amplio("s3:*")


def test_prefijo_estrecho_no_es_amplio():
    assert not _es_comodin_amplio("s3:Get*")


# ---------------------------------------------------------------------------
# _arn_demasiado_amplio (bug #2 del CONTEXTO: comodin dentro del ARN)
# ---------------------------------------------------------------------------


def test_recurso_estrella_es_amplio():
    assert _arn_demasiado_amplio("*") is not None


def test_region_comodin_es_amplia():
    motivo = _arn_demasiado_amplio("arn:aws:dynamodb:*:111122223333:table/x")
    assert motivo is not None
    assert "region comodin" in motivo


@pytest.mark.parametrize("arn", [
    "arn:aws:dynamodb:us-east-1:*:table/x",
    # Un punto de acceso de S3 si lleva region y cuenta (el bucket no).
    # Este caso y el del motivo venian de test_mios.py, que se fundio aqui
    # el 24-10-2026 (O12): sus otros dos tests repetian los de arriba.
    "arn:aws:s3:us-east-1:*:accesspoint/x",
])
def test_cuenta_comodin_es_amplia(arn):
    motivo = _arn_demasiado_amplio(arn)
    assert motivo is not None
    assert "cuenta comodin" in motivo


def test_arn_s3_sin_region_ni_cuenta_es_valido():
    # Los ARN de S3 llevan region y cuenta vacias por diseno del servicio.
    assert _arn_demasiado_amplio("arn:aws:s3:::finanzas-2026") is None


def test_comodin_de_ruta_final_es_legitimo():
    assert _arn_demasiado_amplio("arn:aws:s3:::finanzas-2026/*") is None


def test_texto_que_no_es_arn_no_revienta():
    assert _arn_demasiado_amplio("no-soy-un-arn") is None


# ---------------------------------------------------------------------------
# _revisar_lista_negra: la baranda completa sobre documentos reales.
# El catalogo se monkeypatchea: aqui probamos NUESTRA logica, no la de AWS.
# ---------------------------------------------------------------------------


def _doc(statements):
    return {"Version": "2012-10-17", "Statement": statements}


def test_politica_limpia_pasa(monkeypatch):
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    doc = _doc(
        [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::finanzas-2026/*"],
            }
        ]
    )
    assert _revisar_lista_negra(doc) == []


def test_comodin_de_servicio_se_bloquea(monkeypatch):
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    doc = _doc(
        [{"Effect": "Allow", "Action": ["s3:*"], "Resource": ["arn:aws:s3:::b/*"]}]
    )
    assert any("comodin" in b for b in _revisar_lista_negra(doc))


def test_accion_prohibida_se_bloquea(monkeypatch):
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    doc = _doc(
        [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": ["*"]}]
    )
    assert any("prohibida" in b for b in _revisar_lista_negra(doc))


def test_region_comodin_en_arn_se_bloquea(monkeypatch):
    # Bug #2 del CONTEXTO congelado como test.
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    doc = _doc(
        [
            {
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem"],
                "Resource": ["arn:aws:dynamodb:*:111122223333:table/x"],
            }
        ]
    )
    assert any("region comodin" in b for b in _revisar_lista_negra(doc))


def test_wildcard_exigido_sin_condition_se_bloquea(monkeypatch):
    # Bug #4 del CONTEXTO: las ec2:Describe* exigen Resource "*"; sin
    # Condition se bloquea pidiendola, no rechazando la politica entera.
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: True)
    monkeypatch.setattr(validacion, "es_escritura", lambda a: False)
    doc = _doc(
        [{"Effect": "Allow", "Action": ["ec2:DescribeInstances"], "Resource": ["*"]}]
    )
    bloqueos = _revisar_lista_negra(doc)
    assert len(bloqueos) == 1
    assert "Condition" in bloqueos[0]


def test_wildcard_exigido_con_condition_pasa(monkeypatch):
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: True)
    monkeypatch.setattr(validacion, "es_escritura", lambda a: False)
    doc = _doc(
        [
            {
                "Effect": "Allow",
                "Action": ["ec2:DescribeInstances"],
                "Resource": ["*"],
                "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            }
        ]
    )
    assert _revisar_lista_negra(doc) == []


def test_resource_estrella_con_condition_no_vale_para_acciones_con_arn(monkeypatch):
    """La excepcion de Resource "*" (con Condition) es SOLO para acciones
    que no admiten ARN. `s3:GetObject` si lo admite: un Condition no
    convierte "todos los objetos de todos los buckets" en algo acotado."""
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    doc = _doc([{
        "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["*"],
        "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
    }])
    assert any("sin limite" in b for b in _revisar_lista_negra(doc))


def test_action_y_resource_como_cadena_se_revisan_igual(monkeypatch):
    """IAM admite "Action": "x" y "Resource": "y" sin lista. La tool recibe
    el JSON que escriba el modelo; si la cadena se recorriera letra a
    letra, `iam:PassRole` y `arn:aws:s3:::*` pasarian sin bloqueo."""
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    accion = _revisar_lista_negra(_doc([
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": ["arn:aws:iam::111122223333:role/x"]}]))
    recurso = _revisar_lista_negra(_doc([
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::*"}]))
    assert any("iam:PassRole" in b and "prohibida" in b for b in accion)
    assert any("comodin" in b for b in recurso)


def test_una_duda_del_catalogo_no_abre_resource_estrella(monkeypatch):
    """`todas_exigen_wildcard` es la llave de la excepcion de Resource "*".
    Si de una accion no se sabe (None) o no hay acciones, la llave no
    abre: una duda nunca se convierte en un permiso mas amplio."""
    from agente_iam.herramientas import catalogo

    respuestas = {"ec2:DescribeInstances": False, "ec2:Inventada": None}
    monkeypatch.setattr(catalogo, "soporta_recursos", lambda a: respuestas[a])
    assert catalogo.todas_exigen_wildcard(["ec2:DescribeInstances"]) is True  # control
    assert catalogo.todas_exigen_wildcard(["ec2:DescribeInstances", "ec2:Inventada"]) is False
    assert catalogo.todas_exigen_wildcard([]) is False


# Fase 6: cada vector nuevo de la lista negra, propuesto tal cual, debe
# quedar bloqueado. Si alguien recorta ACCIONES_PROHIBIDAS, este test lo
# delata. Parametrizado desde el 24-10-2026 (O13): antes era un bucle y, si
# fallaban varias, solo se veia la primera.
@pytest.mark.parametrize("accion", [
    "iam:AddUserToGroup",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:PutUserPermissionsBoundary",
    "iam:PutRolePermissionsBoundary",
    "iam:DeleteUserPermissionsBoundary",
    "iam:DeleteRolePermissionsBoundary",
    "iam:SetDefaultPolicyVersion",
    "lambda:UpdateFunctionCode",
    "lambda:AddPermission",
    "sts:AssumeRoleWithSAML",
    "sts:AssumeRoleWithWebIdentity",
    "sts:GetFederationToken",
])
def test_vectores_de_escalada_fase6_se_bloquean(monkeypatch, accion):
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    doc = _doc(
        [
            {
                "Effect": "Allow",
                "Action": [accion],
                "Resource": ["arn:aws:iam::111122223333:role/x"],
            }
        ]
    )
    assert any("prohibida" in b for b in _revisar_lista_negra(doc)), accion


def test_lectura_legitima_de_lambda_no_se_bloquea(monkeypatch):
    # El bloqueo de lambda:UpdateFunctionCode no debe salpicar a las
    # lecturas legitimas del mismo servicio.
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    doc = _doc(
        [
            {
                "Effect": "Allow",
                "Action": ["lambda:GetFunction", "lambda:ListFunctions"],
                "Resource": ["arn:aws:lambda:us-east-1:111122223333:function:x"],
            }
        ]
    )
    assert _revisar_lista_negra(doc) == []


def test_statement_deny_se_ignora(monkeypatch):
    # Un Deny nunca concede permisos: no debe generar bloqueos.
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    doc = _doc([{"Effect": "Deny", "Action": ["iam:*"], "Resource": ["*"]}])
    assert _revisar_lista_negra(doc) == []


def test_statement_unico_como_dict_se_acepta(monkeypatch):
    # IAM permite Statement como objeto suelto, no solo como lista.
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: False)
    doc = _doc(
        {
            "Effect": "Allow",
            "Action": ["iam:PassRole"],
            "Resource": ["arn:aws:iam::111122223333:role/x"],
        }
    )
    assert len(_revisar_lista_negra(doc)) == 1


# ---------------------------------------------------------------------------
# S3 (24-10-2026): con Resource "*", solo lectura. Las escrituras sin tipo
# de recurso son casi todas de alcance de cuenta, y "*" deja fuera los
# chequeos de recurso y de recursos del sistema. Hasta esa fecha cualquier
# Condition las daba por acotadas.
# ---------------------------------------------------------------------------

_CUENTA_PURA = {
    "logs": "PutAccountPolicy", "dynamodb": "PurchaseReservedCapacityOfferings",
    "sns": "SetSMSAttributes", "s3": "PutStorageLensConfiguration",
    "cloudwatch": "PutManagedInsightRules", "lambda": "CreateCodeSigningConfig",
}


@pytest.fixture
def catalogo_de_cuenta(monkeypatch):
    """Un catalogo de juguete: cada accion del informe, sin recurso y de
    escritura, y una lectura sin recurso para el caso de control."""
    for servicio, nombre in _CUENTA_PURA.items():
        monkeypatch.setitem(catalogo._MEMORIA, servicio, {
            nombre.lower(): {"recursos": [], "propiedades": {"IsWrite": True}},
            "listaralgo": {"recursos": [], "propiedades": {"IsList": True}},
            "etiquetaralgo": {"recursos": [], "propiedades": {"IsTaggingOnly": True}},
        })


def _estrella(acciones):
    return _doc([{"Effect": "Allow", "Action": acciones, "Resource": ["*"],
                  "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}}])


@pytest.mark.parametrize("servicio,nombre", sorted(_CUENTA_PURA.items()))
def test_una_escritura_de_cuenta_con_resource_estrella_se_bloquea(catalogo_de_cuenta, servicio, nombre):
    bloqueos = _revisar_lista_negra(_estrella([f"{servicio}:{nombre}"]))
    assert any("no es de lectura ni de listado" in b and nombre in b for b in bloqueos), bloqueos


def test_el_etiquetado_sin_recurso_tambien_cuenta_como_escritura(catalogo_de_cuenta):
    assert _revisar_lista_negra(_estrella(["logs:EtiquetarAlgo"]))


def test_una_lectura_sin_recurso_con_condition_sigue_pasando(catalogo_de_cuenta):
    assert _revisar_lista_negra(_estrella(["logs:ListarAlgo"])) == []


def test_mezclar_una_lectura_con_una_escritura_de_cuenta_no_la_cuela(catalogo_de_cuenta):
    bloqueos = _revisar_lista_negra(_estrella(["logs:ListarAlgo", "logs:PutAccountPolicy"]))
    assert any("PutAccountPolicy" in b for b in bloqueos)
    assert not any("ListarAlgo" in b for b in bloqueos)


def test_la_lista_blanca_de_config_deja_pasar_lo_que_nombra(catalogo_de_cuenta, monkeypatch):
    monkeypatch.setattr(validacion, "ESCRITURAS_SIN_RECURSO_PERMITIDAS", {"logs:PutAccountPolicy": "prueba"})
    assert _revisar_lista_negra(_estrella(["logs:PutAccountPolicy"])) == []


def test_la_lista_blanca_empieza_vacia():
    """Cada entrada es una decision con su motivo; ninguna esta tomada aun."""
    from agente_iam.config import ESCRITURAS_SIN_RECURSO_PERMITIDAS

    assert ESCRITURAS_SIN_RECURSO_PERMITIDAS == {}


def test_una_duda_del_catalogo_cuenta_como_escritura(monkeypatch):
    monkeypatch.setattr(validacion, "todas_exigen_wildcard", lambda a: True)
    monkeypatch.setattr(validacion, "es_escritura", lambda a: None)
    assert _revisar_lista_negra(_estrella(["logs:Rara"]))


def test_es_escritura_lee_el_nivel_del_catalogo(catalogo_de_cuenta):
    assert catalogo.es_escritura("logs:PutAccountPolicy") is True
    assert catalogo.es_escritura("logs:EtiquetarAlgo") is True
    assert catalogo.es_escritura("logs:ListarAlgo") is False
    assert catalogo.es_escritura("logs:NoExiste") is None
    assert catalogo.es_escritura("logs:Put*") is None


def test_las_constantes_de_persona_tienen_los_valores_del_diseno(monkeypatch):
    # Fase 23, 5.1: tope de roles por persona y lista cerrada de regiones
    # (la SCP de la cuenta solo deja us-east-1). Los clientes de Cognito se
    # leen de AGENTE_IAM_CLIENTES separados por coma; se recarga el modulo
    # para probarlo y se restaura al final porque otros tests importan
    # constantes de config.
    import importlib

    from agente_iam import config

    assert config.MAX_ROLES_VIGENTES_POR_PERSONA == 5
    assert config.REGIONES_PERMITIDAS == ["us-east-1"]
    assert isinstance(config.CLIENTES_COGNITO, tuple)
    try:
        monkeypatch.setenv("AGENTE_IAM_CLIENTES", "a, b")
        importlib.reload(config)
        # Cada id sin espacios alrededor; los que no tienen la forma de un
        # cliente de Cognito quedan a la vista, no descartados.
        assert config.CLIENTES_COGNITO == ("a", "b")
        assert config.CLIENTES_COGNITO_INVALIDOS == ("a", "b")

        valido = "abcdefghij0123456789klmnop"
        assert len(valido) == 26
        monkeypatch.setenv("AGENTE_IAM_CLIENTES", f" {valido} ,{valido[:-1]}X,, ")
        importlib.reload(config)
        assert config.CLIENTES_COGNITO == (valido, valido[:-1] + "X")
        assert config.CLIENTES_COGNITO_INVALIDOS == (valido[:-1] + "X",)

        monkeypatch.setenv("AGENTE_IAM_CLIENTES", valido)
        importlib.reload(config)
        assert config.CLIENTES_COGNITO == (valido,)
        assert config.CLIENTES_COGNITO_INVALIDOS == ()

        monkeypatch.setenv("AGENTE_IAM_CLIENTES", valido + "\n")
        importlib.reload(config)
        assert config.CLIENTES_COGNITO_INVALIDOS == ()  # el strip quita el salto de linea
    finally:
        monkeypatch.undo()
        importlib.reload(config)
