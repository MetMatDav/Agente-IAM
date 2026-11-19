"""Gobierno de regiones: PV.1 por OU y la SCP de Bedrock solo por perfil `us.`.

Desde la Fase 15 (23-10-2026) `infra/cfn/gobierno-regiones.yaml` sustituye
a la denegacion de regiones de la landing zone, que no se podia delimitar y
denegaba Haiku 4.5 en `agente-iam` (medido). La pila exime en `Workloads` la
invocacion de Bedrock de la denegacion de regiones y, para que esa exencion
no abra Bedrock en cualquier region, anade una SCP que solo deja pasar lo que
llega por un perfil `us.` de Claude creado en `us-east-1`.

Cada test se pone en rojo si se deshace una regla del diseno. Las SCP no se
pueden comprobar con el simulador de IAM, asi que `_deniega` reproduce la
condicion de la plantilla con la logica de IAM y se prueba contra las
evaluaciones que hace Bedrock con un perfil de inferencia; la prueba real va
en la matriz de la Fase 15.
"""

import re
from fnmatch import fnmatchcase
from pathlib import Path

import pytest
import yaml

PLANTILLA = Path(__file__).resolve().parents[2] / "infra" / "cfn" / "gobierno-regiones.yaml"
PV1 = "arn:aws:controlcatalog:::control/ka8e3pkqefnjsxuyc26ji580"
INVOCACION = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
CUENTA = "111122223333"


def _plantilla() -> dict:
    return yaml.safe_load(PLANTILLA.read_text(encoding="utf-8"))


def _recursos(tipo: str) -> dict[str, dict]:
    return {n: r for n, r in _plantilla()["Resources"].items() if r["Type"] == tipo}


def _controles() -> dict[str, dict]:
    return _recursos("AWS::ControlTower::EnabledControl")


def _control_de(parametro_ou: str) -> dict:
    [control] = [c for c in _controles().values() if c["Properties"]["TargetIdentifier"] == {"Ref": parametro_ou}]
    return control


def _parametros(control: dict) -> dict[str, list[str]]:
    return {p["Key"]: p["Value"] for p in control["Properties"].get("Parameters", [])}


def _scp() -> dict:
    [politica] = _recursos("AWS::Organizations::Policy").values()
    return politica


def _sentencia() -> dict:
    [sentencia] = _scp()["Properties"]["Content"]["Statement"]
    return sentencia


def _deniega(region: str, perfil: str | None) -> bool:
    """La SCP deniega esta evaluacion? Todas las condiciones a la vez (AND).
    `perfil` es el valor de `bedrock:InferenceProfileArn`, o None si la
    peticion no lo trae. Guia de IAM: un operador negado sobre una clave
    ausente es verdadero, y con `IfExists` tambien (una clave ausente con
    `...IfExists` da verdadero); `Null: "false"` exige que la clave exista."""
    contexto = {"aws:RequestedRegion": region, "bedrock:InferenceProfileArn": perfil}
    return _cumple_todas(_sentencia()["Condition"], contexto)


def _cumple_todas(condicion: dict, contexto: dict) -> bool:
    for operador, claves in condicion.items():
        base = operador.removesuffix("IfExists")
        for clave, valores in claves.items():
            valores = [valores] if isinstance(valores, str) else valores
            valor = contexto[clave]
            if base == "Null":
                cumple = (valor is None) == (valores == ["true"])
            elif valor is None:
                cumple = True  # negado o IfExists: clave ausente, verdadero
            elif base == "StringNotEquals":
                cumple = valor not in valores
            elif base == "ArnNotLike":
                cumple = not any(fnmatchcase(valor, v) for v in valores)
            else:
                raise AssertionError(f"operador no previsto en la SCP: {operador}")
            if not cumple:
                return False
    return True


def _perfil(region: str, prefijo: str, modelo: str) -> str:
    return f"arn:aws:bedrock:{region}:{CUENTA}:inference-profile/{prefijo}.anthropic.{modelo}"


MODELOS = ["claude-haiku-4-5-20251001-v1:0", "claude-sonnet-4-6", "claude-haiku-5-5"]


# --- PV.1 -----------------------------------------------------------------


def test_pv1_en_workloads_y_en_security_y_nada_mas():
    """Al apagar la denegacion de la landing zone, la OU sin PV.1 queda sin
    denegacion de regiones. Hoy solo hay dos (medido el 23-10-2026)."""
    objetivos = sorted(c["Properties"]["TargetIdentifier"]["Ref"] for c in _controles().values())
    assert objetivos == ["SecurityOuArn", "WorkloadsOuArn"]
    assert all(c["Properties"]["ControlIdentifier"] == PV1 for c in _controles().values())


@pytest.mark.parametrize("parametro_ou", ["WorkloadsOuArn", "SecurityOuArn"])
def test_pv1_solo_permite_us_east_1(parametro_ou):
    assert _parametros(_control_de(parametro_ou))["AllowedRegions"] == ["us-east-1"]


def test_workloads_exime_exactamente_la_invocacion():
    """Ni `bedrock:*` ni comodines: eximir de mas deja agentes, bases de
    conocimiento o ajuste fino libres en cualquier region."""
    exentas = _parametros(_control_de("WorkloadsOuArn"))["ExemptedActions"]
    assert sorted(exentas) == sorted(INVOCACION)
    assert not any("*" in a for a in exentas)


def test_security_no_exime_nada():
    """Las cuentas de logs y de auditoria no usan Bedrock."""
    parametros = _parametros(_control_de("SecurityOuArn"))
    assert "ExemptedActions" not in parametros
    assert "ExemptedPrincipalArns" not in parametros


@pytest.mark.parametrize("parametro_ou", ["WorkloadsOuArn", "SecurityOuArn"])
def test_ningun_principal_exento(parametro_ou):
    assert "ExemptedPrincipalArns" not in _parametros(_control_de(parametro_ou))


def test_la_exencion_depende_de_la_scp():
    """La SCP se crea antes que la exencion y se borra despues."""
    for nombre, control in _controles().items():
        assert control.get("DependsOn") == "BedrockSoloPerfilUs", nombre


# --- La SCP del proyecto ----------------------------------------------------


def test_scp_solo_en_workloads():
    """En Security no hay exencion que cerrar, y una SCP propia alli puede
    provocar drift con Control Tower."""
    props = _scp()["Properties"]
    assert props["Type"] == "SERVICE_CONTROL_POLICY"
    [objetivo] = props["TargetIds"]
    assert objetivo == {"Fn::Select": [2, {"Fn::Split": ["/", {"Ref": "WorkloadsOuArn"}]}]}


def test_scp_deniega_la_invocacion_sobre_todo():
    s = _sentencia()
    assert s["Effect"] == "Deny"
    assert sorted(s["Action"]) == sorted(INVOCACION)
    assert s["Resource"] == "*"


def test_scp_condicion_exacta():
    """La condicion revisada, tal cual. Cualquier cambio pasa por revision:
    lo que parece reforzarla puede abrirla (ver el test siguiente)."""
    condicion = _sentencia()["Condition"]
    assert condicion == {
        "StringNotEquals": {"aws:RequestedRegion": "us-east-1"},
        "ArnNotLike": {
            "bedrock:InferenceProfileArn": "arn:aws:bedrock:us-east-1:*:inference-profile/us.anthropic.claude-*"
        },
    }


def test_un_null_false_abriria_la_llamada_directa():
    """La trampa de verdad (corrige lo dicho el 23-10-2026, que culpaba a
    `IfExists`): anadir "por seguridad" `Null: false` sobre la clave del
    perfil exige que exista, y la llamada directa fuera de us-east-1, que no
    la trae, deja de denegarse. `IfExists`, en cambio, no cambia nada aqui."""
    base = _sentencia()["Condition"]
    directa = {"aws:RequestedRegion": "us-west-2", "bedrock:InferenceProfileArn": None}
    assert _cumple_todas(base, directa)
    con_null = {**base, "Null": {"bedrock:InferenceProfileArn": "false"}}
    assert not _cumple_todas(con_null, directa)
    con_ifexists = {f"{op}IfExists": v for op, v in base.items()}
    assert _cumple_todas(con_ifexists, directa)
    assert "Null" not in base


# --- Lo que hace la SCP en cada evaluacion de Bedrock -----------------------


@pytest.mark.parametrize("modelo", MODELOS)
def test_perfil_us_desde_us_east_1_pasa_en_todas_sus_evaluaciones(modelo):
    """El perfil y el modelo de origen se evaluan en us-east-1; el modelo en
    cada region de destino, con el ARN del perfil. Destinos medidos el
    23-10-2026 para los tres modelos: us-east-1, us-east-2, us-west-2."""
    perfil = _perfil("us-east-1", "us", modelo)
    assert not _deniega("us-east-1", None)
    for destino in ["us-east-1", "us-east-2", "us-west-2"]:
        assert not _deniega(destino, perfil)


@pytest.mark.parametrize("modelo", MODELOS)
def test_perfil_global_se_deniega(modelo):
    """El modelo del perfil global se evalua con region `unspecified`."""
    assert _deniega("unspecified", _perfil("us-east-1", "global", modelo))


@pytest.mark.parametrize("region", ["us-west-2", "us-east-2", "eu-west-1"])
def test_llamada_directa_fuera_de_us_east_1_se_deniega(region):
    assert _deniega(region, None)


def test_perfil_us_creado_en_otra_region_se_deniega():
    """Llamar con el perfil us. desde el endpoint de us-west-2: el ARN del
    perfil es de us-west-2. El origen tiene que ser us-east-1."""
    assert _deniega("us-west-2", _perfil("us-west-2", "us", MODELOS[0]))


def test_perfil_us_de_otro_proveedor_se_deniega():
    assert _deniega("us-east-2", f"arn:aws:bedrock:us-east-1:{CUENTA}:inference-profile/us.amazon.nova-micro-v1:0")


# --- Higiene ----------------------------------------------------------------


def test_sin_cuenta_real_ni_ids_de_ou():
    """Los ARN de las OU llevan la cuenta de gestion y el id de la
    organizacion: van como parametros, nunca en la plantilla."""
    texto = PLANTILLA.read_text(encoding="utf-8")
    assert re.findall(r"\b\d{12}\b", texto) == []
    assert re.findall(r"\bou-[a-z0-9]{4}-[a-z0-9]{8,}", texto) == []
    assert re.findall(r"\bo-[a-z0-9]{10,}", texto) == []


def test_sin_etiquetas_cortas():
    """`yaml.safe_load` no entiende `!Select` ni `!Ref`; si alguien las usa,
    estos tests dejarian de poder leer la plantilla."""
    assert re.findall(r"(?m)^[^#]*\s!(?:Ref|Sub|Select|Split|GetAtt|Join|If)\b", PLANTILLA.read_text(encoding="utf-8")) == []
