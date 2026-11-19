"""Perfiles de inferencia: los roles y el codigo tienen que coincidir con la SCP.

Desde el 23-10-2026 el agente corre en la cuenta `agente-iam`, donde una SCP
solo deja invocar Bedrock desde us-east-1 a traves de perfiles de inferencia
geograficos `us.` de Claude (`inference-profile/us.anthropic.claude-*`). El
perfil `global.` queda denegado. Un rol que siguiera permitiendo `global.` no
daria un fallo claro: el modelo por defecto se rechazaria en runtime con
`AccessDenied`, y solo con la cuenta delante.

El perfil `us.` enruta a varias regiones de EE. UU.; la invocacion llega
tambien al modelo base en la region de destino, por eso el recurso
`foundation-model/anthropic.claude-*` se mantiene con region comodin.

Estos tests leen los JSON de `infra/` y el valor por defecto de `config`, y
se ponen en rojo si alguien vuelve a `global.` o recorta el patron `us.`.
"""

import importlib
import json
from fnmatch import fnmatchcase
from pathlib import Path

import pytest
import yaml

from tests.dobles import sentencias_de_rol

INFRA = Path(__file__).resolve().parents[2] / "infra"
CUENTA = "111122223333"
# El Analista (JSON de infra/) y el runtime (rol de la pila base, Fase 18).
FICHEROS = ["rol-agente-permisos.json", "cfn/base.yaml#RolRuntime"]
PERFIL = f"arn:aws:bedrock:us-east-1:{CUENTA}:inference-profile/"
PERFILES_US = [
    PERFIL + "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    PERFIL + "us.anthropic.claude-sonnet-4-6",
    PERFIL + "us.anthropic.claude-haiku-5-5",
]
DESTINO = "arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-haiku-5-5"


def _recursos_invocar(fichero: str) -> list[str]:
    """Recursos de la(s) sentencia(s) Allow que dan `bedrock:InvokeModel`."""
    if "#" in fichero:
        ruta, recurso = fichero.split("#")
        sentencias = sentencias_de_rol(yaml.safe_load((INFRA / ruta).read_text(encoding="utf-8")), recurso)
    else:
        sentencias = json.loads((INFRA / fichero).read_text(encoding="utf-8"))["Statement"]
    recursos: list[str] = []
    for s in sentencias:
        acciones = [s["Action"]] if isinstance(s["Action"], str) else s["Action"]
        if s["Effect"] == "Allow" and "bedrock:InvokeModel" in acciones:
            r = s["Resource"]
            recursos += [r] if isinstance(r, str) else r
    return recursos


def _permite(recursos: list[str], arn: str) -> bool:
    return any(fnmatchcase(arn, patron) for patron in recursos)


@pytest.mark.parametrize("fichero", FICHEROS)
def test_el_rol_permite_los_perfiles_us_y_su_destino(fichero):
    recursos = _recursos_invocar(fichero)
    assert recursos, "no hay sentencia Allow con bedrock:InvokeModel"
    for arn in [*PERFILES_US, DESTINO]:
        assert _permite(recursos, arn), arn


@pytest.mark.parametrize("fichero", FICHEROS)
def test_el_rol_no_permite_el_perfil_global(fichero):
    recursos = _recursos_invocar(fichero)
    assert not _permite(recursos, PERFIL + "global.anthropic.claude-haiku-4-5-20251001-v1:0")
    assert not any(fnmatchcase(PERFIL + "global.anthropic.claude-sonnet-4-6", r) for r in recursos)
    # Ningun patron deja pasar `global.*`, ni siquiera uno mas ancho que el nuestro.
    assert not any(r.startswith(PERFIL + "global.") for r in recursos)
    assert not _permite(recursos, PERFIL + "global.fabricante.modelo")


def test_el_modelo_por_defecto_es_un_perfil_us(monkeypatch):
    """Se lee `config` sin `MODEL_ID` en el entorno: si Mateo la tiene
    exportada en su shell, el test mediria su entorno y no el codigo."""
    from agente_iam import config

    monkeypatch.delenv("MODEL_ID", raising=False)
    try:
        importlib.reload(config)
        assert config.MODEL_ID.startswith("us.anthropic.claude-"), config.MODEL_ID
        # Y el rol lo permite: el defecto y los permisos no pueden divergir.
        for fichero in FICHEROS:
            assert _permite(_recursos_invocar(fichero), PERFIL + config.MODEL_ID), fichero
    finally:
        monkeypatch.undo()
        importlib.reload(config)
