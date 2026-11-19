"""Confianza de los roles del agente: entrada por Identity Center, y solo esa.

Desde el 22-10-2026 los roles `AgenteIAM-Analista` y `AgenteIAM-Aplicador`
confian solo en el rol que Identity Center crea para el permission set
`AWSAdministratorAccess`. `user/Mateo` se quito ese dia, junto con la
desactivacion de su clave: ningun usuario IAM debe volver a la confianza. Ese rol lleva un sufijo aleatorio que cambia si
el permission set se reasigna; por eso va en una condicion `ArnLike` con
comodin sobre `aws:PrincipalArn`, y el principal es la cuenta. Puesto como
principal, IAM lo traduciria a un id interno y la confianza se romperia en
silencio al recrearse el rol (guia de IAM, "Examples of policies for
delegating access").

Estos tests leen los JSON de `infra/` y se ponen en rojo si alguien quita
esa via, la abre a otros permission sets o la deja sin condicion.
"""

import json
from pathlib import Path

import pytest

INFRA = Path(__file__).resolve().parents[2] / "infra"
CUENTA = "111122223333"
PATRON_SSO = (
    f"arn:aws:iam::{CUENTA}:role/aws-reserved/sso.amazonaws.com/"
    "AWSReservedSSO_AWSAdministratorAccess_*"
)
FICHEROS = ["rol-agente-confianza.json", "rol-aplicador-confianza.json"]


def _sentencias(fichero: str) -> list[dict]:
    return json.loads((INFRA / fichero).read_text(encoding="utf-8"))["Statement"]


def _via_sso(fichero: str) -> list[dict]:
    return [s for s in _sentencias(fichero) if s.get("Sid") == "AccesoAdministradorPorIdentityCenter"]


@pytest.mark.parametrize("fichero", FICHEROS)
def test_la_via_sso_es_la_unica(fichero):
    """Una sola sentencia y es la de Identity Center: ni `user/Mateo` ni
    ningun otro principal. Una clave de usuario IAM es justo lo que esta
    migracion quita. Y, aunque manana se admitiera otra, confiar en `:root`
    sin condicion abriria el rol a cualquier principal de la cuenta con
    permiso de `sts:AssumeRole`."""
    sentencias = _sentencias(fichero)
    assert len(sentencias) == 1
    assert sentencias == _via_sso(fichero)
    for s in sentencias:
        if s["Principal"].get("AWS", "").endswith(":root"):
            assert "Condition" in s, s.get("Sid")


@pytest.mark.parametrize("fichero", FICHEROS)
def test_la_via_sso_solo_admite_el_permission_set_de_administracion(fichero):
    s = _via_sso(fichero)[0]
    assert s["Effect"] == "Allow"
    assert s["Action"] == "sts:AssumeRole"
    assert s["Principal"] == {"AWS": f"arn:aws:iam::{CUENTA}:root"}
    assert s["Condition"] == {"ArnLike": {"aws:PrincipalArn": PATRON_SSO}}
