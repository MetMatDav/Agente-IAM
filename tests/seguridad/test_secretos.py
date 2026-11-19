"""Ningun secreto ni la cuenta real en lo que git versiona.

No depende de instalar nada: recorre `git ls-files` (mas lo que esta a punto
de anadirse) y busca las formas conocidas de credencial. Si salta, el
arreglo NO es borrar la linea y seguir: una clave que llego a un commit hay
que darla por expuesta y rotarla.
"""

import re
import subprocess
from pathlib import Path

import pytest

_RAIZ = Path(__file__).resolve().parents[2]

_PATRONES = {
    "clave de acceso AWS": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "secreto AWS asignado": re.compile(r"aws_secret_access_key\s*=\s*\S{20,}", re.I),
    "clave privada": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "token de GitHub": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "token de Slack": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
}


def _versionables() -> list[Path]:
    salida = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=_RAIZ, capture_output=True, text=True,
    )
    if salida.returncode != 0:
        pytest.skip("no es un repositorio git")
    return [_RAIZ / f for f in salida.stdout.split() if (_RAIZ / f).is_file()]


def _texto(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def test_ningun_secreto_en_lo_versionable():
    hallazgos = [
        (str(p.relative_to(_RAIZ)), tipo)
        for p in _versionables()
        if (t := _texto(p)) is not None
        for tipo, patron in _PATRONES.items()
        if patron.search(t)
    ]
    assert hallazgos == []


_CUENTA_EN_CONFIG = re.compile(r"(?:sso_account_id\s*=\s*|arn:aws:[a-z0-9-]+::)(\d{12})\b")
# Cuentas inventadas que el repo usa a proposito: la de ejemplo de AWS, la
# "ajena" de los casos de identidad y la del docstring de localizar.py.
_FICTICIAS = {"111122223333", "999999999999", "123456789012"}


def _cuentas_reales() -> set[str]:
    """Las cuentas reales, sin llamar a AWS.

    Antes salian de `sts:GetCallerIdentity` con las credenciales por
    defecto. El 22-10-2026 se desactivo la clave de `Mateo` y el test paso
    a saltarse en silencio. Ahora se leen de `~/.aws/config` (perfiles SSO
    y roles) y de las copias de `local/` que escribe `scripts/localizar.py`.
    Asi tambien cubre las cuentas miembro de la Organization, no solo la
    de las credenciales del momento.

    Solo `local/ejemplos/` y `local/infra/`, lo que escribe `localizar.py`:
    el 23-10-2026 el paquete del eco (`local/eco/paquete/`) trajo los JSON
    de ejemplos de botocore, con ARN de cuentas inventadas como
    `111111111111`, y el test las tomo por reales (falso positivo)."""
    copias = [f for d in ("ejemplos", "infra") for f in (_RAIZ / "local" / d).rglob("*.json")]
    fuentes = [Path.home() / ".aws" / "config", *copias]
    cuentas = {m for f in fuentes if f.is_file() for m in _CUENTA_EN_CONFIG.findall(_texto(f) or "")}
    return cuentas - _FICTICIAS


def test_la_cuenta_real_no_esta_en_lo_versionable():
    """El repo usa 111122223333. La real se pone en `local/` con
    `scripts/localizar.py`. Sin `~/.aws/config` ni `local/` (por ejemplo
    en CI) no hay cuentas reales que buscar y se salta."""
    cuentas = _cuentas_reales()
    if not cuentas:
        pytest.skip("sin ~/.aws/config ni local/: no se conocen cuentas reales")
    con_cuenta = [
        str(p.relative_to(_RAIZ))
        for p in _versionables()
        if any(c in (_texto(p) or "") for c in cuentas)
    ]
    assert con_cuenta == []


@pytest.mark.parametrize("ruta", ["evidencias/funcionales/x/solicitudes/req.json", "local/ejemplos/x.json"])
def test_la_evidencia_y_lo_local_quedan_fuera_de_git(ruta):
    """La evidencia de los funcionales y las copias de `local/` llevan la
    cuenta real (Fase 11 y 9c). Si el `.gitignore` las suelta, esto salta
    antes de que `git add .` las suba."""
    salida = subprocess.run(["git", "check-ignore", "-q", ruta], cwd=_RAIZ)
    if salida.returncode == 128:
        pytest.skip("no es un repositorio git")
    assert salida.returncode == 0, f"{ruta} no esta ignorada"
