"""La puerta de los tests funcionales: cuando pueden tocar la cuenta real.

Los funcionales corren el sistema de verdad contra AWS. Regla del
proyecto: nada se escribe en la cuenta sin que Mateo lo pida. Por eso no
corren por defecto, y abrir la puerta exige tres cosas a la vez:

  1. `AGENTE_IAM_FUNCIONALES=si`, escrito a proposito. Vale exactamente
     "si": un `1` o un `true` heredado de otro proyecto no la abre.
  2. `AWS_PROFILE` explicito y en la lista blanca. Desde el 25-10-2026 solo
     `org-agente-iam-lectura` (`AWSReadOnlyAccess` en la cuenta `agente-iam`,
     por SSO), que no puede escribir en IAM; hasta entonces era `agente-iam`,
     el rol del analista de la cuenta de gestion, borrado en el bloque 4. El
     perfil por defecto (el administrador) y los de operador y aprobador no
     la abren.
  3. Sin claves en variables de entorno. Si `AWS_ACCESS_KEY_ID` esta
     puesta, botocore la usa antes que el perfil y el rol de la lista
     blanca seria decorativo.

Lo unico que escriben los funcionales es el registro de la solicitud, y
va a la carpeta de evidencia de la ejecucion: `carpeta_de_solicitudes`
se niega a devolver `solicitudes/` o algo dentro de ella.

La puerta se aplica dos veces: `tests/conftest.py` salta los funcionales
al recogerlos, y la fixture que les da el entorno vuelve a comprobarla.
Sus tests estan en `tests/seguridad/test_puerta_funcionales.py`.
"""

from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

import pytest

VARIABLE = "AGENTE_IAM_FUNCIONALES"
PERFILES_PERMITIDOS = ("org-agente-iam-lectura",)
_CLAVES_DE_ENTORNO = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")

RAIZ = Path(__file__).resolve().parent.parent


def motivo_para_no_abrir(entorno: Mapping[str, str]) -> str | None:
    """None si la puerta abre; si no, por que no, en una frase accionable."""
    if entorno.get(VARIABLE) != "si":
        return (
            f"funcionales cerrados: falta {VARIABLE}=si. Tocan la cuenta real "
            "y nunca corren por defecto."
        )
    perfil = entorno.get("AWS_PROFILE")
    if perfil not in PERFILES_PERMITIDOS:
        return (
            f"funcionales cerrados: AWS_PROFILE={perfil!r} no esta en la lista "
            f"blanca {PERFILES_PERMITIDOS}. Sin perfil se usaria el administrador."
        )
    puestas = [c for c in _CLAVES_DE_ENTORNO if entorno.get(c)]
    if puestas:
        return (
            f"funcionales cerrados: {', '.join(puestas)} en el entorno ganaria "
            f"al perfil {perfil!r}. Quitalas antes de correrlos."
        )
    return None


def exigir(entorno: Mapping[str, str]) -> None:
    """Segunda capa: la fixture que da el entorno vivo la llama antes de nada.

    Firma su motivo para que se sepa cual de las dos capas salto: si se ve
    "[segunda capa]", la primera (el conftest) no esta haciendo su trabajo.
    """
    motivo = motivo_para_no_abrir(entorno)
    if motivo:
        pytest.skip(f"{motivo} [segunda capa]")


def carpeta_de_evidencia(entorno: Mapping[str, str]) -> Path:
    """La de `scripts/pruebas.sh` (DIR_EVIDENCIA) o una nueva con fecha."""
    if entorno.get("DIR_EVIDENCIA"):
        return Path(entorno["DIR_EVIDENCIA"]).resolve()
    sello = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%SZ")
    return RAIZ / "evidencias" / "funcionales" / f"{sello}-pytest"


def carpeta_de_solicitudes(evidencia: Path, raiz: Path = RAIZ) -> Path:
    """Donde escribe el almacen en una ejecucion funcional. Nunca `solicitudes/`."""
    destino = (evidencia / "solicitudes").resolve()
    prohibida = (raiz / "solicitudes").resolve()
    if destino == prohibida or prohibida in destino.parents:
        raise ValueError(
            f"{destino} es o esta dentro de solicitudes/: los funcionales no "
            "escriben encima de los registros reales."
        )
    return destino
