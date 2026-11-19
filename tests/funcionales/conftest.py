"""Lo que necesitan los funcionales: la puerta abierta y donde dejar la evidencia.

Hasta el 25-10-2026 aqui vivia tambien `intake`, que corria el CLI con el rol
del analista de la cuenta de gestion; ese rol se borro en el bloque 4 y el
camino real es el runtime de AgentCore con JWT (`scripts/solicitar.py`), que
necesita el inicio de sesion de una persona y por eso no es un test
automatico. Queda la puerta (sin ella no se crea nada) y la guardia de que
ningun funcional escriba en `solicitudes/`.
"""

import os

import pytest

from tests.puerta import RAIZ, carpeta_de_evidencia, exigir


@pytest.fixture(scope="session")
def evidencia():
    exigir(os.environ)  # segunda capa: sin la puerta abierta no se crea nada
    carpeta = carpeta_de_evidencia(os.environ)
    carpeta.mkdir(parents=True, exist_ok=True)
    return carpeta


@pytest.fixture(scope="session", autouse=True)
def solicitudes_intactas():
    """Despues de la sesion, `solicitudes/` sigue como estaba."""
    antes = _foto(RAIZ / "solicitudes")
    yield
    assert _foto(RAIZ / "solicitudes") == antes, "un funcional escribio en solicitudes/"


def _foto(carpeta):
    if not carpeta.is_dir():
        return {}
    return {p.name: p.stat().st_mtime_ns for p in carpeta.iterdir()}

