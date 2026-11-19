"""Los tres tipos de tests salen de la carpeta, no de un decorador.

Cada test recibe el marcador de su carpeta (`unitarios`, `seguridad`,
`funcionales`), asi `pytest -m "not funcionales"` funciona sin que nadie
escriba `@pytest.mark` a mano y sin que carpeta y marcador se desincronicen.
Los funcionales se saltan aqui mismo si la puerta esta cerrada
(`tests/puerta.py`): es la primera de sus dos capas.
"""

import os
from pathlib import Path

import pytest

from tests.puerta import motivo_para_no_abrir

TIPOS = ("unitarios", "seguridad", "funcionales")
_TESTS = Path(__file__).resolve().parent


def _tipo(ruta: Path) -> str | None:
    try:
        primera = Path(ruta).resolve().relative_to(_TESTS).parts[0]
    except ValueError:
        return None
    return primera if primera in TIPOS else None


class LlamadaRealAAWS(RuntimeError):
    """Un test sin red intento salir a AWS."""


@pytest.fixture(autouse=True)
def sin_salida_a_aws(request, monkeypatch):
    """Unitarios y seguridad no salen a AWS, aunque falte un doble.

    22-10-2026: un unitario sin el doble de `documento_de_politica` llego a
    llamar a IAM de verdad con el perfil `default`. Nada lo impedia: la
    bateria corre en una maquina con credenciales. Aqui se corta en el
    ultimo punto comun de botocore, el envio HTTP (`URLLib3Session.send`):
    por ahi pasan las llamadas a la API, las de SSO al renovar credenciales
    y las del IMDS. `Stubber` responde antes de llegar a el, asi que los
    dobles no se ven afectados.

    Lanzar no basta: varios modulos capturan `Exception` a proposito (fail
    closed), y el intento quedaria tragado. Por eso cada intento se anota y
    el test falla al terminar. Devuelve la lista para el test que lo
    comprueba. Los funcionales no pasan por aqui: son los que si salen.
    """
    intentos: list[str] = []
    if _tipo(request.node.path) in ("unitarios", "seguridad"):
        import boto3
        import botocore.httpsession

        # Credenciales falsas y sin IMDS (22-10-2026). Sin esto, en el CI
        # (sin credenciales) boto3 las buscaba en el servicio de metadatos
        # de EC2, que es HTTP, y el guardian lo cortaba: 20 errores que en
        # local no salian porque aqui hay perfiles SSO. Ademas asi ningun
        # test de estos ve las credenciales reales de quien lo corre.
        for var in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
        monkeypatch.setenv("AWS_CONFIG_FILE", os.devnull)
        monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", os.devnull)
        monkeypatch.setattr(boto3, "DEFAULT_SESSION", None)
        # Fase 28: el orquestador busca el recurso en la cuenta antes del modelo
        # (`agente_iam.existencia`). Aqui no hay cuenta: se apaga, y la
        # comprobacion se prueba aparte con Stubber (test_existencia.py).
        monkeypatch.setenv("AGENTE_IAM_COMPROBAR_EXISTENCIA", "0")

        def bloquear(self, peticion):
            intentos.append(f"{peticion.method} {peticion.url}")
            raise LlamadaRealAAWS(f"un test sin red intento salir: {peticion.method} {peticion.url}")

        monkeypatch.setattr(botocore.httpsession.URLLib3Session, "send", bloquear)

        # urllib tambien (24-10-2026, O3). El catalogo descarga con
        # `urllib.request.urlopen`, no con botocore, y hasta esa fecha un
        # test que usaba el catalogo real lo bajaba de internet en un
        # checkout limpio (el del CI) sin que nadie lo viera: el catalogo
        # traga la excepcion y la convierte en duda, asi que tambien aqui se
        # anota y se falla al terminar. Lo local (el servidor de eco de
        # test_agente_eco) si puede: no sale de la maquina.
        import urllib.parse
        import urllib.request

        abrir = urllib.request.urlopen

        def abrir_solo_local(url, *a, **k):
            destino = url.full_url if isinstance(url, urllib.request.Request) else str(url)
            if urllib.parse.urlsplit(destino).hostname in ("127.0.0.1", "localhost", "::1"):
                return abrir(url, *a, **k)
            intentos.append(f"urlopen {destino}")
            raise LlamadaRealAAWS(f"un test sin red intento salir: {destino}")

        monkeypatch.setattr(urllib.request, "urlopen", abrir_solo_local)

        # Y los openers propios (revision final, F3): el cliente de aprobacion
        # envia con `build_opener(...).open` para no seguir redirecciones, y ese
        # camino no pasa por `urlopen`. `urlopen` real acaba en este mismo
        # `open`, asi que lo local sigue pudiendo.
        abrir_opener = urllib.request.OpenerDirector.open

        def abrir_opener_solo_local(self, fullurl, *a, **k):
            destino = fullurl.full_url if isinstance(fullurl, urllib.request.Request) else str(fullurl)
            if urllib.parse.urlsplit(destino).hostname in ("127.0.0.1", "localhost", "::1"):
                return abrir_opener(self, fullurl, *a, **k)
            intentos.append(f"opener {destino}")
            raise LlamadaRealAAWS(f"un test sin red intento salir: {destino}")

        monkeypatch.setattr(urllib.request.OpenerDirector, "open", abrir_opener_solo_local)
    yield intentos
    if intentos:
        pytest.fail(f"intento de llamada real a AWS (falta un doble): {intentos}", pytrace=False)


def pytest_collection_modifyitems(config, items):
    motivo = motivo_para_no_abrir(os.environ)
    for item in items:
        tipo = _tipo(item.path)
        if tipo is None:
            continue
        item.add_marker(getattr(pytest.mark, tipo))
        if tipo == "funcionales" and motivo:
            item.add_marker(pytest.mark.skip(reason=motivo))
