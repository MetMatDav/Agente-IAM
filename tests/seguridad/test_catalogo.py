"""Fase 12: el nombre de servicio del catalogo no puede salir de su carpeta.

Lo encontro bandit (B310) el 22-10-2026 al anadirlo a la bateria de
seguridad. `consultar_acciones` es una tool del modelo: las acciones que
recibe las escribe el modelo, y el modelo lee texto del solicitante. De
cada accion, lo que va antes de `:` acababa sin validar en dos sitios:

  - la ruta de la cache:  _CACHE / f"{servicio}.json"
  - la URL de AWS:        .../v1/{servicio}/{servicio}.json

Con `../secreto:Get`, `_cargar` leia `<cache>/../secreto.json` y lo
devolvia como si fuera el catalogo; y si no existia, guardaba la respuesta
de la URL fuera de la cache. Estos tests no tocan la red: si `_cargar`
intentara descargar algo, el doble de `urlopen` hace fallar el test.
"""

import json
import os
import time

import pytest

from agente_iam.herramientas import catalogo

_CATALOGO_FALSO = {
    "Actions": [
        {"Name": "GetX", "Resources": [{"Name": "x"}], "Annotations": {"Properties": {}}},
    ]
}


@pytest.fixture
def cache_aislada(tmp_path, monkeypatch):
    """Cache en tmp, memoria vacia y red prohibida."""
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setattr(catalogo, "_CACHE", cache)
    monkeypatch.setattr(catalogo, "_MEMORIA", {})

    def sin_red(*a, **k):
        raise AssertionError(f"el catalogo intento ir a la red: {a!r}")

    monkeypatch.setattr(catalogo.urllib.request, "urlopen", sin_red)
    return cache


@pytest.mark.parametrize("servicio", [
    # "../secreto": en test_no_lee_un_json_fuera_de_la_cache
    "..\\secreto",
    "/etc/secreto",
    "s3/../../secreto",
    "s3?x=1",
    "s3#x",
    "",
    "s3 ",
])
def test_cargar_rechaza_un_servicio_que_no_es_un_prefijo(cache_aislada, servicio):
    with pytest.raises(ValueError):
        catalogo._cargar(servicio)


def test_no_lee_un_json_fuera_de_la_cache(cache_aislada):
    # El fichero existe justo donde apuntaria la ruta manipulada.
    (cache_aislada.parent / "secreto.json").write_text(json.dumps(_CATALOGO_FALSO))
    with pytest.raises(ValueError):
        catalogo._cargar("../secreto")
    assert "../secreto" not in catalogo._MEMORIA


def test_las_funciones_publicas_lo_tratan_como_desconocido(cache_aislada):
    (cache_aislada.parent / "secreto.json").write_text(json.dumps(_CATALOGO_FALSO))
    # None = "no lo se": las barandas lo tratan como desconocido, nunca
    # como una accion valida sacada de un fichero ajeno.
    assert catalogo.soporta_recursos("../secreto:GetX") is None
    assert catalogo.no_disponibles(["../secreto"]) == ["../secreto"]


# Un prefijo con cifra, uno con guion y uno en mayusculas (que se normaliza).
# `ec2` repetia el camino de `s3` con el mismo JSON de juguete (O13, 24-10-2026).
@pytest.mark.parametrize("servicio", ["s3", "bedrock-agentcore", "S3"])
def test_los_prefijos_reales_siguen_cargando(cache_aislada, servicio):
    (cache_aislada / f"{servicio.lower()}.json").write_text(json.dumps(_CATALOGO_FALSO))
    assert "getx" in catalogo._cargar(servicio)


# --- O2 (24-10-2026): la cache caduca, se escribe entera y se cura sola -----


class _Respuesta:
    def __init__(self, cuerpo: bytes):
        self.cuerpo = cuerpo

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self.cuerpo


_NUEVO = {"Actions": [{"Name": "GetNueva", "Resources": [], "Annotations": {"Properties": {}}}]}


@pytest.fixture
def red_falsa(cache_aislada, monkeypatch):
    """`urlopen` que devuelve el catalogo `_NUEVO` y cuenta las descargas."""
    descargas: list[str] = []

    def abrir(url, timeout=None):
        descargas.append(url)
        return _Respuesta(json.dumps(_NUEVO).encode())

    monkeypatch.setattr(catalogo.urllib.request, "urlopen", abrir)
    return descargas


def _envejecer(archivo, dias):
    viejo = time.time() - dias * 86400
    os.utime(archivo, (viejo, viejo))


def test_una_cache_fresca_no_se_descarga(cache_aislada, red_falsa):
    (cache_aislada / "s3.json").write_text(json.dumps(_CATALOGO_FALSO))
    assert "getx" in catalogo._cargar("s3")
    assert red_falsa == []


def test_una_cache_caducada_se_renueva(cache_aislada, red_falsa):
    archivo = cache_aislada / "s3.json"
    archivo.write_text(json.dumps(_CATALOGO_FALSO))
    _envejecer(archivo, catalogo.CADUCIDAD_CATALOGO_DIAS + 1)
    assert "getnueva" in catalogo._cargar("s3")
    assert len(red_falsa) == 1
    assert json.loads(archivo.read_text()) == _NUEVO


def test_si_la_renovacion_falla_se_usa_la_vieja(cache_aislada, monkeypatch, caplog):
    """Sin catalogo el chequeo de nivel se apaga: peor que uno viejo."""
    archivo = cache_aislada / "s3.json"
    archivo.write_text(json.dumps(_CATALOGO_FALSO))
    _envejecer(archivo, 30)

    def caida(*a, **k):
        raise OSError("sin red")

    monkeypatch.setattr(catalogo.urllib.request, "urlopen", caida)
    assert "getx" in catalogo._cargar("s3")
    assert "hace 30 dias" in caplog.text


def test_una_cache_ilegible_se_borra_y_se_descarga(cache_aislada, red_falsa):
    """Antes un JSON truncado se quedaba para siempre y todo el servicio
    contaba como duda (`soporta_recursos` y `_expandir` devolvian None)."""
    (cache_aislada / "s3.json").write_text('{"Actions": [')
    assert "getnueva" in catalogo._cargar("s3")
    assert len(red_falsa) == 1


def test_en_un_directorio_de_solo_lectura_no_caduca_ni_se_borra(cache_aislada, red_falsa, monkeypatch):
    """El paquete desplegado: el catalogo es el que se empaqueto."""
    archivo = cache_aislada / "s3.json"
    archivo.write_text(json.dumps(_CATALOGO_FALSO))
    _envejecer(archivo, 365)
    monkeypatch.setattr(catalogo, "_escribible", lambda carpeta: False)
    assert "getx" in catalogo._cargar("s3")
    assert red_falsa == []


def test_la_escritura_es_atomica(cache_aislada, monkeypatch):
    """Si el proceso muere a medias, el fichero viejo sigue entero: se
    escribe en un temporal y se renombra."""
    archivo = cache_aislada / "s3.json"
    archivo.write_text(json.dumps(_CATALOGO_FALSO))

    def muere(*a, **k):
        raise OSError("disco lleno a mitad")

    monkeypatch.setattr(catalogo.os, "replace", muere)
    catalogo._guardar_en_cache(archivo, b'{"Actions": [')
    assert json.loads(archivo.read_text()) == _CATALOGO_FALSO
    assert sorted(p.name for p in cache_aislada.iterdir()) == ["s3.json"], "el temporal se limpia"


def test_una_respuesta_que_no_es_json_no_se_cachea(cache_aislada, monkeypatch):
    monkeypatch.setattr(catalogo.urllib.request, "urlopen", lambda url, timeout=None: _Respuesta(b"<html>"))
    with pytest.raises(ValueError):
        catalogo._cargar("s3")
    assert not (cache_aislada / "s3.json").exists()


def test_la_caducidad_es_de_una_semana():
    assert catalogo.CADUCIDAD_CATALOGO_DIAS == 7
