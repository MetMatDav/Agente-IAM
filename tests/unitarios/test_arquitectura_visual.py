"""La animacion del recorrido no se separa del diagrama de despliegue.

`docs/arquitectura/agente-iam-arquitectura.drawio` es la fuente; la animacion
(`agente-iam-animacion.html`) se construye con `scripts/construir_arquitectura.py`
desde la plantilla y el SVG exportado, y encuentra cajas y flechas por su id de
celda. Si alguien anade una flecha al diagrama y no la pone en un paso, o renombra
una celda, la animacion se queda callada o falla sin avisar. Aqui se fija:

  - cada flecha de la pagina "2 Despliegue en AWS" pertenece a algun paso, y cada
    flecha que cita un paso existe;
  - cada caja e insignia que cita un paso existe;
  - la animacion construida lleva los mismos pasos que la plantilla (no se edito
    la plantilla sin reconstruir);
  - el script quita solo las imagenes de reserva de draw.io y mete cada SVG una vez;
  - la version en ingles: cada texto del .drawio tiene traduccion, la tabla no
    guarda traducciones de textos que ya no existen, el .drawio en ingles es el
    que sale de traducir el espanol y cada paso lleva su texto en ingles.

Sin red ni draw.io: se lee el XML y el HTML del repositorio.
"""

import importlib.util
import json
import re
import sys
import xml.etree.ElementTree as ET  # nosec B405: XML propio del repositorio, no de fuera
from pathlib import Path

import pytest

_RAIZ = Path(__file__).resolve().parents[2]
_CARPETA = _RAIZ / "docs" / "arquitectura"
_RUTA = _RAIZ / "scripts" / "construir_arquitectura.py"
_spec = importlib.util.spec_from_file_location("construir_arquitectura", _RUTA)
assert _spec
assert _spec.loader
construir = importlib.util.module_from_spec(_spec)
sys.modules["construir_arquitectura"] = construir
_spec.loader.exec_module(construir)

_BLOQUE_PASOS = re.compile(r'<script type="application/json" id="pasos">(.*?)</script>', re.S)


def _pagina_despliegue() -> ET.Element:
    raiz = ET.parse(_CARPETA / "agente-iam-arquitectura.drawio").getroot()  # nosec B314
    paginas = {d.get("name"): d for d in raiz.iter("diagram")}
    assert set(paginas) == {"1 Contexto", "2 Despliegue en AWS"}
    return paginas["2 Despliegue en AWS"]


def _pasos(html: str) -> list[dict]:
    m = _BLOQUE_PASOS.search(html)
    assert m, "no encuentro el bloque JSON de pasos"
    return json.loads(m.group(1))


def _plantilla() -> str:
    return (_CARPETA / "animacion-plantilla.html").read_text(encoding="utf-8")


def test_cada_flecha_del_despliegue_pertenece_a_un_paso_y_al_reves():
    pagina = _pagina_despliegue()
    flechas = {c.get("id") for c in pagina.iter("mxCell") if c.get("edge") == "1"}
    citadas = {t["arista"] for p in _pasos(_plantilla()) for t in p["tramos"]}
    assert len(flechas) > 15  # que no pase en vacio con una pagina equivocada
    assert flechas - citadas == set(), "flechas del diagrama que ningun paso recorre"
    assert citadas - flechas == set(), "pasos que citan flechas que no existen"


def test_cada_caja_e_insignia_de_un_paso_existe():
    ids = {c.get("id") for c in _pagina_despliegue().iter("mxCell") if c.get("vertex") == "1"}
    faltan = [
        (p["id"], x) for p in _pasos(_plantilla()) for x in p["nodos"] + p["insignias"] if x not in ids
    ]
    assert faltan == []


def test_los_pasos_son_los_de_la_leyenda_y_en_orden():
    assert [p["id"] for p in _pasos(_plantilla())] == ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "F"]


def test_la_animacion_construida_lleva_los_pasos_de_la_plantilla():
    animacion = (_CARPETA / "agente-iam-animacion.html").read_text(encoding="utf-8")
    assert _pasos(animacion) == _pasos(_plantilla()), (
        "la plantilla cambio: corre scripts/construir_arquitectura.py --sin-exportar"
    )
    assert all(marca not in animacion for marca in construir.MARCAS.values())
    assert animacion.count('data-cell-id="tabla"') == 2  # un diagrama por idioma


def test_quitar_reservas_solo_quita_la_imagen_tras_foreignobject():
    svg = (
        '<switch><foreignObject><div>hola</div></foreignObject>'
        '<image x="1" xlink:href="data:image/png;base64,AAAA"/></switch>'
        '<image x="2" xlink:href="icono.png"/>'
    )
    limpio = construir.quitar_reservas(svg)
    assert "base64" not in limpio
    assert "<foreignObject><div>hola</div></foreignObject></switch>" in limpio
    assert 'xlink:href="icono.png"' in limpio


def test_construir_animacion_mete_cada_svg_sin_cabecera_y_exige_sus_marcas():
    svgs = {
        "es": '<?xml version="1.0"?>\n<!DOCTYPE svg PUBLIC "x" "y">\n<svg id="es"/>',
        "en": '<?xml version="1.0"?>\n<svg id="en"/>',
    }
    plantilla = f'<div>{construir.MARCAS["es"]}</div><div>{construir.MARCAS["en"]}</div>'
    assert construir.construir_animacion(svgs, plantilla) == '<div><svg id="es"/></div><div><svg id="en"/></div>'
    with pytest.raises(ValueError):
        construir.construir_animacion(svgs, f'<div>{construir.MARCAS["es"]}</div>')


def test_los_svg_del_repositorio_no_llevan_reservas():
    for nombre in ("agente-iam-contexto.svg", "agente-iam-despliegue.svg",
                   "agente-iam-contexto-en.svg", "agente-iam-despliegue-en.svg"):
        texto = (_CARPETA / nombre).read_text(encoding="utf-8")
        assert construir.quitar_reservas(texto) == texto, nombre


def _tabla_en() -> dict[str, str]:
    return json.loads((_CARPETA / "traduccion-en.json").read_text(encoding="utf-8"))["textos"]


def test_cada_texto_del_drawio_tiene_traduccion_y_ninguna_sobra():
    textos = construir.textos((_CARPETA / "agente-iam-arquitectura.drawio").read_text(encoding="utf-8"))
    tabla = _tabla_en()
    assert len(textos) > 100
    assert [t for t in textos if t not in tabla] == [], "textos sin traducir en traduccion-en.json"
    assert sorted(set(tabla) - set(textos)) == [], "traducciones de textos que ya no estan en el .drawio"


def test_el_drawio_en_ingles_es_el_que_sale_de_traducir_el_espanol():
    espanol = (_CARPETA / "agente-iam-arquitectura.drawio").read_text(encoding="utf-8")
    traducido, faltan = construir.traducir_drawio(espanol, _tabla_en())
    assert faltan == []
    assert (_CARPETA / "agente-iam-arquitectura-en.drawio").read_text(encoding="utf-8") == traducido, (
        "el .drawio en ingles esta viejo: corre scripts/construir_arquitectura.py"
    )


def test_traducir_drawio_conserva_ids_y_geometria_y_avisa_de_lo_que_falta():
    drawio = (
        '<mxfile><diagram name="Pagina" id="p"><mxGraphModel><root>'
        '<mxCell id="a" value="Hola" vertex="1"><mxGeometry x="1" y="2" as="geometry"/></mxCell>'
        '<mxCell id="b" value="7" vertex="1"/></root></mxGraphModel></diagram></mxfile>'
    )
    traducido, faltan = construir.traducir_drawio(drawio, {"Pagina": "Page", "Hola": "Hello"})
    assert faltan == []
    assert 'name="Page"' in traducido
    assert 'id="a" value="Hello"' in traducido
    assert '<mxGeometry x="1" y="2" as="geometry" />' in traducido
    assert 'value="7"' in traducido  # sin letras: no se traduce
    _, faltan = construir.traducir_drawio(drawio, {"Pagina": "Page"})
    assert faltan == ["Hola"]


def test_cada_paso_lleva_su_texto_en_ingles():
    for paso in _pasos(_plantilla()):
        en = paso["en"]
        assert all(en.get(k) for k in ("titulo", "que", "porque", "donde")), paso["id"]
        assert all(t.get("lleva_en") for t in paso["tramos"]), paso["id"]
