"""Exporta los diagramas de arquitectura, en espanol y en ingles, y construye la animacion.

    ./.venv/bin/python scripts/construir_arquitectura.py               # traduce, exporta y construye
    ./.venv/bin/python scripts/construir_arquitectura.py --sin-exportar  # traduce y construye, sin draw.io

POR QUE EXISTE. La fuente de los diagramas es `docs/arquitectura/agente-iam-arquitectura.drawio`
(dos paginas: "1 Contexto" y "2 Despliegue en AWS"); se edita en draw.io y lo demas se
genera desde ella, para que las imagenes y la animacion no cuenten cosas distintas:

1. Genera `agente-iam-arquitectura-en.drawio`, la version en ingles: el mismo XML con cada
   texto cambiado por su traduccion de `docs/arquitectura/traduccion-en.json` (por texto
   exacto en espanol). Asi la version inglesa hereda la posicion de todo; si un texto en
   espanol cambia o se anade sin traduccion, el script se para y dice cual falta.
2. Exporta cada pagina de los dos .drawio a PNG (escala 1,5) y a SVG con el CLI de draw.io
   de escritorio (`drawio` en el PATH, o la ruta en la variable `DRAWIO`).
3. Quita del SVG las imagenes de reserva: draw.io mete, detras de cada etiqueta HTML
   (`foreignObject`), un PNG en base64 para visores que no pintan HTML. Los navegadores no
   las usan y son casi todo el peso (medido el 26-10-2026: de 2,4 MB a 184 KB).
4. Mete los SVG de la pagina 2 (espanol e ingles) en `docs/arquitectura/animacion-plantilla.html`
   y escribe `docs/arquitectura/agente-iam-animacion.html`, un unico fichero sin dependencias
   con boton de idioma. La animacion encuentra cajas y flechas por su `data-cell-id`, que es
   el id de la celda en el .drawio e igual en los dos idiomas; por eso los ids no se cambian a
   la ligera.

`tests/unitarios/test_arquitectura_visual.py` comprueba que cada flecha del diagrama de
despliegue pertenece a un paso de la animacion, que cada id que cita un paso existe y que
cada texto del .drawio tiene traduccion.

Codigos de salida: 0 hecho; 1 falta draw.io, falta una traduccion o fallo la exportacion.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess  # nosec B404: lanza el CLI de draw.io con argumentos fijos, ver _exportar
import sys
import xml.etree.ElementTree as ET  # nosec B405: solo lee el .drawio del propio repositorio
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
CARPETA = RAIZ / "docs" / "arquitectura"
FUENTE = CARPETA / "agente-iam-arquitectura.drawio"
FUENTE_EN = CARPETA / "agente-iam-arquitectura-en.drawio"
TRADUCCION = CARPETA / "traduccion-en.json"
PLANTILLA = CARPETA / "animacion-plantilla.html"
ANIMACION = CARPETA / "agente-iam-animacion.html"
MARCAS = {"es": "<!--SVG_DESPLIEGUE-->", "en": "<!--SVG_DESPLIEGUE_EN-->"}
PAGINAS = {1: "agente-iam-contexto", 2: "agente-iam-despliegue"}

_RESERVA = re.compile(r"(</foreignObject>)<image\b[^>]*/>")
_CABECERA = re.compile(r"^\s*<\?xml[^>]*>\s*(<!DOCTYPE[^>]*>\s*)?")
_LETRA = re.compile(r"[A-Za-z]")


def quitar_reservas(svg: str) -> str:
    """Quita la imagen PNG que draw.io pone tras cada `foreignObject` (ver punto 3)."""
    return _RESERVA.sub(r"\1", svg)


def textos(drawio: str) -> list[str]:
    """Nombres de pagina y valores de celda con alguna letra, en orden y sin repetir."""
    raiz = ET.fromstring(drawio)  # nosec B314: XML propio del repositorio
    vistos: list[str] = []
    for pagina in raiz.iter("diagram"):
        candidatos = [pagina.get("name") or ""] + [c.get("value") or "" for c in pagina.iter("mxCell")]
        vistos += [t for t in candidatos if _LETRA.search(t) and t not in vistos]
    return vistos


def traducir_drawio(drawio: str, tabla: dict[str, str]) -> tuple[str, list[str]]:
    """Devuelve el .drawio con los textos traducidos y la lista de textos sin traduccion."""
    faltan = [t for t in textos(drawio) if t not in tabla]
    if faltan:
        return "", faltan
    raiz = ET.fromstring(drawio)  # nosec B314: XML propio del repositorio
    for pagina in raiz.iter("diagram"):
        nombre = pagina.get("name") or ""
        if nombre in tabla:
            pagina.set("name", tabla[nombre])
        for celda in pagina.iter("mxCell"):
            valor = celda.get("value") or ""
            if valor in tabla:
                celda.set("value", tabla[valor])
    return ET.tostring(raiz, encoding="unicode") + "\n", []


def construir_animacion(svgs: dict[str, str], plantilla: str) -> str:
    """Devuelve la plantilla con cada SVG en su marca, sin cabecera XML ni DOCTYPE."""
    for idioma, marca in MARCAS.items():
        if plantilla.count(marca) != 1:
            raise ValueError(f"la plantilla debe tener exactamente una marca {marca}")
        limpio = _CABECERA.sub("", quitar_reservas(svgs[idioma]), count=1)
        plantilla = plantilla.replace(marca, limpio)
    return plantilla


def _drawio() -> str | None:
    return os.environ.get("DRAWIO") or shutil.which("drawio")


def _exportar(drawio: str, fuente: Path, pagina: int, formato: str, salida: Path) -> None:
    args = [drawio, "--no-sandbox", "-x", "-f", formato, "-b", "20", "--page-index", str(pagina)]
    if formato == "png":
        args += ["-s", "1.5"]
    args += ["-o", str(salida), str(fuente)]
    subprocess.run(args, check=True, capture_output=True, timeout=180)  # nosec B603


def _nombre(base: str, idioma: str) -> str:
    return base if idioma == "es" else f"{base}-en"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sin-exportar", action="store_true",
                        help="no llama a draw.io; usa los SVG que ya hay")
    args = parser.parse_args(argv)

    tabla = json.loads(TRADUCCION.read_text(encoding="utf-8"))["textos"]
    traducido, faltan = traducir_drawio(FUENTE.read_text(encoding="utf-8"), tabla)
    if faltan:
        print(f"Faltan {len(faltan)} traducciones en {TRADUCCION.name}:", file=sys.stderr)
        for texto in faltan:
            print(f"  {texto!r}", file=sys.stderr)
        return 1
    FUENTE_EN.write_text(traducido, encoding="utf-8")
    print(f"escrito {FUENTE_EN.relative_to(RAIZ)}")

    if not args.sin_exportar:
        drawio = _drawio()
        if not drawio:
            print("No encuentro draw.io: instala draw.io de escritorio o pon su ruta en DRAWIO.",
                  file=sys.stderr)
            return 1
        for idioma, fuente in (("es", FUENTE), ("en", FUENTE_EN)):
            for pagina, base in PAGINAS.items():
                nombre = _nombre(base, idioma)
                try:
                    _exportar(drawio, fuente, pagina, "png", CARPETA / f"{nombre}.png")
                    _exportar(drawio, fuente, pagina, "svg", CARPETA / f"{nombre}.svg")
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                    print(f"Fallo la exportacion de {fuente.name}, pagina {pagina}: {exc}", file=sys.stderr)
                    return 1
                ruta_svg = CARPETA / f"{nombre}.svg"
                ruta_svg.write_text(quitar_reservas(ruta_svg.read_text(encoding="utf-8")), encoding="utf-8")
                print(f"exportada {fuente.name}, pagina {pagina}: {nombre}.png y {nombre}.svg")

    svgs = {
        idioma: (CARPETA / f"{_nombre(PAGINAS[2], idioma)}.svg").read_text(encoding="utf-8")
        for idioma in MARCAS
    }
    ANIMACION.write_text(construir_animacion(svgs, PLANTILLA.read_text(encoding="utf-8")), encoding="utf-8")
    print(f"escrita la animacion: {ANIMACION.relative_to(RAIZ)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
