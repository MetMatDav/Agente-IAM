"""Lo que los documentos prometen, comprobado.

Dos cosas que se habian roto en silencio y que la regla de `CLAUDE.md`
obliga a mantener:

  - Cada modulo de `agente_iam/` aparece en el README y en el mapa del
    codigo de CONTEXTO §6. Un modulo que nadie nombra es un modulo que la
    siguiente sesion no sabe que existe.
  - `main.py` decia "hay un test que lo vigila" sobre el orden de sus
    imports, y no lo habia. Ahora si.

Y desde la Fase 11, la forma de la bateria: cada test vive en una de las
tres carpetas, ninguna importa los tests de otra, y cada tipo tiene su
comando documentado.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

_RAIZ = Path(__file__).resolve().parents[2]
_TESTS = _RAIZ / "tests"
_TIPOS = ("unitarios", "seguridad", "funcionales")


def _modulos() -> list[str]:
    paquete = _RAIZ / "agente_iam"
    return sorted(
        str(p.relative_to(paquete)).replace(os.sep, "/")
        for p in paquete.rglob("*.py")
        if p.name != "__init__.py"
    )


def test_cada_modulo_aparece_en_el_readme_y_en_el_contexto():
    readme = (_RAIZ / "README.md").read_text(encoding="utf-8")
    contexto = (_RAIZ / "CONTEXTO.md").read_text(encoding="utf-8")
    faltan = [
        (m, doc)
        for m in _modulos()
        for doc, texto in (("README.md", readme), ("CONTEXTO.md", contexto))
        if Path(m).name not in texto
    ]
    assert faltan == [], f"Modulos sin documentar: {faltan}"


def _ficheros_de_tests() -> list[Path]:
    return sorted(_TESTS.rglob("test_*.py"))


def test_cada_fichero_de_tests_aparece_en_el_contexto():
    contexto = (_RAIZ / "CONTEXTO.md").read_text(encoding="utf-8")
    ficheros = _ficheros_de_tests()
    # Con `glob` en vez de `rglob`, al mover los tests a carpetas este test
    # paso en vacio: sin ficheros que mirar, no faltaba ninguno.
    assert len(ficheros) > 10
    faltan = [p.name for p in ficheros if p.name not in contexto]
    assert faltan == [], f"Tests sin nombrar en CONTEXTO §6: {faltan}"


def test_cada_test_vive_en_una_de_las_tres_carpetas():
    """La carpeta decide el tipo (tests/conftest.py). Un test suelto en
    `tests/` no tendria marcador y se colaria en cualquier seleccion."""
    sueltos = [
        str(p.relative_to(_TESTS))
        for p in _ficheros_de_tests()
        if len(p.relative_to(_TESTS).parts) != 2 or p.relative_to(_TESTS).parts[0] not in _TIPOS
    ]
    assert sueltos == []


# `test_cada_tipo_es_un_marcador_registrado` se quito el 24-10-2026 (O14):
# lo repetia `--strict-markers` de pytest.ini, que aborta la recogida si
# tests/conftest.py pone un marcador que no esta registrado.


def test_ninguna_carpeta_importa_los_tests_de_otra():
    """Lo compartido va en `tests/dobles.py`. Si `seguridad/` importara de
    `unitarios/test_*.py`, una carpeta no podria correr ni moverse sola."""
    cruzados = [
        (str(p.relative_to(_TESTS)), otra)
        for p in _ficheros_de_tests()
        for otra in _TIPOS
        if otra != p.relative_to(_TESTS).parts[0]
        and re.search(rf"\b(from|import)\s+tests\.{otra}\b", p.read_text(encoding="utf-8"))
    ]
    assert cruzados == []


def test_cada_tipo_tiene_su_comando_documentado():
    readme = (_RAIZ / "README.md").read_text(encoding="utf-8")
    contexto = (_RAIZ / "CONTEXTO.md").read_text(encoding="utf-8")
    faltan = [
        (tipo, doc)
        for tipo in _TIPOS
        for doc, texto in (("README.md", readme), ("CONTEXTO.md", contexto))
        if f"scripts/pruebas.sh {tipo}" not in texto
    ]
    assert faltan == []
    assert os.access(_RAIZ / "scripts" / "pruebas.sh", os.X_OK)


def test_main_fija_el_catalogo_antes_de_que_config_lo_lea(tmp_path):
    """Si el import de `main.py` subiera por encima del `setdefault`,
    config leeria la ruta relativa y el catalogo no cargaria desplegado,
    sin ningun error. Se reproduce el zip: main.py con `catalogo/` al lado."""
    shutil.copy(_RAIZ / "main.py", tmp_path / "main.py")
    (tmp_path / "catalogo").mkdir()
    entorno = {k: v for k, v in os.environ.items() if k != "DIR_CACHE_CATALOGO"}
    entorno["PYTHONPATH"] = str(_RAIZ)
    salida = subprocess.run(
        [sys.executable, "-c", "import main, agente_iam.config as c; print(c.DIR_CACHE_CATALOGO)"],
        cwd=tmp_path, env=entorno, capture_output=True, text=True, check=True,
    )
    assert Path(salida.stdout.strip()) == (tmp_path / "catalogo").resolve()


# --- Orden del repositorio (Fase 16, 23-10-2026) -----------------------------
#
# Tras mover las guias de infra/ a docs/ y empaquetar.sh a scripts/, la
# primera comprobacion fue un grep a mano de cada ruta vieja. Estos tests
# hacen ese grep cada vez: si una ruta que README, CONTEXTO o CLAUDE citan
# deja de existir, o un tipo de fichero vuelve a donde no debe, se pone rojo.

_RUTA_CITADA = re.compile(
    r"`((?:docs|infra|scripts|tests|ejemplos|agente_iam)/[A-Za-z0-9_./-]+\.(?:md|json|yaml|py|sh))`"
)


def test_las_rutas_que_citan_los_documentos_existen():
    """README, CONTEXTO y CLAUDE citan rutas del repo entre comillas
    invertidas. Las de local/ y evidencias/ no se versionan y no entran."""
    inexistentes = [
        (doc, ruta)
        for doc in ("README.md", "CONTEXTO.md", "CLAUDE.md")
        for ruta in sorted(set(_RUTA_CITADA.findall((_RAIZ / doc).read_text(encoding="utf-8"))))
        if not (_RAIZ / ruta).exists()
    ]
    assert inexistentes == [], f"Rutas citadas que no existen: {inexistentes}"


def test_empaquetar_trabaja_desde_la_raiz():
    """Vive en scripts/ desde la Fase 16. Si no sube un nivel antes de seguir,
    `./.venv`, `requirements.txt`, `main.py` y `dist/` apuntarian a scripts/.
    (Hasta el 24-10-2026 habia otro test de la mudanza, que las guias
    estuvieran en docs/; lo cubre ya el de las rutas citadas, O14.)"""
    script = _RAIZ / "scripts" / "empaquetar.sh"
    assert os.access(script, os.X_OK)
    assert 'cd "$(dirname "$0")/.."' in script.read_text(encoding="utf-8")


def test_la_politica_del_techo_sigue_donde_la_lee_aprobar():
    """`aprobar._RUTA_TECHO_LOCAL` es una ruta relativa fija. Mover el JSON
    sin tocar el paquete dejaria a `techo()` sin su respaldo local."""
    from agente_iam import aprobar

    assert (_RAIZ / aprobar._RUTA_TECHO_LOCAL).is_file()
