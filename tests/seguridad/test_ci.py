"""Fase 12: el CI y la bateria de seguridad no se aflojan sin que se note.

`.github/workflows/pruebas.yml` corre unitarios y seguridad en GitHub con el
mismo `scripts/pruebas.sh` que en local. Lo que aqui se fija es lo que lo
hace seguro y lo que lo hace util:

  - el workflow no puede escribir en el repositorio ni dejar el token en
    `.git/config`, y cada accion va fijada por commit (una etiqueta se
    puede mover a codigo distinto);
  - corre unitarios y seguridad, nunca funcionales (tocan la cuenta real);
  - sube la evidencia aunque los tests fallen, que es cuando mas se necesita;
  - `scripts/pruebas.sh seguridad` corre bandit y pip-audit, y sus
    versiones estan fijadas.

PyYAML esta declarado en requirements-dev.txt desde el 24-10-2026 (O17).
"""

import re
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parents[2]
WORKFLOW = RAIZ / ".github" / "workflows" / "pruebas.yml"


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _pasos() -> list[dict]:
    return _workflow()["jobs"]["pruebas"]["steps"]


def test_permisos_de_solo_lectura():
    assert _workflow()["permissions"] == {"contents": "read"}
    for job in _workflow()["jobs"].values():
        assert "permissions" not in job, "un job no amplia los permisos del workflow"


def test_cada_accion_fijada_por_commit():
    usos = [p["uses"] for p in _pasos() if "uses" in p]
    assert usos, "el workflow deberia usar al menos checkout"
    for uso in usos:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", uso), uso


def test_checkout_no_guarda_el_token():
    checkout = next(p for p in _pasos() if p.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False


def test_corre_unitarios_y_seguridad_y_nunca_funcionales():
    tipos = _workflow()["jobs"]["pruebas"]["strategy"]["matrix"]["tipo"]
    assert sorted(tipos) == ["seguridad", "unitarios"]
    texto = WORKFLOW.read_text(encoding="utf-8")
    assert "scripts/pruebas.sh ${{ matrix.tipo }}" in texto
    assert "AGENTE_IAM_FUNCIONALES" not in texto
    sin_comentarios = "\n".join(l.split("#", 1)[0] for l in texto.splitlines())
    assert "funcionales" not in sin_comentarios


def test_gitleaks_corre_en_ci_y_escanea_de_verdad():
    """O1 (24-10-2026): hasta esa fecha el paso era `pre-commit run gitleaks
    --all-files`, y el hook es `gitleaks protect --staged`: en un checkout
    limpio no hay nada en el indice, asi que salia 0 sin mirar ni un
    fichero. Este test solo pedia la palabra "gitleaks" y pasaba igual.

    Ahora se exige el subcomando que escanea (`git`, con el historial
    entero, o `dir`), el binario verificado por su sha256 y la version de
    `.pre-commit-config.yaml`, para que el hook local y el CI no se separen.
    """
    pasos = [p for p in _pasos() if "gitleaks" in p.get("run", "")]
    assert len(pasos) == 1
    [paso] = pasos
    assert paso["if"] == "matrix.tipo == 'seguridad'"
    run = paso["run"]
    assert "protect" not in run
    assert "pre-commit run" not in run
    assert "--staged" not in run
    escanea = re.search(r'gitleaks"? (git|dir) ', run)
    assert escanea, run
    # Un hallazgo tiene que poner el paso en rojo, y no puede mostrarse en claro.
    assert "--exit-code 1" in run
    assert "--redact" in run
    # El binario se verifica antes de ejecutarlo.
    assert re.fullmatch(r"[0-9a-f]{64}", paso["env"]["GITLEAKS_SHA256"])
    assert run.index("sha256sum -c") < run.index("tar -xzf")
    assert "set +e" not in run
    assert "|| true" not in run
    # La misma version que el hook de pre-commit.
    config = (RAIZ / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    assert f"# frozen: v{paso['env']['GITLEAKS_VERSION']}" in config
    if escanea[1] == "git":
        checkout = next(p for p in _pasos() if p.get("uses", "").startswith("actions/checkout@"))
        assert checkout["with"]["fetch-depth"] == 0, "con historial corto `gitleaks git` no ve los commits viejos"


def test_todo_rev_de_pre_commit_es_un_commit():
    """S10 (24-10-2026): una etiqueta se puede mover a otro codigo; un SHA
    no. Los hooks `local` no llevan rev."""
    hooks = yaml.safe_load((RAIZ / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    remotos = [r for r in hooks["repos"] if r["repo"] != "local"]
    assert remotos
    for repo in remotos:
        assert re.fullmatch(r"[0-9a-f]{40}", str(repo["rev"])), repo


def test_sube_la_evidencia_aunque_falle():
    subida = next(p for p in _pasos() if p.get("uses", "").startswith("actions/upload-artifact@"))
    assert subida["if"] == "always()"
    assert subida["with"]["path"] == "evidencias/"


def test_seguridad_corre_bandit_y_pip_audit():
    script = (RAIZ / "scripts" / "pruebas.sh").read_text(encoding="utf-8")
    bloque = script.split('if [ "$TIPO" = seguridad ]; then', 1)[1].split("\nfi\n", 1)[0]
    assert "-m bandit -r agente_iam main.py scripts" in bloque
    # Las versiones exactas que se instalan, no las que pip-audit resolveria
    # por su cuenta (Fase 13: asi se escapaban pyjwt, urllib3 y otras).
    assert "-m pip_audit -r constraints.txt --no-deps" in bloque
    # El exit de cada herramienta cuenta: si se ignorara, fallaria en silencio.
    assert 'BANDIT="$?"' in bloque
    # pip-audit va por una tuberia (tee): su exit es PIPESTATUS, no el de tee.
    assert 'AUDIT="${PIPESTATUS[0]}"' in bloque
    assert 'CODIGO="$c"' in bloque


def test_seguridad_corre_cfn_lint_y_cuenta_su_exit():
    """Fase 15: las plantillas de infra/cfn/ se validan en cada ejecucion de
    seguridad, local y en CI, y un error de plantilla hace fallar la corrida."""
    script = (RAIZ / "scripts" / "pruebas.sh").read_text(encoding="utf-8")
    bloque = script.split('if [ "$TIPO" = seguridad ]; then', 1)[1].split("\nfi\n", 1)[0]
    assert "from cfnlint.runner import main" in bloque
    assert "infra/cfn/*.yaml" in bloque
    assert 'CFNLINT="${PIPESTATUS[0]}"' in bloque
    assert 'for c in "$BANDIT" "$AUDIT" "$CFNLINT"; do' in bloque


def test_herramientas_de_seguridad_con_version_fijada():
    dev = (RAIZ / "requirements-dev.txt").read_text(encoding="utf-8")
    for paquete in ("pytest", "pre-commit", "bandit", "pip-audit", "cfn-lint"):
        assert re.search(rf"^{paquete}==\d", dev, re.M), paquete


# --- Fase 13: constraints.txt fija tambien las transitivas -----------------


def _fijadas(nombre: str) -> dict[str, str]:
    fijadas = {}
    for linea in (RAIZ / nombre).read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)==(\S+)", linea)
        if m:
            fijadas[m[1].lower().replace("_", "-")] = m[2]
    return fijadas


def test_constraints_coincide_con_las_directas():
    """Una directa con una version en requirements y otra en constraints
    haria fallar la instalacion o, peor, probar una y desplegar otra."""
    restricciones = _fijadas("constraints.txt")
    ficheros = (
        "requirements.txt", "requirements-dev.txt",
        "requirements-aprobacion.txt", "requirements-aplicador.txt",
    )
    for fichero in ficheros:
        for paquete, version in _fijadas(fichero).items():
            assert restricciones.get(paquete) == version, (fichero, paquete)


def test_constraints_solo_versiones_exactas():
    for linea in (RAIZ / "constraints.txt").read_text(encoding="utf-8").splitlines():
        if linea.strip() and not linea.startswith("#"):
            assert re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!-]+", linea), linea


def test_todo_lo_que_instala_usa_constraints():
    texto = WORKFLOW.read_text(encoding="utf-8")
    instala = [p["run"] for p in _pasos() if "pip install" in p.get("run", "")]
    assert instala
    assert all("-c constraints.txt" in r for r in instala)
    assert "constraints.txt" in texto.split("cache-dependency-path", 1)[1]
    empaquetar = (RAIZ / "scripts" / "empaquetar.sh").read_text(encoding="utf-8")
    assert "-c constraints.txt" in empaquetar


def test_el_runner_esta_fijado():
    runner = _workflow()["jobs"]["pruebas"]["runs-on"]
    assert "latest" not in runner, runner



def test_unitarios_corre_ruff_y_mypy_y_cuenta_su_exit():
    script = (RAIZ / "scripts" / "pruebas.sh").read_text(encoding="utf-8")
    bloque = script.split('if [ "$TIPO" = unitarios ]; then', 1)[1].split("\nfi\n", 1)[0]
    assert '-m ruff check .' in bloque
    assert '-m mypy' in bloque
    assert 'RUFF="${PIPESTATUS[0]}"' in bloque
    assert 'MYPY="${PIPESTATUS[0]}"' in bloque
    assert 'for c in "$RUFF" "$MYPY"' in bloque
    assert 'CODIGO="$c"' in bloque
    config = (RAIZ / "mypy.ini").read_text(encoding="utf-8")
    assert re.search(r"^files = agente_iam, main.py$", config, re.M)


def test_ruff_en_el_pre_commit_con_reglas_de_errores():
    hooks = yaml.safe_load((RAIZ / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    entradas = [h.get("entry", "") for r in hooks["repos"] for h in r["hooks"]]
    assert any("ruff check ." in e for e in entradas)
    config = (RAIZ / "ruff.toml").read_text(encoding="utf-8")
    seleccion = re.search(r"^select = \[(.*)\]", config, re.M)[1]
    for regla in ('"F"', '"B"'):  # F821 y pytest.raises(Exception), como minimo
        assert regla in seleccion


def _lista(script: str, nombre: str) -> list[str]:
    """Los ficheros que `empaquetar.sh` declara en `NOMBRE="a.py b.py"`."""
    return re.search(rf'^{nombre}="([^"]+)"$', script, re.M)[1].split()


def _cadena_de_imports(desde: Path) -> set[str]:
    """Los modulos de `agente_iam` que importa `desde`, directa o
    indirectamente (tambien los imports dentro de funciones)."""
    import ast

    vistos: set[str] = set()
    pendientes = [desde]
    while pendientes:
        ruta = pendientes.pop()
        for n in ast.walk(ast.parse(ruta.read_text(encoding="utf-8"))):
            if isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                nombres = [n.module] + [f"{n.module}.{a.name}" for a in n.names]
            elif isinstance(n, ast.Import):
                nombres = [a.name for a in n.names]
            else:
                continue
            for nombre in nombres:
                if not nombre.startswith("agente_iam"):
                    continue
                base = RAIZ / Path(*nombre.split("."))
                for candidato in (base.with_suffix(".py"), base / "__init__.py"):
                    if candidato.is_file() and str(candidato) not in vistos:
                        vistos.add(str(candidato))
                        pendientes.append(candidato)
    return {str(Path(v).relative_to(RAIZ / "agente_iam")) for v in vistos}


def test_el_runtime_no_importa_lo_que_no_viaja():
    """O5 (24-10-2026): `cp -r agente_iam` metia aprobar.py y aplicador.py
    en el zip del runtime, aunque servidor.py dice que no pueden estar ahi.
    Ahora empaquetar.sh los borra y comprueba el zip. Esto vigila las dos
    mitades: que el script los quita, y que nada de lo que arranca main.py
    los necesita (si un dia se importaran, el runtime no arrancaria)."""
    script = (RAIZ / "scripts" / "empaquetar.sh").read_text(encoding="utf-8")
    fuera = _lista(script, "FUERA_DEL_RUNTIME")
    # cli.py y huella.py desde el 24-10-2026 (decision de Mateo); el cliente
    # de la persona (aprobar_cliente.py) tampoco, ADR-003.
    assert {"aprobar.py", "aplicador.py", "cli.py", "huella.py", "aprobar_cliente.py"} <= set(fuera)
    assert 'rm "$DESTINO/paquete/agente_iam/$m"' in script
    assert script.index('cp -r agente_iam') < script.index('rm "$DESTINO/paquete/agente_iam/$m"')
    # La comprobacion mira el zip, despues de comprimir, y sale con 1.
    despues = script.split('zip -qr "../$(basename "$PAQUETE")" .', 1)[1]
    assert "zipfile.ZipFile" in despues
    assert "exit 1" in despues.split("done", 1)[0]

    cadena = _cadena_de_imports(RAIZ / "main.py")
    assert {"servidor.py", "orquestador.py", "herramientas/validacion.py"} <= cadena
    assert sorted(set(fuera) & cadena) == []


def test_el_paquete_lleva_un_catalogo_recien_descargado():
    """O2 (24-10-2026): se empaquetaba `.cache/servicereference` tal cual,
    con dos meses. Ahora se descarga entero en una carpeta vacia y se deja
    la huella de cada fichero en VERSIONES.txt."""
    script = (RAIZ / "scripts" / "empaquetar.sh").read_text(encoding="utf-8")
    codigo = "\n".join(l for l in script.splitlines() if not l.lstrip().startswith("#"))
    assert ".cache" not in codigo
    assert 'rm -rf "$CATALOGO"' in script
    assert 'DIR_CACHE_CATALOGO="$CATALOGO"' in script
    assert script.index('rm -rf "$CATALOGO"') < script.index('DIR_CACHE_CATALOGO="$CATALOGO"')
    assert 'cp "$CATALOGO"/*.json "$DESTINO/paquete/catalogo/"' in script
    assert "sha256sum" in script


# --- 24-10-2026 (revision, paso 2): lo que se instala es lo que se declara ---


def _norma(nombre: str) -> str:
    return re.sub(r"[-_.]+", "-", nombre).lower()


def test_constraints_fija_todo_lo_que_se_instala():
    """O4: cfn-lint exige sympy (y sympy, mpmath) desde la Fase 15, y ninguno
    de los dos estaba en constraints.txt: el CI los instalaba en la ultima
    version y pip-audit no los veia. Se recorre el arbol de dependencias de
    lo que piden requirements*.txt, con los metadatos de lo instalado, y
    cada paquete del arbol tiene que estar fijado."""
    from importlib.metadata import PackageNotFoundError, distribution

    from packaging.requirements import Requirement

    fijadas = {_norma(n) for n in _fijadas("constraints.txt")}
    pendientes = [_norma(n) for f in ("requirements.txt", "requirements-dev.txt") for n in _fijadas(f)]
    vistos, sin_fijar = set(), []
    while pendientes:
        nombre = pendientes.pop()
        if nombre in vistos:
            continue
        vistos.add(nombre)
        if nombre not in fijadas:
            sin_fijar.append(nombre)
        try:
            requisitos = distribution(nombre).requires or []
        except PackageNotFoundError:
            continue  # lo dira test_constraints_coincide_con_las_directas o pip
        for r in map(Requirement, requisitos):
            if r.marker is None or r.marker.evaluate({"extra": ""}):
                pendientes.append(_norma(r.name))
    assert len(vistos) > 50, "el arbol salio casi vacio: no se estan leyendo los metadatos"
    assert sorted(sin_fijar) == []


def test_las_dependencias_que_se_importan_estan_declaradas():
    """O17: `agente_iam` importaba pydantic y botocore, y los tests y
    generar_techo.py importaban PyYAML, sin declararlos: llegaban de rebote.
    Lo que importa el paquete desplegado va en requirements.txt; lo que
    importan tests y scripts, en cualquiera de los dos."""
    import ast
    import sys
    from importlib.metadata import packages_distributions

    propios = {"agente_iam", "tests", "main", "conftest", "generar_techo", "__future__"}
    distribucion = packages_distributions()

    def importados(rutas) -> set[str]:
        nombres = set()
        for ruta in rutas:
            for n in ast.walk(ast.parse(ruta.read_text(encoding="utf-8"))):
                if isinstance(n, ast.Import):
                    nombres |= {a.name.split(".")[0] for a in n.names}
                elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                    nombres.add(n.module.split(".")[0])
        terceros = nombres - set(sys.stdlib_module_names) - propios
        return {_norma(d) for m in terceros for d in distribucion.get(m, [m])}

    runtime = importados([*(RAIZ / "agente_iam").rglob("*.py"), RAIZ / "main.py"])
    resto = importados([p for d in ("tests", "scripts", "infra") for p in (RAIZ / d).rglob("*.py")])
    assert {"pydantic", "botocore", "boto3", "strands-agents"} <= runtime
    assert "pyyaml" in resto
    produccion = {_norma(n) for n in _fijadas("requirements.txt")}
    desarrollo = {_norma(n) for n in _fijadas("requirements-dev.txt")}
    assert sorted(runtime - produccion) == []
    assert sorted(resto - produccion - desarrollo) == []


def test_mypy_mantiene_el_paso_1():
    """O7 (24-10-2026): cinco opciones que daban 0 errores sin tocar codigo.
    Quitarlas no rompe nada que se vea; por eso se fijan aqui."""
    config = (RAIZ / "mypy.ini").read_text(encoding="utf-8")
    for opcion in ("check_untyped_defs", "warn_unreachable", "warn_redundant_casts",
                   "no_implicit_optional", "warn_unused_configs"):
        assert re.search(rf"^{opcion} = True$", config, re.M), opcion


def test_ruff_vigila_los_noqa_y_los_assert_compuestos():
    """RUF100 (O6) y PT018 (O14), 24-10-2026: sin ellas vuelven los `noqa`
    que no callan nada y los `assert a and b` que no dicen cual fallo."""
    config = (RAIZ / "ruff.toml").read_text(encoding="utf-8")
    seleccion = re.search(r"^select = \[(.*)\]", config, re.M)[1]
    for regla in ('"RUF100"', '"PT018"'):
        assert regla in seleccion


# --- 24-10-2026 (ADR-003, Tarea 6): el zip de la Lambda de aprobacion ----------


def _script() -> str:
    return (RAIZ / "scripts" / "empaquetar.sh").read_text(encoding="utf-8")


def test_la_lambda_de_aprobacion_lleva_lo_que_importa_y_nada_mas():
    """La Lambda arranca `agente_iam.aprobar.manejador`. Lo que su cadena de
    imports necesita viaja; lo demas (el cliente de la persona, el aplicador,
    el CLI, el servidor y el orquestador del agente) se borra del zip. Si un
    dia aprobar.py importara algo de la lista de fuera, la Lambda no
    arrancaria: por eso las dos listas tienen que ser disjuntas."""
    fuera = _lista(_script(), "FUERA_DE_LA_APROBACION")
    cadena = _cadena_de_imports(RAIZ / "agente_iam" / "aprobar.py")
    # La cadena no incluye el modulo de partida: aprobar.py se comprueba aparte.
    assert {"huella.py", "almacen.py"} <= cadena
    assert "aprobar.py" not in fuera
    assert {
        "aprobar_cliente.py", "aplicador.py", "cli.py", "servidor.py", "orquestador.py", "agente.py",
    } <= set(fuera)
    assert sorted(set(fuera) & cadena) == []


def _modulos_de_agente_iam() -> set[str]:
    """Todos los .py de `agente_iam/`, relativos a esa carpeta (con `/`)."""
    raiz = RAIZ / "agente_iam"
    return {p.relative_to(raiz).as_posix() for p in raiz.rglob("*.py") if "__pycache__" not in p.parts}


def test_cada_modulo_esta_en_un_lado_del_paquete_de_la_aprobacion():
    """Lista POSITIVA (revision final, F6). Las listas de `fuera` se borran del
    zip y la cadena de imports viaja; un modulo nuevo que no este en ninguna
    de las dos viajaria por omision. Aqui toda la carpeta tiene que ser: lo
    que importa aprobar.py, lo que el script borra, o aprobar.py. Un modulo
    nuevo falla este test hasta que alguien decida de que lado va."""
    fuera = set(_lista(_script(), "FUERA_DE_LA_APROBACION"))
    cadena = _cadena_de_imports(RAIZ / "agente_iam" / "aprobar.py")
    assert _modulos_de_agente_iam() == cadena | fuera | {"aprobar.py"}


def test_cada_modulo_esta_en_un_lado_del_paquete_del_runtime():
    """Lo mismo para el runtime, cuyo punto de entrada (main.py) vive fuera de
    `agente_iam/`, asi que no hay modulo de entrada que sumar."""
    fuera = set(_lista(_script(), "FUERA_DEL_RUNTIME"))
    cadena = _cadena_de_imports(RAIZ / "main.py")
    assert _modulos_de_agente_iam() == cadena | fuera


def test_el_zip_de_la_aprobacion_comprueba_que_lleva_lo_que_necesita():
    """El otro sentido de la comprobacion del zip: no basta con que no lleve lo
    que sobra; la Lambda no arranca sin aprobar.py ni huella.py, y un
    `FUERA_DE_LA_APROBACION` que los borrara por error daria un zip que solo
    falla en la nube. El script sale con 1 si faltan en el zip. La lista
    concreta la fija el `case` en `LLEVA` (una sola comprobacion para las dos
    Lambdas), y el runtime la deja vacia."""
    script = _script()
    necesarios = _lista(script, "LLEVA_LA_APROBACION")
    assert {"aprobar.py", "huella.py"} <= set(necesarios)
    assert re.search(r'aprobacion\)(?:(?!;;).)*?LLEVA="\$LLEVA_LA_APROBACION"', script, re.S)
    assert re.search(r'runtime\)(?:(?!;;).)*?LLEVA=""', script, re.S)
    _comprueba_lo_que_lleva(script)


def _comprueba_lo_que_lleva(script: str) -> None:
    """La comprobacion final mira el zip y sale con 1 si falta algo de `LLEVA`."""
    despues = script.split('zip -qr "../$(basename "$PAQUETE")" .', 1)[1]
    comprobacion = despues.split("comprimido=", 1)[0]
    assert "for m in $LLEVA; do" in comprobacion
    assert "zipfile.ZipFile" in comprobacion
    assert "exit 1" in comprobacion.split("$LLEVA", 1)[1]


def test_el_runtime_tampoco_lleva_el_cliente():
    """El cliente firma con las credenciales de la persona: es de su equipo,
    no del runtime donde corre el agente."""
    assert "aprobar_cliente.py" in _lista(_script(), "FUERA_DEL_RUNTIME")


def test_la_aprobacion_no_lleva_el_sdk_de_agentcore():
    """bedrock-agentcore solo lo usa servidor.py, que la Lambda no lleva."""
    fijadas = _fijadas("requirements-aprobacion.txt")
    assert "bedrock-agentcore" not in fijadas
    # strands lo importan catalogo.py y validacion.py (la cadena de aprobar.py).
    assert set(fijadas) == {"strands-agents", "boto3", "pydantic", "botocore"}
    runtime = _fijadas("requirements.txt")
    assert fijadas == {p: runtime[p] for p in fijadas}
    assert "requirements-aprobacion.txt" in _script()


def test_la_lambda_cabe_en_250_mb():
    """El limite de Lambda es 250 MB sin comprimir y no se amplia. El script
    compara el tamano plano con 250 para `aprobacion` (750 para el runtime) y
    lo hace antes de dar el zip por bueno."""
    script = _script()
    assert re.search(r'aprobacion\)(?:(?!;;).)*?LIMITE_PLANO=250', script, re.S)
    assert re.search(r'runtime\)(?:(?!;;).)*?LIMITE_PLANO=750', script, re.S)
    assert '[ "$plano" -lt "$LIMITE_PLANO" ]' in script


def test_empaquetar_elige_destino_y_rechaza_lo_desconocido():
    script = _script()
    assert 'DESTINO_PAQUETE="${1:-runtime}"' in script
    # Sin argumento o `runtime`: el zip de siempre. `aprobacion`: el suyo.
    assert 'PAQUETE="$DESTINO/agente-iam.zip"' in script
    assert 'PAQUETE="$DESTINO/agente-iam-aprobacion.zip"' in script
    # main.py es del runtime y solo del runtime.
    assert re.search(r'if \[ "\$DESTINO_PAQUETE" = runtime \]; then\s+cp main\.py ', script)
    # La clave S3 que se sube: 12 hex del sha256 del zip.
    assert 'PREFIJO_S3="aprobacion"' in script
    assert "agente-iam/${PREFIJO_S3}-" in script
    assert "sha256sum" in script.split("agente-iam/${PREFIJO_S3}-", 1)[0]

    import subprocess

    fallo = subprocess.run(
        ["bash", str(RAIZ / "scripts" / "empaquetar.sh"), "desconocido"],
        capture_output=True, text=True, timeout=30,
    )
    assert fallo.returncode != 0
    assert "uso" in fallo.stderr.lower()
    assert "runtime" in fallo.stderr
    assert "aprobacion" in fallo.stderr
    # Falla antes de los tests y de la red: no empieza ningun paso.
    assert "==>" not in fallo.stdout


# --- 25-10-2026: el zip de la Lambda del aplicador -----------------------------
# El aplicador (agente_iam.aplicador.manejador) escribe en IAM y la aprobacion
# no: son dos Lambdas con dos roles y dos zips. El del aplicador lleva lo del de
# la aprobacion mas aplicador.py.


def test_la_lambda_del_aplicador_lleva_lo_que_importa_y_nada_mas():
    """Misma regla que para la aprobacion: lo que importa aplicador.py viaja, lo
    demas se borra del zip, y las dos listas tienen que ser disjuntas o la
    Lambda no arrancaria. aprobar.py viaja porque aplicador.py importa de ahi
    `revalidar`, `comprobar_techo` e `identificar_aprobador`."""
    fuera = _lista(_script(), "FUERA_DEL_APLICADOR")
    cadena = _cadena_de_imports(RAIZ / "agente_iam" / "aplicador.py")
    assert {"aprobar.py", "huella.py", "almacen.py", "coherencia.py"} <= cadena
    assert "aplicador.py" not in fuera
    assert {
        "aprobar_cliente.py", "cli.py", "servidor.py", "orquestador.py", "agente.py",
    } <= set(fuera)
    assert sorted(set(fuera) & cadena) == []


def test_cada_modulo_esta_en_un_lado_del_paquete_del_aplicador():
    """Lista POSITIVA, como la de la aprobacion: toda la carpeta es lo que
    importa aplicador.py, lo que el script borra, o aplicador.py. Un modulo
    nuevo falla hasta que alguien decida de que lado va."""
    fuera = set(_lista(_script(), "FUERA_DEL_APLICADOR"))
    cadena = _cadena_de_imports(RAIZ / "agente_iam" / "aplicador.py")
    # avisos.py es el manejador de la otra Lambda que usa este zip (la de avisos);
    # lo que importa (motivos.py desde la Fase 28) tambien tiene que viajar.
    cadena |= _cadena_de_imports(RAIZ / "agente_iam" / "avisos.py")
    assert _modulos_de_agente_iam() == cadena | fuera | {"aplicador.py", "avisos.py"}


def test_el_zip_del_aplicador_comprueba_que_lleva_lo_que_necesita():
    """Sin aplicador.py (el manejador), aprobar.py (de donde importa) ni
    huella.py la Lambda no arranca; el script lo comprueba en el zip."""
    script = _script()
    necesarios = _lista(script, "LLEVA_EL_APLICADOR")
    assert {"aplicador.py", "avisos.py", "aprobar.py", "huella.py"} <= set(necesarios)
    assert re.search(r'aplicador\)(?:(?!;;).)*?LLEVA="\$LLEVA_EL_APLICADOR"', script, re.S)
    _comprueba_lo_que_lleva(script)


def test_el_aplicador_lleva_las_mismas_dependencias_que_la_aprobacion():
    """Sin bedrock-agentcore (solo lo usa servidor.py); strands-agents entra por
    catalogo.py y validacion.py a traves de aprobar.py. Mismas versiones que
    requirements.txt, que ya vigila test_constraints_coincide_con_las_directas."""
    fijadas = _fijadas("requirements-aplicador.txt")
    assert "bedrock-agentcore" not in fijadas
    assert set(fijadas) == {"strands-agents", "boto3", "pydantic", "botocore"}
    assert fijadas == _fijadas("requirements-aprobacion.txt")
    runtime = _fijadas("requirements.txt")
    assert fijadas == {p: runtime[p] for p in fijadas}


def test_empaquetar_construye_tambien_el_aplicador():
    script = _script()
    assert 'PAQUETE="$DESTINO/agente-iam-aplicador.zip"' in script
    assert "requirements-aplicador.txt" in script
    assert re.search(r'aplicador\)(?:(?!;;).)*?FUERA="\$FUERA_DEL_APLICADOR"', script, re.S)
    # Cabe en una Lambda: 250 MB sin comprimir, como la aprobacion.
    assert re.search(r'aplicador\)(?:(?!;;).)*?LIMITE_PLANO=250', script, re.S)
    # main.py es solo del runtime, tambien con el tercer paquete.
    assert re.search(r'if \[ "\$DESTINO_PAQUETE" = runtime \]; then\s+cp main\.py ', script)
    # La clave S3 lleva la huella del zip y el nombre de la Lambda que lo usa.
    assert 'PREFIJO_S3="aplicador"' in script
    assert "agente-iam/${PREFIJO_S3}-" in script

    import subprocess

    fallo = subprocess.run(
        ["bash", str(RAIZ / "scripts" / "empaquetar.sh"), "desconocido"],
        capture_output=True, text=True, timeout=30,
    )
    assert fallo.returncode != 0
    assert "aplicador" in fallo.stderr
