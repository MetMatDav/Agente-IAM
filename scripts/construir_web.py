"""Construye la carpeta de la pagina web con la configuracion de la cuenta.

    ./.venv/bin/python scripts/construir_web.py                      # escribe en local/web
    ./.venv/bin/python scripts/construir_web.py --destino /ruta --cliente-web <id>

POR QUE EXISTE. La pagina (`web/index.html`, `estilos.css`, `app.js`) esta en
el repositorio, que es publico, y por eso no lleva NADA de la cuenta: ni el
dominio de Cognito, ni el id del pool, ni el del cliente, ni el endpoint del
runtime. Todo eso se genera al construir, desde dos fuentes: las listas
cerradas de `agente_iam/config.py` (las mismas que usa el servidor, para que
la pagina no pueda ofrecer algo que el servidor rechaza) y las salidas de las
pilas `agente-iam-acceso` y `agente-iam-runtime`. Es el mismo patron que
`scripts/localizar.py` con `local/`: lo versionado lleva la cuenta de ejemplo
y lo real se genera en una carpeta ignorada por git.

El resultado es `config.js`, UNA linea `window.AGENTE_IAM = {...};` que
`index.html` carga antes de `app.js`. Ahi no hay secretos: el id del cliente
de Cognito y el dominio son publicos por diseno (PKCE, sin secreto del
cliente). El script solo imprime rutas, nunca el contenido.

La URL del runtime se calcula con `scripts/solicitar.py:url_runtime`, cargado
igual que `solicitar.py` carga `prueba_b.py`, para no duplicar la formula.

Codigos de salida: 0 escrito; 2 la pila `acceso` no tiene todavia el cliente
web (y no se paso `--cliente-web`); 1 todo lo demas (red, perfil sin sesion).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from agente_iam import config, personas

PILA_ACCESO = "agente-iam-acceso"
PILA_RUNTIME = "agente-iam-runtime"
REGION = "us-east-1"
ORIGEN = RAIZ / "web"
# vista-previa.png es la imagen de las etiquetas Open Graph (Fase 28): la leen los robots de
# vista previa (LinkedIn), no la pagina.
FICHEROS = ("index.html", "estilos.css", "app.js", "vista-previa.png")


def _cargar_solicitar() -> Any:
    ruta = Path(__file__).resolve().parent / "solicitar.py"
    spec = importlib.util.spec_from_file_location("solicitar", ruta)
    if spec is None or spec.loader is None:
        raise ImportError(f"no se puede cargar {ruta}")
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


_solicitar = _cargar_solicitar()


# --- Piezas puras (las prueba tests/unitarios/test_web.py) -------------------


def configuracion(salidas_acceso: dict[str, str], salidas_runtime: dict[str, str],
                  cliente_web: str, cuenta: str) -> dict[str, Any]:
    """Lo que la pagina necesita saber de la cuenta y del servidor."""
    return {
        "region": REGION,
        "dominioCognito": salidas_acceso["UrlDominio"],
        "clienteId": cliente_web,
        "poolId": salidas_acceso["UserPoolId"],
        "urlRuntime": _solicitar.url_runtime(salidas_runtime["RuntimeArn"]),
        "servicios": list(config.SERVICIOS_PERMITIDOS),
        "regiones": list(config.REGIONES_PERMITIDAS),
        "horasMin": personas.HORAS_MIN,
        "horasMax": personas.HORAS_MAX,
        "cuenta": cuenta,
    }


def escribir(configuracion: dict[str, Any], destino: Path) -> Path:
    """Copia `web/*` a `destino` y escribe `destino/config.js`; devuelve su ruta."""
    destino.mkdir(parents=True, exist_ok=True)
    for nombre in FICHEROS:
        shutil.copyfile(ORIGEN / nombre, destino / nombre)
    ruta = destino / "config.js"
    ruta.write_text(
        f"window.AGENTE_IAM = {json.dumps(configuracion, ensure_ascii=True, sort_keys=True)};\n",
        encoding="utf-8")
    return ruta


# --- Con red ------------------------------------------------------------------


def _salidas(perfil: str, pila: str) -> dict[str, str]:
    import boto3

    cf = boto3.Session(profile_name=perfil, region_name=REGION).client("cloudformation")
    return {o["OutputKey"]: o["OutputValue"] for o in cf.describe_stacks(StackName=pila)["Stacks"][0]["Outputs"]}


def _cuenta(perfil: str) -> str:
    import boto3

    return str(boto3.Session(profile_name=perfil, region_name=REGION).client("sts").get_caller_identity()["Account"])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Escribe la pagina web con la configuracion de la cuenta.")
    p.add_argument("--perfil", default="org-agente-iam")
    p.add_argument("--destino", default=str(RAIZ / "local" / "web"))
    p.add_argument("--cliente-web", default=None,
                   help="id del cliente de Cognito de la web (por defecto, la salida ClienteWebId de la pila acceso)")
    args = p.parse_args(argv)

    acceso = _salidas(args.perfil, PILA_ACCESO)
    cliente = args.cliente_web or acceso.get("ClienteWebId")
    if not cliente:
        print("la pila acceso no tiene todavia el cliente web", file=sys.stderr)
        return 2
    runtime = _salidas(args.perfil, PILA_RUNTIME)
    cuenta = _cuenta(args.perfil)
    ruta = escribir(configuracion(acceso, runtime, cliente, cuenta), Path(args.destino))
    print(f"pagina escrita en {ruta.parent}")
    print(f"configuracion: {ruta}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
