"""Punto de entrada del paquete desplegado en AgentCore Runtime.

    entryPoint: ["main.py"]

EXISTE POR `sys.path`, no por gusto. AgentCore ejecuta el entryPoint como
un proceso normal, asi que Python pone la carpeta DEL SCRIPT como
`sys.path[0]`. Si el entryPoint fuera `agente_iam/servidor.py`, ese primer
elemento seria `/var/task/agente_iam` y `from agente_iam import almacen` no
resolveria: el paquete quedaria justo fuera del camino de busqueda. Con
este archivo en la raiz del zip, `sys.path[0]` es la raiz, que es donde
esta `agente_iam/`.

Y RESUELVE EL CATALOGO SIN DEPENDER DEL CWD. `config.DIR_CACHE_CATALOGO`
trae por defecto una ruta RELATIVA, comoda en local y peligrosa aqui: el
directorio de trabajo del proceso desplegado no es el nuestro, y si no
resuelve, el catalogo no carga. Un catalogo que no carga no revienta nada:
apaga el chequeo de nivel de acceso en silencio (ver
`catalogo._guardar_en_cache`). Asi que la ruta se calcula desde `__file__`,
que siempre sabe donde esta.

OJO AL ORDEN, que es la parte que solo se rompe desplegado: `config.py`
lee las variables de entorno AL IMPORTARSE. Si el `import` de abajo
subiera por encima del `setdefault`, la variable llegaria tarde, config ya
tendria la ruta relativa y esto no serviria de nada — sin ningun error.
Por eso el import va despues, y por eso hay un test que lo vigila.
"""

import os
from pathlib import Path

# Solo si el catalogo esta AQUI AL LADO, que es como llega dentro del zip
# (lo mete `scripts/empaquetar.sh`). Corriendo esto en el arbol de desarrollo esa
# carpeta no existe, y fijar la variable de todos modos haria que el
# catalogo se volviera a descargar entero en la raiz del proyecto en vez
# de usar la cache de siempre. Comprobado ejecutandolo: paso exactamente eso.
_CATALOGO = Path(__file__).resolve().parent / "catalogo"
if _CATALOGO.is_dir():
    os.environ.setdefault("DIR_CACHE_CATALOGO", str(_CATALOGO))

from agente_iam.servidor import arrancar  # ver la nota del orden

if __name__ == "__main__":
    arrancar()
