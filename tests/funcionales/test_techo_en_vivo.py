"""Funcional: el techo sigue al dia con la referencia de autorizacion de hoy.

La lista de D1 (ADR-002) se genero el 23-10-2026 desde la referencia
publica de AWS. Si AWS anade una accion de gestion de permisos a uno de los
servicios permitidos, el techo no la niega hasta regenerarlo; el codigo la
sigue frenando, porque mira el catalogo. Este test lo dice: corre
`scripts/generar_techo.py --comprobar`, que descarga la referencia del dia.

No usa credenciales ni toca la cuenta (la referencia es publica); vive aqui
porque sale a la red y su resultado depende del dia. Si se pone en rojo:
regenerar, revisar el diff y actualizar la pila de arranque (con el si de
Mateo).
"""

import subprocess
import sys

from tests.puerta import RAIZ


def test_el_techo_coincide_con_la_referencia_de_hoy():
    salida = subprocess.run(  # nosec B603 -- argumentos fijos, sin shell
        [sys.executable, str(RAIZ / "scripts" / "generar_techo.py"), "--comprobar"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert salida.returncode == 0, salida.stdout + salida.stderr
