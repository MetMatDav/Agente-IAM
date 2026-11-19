"""Genera copias locales de `ejemplos/` e `infra/` con la cuenta real.

    ./.venv/bin/python scripts/localizar.py              # cuenta de las credenciales actuales
    ./.venv/bin/python scripts/localizar.py 123456789012 # o una cuenta explicita

El repositorio usa `111122223333`, la cuenta de ejemplo de la documentacion
de AWS, para no publicar la real. Con ella los ejemplos no sirven en vivo:
`identidad.verificar` los rechazaria por cuenta ajena, que es justo lo que
debe hacer. Este script escribe en `local/` (ignorada por git) una copia con
la cuenta sustituida:

    local/ejemplos/*.json   para el intake
    local/infra/*.json      para pegar en la consola de IAM

Nunca escribe dentro de `ejemplos/` ni de `infra/`.
"""

import sys
from pathlib import Path

MARCADOR = "111122223333"
RAIZ = Path(__file__).resolve().parent.parent


def cuenta_actual() -> str:
    import boto3

    return boto3.client("sts").get_caller_identity()["Account"]


def main() -> None:
    cuenta = sys.argv[1] if len(sys.argv) > 1 else cuenta_actual()
    if not (cuenta.isdigit() and len(cuenta) == 12):
        sys.exit(f"'{cuenta}' no es un id de cuenta AWS de 12 digitos")
    escritos = 0
    for origen in ("ejemplos", "infra"):
        for f in (RAIZ / origen).rglob("*.json"):
            destino = RAIZ / "local" / f.relative_to(RAIZ)
            destino.parent.mkdir(parents=True, exist_ok=True)
            destino.write_text(f.read_text(encoding="utf-8").replace(MARCADOR, cuenta), encoding="utf-8")
            escritos += 1
    print(f"{escritos} archivos en {RAIZ / 'local'} con la cuenta {cuenta}")


if __name__ == "__main__":
    main()
