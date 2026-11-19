"""Genera el techo de los beneficiarios (`AgenteIAM-Techo` v2, ADR-002).

    ./.venv/bin/python scripts/generar_techo.py              # escribe el JSON y la copia de arranque.yaml
    ./.venv/bin/python scripts/generar_techo.py --comprobar  # sale con 1 si no coinciden con lo generado
    ./.venv/bin/python scripts/generar_techo.py --catalogo DIR  # lee <DIR>/<servicio>.json en vez de descargar

POR QUE EXISTE (23-10-2026). El techo v1 permitia enteros los 8 servicios
que concede el codigo, asi que solo frenaba lo que el codigo ya frenaba.
El v2 refleja las reglas del codigo en IAM, para el caso en que alguien se
salta el codigo (ADR-002):

  - B:  EC2 solo `Describe*` (`SOLO_LECTURA` de config).
  - D1: Deny de las acciones de gestion de permisos de lo que el Allow
        deja pasar. Es la regla del codigo "ningun tipo de acceso concede
        IsPermissionManagement"; la lista sale de la referencia de
        autorizacion, no se escribe a mano.
  - D2: Deny de todo sobre los recursos del sistema, con los mismos
        patrones con los que el rol de despliegue puede crearlos
        (`infra/cfn/arranque.yaml`; un test los compara).
  - La gemela de ACCIONES_PROHIBIDAS dentro de los servicios permitidos,
    como en el v1.

Y dos mas desde la revision del 24-10-2026:

  - S3: Deny de las acciones de escritura (o de etiquetado) SIN tipo de
        recurso que el Allow deja pasar, salvo las de
        `ESCRITURAS_SIN_RECURSO_PERMITIDAS`. Es la regla del codigo "con
        Resource '*' solo lectura": esas acciones actuan sobre la cuenta
        entera (`logs:PutAccountPolicy`, `sns:SetSMSAttributes`...). Sale
        de la referencia, como D1. Para que quepa en los 6144 caracteres se
        agrupan con un prefijo (`sns:CreatePlatform*`) solo cuando TODAS las
        acciones del catalogo con ese prefijo ya las niega el techo; si
        aparece una que no, el prefijo deja de valer al regenerar.
  - S5: Deny de los servicios permitidos cuando el recurso es de otra
        cuenta (`aws:ResourceAccount` distinto de `${aws:PrincipalAccount}`,
        variable de politica: no se escribe ninguna cuenta). Un Deny con
        operador negado e `IfExists` niega TAMBIEN si la clave falta (guia
        de operadores de condicion de IAM). Medido el 24-10-2026 con
        `scripts/sonda_cuenta.py`: las 17 llamadas concluyentes de los ocho
        servicios llevan la clave; las de la propia cuenta pasan, y un bucket
        publico de otra cuenta y una capa de Lambda de AWS se niegan.

Escribe las dos copias que deben ser identicas: el JSON que lee
`agente_iam/aprobar.py` y el `PolicyDocument` del recurso `Techo` de la
pila de arranque. La referencia se descarga cada vez (no usa la cache del
agente), para que el techo no herede un catalogo viejo. `--comprobar` es lo
que corre `tests/funcionales/test_techo_en_vivo.py` contra la referencia
del dia.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

_RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_RAIZ))

from agente_iam.config import (
    ACCIONES_PROHIBIDAS,
    ESCRITURAS_SIN_RECURSO_PERMITIDAS,
    SERVICIOS_PERMITIDOS,
    SOLO_LECTURA,
)

RUTA_JSON = _RAIZ / "infra" / "boundary-agente-iam-techo.json"
RUTA_ARRANQUE = _RAIZ / "infra" / "cfn" / "arranque.yaml"
_URL = "https://servicereference.us-east-1.amazonaws.com/v1/{s}/{s}.json"

# Limite de IAM para una politica gestionada, sin contar espacios.
LIMITE_CARACTERES = 6144

# D2. Los recursos que el rol de despliegue puede crear dentro de los 8
# servicios, con region y cuenta abiertas: un Deny ancho no abre nada.
# `agente-iam-*` de S3 cubre tambien los objetos (el `*` cruza la `/`), y el
# de DynamoDB, los streams de la tabla.
PATRONES_DEL_SISTEMA = [
    "arn:aws:s3:::agente-iam-*",
    "arn:aws:dynamodb:*:*:table/agente-iam-*",
    "arn:aws:sqs:*:*:agente-iam-*",
    "arn:aws:sns:*:*:agente-iam-*",
    "arn:aws:lambda:*:*:function:agente-iam-*",
    "arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/runtimes/agente_iam*",
    "arn:aws:logs:*:*:log-group:/aws/lambda/agente-iam-*",
    "arn:aws:logs:*:*:log-group:agente-iam-*",
    "arn:aws:cloudwatch:*:*:alarm:agente-iam-*",
]

# Los disparadores (event source mappings) no llevan nombre: el rol de
# despliegue los crea sobre `event-source-mapping:*`. Se reconocen por la
# funcion a la que apuntan, con `lambda:FunctionArn`, que la referencia
# trae en estas cuatro acciones.
_ACCIONES_DE_DISPARADORES = [
    "lambda:CreateEventSourceMapping",
    "lambda:DeleteEventSourceMapping",
    "lambda:GetEventSourceMapping",
    "lambda:UpdateEventSourceMapping",
]

_AUTOSERVICIO = [
    "iam:ChangePassword",
    "iam:GetUser",
    "iam:GetAccountPasswordPolicy",
    "iam:ListMFADevices",
    "sts:GetCallerIdentity",
]


def patron_permitido(servicio: str) -> str:
    """El nombre de accion que el Allow del techo deja pasar en el servicio."""
    return SOLO_LECTURA.get(servicio, "*")


def descargar(servicio: str) -> dict:
    # bandit B310 revisado: esquema y host fijos; servicio sale de config.
    with urllib.request.urlopen(_URL.format(s=servicio), timeout=30) as r:  # nosec B310
        return json.loads(r.read())


def gestion_de_permisos(catalogos: dict[str, dict]) -> list[str]:
    """Las acciones de gestion de permisos que el Allow del techo dejaria pasar.

    Por servicio, en el orden de SERVICIOS_PERMITIDOS y por nombre. Quedan
    fuera las que ya niega la gemela, para no repetirlas.
    """
    gemela = {a.lower() for a in _gemela()}
    acciones = []
    for servicio in SERVICIOS_PERMITIDOS:
        patron = patron_permitido(servicio).lower()
        nombres = sorted(
            a["Name"]
            for a in catalogos[servicio].get("Actions", [])
            if a.get("Annotations", {}).get("Properties", {}).get("IsPermissionManagement")
            and fnmatchcase(a["Name"].lower(), patron)
        )
        acciones += [f"{servicio}:{n}" for n in nombres if f"{servicio}:{n}".lower() not in gemela]
    return acciones


def _escritura_sin_recurso(accion: dict) -> bool:
    """Escribe o etiqueta y no tiene tipo de recurso. La gestion de permisos
    no cuenta: la niega D1."""
    props = accion.get("Annotations", {}).get("Properties", {})
    return (
        not accion.get("Resources")
        and not props.get("IsPermissionManagement")
        and bool(props.get("IsWrite") or props.get("IsTaggingOnly"))
    )


def _palabras(nombre: str) -> list[str]:
    return re.findall(r"[A-Z][a-z0-9]*|[a-z0-9]+", nombre)


def _comprimir(pendientes: list[str], todos: list[str], negadas: set[str]) -> list[str]:
    """Agrupa `pendientes` (nombres de un servicio) por prefijos seguros.

    Un prefijo `P*` sustituye a sus acciones solo si TODAS las del catalogo
    que empiezan por P estan en `negadas` (las que el techo ya niega) y
    cubre al menos dos pendientes. Se prueba de mas corto a mas largo, en
    fronteras de palabra (`Create`, `CreatePlatform`...), para que el
    patron sea legible. Deterministico: misma entrada, mismo resultado.
    """
    quedan = set(pendientes)
    salida: list[str] = []
    for nombre in sorted(pendientes):
        if nombre not in quedan:
            continue
        palabras = _palabras(nombre)
        elegido = nombre
        for k in range(1, len(palabras)):
            prefijo = "".join(palabras[:k]).lower()
            cubre = [a for a in todos if a.lower().startswith(prefijo)]
            if all(a.lower() in negadas for a in cubre) and sum(a in quedan for a in cubre) >= 2:
                elegido = "".join(palabras[:k]) + "*"
                break
        if elegido.endswith("*"):
            quedan -= {a for a in todos if a.lower().startswith(elegido[:-1].lower())}
        else:
            quedan.discard(nombre)
        salida.append(elegido)
    return salida


def escrituras_sin_recurso(catalogos: dict[str, dict], gestion: list[str]) -> list[str]:
    """S3: las escrituras sin tipo de recurso que el Allow dejaria pasar.

    Por servicio, en el orden de SERVICIOS_PERMITIDOS. Quedan fuera la
    gemela, la gestion de permisos (D1) y la lista blanca de config. Se
    agrupan con `_comprimir`, contando como ya negadas las de D1 y la gemela.
    """
    permitidas = {a.lower() for a in ESCRITURAS_SIN_RECURSO_PERMITIDAS}
    gemela = {a.lower() for a in _gemela()}
    acciones: list[str] = []
    for servicio in SERVICIOS_PERMITIDOS:
        patron = patron_permitido(servicio).lower()
        todos = [a["Name"] for a in catalogos[servicio].get("Actions", [])]
        pendientes = [
            a["Name"]
            for a in catalogos[servicio].get("Actions", [])
            if _escritura_sin_recurso(a)
            and fnmatchcase(a["Name"].lower(), patron)
            and f"{servicio}:{a['Name']}".lower() not in gemela | permitidas
        ]
        ya_negadas = {
            a.split(":", 1)[1].lower()
            for a in [*gestion, *_gemela()]
            if a.split(":", 1)[0] == servicio
        }
        negadas = ya_negadas | {n.lower() for n in pendientes}
        acciones += [f"{servicio}:{n}" for n in _comprimir(pendientes, todos, negadas)]
    return acciones


def _gemela() -> list[str]:
    return [a for a in ACCIONES_PROHIBIDAS if a.split(":", 1)[0] in SERVICIOS_PERMITIDOS]


def construir_techo(gestion: list[str], escrituras: list[str]) -> dict:
    """El documento entero. Determinista: misma entrada, mismo JSON."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AlcanceDelSistema",
                "Effect": "Allow",
                "Action": [f"{s}:{patron_permitido(s)}" for s in SERVICIOS_PERMITIDOS],
                "Resource": "*",
            },
            {
                "Sid": "AutoservicioMinimoDelUsuario",
                "Effect": "Allow",
                "Action": _AUTOSERVICIO,
                "Resource": "*",
            },
            {
                "Sid": "GemelaDeAccionesProhibidasDelCodigo",
                "Effect": "Deny",
                "Action": _gemela(),
                "Resource": "*",
            },
            {
                "Sid": "SinGestionDePermisos",
                "Effect": "Deny",
                "Action": gestion,
                "Resource": "*",
            },
            {
                "Sid": "SinEscriturasDeAlcanceDeCuenta",
                "Effect": "Deny",
                "Action": escrituras,
                "Resource": "*",
            },
            {
                "Sid": "NadaSobreLosRecursosDelSistema",
                "Effect": "Deny",
                "Action": "*",
                "Resource": PATRONES_DEL_SISTEMA,
            },
            {
                "Sid": "NiLosDisparadoresDelSistema",
                "Effect": "Deny",
                "Action": _ACCIONES_DE_DISPARADORES,
                "Resource": "*",
                "Condition": {"ArnLike": {"lambda:FunctionArn": "arn:aws:lambda:*:*:function:agente-iam-*"}},
            },
            {
                "Sid": "SoloRecursosDeLaPropiaCuenta",
                "Effect": "Deny",
                "Action": [f"{s}:*" for s in SERVICIOS_PERMITIDOS],
                "Resource": "*",
                "Condition": {"StringNotEqualsIfExists": {"aws:ResourceAccount": "${aws:PrincipalAccount}"}},
            },
        ],
    }


def caracteres(documento: dict) -> int:
    """Lo que IAM cuenta contra el limite: el JSON sin espacios."""
    return len(json.dumps(documento, separators=(",", ":")))


def texto_json(documento: dict) -> str:
    return json.dumps(documento, indent=2, ensure_ascii=False) + "\n"


def arranque_con(documento: dict, texto: str) -> str:
    """`arranque.yaml` con el PolicyDocument del Techo sustituido.

    El Techo es el ultimo recurso de la plantilla: su documento va de la
    linea `PolicyDocument:` que sigue a `ManagedPolicyName: AgenteIAM-Techo`
    hasta `Outputs:`. Lo demas (comentarios incluidos) queda intacto.
    """
    nombre = texto.index("ManagedPolicyName: AgenteIAM-Techo")
    inicio = texto.index("      PolicyDocument:\n", nombre)
    fin = texto.index("\nOutputs:", inicio)
    cuerpo = yaml.safe_dump(documento, sort_keys=False, default_flow_style=False, width=1000)
    sangrado = "".join(f"        {linea}\n" for linea in cuerpo.splitlines())
    return texto[:inicio] + "      PolicyDocument:\n" + sangrado + texto[fin:]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--comprobar", action="store_true", help="no escribe; sale con 1 si hay diferencias")
    p.add_argument("--catalogo", type=Path, help="carpeta con <servicio>.json en lugar de descargar")
    args = p.parse_args(argv)

    if args.catalogo:
        catalogos = {s: json.loads((args.catalogo / f"{s}.json").read_text()) for s in SERVICIOS_PERMITIDOS}
    else:
        catalogos = {s: descargar(s) for s in SERVICIOS_PERMITIDOS}

    gestion = gestion_de_permisos(catalogos)
    documento = construir_techo(gestion, escrituras_sin_recurso(catalogos, gestion))
    n = caracteres(documento)
    if n > LIMITE_CARACTERES:
        print(f"El techo ocupa {n} caracteres; el limite de IAM es {LIMITE_CARACTERES}.", file=sys.stderr)
        return 1

    nuevo_json = texto_json(documento)
    nuevo_arranque = arranque_con(documento, RUTA_ARRANQUE.read_text(encoding="utf-8"))
    if args.comprobar:
        distintos = [
            str(ruta.relative_to(_RAIZ))
            for ruta, nuevo in ((RUTA_JSON, nuevo_json), (RUTA_ARRANQUE, nuevo_arranque))
            if ruta.read_text(encoding="utf-8") != nuevo
        ]
        if distintos:
            print("No coincide con lo generado: " + ", ".join(distintos), file=sys.stderr)
            return 1
        print(f"Techo al dia ({n} caracteres).")
        return 0

    RUTA_JSON.write_text(nuevo_json, encoding="utf-8")
    RUTA_ARRANQUE.write_text(nuevo_arranque, encoding="utf-8")
    print(f"Escrito {RUTA_JSON.relative_to(_RAIZ)} y el Techo de {RUTA_ARRANQUE.relative_to(_RAIZ)} ({n} caracteres).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
