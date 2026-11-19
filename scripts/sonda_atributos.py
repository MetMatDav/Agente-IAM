"""Sonda de `dynamodb:Attributes` con llamadas reales (Fase 18, tarea 6).

    ./.venv/bin/python scripts/sonda_atributos.py                                     # solo muestra el plan
    ./.venv/bin/python scripts/sonda_atributos.py --ejecutar --perfil org-agente-iam-aprobador-demo
    ./.venv/bin/python scripts/sonda_atributos.py --ejecutar --perfil org-agente-iam-aprobador-demo --solo-lectura

POR QUE EXISTE (24-10-2026). Todo el reparto de la tabla (un atributo por
actor, ningun `PutItem`) descansa en que `dynamodb:Attributes` frene de verdad
un `UpdateItem` sobre un atributo que no esta en la lista. Eso estaba en la guia
de control de acceso detallado de DynamoDB y en el simulador (MEDICIONES F.4,
F.5), nunca en una llamada real. Y queda una pregunta que la guia no contesta:
si los atributos que solo aparecen en la `ConditionExpression` cuentan.

COMO MIDE. Con el unico principal humano que hoy tiene un `UpdateItem` acotado
en la cuenta: el permission set `AgenteIAM-Aprobador` (lista `id`, `estado`,
`tiene_aprobacion`, `aprobacion`, `rechazo`; `infra/cfn/identidades.yaml`),
como `aprobador.demo`. Siete llamadas sobre una fila propia de la sonda,
`sonda-atributos-<AAAAMMDD>`, nunca sobre una solicitud:

    leer                       GetItem                                  permitido
    estado                     UpdateItem SET estado                    permitido (crea la fila)
    aprobacion                 UpdateItem SET aprobacion                permitido
    documento                  UpdateItem SET documento                 denegado
    putitem                    PutItem                                  denegado
    condicion                  SET aprobacion IF attribute_not_exists(documento)   la medicion
    returnvalues               SET aprobacion con ReturnValues ALL_NEW  denegado

Una denegacion es `AccessDeniedException`; un `ConditionalCheckFailedException`
quiere decir que IAM dejo pasar y fallo la condicion, y nunca cuenta como
"cumple". Se guarda el mensaje de cada denegacion: "explicit deny" frente a "no
identity-based policy allows" dice que capa paro la llamada.

LO QUE DEJA EN LA TABLA. La fila de la sonda, con `estado = sonda` y un
`aprobacion` de prueba, sin `documento`: `almacen.leer` la rechaza como
inconsistente, y ningun proceso la toma por una solicitud. El aprobador no
puede borrarla (no tiene `DeleteItem`); la borra el administrador si se quiere.
Nunca pone `estado = aprobada`.

DESDE ADR-003 (24-10-2026). El permission set del aprobador ya no escribe la
tabla: perdio `UpdateItem` y lleva un Deny explicito de toda escritura (la
decision la escribe la Lambda `agente-iam-aprobacion` con su propio rol, que
ninguna persona asume). Con `--solo-lectura` las mismas siete llamadas esperan
`leer` permitido y las seis escrituras denegadas, tambien la de la condicion, y
cada fila anota la capa que denego: `explicita` ("explicit deny", el Deny del
permission set gana) o `implicita` ("no identity-based policy allows", solo
falta el Allow). La medicion original de `dynamodb:Attributes` (F.6) ya no se
puede repetir con una persona.

SALIDA. Tabla en consola y `evidencias/sonda-atributos/<fecha UTC>/resultado.json`
(`evidencias/` esta en .gitignore). Codigo de salida: 0 todo cumple; 3 algun caso
no cumple; 1 error de corrida (credenciales caducadas, perfil que no existe).
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

RAIZ = Path(__file__).resolve().parent.parent
REGION = "us-east-1"
TABLA = "agente-iam-solicitudes"
PREFIJO = "sonda-atributos-"
DENEGACION = "AccessDeniedException"
CONDICION_FALLIDA = "ConditionalCheckFailedException"

_CUENTA = re.compile(r"(?<!\d)(\d{8})(\d{4})(?!\d)")


def enmascarar(valor: Any) -> Any:
    """Las cuentas de 12 digitos quedan en sus 4 ultimos, en toda la estructura."""
    if isinstance(valor, str):
        return _CUENTA.sub(lambda m: "*" * 8 + m.group(2), valor)
    if isinstance(valor, dict):
        return {k: enmascarar(v) for k, v in valor.items()}
    if isinstance(valor, list):
        return [enmascarar(v) for v in valor]
    return valor


@dataclass
class Caso:
    nombre: str
    operacion: str  # metodo del cliente de boto3
    params: dict
    esperado: str | None  # permitido | denegado | None (el resultado es la medicion)


def clave_de_hoy() -> str:
    return PREFIJO + datetime.now(timezone.utc).strftime("%Y%m%d")


def casos(clave: str, solo_lectura: bool = False) -> list[Caso]:
    fila = {"id": {"S": clave}}
    prueba = {"S": json.dumps({"sonda": "atributos", "no es": "una aprobacion"})}

    def update(expresion: str, valores: dict, **extra) -> dict:
        return {"TableName": TABLA, "Key": fila, "UpdateExpression": expresion,
                "ExpressionAttributeValues": valores, **extra}

    lista = [
        Caso("leer", "get_item", {"TableName": TABLA, "Key": fila, "ConsistentRead": True}, "permitido"),
        Caso("estado", "update_item", update("SET estado = :e", {":e": {"S": "sonda"}}), "permitido"),
        Caso("aprobacion", "update_item", update("SET aprobacion = :a", {":a": prueba}), "permitido"),
        Caso("documento", "update_item", update("SET documento = :d", {":d": {"S": "{}"}}), "denegado"),
        Caso("putitem", "put_item", {"TableName": TABLA, "Item": {**fila, "estado": {"S": "sonda"}}}, "denegado"),
        Caso("aprobacion con documento en la condicion", "update_item",
             update("SET aprobacion = :a", {":a": prueba}, ConditionExpression="attribute_not_exists(documento)"), None),
        Caso("aprobacion con ReturnValues ALL_NEW", "update_item",
             update("SET aprobacion = :a", {":a": prueba}, ReturnValues="ALL_NEW"), "denegado"),
    ]
    if solo_lectura:
        # ADR-003: ninguna escritura del aprobador, ni la que solo condiciona.
        for caso in lista[1:]:
            caso.esperado = "denegado"
    return lista


def veredicto(caso: Caso, codigo: str | None) -> str:
    if codigo == CONDICION_FALLIDA:
        return "condicion_fallida"
    if codigo is not None and codigo != DENEGACION:
        return f"error:{codigo}"
    denegado = codigo == DENEGACION
    if caso.esperado is None:
        return "denegado" if denegado else "permitido"
    return "cumple" if (caso.esperado == "denegado") == denegado else "no_cumple"


def capa(codigo: str | None, mensaje: str) -> str | None:
    """Que capa denego, leido del mensaje de IAM: `explicita` si un Deny gano,
    `implicita` si solo falto el Allow; None si no hubo denegacion o no se lee."""
    if codigo != DENEGACION:
        return None
    if "explicit deny" in mensaje:
        return "explicita"
    if "no identity-based policy allows" in mensaje:
        return "implicita"
    return "desconocida"


def ejecutar(cliente: Any, lista: list[Caso]) -> list[dict]:
    filas = []
    for caso in lista:
        codigo, mensaje = None, ""
        try:
            getattr(cliente, caso.operacion)(**caso.params)
        except ClientError as e:
            codigo, mensaje = e.response["Error"]["Code"], e.response["Error"].get("Message", "")
        filas.append({"caso": caso.nombre, "esperado": caso.esperado, "veredicto": veredicto(caso, codigo),
                      "codigo": codigo, "capa": capa(codigo, mensaje), "mensaje": mensaje})
    return filas


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ejecutar", action="store_true", help="correr de verdad (escribe la fila de la sonda)")
    ap.add_argument("--perfil", default="", help="perfil del permission set AgenteIAM-Aprobador")
    ap.add_argument("--solo-lectura", action="store_true",
                    help="ADR-003: el aprobador solo lee; se espera cada escritura denegada")
    args = ap.parse_args(argv)
    if args.ejecutar and not args.perfil:
        ap.error("--ejecutar necesita --perfil (el del aprobador)")

    clave = clave_de_hoy()
    lista = casos(clave, solo_lectura=args.solo_lectura)
    print(f"{len(lista)} llamadas sobre {TABLA}, fila {clave}, region {REGION}"
          + (" (solo lectura, ADR-003)" if args.solo_lectura else ""))
    for c in lista:
        print(f"  {c.nombre:<42} {c.operacion:<12} esperado {c.esperado or 'la medicion'}")
    if not args.ejecutar:
        print("\nSolo el plan. Para correrlo: --ejecutar --perfil <perfil del aprobador>")
        return 0

    # boto3 se importa aqui y no arriba: sin --ejecutar el script no lo toca.
    import boto3

    try:
        sesion = boto3.Session(profile_name=args.perfil, region_name=REGION)
        quien = sesion.client("sts").get_caller_identity()["Arn"]
        filas = ejecutar(sesion.client("dynamodb"), lista)
    except (ClientError, BotoCoreError) as e:
        print(f"\nerror de corrida: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    print(f"\ncomo: {enmascarar(quien)}")
    for f in filas:
        print(f"  {f['caso']:<42} {f['veredicto']:<18} {f['codigo'] or '-':<24} {f['capa'] or ''}")
    fecha = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    carpeta = RAIZ / "evidencias" / "sonda-atributos" / fecha
    carpeta.mkdir(parents=True)
    (carpeta / "resultado.json").write_text(
        json.dumps(enmascarar({"fecha_utc": fecha, "perfil": args.perfil, "solo_lectura": args.solo_lectura, "como": quien,
                               "clave": clave, "filas": filas}),
                   ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"\n{carpeta / 'resultado.json'}")
    if any(f["veredicto"].startswith("error:") for f in filas):
        return 1
    return 3 if any(f["veredicto"] in ("no_cumple", "condicion_fallida") for f in filas) else 0


if __name__ == "__main__":
    sys.exit(main())
