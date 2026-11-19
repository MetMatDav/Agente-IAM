"""Matriz de pruebas reales de la denegacion de regiones (Fase 15, opcion B).

    ./.venv/bin/python scripts/matriz_regiones.py                  # solo muestra el plan
    ./.venv/bin/python scripts/matriz_regiones.py --ejecutar       # lo corre contra la cuenta
    ./.venv/bin/python scripts/matriz_regiones.py --modelo us.anthropic.claude-haiku-5-5 --ejecutar

POR QUE EXISTE (23-10-2026). La opcion B de la Fase 15 descansa en dos
afirmaciones sobre las SCP que ningun test unitario puede comprobar, porque
son comportamiento de AWS y no de nuestro codigo: (1) la denegacion de
regiones de Control Tower exime `bedrock:InvokeModel` e
`InvokeModelWithResponseStream` en la OU Workloads, y (2) una SCP propia solo
deja invocar Bedrock fuera de us-east-1 cuando la llamada viene por un perfil
`us.` de Claude creado en us-east-1. Esta matriz las mide con llamadas
reales y se puede repetir: cuando Haiku 5.5 tenga cuota, el caso 12 pasa de
"falla por cuota" a "responde" y sigue pasando, porque lo que vigila es que
NO lo pare una SCP.

QUE MIDE. Cada caso es una llamada (perfil, region del cliente, API) con un
resultado esperado. Se clasifica en OK (respuesta), DENY_SCP (AccessDenied
cuyo mensaje nombra una "service control policy"), DENY_OTRO (AccessDenied
sin SCP: falta un permiso IAM, no un control de la organizacion) o ERROR
(cualquier otra cosa: cuota, modelo sin acceso, red). Esa distincion es el
punto: un `DENY_OTRO` donde se esperaba `DENY_SCP` no demuestra que la SCP
funcione. El esperado `NO_DENY_SCP` vale cualquier resultado salvo una SCP.

LO QUE NO TOCA. Solo llamadas de lectura o de coste minimo (maxTokens 5, o 1
en Nova), en secuencia. No crea nada en la cuenta. Las cuentas de 12 digitos
se enmascaran (quedan los 4 ultimos) en consola y en el JSON, y nunca se
imprimen credenciales: solo el nombre del perfil.

SALIDA. Tabla en consola y `evidencias/matriz-regiones/<fecha UTC>/resultado.json`
(`evidencias/` esta en .gitignore: lleva ARNs de la cuenta, aunque
enmascarados). Codigo de salida: 0 todos pasan; 3 algun caso no pasa
(convencion del proyecto: un control no respondio como se esperaba); 1 error
de corrida (perfil que no existe, credenciales caducadas: la matriz no vale).
"""

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    CredentialRetrievalError,
    NoCredentialsError,
    PartialCredentialsError,
    ProfileNotFound,
    SSOTokenLoadError,
    TokenRetrievalError,
    UnauthorizedSSOTokenError,
)

RAIZ = Path(__file__).resolve().parent.parent
MODELO_POR_DEFECTO = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
MODELO_SONNET = "us.anthropic.claude-sonnet-4-6"
MODELO_GLOBAL = "global.anthropic.claude-haiku-4-5-20251001-v1:0"
MODELO_HAIKU_5_5 = "us.anthropic.claude-haiku-5-5"
MODELO_NOVA = "amazon.nova-lite-v1:0"
REGION_BASE = "us-east-1"
REGION_FUERA = "us-west-2"
TEXTO = "Responde solo: ok"
CUERPO_NOVA = {"messages": [{"role": "user", "content": [{"text": "ok"}]}], "inferenceConfig": {"maxTokens": 1}}

OK, DENY_SCP, DENY_OTRO, ERROR = "OK", "DENY_SCP", "DENY_OTRO", "ERROR"
NO_DENY_SCP = "NO_DENY_SCP"  # solo como esperado: cualquier clase menos DENY_SCP

# Sin ellas la matriz entera no vale (no es que el control responda raro,
# es que nadie llego a preguntarle): son error de corrida, no caso fallido.
ERRORES_DE_CREDENCIALES = (
    NoCredentialsError, PartialCredentialsError, CredentialRetrievalError,
    TokenRetrievalError, SSOTokenLoadError, UnauthorizedSSOTokenError,
)
# EC2 no usa AccessDenied: devuelve UnauthorizedOperation.
CODIGOS_DENEGACION = ("AccessDenied", "UnauthorizedOperation")

_CUENTA = re.compile(r"(?<!\d)(\d{8})(\d{4})(?!\d)")
_POLITICA = re.compile(r"(?<![\w-])p-[0-9a-z]{8,}\b")
_RECURSO = re.compile(r"on resource:\s*(\S+)")


# --- Clasificacion: funciones puras, probadas sin red -----------------------

def enmascarar(valor: Any) -> Any:
    """Cambia los 8 primeros digitos de todo numero de cuenta de 12 por `*`.

    Recorre cadenas, listas y diccionarios (claves incluidas), porque lo que
    se enmascara es el JSON entero y no solo el campo que hoy se sabe que
    lleva una cuenta.
    """
    if isinstance(valor, str):
        return _CUENTA.sub(lambda m: "*" * 8 + m.group(2), valor)
    if isinstance(valor, list):
        return [enmascarar(v) for v in valor]
    if isinstance(valor, dict):
        return {enmascarar(k): enmascarar(v) for k, v in valor.items()}
    return valor


def clasificar(error: BaseException | None = None) -> dict:
    """Clase de una llamada: sin excepcion es OK; con ella, segun su mensaje.

    Recibe la excepcion (o None si hubo respuesta) y no la llamada, para
    poder probarla con un `ClientError` fabricado. La politica y el recurso
    solo se extraen de una denegacion de SCP: es lo que la tabla necesita
    para saber QUE SCP paro la llamada.
    """
    vacio = {"clase": OK, "politica": None, "recurso": None, "detalle": None, "aviso_marketplace": False}
    if error is None:
        return vacio
    if isinstance(error, ClientError):
        codigo = error.response.get("Error", {}).get("Code", "")
        mensaje = error.response.get("Error", {}).get("Message", "") or str(error)
        tipo = codigo
    else:
        codigo, mensaje, tipo = "", str(error), type(error).__name__
    resultado = {**vacio, "detalle": f"{tipo}: {mensaje}", "aviso_marketplace": "marketplace" in mensaje.lower()}
    if isinstance(error, ClientError) and any(c in codigo for c in CODIGOS_DENEGACION):
        if "service control policy" in mensaje.lower():
            politica, recurso = _POLITICA.search(mensaje), _RECURSO.search(mensaje)
            return {
                **resultado, "clase": DENY_SCP,
                "politica": politica.group(0) if politica else None,
                "recurso": recurso.group(1) if recurso else None,
            }
        return {**resultado, "clase": DENY_OTRO}
    return {**resultado, "clase": ERROR}


def pasa(esperado: str, obtenido: str) -> bool:
    """`NO_DENY_SCP` pasa con cualquier clase salvo `DENY_SCP`; el resto, igualdad."""
    if esperado == NO_DENY_SCP:
        return obtenido != DENY_SCP
    return esperado == obtenido


# --- Llamadas: reciben un cliente ya creado y no clasifican nada ------------

def _converse(cliente: Any, modelo: str) -> None:
    cliente.converse(
        modelId=modelo,
        messages=[{"role": "user", "content": [{"text": TEXTO}]}],
        inferenceConfig={"maxTokens": 5},
    )


def _converse_stream(cliente: Any, modelo: str) -> None:
    respuesta = cliente.converse_stream(
        modelId=modelo,
        messages=[{"role": "user", "content": [{"text": TEXTO}]}],
        inferenceConfig={"maxTokens": 5},
    )
    # Un stream puede abrirse bien y fallar a mitad: se consume entero.
    for _ in respuesta["stream"]:
        pass


def _invoke_nova(cliente: Any, modelo: str) -> None:
    respuesta = cliente.invoke_model(
        modelId=modelo, body=json.dumps(CUERPO_NOVA),
        contentType="application/json", accept="application/json",
    )
    respuesta["body"].read()


def _describe_vpcs(cliente: Any, _: str) -> None:
    cliente.describe_vpcs()


def _list_roles(cliente: Any, _: str) -> None:
    cliente.list_roles(MaxItems=1)


def _get_caller_identity(cliente: Any, _: str) -> None:
    cliente.get_caller_identity()


@dataclass(frozen=True)
class Llamada:
    servicio: str
    nombre: str
    funcion: Callable[[Any, str], None]
    modelo: str = ""


@dataclass(frozen=True)
class Caso:
    id: int
    descripcion: str
    perfil: str  # "agente", "gestion" o "audit": se resuelve con los --perfil-*
    region: str
    llamadas: tuple[Llamada, ...]
    esperado: str
    notas: list[str] = field(default_factory=list, compare=False)


def _bedrock(nombre: str, funcion: Callable[[Any, str], None], modelo: str) -> Llamada:
    return Llamada("bedrock-runtime", nombre, funcion, modelo)


def construir_casos(modelo: str) -> list[Caso]:
    """Los 12 casos de la matriz; `modelo` es el caso principal (1, 2 y 5)."""
    return [
        Caso(1, f"Converse {modelo}", "agente", REGION_BASE, (_bedrock("Converse", _converse, modelo),), OK),
        Caso(2, f"ConverseStream {modelo}", "agente", REGION_BASE, (_bedrock("ConverseStream", _converse_stream, modelo),), OK),
        Caso(3, f"Converse {MODELO_SONNET}", "agente", REGION_BASE, (_bedrock("Converse", _converse, MODELO_SONNET),), OK),
        Caso(4, f"Converse {MODELO_GLOBAL} (perfil global.)", "agente", REGION_BASE, (_bedrock("Converse", _converse, MODELO_GLOBAL),), DENY_SCP),
        Caso(5, f"Converse {modelo} con el cliente en {REGION_FUERA}", "agente", REGION_FUERA, (_bedrock("Converse", _converse, modelo),), DENY_SCP),
        Caso(6, f"InvokeModel {MODELO_NOVA}", "agente", REGION_BASE, (_bedrock("InvokeModel", _invoke_nova, MODELO_NOVA),), OK),
        Caso(7, f"InvokeModel {MODELO_NOVA} en {REGION_FUERA}", "agente", REGION_FUERA, (_bedrock("InvokeModel", _invoke_nova, MODELO_NOVA),), DENY_SCP),
        Caso(8, f"ec2 DescribeVpcs en {REGION_FUERA}", "agente", REGION_FUERA, (Llamada("ec2", "DescribeVpcs", _describe_vpcs),), DENY_SCP),
        Caso(9, "iam ListRoles y sts GetCallerIdentity", "agente", REGION_BASE,
             (Llamada("iam", "ListRoles", _list_roles), Llamada("sts", "GetCallerIdentity", _get_caller_identity)), OK),
        Caso(10, f"Converse {MODELO_GLOBAL} desde la cuenta de gestion", "gestion", REGION_BASE, (_bedrock("Converse", _converse, MODELO_GLOBAL),), OK,
             ["las SCP no aplican a la cuenta de gestion"]),
        Caso(11, f"ec2 DescribeVpcs en {REGION_FUERA} desde audit", "audit", REGION_FUERA, (Llamada("ec2", "DescribeVpcs", _describe_vpcs),), DENY_SCP),
        Caso(12, f"Converse {MODELO_HAIKU_5_5}", "agente", REGION_BASE, (_bedrock("Converse", _converse, MODELO_HAIKU_5_5),), NO_DENY_SCP,
             ["hoy la cuota es 0 y fallara por cuota o acceso; con cuota sera OK"]),
    ]


# --- Ejecucion --------------------------------------------------------------

def ejecutar_caso(caso: Caso, crear_cliente: Callable[[str, str, str], Any]) -> dict:
    """Corre las llamadas del caso en orden; manda la primera que no sea OK.

    `crear_cliente(perfil, servicio, region)` se inyecta para que la prueba
    de esta funcion no necesite boto3. Si una llamada falla, las siguientes
    del mismo caso no se hacen: la primera ya dice lo que hay que saber.
    """
    inicio = time.monotonic()
    pasos = []
    final = clasificar(None)
    de_corrida = False
    for ll in caso.llamadas:
        try:
            cliente = crear_cliente(caso.perfil, ll.servicio, caso.region)
            ll.funcion(cliente, ll.modelo)
            error = None
        except ERRORES_DE_CREDENCIALES as e:
            error, de_corrida = e, True
        except (ClientError, BotoCoreError, OSError, ValueError) as e:
            error = e
        paso = clasificar(error)
        pasos.append({"llamada": f"{ll.servicio}:{ll.nombre}", "modelo": ll.modelo or None, **paso})
        if paso["clase"] != OK:
            final = paso
            break
    return {
        "id": caso.id,
        "caso": caso.descripcion,
        "perfil": caso.perfil,
        "region": caso.region,
        "esperado": caso.esperado,
        "obtenido": final["clase"],
        "pasa": pasa(caso.esperado, final["clase"]),
        "politica": final["politica"],
        "recurso": final["recurso"],
        "detalle": final["detalle"],
        "aviso_marketplace": any(p["aviso_marketplace"] for p in pasos),
        "pasos": pasos,
        "notas": caso.notas,
        "credenciales": de_corrida,
        "ms": round((time.monotonic() - inicio) * 1000),
    }


def tabla(resultados: list[dict]) -> str:
    cabecera = ["id", "caso", "esperado", "obtenido", "pasa", "politica", "recurso"]
    filas = [
        [str(r["id"]), r["caso"], r["esperado"], r["obtenido"], "si" if r["pasa"] else "NO", r["politica"] or "-", r["recurso"] or "-"]
        for r in resultados
    ]
    # El recurso es un ARN largo: se corta para que la tabla quepa en consola.
    filas = [f[:6] + [f[6] if len(f[6]) <= 60 else f[6][:57] + "..."] for f in filas]
    anchos = [max(len(x[i]) for x in [cabecera, *filas]) for i in range(len(cabecera))]
    lineas = ["  ".join(c.ljust(a) for c, a in zip(f, anchos, strict=True)).rstrip() for f in [cabecera, *filas]]
    lineas.insert(1, "  ".join("-" * a for a in anchos))
    return "\n".join(lineas)


def mostrar_plan(casos: list[Caso], perfiles: dict[str, str], modelo: str) -> None:
    print(f"{len(casos)} casos en secuencia; modelo principal: {modelo}")
    print("  perfiles: " + ", ".join(f"{k}={v}" for k, v in perfiles.items()))
    print(f"  regiones: {', '.join(sorted({c.region for c in casos}))}")
    for c in casos:
        print(f"  {c.id:>2}  {c.descripcion}  [{perfiles[c.perfil]}, {c.region}]  esperado {c.esperado}")
    print("  salida: evidencias/matriz-regiones/<fecha UTC>/resultado.json")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ejecutar", action="store_true", help="correr de verdad (llama a AWS)")
    ap.add_argument("--modelo", default=MODELO_POR_DEFECTO, help="modelo del caso principal (casos 1, 2 y 5)")
    ap.add_argument("--perfil-agente", default="org-agente-iam")
    ap.add_argument("--perfil-gestion", default="org-gestion")
    ap.add_argument("--perfil-audit", default="org-audit-lectura")
    args = ap.parse_args(argv)

    perfiles = {"agente": args.perfil_agente, "gestion": args.perfil_gestion, "audit": args.perfil_audit}
    casos = construir_casos(args.modelo)
    mostrar_plan(casos, perfiles, args.modelo)
    if not args.ejecutar:
        print("\nSolo el plan. Para correrlo: --ejecutar")
        return 0

    # boto3 se importa aqui y no arriba: sin --ejecutar el script no lo toca.
    import boto3
    from botocore.config import Config

    sesiones: dict[str, Any] = {}
    try:
        # Crear la sesion solo lee la configuracion local: no llama a AWS,
        # pero ya delata un perfil mal escrito antes de gastar nada.
        for clave, nombre in perfiles.items():
            sesiones[clave] = boto3.Session(profile_name=nombre)
    except ProfileNotFound as e:
        print(f"\nerror de corrida: {e}", file=sys.stderr)
        return 1

    config = Config(retries={"max_attempts": 3, "mode": "standard"}, read_timeout=60)

    def crear_cliente(perfil: str, servicio: str, region: str) -> Any:
        return sesiones[perfil].client(servicio, region_name=region, config=config)

    resultados = []
    for caso in casos:
        r = ejecutar_caso(caso, crear_cliente)
        resultados.append(r)
        print(f"  caso {r['id']:>2}: {r['obtenido']} ({'pasa' if r['pasa'] else 'NO PASA'})", flush=True)

    fecha = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    carpeta = RAIZ / "evidencias" / "matriz-regiones" / fecha
    carpeta.mkdir(parents=True)
    informe = enmascarar({
        "fecha_utc": fecha,
        "modelo": args.modelo,
        "perfiles": perfiles,
        "pasan": sum(1 for r in resultados if r["pasa"]),
        "total": len(resultados),
        "resultados": resultados,
    })
    (carpeta / "resultado.json").write_text(json.dumps(informe, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n" + enmascarar(tabla(resultados)))
    for r in enmascarar(resultados):
        if r["aviso_marketplace"]:
            print(f"\naviso caso {r['id']}: el error menciona Marketplace (no es de SCP): {r['detalle']}")
    print(f"\n{informe['pasan']}/{informe['total']} casos pasan. Evidencia en {carpeta.relative_to(RAIZ)}/resultado.json")

    if any(r["credenciales"] for r in resultados):
        print("error de corrida: credenciales ausentes o caducadas; la matriz no vale (aws sso login)", file=sys.stderr)
        return 1
    return 0 if informe["pasan"] == informe["total"] else 3


if __name__ == "__main__":
    sys.exit(main())
