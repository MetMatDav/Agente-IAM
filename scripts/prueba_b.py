"""Prueba B de AgentCore: token de Cognito, invocaciones y CloudTrail.

    ./.venv/bin/python scripts/prueba_b.py token --usuario mateo       # B.5: inicio de sesion y token
    ./.venv/bin/python scripts/prueba_b.py invocar --usuario mateo     # B.7: tres invocaciones
    ./.venv/bin/python scripts/prueba_b.py cloudtrail                  # B.8 y B.9: que quedo registrado

POR QUE EXISTE (Fase 15, 23-10-2026). La pila `infra/cfn/prueba-eco.yaml`
ya esta desplegada; faltan los pasos de `docs/PRUEBAS-AGENTCORE.md` que
necesitan un humano: entrar en Identity Center con MFA y sacar un token.
La guia lo hacia con comandos sueltos que dejaban el token en la shell y
el codigo de autorizacion en la barra de direcciones. Este script:

  - `token`: genera PKCE (verifier y challenge S256), imprime el enlace,
    recibe el codigo en un servidor de un solo uso en localhost:8080 (con
    comprobacion de `state`), lo canjea y guarda el token de acceso en
    `local/prueba-eco/token-<usuario>.json` con permisos 600. Solo imprime
    los claims, NUNCA el token. Lo corre Mateo: el inicio de sesion es suyo.
  - `invocar`: las tres invocaciones de B.7 (con token, sin token y con la
    firma alterada) contra el runtime eco, y guarda la respuesta en
    `evidencias/prueba-b/<fecha>/` (fuera de git).
  - `cloudtrail`: los `AssumeRole` del rol del eco (quien lo asumio, nombre
    de sesion, sourceIdentity) y los eventos de datos `InvokeAgentRuntime`
    del trail temporal (que `userIdentity` traen).

Usa los perfiles SSO (`--perfil`, por defecto org-agente-iam) y las salidas
de la pila; no hay que copiar ids a mano.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import http.server
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

RAIZ = Path(__file__).resolve().parent.parent
LOCAL = RAIZ / "local" / "prueba-eco"
EVIDENCIA = RAIZ / "evidencias" / "prueba-b"
PILA = "agente-iam-prueba-eco"
REGION = "us-east-1"
PUERTO = 8080
RETORNO = f"http://localhost:{PUERTO}/callback"
ROL_ECO = "AgenteIAM-PruebaEco-Runtime"
CLAIMS_VISIBLES = ("iss", "client_id", "token_use", "username", "sub", "scope", "auth_time", "exp")
_CUENTA = re.compile(r"\b(\d{8})(\d{4})\b")


# --- Piezas puras (las prueba tests/unitarios/test_prueba_b.py) -------------


def pkce() -> tuple[str, str]:
    """(verifier, challenge) segun RFC 7636, metodo S256."""
    verifier = secrets.token_urlsafe(64)
    return verifier, challenge_de(verifier)


def challenge_de(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


def url_autorizacion(dominio: str, cliente: str, challenge: str, state: str) -> str:
    """Enlace de inicio de sesion. `identity_provider=IdentityCenter` manda
    directo a Identity Center, sin pasar por la pantalla de Cognito."""
    params = {
        "response_type": "code",
        "client_id": cliente,
        "redirect_uri": RETORNO,
        "scope": "openid email",
        "identity_provider": "IdentityCenter",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    return f"{dominio}/oauth2/authorize?{urllib.parse.urlencode(params)}"


def claims(token: str) -> dict[str, Any]:
    """La carga de un JWT, sin comprobar la firma (eso lo hace AgentCore)."""
    carga = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(carga + "=" * (-len(carga) % 4)))


def visibles(c: dict[str, Any]) -> dict[str, Any]:
    return {k: c.get(k) for k in CLAIMS_VISIBLES}


def alterar_firma(token: str) -> str:
    """Cambia el PRIMER caracter de la firma. El ultimo no sirve: en
    base64url sus bits finales pueden ser relleno y la firma decodificada
    quedaria igual."""
    cuerpo, firma = token.rsplit(".", 1)
    return f"{cuerpo}.{'B' if firma[0] != 'B' else 'C'}{firma[1:]}"


def sub_repetido(dir_tokens: Path, usuario: str, sub: str) -> str | None:
    """El otro usuario si su token guardado tiene este mismo `sub`. Pasa
    si el navegador reutiliza la sesion de Identity Center o de Cognito:
    el enlace no pide usuario y entra quien ya estaba (23-10-2026, el
    primer token "del aprobador" era de Mateo)."""
    for otro in ("mateo", "aprobador"):
        ruta = dir_tokens / f"token-{otro}.json"
        if otro != usuario and ruta.exists():
            if claims(json.loads(ruta.read_text())["access_token"]).get("sub") == sub:
                return otro
    return None


def assume_roles_del_eco(cloudtrail: Any, desde: datetime) -> list[dict[str, Any]]:
    """Los `AssumeRole` del rol del eco, recorriendo TODAS las paginas. Una
    sola llamada trae como mucho 50, y en una cuenta con Control Tower 50
    `AssumeRole` son unos minutos: los del eco quedarian fuera."""
    encontrados = []
    paginas = cloudtrail.get_paginator("lookup_events").paginate(
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "AssumeRole"}], StartTime=desde)
    for pagina in paginas:
        for e in pagina["Events"]:
            d = json.loads(e["CloudTrailEvent"])
            if ROL_ECO in str((d.get("requestParameters") or {}).get("roleArn", "")):
                encontrados.append(d)
    return encontrados


def es_registro_de_eventos(clave: str) -> bool:
    """Solo `AWSLogs/<cuenta>/CloudTrail/...json.gz` trae `Records`. Con la
    validacion de integridad activa, el trail tambien escribe
    `CloudTrail-Digest/...json.gz` cada hora, sin eventos (medido el
    23-10-2026: el script reventaba con KeyError 'Records')."""
    return "/CloudTrail/" in clave and clave.endswith(".json.gz")


def enmascarar(texto: str) -> str:
    return _CUENTA.sub(lambda m: "********" + m.group(2), texto)


def guardar_token(ruta: Path, token: str, id_token: str | None = None) -> None:
    """Fichero nuevo con permisos 600 desde el principio (no se crea abierto
    y se cierra despues). Desde el 26-10-2026 guarda tambien el token de
    identidad si Cognito lo devolvio: `AssumeRoleWithWebIdentity` exige un
    token con `aud`, y el de acceso no lo lleva (Fase 23, MEDICIONES N)."""
    ruta.parent.mkdir(parents=True, exist_ok=True)
    if ruta.exists():
        ruta.unlink()
    fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        contenido = {"access_token": token, "obtenido_utc": datetime.now(timezone.utc).isoformat()}
        if id_token:
            contenido["id_token"] = id_token
        json.dump(contenido, f)


# --- Con red ------------------------------------------------------------------


def _salidas(perfil: str) -> dict[str, str]:
    import boto3

    cf = boto3.Session(profile_name=perfil, region_name=REGION).client("cloudformation")
    return {o["OutputKey"]: o["OutputValue"] for o in cf.describe_stacks(StackName=PILA)["Stacks"][0]["Outputs"]}


def _esperar_codigo(state: str, segundos: int = 300) -> str:
    """Servidor de un solo uso en 127.0.0.1: recibe /callback, comprueba el
    state y devuelve el codigo. No queda nada escuchando despues."""
    recibido: dict[str, str] = {}

    class Manejador(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # nombre que exige http.server
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            ok = q.get("state", [""])[0] == state and "code" in q
            if ok:
                recibido["code"] = q["code"][0]
            elif "error" in q:
                recibido["error"] = q.get("error_description", q["error"])[0]
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(("Listo, ya puedes cerrar esta ventana." if ok else "State o codigo incorrecto.").encode())

        def log_message(self, *args: Any) -> None:  # sin el codigo en la consola
            pass

    servidor = http.server.HTTPServer(("127.0.0.1", PUERTO), Manejador)
    servidor.timeout = 1
    limite = datetime.now() + timedelta(seconds=segundos)
    while not recibido and datetime.now() < limite:
        servidor.handle_request()
    servidor.server_close()
    if "error" in recibido:
        sys.exit(f"Identity Center o Cognito devolvieron un error: {recibido['error']}")
    if "code" not in recibido:
        sys.exit("No llego ningun codigo en 5 minutos.")
    return recibido["code"]


def cmd_token(args: argparse.Namespace) -> int:
    s = _salidas(args.perfil)
    dominio, cliente = s["UrlDominio"], s["ClienteId"]
    verifier, challenge = pkce()
    state = secrets.token_urlsafe(24)
    print(f"Abre este enlace en una ventana PRIVADA y entra como '{args.usuario}' (con su MFA):\n")
    print(url_autorizacion(dominio, cliente, challenge, state))
    print(f"\nEsperando el retorno en {RETORNO} (5 minutos)...")
    codigo = _esperar_codigo(state)
    datos = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "client_id": cliente,
        "code": codigo,
        "redirect_uri": RETORNO,
        "code_verifier": verifier,
    }).encode()
    peticion = urllib.request.Request(f"{dominio}/oauth2/token", data=datos,
                                      headers={"Content-Type": "application/x-www-form-urlencoded"})
    # La URL es https y sale de las salidas de la pila, no de una entrada.
    with urllib.request.urlopen(peticion, timeout=20) as r:  # nosec B310
        respuesta = json.load(r)
    token = respuesta["access_token"]
    otro = sub_repetido(LOCAL, args.usuario, claims(token).get("sub", ""))
    if otro:
        sys.exit(f"Este token es del mismo usuario que token-{otro}.json: el navegador reutilizo una sesion. "
                 "No se guarda. Cierra TODAS las ventanas privadas y repite en una nueva.")
    ruta = LOCAL / f"token-{args.usuario}.json"
    guardar_token(ruta, token, respuesta.get("id_token"))
    print(f"\nToken guardado en {ruta.relative_to(RAIZ)} (permisos 600; no se imprime).")
    print("Claims:", json.dumps(visibles(claims(token)), ensure_ascii=False, indent=1))
    return 0


def _invocar(url: str, sesion: str, token: str | None) -> tuple[int, Any]:
    cabeceras = {"Content-Type": "application/json", "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": sesion}
    if token:
        cabeceras["Authorization"] = f"Bearer {token}"
    peticion = urllib.request.Request(url, data=json.dumps({"prompt": "hola"}).encode(), headers=cabeceras)
    try:
        # Endpoint https fijo de AgentCore con el ARN de la pila.
        with urllib.request.urlopen(peticion, timeout=60) as r:  # nosec B310
            cuerpo = r.read().decode()
            codigo = r.status
    except urllib.error.HTTPError as e:
        cuerpo, codigo = e.read().decode(errors="replace"), e.code
    try:
        return codigo, json.loads(cuerpo)
    except json.JSONDecodeError:
        return codigo, cuerpo[:500]


def cmd_invocar(args: argparse.Namespace) -> int:
    ruta = LOCAL / f"token-{args.usuario}.json"
    if not ruta.exists():
        sys.exit(f"No hay token de '{args.usuario}': corre antes `token --usuario {args.usuario}`.")
    token = json.loads(ruta.read_text())["access_token"]
    otro = sub_repetido(LOCAL, args.usuario, claims(token).get("sub", ""))
    if otro:
        sys.exit(f"token-{args.usuario}.json es del mismo usuario que token-{otro}.json: repite `token --usuario {args.usuario}`.")
    arn = _salidas(args.perfil)["RuntimeArn"]
    url = (f"https://bedrock-agentcore.{REGION}.amazonaws.com/runtimes/"
           f"{urllib.parse.quote(arn, safe='')}/invocations?qualifier=DEFAULT")
    sesion = uuid.uuid4().hex * 2  # minimo 33 caracteres
    resultados = {}
    for nombre, t in [("con_token", token), ("sin_token", None), ("firma_alterada", alterar_firma(token))]:
        codigo, cuerpo = _invocar(url, sesion, t)
        texto = json.dumps(cuerpo, ensure_ascii=False)
        if token in texto:  # el eco nunca debe devolver el token (test_agente_eco.py)
            texto, cuerpo = "(respuesta omitida: contenia el token)", None
        resultados[nombre] = {"http": codigo, "respuesta": json.loads(enmascarar(json.dumps(cuerpo, ensure_ascii=False)))}
        print(f"{nombre:15} HTTP {codigo}  {enmascarar(texto)[:400]}")
    destino = EVIDENCIA / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destino.mkdir(parents=True, exist_ok=True)
    (destino / f"invocar-{args.usuario}.json").write_text(json.dumps(resultados, ensure_ascii=False, indent=1))
    print(f"\nEvidencia en {destino.relative_to(RAIZ)}/invocar-{args.usuario}.json")
    ok = resultados["con_token"]["http"] == 200 and all(resultados[n]["http"] >= 400 for n in ("sin_token", "firma_alterada"))
    print("Resultado:", "como se esperaba" if ok else "NO es lo esperado: revisalo antes de seguir")
    return 0 if ok else 3


def cmd_cloudtrail(args: argparse.Namespace) -> int:
    import boto3

    s = boto3.Session(profile_name=args.perfil, region_name=REGION)
    desde = datetime.now(timezone.utc) - timedelta(hours=args.horas)
    print(f"== AssumeRole de {ROL_ECO} (historial de eventos, ultimas {args.horas} h)")
    for d in assume_roles_del_eco(s.client("cloudtrail"), desde):
        rp = d.get("requestParameters") or {}
        quien = d["userIdentity"].get("invokedBy") or d["userIdentity"].get("type")
        print(enmascarar(f"  {d['eventTime']}  por {quien}  sesion={rp.get('roleSessionName')}  sourceIdentity={rp.get('sourceIdentity')}"))
    print("\n== InvokeAgentRuntime en el trail de datos")
    bucket = next(r["PhysicalResourceId"] for r in s.client("cloudformation").describe_stack_resources(StackName=PILA)["StackResources"]
                  if r["LogicalResourceId"] == "BucketTrail")
    s3 = s.client("s3")
    claves = [o["Key"] for p in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="AWSLogs/")
              for o in p.get("Contents", []) if o["LastModified"] >= desde and es_registro_de_eventos(o["Key"])]
    vistos = 0
    for clave in claves:
        for d in json.loads(gzip.decompress(s3.get_object(Bucket=bucket, Key=clave)["Body"].read()))["Records"]:
            if d.get("eventName") != "InvokeAgentRuntime":
                continue
            vistos += 1
            print(enmascarar(f"  {d['eventTime']}  error={d.get('errorCode')}  userIdentity={json.dumps(d.get('userIdentity'), ensure_ascii=False)}"))
    if not vistos:
        print("  (ninguno todavia: el trail entrega cada pocos minutos)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--perfil", default="org-agente-iam")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("token", help="B.5: inicio de sesion y token (lo corre Mateo)")
    t.add_argument("--usuario", required=True, choices=["mateo", "aprobador"])
    i = sub.add_parser("invocar", help="B.7: tres invocaciones al eco")
    i.add_argument("--usuario", required=True, choices=["mateo", "aprobador"])
    c = sub.add_parser("cloudtrail", help="B.8 y B.9: que quedo en CloudTrail")
    c.add_argument("--horas", type=int, default=3)
    args = ap.parse_args(argv)
    return {"token": cmd_token, "invocar": cmd_invocar, "cloudtrail": cmd_cloudtrail}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
