"""Cliente del solicitante: saca su token de Cognito y manda una solicitud al runtime.

    ./.venv/bin/python scripts/solicitar.py token --usuario ana          # inicio de sesion y token
    ./.venv/bin/python scripts/solicitar.py enviar solicitud.json --usuario ana
    ./.venv/bin/python scripts/solicitar.py asumir <rol_arn> --usuario ana [--horas 4] [--listar bucket]

POR QUE EXISTE. El runtime de AgentCore autoriza con JWT (Cognito), no con
IAM. La CLI y el SDK de AWS firman con SigV4, asi que con JWT no se pueden
usar para invocar: hace falta una peticion HTTPS con
`Authorization: Bearer <token>`. Este script es esa peticion, mas el
inicio de sesion que da el token. Es un script y no un modulo de
`agente_iam/` (D7): es una herramienta de quien solicita, no logica del
agente.

  - `token`: PKCE contra la pila `agente-iam-acceso` (salidas `UrlDominio` y
    `ClienteId`), codigo recibido en localhost:8080, token guardado en
    `local/tokens/<usuario>.json` con permisos 600. Solo imprime los claims
    visibles, NUNCA el token. Se niega a guardar un token cuyo `sub` ya es
    de otra persona (el navegador reutilizo una sesion): otra persona entra
    en una ventana privada nueva, con todas las demas cerradas.
  - `enviar`: POST del fichero JSON al runtime de la pila `agente-iam-runtime`
    (salida `RuntimeArn`). El script solo comprueba que el fichero sea un
    objeto JSON; la forma de la solicitud la valida el servidor. Imprime el
    resultado, el estado, donde se guardo, quien solicito, el `solicitud_id`
    y el `rol_previsto`, todo escapado con `models.imprimible` (S7), y nunca
    el token, ni aunque un error lo repita. Si el fichero no trae
    `clave_envio`, el script pone un UUID nuevo y lo imprime: con
    `--clave <uuid>` se repite el mismo envio y el servidor responde con el
    mismo id en vez de abrir otra solicitud (idempotencia del reintento).
  - `asumir <rol_arn>`: canjea el `id_token` guardado por credenciales del
    rol que se creo para la persona (`AssumeRoleWithWebIdentity`, sin firmar:
    quien llama no tiene credenciales de AWS, solo su token). Escribe las
    credenciales en `local/credenciales/<usuario>-<rol>.json` con permisos 600
    e imprime SOLO la ruta y `Expiration`, nunca las claves. Con `--listar
    <bucket>` hace un `ListObjectsV2` de prueba de vida.

DOS TOKENS, DOS USOS, nunca cruzados. El `access_token` es el que viaja al
runtime (`enviar`); el `id_token` es el UNICO que vale para
`AssumeRoleWithWebIdentity`, porque es el que lleva `aud` (el de acceso
falla con `Missing a required claim: aud`, docs/MEDICIONES.md N.2, fila 2).

POR QUE `asumir` RECIBE EL ARN Y NO EL `solicitud_id`. Con el id el script
tendria que leer la tabla para saber el rol, y la persona no puede leerla
(ni debe). El ARN lo imprime `enviar` (`rol_previsto`) y lo trae el correo
de `aplicada`; es el rol que se creara para su `sub`, y si el `sub` no es el
suyo, STS responde `AccessDenied` (N.2, fila 3).

Codigos de salida de `enviar`: 0 solicitud procesada; 2 fichero que no es un
objeto JSON, `--clave` que no es un UUID, `forma_invalida` o
`registro_existente` (lo corrige quien solicita); 1 todo lo demas (401, 403,
424, red, token ausente).

Codigos de salida de `asumir`: 0 credenciales guardadas (y listado, si se
pidio); 2 argumentos malos (`--horas` fuera de 1 a 12, ARN que no es de un
rol); 1 todo lo demas (sin `id_token`, `AccessDenied`, token caducado, red).

Reutiliza de `scripts/prueba_b.py` el PKCE, el canje, el servidor de un solo
uso y el guardado del token.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from agente_iam import personas
from agente_iam.models import imprimible


def _cargar_prueba_b() -> Any:
    ruta = Path(__file__).resolve().parent / "prueba_b.py"
    spec = importlib.util.spec_from_file_location("prueba_b", ruta)
    if spec is None or spec.loader is None:
        raise ImportError(f"no se puede cargar {ruta}")
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


_pb = _cargar_prueba_b()
pkce = _pb.pkce
url_autorizacion = _pb.url_autorizacion
claims = _pb.claims
visibles = _pb.visibles
guardar_token = _pb.guardar_token
_esperar_codigo = _pb._esperar_codigo
RETORNO = _pb.RETORNO

LOCAL_TOKENS = RAIZ / "local" / "tokens"
LOCAL_CREDENCIALES = RAIZ / "local" / "credenciales"
PILA_ACCESO = "agente-iam-acceso"
PILA_RUNTIME = "agente-iam-runtime"
REGION = "us-east-1"
TIMEOUT = 180  # una corrida con tres intentos pasa del minuto
_USUARIO = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
# Ni "." ni ".." como segmento: el nombre del rol da nombre a un fichero local.
_ROL_ARN = re.compile(
    r"^arn:aws:iam::[0-9]{12}:role/((?!\.{1,2}/)[A-Za-z0-9+=,.@_-]+/)*(?!\.{1,2}$)([A-Za-z0-9+=,.@_-]{1,64})$")
HORAS_MIN, HORAS_MAX = 1, 12


# --- Piezas puras (las prueba tests/unitarios/test_solicitar.py) ------------


def id_de_sesion() -> str:
    """Id de sesion de AgentCore: minimo 33 caracteres, distinto cada vez."""
    return f"solicitud-{uuid.uuid4()}-{uuid.uuid4()}"


def sub_de_otro(dir_tokens: Path, usuario: str, sub: str) -> str | None:
    """El otro usuario si su token guardado tiene este mismo `sub`.

    Como `prueba_b.sub_repetido`, pero con nombres libres: recorre todos los
    ficheros de `local/tokens/` menos el del propio usuario."""
    if not dir_tokens.is_dir():
        return None
    for ruta in sorted(dir_tokens.glob("*.json")):
        if ruta.stem == usuario:
            continue
        try:
            otro_sub = claims(json.loads(ruta.read_text())["access_token"]).get("sub")
        except (ValueError, KeyError, IndexError, OSError):
            continue
        if otro_sub == sub:
            return ruta.stem
    return None


def _seguro(texto: object, token: str | None = None, limite: int | None = None) -> str:
    """Texto listo para la terminal: sin el token y sin caracteres de control.

    Primero se quita el token y despues se recorta: al reves, un token que
    cruza el limite dejaria su comienzo a la vista."""
    s = str(texto)
    if token:
        s = s.replace(token, "(token omitido)")
    if limite is not None:
        s = s[:limite]
    return imprimible(s)


class _SinRedirecciones(urllib.request.HTTPRedirectHandler):
    """No sigue ninguna redireccion: un 3xx es un error, no un destino nuevo.

    `urlopen` a secas repite la peticion contra la `Location` que diga quien
    contesta, y con ella la cabecera `Authorization: Bearer`. El runtime no
    redirige nunca: si lo hace, algo va mal y el token no debe ir detras
    (mismo endurecimiento que `agente_iam/aprobar_cliente.py`).
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _abrir(peticion: urllib.request.Request, timeout: int) -> Any:
    """Abre la peticion sin seguir redirecciones. Un solo punto de salida a la
    red: los tests lo sustituyen."""
    abridor = urllib.request.build_opener(_SinRedirecciones)
    # Endpoint https fijo (AgentCore o el dominio de Cognito de la pila), no una entrada.
    return abridor.open(peticion, timeout=timeout)  # nosec B310


def _falla(mensaje: str) -> int:
    """Mensaje a stderr y codigo de salida 1 (sin SystemExit: se puede probar)."""
    print(mensaje, file=sys.stderr)
    return 1


def url_runtime(arn: str) -> str:
    return (f"https://bedrock-agentcore.{REGION}.amazonaws.com/runtimes/"
            f"{urllib.parse.quote(arn, safe='')}/invocations?qualifier=DEFAULT")


# --- Con red ------------------------------------------------------------------


def _salidas(perfil: str, pila: str) -> dict[str, str]:
    import boto3

    cf = boto3.Session(profile_name=perfil, region_name=REGION).client("cloudformation")
    return {o["OutputKey"]: o["OutputValue"] for o in cf.describe_stacks(StackName=pila)["Stacks"][0]["Outputs"]}


def cmd_token(args: argparse.Namespace) -> int:
    s = _salidas(args.perfil, PILA_ACCESO)
    dominio, cliente = s["UrlDominio"], s["ClienteId"]
    verifier, challenge = pkce()
    state = secrets.token_urlsafe(24)
    print(f"Abre este enlace en una ventana PRIVADA NUEVA (otra persona = otra ventana privada, con las demas cerradas) "
          f"y entra como '{_seguro(args.usuario)}' (con su MFA):\n")
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
    with _abrir(peticion, 20) as r:
        respuesta = json.load(r)
    token = respuesta["access_token"]
    otro = sub_de_otro(LOCAL_TOKENS, args.usuario, claims(token).get("sub", ""))
    if otro:
        return _falla(f"Este token es del mismo usuario que {otro}.json: el navegador reutilizo una sesion. "
                      "No se guarda. Cierra TODAS las ventanas privadas y repite en una nueva.")
    ruta = LOCAL_TOKENS / f"{args.usuario}.json"
    guardar_token(ruta, token, respuesta.get("id_token"))
    print(f"\nToken guardado en {ruta.relative_to(RAIZ) if ruta.is_relative_to(RAIZ) else ruta} (permisos 600; no se imprime).")
    print("Claims:", json.dumps(visibles(claims(token)), ensure_ascii=False, indent=1))
    return 0


def _leer_solicitud(ruta: str) -> dict[str, Any] | None:
    """El objeto JSON del fichero; si no es un objeto legible, None."""
    try:
        datos = json.loads(Path(ruta).read_bytes())
    except (OSError, ValueError):
        return None
    return datos if isinstance(datos, dict) else None


def _es_uuid(texto: str) -> bool:
    try:
        return str(uuid.UUID(texto)) == texto.lower()
    except ValueError:
        return False


def cmd_enviar(args: argparse.Namespace) -> int:
    solicitud = _leer_solicitud(args.fichero)
    if solicitud is None:
        print(f"{_seguro(args.fichero)} no es un objeto JSON legible: no se envia nada.", file=sys.stderr)
        return 2
    if args.clave is not None and not _es_uuid(args.clave):
        print("--clave debe ser un UUID (el que imprimio el envio anterior).", file=sys.stderr)
        return 2
    # La clave de envio identifica ESTE envio: el servidor deriva de ella el
    # solicitud_id, asi que repetirla reintenta sin abrir otra solicitud.
    if args.clave is not None:
        solicitud["clave_envio"] = args.clave
    elif "clave_envio" not in solicitud:
        solicitud["clave_envio"] = str(uuid.uuid4())
    cuerpo = json.dumps(solicitud).encode()
    ruta = LOCAL_TOKENS / f"{args.usuario}.json"
    if not ruta.exists():
        return _falla(f"No hay token de '{_seguro(args.usuario)}': corre antes `token --usuario {_seguro(args.usuario)}`.")
    token = json.loads(ruta.read_text())["access_token"]
    otro = sub_de_otro(LOCAL_TOKENS, args.usuario, claims(token).get("sub", ""))
    if otro:
        return _falla(f"{ruta.name} es del mismo usuario que {otro}.json: repite `token --usuario {_seguro(args.usuario)}`.")
    print(f"clave_envio: {_seguro(solicitud['clave_envio'], token, 64)} "
          "(repite con --clave para reintentar sin abrir otra solicitud)")
    arn = _salidas(args.perfil, PILA_RUNTIME)["RuntimeArn"]
    cabeceras = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": id_de_sesion(),
    }
    peticion = urllib.request.Request(url_runtime(arn), data=cuerpo, headers=cabeceras)
    try:
        with _abrir(peticion, TIMEOUT) as r:
            texto, http = r.read().decode(errors="replace"), r.status
    except urllib.error.HTTPError as e:
        texto, http = e.read().decode(errors="replace"), e.code
    except (urllib.error.URLError, OSError) as e:
        print(f"Error de red: {_seguro(e, token)}", file=sys.stderr)
        return 1
    print(f"HTTP {http}")
    if 300 <= http < 400:
        print("El runtime contesto con una redireccion; no se sigue (el token no sale hacia otro destino).", file=sys.stderr)
        return 1
    try:
        resp = json.loads(texto)
    except ValueError:
        resp = None
    if not isinstance(resp, dict):
        print(f"Respuesta: {_seguro(texto, token, 500)}")
        return 1
    if resp.get("resultado") == "error":
        print(f"resultado: error\ncodigo: {_seguro(resp.get('codigo'), token)}\ndetalle: {_seguro(resp.get('detalle'), token)}")
        return 2 if http == 200 and resp.get("codigo") in ("forma_invalida", "registro_existente") else 1
    if "resultado" not in resp:  # p. ej. {"message": ...} de un 401 o 403
        print(f"mensaje: {_seguro(resp.get('message', texto), token, 500)}")
        return 1
    registro = resp.get("registro") if isinstance(resp.get("registro"), dict) else {}
    print(f"resultado: {_seguro(resp['resultado'], token)}")
    print(f"estado: {_seguro(registro.get('estado'), token)}")
    print(f"guardado_en: {_seguro(resp.get('guardado_en'), token)}")
    print(f"solicitante: {_seguro(registro.get('solicitante'), token)}")
    for campo in ("solicitud_id", "rol_previsto"):
        if campo in resp:
            print(f"{campo}: {_seguro(resp[campo], token)}")
    if registro.get("horas") is not None:
        print(f"horas: {_seguro(registro['horas'], token)}")
    return 0 if http == 200 and resp["resultado"] == "procesada" else 1


# --- asumir: el canje del id_token por credenciales del rol ---------------------


def _sts() -> Any:
    """Cliente de STS SIN credenciales: `AssumeRoleWithWebIdentity` no se firma
    (quien llama solo tiene su token). Un solo punto de creacion: los tests lo
    sustituyen."""
    import boto3
    import botocore
    from botocore.config import Config

    return boto3.client("sts", region_name=REGION, config=Config(signature_version=botocore.UNSIGNED))


def _s3(credenciales: dict[str, Any]) -> Any:
    """Cliente de S3 con las credenciales del rol asumido (los tests lo sustituyen)."""
    import boto3

    # Las tres claves van como mapa y no como argumentos con nombre: el detector
    # de secretos del repositorio (tests/seguridad/test_secretos.py) toma
    # `aws_secret_access_key=<algo largo>` por un secreto asignado.
    claves = {
        "aws_access_key_id": credenciales["AccessKeyId"],
        "aws_secret_access_key": credenciales["SecretAccessKey"],
        "aws_session_token": credenciales["SessionToken"],
    }
    return boto3.client("s3", region_name=REGION, **claves)


def _asumir(sts: Any, rol_arn: str, token: str, sesion: str, segundos: int) -> dict[str, Any]:
    """Canjea el token de identidad por las credenciales temporales del rol."""
    respuesta = sts.assume_role_with_web_identity(
        RoleArn=rol_arn,
        RoleSessionName=sesion,
        WebIdentityToken=token,
        DurationSeconds=segundos,
    )
    return respuesta["Credentials"]


def _guardar_credenciales(ruta: Path, credenciales: dict[str, Any]) -> None:
    """Credenciales en un fichero nuevo con permisos 600 desde el principio y
    carpeta 700. `Expiration` llega como datetime de boto3: se guarda en
    ISO 8601."""
    ruta.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    expira = credenciales["Expiration"]
    contenido = {
        "AccessKeyId": credenciales["AccessKeyId"],
        "SecretAccessKey": credenciales["SecretAccessKey"],
        "SessionToken": credenciales["SessionToken"],
        "Expiration": expira.isoformat() if hasattr(expira, "isoformat") else str(expira),
    }
    if ruta.exists():
        ruta.unlink()
    fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(contenido, f)


def _mensaje_de_error(e: Exception, *secretos: str | None) -> str:
    """Texto del error de AWS sin ningun secreto y sin caracteres de control."""
    texto = str(e)
    for secreto in secretos:
        if secreto:
            texto = texto.replace(secreto, "(omitido)")
    return _seguro(texto, None, 300)


# STS rechaza (ValidationError, o AccessDenied segun el caso) una sesion mas larga
# que el MaxSessionDuration del rol, que la Lambda fija con las horas pedidas.
_TOPE_HORAS = "y --horas no puede superar las horas que pediste en la solicitud (MaxSessionDuration del rol)"


def cmd_asumir(args: argparse.Namespace) -> int:
    from botocore.exceptions import BotoCoreError, ClientError

    ruta = LOCAL_TOKENS / f"{args.usuario}.json"
    falta_id = "vuelve a entrar con `token`: hace falta el token de identidad"
    try:
        guardado = json.loads(ruta.read_text())
    except (OSError, ValueError):
        return _falla(f"No hay token de '{_seguro(args.usuario)}': {falta_id}.")
    token = guardado.get("id_token") if isinstance(guardado, dict) else None
    if not isinstance(token, str) or not token:
        return _falla(f"{ruta.name} no trae id_token: {falta_id}.")
    try:
        sub = claims(token).get("sub", "")
    except (ValueError, IndexError):
        return _falla(f"El id_token de {ruta.name} no se puede leer: {falta_id}.")
    otro = sub_de_otro(LOCAL_TOKENS, args.usuario, sub)
    if otro:
        return _falla(f"{ruta.name} es del mismo usuario que {otro}.json: repite `token --usuario {_seguro(args.usuario)}`.")
    sesion = ("agente-iam-" + personas.normalizar_usuario(args.usuario))[:64]
    try:
        credenciales = _asumir(_sts(), args.rol_arn, token, sesion, args.horas * 3600)
    except ClientError as e:
        codigo = e.response.get("Error", {}).get("Code", "")
        print(f"STS rechazo el canje: {_seguro(codigo, token)}: {_mensaje_de_error(e, token)}", file=sys.stderr)
        if codigo == "AccessDenied":
            print("Si el rol se acaba de crear, espera unos segundos y repite (IAM tarda en propagar). "
                  "Si sigue, el rol no es tuyo o ya vencio, " + _TOPE_HORAS + ".", file=sys.stderr)
        elif codigo == "ValidationError":
            print("STS no acepto los datos del canje: " + _TOPE_HORAS + ".", file=sys.stderr)
        elif codigo in ("ExpiredTokenException", "InvalidIdentityToken"):
            print("El token de identidad caduco: vuelve a entrar con `token`.", file=sys.stderr)
        return 1
    except (BotoCoreError, OSError) as e:
        print(f"Error de red: {_mensaje_de_error(e, token)}", file=sys.stderr)
        return 1
    nombre = _ROL_ARN.fullmatch(args.rol_arn).group(2)  # type: ignore[union-attr]  # ya validado en main
    destino = LOCAL_CREDENCIALES / f"{args.usuario}-{nombre}.json"
    _guardar_credenciales(destino, credenciales)
    print(f"Credenciales guardadas en {destino.relative_to(RAIZ) if destino.is_relative_to(RAIZ) else destino} "
          "(permisos 600; no se imprimen).")
    expira = credenciales["Expiration"]
    print(f"Expiration: {_seguro(expira.isoformat() if hasattr(expira, 'isoformat') else expira)}")
    if args.listar:
        secretos = (credenciales["SecretAccessKey"], credenciales["SessionToken"], token)
        try:
            r = _s3(credenciales).list_objects_v2(Bucket=args.listar, MaxKeys=5)
        except (ClientError, BotoCoreError, OSError) as e:
            print(f"No se pudo listar {_seguro(args.listar)}: {_mensaje_de_error(e, *secretos)}", file=sys.stderr)
            return 1
        print(f"objetos listados: {len(r.get('Contents', []))} (KeyCount {_seguro(r.get('KeyCount'))})")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--perfil", default="org-agente-iam")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("token", help="inicio de sesion y token (otra persona = ventana privada nueva)")
    t.add_argument("--usuario", required=True, help="nombre de quien entra; da nombre al fichero local/tokens/<usuario>.json")
    e = sub.add_parser("enviar", help="manda un fichero JSON de solicitud al runtime")
    e.add_argument("fichero", help="solicitud en JSON (un objeto)")
    e.add_argument("--usuario", required=True, help="de quien es el token guardado con `token`")
    e.add_argument("--clave", help="clave_envio (UUID) de un envio anterior, para reintentarlo sin abrir otra solicitud")
    a = sub.add_parser("asumir", help="canjea el id_token por credenciales del rol que se creo para ti")
    a.add_argument("rol_arn", help="ARN del rol (lo imprime `enviar` como rol_previsto)")
    a.add_argument("--usuario", required=True, help="de quien es el token guardado con `token`")
    a.add_argument("--horas", type=int, default=1, help="vida de la sesion, de 1 a 12 (por defecto 1)")
    a.add_argument("--listar", metavar="BUCKET", help="prueba de vida: lista hasta 5 objetos del bucket con las credenciales")
    args = ap.parse_args(argv)
    if not _USUARIO.fullmatch(args.usuario):
        print("--usuario debe ser un nombre simple: letras, numeros, punto, guion y guion bajo (1 a 64).", file=sys.stderr)
        return 2
    if args.cmd == "asumir":
        if not HORAS_MIN <= args.horas <= HORAS_MAX:
            print(f"--horas debe ser un entero de {HORAS_MIN} a {HORAS_MAX}.", file=sys.stderr)
            return 2
        if not _ROL_ARN.fullmatch(args.rol_arn):
            print("rol_arn debe ser el ARN de un rol de IAM (arn:aws:iam::<cuenta>:role/...).", file=sys.stderr)
            return 2
    return {"token": cmd_token, "enviar": cmd_enviar, "asumir": cmd_asumir}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
