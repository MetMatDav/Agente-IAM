"""Agente eco para las pruebas A y B de AgentCore (Fase 10a).

    entryPoint: ["agente_eco.py"]

NO es el agente IAM. No llama al modelo ni lee IAM: solo contesta que le
llego, para poder mirar desde fuera dos cosas sin desplegar el sistema
entero:

  1. Que claims del token llegan al contenedor, una vez que el autorizador
     JWT de AgentCore ya lo valido (firma, emisor, caducidad, cliente).
  2. Con que identidad AWS corre el contenedor: el ARN de la sesion del
     rol de ejecucion, que es lo que despues aparece en CloudTrail.

EL TOKEN SE DECODIFICA SIN VERIFICAR, y aqui es correcto: la verificacion
la hizo AgentCore antes de dejar pasar la peticion. Este codigo solo lee
la carga para ensenarla. Copiar este patron a un servicio que NO tenga
delante un autorizador seria un agujero: cualquiera podria fabricar los
claims que quisiera.

NUNCA DEVUELVE NI REGISTRA EL TOKEN, solo una lista cerrada de claims. Un
token en un log es una credencial en un log.

Solo usa la biblioteca estandar y boto3 (Python puro), asi que el zip se
construye igual en x86 que en ARM64. Cumple el contrato HTTP de AgentCore
Runtime: escucha en 0.0.0.0:8080, `POST /invocations` y `GET /ping`.
`PUERTO` existe solo para que el test lo arranque en un puerto libre.
"""

import base64
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PUERTO = int(os.getenv("PUERTO", "8080"))

# Lista cerrada: lo que sirve para decidir las pruebas y nada mas.
CLAIMS_VISIBLES = (
    "iss", "sub", "aud", "client_id", "username", "token_use", "scope",
    "email", "cognito:groups", "exp", "iat",
)


def claims_sin_verificar(cabecera: str | None) -> dict | None:
    """La carga del JWT de `Authorization: Bearer ...`, filtrada.

    None si no hay cabecera Bearer. Si el token no tiene forma de JWT (tres
    partes separadas por puntos) lo dice en `_formato` en vez de fallar:
    en la Prueba A, que no lo sea ES el resultado.
    """
    if not cabecera or not cabecera.lower().startswith("bearer "):
        return None
    partes = cabecera.split(" ", 1)[1].strip().split(".")
    if len(partes) != 3:
        return {"_formato": f"no es un JWT: {len(partes)} partes"}
    carga = partes[1] + "=" * (-len(partes[1]) % 4)
    try:
        datos = json.loads(base64.urlsafe_b64decode(carga))
    except (ValueError, UnicodeDecodeError):
        return {"_formato": "la carga no es JSON en base64url"}
    if not isinstance(datos, dict):
        return {"_formato": "la carga no es un objeto JSON"}
    return {k: datos[k] for k in CLAIMS_VISIBLES if k in datos}


def identidad_aws() -> dict:
    """El ARN con el que corre el contenedor (sts:GetCallerIdentity).

    No necesita permisos en la politica del rol. Si falla (sin credenciales,
    en local) se devuelve el tipo de error, no se revienta: la prueba
    tambien tiene que poder leer lo demas.
    """
    try:
        import boto3

        r = boto3.client("sts").get_caller_identity()
        return {"Arn": r["Arn"], "Account": r["Account"]}
    except Exception as e:  # se informa, no se oculta
        return {"error": type(e).__name__}


class Manejador(BaseHTTPRequestHandler):
    def _responder(self, codigo: int, cuerpo: dict) -> None:
        datos = json.dumps(cuerpo, ensure_ascii=False).encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(datos)))
        self.end_headers()
        self.wfile.write(datos)

    def do_GET(self) -> None:  # nombre impuesto por http.server
        if self.path == "/ping":
            self._responder(200, {"status": "Healthy", "time_of_last_update": int(time.time())})
        else:
            self._responder(404, {"error": "no existe"})

    def do_POST(self) -> None:
        if self.path != "/invocations":
            self._responder(404, {"error": "no existe"})
            return
        largo = int(self.headers.get("Content-Length") or 0)
        cuerpo = self.rfile.read(largo) if largo else b""
        try:
            payload = json.loads(cuerpo) if cuerpo else None
        except ValueError:
            payload = None
        claims = claims_sin_verificar(self.headers.get("Authorization"))
        respuesta = {
            "agente": "eco",
            "payload_recibido": payload,
            "cabecera_authorization_presente": self.headers.get("Authorization") is not None,
            "claims": claims,
            "sesion_runtime": self.headers.get("X-Amzn-Bedrock-AgentCore-Runtime-Session-Id"),
            "identidad_aws": identidad_aws(),
        }
        # Una linea por invocacion en CloudWatch Logs, sin el token.
        quien = (claims or {}).get("username") or (claims or {}).get("sub")
        print(json.dumps({"invocacion": True, "usuario": quien}), flush=True)
        self._responder(200, respuesta)


def main() -> None:
    ThreadingHTTPServer(("0.0.0.0", PUERTO), Manejador).serve_forever()


if __name__ == "__main__":
    main()
