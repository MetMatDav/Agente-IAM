"""Aprobacion humana de una solicitud ya propuesta: el lado de la persona.

    python -m agente_iam.aprobar_cliente <id>                        muestra y da la huella
    python -m agente_iam.aprobar_cliente <id> --huella sha256:...    aprueba ESO
    python -m agente_iam.aprobar_cliente <id> --huella ... --autoaprobacion-demo
    python -m agente_iam.aprobar_cliente <id> --rechazar "motivo"

Este comando YA NO DECIDE (ADR-003, A2). Lee la solicitud, pinta la propuesta
con su huella y manda la peticion, firmada con SigV4 con las credenciales de
quien lo corre, a la URL de la Lambda de aprobacion (`agente_iam.aprobar`). Es
la Lambda quien saca de la firma QUIEN aprueba, aplica los controles y escribe
la decision; el cliente no tiene permiso de escritura sobre la tabla ni elige
su identidad. Lo unico que viaja es el id, la accion y lo que la persona
confirma (`models.PeticionAprobacion`).

CORRELO CON TUS CREDENCIALES DE HUMANO (el permission set del aprobador), no
con `AWS_PROFILE=agente-iam`: aprobar es un acto humano, y la persona que
queda grabada es la que dice la firma.

LA HUELLA ATA LO QUE SE LEYO CON LO QUE SE FIRMA. La primera corrida pinta la
propuesta y su huella y sale sin enviar nada; la segunda manda esa huella, y el
servidor solo aprueba si es la del registro que lee en ese momento. `--rechazar`
va sin huella: el servidor la calcula sobre lo que rechaza.

Con `ALMACEN=disco` (desarrollo) no hay servidor: el comando decide aqui con
tus credenciales, importando `aprobar` solo en esa rama, y lo dice. No tiene la
garantia de ADR-003. En `dynamodb` el cliente nunca llama a
`almacen.guardar_decision` ni a `aprobar.decidir`: solo `almacen.leer` y la URL.

Codigos de salida: 0 aprobada o rechazada, 1 error, 3 bloqueada por un
control (que no es un fallo: es el sistema haciendo su trabajo).
"""

import hashlib
import http.client
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import BotoCoreError
from pydantic import ValidationError

from agente_iam import almacen, huella, personas
from agente_iam.coherencia import riesgo_minimo
from agente_iam.config import ALMACEN, AWS_REGION, URL_APROBACION
from agente_iam.models import PeticionAprobacion, imprimible

# Lo que se pinta lo escribieron otros (solicitante y modelo) o llega por la
# red desde la Lambda: se escapa todo lo no imprimible antes de que llegue a
# la terminal (S7).
_t = imprimible

_TIMEOUT_SEGUNDOS = 90
# La Lambda tarda lo que tarda Access Analyzer; una respuesta de decision cabe
# de sobra en un mega.
_MAX_RESPUESTA = 1 << 20

_SIN_SERVIDOR = (
    "AVISO: ALMACEN=disco, sin servidor. Decido AQUI con tus credenciales, sin la Lambda "
    "de aprobacion y sin la garantia de ADR-003 (que quien firma lo identifique el servidor)."
)


# --- Enviar ------------------------------------------------------------------


class _SinRedirecciones(urllib.request.HTTPRedirectHandler):
    """No sigue ninguna redireccion: un 3xx es un error, no un destino nuevo.

    El comportamiento por defecto de urllib ante un 307/308 es repetir el POST,
    con sus cabeceras (la firma y el token de sesion) y el cuerpo, contra la
    `Location` que diga quien contesta. La URL de la Lambda no redirige nunca:
    si lo hace, algo va mal y las credenciales no deben ir detras.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def enviar(url: str, peticion: PeticionAprobacion) -> tuple[int, dict]:
    """Manda la peticion firmada a la URL de la Lambda; devuelve (codigo, cuerpo).

    El cuerpo es siempre un dict, venga de la Lambda o no, para que quien llama
    no tenga que adivinar. Codigo 0 es "no hubo respuesta" (`sin_respuesta`: la
    decision pudo escribirse igualmente) o "ni se envio" (`sin_credenciales`,
    `url_no_valida`). Un 403 de la URL es `sin_permiso`: IAM lo contesta antes
    de que la Lambda se entere (falta de permiso, credenciales caducadas o un
    problema de firma). Una redireccion (3xx) es `redireccion` y no se sigue.
    """
    if urllib.parse.urlsplit(url).scheme != "https":
        # La firma no es secreta, pero no se manda una peticion de aprobacion
        # por un canal en claro ni a un esquema que urllib sabe abrir (file:).
        return 0, {"resultado": "url_no_valida", "detalle": "la URL de aprobacion tiene que ser https"}

    cuerpo = peticion.model_dump_json().encode()
    try:
        credenciales = boto3.Session().get_credentials()
        if credenciales is None:
            return 0, {"resultado": "sin_credenciales", "detalle": "no hay credenciales de AWS con las que firmar"}
        credenciales = credenciales.get_frozen_credentials()
    except BotoCoreError as e:
        # Un token de SSO caducado cae aqui: hay que volver a entrar.
        return 0, {"resultado": "sin_credenciales", "detalle": f"{type(e).__name__}: {e}"}

    # Lo firmado es el pedido de botocore; lo enviado es el de urllib con las
    # cabeceras que dejo la firma. El cuerpo es el mismo array de bytes.
    # x-amz-content-sha256 va ANTES de firmar, asi viaja y queda firmada.
    # Medido el 25-10-2026 UTC (docs/MEDICIONES.md F.7, M1b): la URL de funcion
    # con AWS_IAM NO la exige en POST (la misma peticion sin ella da el mismo
    # 409). Se deja porque es inocua y, firmada, ata el cuerpo a la firma por
    # segunda vez; la SigV4Auth generica de botocore solo mete la huella en la
    # peticion canonica (la cabecera la anade solo S3SigV4Auth).
    firmado = AWSRequest(
        method="POST",
        url=url,
        data=cuerpo,
        headers={"content-type": "application/json", "x-amz-content-sha256": hashlib.sha256(cuerpo).hexdigest()},
    )
    SigV4Auth(credenciales, "lambda", AWS_REGION).add_auth(firmado)
    pedido = urllib.request.Request(url, data=cuerpo, headers=dict(firmado.headers), method="POST")

    # Sin `urlopen` a secas: ese sigue redirecciones y repetiria la firma contra
    # otro destino (`_SinRedirecciones`).
    abridor = urllib.request.build_opener(_SinRedirecciones)
    try:
        with abridor.open(pedido, timeout=_TIMEOUT_SEGUNDOS) as respuesta:
            codigo, datos = respuesta.status, respuesta.read(_MAX_RESPUESTA)
    except urllib.error.HTTPError as e:
        codigo, datos = e.code, e.read(_MAX_RESPUESTA)
        if 300 <= codigo < 400:
            return codigo, {
                "resultado": "redireccion",
                "detalle": f"la URL de aprobacion contesto con una redireccion (codigo {codigo}); no se sigue",
            }
        if codigo == 403:
            return 403, {"resultado": "sin_permiso", "detalle": datos.decode("utf-8", "replace")[:500]}
    except (OSError, http.client.HTTPException) as e:
        # URLError, timeouts y cortes de conexion. No sabemos si la Lambda llego a decidir.
        return 0, {"resultado": "sin_respuesta", "detalle": f"{type(e).__name__}: {e}"}

    texto = datos.decode("utf-8", "replace")
    try:
        cuerpo_json = json.loads(texto)
    except ValueError:
        cuerpo_json = None
    if isinstance(cuerpo_json, dict):
        return codigo, cuerpo_json
    if codigo < 400:
        return codigo, {"resultado": "respuesta_ilegible", "detalle": texto[:500]}
    return codigo, {"resultado": f"http_{codigo}", "detalle": texto[:500]}


# --- Pintar ------------------------------------------------------------------


def _mostrar_rol_por_persona(ident: dict, sol: dict) -> None:
    """Las cuatro lineas del modo rol por persona (Fase 23).

    Aqui el beneficiario no existe aun: es el rol que el aplicador creara para
    la persona del token, con confianza solo para su `sub` y vida de `horas`.
    El aprobador tiene que ver quien es, cuanto dura y a donde llega el aviso;
    el vencimiento es el de aprobar y aplicar ahora (el real cuenta desde que
    se aplica). Todo se escapa con `_t`: la persona, el correo y las horas
    viajan en un registro que no se da por confiable.
    """
    persona = ident.get("persona") or {}
    horas = ident.get("horas")
    try:
        vence = personas.vence_desde(datetime.now(timezone.utc), horas)  # type: ignore[arg-type]
    except ValueError:
        vence = "(horas invalidas: no se puede calcular)"
    print(f"Beneficiario: rol por persona {_t(ident.get('principal_arn'))} (se crea al aplicar)")
    print(f"Persona: {_t(persona.get('usuario'))} (sub {_t(persona.get('sub'))})")
    print(f"Horas: {_t(horas)}; venceria el {_t(vence)} si se aplicara ahora")
    print(f"Correo de aviso: {_t(sol.get('correo_aviso'))}")


def _mostrar_propuesta(registro: dict) -> None:
    """Lo que el aprobador tiene que haber visto para que su firma valga."""
    p = registro.get("propuesta") or {}
    ident = registro.get("identidad_verificada") or {}
    sol = registro.get("solicitud") or {}
    campos = sol.get("campos") or {}
    print("\n" + "=" * 70)
    print(f"REVISION de {_t(registro.get('id'))}  (estado: {_t(registro.get('estado'))})")
    print("=" * 70)
    if ident.get("modo") == "rol_por_persona":
        _mostrar_rol_por_persona(ident, sol)
    else:
        print(f"Beneficiario: {_t(ident.get('principal_arn'))}  [{_t(ident.get('principal_id'))}]")
    print(
        f"Pedido: {_t(campos.get('servicio'))}/{_t(campos.get('recurso'))} ({_t(campos.get('region'))}); "
        f"nivel entendido por el modelo: {_t(p.get('nivel_entendido') or campos.get('tipo_acceso'))}; "
        f"concede, segun el codigo: {_t(registro.get('nivel_real') or 'no determinado')}"
    )
    print(f"Justificacion del solicitante (dato no confiable): {_t(sol.get('justificacion'))}")
    print(f"Riesgo segun el modelo: {_t(p.get('nivel_riesgo'))}")
    for m in riesgo_minimo(
        sol, ident.get("principal_arn", ""), registro.get("historial_validacion") or [], registro.get("nivel_real")
    ):
        print(f"  riesgo ALTO fijado por el codigo: {_t(m)}")
    for s in p.get("supuestos", []):
        print(f"  supuesto: {_t(s)}")
    print("\nDocumento que se concederia:")
    # ensure_ascii: json.dumps ya escapa los de control, pero no DEL, C1 ni
    # los de formato como U+202E; en ASCII no queda ninguno.
    print(json.dumps(p.get("policy_document"), indent=2, ensure_ascii=True))
    delta = registro.get("acceso_nuevo") or {}
    if delta:
        print(f"\nAcceso nuevo: {_t(', '.join(delta.get('acceso_nuevo', [])) or '(ninguno)')}")
    for m in (registro.get("validacion") or {}).get("menores", []):
        print(f"  [AVISO] {_t(m.get('codigo'))}: {_t(m.get('detalle'))}")
    print(f"\nHuella de lo que estas viendo: {huella.calcular(registro)}")


def _mostrar(cuerpo: dict) -> None:
    """La decision que la Lambda dice haber escrito (el cuerpo de un 200).

    Todo con `.get`: ya esta escrita, y un cuerpo con otra forma no debe
    esconderla detras de un KeyError.
    """
    ap = cuerpo.get("decision") or {}
    por = ap.get("por") or {}
    print("\n" + "=" * 70)
    print(f"SOLICITUD {_t(cuerpo.get('id'))}  ->  {_t(cuerpo.get('estado'))}")
    print("=" * 70)
    # Lo que la Lambda saco de la firma: a quien se le atribuyo la decision.
    print(f"Aprobador (persona): {_t((cuerpo.get('aprobador') or {}).get('persona'))}")
    print(f"Aprobador (llamante): {_t(por.get('arn_llamante'))}")
    print(f"Aprobador (canonico): {_t(por.get('arn_canonico'))}")
    print(f"  verificado por: {_t(por.get('como_se_verifico'))}")
    print(f"Cuando:  {_t(ap.get('cuando'))}")
    print(f"Huella:  {_t(ap.get('huella'))}")

    if cuerpo.get("estado") == "rechazada_por_aprobador":
        print(f"\nRECHAZADA por el aprobador: {_t(ap.get('motivo'))}")
        return

    sep = ap.get("separacion_de_funciones") or {}
    print(f"\nSeparacion de funciones: {_t(sep.get('resultado'))}")
    print(f"  beneficiario: {_t(sep.get('beneficiario'))}")
    print(f"  aprobador (persona): {_t(sep.get('aprobador'))}")
    print(f"  solicitante (persona): {_t(sep.get('solicitante'))}")
    if sep.get("resultado") == "SALTADO":
        print(f"  [CONTROL SALTADO] {_t(sep.get('motivo'))}")
        print(f"  saltado por: {_t(sep.get('saltado_por'))} el {_t(sep.get('cuando'))}")

    techo = ap.get("techo") or {}
    print(f"\nCheckNoNewAccess: {_t(techo.get('resultado'))}")
    print(f"  techo usado: {_t(techo.get('origen_del_techo'))}")
    if ap.get("riesgo_confirmado"):
        print("\n[RIESGO ALTO] confirmado explicitamente por el aprobador.")


def _mostrar_fallo(solicitud_id: str, codigo: int, cuerpo: dict) -> None:
    """Un codigo que no es 200 ni 409: lo que se sabe, sin adornos."""
    print(f"\nNo se pudo decidir {_t(solicitud_id)} (codigo {codigo}).")
    for campo in ("resultado", "error", "tipo", "detalle"):
        if campo in cuerpo:
            print(f"  {campo}: {_t(cuerpo[campo])}")
    if codigo == 403:
        print(
            "  La URL no dejo pasar la peticion. Puede ser: que a tu identidad le falte el permiso "
            "lambda:InvokeFunctionUrl sobre la Lambda de aprobacion (el del permission set del "
            "aprobador); que las credenciales hayan caducado (repite `aws sso login`); o un problema "
            "de la firma. Lo que dijo la URL esta en `detalle`."
        )
    # Un 200 que llega aqui es un cuerpo sin decision: la Lambda contesto
    # algo que no se sabe leer, y lo probable es que ya haya escrito.
    if codigo >= 500 or codigo == 200 or cuerpo.get("resultado") in ("sin_respuesta", "respuesta_ilegible"):
        # La Lambda escribe y despues contesta: sin respuesta no se sabe en
        # que orden se rompio. Reintentar a ciegas daria un 409 que parece
        # culpa del primer intento.
        print(
            "\nATENCION: puede que la decision SI se haya escrito aunque no llegara la respuesta. "
            f"Antes de reintentar, relee la solicitud: python -m agente_iam.aprobar_cliente {_t(solicitud_id)} "
            "(si ya figura como aprobada o rechazada, no la repitas)."
        )


# --- CLI ---------------------------------------------------------------------


def _valor(argumentos: list[str], bandera: str, queda: str) -> str | None:
    """El valor que sigue a `bandera`, o None si no esta; sale con 1 si no lo trae."""
    if bandera not in argumentos:
        return None
    i = argumentos.index(bandera)
    if i + 1 >= len(argumentos):
        print(f"{bandera} necesita {queda}.")
        sys.exit(1)
    return argumentos[i + 1]


def main() -> None:
    argumentos = sys.argv[1:]
    if not argumentos:
        print(__doc__)
        sys.exit(1)

    solicitud_id = argumentos[0]
    huella_confirmada = _valor(argumentos, "--huella", "el valor que se mostro al revisar")
    motivo_rechazo = _valor(argumentos, "--rechazar", "un motivo entre comillas")
    rechazando = motivo_rechazo is not None

    # La peticion se arma antes de leer nada: un id o un motivo que no valen
    # no tocan la tabla. Con --rechazar no viaja huella; la calcula el servidor.
    try:
        peticion = PeticionAprobacion(
            id=solicitud_id,
            accion="rechazar" if rechazando else "aprobar",
            huella=None if rechazando else huella_confirmada,
            motivo=motivo_rechazo,
            autoaprobacion_demo="--autoaprobacion-demo" in argumentos,
            riesgo_alto_confirmado="--riesgo-alto-confirmado" in argumentos,
        )
    except ValidationError as e:
        # Campo y motivo, sin `input`: no se repite lo que se escribio.
        campos = ", ".join(sorted({".".join(str(p) for p in err["loc"]) or "(peticion)" for err in e.errors()}))
        print(f"La peticion no es valida ({_t(campos)}): revisa el id y el motivo.")
        sys.exit(1)

    # 1. Lectura UNICA: de este objeto salen la pantalla y la huella.
    try:
        registro = almacen.leer(solicitud_id)
    except almacen.RegistroInconsistente as e:
        # Una fila con forma imposible (S1) es un control que salta, no un
        # fallo del comando: sale con 3, como cualquier bloqueo.
        print(f"\nNO se aprueba {_t(solicitud_id)}: {_t(e)}")
        sys.exit(3)
    if registro is None:
        print(f"No encuentro la solicitud '{_t(solicitud_id)}' en {almacen.describir()}")
        sys.exit(1)

    if not rechazando:
        # Se pinta ANTES de enviar, y desde el mismo objeto cuya huella se muestra.
        _mostrar_propuesta(registro)
        if huella_confirmada is None:
            print(
                "\nFalta confirmar la huella. Revisa la propuesta y repite con "
                f"--huella {huella.calcular(registro)}"
            )
            sys.exit(3)

    if ALMACEN == "dynamodb":
        if not URL_APROBACION:
            print(
                "No hay a donde enviar la decision: falta AGENTE_IAM_URL_APROBACION "
                "(la URL de funcion de la Lambda de aprobacion). Con ALMACEN=dynamodb este "
                "comando no decide por su cuenta."
            )
            sys.exit(1)
        codigo, cuerpo = enviar(URL_APROBACION, peticion)
    else:
        # El servidor se importa solo aqui: en DynamoDB ni se carga.
        from agente_iam import aprobar

        print(_SIN_SERVIDOR)
        codigo, cuerpo = aprobar.decidir(peticion, aprobar.identificar_aprobador())

    if codigo == 200 and cuerpo.get("decision"):
        _mostrar(cuerpo)
        print(f"\nGuardado en: {_t(cuerpo.get('guardado_en'))}")
        return
    if codigo == 409:
        print(f"\nNO se aprueba {_t(solicitud_id)}. Motivos:\n")
        bloqueos = cuerpo.get("bloqueos")
        if not isinstance(bloqueos, list):
            bloqueos = [bloqueos or "(el servidor no dio el motivo)"]
        for b in bloqueos:
            print(f"  - {_t(b)}\n")
        sys.exit(3)
    _mostrar_fallo(solicitud_id, codigo, cuerpo)
    sys.exit(1)


if __name__ == "__main__":
    main()
