"""CLI de intake.

Es el modo de principal existente (adjuntar con el techo a un principal ya
declarado, sin token); el modo de rol por persona es solo del servidor, que
tiene JWT (diseno de la Fase 23, 5.5).

Uso:
    python -m agente_iam.cli ejemplos/solicitud-ana.json

Recibe una solicitud estructurada (el "formulario" en formato JSON), la
procesa y guarda el registro con su estado en la carpeta de solicitudes.

Codigos de salida:
    0  la solicitud se proceso (con el estado que sea)
    1  la corrida fallo a mitad de camino; el registro quedo guardado
    2  la solicitud no tiene forma valida y no se proceso
"""

import json
import sys
from pathlib import Path

import boto3
from pydantic import ValidationError

from agente_iam.almacen import RegistroExistente, describir, guardar_propuesta
from agente_iam.config import AWS_REGION
from agente_iam.models import SolicitanteVerificado, SolicitudEstructurada, imprimible
from agente_iam.orquestador import procesar

# Todo lo que se pinta sale del registro, y parte del registro lo escribio
# otro: el solicitante (justificacion) o el modelo, que la justificacion
# puede dictar (supuestos, justificacion de la propuesta, y los motivos que
# citan acciones o ARN propuestos). Se escapa todo lo no imprimible (S7).
_t = imprimible

# Se graba en cada registro: el CLI corre con el rol del Analista y no hay
# JWT, asi que no hay persona que comprobar. Va antes de guardar_propuesta
# para quedar dentro de `documento`, bajo la huella.
SOLICITANTE_CLI = (
    "CLI de intake: corre con el rol del Analista, sin persona verificada (ADR-003, B2)"
)

MENSAJE_SOLO_PRINCIPAL_EXISTENTE = (
    "El CLI de desarrollo solo tramita solicitudes con principal_arn_declarado; "
    "horas, persona y correo_aviso son del servidor con JWT (diseno de la Fase 23, 5.5)."
)


def mostrar(registro: dict) -> None:
    print("\n" + "=" * 70)
    print(f"SOLICITUD {_t(registro['id'])}  ->  {_t(registro['estado'])}")
    print(f"intentos del agente: {_t(registro['intentos'])}")
    if uso := registro.get("uso_modelo"):
        print(
            f"modelo: {_t(uso['modelo'])}  tokens: {_t(uso['tokens_entrada'])} entrada, "
            f"{_t(uso['tokens_salida'])} salida  ({_t(uso['latencia_ms'])} ms)"
        )
    print("=" * 70)

    # Fase 4: un registro de error puede no tener identidad ni propuesta.
    # Esta funcion se lee con .get() en todo lo opcional; si reventara al
    # mostrar un error, el manejo de errores fallaria justo cuando importa.
    ident = registro.get("identidad_verificada") or {}
    if ident:
        print(f"Principal: {_t(ident['principal_arn'])}")
        print(f"  tipo: {_t(ident['tipo'])} | existe: {_t(ident['existe'])}")
        if ident.get("detalle"):
            print(f"  detalle: {_t(ident['detalle'])}")
        if ident.get("politicas_actuales"):
            print(f"  politicas que ya tiene: {_t(', '.join(ident['politicas_actuales']))}")

    if registro.get("error"):
        err = registro["error"]
        print(f"\n[ERROR] La corrida fallo en la fase '{_t(err['fase'])}'")
        print(f"  {_t(err['tipo'])}: {_t(err['detalle'])}")
        print("  El registro se guardo igual; la traza completa esta en el archivo.")

    if registro.get("motivos"):
        print("\nRechazada antes de invocar al modelo:")
        for m in registro["motivos"]:
            print(f"  - {_t(m)}")
        return

    p = registro.get("propuesta")
    if p:
        print(f"\nAccion: {_t(p['accion'])} | Politica: {_t(p['nombre_politica'])}")
        print(f"Riesgo: {_t(p['nivel_riesgo'])}")
        print(f"\nJustificacion: {_t(p['justificacion'])}")
        for s in p.get("supuestos", []):
            print(f"  supuesto: {_t(s)}")
        print("\nDocumento propuesto:")
        # ensure_ascii: json.dumps escapa los de control, pero no DEL, C1 ni
        # los de formato (U+202E); en ASCII no queda ninguno.
        print(json.dumps(p["policy_document"], indent=2, ensure_ascii=True))

    delta = registro.get("acceso_nuevo") or {}
    if delta:
        print("\nContraste con lo que ya puede hacer hoy:")
        # Dos cubos y ninguno intermedio: lo que el simulador confirmo que
        # ya podia hacer, y todo lo demas. Lo que no esta probado cuenta
        # como acceso nuevo (ver simulacion.redundancia).
        print(f"  ya tenia:     {_t(', '.join(delta['ya_tenia']) or '(nada)')}")
        print(f"  acceso nuevo: {_t(', '.join(delta['acceso_nuevo']) or '(ninguno)')}")

    historial = registro.get("historial_validacion") or []
    if historial:
        print("\nHistorial de validacion:")
        for h in historial:
            v = h["veredicto"]
            print(f"  intento {_t(h['intento'])}: aprobable={_t(v['aprobable'])}")
            for b in v["bloqueos"]:
                print(f"    [BLOQUEO] {_t(b)}")
            for c in v["criticos"]:
                print(f"    [CRITICO] {_t(c['codigo'])}: {_t(c['detalle'])}")
            # Las advertencias no bloquean, pero si no se muestran no
            # sirven de nada: son justo lo que el humano debe revisar.
            for m in v.get("menores", []):
                if m.get("tipo") == "WARNING":
                    print(f"    [AVISO]   {_t(m['codigo'])}: {_t(m['detalle'])}")


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)

    ruta_entrada = Path(sys.argv[1])
    if not ruta_entrada.exists():
        print(f"No encuentro el archivo: {ruta_entrada}")
        sys.exit(1)

    # Fase 1: si la solicitud ni siquiera tiene forma valida (alfabetos,
    # patrones, longitudes de models.py), se corta aqui con un mensaje
    # legible. La validacion semantica (servicio permitido, principal
    # existente) ocurre despues, en chequeos_previos, y esa si deja registro.
    try:
        sol = SolicitudEstructurada.model_validate_json(ruta_entrada.read_text())
    except ValidationError as e:
        print("La solicitud no tiene una forma valida; no se procesa:")
        for err in e.errors():
            campo = ".".join(str(p) for p in err["loc"])
            print(f"  - {campo}: {err['msg']}")
        sys.exit(2)

    # Fase 23 (diseno 5.5): el modo de rol por persona exige un JWT del que
    # sacar `persona`, y el CLI no tiene token. Si dejara pasar un fichero con
    # `persona`, cualquiera con acceso al disco escribiria el beneficiario a
    # mano. Se corta aqui, sin procesar ni guardar nada.
    if sol.principal_arn_declarado is None:
        print(MENSAJE_SOLO_PRINCIPAL_EXISTENTE)
        sys.exit(2)

    # Fase 4: guardar PRIMERO. `procesar` nunca lanza, asi que toda
    # corrida deja archivo; el fallo se reporta despues, con exit code.
    registro = procesar(sol)
    registro["ejecutado_por"] = _quien_corre_esto()
    registro["solicitante"] = SolicitanteVerificado(
        persona=None, como_se_verifico=SOLICITANTE_CLI
    ).model_dump()
    try:
        donde = guardar_propuesta(registro)
    except RegistroExistente as e:
        print(f"\nNo se guarda: {e}")
        sys.exit(1)
    mostrar(registro)
    print(f"\nGuardado en: {donde}")
    print(f"Almacen: {describir()}")

    if registro["estado"] == "error":
        sys.exit(1)


def _quien_corre_esto() -> dict:
    """Quien EJECUTO el intake. No es quien lo pidio.

    La distincion importa y por eso el campo se llama asi. Hoy el sistema
    no autentica al remitente: el formulario no tiene un campo para "quien
    envia", asi que remitente y beneficiario coinciden por construccion, no
    porque se haya comprobado. Esto solo dice desde que credenciales se
    lanzo el proceso — util para auditar, inutil como control de identidad.
    Lo cierra el IdP.
    """
    try:
        ident = boto3.client("sts", region_name=AWS_REGION).get_caller_identity()
        return {"arn": ident["Arn"], "user_id": ident["UserId"]}
    except Exception as e:
        # Que esto falle no puede tumbar el intake: es metadato, no control.
        return {"arn": None, "error": str(e)}


if __name__ == "__main__":
    main()
