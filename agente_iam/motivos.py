"""El motivo corto de cada estado, para la pagina y el correo (Fase 28, punto 4).

POR QUE EXISTE. Hasta la Fase 27 cada estado tenia una frase fija y nada mas:
el 27-10-2026 una solicitud quedo en `requiere_revision_humana` sin decir por
que (docs/MEDICIONES.md Q.1). El porque estaba en el registro (los motivos de
los chequeos previos, el riesgo, si ya tenia el acceso), pero no llegaba a la
persona. Este modulo lo convierte en {codigo, texto}: el codigo para quien
programe o resuelva, el texto para la persona.

LA REGLA. El texto se arma con frases fijas de aqui, elegidas con datos que
pone el codigo (codigos de motivo, estado, nivel calculado, riesgo). Nunca se
copia texto del modelo ni de la justificacion: una solicitud maliciosa no puede
colar mensajes en la pagina ni en el correo. Las unicas piezas variables son el
nombre del recurso (alfabeto cerrado en `models`), la hora de vencimiento (la
pone el aplicador) y el motivo de un rechazo del aprobador, que escribe una
persona del sistema y se escapa. El detalle completo sigue en el registro.

Lo usan `servidor` (la respuesta a la pagina) y `avisos` (el correo). Es puro y
no importa nada de AWS.
"""

from __future__ import annotations

from agente_iam.models import imprimible

# Chequeos previos: un texto por codigo de `coherencia.chequeos_formulario_con_codigo`
# y de `orquestador._chequeos_con_codigo`.
TEXTOS_DE_CHEQUEO: dict[str, str] = {
    "recurso_no_encontrado": "No se encontro el recurso en esta cuenta. Revisa el nombre.",
    "arn_no_coincide": "El ARN no corresponde a esta cuenta.",
    "servicio_no_admitido": "El sistema no concede accesos en ese servicio.",
    "region_no_admitida": "El sistema no concede accesos en esa region.",
    "recurso_del_sistema": "Ese recurso es del propio sistema y no se concede.",
    "palabra_del_arn": "Eso es un tipo de recurso, no un nombre. Escribe el nombre del recurso.",
    "tope_de_roles": "Ya tienes el maximo de accesos vigentes; espera a que venza alguno.",
    "solo_lectura": "Ese servicio solo se concede para consultar.",
    "principal_no_verificado": "No se pudo verificar a quien seria el beneficiario.",
    "principal_sin_techo": "El beneficiario no esta dado de alta en el sistema.",
}
_CHEQUEO_SIN_CODIGO = "La solicitud no pasa las reglas del sistema y no se tramita."

_NIVELES = {
    "lectura": "Permite ver",
    "modifica": "Permite ver y modificar",
    "borra": "Permite ver, modificar y borrar",
}

_LARGO_MAXIMO_DEL_RECHAZO = 200


def motivo_publico(registro: dict) -> dict[str, str]:
    """{codigo, texto} del estado del registro. Estado desconocido: codigo `desconocido`, texto vacio."""
    estado = registro.get("estado")
    if estado == "rechazada_en_chequeos_previos":
        codigos = registro.get("motivos_codigos") or []
        if codigos and codigos[0] in TEXTOS_DE_CHEQUEO:
            return {"codigo": codigos[0], "texto": TEXTOS_DE_CHEQUEO[codigos[0]]}
        return {"codigo": "reglas_del_sistema", "texto": _CHEQUEO_SIN_CODIGO}
    if estado == "redundante_no_requiere_cambio":
        return {"codigo": "ya_tiene_el_acceso", "texto": "Ya tienes ese acceso con un rol vigente; no hace falta otro."}
    if estado == "requiere_revision_humana":
        return _revision_humana(registro)
    if estado == "propuesta":
        return _propuesta(registro)
    if estado == "aprobada":
        return {"codigo": "aprobada", "texto": "Una persona la aprobo; el acceso se esta creando."}
    if estado == "rechazada_por_aprobador":
        motivo = imprimible(((registro.get("rechazo") or {}).get("motivo") or "").strip())
        texto = "Una persona la rechazo."
        if motivo:
            texto += " Motivo: " + motivo[:_LARGO_MAXIMO_DEL_RECHAZO]
        return {"codigo": "rechazada", "texto": texto}
    if estado == "bloqueada_al_aplicar":
        return {
            "codigo": "bloqueada",
            "texto": "Algo cambio entre la aprobacion y la aplicacion; no se creo nada. Pidela de nuevo.",
        }
    if estado == "aplicada":
        vence = imprimible((registro.get("aplicacion") or {}).get("vence") or "")
        texto = "Acceso creado."
        if vence:
            texto += f" Vence: {vence} (UTC)."
        texto += " Usa el id de la solicitud para obtener tus credenciales."
        return {"codigo": "aplicada", "texto": texto}
    if estado == "error":
        return {"codigo": "error", "texto": "La solicitud no se pudo procesar; vuelve a intentarlo."}
    return {"codigo": "desconocido", "texto": ""}


def _revision_humana(registro: dict) -> dict[str, str]:
    """Que llevo a la revision humana, con datos del codigo y no del modelo.

    `excede_limites` si el riesgo minimo del codigo dice que se pidieron o
    propusieron acciones de escalada o prohibidas; `riesgo_alto` si la ultima
    propuesta vino marcada de riesgo alto (es una categoria del modelo, no un
    texto suyo); `sin_politica_valida` en lo demas.
    """
    riesgo = registro.get("riesgo_minimo") or []
    if any(m.startswith(("el modelo propuso", "la justificacion pide")) for m in riesgo):
        return {
            "codigo": "excede_limites",
            "texto": "Lo pedido supera lo que el sistema puede conceder; la revisara una persona.",
        }
    if (registro.get("propuesta") or {}).get("nivel_riesgo") == "alto":
        return {"codigo": "riesgo_alto", "texto": "La solicitud se marco de riesgo alto; la revisara una persona."}
    return {
        "codigo": "sin_politica_valida",
        "texto": "No se pudo armar un permiso seguro con lo descrito; la revisara una persona.",
    }


def _propuesta(registro: dict) -> dict[str, str]:
    """El nivel que concede la propuesta (calculado por el codigo) y si el aprobador tendra que confirmar riesgo."""
    partes: list[str] = []
    nivel = registro.get("nivel_real")
    recurso = ((registro.get("solicitud") or {}).get("campos") or {}).get("recurso")
    if nivel in _NIVELES:
        partes.append(_NIVELES[nivel] + (f" en '{imprimible(recurso)}'." if recurso else "."))
    if registro.get("exige_confirmacion_de_riesgo"):
        partes.append("El aprobador tendra que confirmar el riesgo.")
        codigo = "confirmar_riesgo"
    else:
        partes.append("Espera la aprobacion de una persona.")
        codigo = "espera_aprobacion"
    return {"codigo": codigo, "texto": " ".join(partes)}
