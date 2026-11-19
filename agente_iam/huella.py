"""La huella del registro aprobado.

Responde una sola pregunta, y hay que tenerla clara porque es facil
confundirla con la otra: **¿es esto exactamente lo que se aprobo?**

No responde "¿sigue siendo aceptable?" — eso lo contesta la revalidacion,
que corre las barandas de HOY. Hacen falta las dos y no se sustituyen:
un registro intacto puede haber quedado obsoleto (las reglas cambiaron), y
un registro que pasa las reglas de hoy puede no ser el que el humano leyo.
Es el mismo desdoblamiento que hace Terraform: `apply` ejecuta el plan
guardado en vez de reevaluar la configuracion, y ademas falla si el estado
cambio desde que se genero el plan.

Vive en su propio modulo por una razon concreta: lo que el aprobador ve y lo
que el servidor firma salen de la misma funcion, `calcular`, sin copia
(ADR-003). El MAC con KMS se descarto el 24-10-2026 (ESTUDIO §20): quien
escribe el bloque tendria la clave.

SOBRE LA CANONICALIZACION. `sort_keys=True` con `separators=(",", ":")` es
un JCS (RFC 8785) de andar por casa. Se aparta del estandar en dos sitios:
la serializacion de numeros en coma flotante, y que JCS ordena las claves
por unidades de codigo UTF-16 y no por puntos de codigo. Para lo que hay
en este registro —cadenas, listas, diccionarios y enteros, ni un solo
float— los dos coinciden. El dia que el registro gane un decimal, esta
frase deja de ser cierta y hay que pasar a una implementacion de JCS.

LIMITE, y va aqui porque es donde se lee: la huella detecta la deriva y el
accidente, no a quien controla el proceso. Quien pueda escribir el archivo
puede cambiar el documento y recalcular la huella a la vez. Lo que impide
el desastre no es esto, es el rol del aplicador y el techo del destino;
esto es lo que permite saber que paso. Se sube el liston con KMS o con
almacenamiento de escritura unica (S3 Object Lock).
"""

import hashlib
import json

# Lo que NO entra en la huella, y son dos cosas distintas:
#
#   - Los BLOQUES que se escriben despues de calcularla (`aprobacion`,
#     `rechazo`, `aplicacion`; el rechazo es bloque propio desde el
#     24-10-2026, antes iba dentro de `aprobacion`). Si entraran seria imposible verificarla, porque
#     guardar el resultado cambiaria aquello sobre lo que se calculo.
#
#   - El ESTADO. Este se olvido en la primera version y el error solo
#     aparecio al correr el comando de verdad: la huella se calculaba con
#     `estado: propuesta` y se guardaba junto a `estado: aprobada`, asi que
#     no verificaba nunca. El aplicador habria rechazado el 100% de los
#     registros. Y la leccion no es "reordenar las lineas": el estado es
#     precisamente el campo que el flujo esta DISENADO para ir cambiando
#     (propuesta -> aprobada -> aplicada), asi que meterlo en una firma
#     garantiza que la firma se rompa en cada transicion legitima. La
#     huella responde "¿es esta la misma propuesta?", no "¿en que punto
#     del flujo esta?".
#
# Que quede fuera no abre un hueco: cambiar el estado a mano no consigue
# que se aplique nada en una fila sin aprobacion real, porque el aplicador
# exige ademas el bloque de aprobacion y que la huella cuadre; y sobre una
# fila ya decidida (con `aplicacion` o `rechazo`) el aplicador lo rechaza y
# el evento va a la cola de fallos. Falsificar el bloque entero es el
# limite ya conocido —quien pueda escribir el archivo— y no lo tapa esto.
CAMPOS_FUERA_DE_LA_HUELLA = ("aprobacion", "rechazo", "aplicacion", "estado")


def instantanea(registro: dict) -> dict:
    """Lo que la aprobacion congela: el registro menos lo que viene despues.

    Se toma el registro ENTERO a proposito, no solo la propuesta. De el
    dependen las dos revalidaciones posteriores: los chequeos posteriores
    se evaluan contra `solicitud.campos` y contra `identidad_verificada`,
    asi que si la huella solo cubriera `propuesta`, alguien podria cambiar
    el servicio solicitado o el beneficiario sin moverla — y el aplicador
    revalidaria contra unos datos distintos de los que leyo el humano.
    """
    return {k: v for k, v in registro.items() if k not in CAMPOS_FUERA_DE_LA_HUELLA}


def calcular(registro: dict) -> str:
    """SHA-256 de la instantanea, serializada de forma determinista."""
    serializado = json.dumps(
        instantanea(registro),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "sha256:" + hashlib.sha256(serializado.encode("utf-8")).hexdigest()


def coincide(registro: dict, esperada: str) -> bool:
    """¿El registro sigue siendo el que se aprobo?

    `compare_digest` en vez de `==` por costumbre, no porque aqui haya un
    canal de temporizacion que explotar: el dia que esto sea un MAC de KMS
    la comparacion si sera sensible, y el habito ya estara puesto.
    """
    import hmac

    return hmac.compare_digest(calcular(registro), esperada)
