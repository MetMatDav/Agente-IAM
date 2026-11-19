"""Tercera capa de validacion: preguntarle a IAM que pasaria de verdad.

Las dos capas anteriores responden "no concede de mas". Faltaba responder
"si concede lo pedido", y esa es otra pregunta, con otra herramienta.

  eficacia(doc)      -> SimulateCustomPolicy: la politica propuesta,
                        evaluada sola. Si toda accion sale implicitDeny,
                        la politica no sirve para nada aunque sea segura.
  redundancia(...)   -> SimulatePrincipalPolicy: evalua los permisos que
                        el principal YA tiene, incluidos los heredados de
                        grupos y con sus boundaries. Si ya puede hacerlo,
                        la solicitud sobra.

Por que no leemos las politicas del usuario y las comparamos nosotros:
porque eso seria reimplementar el motor de evaluacion de IAM, con sus
grupos, boundaries, denies y condiciones. IAM ya lo hace bien. Se le
pregunta.

Fase 5 — simular CON el contexto de la peticion. Antes se simulaba sin
`ContextEntries`, asi que una politica con `Condition` se evaluaba sin que
la condicion se ejerciera: el veredicto era sobre una politica parecida a
la propuesta, no sobre la propuesta. Y la capa 1 EXIGE `Condition` cuando
una accion requiere `Resource: "*"`, o sea que el sistema forzaba justo el
caso que no sabia evaluar.

La regla al aportar contexto: solo lo que se sabe con certeza. La region
del formulario, la cuenta verificada y el ARN canonico. Nada de
`aws:PrincipalType` (nosotros decimos "role", AWS dice "AssumedRole": no
es lo mismo y afirmarlo seria inventar), nada de `aws:SourceIp` ni
`aws:CurrentTime`, que dependen de quien haga la llamada real.

Comportamiento del simulador, medido contra la cuenta real (28-08-2026,
cinco pruebas; ver PLAN-CORRECCIONES.md). Resumen operativo:

  - Cuando una condicion NO se cumple por falta de contexto, el simulador
    devuelve implicitDeny Y reporta la clave en `MissingContextValues`,
    en los dos sitios. Ahi si avisa.
  - Pero para `aws:RequestedRegion` tiene un valor implicito: la region
    del endpoint contra el que se simula. Una politica que condiciona a
    us-east-1, simulada desde us-east-1 sin aportar nada, sale 'allowed'
    y sin reportar nada. El permiso parece verificado y no lo esta: lo
    que se comprobo fue la region de NUESTRA llamada, no la del
    solicitante. Justo la clave que la capa 1 le sugiere al agente.

De ahi las dos reglas de este modulo:

  1. Se aporta `aws:RequestedRegion` desde el formulario, para que la
     evaluacion use la region del solicitante y no la nuestra.
  2. En `eficacia`, las claves sin resolver las deduce NUESTRO codigo,
     leyendo los bloques `Condition` del documento y restando las
     aportadas; lo que el simulador reporte se suma como complemento. Un
     implicitDeny con claves sin resolver no es "no concede": es "no se
     pudo evaluar", y tratarlo como denegado bloquearia una politica
     correcta.

La regla 2 vale SOLO para `eficacia`, y la razon esta en la docstring de
`redundancia`: alli lo que el simulador evalua no es nuestro documento
sino las politicas del principal, asi que ni sus condiciones ni su
reporte de claves faltantes hablan de la propuesta. Medido 29-08-2026.
"""

import json
from datetime import datetime

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from agente_iam import personas
from agente_iam.config import AWS_REGION
from agente_iam.personas import FORMATO_VENCE

_cliente = None

# Claves de condicion que este sistema sabe aportar, con su tipo. El tipo
# es obligatorio en ContextEntries y es un enum cerrado de la API
# (string | stringList | numeric | ... | date | dateList). Como
# GetContextKeysForCustomPolicy devuelve solo NOMBRES, el tipo lo tenemos
# que saber nosotros: lo que no este en esta tabla no se aporta, porque
# adivinar el tipo seria inventar igual que adivinar el valor.
_TIPO_DE_CLAVE = {
    "aws:RequestedRegion": "string",
    "aws:PrincipalAccount": "string",
    "aws:PrincipalArn": "string",
    # Medido en MEDICIONES A.3: el simulador NO tiene valor implicito para
    # esta clave; sin aportarla, la politica de un rol de persona (que lleva
    # `DateLessThan aws:CurrentTime`) sale implicitDeny y la redundancia
    # seria siempre "acceso nuevo". Solo la aporta `redundancia_persona`:
    # `eficacia` NO, porque la propuesta del modelo no lleva vencimiento (se
    # anade al aplicar).
    "aws:CurrentTime": "date",
}


def _iam():
    global _cliente
    if _cliente is None:
        _cliente = boto3.client("iam", region_name=AWS_REGION)
    return _cliente


def _claves_de_condicion(statement: dict) -> set[str]:
    """Claves de condicion que ESTE statement referencia, leidas del propio
    documento — no del simulador.

    Existe porque el simulador no siempre avisa: para `aws:RequestedRegion`
    usa un valor implicito (la region del endpoint) y, si la condicion
    coincide con el, devuelve 'allowed' sin reportar nada. Leyendo el
    documento sabemos que claves pide la politica sin depender de eso.

    Los operadores `...IfExists` no cuentan: estan disenados para tolerar
    la ausencia de la clave, asi que su falta no es una duda. El prefijo
    `ForAnyValue:`/`ForAllValues:` se descarta antes de mirar el sufijo.
    """
    claves: set[str] = set()
    for operador, pares in (statement.get("Condition") or {}).items():
        if not isinstance(pares, dict):
            continue
        base = operador.split(":")[-1]
        if base.lower().endswith("ifexists"):
            continue
        # Se conserva la grafia original: los nombres de clave no
        # distinguen mayusculas para comparar (de eso se encarga
        # `_sin_aportar`), pero al humano se le muestran bien escritos.
        claves |= set(pares)
    return claves


def _sin_aportar(referenciadas: set[str], aportadas: set[str]) -> set[str]:
    """Las referenciadas que no estan entre las aportadas.

    La comparacion ignora mayusculas —los nombres de clave de condicion no
    las distinguen— pero devuelve la grafia original del documento.
    """
    en_minusculas = {clave.lower() for clave in aportadas}
    return {c for c in referenciadas if c.lower() not in en_minusculas}


def _por_statement(documento: dict):
    """Genera (acciones, recursos, claves_de_condicion) de cada Allow."""
    statements = documento.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        if st.get("Effect") != "Allow":
            continue
        acciones = st.get("Action", [])
        if isinstance(acciones, str):
            acciones = [acciones]
        recursos = st.get("Resource", [])
        if isinstance(recursos, str):
            recursos = [recursos]
        yield acciones, recursos, _claves_de_condicion(st)


def _context_entries(contexto: dict | None) -> list[dict]:
    """Traduce {clave: valor} al formato ContextEntries de la API."""
    if not contexto:
        return []
    entradas = []
    for clave, valor in contexto.items():
        tipo = _TIPO_DE_CLAVE.get(clave)
        if tipo is None or not valor:
            continue  # clave desconocida o valor vacio: no se aporta
        entradas.append(
            {
                "ContextKeyName": clave,
                "ContextKeyValues": [str(valor)],
                "ContextKeyType": tipo,
            }
        )
    return entradas


def _reportadas_por_el_simulador(resultado: dict) -> set[str]:
    """Claves que el simulador DICE que le faltaron.

    Vienen en DOS sitios y hay que leer los dos. La API lo dice: el campo
    de nivel superior se usa cuando el recurso simulado es "*", pero "if
    you include a list of resources, then any missing context values are
    instead included under the ResourceSpecificResults section". Nosotros
    siempre pasamos ResourceArns, asi que leer solo el de arriba daria
    "no falta nada" SIEMPRE — un falso diagnostico con cara de certeza.

    Es un COMPLEMENTO, no la fuente principal: el simulador reporta bien
    cuando la condicion falla, pero calla cuando su valor implicito de
    `aws:RequestedRegion` la satisface. La deteccion de base la hace
    `_claves_de_condicion` leyendo el documento.

    Solo la usa `eficacia`. Lo que reporta son las claves de los
    statements que el simulador considero, y en `redundancia` esos
    statements son los del principal, no los nuestros: alli el reporte
    habla de otras politicas y no de la propuesta.
    """
    faltan = set(resultado.get("MissingContextValues") or [])
    for especifico in resultado.get("ResourceSpecificResults") or []:
        faltan |= set(especifico.get("MissingContextValues") or [])
    return faltan


def _permitida_en_algun_recurso(resultado: dict) -> bool:
    """¿La accion sale 'allowed' para AL MENOS uno de los recursos?

    Hay que mirar `ResourceSpecificResults`, no `EvalDecision`. Medido
    contra la cuenta real (30-08-2026), misma accion y mismo principal:

        solo el ARN de objeto  -> EvalDecision = allowed
        solo el ARN de bucket  -> EvalDecision = implicitDeny
        los dos juntos         -> EvalDecision = implicitDeny
                                  por recurso: bucket=implicitDeny,
                                               bucket/*=allowed

    O sea que con varios `ResourceArns` el `EvalDecision` de nivel
    superior es el agregado PESIMISTA: deniega si deniega para alguno. La
    verdad por recurso solo esta dentro.

    Importa porque en S3 conviven en un mismo statement acciones que solo
    aplican al bucket (`ListBucket`) con otras que solo aplican al objeto
    (`GetObject`), y el modelo a veces las funde en un statement con los
    dos ARNs. Leyendo el nivel superior, esa politica —correcta y util—
    saldria como que no concede nada, y el orquestador mandaria al agente
    a arreglar lo que no esta roto. Un falso positivo de los caros.

    Si no vienen resultados por recurso (se simulo contra "*"), el de
    nivel superior es el unico que hay y es el correcto.
    """
    especificos = resultado.get("ResourceSpecificResults") or []
    if especificos:
        return any(e.get("EvalResourceDecision") == "allowed" for e in especificos)
    return resultado.get("EvalDecision") == "allowed"


def _resultados(llamar, **kwargs):
    """Recorre EvaluationResults siguiendo la paginacion de la API."""
    while True:
        respuesta = llamar(**kwargs)
        yield from respuesta["EvaluationResults"]
        if not respuesta.get("IsTruncated") or not respuesta.get("Marker"):
            break
        kwargs["Marker"] = respuesta["Marker"]


def documento_de_politica(arn: str) -> dict:
    """El documento en vigor (version por defecto) de una politica gestionada."""
    import urllib.parse

    version = _iam().get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
    documento = _iam().get_policy_version(PolicyArn=arn, VersionId=version)[
        "PolicyVersion"
    ]["Document"]
    if isinstance(documento, str):  # segun version de botocore
        documento = json.loads(urllib.parse.unquote(documento))
    return documento


def eficacia(
    documento: dict, contexto: dict | None = None, boundary: dict | None = None
) -> dict:
    """Comprueba que la politica realmente conceda lo que dice conceder.

    Una accion cuenta como efectiva si sale 'allowed' para AL MENOS uno de
    los recursos de su statement. Eso evita falsas alarmas: en S3,
    ListBucket solo aplica al ARN del bucket y GetObject solo al de objeto,
    y ambos conviven en el mismo statement.

    Fase 5 — la duda NO bloquea aqui. Una accion permitida pero con alguna
    clave de condicion sin resolver va a `acciones_condicionales`: cuenta
    como que la politica concede algo (bloquearla seria un falso positivo,
    y ya sabemos lo que cuestan), pero se reporta para que el aprobador lo
    sepa. Comparar con `redundancia`, donde la duda se trata al reves.

    `boundary` (revision 2026-10): el permission boundary del beneficiario.
    En ejecucion IAM concede la INTERSECCION de la politica con el
    boundary; simular la politica sola diria "concede" para algo que el
    boundary corta, y la politica aprobada no serviria de nada (el error
    3 del CONTEXTO, por otra puerta). Hasta el techo v2 (23-10-2026) el
    techo permitia enteros los servicios permitidos y no cambiaba el
    resultado; desde entonces EC2 se queda en `Describe*` y los Deny niegan
    la gestion de permisos y los recursos del sistema, asi que esto es lo
    que impide que `eficacia` mienta. (Que recorte de verdad con un
    beneficiario real no se ha medido contra la cuenta.) `redundancia` no
    lo necesita: SimulatePrincipalPolicy ya aplica el boundary adjunto.
    """
    permitidas: set[str] = set()
    condicionales: set[str] = set()
    evaluadas: set[str] = set()
    claves: set[str] = set()
    entradas = _context_entries(contexto)
    aportadas = {e["ContextKeyName"] for e in entradas}

    for acciones, recursos, claves_st in _por_statement(documento):
        # La deteccion propia: lo que el statement pide y nosotros no
        # aportamos queda sin evaluar, diga lo que diga el simulador.
        sin_aportar = _sin_aportar(claves_st, aportadas)

        parametros = {
            "PolicyInputList": [json.dumps(documento)],
            "ActionNames": acciones,
            "ResourceArns": recursos or ["*"],
        }
        if entradas:
            parametros["ContextEntries"] = entradas
        if boundary:
            parametros["PermissionsBoundaryPolicyInputList"] = [json.dumps(boundary)]

        for r in _resultados(_iam().simulate_custom_policy, **parametros):
            accion = r["EvalActionName"]
            evaluadas.add(accion)
            faltan = sin_aportar | _reportadas_por_el_simulador(r)
            if faltan:
                # Con claves sin resolver, NINGUNA decision es concluyente
                # — tampoco un implicitDeny. El simulador deniega cuando
                # le falta contexto, y contar eso como "no concede nada"
                # bloquearia una politica correcta y mandaria al agente a
                # "arreglar" lo que no esta roto.
                condicionales.add(accion)
                claves |= faltan
            elif _permitida_en_algun_recurso(r):
                permitidas.add(accion)

    # Si una accion salio limpia en algun statement, esa certeza gana.
    condicionales -= permitidas
    sin_efecto = sorted(evaluadas - permitidas - condicionales)

    return {
        "acciones_efectivas": sorted(permitidas),
        "acciones_condicionales": sorted(condicionales),
        "acciones_sin_efecto": sin_efecto,
        "claves_sin_resolver": sorted(claves),
        # La duda no bloquea: si concede aunque sea condicionalmente, la
        # politica no es inutil y no hay que mandar al agente a corregir.
        "concede_algo": bool(permitidas or condicionales),
        # Si no se evaluo nada, el documento no tenia statements Allow con
        # acciones. Eso no es "no concede": es que no hay nada que evaluar,
        # y hay que distinguirlo para no dar un diagnostico falso.
        "no_evaluable": not evaluadas,
    }


def redundancia(
    principal_arn: str, documento: dict, contexto: dict | None = None
) -> dict:
    """Que parte de lo propuesto el principal YA puede hacer hoy.

    Usa SimulatePrincipalPolicy, que evalua los permisos efectivos del
    principal: politicas adjuntas, inline, heredadas de grupos y su
    permission boundary. Por eso no necesitamos leer ni comparar
    documentos a mano.

    La asimetria de la Fase 5 sigue en pie: la duda cae del lado de "no es
    redundante", porque declarar redundante por error deja sin acceso a
    quien si lo necesita. Lo que cambio es COMO se detecta la duda.

    Aqui NO se usan `_reportadas_por_el_simulador` ni `_sin_aportar`, y
    las dos omisiones tienen motivo (medido contra la cuenta real,
    29-08-2026; ver CONTEXTO §12):

      - El reporte del simulador es de OTRAS politicas. `MissingContextValues`
        lista las claves que aparecen en los statements que el simulador
        CONSIDERO, no las que determinaron el resultado. En `eficacia` todo
        lo considerado es nuestro documento, asi que el reporte significa
        algo; aqui lo considerado son las politicas del principal. Medido:
        simulando `s3:GetObject` para ana.gomez sale `implicitDeny` y
        reporta `aws:CalledViaLast`, que viene de un statement sobre
        SageMaker dentro de `AmazonBedrockReadOnly` y no tiene ninguna
        relacion con leer un bucket. Usarlo marcaba el 100% de las
        acciones como no concluyentes: una advertencia que siempre esta
        encendida no informa de nada.

      - Un `allowed` es concluyente por construccion. Es el hallazgo (b)
        del §12 leido al reves: si a una clave le falta valor, el
        simulador DENIEGA. Luego, si concedio, ninguna clave sin resolver
        pudo estar bloqueando el statement que concedio. Medido: Mateo
        (admin) sale `allowed` con los dos sitios de
        `MissingContextValues` vacios.

      - Las `Condition` de NUESTRO documento no pintan nada aqui. Esta
        simulacion evalua las politicas DEL PRINCIPAL; nuestro documento
        solo aporta la lista de acciones y recursos. Sus condiciones ni
        siquiera entran en la evaluacion.

    Quedan dos cubos y ninguno intermedio: `allowed` es "ya lo tenia",
    cualquier otra cosa es "no esta probado que lo tenga" y cuenta como
    acceso nuevo.
    """
    ya_permitidas: set[str] = set()
    total: set[str] = set()
    entradas = _context_entries(contexto)

    for acciones, recursos, _claves_del_statement in _por_statement(documento):
        parametros = {
            "PolicySourceArn": principal_arn,
            "ActionNames": acciones,
            "ResourceArns": recursos or ["*"],
        }
        if entradas:
            parametros["ContextEntries"] = entradas

        for r in _resultados(_iam().simulate_principal_policy, **parametros):
            accion = r["EvalActionName"]
            total.add(accion)
            if _permitida_en_algun_recurso(r):
                ya_permitidas.add(accion)

    # Todo lo que no se probo que ya tuviera cuenta como acceso nuevo: si
    # no esta demostrado, la solicitud no sobra.
    nuevas = sorted(total - ya_permitidas)

    return {
        "ya_tenia": sorted(ya_permitidas),
        "acceso_nuevo": nuevas,
        "es_totalmente_redundante": bool(total) and not nuevas,
    }


def redundancia_persona(
    usuario: str,
    documento: dict,
    contexto: dict | None,
    ahora: datetime,
    *,
    vence_nuevo: str | None = None,
    roles: list[dict] | None = None,
) -> dict:
    """Que parte de lo propuesto la persona YA puede hacer con sus roles vigentes.

    En el modo por persona no hay principal al que adjuntar: cada solicitud
    crea un rol nuevo. Lo que la persona ya tiene son sus otros roles de
    persona vigentes, asi que se simula `redundancia` contra cada uno y se
    une lo que ya podia (la propuesta sobra si entre todos lo cubren).

    `roles` son esos roles ya listados (el orquestador los lee una vez por
    solicitud para el tope y los pasa aqui); si no vienen, se listan con
    `personas.roles_vigentes`. `vence_nuevo` es cuando vencera el permiso
    pedido: un rol que vence ANTES no lo hace redundante (la persona se
    quedaria sin permiso entre las dos horas), asi que solo se compara contra
    los que vencen a la misma hora o despues. `roles_comparados` son los ARN
    contra los que de verdad se simulo.

    El contexto de cada simulacion lleva `aws:CurrentTime` (la hora de
    `ahora` en `FORMATO_VENCE`, porque la politica de esos roles caduca con
    esa clave y sin ella el simulador deniega todo, MEDICIONES A.3) y
    `aws:PrincipalArn` con el ARN del rol que se simula, no el del rol
    previsto para esta solicitud.

    La duda cae del lado de conceder con aprobacion (diseno 5.4.3): si no se
    pueden listar los roles, todo es acceso nuevo y `no_comprobada` dice por
    que, para que el aprobador lo sepa. Declarar redundante por un error de
    lectura dejaria sin permiso a quien lo necesita. Sin roles que comparar
    no hay duda: `roles_comparados` queda vacio y nada es redundante.
    """
    total = {accion for acciones, _, _ in _por_statement(documento) for accion in acciones}
    if roles is None:
        try:
            roles = personas.roles_vigentes(usuario, ahora)
        except (ClientError, BotoCoreError) as e:
            return {
                "ya_tenia": [],
                "acceso_nuevo": sorted(total),
                "es_totalmente_redundante": False,
                "roles_comparados": [],
                "no_comprobada": f"{type(e).__name__}: {e}",
            }

    if vence_nuevo is not None:
        limite = personas.vence_como_fecha(vence_nuevo)
        if limite is None:
            raise ValueError(f"vence_nuevo no tiene el formato {personas.FORMATO_VENCE}: {vence_nuevo!r}")
        # Un vencimiento ilegible no cubre nada: la duda no declara redundante.
        roles = [
            r
            for r in roles
            if (fecha := personas.vence_como_fecha(r.get("vence", ""))) is not None
            and fecha >= limite
        ]

    ya: set[str] = set()
    comparados: list[str] = []
    for rol in roles:
        contexto_del_rol = {
            **(contexto or {}),
            "aws:CurrentTime": ahora.strftime(FORMATO_VENCE),
            "aws:PrincipalArn": rol["arn"],
        }
        ya |= set(redundancia(rol["arn"], documento, contexto_del_rol)["ya_tenia"])
        comparados.append(rol["arn"])

    nuevas = sorted(total - ya)
    return {
        "ya_tenia": sorted(total & ya),
        "acceso_nuevo": nuevas,
        "es_totalmente_redundante": bool(total) and not nuevas,
        "roles_comparados": comparados,
        "no_comprobada": None,
    }
