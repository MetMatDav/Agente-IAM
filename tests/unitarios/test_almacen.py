"""El almacen: los dos backends y la trampa que separa uno del otro.

Ninguno de estos tests toca la red. El de DynamoDB usa `Stubber` sobre el
cliente que hay debajo del recurso, y `expected_params` verifica que la
condicion viaja de verdad — que es lo unico que distingue una escritura
protegida de una que se cree protegida.
"""

import json
import re
from pathlib import Path

import boto3
import pytest
import yaml
from boto3.dynamodb.types import TypeSerializer
from botocore.stub import ANY, Stubber

from agente_iam import almacen, huella
from tests.dobles import sentencias_de_rol

_SERIALIZADOR = TypeSerializer()
_RAIZ = Path(__file__).resolve().parents[2]


def _cable(item: dict) -> dict:
    """El item en formato de cable ({"S": ...}), que es el que ve el cliente.

    `Stubber` intercepta al nivel del CLIENTE, no del recurso: el recurso
    serializa antes de llamar. Asi que las respuestas del doble hay que
    darlas ya serializadas, y se hace con el serializador de boto3 en vez
    de a mano para que el test no dependa de nuestra idea del formato.
    """
    return {k: _SERIALIZADOR.serialize(v) for k, v in item.items()}


def _registro(**extra) -> dict:
    """Un registro con los tipos que de verdad aparecen: str, int, bool,
    None, dict y list. Ni un float, que es la premisa de `huella.py`."""
    base = {
        "id": "req-prueba",
        "creada": "2026-08-31T00:00:00+00:00",
        "estado": "propuesta",
        "intentos": 2,
        "solicitud": {"campos": {"servicio": "s3", "region": "us-east-1"}},
        "identidad_verificada": {
            "principal_arn": "arn:aws:iam::111122223333:user/jose.torres",
            "existe": True,
            "principal_id": "AIDAEXAMPLE",
            "detalle": None,
            "politicas_actuales": ["AmazonBedrockReadOnly"],
        },
        "exige_confirmacion_de_riesgo": False,
    }
    base.update(extra)
    return base


@pytest.fixture
def dynamo(monkeypatch):
    """Un `almacen` apuntando a un DynamoDB stubeado."""
    recurso = boto3.resource("dynamodb", region_name="us-east-1")
    tabla = recurso.Table("agente-iam-solicitudes")
    stub = Stubber(tabla.meta.client)
    stub.activate()
    monkeypatch.setattr(almacen, "ALMACEN", "dynamodb")
    monkeypatch.setattr(almacen, "_tabla", tabla)
    yield stub
    stub.deactivate()


def _fila(registro: dict) -> dict:
    """La fila tal como queda en la tabla tras el intake y las decisiones."""
    fila = {"id": registro["id"], "documento": almacen._documento(registro), "estado": registro["estado"]}
    for bloque in almacen.BLOQUES:
        if bloque in registro:
            fila[bloque] = json.dumps(registro[bloque], ensure_ascii=False)
    return fila


# ---------------------------------------------------------------------------
# La trampa del Decimal: por que cada parte se guarda como cadena
# ---------------------------------------------------------------------------


def test_la_huella_sobrevive_al_viaje_de_ida_y_vuelta(dynamo):
    """El test que importa.

    DynamoDB no tiene float: si el registro se guardara descompuesto en un
    mapa, `"intentos": 2` volveria como `Decimal('2')` y `huella.calcular`
    —que hace `json.dumps` sobre el registro— daria otro resultado o
    reventaria. La huella dejaria de cuadrar por el ROUND-TRIP y no por
    manipulacion, que es el peor fallo posible: parece manipulacion.

    Desde el 24-10-2026 la fila tiene varias partes (documento, estado y
    bloques): la lectura las recompone y el registro tiene que salir igual.
    """
    original = _registro(estado="aprobada", aprobacion={"cuando": "ya", "huella": "sha256:x", "n": 1})
    esperada = huella.calcular(original)

    dynamo.add_response(
        "get_item",
        {"Item": _cable(_fila(original))},
        {"TableName": ANY, "Key": ANY, "ConsistentRead": True},
    )
    leido = almacen.leer("req-prueba")

    assert leido == original
    assert huella.calcular(leido) == esperada
    assert isinstance(leido["intentos"], int)  # int, no Decimal
    assert isinstance(leido["aprobacion"]["n"], int)


def test_el_documento_no_lleva_ni_el_estado_ni_las_decisiones():
    """Una sola fuente por dato: el estado vive en su atributo y cada
    decision en el suyo, no repetidos dentro del documento."""
    documento = json.loads(almacen._documento(_registro(aprobacion={"cuando": "ya"})))
    assert documento["intentos"] == 2
    assert "estado" not in documento
    assert "aprobacion" not in documento


# ---------------------------------------------------------------------------
# Las escrituras: siempre UpdateItem, cada una con sus atributos y su
# condicion. `expected_params` exacto, porque es lo unico que separa una
# escritura protegida de una que se cree protegida. Un PutItem haria
# fallar el Stubber: no hay respuesta preparada para el.
# ---------------------------------------------------------------------------


def test_el_intake_escribe_documento_y_estado_solo_si_la_fila_no_existe(dynamo):
    """S6 (24-10-2026): la condicion es `attribute_not_exists(id)`. Hasta
    esa fecha era "no esta en un estado decidido" y el intake pisaba
    `propuesta`, `requiere_revision_humana`, `error`... borrando el rastro
    de la corrida anterior."""
    registro = _registro()
    dynamo.add_response(
        "update_item",
        {},
        {
            "TableName": ANY,
            "Key": {"id": "req-prueba"},
            "UpdateExpression": "SET documento = :documento, estado = :estado",
            "ConditionExpression": "attribute_not_exists(id)",
            "ExpressionAttributeValues": {
                ":documento": almacen._documento(registro),
                ":estado": "propuesta",
            },
        },
    )
    almacen.guardar_propuesta(registro)
    dynamo.assert_no_pending_responses()


def test_el_intake_no_acepta_un_registro_con_decision(dynamo):
    with pytest.raises(ValueError, match="no escribe decisiones"):
        almacen.guardar_propuesta(_registro(aprobacion={"cuando": "ya"}))


@pytest.mark.parametrize("bloque,condicion", [
    ("aprobacion", "estado = :esperado AND attribute_not_exists(aprobacion) AND attribute_not_exists(rechazo)"),
    ("rechazo", "estado = :esperado AND attribute_not_exists(aprobacion) AND attribute_not_exists(rechazo)"),
    ("aplicacion", "estado = :esperado AND attribute_not_exists(aplicacion)"),
])
def test_una_decision_escribe_solo_su_bloque_y_el_estado(dynamo, bloque, condicion):
    """Ni el documento ni otro bloque: aunque la propuesta haya cambiado en
    memoria, de aqui no sale."""
    registro = _registro(estado="nuevo", **{bloque: {"cuando": "ya"}})
    registro["propuesta"] = {"reescrita": True}
    dynamo.add_response(
        "update_item",
        {},
        {
            "TableName": ANY,
            "Key": {"id": "req-prueba"},
            "UpdateExpression": f"SET {bloque} = :{bloque}, estado = :estado",
            "ConditionExpression": condicion,
            "ExpressionAttributeValues": {
                f":{bloque}": json.dumps({"cuando": "ya"}),
                ":estado": "nuevo",
                ":esperado": "leido",
            },
        },
    )
    almacen.guardar_decision(registro, bloque, "leido", clave="req-prueba")
    dynamo.assert_no_pending_responses()


def test_un_bloque_que_no_es_de_decision_no_se_escribe(dynamo):
    with pytest.raises(ValueError, match="no es un bloque de decision"):
        almacen.guardar_decision(_registro(), "documento", "propuesta", clave="req-prueba")


_PALABRAS = {"SET", "AND", "OR", "NOT", "IN", "attribute_exists", "attribute_not_exists"}


def _atributos_nombrados(*expresiones: str) -> set[str]:
    nombres = set()
    for expresion in expresiones:
        for token in re.findall(r":?[A-Za-z_]+", expresion):
            if not token.startswith(":") and token not in _PALABRAS:
                nombres.add(token)
    return nombres


def _permitidos_al_aprobador() -> set[str]:
    """Quien escribe la decision es el rol de la Lambda de aprobacion (ADR-003,
    24-10-2026), no el permission set de la persona, que solo lee."""
    plantilla = yaml.safe_load((_RAIZ / "infra/cfn/base.yaml").read_text())
    [st] = [
        s for s in sentencias_de_rol(plantilla, "RolAprobacion")
        if s["Sid"] == "EscribirSoloLaDecision"
    ]
    return set(st["Condition"]["ForAllValues:StringEquals"]["dynamodb:Attributes"])


@pytest.mark.parametrize("bloque", ["aprobacion", "rechazo"])
def test_lo_que_escribe_el_aprobador_cabe_en_su_permission_set(dynamo, monkeypatch, bloque):
    """El rol de la Lambda de aprobacion (`AgenteIAM-Aprobacion`, el que
    escribe la decision desde ADR-003) solo deja UpdateItem de unos atributos. Si este codigo nombrara otro, en la cuenta
    seria un AccessDenied. Se cuentan tambien los de la condicion, porque
    la guia no aclara si `dynamodb:Attributes` los incluye."""
    llamadas: list[dict] = []
    monkeypatch.setattr(almacen._tabla, "update_item", lambda **kw: llamadas.append(kw) or {})
    almacen.guardar_decision(_registro(**{bloque: {"cuando": "ya"}}), bloque, "propuesta", clave="req-prueba")
    [kw] = llamadas
    nombres = _atributos_nombrados(kw["UpdateExpression"], kw["ConditionExpression"]) | set(kw["Key"])
    assert nombres <= _permitidos_al_aprobador()
    assert "documento" not in nombres
    assert "aplicacion" not in nombres


def test_cada_actor_nombra_solo_sus_atributos():
    """El reparto que llevaran los roles de la pila base: runtime
    {documento, estado}, aplicador {aplicacion, estado}."""
    intake = _atributos_nombrados(
        "SET documento = :documento, estado = :estado",
        almacen._CONDICION_INTAKE,
    )
    # `id` es la clave: el runtime la nombra en la condicion (S6) y ya va
    # en su `dynamodb:Attributes` (id, documento, estado).
    assert intake == {"documento", "estado", "id"}
    assert _atributos_nombrados("SET aplicacion = :aplicacion, estado = :estado",
                                almacen._CONDICION["aplicacion"]) == {"aplicacion", "estado"}


def test_condicion_incumplida_en_el_intake_es_RegistroExistente(dynamo):
    dynamo.add_client_error("update_item", "ConditionalCheckFailedException")
    with pytest.raises(almacen.RegistroExistente):
        almacen.guardar_propuesta(_registro())


def test_condicion_incumplida_en_una_decision_es_EstadoCambiado(dynamo):
    dynamo.add_client_error("update_item", "ConditionalCheckFailedException")
    with pytest.raises(almacen.EstadoCambiado):
        almacen.guardar_decision(_registro(estado="aprobada", aprobacion={}), "aprobacion", "propuesta",
                                 clave="req-prueba")


def test_otros_errores_de_dynamo_no_se_disfrazan(dynamo):
    """Un fallo de permisos NO puede salir como 'ya estaba aprobada'.

    Traducir cualquier ClientError al error de negocio contaria una historia
    falsa: el operador buscaria una aprobacion que no existe en vez de
    mirar el rol. Solo se traduce la condicion incumplida.
    """
    from botocore.exceptions import ClientError

    dynamo.add_client_error("update_item", "AccessDeniedException")
    with pytest.raises(ClientError):
        almacen.guardar_propuesta(_registro())


def test_la_lectura_es_fuertemente_consistente(dynamo):
    """Con lectura eventual, el aplicador podria leer el registro de ANTES
    de la aprobacion que acaba de escribirse y concluir que no esta
    aprobado. En un flujo de permisos, actuar sobre el pasado no vale."""
    dynamo.add_response(
        "get_item",
        {"Item": _cable(_fila(_registro()))},
        # Asimetria de `Stubber` con recursos, y conviene saberla: los
        # PARAMETROS se comprueban antes de serializar (formato Python) y la
        # RESPUESTA se valida contra el shape del cliente (formato de cable).
        {"TableName": ANY, "Key": {"id": "req-prueba"}, "ConsistentRead": True},
    )
    almacen.leer("req-prueba")
    dynamo.assert_no_pending_responses()


def test_lo_que_no_existe_es_None_y_no_un_dict_vacio(dynamo):
    dynamo.add_response("get_item", {}, {"TableName": ANY, "Key": ANY,
                                         "ConsistentRead": True})
    assert almacen.leer("req-inexistente") is None


# ---------------------------------------------------------------------------
# El limite de tamano
# ---------------------------------------------------------------------------


def test_un_registro_demasiado_grande_falla_diciendo_por_que(dynamo):
    """El limite de 400 KB tiene que salir como un mensaje que se entiende,
    no como un ValidationException opaco justo despues de haber gastado una
    corrida entera del modelo. Y no se guarda truncado: un registro de
    auditoria incompleto es peor que ninguno."""
    enorme = _registro(historial_validacion=["x" * 500_000])
    with pytest.raises(ValueError, match="limite de un item"):
        almacen.guardar_propuesta(enorme)


# ---------------------------------------------------------------------------
# El backend de disco: la misma intencion, garantia distinta
# ---------------------------------------------------------------------------


def test_en_disco_un_json_corrupto_tampoco_se_pisa(tmp_path, monkeypatch):
    """Hasta el 24-10-2026 un fichero ilegible contaba como vacio y el
    intake escribia encima (este test afirmaba eso). Desde S6 el intake no
    pisa nada: un fichero que no se puede leer es evidencia de la que no se
    sabe que decia, y se queda como esta."""
    monkeypatch.setattr(almacen, "ALMACEN", "disco")
    monkeypatch.setattr(almacen, "DIR_SOLICITUDES", str(tmp_path))
    (tmp_path / "req-prueba.json").write_text("{ esto no es json")

    with pytest.raises(almacen.RegistroExistente):
        almacen.guardar_propuesta(_registro())
    assert (tmp_path / "req-prueba.json").read_text() == "{ esto no es json"


@pytest.fixture
def disco(tmp_path, monkeypatch):
    monkeypatch.setattr(almacen, "ALMACEN", "disco")
    monkeypatch.setattr(almacen, "DIR_SOLICITUDES", str(tmp_path))
    return tmp_path


def test_en_disco_la_decision_no_reescribe_la_propuesta(disco):
    """La misma propiedad que en DynamoDB: del registro en memoria solo
    viajan el bloque y el estado."""
    almacen.guardar_propuesta(_registro())
    en_memoria = _registro(estado="aprobada", aprobacion={"cuando": "ya"})
    en_memoria["identidad_verificada"] = {"principal_arn": "otro"}
    almacen.guardar_decision(en_memoria, "aprobacion", "propuesta", clave="req-prueba")
    guardado = json.loads((disco / "req-prueba.json").read_text())
    assert guardado["identidad_verificada"]["principal_arn"].endswith("user/jose.torres")
    assert guardado["aprobacion"] == {"cuando": "ya"}
    assert guardado["estado"] == "aprobada"


def test_en_disco_aprobar_y_rechazar_se_excluyen(disco):
    almacen.guardar_propuesta(_registro())
    almacen.guardar_decision(_registro(estado="aprobada", aprobacion={"cuando": "ya"}), "aprobacion", "propuesta",
                             clave="req-prueba")
    with pytest.raises(almacen.EstadoCambiado):
        # Aunque alguien devolviera el estado a 'propuesta', el bloque ya esta.
        almacen.guardar_decision(_registro(estado="rechazada_por_aprobador", rechazo={"motivo": "no"}),
                                 "rechazo", "aprobada", clave="req-prueba")


def test_en_disco_el_intake_no_pisa_un_estado_decidido(disco):
    almacen.guardar_propuesta(_registro())
    almacen.guardar_decision(_registro(estado="rechazada_por_aprobador", rechazo={"motivo": "no"}),
                             "rechazo", "propuesta", clave="req-prueba")
    with pytest.raises(almacen.RegistroExistente):
        almacen.guardar_propuesta(_registro())


@pytest.mark.parametrize("estado", [
    "propuesta", "requiere_revision_humana", "error", "redundante_no_requiere_cambio",
    "rechazada_en_chequeos_previos", "aprobada", "aplicada", "rechazada_por_aprobador",
])
def test_en_disco_el_intake_no_pisa_ningun_registro(disco, estado):
    """S6: en cualquier estado. Hasta el 24-10-2026 solo los decididos se
    salvaban; un `requiere_revision_humana` con el intento de inyeccion
    anotado se borraba reenviando una solicitud limpia con el mismo id."""
    anterior = _registro(estado=estado, riesgo_minimo=["la justificacion pide acciones de IAM"])
    (disco / "req-prueba.json").write_text(json.dumps(anterior))
    with pytest.raises(almacen.RegistroExistente):
        almacen.guardar_propuesta(_registro())
    assert json.loads((disco / "req-prueba.json").read_text()) == anterior


def test_en_disco_no_se_decide_sobre_lo_que_no_existe(disco):
    with pytest.raises(almacen.EstadoCambiado, match="no existe"):
        almacen.guardar_decision(_registro(estado="aprobada", aprobacion={}), "aprobacion", "propuesta",
                                 clave="req-prueba")


# ---------------------------------------------------------------------------
# S1 (24-10-2026): cada parte sale de su atributo, y la clave manda
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("intrusa", ["aprobacion", "rechazo", "aplicacion", "estado"])
def test_un_documento_con_un_bloque_o_el_estado_no_se_lee(dynamo, intrusa):
    """El `documento` lo escribe el runtime. Si trae su propia `aprobacion`
    (con la huella, que cualquiera calcula) y la fila no tiene el atributo,
    hasta el 24-10-2026 el registro leido la llevaba igual y el aplicador la
    daba por buena: el runtime aprobaba sin humano."""
    registro = _registro(estado="aprobada")
    documento = json.loads(almacen._documento(registro))
    documento[intrusa] = {"huella": huella.calcular(registro)} if intrusa != "estado" else "aprobada"
    fila = {"id": "req-prueba", "documento": json.dumps(documento), "estado": "aprobada"}
    dynamo.add_response("get_item", {"Item": _cable(fila)},
                        {"TableName": ANY, "Key": ANY, "ConsistentRead": True})
    with pytest.raises(almacen.RegistroInconsistente, match=intrusa):
        almacen.leer("req-prueba")


def test_un_documento_con_otro_id_no_se_lee(dynamo):
    """Variante de S1: con `documento.id` distinto de la clave, una decision
    sobre `req-prueba` acababa escrita en la fila del otro id."""
    fila = _fila(_registro())
    fila["documento"] = almacen._documento(_registro(id="victima"))
    dynamo.add_response("get_item", {"Item": _cable(fila)},
                        {"TableName": ANY, "Key": ANY, "ConsistentRead": True})
    with pytest.raises(almacen.RegistroInconsistente, match="victima"):
        almacen.leer("req-prueba")


def test_la_decision_se_escribe_en_la_clave_leida_y_en_ninguna_otra(dynamo, monkeypatch):
    """La clave de la escritura es la que se leyo, no `registro["id"]`. Si
    no coinciden no se escribe nada: el Stubber no tiene respuestas, asi que
    cualquier UpdateItem haria fallar el test."""
    llamadas: list[dict] = []
    monkeypatch.setattr(almacen._tabla, "update_item", lambda **kw: llamadas.append(kw) or {})
    otro = _registro(id="victima", estado="aprobada", aprobacion={"cuando": "ya"})
    with pytest.raises(almacen.RegistroInconsistente):
        almacen.guardar_decision(otro, "aprobacion", "propuesta", clave="req-prueba")
    assert llamadas == []
    almacen.guardar_decision(_registro(estado="aprobada", aprobacion={"cuando": "ya"}),
                             "aprobacion", "propuesta", clave="req-prueba")
    assert [kw["Key"] for kw in llamadas] == [{"id": "req-prueba"}]


def test_en_disco_un_fichero_con_otro_id_no_se_lee(disco):
    (disco / "req-prueba.json").write_text(json.dumps(_registro(id="victima")))
    with pytest.raises(almacen.RegistroInconsistente):
        almacen.leer("req-prueba")


def test_describir_dice_que_backend_esta_activo(monkeypatch, tmp_path):
    """Dos backends sin senal de cual esta activo invitan a mirar el disco
    mientras el agente escribe en la nube."""
    monkeypatch.setattr(almacen, "ALMACEN", "dynamodb")
    assert "DynamoDB" in almacen.describir()

    monkeypatch.setattr(almacen, "ALMACEN", "disco")
    monkeypatch.setattr(almacen, "DIR_SOLICITUDES", str(tmp_path))
    assert str(tmp_path) in almacen.describir()


@pytest.mark.parametrize("fila", [
    # Un UpdateItem sobre un id que no existe CREA la fila: con la CLI, el
    # permission set del aprobador puede dejar una sin `documento` (Fase 18,
    # mapa del flujo por la tabla). Hasta el 24-10-2026 eso era un KeyError.
    {"id": "req-prueba", "estado": "aprobada", "aprobacion": json.dumps({"huella": "sha256:x"})},
    {"id": "req-prueba", "documento": json.dumps({"id": "req-prueba"})},
], ids=["sin-documento", "sin-estado"])
def test_una_fila_a_medio_crear_es_inconsistente(dynamo, fila):
    dynamo.add_response("get_item", {"Item": _cable(fila)},
                        {"TableName": ANY, "Key": ANY, "ConsistentRead": True})
    with pytest.raises(almacen.RegistroInconsistente):
        almacen.leer("req-prueba")
