"""Fase 28, punto 3: el recurso se busca en la cuenta antes de llamar al modelo.

`existencia.comprobar` con `Stubber` por servicio: cada servicio responde
`existe` si esta, `no_existe` con su error de "no encontrado" y `no_comprobado`
con cualquier otro error (un AccessDenied no puede convertirse en "no existe" ni
en "existe"). Y el orquestador: con `no_existe` no se llama al modelo y el
registro lleva el codigo `recurso_no_encontrado`; con `no_comprobado` se sigue y
la duda queda para el aprobador. Se ponen en rojo si S3 acepta un bucket que no
esta en la lista de la cuenta, si Lambda pide la configuracion (trae variables
de entorno) o si un fallo de la comprobacion rechaza la solicitud.
"""

import boto3
import pytest
from botocore.stub import Stubber

from agente_iam import existencia

CUENTA = "111122223333"
REGION = "us-east-1"


class _Fabrica:
    """Crea un cliente por servicio, ya envuelto en un Stubber que el test programa."""

    def __init__(self):
        self.clientes: dict[str, object] = {}
        self.stubs: dict[str, Stubber] = {}

    def stub(self, servicio: str) -> Stubber:
        cliente = boto3.client(servicio, region_name=REGION)
        self.clientes[servicio] = cliente
        self.stubs[servicio] = Stubber(cliente)
        self.stubs[servicio].activate()
        return self.stubs[servicio]

    def __call__(self, servicio: str, region: str):
        assert region == REGION
        return self.clientes[servicio]


@pytest.fixture
def fabrica():
    f = _Fabrica()
    yield f
    for s in f.stubs.values():
        s.assert_no_pending_responses()


def _comprobar(fabrica, servicio, nombre):
    return existencia.comprobar(servicio, nombre, REGION, CUENTA, crear_cliente=fabrica)


def test_s3_existe_solo_si_esta_entre_los_buckets_de_la_cuenta(fabrica):
    fabrica.stub("s3").add_response("list_buckets", {"Buckets": [{"Name": "finanzas-2026"}, {"Name": "otro"}]})
    assert _comprobar(fabrica, "s3", "finanzas-2026") == ("existe", "")


def test_s3_un_bucket_que_no_esta_en_la_lista_no_existe(fabrica):
    fabrica.stub("s3").add_response("list_buckets", {"Buckets": [{"Name": "otro"}]})
    assert _comprobar(fabrica, "s3", "bucket-de-ejemplo") == ("no_existe", "")


def test_dynamodb_existe_y_no_existe(fabrica):
    s = fabrica.stub("dynamodb")
    s.add_response("describe_table", {"Table": {"TableName": "Ventas"}}, {"TableName": "Ventas"})
    s.add_client_error("describe_table", "ResourceNotFoundException", expected_params={"TableName": "Nada"})
    assert _comprobar(fabrica, "dynamodb", "Ventas") == ("existe", "")
    assert _comprobar(fabrica, "dynamodb", "Nada") == ("no_existe", "")


def test_lambda_pide_las_etiquetas_y_no_la_configuracion(fabrica):
    s = fabrica.stub("lambda")
    arn = f"arn:aws:lambda:{REGION}:{CUENTA}:function:cobros"
    s.add_response("list_tags", {"Tags": {}}, {"Resource": arn})
    s.add_client_error("list_tags", "ResourceNotFoundException")
    assert _comprobar(fabrica, "lambda", "cobros") == ("existe", "")
    assert _comprobar(fabrica, "lambda", "nada") == ("no_existe", "")


def test_sqs_busca_la_cola_de_esta_cuenta(fabrica):
    s = fabrica.stub("sqs")
    s.add_response(
        "get_queue_url",
        {"QueueUrl": f"https://sqs.{REGION}.amazonaws.com/{CUENTA}/pedidos"},
        {"QueueName": "pedidos", "QueueOwnerAWSAccountId": CUENTA},
    )
    s.add_client_error("get_queue_url", "AWS.SimpleQueueService.NonExistentQueue")
    assert _comprobar(fabrica, "sqs", "pedidos") == ("existe", "")
    assert _comprobar(fabrica, "sqs", "nada") == ("no_existe", "")


def test_sns_arma_el_arn_con_la_cuenta_y_la_region(fabrica):
    s = fabrica.stub("sns")
    s.add_response("get_topic_attributes", {"Attributes": {}}, {"TopicArn": f"arn:aws:sns:{REGION}:{CUENTA}:alertas"})
    s.add_client_error("get_topic_attributes", "NotFound")
    assert _comprobar(fabrica, "sns", "alertas") == ("existe", "")
    assert _comprobar(fabrica, "sns", "nada") == ("no_existe", "")


def test_logs_exige_el_nombre_exacto_y_no_un_prefijo(fabrica):
    s = fabrica.stub("logs")
    s.add_response("describe_log_groups", {"logGroups": [{"logGroupName": "/app/pagos-viejo"}]}, {"logGroupNamePrefix": "/app/pagos"})
    s.add_response("describe_log_groups", {"logGroups": [{"logGroupName": "/app/pagos"}]}, {"logGroupNamePrefix": "/app/pagos"})
    assert _comprobar(fabrica, "logs", "/app/pagos") == ("no_existe", "")
    assert _comprobar(fabrica, "logs", "/app/pagos") == ("existe", "")


def test_cloudwatch_busca_la_alarma_por_nombre(fabrica):
    s = fabrica.stub("cloudwatch")
    s.add_response("describe_alarms", {"MetricAlarms": [{"AlarmName": "cpu-alta"}]}, {"AlarmNames": ["cpu-alta"]})
    s.add_response("describe_alarms", {"MetricAlarms": [], "CompositeAlarms": []}, {"AlarmNames": ["nada"]})
    assert _comprobar(fabrica, "cloudwatch", "cpu-alta") == ("existe", "")
    assert _comprobar(fabrica, "cloudwatch", "nada") == ("no_existe", "")


@pytest.mark.parametrize("servicio", ["dynamodb", "lambda", "sqs", "sns"])
def test_un_permiso_denegado_no_es_ni_existe_ni_no_existe(fabrica, servicio):
    operacion = {"dynamodb": "describe_table", "lambda": "list_tags", "sqs": "get_queue_url", "sns": "get_topic_attributes"}
    fabrica.stub(servicio).add_client_error(operacion[servicio], "AccessDeniedException")
    assert _comprobar(fabrica, servicio, "x") == ("no_comprobado", "AccessDeniedException")


def test_ec2_no_tiene_recurso_que_comprobar():
    assert existencia.comprobar("ec2", "todas-las-instancias", REGION, CUENTA, crear_cliente=lambda *_: None) == ("no_aplica", "")


def test_en_unitarios_y_seguridad_la_comprobacion_esta_apagada():
    """`tests/conftest.py` la apaga: sin esto el orquestador saldria a AWS en cada test."""
    assert existencia.activa() is False


def test_fuera_de_los_tests_esta_encendida(monkeypatch):
    monkeypatch.delenv("AGENTE_IAM_COMPROBAR_EXISTENCIA")
    assert existencia.activa() is True
