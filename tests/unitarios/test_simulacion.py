"""Fase 5: el simulador recibe contexto y reporta lo que no pudo resolver.

Con Stubber otra vez, y aqui `expected_params` hace el trabajo importante:
no basta con que el codigo no falle — hay que probar que las
ContextEntries VIAJAN, con su nombre, su valor y su tipo.
"""

import json
from datetime import datetime, timezone

import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from agente_iam import personas, simulacion
from tests.dobles import _cliente

_ARN = "arn:aws:iam::111122223333:user/ana.gomez"

_CONTEXTO = {
    "aws:RequestedRegion": "us-east-1",
    "aws:PrincipalAccount": "111122223333",
    "aws:PrincipalArn": _ARN,
}

_ENTRIES = [
    {
        "ContextKeyName": "aws:RequestedRegion",
        "ContextKeyValues": ["us-east-1"],
        "ContextKeyType": "string",
    },
    {
        "ContextKeyName": "aws:PrincipalAccount",
        "ContextKeyValues": ["111122223333"],
        "ContextKeyType": "string",
    },
    {
        "ContextKeyName": "aws:PrincipalArn",
        "ContextKeyValues": [_ARN],
        "ContextKeyType": "string",
    },
]

_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::finanzas-2026/*"],
            "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
        }
    ],
}


@pytest.fixture
def iam(monkeypatch):
    cliente = _cliente("iam")
    stub = Stubber(cliente)
    monkeypatch.setattr(simulacion, "_cliente", cliente)
    with stub:
        yield stub
        stub.assert_no_pending_responses()


def _params(**extra) -> dict:
    base = {
        "PolicyInputList": [json.dumps(_DOC)],
        "ActionNames": ["s3:GetObject"],
        "ResourceArns": ["arn:aws:s3:::finanzas-2026/*"],
    }
    base.update(extra)
    return base


def _resultado(decision="allowed", faltan_arriba=None, faltan_por_recurso=None):
    r = {
        "EvalActionName": "s3:GetObject",
        "EvalDecision": decision,
        "MissingContextValues": faltan_arriba or [],
    }
    if faltan_por_recurso is not None:
        r["ResourceSpecificResults"] = [
            {
                "EvalResourceName": "arn:aws:s3:::finanzas-2026/objeto.csv",
                "EvalResourceDecision": decision,
                "MissingContextValues": faltan_por_recurso,
            }
        ]
    return r


# ---------------------------------------------------------------------------
# Lo esencial: el contexto viaja.
# ---------------------------------------------------------------------------


def test_las_context_entries_viajan_con_su_tipo(iam):
    # _DOC condiciona con aws:RequestedRegion, que SI se aporta: la condicion
    # se evaluo de verdad y no genera duda. (Hasta el 22-10-2026 esto era
    # ademas `test_clave_aportada_no_genera_duda`, con la misma entrada.)
    iam.add_response(
        "simulate_custom_policy",
        {"EvaluationResults": [_resultado()]},
        _params(ContextEntries=_ENTRIES),
    )
    r = simulacion.eficacia(_DOC, _CONTEXTO)
    assert r["acciones_efectivas"] == ["s3:GetObject"]
    assert r["acciones_condicionales"] == []


def test_sin_contexto_no_se_manda_el_parametro(iam):
    # Compatibilidad: sin contexto, la llamada es la de antes.
    iam.add_response(
        "simulate_custom_policy", {"EvaluationResults": [_resultado()]}, _params()
    )
    assert simulacion.eficacia(_DOC)["concede_algo"] is True


def test_clave_desconocida_no_se_aporta(iam):
    # aws:SourceIp no esta en la tabla de tipos: no se adivina su tipo.
    iam.add_response(
        "simulate_custom_policy",
        {"EvaluationResults": [_resultado()]},
        _params(
            ContextEntries=[
                {
                    "ContextKeyName": "aws:RequestedRegion",
                    "ContextKeyValues": ["us-east-1"],
                    "ContextKeyType": "string",
                }
            ]
        ),
    )
    simulacion.eficacia(
        _DOC, {"aws:RequestedRegion": "us-east-1", "aws:SourceIp": "1.2.3.4"}
    )


def test_valor_vacio_no_se_aporta(iam):
    iam.add_response(
        "simulate_custom_policy", {"EvaluationResults": [_resultado()]}, _params()
    )
    simulacion.eficacia(_DOC, {"aws:RequestedRegion": None})


# ---------------------------------------------------------------------------
# Las claves sin resolver se leen de los DOS sitios.
# ---------------------------------------------------------------------------


def test_faltantes_dentro_de_resource_specific_results(iam):
    # El detalle que la API documenta y que casi cuesta un bug: pasando
    # ResourceArns, las faltantes NO van en el campo de nivel superior.
    iam.add_response(
        "simulate_custom_policy",
        {
            "EvaluationResults": [
                _resultado(faltan_arriba=[], faltan_por_recurso=["aws:SourceIp"])
            ]
        },
        _params(ContextEntries=_ENTRIES),
    )
    r = simulacion.eficacia(_DOC, _CONTEXTO)
    assert r["acciones_condicionales"] == ["s3:GetObject"]
    assert r["claves_sin_resolver"] == ["aws:SourceIp"]
    assert r["acciones_efectivas"] == []
    # La asimetria, lado eficacia: la duda NO bloquea. Bloquear una politica
    # por una condicion que no supimos evaluar seria un falso positivo.
    # (Antes, `test_eficacia_la_duda_no_bloquea`, con la misma entrada.)
    assert r["concede_algo"] is True
    assert r["acciones_sin_efecto"] == []


def test_faltantes_en_el_nivel_superior_tambien_cuentan(iam):
    iam.add_response(
        "simulate_custom_policy",
        {"EvaluationResults": [_resultado(faltan_arriba=["aws:SourceIp"])]},
        _params(ContextEntries=_ENTRIES),
    )
    assert simulacion.eficacia(_DOC, _CONTEXTO)["claves_sin_resolver"] == [
        "aws:SourceIp"
    ]


# ---------------------------------------------------------------------------
# El hallazgo del 28-08-2026: el simulador puede CALLAR una clave faltante.
# La deteccion real la hace nuestro codigo, leyendo el documento.
# ---------------------------------------------------------------------------


def _doc_con_condicion(condicion: dict) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::finanzas-2026/*"],
                "Condition": condicion,
            }
        ],
    }


def _params_de(doc: dict, **extra) -> dict:
    base = {
        "PolicyInputList": [json.dumps(doc)],
        "ActionNames": ["s3:GetObject"],
        "ResourceArns": ["arn:aws:s3:::finanzas-2026/*"],
    }
    base.update(extra)
    return base


def test_condicion_sin_aportar_se_detecta_aunque_el_simulador_calle(iam):
    # El caso medido contra la cuenta real: con `aws:RequestedRegion` el
    # simulador usa la region de SU endpoint, asi que puede devolver
    # 'allowed' sin reportar nada aunque nadie haya aportado la clave. El
    # permiso parece verificado y no lo esta. Nuestra deteccion no depende
    # de que el simulador avise.
    doc = _doc_con_condicion({"StringEquals": {"aws:SourceIp": "10.0.0.1"}})
    iam.add_response(
        "simulate_custom_policy",
        {"EvaluationResults": [_resultado(faltan_por_recurso=[])]},
        _params_de(doc, ContextEntries=_ENTRIES),
    )
    r = simulacion.eficacia(doc, _CONTEXTO)
    assert r["acciones_condicionales"] == ["s3:GetObject"]
    assert r["claves_sin_resolver"] == ["aws:SourceIp"]
    assert r["acciones_efectivas"] == []
    assert r["concede_algo"] is True  # la duda no bloquea


def test_deny_por_falta_de_contexto_no_es_sin_efecto(iam):
    # Lo que revelaron las pruebas 4 y 5: cuando le falta una clave, el
    # simulador DENIEGA y la reporta. Contar ese deny como "la politica no
    # concede nada" bloquearia una politica correcta y mandaria al agente
    # a corregir lo que no esta roto — el falso positivo de siempre.
    doc = _doc_con_condicion(
        {"StringEquals": {"aws:PrincipalTag/equipo": "finanzas"}}
    )
    iam.add_response(
        "simulate_custom_policy",
        {
            "EvaluationResults": [
                _resultado(
                    decision="implicitDeny",
                    faltan_arriba=["aws:PrincipalTag/equipo"],
                    faltan_por_recurso=["aws:PrincipalTag/equipo"],
                )
            ]
        },
        _params_de(doc, ContextEntries=_ENTRIES),
    )
    r = simulacion.eficacia(doc, _CONTEXTO)
    assert r["acciones_sin_efecto"] == []  # no se declara inutil
    assert r["acciones_condicionales"] == ["s3:GetObject"]
    assert r["concede_algo"] is True


def test_mayusculas_de_la_clave_no_importan(iam):
    # Los nombres de clave de condicion no distinguen mayusculas.
    doc = _doc_con_condicion(
        {"StringEquals": {"aws:requestedregion": "us-east-1"}}
    )
    iam.add_response(
        "simulate_custom_policy",
        {"EvaluationResults": [_resultado()]},
        _params_de(doc, ContextEntries=_ENTRIES),
    )
    assert simulacion.eficacia(doc, _CONTEXTO)["acciones_condicionales"] == []


def test_if_exists_no_es_una_duda(iam):
    # ...IfExists esta disenado para tolerar que la clave falte: si no
    # esta, la condicion no bloquea. No es incertidumbre.
    doc = _doc_con_condicion({"StringEqualsIfExists": {"aws:SourceIp": "10.0.0.1"}})
    iam.add_response(
        "simulate_custom_policy",
        {"EvaluationResults": [_resultado()]},
        _params_de(doc, ContextEntries=_ENTRIES),
    )
    assert simulacion.eficacia(doc, _CONTEXTO)["acciones_efectivas"] == [
        "s3:GetObject"
    ]


def test_prefijo_for_any_value_se_maneja(iam):
    doc = _doc_con_condicion(
        {"ForAnyValue:StringEquals": {"aws:PrincipalTag/equipo": "finanzas"}}
    )
    iam.add_response(
        "simulate_custom_policy",
        {"EvaluationResults": [_resultado()]},
        _params_de(doc, ContextEntries=_ENTRIES),
    )
    r = simulacion.eficacia(doc, _CONTEXTO)
    assert r["claves_sin_resolver"] == ["aws:PrincipalTag/equipo"]


def test_redundancia_ignora_las_condiciones_de_nuestro_documento(iam):
    # Nuestra propuesta concede s3:GetObject solo si SourceIp coincide.
    # El principal, segun el simulador, ya lo tiene sin condicion alguna.
    # Esta simulacion evalua las politicas DEL PRINCIPAL: las Condition de
    # nuestro documento no participan, y lo que el ya tiene cubre de sobra
    # lo que ibamos a darle. Es redundante, y decir lo contrario seria
    # tramitar una solicitud que no hace falta.
    doc = _doc_con_condicion({"StringEquals": {"aws:SourceIp": "10.0.0.1"}})
    iam.add_response(
        "simulate_principal_policy",
        {"EvaluationResults": [_resultado()]},
        {
            "PolicySourceArn": _ARN,
            "ActionNames": ["s3:GetObject"],
            "ResourceArns": ["arn:aws:s3:::finanzas-2026/*"],
            "ContextEntries": _ENTRIES,
        },
    )
    r = simulacion.redundancia(_ARN, doc, _CONTEXTO)
    assert r["ya_tenia"] == ["s3:GetObject"]
    assert r["es_totalmente_redundante"] is True
    # Es tambien el caso "sin dudas -> redundante" (antes
    # `test_redundancia_sin_dudas_si_declara_redundante`, mismo stub).


# ---------------------------------------------------------------------------
# La asimetria: la duda va en direccion opuesta en cada funcion. El lado de
# eficacia esta en `test_faltantes_dentro_de_resource_specific_results`.
# ---------------------------------------------------------------------------


def test_redundancia_la_duda_impide_declarar_redundante(iam):
    # Al reves que en eficacia: si no se probo que YA lo tenia, la
    # solicitud no sobra. Declararla redundante por error deja a alguien
    # sin su acceso.
    #
    # Esta es la respuesta REAL que devuelve la cuenta para ana.gomez
    # (medida 29-08-2026): implicitDeny, y de propina reporta
    # `aws:CalledViaLast`, que sale de un statement sobre SageMaker en
    # AmazonBedrockReadOnly y no tiene nada que ver con leer un bucket.
    # La accion cuenta como acceso nuevo, que es lo correcto — y esa
    # clave ajena no debe ensuciar el informe del aprobador.
    iam.add_response(
        "simulate_principal_policy",
        {
            "EvaluationResults": [
                _resultado(
                    decision="implicitDeny",
                    faltan_arriba=["aws:CalledViaLast"],
                    faltan_por_recurso=["aws:CalledViaLast"],
                )
            ]
        },
        {
            "PolicySourceArn": _ARN,
            "ActionNames": ["s3:GetObject"],
            "ResourceArns": ["arn:aws:s3:::finanzas-2026/*"],
            "ContextEntries": _ENTRIES,
        },
    )
    r = simulacion.redundancia(_ARN, _DOC, _CONTEXTO)
    assert r["es_totalmente_redundante"] is False
    assert r["ya_tenia"] == []
    assert r["acceso_nuevo"] == ["s3:GetObject"]
    assert "acciones_no_concluyentes" not in r
    assert "claves_sin_resolver" not in r


# ---------------------------------------------------------------------------
# Otros comportamientos que no deben cambiar.
# ---------------------------------------------------------------------------


def test_permitida_en_un_recurso_basta_aunque_el_agregado_deniegue(iam):
    """Con varios recursos, `EvalDecision` es el agregado PESIMISTA.

    Medido contra la cuenta (30-08-2026), misma accion y mismo principal:
    solo el ARN de objeto -> allowed; solo el de bucket -> implicitDeny;
    los dos juntos -> implicitDeny, y por recurso bucket=implicitDeny,
    bucket/*=allowed. O sea que el nivel superior deniega si deniega para
    alguno, y la verdad por recurso solo esta dentro.

    Importa porque en S3 `ListBucket` solo aplica al ARN del bucket y
    `GetObject` solo al del objeto, y el modelo a veces los funde en un
    statement con los dos ARNs. Leyendo el nivel superior, esa politica
    —correcta y util— saldria como que no concede nada.
    """
    iam.add_response(
        "simulate_custom_policy",
        {
            "EvaluationResults": [
                {
                    "EvalActionName": "s3:GetObject",
                    "EvalDecision": "implicitDeny",  # el agregado pesimista
                    "MissingContextValues": [],
                    "ResourceSpecificResults": [
                        {
                            "EvalResourceName": "arn:aws:s3:::finanzas-2026",
                            "EvalResourceDecision": "implicitDeny",
                            "MissingContextValues": [],
                        },
                        {
                            "EvalResourceName": "arn:aws:s3:::finanzas-2026/*",
                            "EvalResourceDecision": "allowed",
                            "MissingContextValues": [],
                        },
                    ],
                }
            ]
        },
        _params(ContextEntries=_ENTRIES),
    )
    r = simulacion.eficacia(_DOC, _CONTEXTO)
    assert r["acciones_efectivas"] == ["s3:GetObject"]
    assert r["concede_algo"] is True
    assert r["acciones_sin_efecto"] == []


def test_denegada_sigue_siendo_sin_efecto(iam):
    iam.add_response(
        "simulate_custom_policy",
        {"EvaluationResults": [_resultado(decision="implicitDeny")]},
        _params(ContextEntries=_ENTRIES),
    )
    r = simulacion.eficacia(_DOC, _CONTEXTO)
    assert r["concede_algo"] is False
    assert r["acciones_sin_efecto"] == ["s3:GetObject"]
    assert r["no_evaluable"] is False


def test_paginacion_recorre_todas_las_paginas(iam):
    iam.add_response(
        "simulate_custom_policy",
        {
            "EvaluationResults": [_resultado(decision="implicitDeny")],
            "IsTruncated": True,
            "Marker": "pagina-2",
        },
        _params(ContextEntries=_ENTRIES),
    )
    iam.add_response(
        "simulate_custom_policy",
        {"EvaluationResults": [_resultado()]},
        _params(ContextEntries=_ENTRIES, Marker="pagina-2"),
    )
    # La segunda pagina dice 'allowed': si no se leyera, la accion
    # quedaria marcada como sin efecto.
    assert simulacion.eficacia(_DOC, _CONTEXTO)["acciones_efectivas"] == [
        "s3:GetObject"
    ]


def test_documento_sin_allow_es_no_evaluable(iam):
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": ["s3:*"], "Resource": ["*"]}]}
    r = simulacion.eficacia(doc, _CONTEXTO)
    assert r["no_evaluable"] is True
    assert r["concede_algo"] is False


# --- Tarea 4: aws:CurrentTime y la redundancia por persona ------------------

_AHORA = datetime(2026, 10, 26, 3, 4, 51, tzinfo=timezone.utc)
_ARN_ROL = "arn:aws:iam::111122223333:role/agente-iam/personas/agente-iam-persona-ana-req-1"
_DOC_DOS = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": ["*"]}
    ],
}


def _vigente(arn: str = _ARN_ROL) -> dict:
    return {"arn": arn, "nombre": arn.rsplit("/", 1)[1], "vence": "2026-10-26T15:04:51Z", "solicitud_id": "req-1"}


def test_aws_current_time_viaja_como_date():
    entradas = simulacion._context_entries({"aws:CurrentTime": "2026-10-26T15:04:51Z"})
    assert entradas == [
        {
            "ContextKeyName": "aws:CurrentTime",
            "ContextKeyValues": ["2026-10-26T15:04:51Z"],
            "ContextKeyType": "date",
        }
    ]


def test_eficacia_de_un_documento_sin_vencimiento_no_manda_current_time(iam):
    # expected_params exacto, sin ContextEntries ni aws:CurrentTime: la
    # propuesta del modelo no lleva vencimiento (se anade al aplicar).
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::b/*"]}],
    }
    iam.add_response(
        "simulate_custom_policy",
        {
            "EvaluationResults": [
                {
                    "EvalActionName": "s3:GetObject",
                    "EvalDecision": "allowed",
                    "EvalResourceName": "arn:aws:s3:::b/*",
                }
            ],
            "IsTruncated": False,
        },
        {
            "PolicyInputList": [json.dumps(doc)],
            "ActionNames": ["s3:GetObject"],
            "ResourceArns": ["arn:aws:s3:::b/*"],
        },
    )

    r = simulacion.eficacia(doc)

    assert r["acciones_efectivas"] == ["s3:GetObject"]


def test_redundancia_persona_sin_roles_vigentes_no_es_redundante(monkeypatch):
    monkeypatch.setattr(personas, "roles_vigentes", lambda usuario, ahora, iam=None: [])
    monkeypatch.setattr(
        simulacion, "redundancia", lambda *a, **k: pytest.fail("no hay rol que simular")
    )

    r = simulacion.redundancia_persona("ana", _DOC_DOS, {"aws:RequestedRegion": "us-east-1"}, _AHORA)

    assert r == {
        "ya_tenia": [],
        "acceso_nuevo": ["s3:GetObject", "s3:ListBucket"],
        "es_totalmente_redundante": False,
        "roles_comparados": [],
        "no_comprobada": None,
    }


def test_redundancia_persona_con_un_rol_que_ya_lo_permite_todo(monkeypatch):
    monkeypatch.setattr(personas, "roles_vigentes", lambda usuario, ahora, iam=None: [_vigente()])
    monkeypatch.setattr(
        simulacion,
        "redundancia",
        lambda arn, doc, ctx=None: {
            "ya_tenia": ["s3:GetObject", "s3:ListBucket"],
            "acceso_nuevo": [],
            "es_totalmente_redundante": True,
        },
    )

    r = simulacion.redundancia_persona("ana", _DOC_DOS, None, _AHORA)

    assert r["es_totalmente_redundante"] is True
    assert r["ya_tenia"] == ["s3:GetObject", "s3:ListBucket"]
    assert r["acceso_nuevo"] == []
    assert r["roles_comparados"] == [_ARN_ROL]
    assert r["no_comprobada"] is None


def test_redundancia_persona_une_lo_que_tiene_cada_rol(monkeypatch):
    otro = _ARN_ROL.replace("req-1", "req-2")
    monkeypatch.setattr(
        personas, "roles_vigentes", lambda usuario, ahora, iam=None: [_vigente(), _vigente(otro)]
    )
    por_rol = {_ARN_ROL: ["s3:GetObject"], otro: ["s3:ListBucket"]}
    monkeypatch.setattr(
        simulacion,
        "redundancia",
        lambda arn, doc, ctx=None: {"ya_tenia": por_rol[arn], "acceso_nuevo": [], "es_totalmente_redundante": False},
    )

    r = simulacion.redundancia_persona("ana", _DOC_DOS, None, _AHORA)

    assert r["es_totalmente_redundante"] is True
    assert r["roles_comparados"] == [_ARN_ROL, otro]


def test_redundancia_persona_con_lo_parcial_deja_el_resto_como_nuevo(monkeypatch):
    monkeypatch.setattr(personas, "roles_vigentes", lambda usuario, ahora, iam=None: [_vigente()])
    monkeypatch.setattr(
        simulacion,
        "redundancia",
        lambda arn, doc, ctx=None: {"ya_tenia": ["s3:GetObject"], "acceso_nuevo": ["s3:ListBucket"], "es_totalmente_redundante": False},
    )

    r = simulacion.redundancia_persona("ana", _DOC_DOS, None, _AHORA)

    assert r["es_totalmente_redundante"] is False
    assert r["ya_tenia"] == ["s3:GetObject"]
    assert r["acceso_nuevo"] == ["s3:ListBucket"]


def test_redundancia_persona_manda_current_time_y_el_arn_del_rol_vigente(monkeypatch):
    recibidos = []

    def doble(arn, documento, contexto=None):
        recibidos.append((arn, contexto))
        return {"ya_tenia": [], "acceso_nuevo": [], "es_totalmente_redundante": False}

    monkeypatch.setattr(personas, "roles_vigentes", lambda usuario, ahora, iam=None: [_vigente()])
    monkeypatch.setattr(simulacion, "redundancia", doble)
    contexto = {"aws:RequestedRegion": "us-east-1", "aws:PrincipalArn": "arn:del:rol:previsto"}

    simulacion.redundancia_persona("ana", _DOC_DOS, contexto, _AHORA)

    assert recibidos == [
        (
            _ARN_ROL,
            {
                "aws:RequestedRegion": "us-east-1",
                "aws:CurrentTime": "2026-10-26T03:04:51Z",
                "aws:PrincipalArn": _ARN_ROL,
            },
        )
    ]
    assert contexto["aws:PrincipalArn"] == "arn:del:rol:previsto"  # no se muta la entrada


def test_si_no_se_pueden_listar_los_roles_todo_es_acceso_nuevo(monkeypatch):
    def falla(usuario, ahora, iam=None):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no puedes listar roles"}}, "ListRoles"
        )

    monkeypatch.setattr(personas, "roles_vigentes", falla)
    monkeypatch.setattr(simulacion, "redundancia", lambda *a, **k: pytest.fail("no debe simular"))

    r = simulacion.redundancia_persona("ana", _DOC_DOS, None, _AHORA)

    assert r["es_totalmente_redundante"] is False
    assert r["acceso_nuevo"] == ["s3:GetObject", "s3:ListBucket"]
    assert r["ya_tenia"] == []
    assert r["roles_comparados"] == []
    assert r["no_comprobada"].startswith("ClientError: ")
    assert "AccessDenied" in r["no_comprobada"]


def test_un_rol_que_vence_antes_que_el_permiso_pedido_no_lo_hace_redundante(monkeypatch):
    # El rol vigente vence a las 15:04:51 y el permiso nuevo durara hasta las
    # 20:04:51: cubrirlo con un rol que caduca antes dejaria a la persona sin
    # permiso entre las dos horas.
    monkeypatch.setattr(personas, "roles_vigentes", lambda usuario, ahora, iam=None: [_vigente()])
    monkeypatch.setattr(
        simulacion, "redundancia", lambda *a, **k: pytest.fail("no debe compararse con ese rol")
    )

    r = simulacion.redundancia_persona(
        "ana", _DOC_DOS, None, _AHORA, vence_nuevo="2026-10-26T20:04:51Z"
    )

    assert r["es_totalmente_redundante"] is False
    assert r["roles_comparados"] == []
    assert r["acceso_nuevo"] == ["s3:GetObject", "s3:ListBucket"]


def test_un_rol_que_vence_a_la_misma_hora_o_despues_si_cuenta(monkeypatch):
    otro = _ARN_ROL.replace("req-1", "req-2")
    antes = _vigente()
    justo = {**_vigente(otro), "vence": "2026-10-26T20:04:51Z"}
    monkeypatch.setattr(
        personas, "roles_vigentes", lambda usuario, ahora, iam=None: [antes, justo]
    )
    monkeypatch.setattr(
        simulacion,
        "redundancia",
        lambda arn, doc, ctx=None: {
            "ya_tenia": ["s3:GetObject", "s3:ListBucket"],
            "acceso_nuevo": [],
            "es_totalmente_redundante": True,
        },
    )

    r = simulacion.redundancia_persona(
        "ana", _DOC_DOS, None, _AHORA, vence_nuevo="2026-10-26T20:04:51Z"
    )

    assert r["roles_comparados"] == [otro]
    assert r["es_totalmente_redundante"] is True


def test_con_roles_dados_no_se_vuelven_a_listar(monkeypatch):
    def bomba(*a, **k):
        raise AssertionError("roles_vigentes no debe llamarse si ya vienen los roles")

    monkeypatch.setattr(personas, "roles_vigentes", bomba)
    monkeypatch.setattr(
        simulacion,
        "redundancia",
        lambda arn, doc, ctx=None: {
            "ya_tenia": ["s3:GetObject", "s3:ListBucket"],
            "acceso_nuevo": [],
            "es_totalmente_redundante": True,
        },
    )

    r = simulacion.redundancia_persona("ana", _DOC_DOS, None, _AHORA, roles=[_vigente()])

    assert r["es_totalmente_redundante"] is True
    assert r["roles_comparados"] == [_ARN_ROL]
    assert r["no_comprobada"] is None


def test_con_una_lista_de_roles_vacia_tampoco_se_lista(monkeypatch):
    monkeypatch.setattr(personas, "roles_vigentes", lambda *a, **k: pytest.fail("no se lista"))

    r = simulacion.redundancia_persona("ana", _DOC_DOS, None, _AHORA, roles=[])

    assert r["roles_comparados"] == []
    assert r["es_totalmente_redundante"] is False
