"""Las piezas puras del rol por persona (Fase 23, tarea 1).

Sin red ni boto3: nombres, ids, vencimiento y confianza son funciones puras,
y de que sean deterministas depende la idempotencia del aplicador.
"""

import json
import re
from datetime import datetime, timedelta, timezone

import pytest
from botocore.stub import Stubber

from agente_iam import personas
from tests.dobles import _cliente

AHORA = datetime(2026, 10, 26, 3, 4, 51, tzinfo=timezone.utc)
VENCE = "2026-10-26T15:04:51Z"


def test_el_id_sale_de_la_fecha_y_de_la_clave_y_es_repetible():
    a = personas.id_de_solicitud("1b4e28ba-2fa1-11d2-883f-0016d3cca427", AHORA)
    assert re.fullmatch(r"req-20261026-[0-9a-f]{8}", a)
    assert a == personas.id_de_solicitud("1b4e28ba-2fa1-11d2-883f-0016d3cca427", AHORA)
    assert a != personas.id_de_solicitud("otra-clave", AHORA)


def test_el_id_usa_el_dia_utc_aunque_la_hora_llegue_en_otra_zona():
    # 23:30 del 25 en UTC-5 es la 04:30 del 26 en UTC.
    ahora = datetime(2026, 10, 25, 23, 30, tzinfo=timezone(timedelta(hours=-5)))
    assert personas.id_de_solicitud("k", ahora).startswith("req-20261026-")


def test_el_nombre_del_rol_cabe_en_64_y_es_determinista():
    nombre = personas.nombre_de_rol("Solicitante.Demo", "req-20261026-ab12cd34")
    assert nombre == "agente-iam-persona-solicitante.demo-req-20261026-ab12cd34"
    largo = personas.nombre_de_rol("persona.con.un.correo.muy.largo@ejemplo-empresa.com", "req-20261026-ab12cd34")
    assert len(largo) <= 64
    assert largo.startswith("agente-iam-persona-persona.con.un.correo")
    assert largo.endswith("-req-20261026-ab12cd34")
    assert re.fullmatch(r"[a-z0-9+=,.@_-]{1,64}", largo)
    assert largo == personas.nombre_de_rol("persona.con.un.correo.muy.largo@ejemplo-empresa.com", "req-20261026-ab12cd34")


def test_el_nombre_va_en_minusculas_como_el_de_la_politica():
    assert personas.nombre_de_rol("x", "REQ-20261026-AB12CD34") == personas.nombre_de_rol("x", "req-20261026-ab12cd34")


def test_dos_usuarios_que_difieren_solo_despues_del_recorte_dan_el_mismo_prefijo_pero_otro_id_los_separa():
    # Documenta el limite: el recorte puede igualar a dos usuarios, y lo que
    # los distingue es el solicitud_id, que lleva el hash de la clave de envio.
    base = "u" * 40
    a = personas.nombre_de_rol(base + "a", personas.id_de_solicitud("k1", AHORA))
    b = personas.nombre_de_rol(base + "b", personas.id_de_solicitud("k2", AHORA))
    assert a != b
    assert len(a) <= 64
    assert len(b) <= 64


def test_normalizar_usuario_quita_lo_que_iam_no_admite():
    assert personas.normalizar_usuario("Ana Gomez/ñ") == "ana-gomez--"
    assert personas.normalizar_usuario("ＡNA") == "ana"  # NFKC
    assert personas.normalizar_usuario("a+b=c.d@e_f-g") == "a+b=c.d@e_f-g"


def test_normalizar_usuario_saca_la_coma_porque_iam_no_la_admite_en_el_valor_de_una_etiqueta():
    # El valor normalizado viaja en la etiqueta `agente-iam-persona`, cuyo
    # alfabeto no incluye la coma (aunque el nombre de un rol si la admite).
    assert personas.normalizar_usuario("ana,gomez") == "ana-gomez"
    assert "," not in personas.normalizar_usuario("a,b,c")


def test_normalizar_usuario_une_las_formas_que_aprobar_considera_la_misma_persona():
    assert personas.normalizar_usuario("Aprobador.Demo") == personas.normalizar_usuario("aprobador.demo")


def test_vence_desde_formatea_en_utc_con_z_y_acota_las_horas():
    assert personas.vence_desde(AHORA, 12) == VENCE
    assert personas.vence_desde(AHORA, 1) == "2026-10-26T04:04:51Z"
    for horas in (0, 13, -1):
        with pytest.raises(ValueError):
            personas.vence_desde(AHORA, horas)


def test_vence_desde_convierte_a_utc_una_hora_con_zona():
    ahora = datetime(2026, 10, 25, 22, 4, 51, tzinfo=timezone(timedelta(hours=-5)))
    assert personas.vence_desde(ahora, 1) == "2026-10-26T04:04:51Z"


def test_el_vencimiento_entra_en_cada_allow_y_respeta_la_s5_y_los_deny():
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": ["arn:aws:s3:::b"],
                "Condition": {"StringEquals": {"aws:ResourceAccount": "${aws:PrincipalAccount}"}},
            },
            {"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": ["*"]},
        ],
    }
    copia = json.loads(json.dumps(doc))
    salida = personas.documento_con_vencimiento(doc, VENCE)
    assert doc == copia  # no muta
    allow, deny = salida["Statement"]
    assert allow["Condition"] == {
        "StringEquals": {"aws:ResourceAccount": "${aws:PrincipalAccount}"},
        "DateLessThan": {"aws:CurrentTime": VENCE},
    }
    assert "Condition" not in deny
    assert deny == doc["Statement"][1]


def test_el_vencimiento_acepta_un_statement_suelto_y_un_allow_sin_condicion():
    doc = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}
    salida = personas.documento_con_vencimiento(doc, VENCE)
    assert salida["Statement"]["Condition"] == {"DateLessThan": {"aws:CurrentTime": VENCE}}
    assert "Condition" not in doc["Statement"]


def test_si_el_allow_ya_tiene_datelessthan_con_otra_clave_se_conserva():
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"DateLessThan": {"aws:TokenIssueTime": "2030-01-01T00:00:00Z"}},
            }
        ],
    }
    [st] = personas.documento_con_vencimiento(doc, VENCE)["Statement"]
    assert st["Condition"]["DateLessThan"] == {
        "aws:TokenIssueTime": "2030-01-01T00:00:00Z",
        "aws:CurrentTime": VENCE,
    }


def test_la_copia_no_comparte_estructuras_con_la_entrada():
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["a:b"], "Resource": ["*"]}]}
    salida = personas.documento_con_vencimiento(doc, VENCE)
    salida["Statement"][0]["Action"].append("c:d")
    assert doc["Statement"][0]["Action"] == ["a:b"]


def test_emisor_y_proveedor_oidc():
    assert personas.emisor("us-east-1_AbC123") == "cognito-idp.us-east-1.amazonaws.com/us-east-1_AbC123"
    assert personas.emisor("p", "eu-west-1") == "cognito-idp.eu-west-1.amazonaws.com/p"
    assert personas.proveedor_oidc("111122223333", "p", "eu-west-1") == (
        "arn:aws:iam::111122223333:oidc-provider/cognito-idp.eu-west-1.amazonaws.com/p"
    )


def test_la_confianza_es_la_medida_en_mediciones_n():
    doc = personas.confianza("111122223333", "us-east-1_AbC123", ["cli26", "web26"], "sub-1", VENCE)
    assert doc["Version"] == "2012-10-17"
    [st] = doc["Statement"]
    emisor = "cognito-idp.us-east-1.amazonaws.com/us-east-1_AbC123"
    assert st["Effect"] == "Allow"
    assert st["Principal"] == {"Federated": f"arn:aws:iam::111122223333:oidc-provider/{emisor}"}
    assert st["Action"] == "sts:AssumeRoleWithWebIdentity"
    assert st["Condition"]["StringEquals"] == {f"{emisor}:aud": ["cli26", "web26"], f"{emisor}:sub": "sub-1"}
    assert st["Condition"]["DateLessThan"] == {"aws:CurrentTime": VENCE}
    assert set(st["Condition"]) == {"StringEquals", "DateLessThan"}
    json.dumps(doc)  # serializable tal cual para IAM


def test_la_confianza_acepta_un_solo_cliente_y_una_tupla():
    doc = personas.confianza("111122223333", "p", ("solo",), "s", VENCE)
    aud = doc["Statement"][0]["Condition"]["StringEquals"]["cognito-idp.us-east-1.amazonaws.com/p:aud"]
    assert aud == ["solo"]


def test_arn_de_rol():
    assert (
        personas.arn_de_rol("111122223333", "x", "req-1")
        == "arn:aws:iam::111122223333:role/agente-iam/personas/agente-iam-persona-x-req-1"
    )


def test_las_constantes_son_las_del_diseno():
    assert personas.PATH_PERSONAS == "/agente-iam/personas/"
    assert personas.PREFIJO_ROL == "agente-iam-persona-"
    assert (personas.HORAS_MIN, personas.HORAS_MAX) == (1, 12)
    assert personas.FORMATO_VENCE == "%Y-%m-%dT%H:%M:%SZ"
    assert {personas.TAG_SOLICITUD, personas.TAG_PERSONA, personas.TAG_SUB, personas.TAG_VENCE} == {
        "agente-iam-solicitud",
        "agente-iam-persona",
        "agente-iam-sub",
        "agente-iam-vence",
    }


# --- Tarea 4: las dos funciones con red (roles vigentes y cuenta) ----------

_CUENTA = "111122223333"
_FECHA = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _rol(nombre: str) -> dict:
    return {
        "Path": personas.PATH_PERSONAS,
        "RoleName": nombre,
        "RoleId": "AROAEXAMPLE123456789",
        "Arn": f"arn:aws:iam::{_CUENTA}:role{personas.PATH_PERSONAS}{nombre}",
        "CreateDate": _FECHA,
    }


def _etiquetas(persona: str, vence: str, solicitud: str, sub: str = "sub-1") -> dict:
    return {
        "Tags": [
            {"Key": personas.TAG_PERSONA, "Value": persona},
            {"Key": personas.TAG_VENCE, "Value": vence},
            {"Key": personas.TAG_SOLICITUD, "Value": solicitud},
            {"Key": personas.TAG_SUB, "Value": sub},
        ],
        "IsTruncated": False,
    }


@pytest.fixture
def iam():
    stub = Stubber(_cliente("iam"))
    with stub:
        yield stub
        stub.assert_no_pending_responses()


def test_roles_vigentes_devuelve_solo_el_vigente_y_pide_dos_etiquetas(iam):
    vigente = personas.nombre_de_rol("Ana", "req-20261026-aaaaaaaa")
    vencido = personas.nombre_de_rol("Ana", "req-20261025-bbbbbbbb")
    de_otra = personas.nombre_de_rol("Bob", "req-20261026-cccccccc")
    iam.add_response(
        "list_roles",
        {"Roles": [_rol(vigente), _rol(vencido), _rol(de_otra)], "IsTruncated": False},
        {"PathPrefix": personas.PATH_PERSONAS},
    )
    # Solo dos ListRoleTags: el de Bob no empieza por el prefijo de Ana y el
    # Stubber falla si se pide un tercero.
    iam.add_response(
        "list_role_tags", _etiquetas("ana", VENCE, "req-20261026-aaaaaaaa"), {"RoleName": vigente}
    )
    iam.add_response(
        "list_role_tags",
        _etiquetas("ana", "2026-10-26T01:00:00Z", "req-20261025-bbbbbbbb"),
        {"RoleName": vencido},
    )

    r = personas.roles_vigentes("Ana", AHORA, iam=iam.client)

    assert r == [
        {
            "arn": f"arn:aws:iam::{_CUENTA}:role{personas.PATH_PERSONAS}{vigente}",
            "nombre": vigente,
            "vence": VENCE,
            "solicitud_id": "req-20261026-aaaaaaaa",
        }
    ]


def test_las_etiquetas_son_la_fuente_de_verdad_de_la_persona(iam):
    # El nombre empieza por el prefijo de "ana", pero la etiqueta dice otra
    # persona (p. ej. el usuario "ana-maria"): no es de Ana.
    nombre = personas.nombre_de_rol("ana-maria", "req-20261026-aaaaaaaa")
    assert nombre.startswith(personas.PREFIJO_ROL + "ana-")
    iam.add_response(
        "list_roles",
        {"Roles": [_rol(nombre)], "IsTruncated": False},
        {"PathPrefix": personas.PATH_PERSONAS},
    )
    iam.add_response(
        "list_role_tags", _etiquetas("ana-maria", VENCE, "req-20261026-aaaaaaaa"), {"RoleName": nombre}
    )

    assert personas.roles_vigentes("ana", AHORA, iam=iam.client) == []


def test_roles_vigentes_sigue_la_paginacion_de_list_roles(iam):
    uno = personas.nombre_de_rol("ana", "req-20261026-aaaaaaaa")
    dos = personas.nombre_de_rol("ana", "req-20261026-bbbbbbbb")
    iam.add_response(
        "list_roles",
        {"Roles": [_rol(uno)], "IsTruncated": True, "Marker": "m1"},
        {"PathPrefix": personas.PATH_PERSONAS},
    )
    iam.add_response("list_role_tags", _etiquetas("ana", VENCE, "req-20261026-aaaaaaaa"), {"RoleName": uno})
    iam.add_response(
        "list_roles",
        {"Roles": [_rol(dos)], "IsTruncated": False},
        {"PathPrefix": personas.PATH_PERSONAS, "Marker": "m1"},
    )
    iam.add_response("list_role_tags", _etiquetas("ana", VENCE, "req-20261026-bbbbbbbb"), {"RoleName": dos})

    r = personas.roles_vigentes("ana", AHORA, iam=iam.client)

    assert [x["nombre"] for x in r] == [uno, dos]


def test_un_vence_ilegible_o_igual_a_ahora_no_es_vigente(iam):
    a = personas.nombre_de_rol("ana", "req-20261026-aaaaaaaa")
    b = personas.nombre_de_rol("ana", "req-20261026-bbbbbbbb")
    iam.add_response(
        "list_roles",
        {"Roles": [_rol(a), _rol(b)], "IsTruncated": False},
        {"PathPrefix": personas.PATH_PERSONAS},
    )
    iam.add_response("list_role_tags", _etiquetas("ana", "manana", "req-20261026-aaaaaaaa"), {"RoleName": a})
    iam.add_response(
        "list_role_tags",
        _etiquetas("ana", AHORA.strftime(personas.FORMATO_VENCE), "req-20261026-bbbbbbbb"),
        {"RoleName": b},
    )

    assert personas.roles_vigentes("ana", AHORA, iam=iam.client) == []


def test_el_prefijo_de_busqueda_es_el_que_da_nombre_de_rol_con_usuario_largo(iam):
    # Con un usuario que se recorta, el prefijo usa la misma regla que el nombre.
    usuario = "u" * 80 + "@ejemplo.com"
    nombre = personas.nombre_de_rol(usuario, "req-20261026-aaaaaaaa")
    assert len(nombre) <= 64
    iam.add_response(
        "list_roles",
        {"Roles": [_rol(nombre)], "IsTruncated": False},
        {"PathPrefix": personas.PATH_PERSONAS},
    )
    iam.add_response(
        "list_role_tags",
        _etiquetas(personas.normalizar_usuario(usuario), VENCE, "req-20261026-aaaaaaaa"),
        {"RoleName": nombre},
    )

    r = personas.roles_vigentes(usuario, AHORA, iam=iam.client)

    assert [x["nombre"] for x in r] == [nombre]


def test_con_sub_solo_salen_los_roles_de_ese_sub(iam):
    # Dos personas distintas pueden normalizar al mismo texto (`ana.\u00e9` y
    # `ana.\u00e8` dan `ana.-`): el nombre y la etiqueta de persona no las
    # separan, el `sub` si.
    assert personas.normalizar_usuario("ana.\u00e9") == personas.normalizar_usuario("ana.\u00e8")
    de_uno = personas.nombre_de_rol("ana.\u00e9", "req-20261026-aaaaaaaa")
    de_otro = personas.nombre_de_rol("ana.\u00e8", "req-20261026-bbbbbbbb")
    persona = personas.normalizar_usuario("ana.\u00e9")
    iam.add_response(
        "list_roles",
        {"Roles": [_rol(de_uno), _rol(de_otro)], "IsTruncated": False},
        {"PathPrefix": personas.PATH_PERSONAS},
    )
    iam.add_response(
        "list_role_tags",
        _etiquetas(persona, VENCE, "req-20261026-aaaaaaaa", sub="sub-uno"),
        {"RoleName": de_uno},
    )
    iam.add_response(
        "list_role_tags",
        _etiquetas(persona, VENCE, "req-20261026-bbbbbbbb", sub="sub-otro"),
        {"RoleName": de_otro},
    )

    r = personas.roles_vigentes("ana.\u00e9", AHORA, iam=iam.client, sub="sub-uno")

    assert [x["nombre"] for x in r] == [de_uno]


def test_sin_sub_salen_los_roles_de_todos_los_sub_de_ese_usuario_normalizado(iam):
    de_uno = personas.nombre_de_rol("ana", "req-20261026-aaaaaaaa")
    de_otro = personas.nombre_de_rol("ana", "req-20261026-bbbbbbbb")
    iam.add_response(
        "list_roles",
        {"Roles": [_rol(de_uno), _rol(de_otro)], "IsTruncated": False},
        {"PathPrefix": personas.PATH_PERSONAS},
    )
    iam.add_response(
        "list_role_tags", _etiquetas("ana", VENCE, "req-20261026-aaaaaaaa", sub="a"), {"RoleName": de_uno}
    )
    iam.add_response(
        "list_role_tags", _etiquetas("ana", VENCE, "req-20261026-bbbbbbbb", sub="b"), {"RoleName": de_otro}
    )

    r = personas.roles_vigentes("ana", AHORA, iam=iam.client)

    assert [x["nombre"] for x in r] == [de_uno, de_otro]


def test_vence_como_fecha_parsea_el_formato_en_utc_y_devuelve_none_si_no_cuadra():
    assert personas.vence_como_fecha("2026-10-26T15:04:51Z") == datetime(
        2026, 10, 26, 15, 4, 51, tzinfo=timezone.utc
    )
    assert personas.vence_como_fecha("manana") is None
    assert personas.vence_como_fecha("") is None
    assert personas.vence_como_fecha("2026-10-26 15:04:51") is None
    # Lo que sale de `vence_desde` siempre se lee de vuelta.
    assert personas.vence_como_fecha(personas.vence_desde(AHORA, 3)) == AHORA + timedelta(hours=3)


def test_cuenta_actual_cachea(monkeypatch):
    monkeypatch.setattr(personas, "_cuenta", None)
    stub = Stubber(_cliente("sts"))
    stub.add_response(
        "get_caller_identity",
        {"UserId": "AIDAEXAMPLE", "Account": _CUENTA, "Arn": f"arn:aws:iam::{_CUENTA}:user/x"},
    )
    with stub:
        assert personas.cuenta_actual(sts=stub.client) == _CUENTA
        # Segunda llamada: no hay otra respuesta programada; si pidiera
        # GetCallerIdentity otra vez el Stubber fallaria.
        assert personas.cuenta_actual(sts=stub.client) == _CUENTA
        stub.assert_no_pending_responses()
