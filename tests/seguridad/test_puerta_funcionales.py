"""La puerta de los funcionales: que nada toque la cuenta sin pedirlo.

Un funcional que corriera por defecto, o con el perfil del administrador,
o escribiendo en `solicitudes/`, romperia la regla del proyecto sin que
nadie lo notara. Cada condicion de `tests/puerta.py` tiene aqui el test
que se pone en rojo si se afloja.
"""

import os
import subprocess
import sys

import pytest

from tests.puerta import (
    PERFILES_PERMITIDOS,
    RAIZ,
    VARIABLE,
    carpeta_de_solicitudes,
    exigir,
    motivo_para_no_abrir,
)

_ABIERTA = {VARIABLE: "si", "AWS_PROFILE": "org-agente-iam-lectura"}


def test_abierta_solo_con_todo_en_regla():
    assert motivo_para_no_abrir(_ABIERTA) is None


def test_por_defecto_esta_cerrada():
    assert VARIABLE in motivo_para_no_abrir({})


@pytest.mark.parametrize("valor", ["1", "true", "SI", "si ", "yes", ""])
def test_solo_abre_con_si_exacto(valor):
    assert motivo_para_no_abrir({**_ABIERTA, VARIABLE: valor}) is not None


@pytest.mark.parametrize(
    "perfil",
    [None, "default", "agente-iam", "agente-iam-aplicador", "aws-dev", "org-agente-iam", "org-agente-iam-operador",
     "org-agente-iam-aprobador-demo"],
)
def test_solo_abre_con_un_perfil_de_la_lista_blanca(perfil):
    entorno = {VARIABLE: "si"} | ({"AWS_PROFILE": perfil} if perfil else {})
    assert "AWS_PROFILE" in motivo_para_no_abrir(entorno)


def test_la_lista_blanca_no_incluye_al_aplicador():
    """El aplicador es el unico rol que escribe en IAM."""
    assert not any("aplicador" in p for p in PERFILES_PERMITIDOS)


def test_la_lista_blanca_solo_tiene_perfiles_de_lectura():
    """Desde el 25-10-2026 el unico perfil es el de solo lectura de agente-iam (el rol del analista ya no existe)."""
    assert PERFILES_PERMITIDOS == ("org-agente-iam-lectura",)


@pytest.mark.parametrize("clave", ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"])
def test_claves_en_el_entorno_la_cierran(clave):
    assert clave in motivo_para_no_abrir({**_ABIERTA, clave: "x"})


def test_la_segunda_capa_salta_si_esta_cerrada():
    with pytest.raises(pytest.skip.Exception, match="segunda capa"):
        exigir({})


def test_la_evidencia_no_va_a_solicitudes(tmp_path):
    assert carpeta_de_solicitudes(tmp_path, raiz=tmp_path / "repo") == tmp_path / "solicitudes"


@pytest.mark.parametrize("evidencia", [".", "solicitudes", "otra/.."])
def test_nunca_escribe_en_solicitudes(tmp_path, evidencia):
    # `evidencia/solicitudes` resuelve a `<raiz>/solicitudes` o dentro de ella.
    # "otra/.." es el unico caso que exige el `resolve()`: sin el,
    # `<raiz>/otra/../solicitudes` no es igual a `<raiz>/solicitudes` ni la
    # tiene entre sus padres (22-10-2026).
    with pytest.raises(ValueError, match="solicitudes"):
        carpeta_de_solicitudes(tmp_path / evidencia, raiz=tmp_path)


def test_sin_la_variable_los_funcionales_se_saltan_al_recogerlos():
    """La primera capa, de verdad: pytest sobre `tests/funcionales` sin la
    variable no corre ninguno. Se quita del entorno por si quien lanza la
    bateria la tiene puesta."""
    entorno = {k: v for k, v in os.environ.items() if k != VARIABLE}
    salida = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/funcionales", "-q", "-rs", "-p", "no:cacheprovider"],
        cwd=RAIZ, env=entorno, capture_output=True, text=True,
    )
    assert salida.returncode == 0, salida.stdout
    assert "passed" not in salida.stdout
    assert "failed" not in salida.stdout
    assert "skipped" in salida.stdout
    assert VARIABLE in salida.stdout
    # El salto lo pone el marcador del conftest, no la fixture: pytest
    # atribuye los dos al test, asi que la segunda capa firma el suyo.
    assert "[segunda capa]" not in salida.stdout


def test_unitarios_y_seguridad_no_salen_a_aws(sin_salida_a_aws):
    """El reverso de la puerta: lo que no es funcional no llega a AWS aunque
    olvide un doble (`tests/conftest.py::sin_salida_a_aws`). El endpoint es
    un puerto local cerrado, asi que sin el guardian tampoco sale nada: el
    test se pondria en rojo con un error de conexion, no con una llamada."""
    import boto3

    sts = boto3.client("sts", region_name="us-east-1", endpoint_url="http://127.0.0.1:9",
                       aws_access_key_id="testing", aws_secret_access_key="testing")
    # Por el mensaje y no por la clase: pytest importa el conftest como
    # `conftest`, y `tests.conftest.LlamadaRealAAWS` seria otra clase.
    with pytest.raises(RuntimeError, match="un test sin red intento salir"):
        sts.get_caller_identity()
    assert len(sin_salida_a_aws) == 1
    sin_salida_a_aws.clear()  # el intento era el objeto de la prueba
