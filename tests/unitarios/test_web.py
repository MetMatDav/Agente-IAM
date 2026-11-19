"""La pagina web (`web/`) y su constructor (`scripts/construir_web.py`), sin red.

La pagina no tiene suite de JavaScript (el repositorio es Python y no se
anade Node). Por eso lo que se fija por test es la SUPERFICIE: que las listas
de la pagina sean las del servidor (se generan desde `config.py` al
construir), que no haya nada inline ni nada externo, que los tokens vivan
solo en la memoria de la pestana y que cada token tenga un solo destino (el
`access_token` al runtime, el `id_token` a STS). Son comprobaciones sobre el
texto de `index.html` y `app.js`: no prueban que el flujo funcione, eso lo
mide la prueba en vivo desde el navegador (docs/MEDICIONES.md).
"""

import importlib.util
import json
import re
import shutil
import subprocess  # nosec B404: node con un guion fijo, solo en el test de paridad
from pathlib import Path

import pytest

from agente_iam import config, personas

RAIZ = Path(__file__).resolve().parents[2]
_RUTA = RAIZ / "scripts" / "construir_web.py"
_spec = importlib.util.spec_from_file_location("construir_web", _RUTA)
assert _spec
assert _spec.loader
construir_web = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(construir_web)

_solicitar_spec = importlib.util.spec_from_file_location("solicitar", RAIZ / "scripts" / "solicitar.py")
assert _solicitar_spec
assert _solicitar_spec.loader
solicitar = importlib.util.module_from_spec(_solicitar_spec)
_solicitar_spec.loader.exec_module(solicitar)

ARN = "arn:aws:bedrock-agentcore:us-east-1:111122223333:runtime/agente_iam-AbC123"
ACCESO = {
    "UserPoolId": "us-east-1_EjemploPool",
    "UrlDominio": "https://ejemplo.auth.us-east-1.amazoncognito.com",
    "ClienteWebId": "clienteweb111",
}
RUNTIME = {"RuntimeArn": ARN}

HTML = (RAIZ / "web" / "index.html").read_text(encoding="utf-8")
JS = (RAIZ / "web" / "app.js").read_text(encoding="utf-8")
CSS = (RAIZ / "web" / "estilos.css").read_text(encoding="utf-8")


def _config() -> dict:
    return construir_web.configuracion(ACCESO, RUNTIME, "clienteweb111", "111122223333")


def _cuerpo_de(funcion: str) -> str:
    """El texto de `function <funcion>(` hasta la siguiente `function `."""
    inicio = JS.index(f"function {funcion}(")
    siguiente = JS.find("function ", inicio + 1)
    return JS[inicio:] if siguiente == -1 else JS[inicio:siguiente]


# --- El constructor -----------------------------------------------------------


def test_las_listas_de_la_pagina_son_las_del_servidor():
    c = _config()
    assert c["servicios"] == config.SERVICIOS_PERMITIDOS
    assert c["regiones"] == config.REGIONES_PERMITIDAS
    # Fase 28: el formulario ya no pide el tipo de acceso.
    assert "tiposAcceso" not in c
    assert (c["horasMin"], c["horasMax"]) == (personas.HORAS_MIN, personas.HORAS_MAX) == (1, 12)
    assert c["region"] == "us-east-1"
    assert c["dominioCognito"] == ACCESO["UrlDominio"]
    assert c["clienteId"] == "clienteweb111"
    assert c["poolId"] == ACCESO["UserPoolId"]
    assert c["cuenta"] == "111122223333"


def test_la_url_del_runtime_es_la_de_solicitar():
    assert _config()["urlRuntime"] == solicitar.url_runtime(ARN)


def test_escribir_deja_config_js_con_el_json_en_una_linea(tmp_path):
    c = _config()
    ruta = construir_web.escribir(c, tmp_path)
    assert ruta == tmp_path / "config.js"
    texto = ruta.read_text(encoding="utf-8")
    assert texto.endswith("\n")
    lineas = texto.splitlines()
    assert len(lineas) == 1
    prefijo = "window.AGENTE_IAM = "
    assert lineas[0].startswith(prefijo)
    assert lineas[0].endswith(";")
    assert json.loads(lineas[0][len(prefijo):-1]) == c
    for nombre in construir_web.FICHEROS:
        assert (tmp_path / nombre).read_bytes() == (RAIZ / "web" / nombre).read_bytes()


def test_main_sin_argumentos_no_toca_la_red(monkeypatch):
    def falla(*a, **k):
        raise AssertionError("--help no debe tocar la red")

    monkeypatch.setattr(construir_web, "_salidas", falla)
    monkeypatch.setattr(construir_web, "_cuenta", falla)
    with pytest.raises(SystemExit) as e:
        construir_web.main(["--help"])
    assert e.value.code == 0


def test_main_sin_cliente_web_sale_con_2(monkeypatch, tmp_path, capsys):
    sin_cliente = {k: v for k, v in ACCESO.items() if k != "ClienteWebId"}
    monkeypatch.setattr(construir_web, "_salidas",
                        lambda perfil, pila: sin_cliente if pila == "agente-iam-acceso" else RUNTIME)
    monkeypatch.setattr(construir_web, "_cuenta", lambda perfil: "111122223333")
    assert construir_web.main(["--destino", str(tmp_path)]) == 2
    assert "la pila acceso no tiene todavia el cliente web" in capsys.readouterr().err
    assert not (tmp_path / "config.js").exists()


def test_main_escribe_en_el_destino(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(construir_web, "_salidas",
                        lambda perfil, pila: ACCESO if pila == "agente-iam-acceso" else RUNTIME)
    monkeypatch.setattr(construir_web, "_cuenta", lambda perfil: "111122223333")
    assert construir_web.main(["--destino", str(tmp_path), "--cliente-web", "otrocliente"]) == 0
    texto = (tmp_path / "config.js").read_text(encoding="utf-8")
    cfg = json.loads(texto.splitlines()[0][len("window.AGENTE_IAM = "):-1])
    assert cfg["clienteId"] == "otrocliente"
    salida = capsys.readouterr().out
    assert "config.js" in salida
    assert "otrocliente" not in salida  # solo rutas, nunca el contenido


# --- index.html ---------------------------------------------------------------


# Las etiquetas Open Graph (Fase 28) son las unicas que llevan URL absolutas: el
# navegador no las carga, solo las leen los robots que dibujan la vista previa
# (LinkedIn, WhatsApp). Se quitan antes de buscar URL externas en el resto.
_OPEN_GRAPH = re.compile(r'<meta property="og:[a-z:_]+" content="[^"]*">\n?')
DOMINIO = "https://agente-iam.mateo.solutions/"


def test_la_pagina_no_lleva_script_inline_ni_urls_externas():
    html = _OPEN_GRAPH.sub("", HTML)
    etiquetas = re.findall(r"<script\b[^>]*>", html, flags=re.IGNORECASE)
    assert len(etiquetas) == 2
    fuentes = []
    for e in etiquetas:
        m = re.search(r'\bsrc="([^"]+)"', e)
        assert m, f"script inline: {e}"
        fuentes.append(m.group(1))
    assert fuentes == ["config.js", "app.js"]
    for cuerpo in re.findall(r"<script\b[^>]*>(.*?)</script>", html, flags=re.IGNORECASE | re.DOTALL):
        assert cuerpo.strip() == "", "script con cuerpo inline"
    assert "http://" not in html
    assert "https://" not in html
    assert not re.search(r"\son[a-z]+\s*=", html, flags=re.IGNORECASE)
    assert not re.search(r"\sstyle\s*=", html, flags=re.IGNORECASE)
    assert 'name="referrer" content="no-referrer"' in HTML
    assert 'lang="es"' in HTML


def test_las_etiquetas_open_graph_apuntan_solo_al_dominio_y_a_una_imagen_propia():
    """La vista previa de LinkedIn: titulo, descripcion, URL e imagen absolutas, y todas del propio dominio. La
    imagen es un fichero de `web/` que copia `construir_web.py`, de 1200 x 627 (la medida que pide LinkedIn)."""
    og = dict(re.findall(r'<meta property="(og:[a-z:_]+)" content="([^"]*)">', HTML))
    assert {"og:type", "og:title", "og:description", "og:url", "og:image", "og:image:width",
            "og:image:height", "og:image:alt", "og:locale"} <= set(og)
    assert og["og:url"] == DOMINIO
    assert og["og:image"] == DOMINIO + "vista-previa.png"
    for clave, valor in og.items():
        if "://" in valor:
            assert valor.startswith(DOMINIO), clave
    assert len(_OPEN_GRAPH.findall(HTML)) == len(og)  # ninguna og: escrita de otra forma
    imagen = RAIZ / "web" / "vista-previa.png"
    cabecera = imagen.read_bytes()[:24]
    assert cabecera[:8] == b"\x89PNG\r\n\x1a\n"
    ancho, alto = int.from_bytes(cabecera[16:20], "big"), int.from_bytes(cabecera[20:24], "big")
    assert (ancho, alto) == (1200, 627) == (int(og["og:image:width"]), int(og["og:image:height"]))
    assert "vista-previa.png" in construir_web.FICHEROS


def test_la_pagina_y_los_estilos_no_cargan_nada_externo():
    assert "@import" not in CSS
    assert "url(" not in CSS
    assert "http://" not in CSS
    assert "https://" not in CSS


def test_los_campos_que_usa_app_js_existen_en_la_pagina():
    ids_html = set(re.findall(r'\bid="([^"]+)"', HTML))
    usados = set(re.findall(r'\$\("([a-z_]+)"\)', JS))
    assert usados, "app.js deberia buscar sus elementos con $(...)"
    assert usados <= ids_html, usados - ids_html


def test_textos_sin_acentos_ni_guion_largo():
    for nombre, texto in (("index.html", HTML), ("estilos.css", CSS), ("app.js", JS)):
        assert "\u2014" not in texto, nombre
        assert "\u2013" not in texto, nombre
        assert texto.isascii(), nombre


# --- app.js -------------------------------------------------------------------


def test_app_js_no_guarda_tokens_fuera_de_la_memoria():
    for prohibido in ("localStorage", "document.cookie", "innerHTML"):
        assert prohibido not in JS, prohibido
    for linea in JS.splitlines():
        if "sessionStorage" in linea:
            # solo el verificador PKCE y el state, que no son tokens
            assert "verifier" in linea or "state" in linea, linea
            for token in ("access_token", "id_token", "accessToken", "idToken"):
                assert token not in linea, linea
    assert JS.count("agente-iam.verifier") >= 1
    assert JS.count("agente-iam.state") >= 1


def test_app_js_llama_solo_a_cognito_runtime_y_sts():
    urls = re.findall(r"https://[^\s\"'`)]*", JS)
    assert urls
    assert set(urls) == {"https://sts.us-east-1.amazonaws.com/"}
    assert "http://" not in JS
    assert "CFG.dominioCognito" in JS
    assert "CFG.urlRuntime" in JS


def test_el_id_token_solo_viaja_a_sts_y_el_access_token_al_runtime():
    cuerpo_obtener = _cuerpo_de("obtener")
    fuera = JS.replace(cuerpo_obtener, "")
    # `idToken` fuera de obtener(): solo se guarda al canjear (asignacion), nunca se manda
    for linea in fuera.splitlines():
        if "idToken" in linea or "id_token" in linea:
            assert "Bearer" not in linea, linea
            assert "fetch(" not in linea, linea
    assert "idToken" in cuerpo_obtener
    assert "accessToken" not in cuerpo_obtener
    for linea in JS.splitlines():
        if '"Bearer "' in linea:
            assert "accessToken" in linea, linea
            assert "idToken" not in linea
    assert JS.count('"Bearer "') == 1


def test_enviar_se_deshabilita_en_vuelo():
    cuerpo = _cuerpo_de("enviar")
    assert "disabled = true" in cuerpo
    assert cuerpo.index("disabled = true") < cuerpo.index("fetch(CFG.urlRuntime")
    assert "finally" in cuerpo
    assert "disabled = false" in cuerpo.split("finally")[1]
    assert "crypto.randomUUID()" in JS


def test_manda_la_cabecera_de_sesion_con_un_id_de_33_o_mas():
    # Medido el 26-10-2026 (MEDICIONES O.4): el preflight del runtime admite la
    # cabecera de sesion cuando se pide; se manda un id como el de solicitar.py.
    assert '"X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": idDeSesion()' in JS
    assert 'return "solicitud-" + crypto.randomUUID() + "-" + crypto.randomUUID();' in JS
    assert "Runtime-Session-Id" not in HTML


def test_la_pagina_usa_textcontent_y_nunca_innerhtml():
    assert "textContent" in JS
    for peligroso in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert peligroso not in JS, peligroso


def test_app_js_en_modo_estricto_y_sin_dependencias():
    assert '"use strict";' in JS
    assert not re.search(r"\b(import|require)\b\s*[(\"']", JS)


# --- Fase 28: sin tipo de acceso, motivo y credenciales por id ----------------


def test_la_pagina_ya_no_pide_tipo_de_acceso_y_el_texto_se_llama_solicitud():
    assert "tipo_acceso" not in HTML
    assert "tipo_acceso" not in JS
    assert '<label for="justificacion">Solicitud</label>' in HTML
    assert 'maxlength="1500"' in HTML
    assert "Ejemplo:" in HTML
    assert "nombre o ARN" in HTML


def test_el_resultado_pinta_el_motivo_del_servidor_con_textcontent():
    cuerpo = _cuerpo_de("pintarResultado")
    assert '$("motivo").textContent' in cuerpo
    assert "registro.motivo" in cuerpo


def test_las_credenciales_se_piden_por_id_y_no_por_el_rol_de_la_respuesta():
    """El rol no sale de la respuesta del envio (se pierde al recargar): se arma con el id."""
    assert "rolPrevisto" not in JS
    cuerpo = _cuerpo_de("obtener")
    assert "PATRON_ID.test(solicitudId)" in cuerpo
    assert '["RoleArn", rol]' in cuerpo
    assert "errorDeSts(" in cuerpo


def test_el_access_denied_de_sts_se_traduce():
    cuerpo = _cuerpo_de("errorDeSts")
    assert '"AccessDenied"' in cuerpo
    assert "todavia no esta aplicado, ya vencio o no es tuyo" in cuerpo


def test_el_id_del_enlace_cruza_el_login_dentro_del_state():
    assert "solicitudDelEnlace" in _cuerpo_de("entrar")
    assert 'state.split(".")[1]' in _cuerpo_de("volverDeCognito")
    assert 'params.get("solicitud")' in _cuerpo_de("iniciar")


@pytest.mark.skipif(shutil.which("node") is None, reason="sin node: la paridad se comprueba donde lo haya")
@pytest.mark.parametrize(
    ("usuario", "solicitud_id"),
    [
        ("solicitante.demo", "req-20261027-00a77ee2"),
        ("Ana.Gomez", "req-20261027-0123abcd"),
        ("josé torres", "req-20261027-89abcdef"),
        ("x" * 80, "req-20261027-ffffffff"),
    ],
)
def test_el_nombre_de_rol_de_la_pagina_es_el_de_personas(usuario, solicitud_id):
    """La pagina arma el ARN igual que el aplicador: si no, STS diria AccessDenied a un acceso valido."""
    funcion = _cuerpo_de("nombreDeRol")
    constantes = "\n".join(
        linea for linea in JS.splitlines() if re.match(r"\s*const (PREFIJO_ROL|PATH_PERSONAS|MAX_NOMBRE_ROL) =", linea)
    )
    guion = f"{constantes}\n{funcion}\nprocess.stdout.write(nombreDeRol({json.dumps(usuario)}, {json.dumps(solicitud_id)}));"
    salida = subprocess.run(["node", "-e", guion], capture_output=True, text=True, timeout=30, check=True)  # nosec B603 B607
    assert salida.stdout == personas.nombre_de_rol(usuario, solicitud_id)
    assert "/agente-iam/personas/" == personas.PATH_PERSONAS
    assert '"/agente-iam/personas/"' in constantes


# --- Fase 30: la fila "Rol previsto" solo donde puede haber rol --------------

_ROL = "arn:aws:iam::111122223333:role/agente-iam/personas/agente-iam-persona-ana-req-20261027-0123abcd"


def _fila_del_rol_tras_pintar(estados: list[str]) -> dict:
    """Corre `pintarResultado` de app.js en node, una vez por estado, sobre un DOM de mentira.

    Devuelve como queda la fila del rol (la etiqueta `dt` y el valor `dd`)
    despues del ultimo estado: asi se ve tambien que una solicitud nueva
    vuelve a mostrar la fila que la anterior escondio.
    """
    lineas = JS.splitlines()
    constantes = [linea for linea in lineas if re.match(r"\s*const (PATRON_ID|ESTADOS_CON_ROL) =", linea)]
    inicio = next(i for i, linea in enumerate(lineas) if "const MENSAJES = {" in linea)
    fin = next(i for i in range(inicio, len(lineas)) if lineas[i].strip() == "};")
    funciones = _cuerpo_de("mensajeDelEstado") + _cuerpo_de("pintarResultado")
    llamadas = "\n".join(
        f"pintarResultado({json.dumps({'solicitud_id': 'req-20261027-0123abcd', 'rol_previsto': _ROL, 'registro': {'estado': e}})}, 'ana@example.com');"
        for e in estados
    )
    guion = "\n".join([
        "const elementos = {};",
        'const $ = (id) => (elementos[id] = elementos[id] || {id, textContent: "", value: "", hidden: false});',
        *constantes,
        *lineas[inicio:fin + 1],
        funciones,
        llamadas,
        "process.stdout.write(JSON.stringify({etiqueta: $('rol_previsto_etiqueta'), valor: $('rol_previsto')}));",
    ])
    salida = subprocess.run(["node", "-e", guion], capture_output=True, text=True, timeout=30, check=True)  # nosec B603 B607
    return json.loads(salida.stdout)


@pytest.mark.skipif(shutil.which("node") is None, reason="sin node: el comportamiento se comprueba donde lo haya")
@pytest.mark.parametrize(
    "estado",
    [
        "rechazada_en_chequeos_previos",
        "rechazada_por_aprobador",
        "redundante_no_requiere_cambio",
        "requiere_revision_humana",
        "bloqueada_al_aplicar",
        "error",
        "un_estado_que_aun_no_existe",  # lista de permitidos: lo nuevo sale oculto
    ],
)
def test_en_un_estado_sin_rol_la_pagina_esconde_la_fila_del_rol(estado):
    """MEDICIONES R.11: una solicitud rechazada mostraba el ARN de un rol que nunca se creara."""
    fila = _fila_del_rol_tras_pintar([estado])
    assert fila["etiqueta"]["hidden"] is True
    assert fila["valor"]["hidden"] is True


@pytest.mark.skipif(shutil.which("node") is None, reason="sin node: el comportamiento se comprueba donde lo haya")
@pytest.mark.parametrize("estado", ["propuesta", "aprobada", "aplicada"])
def test_en_un_estado_que_puede_acabar_en_rol_la_fila_vuelve_y_lleva_el_arn(estado):
    fila = _fila_del_rol_tras_pintar(["rechazada_en_chequeos_previos", estado])
    assert fila["etiqueta"]["hidden"] is False
    assert fila["valor"]["hidden"] is False
    assert fila["valor"]["textContent"] == _ROL


def test_la_etiqueta_del_rol_tiene_id_para_poder_esconderla():
    assert '<dt id="rol_previsto_etiqueta">Rol previsto</dt>' in HTML
