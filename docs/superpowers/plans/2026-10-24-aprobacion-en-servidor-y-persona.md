# Aprobacion en servidor y separacion por persona (ADR-003) - plan de implementacion

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** que el bloque `aprobacion` (y `rechazo`) solo lo pueda escribir una Lambda que identifica a quien firma la
peticion, y que la separacion de funciones compare personas de Identity Center y no el rol del permission set.

**Architecture:** `agente_iam/aprobar.py` pasa a ser el servidor: controles de hoy, identidad sacada del evento de una
URL de funcion `AWS_IAM`, `decidir()` y el manejador de la Lambda `agente-iam-aprobacion`. Un modulo nuevo,
`agente_iam/aprobar_cliente.py`, es lo que corre la persona: lee la fila, pinta la propuesta y su huella, y manda
`id` y huella firmados con SigV4. IAM cierra el resto: el rol `AgenteIAM-Aprobacion` es el unico con `UpdateItem` de
`aprobacion` y `rechazo`; el permission set del aprobador solo lee, invoca la URL y tiene Deny explicito de escribir
en la tabla.

**Tech Stack:** Python 3.12 del `.venv`, boto3/botocore 1.43.82 (`Stubber`, `botocore.auth.SigV4Auth`), pydantic
2.13.4, pytest, CloudFormation YAML leido con `yaml.safe_load`, Lambda arm64 `python3.12` con URL de funcion.

**Spec:** `docs/ADR-003-aprobacion-en-servidor-y-persona.md` (aceptado el 24-10-2026). Contexto: `CONTEXTO.md` §4,
§10 y §11 paso 6b; `docs/MEDICIONES.md` F.5 y F.6.

## Global Constraints

- Nada se escribe en la cuenta AWS sin el si de Mateo para esa accion concreta; los pasos de consola son suyos.
- No hay commits sin el si de Mateo: cada "Commit" de abajo es "ensenar el diff y proponer el commit".
- Antes de escribir el codigo de cada tarea, Claude le explica a Mateo el diseno de esa tarea (CLAUDE.md).
- En lo versionado va la cuenta `111122223333`; lo que necesite la real sale de `scripts/localizar.py` a `local/`.
- Sin guion largo en nombres ni descripciones de recursos; sin etiquetas cortas de YAML (lo lee `yaml.safe_load`).
- Region `us-east-1`. Claude usa boto3 del `.venv` o el MCP de AWS; `aws sso login` lo corre Mateo.
- Lo que el aprobador ve y lo que el servidor firma salen de la misma funcion: `huella.calcular`, sin copia.
- La duda bloquea: persona no determinable, rol que no es el del permission set o evento sin identidad = no se aprueba.
- Cierre de cada tarea: `./.venv/bin/python -m pytest tests/ -q` y `./.venv/bin/ruff check .` en verde.
- La documentacion la escribe un subagente Sonnet con encargo cerrado y la revisa Claude (Tarea 11); un modulo o
  fichero de tests nuevo entra en README y CONTEXTO §6 en su propia tarea, o `test_documentacion.py` falla.

## Decisiones que toma el plan (para que Mateo las confirme o cambie)

El ADR fija el que; esto es el como, y cada una se puede cambiar antes de empezar:

1. **Nombres de modulo.** El servidor se queda en `aprobar.py` (lo dice el ADR, y el aplicador y 10 ficheros de tests
   ya importan de ahi `revalidar`, `comprobar_techo` e `identificar_aprobador`). El cliente es nuevo:
   `aprobar_cliente.py`. **El comando de la persona cambia** a `python -m agente_iam.aprobar_cliente <id>`;
   `python -m agente_iam.aprobar` imprime a donde ir y sale con 1. La alternativa (cliente en `aprobar.py`, servidor
   en un `aprobacion.py` nuevo) conserva el comando pero mueve casi todo el codigo y sus tests.
2. **Solo el permission set `AgenteIAM-Aprobador` aprueba.** El servidor exige que el rol que firma empiece por
   `AWSReservedSSO_AgenteIAM-Aprobador_` y tenga el path de Identity Center. El ADR solo pide "un permission set";
   esto deja fuera a un administrador que tenga permiso de invocar (no podria aprobar ni para probar).
3. **Comparacion `NFKC` + `casefold()`** en vez de solo `casefold()`: dos nombres que solo difieren en una forma de
   compatibilidad (letras de ancho completo) cuentan como la misma persona. Va en la direccion del ADR: bloquea mas.
4. **El permission set del aprobador pierde tambien la lectura de IAM y Access Analyzer.** El cliente ya no revalida
   (lo hace la Lambda); le quedan `GetItem` y la invocacion. Y su Deny explicito anade `PartiQLInsert`,
   `PartiQLUpdate` y `PartiQLDelete` a los cuatro del ADR, como los roles de la pila base.
5. **Dependencias propias de la Lambda** (`requirements-aprobacion.txt`, sin `bedrock-agentcore`): el limite de Lambda
   es 250 MB descomprimido, no los 750 de AgentCore. Si aun asi no cabe, se para y se decide (Tarea 6).
6. **Hallazgo al preparar el plan, se arregla en la Tarea 9:** el permission set `AgenteIAM-Operador` sube el paquete a
   `agente-iam-paquete-<cuenta>`, pero la pila base creo `agente-iam-despliegue-<cuenta>` (F.5). Hoy el operador no
   puede subir ningun paquete; leido en las plantillas el 24-10-2026, sin medir.
7. **Hallazgo:** el rol `AgenteIAM-Despliegue` no tiene `lambda:*FunctionUrlConfig`; sin eso la pila base no puede
   crear la URL. Cambia la pila de arranque, que despliega Mateo como administrador (Tarea 8).
8. **Consecuencia que conviene tener presente:** hasta que el runtime grabe la persona del JWT (pila `acceso`), el
   solicitante nunca es determinable, asi que **toda** aprobacion real bloquea salvo con `--autoaprobacion-demo`
   (`SALTADO`), que el aplicador solo acepta con `AGENTE_IAM_PERMITIR_AUTOAPROBACION=si`. Es lo que dice el ADR.

## Review Focus

1. Un aprobador que llama a `lambda:Invoke` directamente con un evento fabricado (un `userArn` ajeno) se haria pasar
   por otra persona: el `InvokeFunction` del permission set solo vale con `lambda:InvokedViaFunctionUrl = true` y la
   pila no lleva ninguna politica de recurso (test en Tarea 9; medicion M2 en Tarea 10).
2. Una Lambda desplegada sin `ALMACEN=dynamodb` escribiria la decision en el disco efimero y responderia 200; sin
   catalogo, la revalidacion se degradaria a aviso: las dos dan 500 y no escriben nada (test en Tarea 4).
3. `Aprobador.Demo` firmando la solicitud de `aprobador.demo` (o con letras de ancho completo) es la misma persona:
   bloquea (test en Tarea 3).
4. Las filas escritas antes de este cambio no tienen `solicitante`: separacion no determinable, bloqueo con motivo, no
   `KeyError` (test en Tarea 3).
5. Un cliente con `ALMACEN=dynamodb` y sin URL configurada no debe caer al camino local que escribe en la tabla: sale
   con 1 sin llamar a `almacen.guardar_decision` (test en Tarea 5).

---

### Tarea 1: el intake graba quien pidio

**Files:**
- Modify: `agente_iam/models.py` (junto a `AprobadorVerificado`), `agente_iam/cli.py:133`, `agente_iam/servidor.py:192`
- Test: `tests/unitarios/test_cli.py`, `tests/unitarios/test_servidor.py`

**Interfaces:**
- Produces: `models.SolicitanteVerificado(persona: str | None, como_se_verifico: str)`; todo registro nuevo lleva
  `registro["solicitante"] = SolicitanteVerificado(...).model_dump()`, dentro de `documento` y bajo la huella.

- [ ] **Step 1: tests que fallan**

```python
def test_el_intake_del_cli_graba_solicitante_sin_persona(...):   # en test_cli.py, con el doble que ya usan
    assert registro["solicitante"] == {"persona": None, "como_se_verifico": SOLICITANTE_CLI}

def test_el_runtime_graba_solicitante_sin_persona(...):           # en test_servidor.py, via servidor.manejar
    assert resultado["registro"]["solicitante"]["persona"] is None
    assert "SigV4" in resultado["registro"]["solicitante"]["como_se_verifico"]
```

- [ ] **Step 2:** `./.venv/bin/python -m pytest tests/unitarios/test_cli.py tests/unitarios/test_servidor.py -q`; FAIL con `KeyError: 'solicitante'`.
- [ ] **Step 3: implementar.** `SolicitanteVerificado` sin valores por defecto. Textos exactos:
  `cli.SOLICITANTE_CLI = "CLI de intake: corre con el rol del Analista, sin persona verificada (ADR-003, B2)"` y en
  `servidor` `"runtime con SigV4: sin JWT no hay persona verificada (ADR-001, ADR-003 B2)"`. `ejecutado_por` no cambia.
- [ ] **Step 4:** los mismos tests y la bateria entera en verde.
- [ ] **Step 5: Commit** (con el si de Mateo): `Intake: el registro graba el solicitante, sin persona hasta el JWT (ADR-003)`.

### Tarea 2: el aprobador con persona, desde STS o desde el evento

**Files:**
- Modify: `agente_iam/models.py` (`AprobadorVerificado`), `agente_iam/aprobar.py:85-177` (`identificar_aprobador`)
- Test: `tests/unitarios/test_aprobacion.py` (seccion de identidad, con `Stubber` como hoy)

**Interfaces:**
- Produces:
  - `AprobadorVerificado.persona: str | None = None`.
  - `aprobar.identificar_aprobador() -> AprobadorVerificado` (misma firma; la sigue usando el aplicador).
  - `aprobar.aprobador_desde_evento(evento: dict) -> AprobadorVerificado`.
  - Las dos llaman a `aprobar._resolver(arn: str, user_id: str, cuenta: str, fuente: str) -> AprobadorVerificado`.
  - Constantes `_PATH_SSO = "/aws-reserved/sso.amazonaws.com/"`, `_PREFIJO_ROL_APROBADOR = "AWSReservedSSO_AgenteIAM-Aprobador_"`.

- [ ] **Step 1: tests que fallan** (dobles de `GetRole` como en `test_rol_asumido_se_resuelve_contra_iam`):

```python
_ARN_SSO = "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_AgenteIAM-Aprobador_0a1b2c3d4e5f6a7b/aprobador.demo"
_ROL_SSO = {"RoleName": "AWSReservedSSO_AgenteIAM-Aprobador_0a1b2c3d4e5f6a7b", "RoleId": "AROAEJEMPLOSSO",
            "Path": "/aws-reserved/sso.amazonaws.com/",
            "Arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AgenteIAM-Aprobador_0a1b2c3d4e5f6a7b"}
# mas los campos obligatorios de la respuesta de GetRole, como en los dobles de hoy

def test_sesion_del_permission_set_da_la_persona(aws):            # UserId "AROAEJEMPLOSSO:aprobador.demo"
    assert a.determinable and a.persona == "aprobador.demo" and a.arn_canonico == _ROL_SSO["Arn"]
def test_otro_permission_set_no_da_persona(aws):                  # AWSReservedSSO_AWSAdministratorAccess_...
    assert a.persona is None and "AgenteIAM-Aprobador" in a.como_se_verifico
def test_rol_fuera_del_path_de_identity_center_no_da_persona(aws): # mismo nombre, Path "/"
    assert a.persona is None
def test_nombre_de_sesion_distinto_del_user_id_no_da_persona(aws): # ARN .../aprobador.demo, UserId "AROA...:otra"
    assert a.persona is None
def test_usuario_iam_no_tiene_persona(aws):
    assert a.determinable and a.persona is None
def test_el_evento_de_la_url_se_resuelve_igual(aws):
    a = aprobar.aprobador_desde_evento(_evento(user_arn=_ARN_SSO, user_id="AROAEJEMPLOSSO:aprobador.demo"))
    assert a.persona == "aprobador.demo" and a.arn_llamante == _ARN_SSO
def test_evento_sin_identidad_iam_no_es_determinable():           # requestContext.authorizer None
    assert not a.determinable and a.persona is None
def test_evento_de_otra_cuenta_no_es_determinable():              # authorizer.iam.accountId != requestContext.accountId
    assert not a.determinable
```

  `_evento(...)` es un constructor nuevo en `tests/dobles.py` con la forma de la guia de Lambda ("Invoking Lambda
  function URLs", leida el 24-10-2026): `requestContext.accountId`, `requestContext.authorizer.iam.{accountId,
  userArn, userId, callerId, accessKey}`, `requestContext.http.method`, `body`, `isBase64Encoded`.

- [ ] **Step 2:** `./.venv/bin/python -m pytest tests/unitarios/test_aprobacion.py -q -k "persona or evento or permission_set or path"`; FAIL.
- [ ] **Step 3: implementar.** `_resolver` es el cuerpo de hoy de `identificar_aprobador` (usuario IAM, rol asumido con
  `GetRole` y `RoleId` prefijo del `UserId`, resto no determinable) mas la persona: solo si `rol["Path"]` empieza por
  `_PATH_SSO`, `RoleName` empieza por `_PREFIJO_ROL_APROBADOR` y el nombre de sesion del ARN es igual a lo que va
  tras `:` en el `UserId`. `como_se_verifico` dice cual de las tres fallo. `aprobador_desde_evento` lee
  `requestContext.authorizer.iam.userArn`, `.userId` y `.accountId`; si falta alguno o la cuenta no es
  `requestContext.accountId`, devuelve no determinable con el motivo. Nunca lee ni guarda `accessKey`.
- [ ] **Step 4:** `test_aprobacion.py`, `test_aplicador.py` y la bateria entera en verde.
- [ ] **Step 5: Commit** (con el si de Mateo): `Aprobar: el aprobador lleva su persona de Identity Center (ADR-003, B2)`.

### Tarea 3: separacion por persona, el aprobador inyectado

**Files:**
- Modify: `agente_iam/aprobar.py` (`aprobar`, `rechazar`, `_separacion`)
- Test: `tests/unitarios/test_aprobacion.py` (los cuatro `test_*` de separacion y los que llaman a `aprobar`/`rechazar`)

**Interfaces:**
- Consumes: `AprobadorVerificado.persona` (Tarea 2), `registro["solicitante"]["persona"]` (Tarea 1).
- Produces:
  - `aprobar.aprobar(registro: dict, aprobador: AprobadorVerificado, autoaprobacion_demo: bool = False, riesgo_confirmado: bool = False, huella_confirmada: str | None = None) -> tuple[dict | None, list[str]]`. Ya no llama a STS.
  - `aprobar.rechazar(registro: dict, motivo: str, aprobador: AprobadorVerificado) -> tuple[dict | None, list[str]]`.
  - `aprobar._separacion(aprobador: AprobadorVerificado, registro: dict, autoaprobacion_demo: bool) -> tuple[dict, str | None]`.
  - `aprobar._misma_persona(a: str, b: str) -> bool` (`unicodedata.normalize("NFKC", x).casefold()` a los dos lados).
  - El bloque `separacion_de_funciones` gana `"aprobador": persona | None` y `"solicitante": persona | None`; `"beneficiario"` y `"resultado"` (`cumplido` / `SALTADO`) no cambian: el aplicador sigue igual.

- [ ] **Step 1: tests que fallan.** `_aprobador_sso(persona)` nuevo en `tests/dobles.py` (determinable, rol SSO, esa persona); `_registro(solicitante={"persona": ..., "como_se_verifico": "prueba"})`.

```python
def test_personas_distintas_cumple():                         # aprobador.demo frente a solicitante.demo
    assert sep["resultado"] == "cumplido" and motivo is None
    assert sep["aprobador"] == "aprobador.demo" and sep["solicitante"] == "solicitante.demo"
def test_aprobar_lo_que_uno_mismo_pidio_bloquea():            # misma persona
    assert "solicitante" in motivo
def test_la_misma_persona_con_otras_mayusculas_bloquea():      # "Aprobador.Demo" frente a "aprobador.demo"
def test_la_misma_persona_en_ancho_completo_bloquea():         # "ａｐｒｏｂａｄｏｒ.demo"
def test_sin_persona_del_solicitante_bloquea():                # persona None
def test_una_fila_anterior_sin_solicitante_bloquea():          # registro sin la clave "solicitante": motivo, no KeyError
def test_sin_persona_del_aprobador_bloquea():                  # usuario IAM: determinable pero sin persona
def test_el_beneficiario_con_el_nombre_del_aprobador_bloquea():# beneficiario user/aprobador.demo
def test_el_aprobador_que_es_el_beneficiario_sigue_bloqueando():# arn_canonico == beneficiario (el de hoy)
def test_la_puerta_explicita_sigue_dejando_rastro():           # SALTADO con motivo, saltado_por, cuando
def test_aprobar_no_identifica_a_nadie(monkeypatch):           # identificar_aprobador -> pytest.fail
def test_el_rechazo_graba_la_persona():                        # rechazo["por"]["persona"] == "aprobador.demo"
```

- [ ] **Step 2:** `./.venv/bin/python -m pytest tests/unitarios/test_aprobacion.py -q`; FAIL.
- [ ] **Step 3: implementar.** `_separacion` junta los problemas en este orden y bloquea con el primero (el resto va en
  `motivo` del `SALTADO`): aprobador no determinable o sin persona; solicitante sin persona o sin bloque; misma
  persona que el solicitante; `arn_canonico == beneficiario`; beneficiario `arn:aws:iam::<cuenta>:user/<...>/nombre`
  con `_misma_persona(nombre, persona_aprobador)`. Los textos de bloqueo siguen la forma de hoy y terminan con la
  pista de `--autoaprobacion-demo`. Los demas pasos de `aprobar` (estado, huella, riesgo, revalidacion, techo) no cambian.
  El `main()` de hoy sigue vivo hasta la Tarea 5: pasa `identificar_aprobador()` a `aprobar` y a `rechazar`.
- [ ] **Step 4:** `test_aprobacion.py`, `test_aplicador.py`, `tests/seguridad/` y la bateria entera en verde
  (`test_compuertas.py`, `test_revision_2026_10.py` y `test_riesgo_minimo.py` llaman a `aprobar`: se adaptan a la
  firma nueva en esta tarea).
- [ ] **Step 5: Commit** (con el si de Mateo): `Aprobar: la separacion compara personas, frente al solicitante y al beneficiario (ADR-003, B2)`.

### Tarea 4: `decidir` y el manejador de la Lambda

**Files:**
- Modify: `agente_iam/models.py` (`PeticionAprobacion`), `agente_iam/aprobar.py` (entran `decidir` y `manejador`; `main()` no se toca hasta la Tarea 5)
- Test: `tests/unitarios/test_aprobacion.py` (los `test_main_*` pasan a ser `test_decidir_*` y `test_manejador_*`)

**Interfaces:**
- Consumes: `aprobar`, `rechazar`, `aprobador_desde_evento` (Tareas 2 y 3); `almacen.leer`, `almacen.guardar_decision(registro, bloque, estado_esperado, *, clave)`.
- Produces:
  - `models.PeticionAprobacion` (`extra="forbid"`): `id` (el patron de `models._PATRON_ID`), `accion: Literal["aprobar", "rechazar"]`, `huella: str | None = None`, `motivo: str | None = None`, `autoaprobacion_demo: bool = False`, `riesgo_alto_confirmado: bool = False`; `rechazar` exige `motivo` no vacio.
  - `aprobar.decidir(peticion: PeticionAprobacion, aprobador: AprobadorVerificado) -> tuple[int, dict]`. Codigos: `200` decision escrita, `404` no existe, `409` bloqueada por un control (incluye `RegistroInconsistente` y `EstadoCambiado`). Cuerpo siempre con `"id"`, `"resultado"` (`aprobada`, `rechazada_por_aprobador`, `bloqueada`, `no_existe`) y `"aprobador"` (`model_dump()`); con `"bloqueos": list[str]` si bloquea; con `"decision"` (el bloque escrito), `"estado"` y `"guardado_en"` si escribe.
  - `aprobar.manejador(evento: dict, contexto) -> dict` con `{"statusCode", "headers": {"content-type": "application/json"}, "body": json.dumps(cuerpo, ensure_ascii=True)}`; `400` peticion mal formada o sin identidad firmada, `405` metodo que no es `POST`, `500` entorno roto o error inesperado.

- [ ] **Step 1: tests que fallan.**

```python
def test_decidir_aprueba_y_escribe_solo_su_bloque(monkeypatch):    # guardar_decision(r, "aprobacion", "propuesta", clave="req-prueba")
    assert codigo == 200 and cuerpo["resultado"] == "aprobada" and cuerpo["aprobador"]["persona"] == "aprobador.demo"
def test_decidir_con_otra_huella_no_escribe(monkeypatch):          # 409, guardar_decision -> pytest.fail
def test_decidir_escribe_en_el_id_pedido(monkeypatch):            # documento con otro id -> 409, nada escrito
def test_decidir_fila_inconsistente_es_409(monkeypatch):          # almacen.leer lanza RegistroInconsistente
def test_decidir_otra_corrida_gano_es_409(monkeypatch):           # guardar_decision lanza EstadoCambiado
def test_decidir_no_existe_es_404(monkeypatch):
def test_decidir_rechaza_con_motivo(monkeypatch):                 # bloque "rechazo", estado rechazada_por_aprobador
def test_manejador_solo_post():                                    # GET -> 405
def test_manejador_cuerpo_invalido_o_con_campos_de_mas_es_400():   # incluye {"id": ..., "accion": "aprobar", "estado": "aprobada"}
def test_manejador_sin_identidad_firmada_es_400_y_no_lee():        # authorizer None; almacen.leer -> pytest.fail
def test_manejador_cuerpo_en_base64():                             # isBase64Encoded True
def test_manejador_sin_dynamodb_es_500_y_no_escribe(monkeypatch):  # ALMACEN="disco"
def test_manejador_sin_catalogo_es_500_y_no_escribe(monkeypatch):  # catalogo.no_disponibles -> ["s3"]
def test_manejador_responde_en_ascii():                            # bloqueo con U+202E -> "\\u202e" en body
def test_manejador_no_registra_la_clave_de_acceso(caplog):         # "AKIA" no aparece en los logs
```

- [ ] **Step 2:** `./.venv/bin/python -m pytest tests/unitarios/test_aprobacion.py -q`; FAIL.
- [ ] **Step 3: implementar.** `decidir`: una sola lectura (`almacen.leer(peticion.id)`), `estado_leido` antes de
  decidir (como el `main()` de hoy), `aprobar` o `rechazar`, `guardar_decision(..., clave=peticion.id)`. `manejador`:
  primero `_comprobar_entorno()` (`ALMACEN == "dynamodb"` y `catalogo.no_disponibles(SERVICIOS_PERMITIDOS) == []`,
  calculado una vez por arranque), luego metodo, cuerpo, `aprobador_desde_evento`, `decidir`. Un log por peticion con
  `id`, `accion`, `userArn`, `userId`, `accountId` y el codigo; nada del registro. La excepcion inesperada se registra
  con traza y responde `500` con su tipo.
- [ ] **Step 4:** `test_aprobacion.py` y la bateria entera en verde.
- [ ] **Step 5: Commit** (con el si de Mateo): `Aprobar: decidir y el manejador de la Lambda de aprobacion (ADR-003, A2)`.

### Tarea 5: el cliente de la persona

**Files:**
- Create: `agente_iam/aprobar_cliente.py`, `tests/unitarios/test_aprobar_cliente.py`
- Modify: `agente_iam/config.py` (`URL_APROBACION`), `README.md` (estructura y uso), `CONTEXTO.md` §6 y §7
- Test: el nuevo; los dos de caracteres de control de `test_aprobacion.py` se mueven aqui

**Interfaces:**
- Consumes: `almacen.leer`, `huella.calcular`, `coherencia.riesgo_minimo`, `models.PeticionAprobacion`; en disco,
  `aprobar.decidir` y `aprobar.identificar_aprobador`.
- Produces:
  - `config.URL_APROBACION = os.getenv("AGENTE_IAM_URL_APROBACION", "")`.
  - `aprobar_cliente.enviar(url: str, peticion: PeticionAprobacion) -> tuple[int, dict]`: `POST` con cuerpo
    `peticion.model_dump_json()`, firmado con `SigV4Auth(credenciales, "lambda", AWS_REGION)` sobre un `AWSRequest`
    (credenciales de `boto3.Session().get_credentials().get_frozen_credentials()`), enviado con `urllib.request`,
    timeout 90 s. Un `403` de la URL devuelve `(403, {"resultado": "sin_permiso", "detalle": <texto>})`.
  - `aprobar_cliente.main() -> None`, con las mismas banderas que hoy. Salida: `200` -> 0, `409` -> 3, lo demas -> 1.
  - `_mostrar_propuesta(registro)` y `_mostrar(cuerpo)` se mudan aqui desde `aprobar.py`; `_mostrar` muestra tambien
    `aprobador.persona` y `separacion_de_funciones.solicitante`.
  - El `main()` de `aprobar.py` se va; `python -m agente_iam.aprobar` imprime
    `"Para aprobar: python -m agente_iam.aprobar_cliente <id> (ADR-003)"` y sale con 1, sin importar el cliente.

- [ ] **Step 1: tests que fallan.**

```python
def test_la_firma_es_sigv4_de_lambda_en_la_region(monkeypatch):     # credenciales falsas con token; urlopen capturado
    assert "/us-east-1/lambda/aws4_request" in pedido.headers["Authorization"]
    assert pedido.headers["X-Amz-Security-Token"] == "token-falso" and pedido.data == peticion.model_dump_json().encode()
def test_sin_huella_solo_pinta_y_no_envia(monkeypatch, capsys):      # enviar -> pytest.fail; sale con 3; huella en pantalla
def test_con_huella_envia_id_y_huella(monkeypatch):
def test_dynamodb_sin_url_no_escribe_nada(monkeypatch):              # URL_APROBACION ""; guardar_decision y decidir -> pytest.fail; sale con 1
def test_en_dynamodb_nunca_llama_a_guardar_decision(monkeypatch):
def test_en_disco_decide_aqui_y_lo_dice(monkeypatch, capsys):        # "sin servidor" en la salida; decidir llamado
@pytest.mark.parametrize("codigo,salida", [(200, 0), (409, 3), (404, 1), (400, 1), (403, 1), (500, 1)])
def test_codigo_de_la_url_a_codigo_de_salida(monkeypatch, codigo, salida):
def test_la_revision_no_imprime_caracteres_de_control(capsys):       # movido
def test_lo_que_responde_el_servidor_tampoco(capsys, monkeypatch):   # bloqueos con "\x1b[2J" escapados
def test_python_m_aprobar_apunta_al_cliente():                       # runpy; SystemExit(1) y el texto exacto
```

- [ ] **Step 2:** `./.venv/bin/python -m pytest tests/unitarios/test_aprobar_cliente.py -q`; FAIL (`ModuleNotFoundError`).
- [ ] **Step 3: implementar.** La lectura unica y lo que se pinta son los de hoy. Con `ALMACEN == "dynamodb"` envia a
  `URL_APROBACION`; con disco, avisa en una linea de que no hay servidor ni la garantia de ADR-003 y llama a
  `aprobar.decidir(peticion, aprobar.identificar_aprobador())` importado dentro de esa rama. Lo que responde el
  servidor se pinta con `imprimible`, como hoy. README: estructura (`aprobar.py` = servidor y Lambda,
  `aprobar_cliente.py` = la persona), el comando nuevo y `AGENTE_IAM_URL_APROBACION`; CONTEXTO §6 los dos modulos y
  el fichero de tests; §7 el comando.
- [ ] **Step 4:** el fichero nuevo, `test_documentacion.py` y la bateria entera en verde.
- [ ] **Step 5: Commit** (con el si de Mateo): `Aprobar: cliente que lee, ensena la huella y firma la peticion (ADR-003, A2)`.

### Tarea 6: el paquete de la Lambda

**Files:**
- Create: `requirements-aprobacion.txt`
- Modify: `scripts/empaquetar.sh`, `tests/seguridad/test_ci.py`

**Interfaces:**
- Consumes: el manejador `agente_iam.aprobar.manejador` (Tarea 4).
- Produces: `scripts/empaquetar.sh aprobacion` deja `dist/agente-iam-aprobacion.zip` e imprime la clave S3
  `agente-iam/aprobacion-<12 primeros hex del sha256 del zip>.zip`; `scripts/empaquetar.sh` sin argumento (o
  `runtime`) hace lo de hoy, byte a byte.

- [ ] **Step 1: tests que fallan** en `test_ci.py`:

```python
def test_la_lambda_de_aprobacion_lleva_lo_que_importa_y_nada_mas():
    fuera = _lista(script, "FUERA_DE_LA_APROBACION")
    cadena = _cadena_de_imports(RAIZ / "agente_iam" / "aprobar.py")
    assert {"aprobar.py", "huella.py", "almacen.py"} <= cadena
    assert {"aprobar_cliente.py", "aplicador.py", "cli.py", "servidor.py", "orquestador.py", "agente.py"} <= set(fuera)
    assert sorted(set(fuera) & cadena) == []
def test_el_runtime_tampoco_lleva_el_cliente():          # "aprobar_cliente.py" en FUERA_DEL_RUNTIME
def test_la_aprobacion_no_lleva_el_sdk_de_agentcore():   # bedrock-agentcore no esta en requirements-aprobacion.txt
def test_la_lambda_cabe_en_250_mb():                     # el script compara el plano con 250 para "aprobacion"
```

  `test_constraints_coincide_con_las_directas` incluye `requirements-aprobacion.txt` en su tupla.

- [ ] **Step 2:** `./.venv/bin/python -m pytest tests/seguridad/test_ci.py -q`; FAIL.
- [ ] **Step 3: implementar.** Un argumento `DESTINO_PAQUETE` (`runtime` o `aprobacion`) que elige requisitos, lista de
  fuera, nombre del zip, si copia `main.py` (solo el runtime) y el limite plano (750 o 250). Los pasos 1, 2, 4 y 6
  son los mismos. `requirements-aprobacion.txt`: `strands-agents`, `boto3`, `pydantic`, `botocore` con las versiones
  de `requirements.txt` (`strands` lo importan `catalogo.py` y `validacion.py`).
- [ ] **Step 4:** tests en verde y `scripts/empaquetar.sh aprobacion` de verdad (local, sin cuenta; necesita red para
  el catalogo y las ruedas). Anotar comprimido y plano. **Si el plano pasa de 250 MB, se para aqui y se decide con
  Mateo** (capa, o quitar `strands` de la cadena de la Lambda).
- [ ] **Step 5: Commit** (con el si de Mateo): `Empaquetar: zip de la Lambda de aprobacion, sin el cliente ni el runtime (ADR-003)`.

### Tarea 7: la pila base con la Lambda, su rol y los dos menores

**Files:**
- Modify: `infra/cfn/base.yaml`, `tests/seguridad/test_pila_base.py`

**Interfaces:**
- Consumes: la clave S3 de la Tarea 6, `huella`/`almacen` (las condiciones de `guardar_decision`).
- Produces (nombres exactos):
  - Parametro `ClaveCodigoAprobacion` (String, sin defecto, `AllowedPattern: ^agente-iam/aprobacion-[0-9a-f]{12}\.zip$`).
  - `RolAprobacion`: `AgenteIAM-Aprobacion`, boundary `AgenteIAM-LimiteSistema`, confianza `lambda.amazonaws.com` con
    `aws:SourceAccount` y `aws:SourceArn` = `arn:aws:lambda:us-east-1:${AWS::AccountId}:function:agente-iam-aprobacion`.
    Inline `AgenteIAM-Aprobacion-permisos`: `LeerLaSolicitud` (`GetItem`); `EscribirSoloLaDecision` (`UpdateItem`,
    `dynamodb:Attributes` = `id`, `estado`, `aprobacion`, `rechazo`, `Null` en falso, `ReturnValues` como los otros);
    `RevalidarConLasReglasDeHoy` (la lista de hoy del permission set, sobre `policy/*`, `role/*`, `user/*` de la
    cuenta); `AccessAnalyzerNoTieneRecurso` (`ValidatePolicy`, `CheckNoNewAccess`); `LogsDeSuLambda`;
    `NuncaReemplazarNiBorrarFilas`; `NuncaEscribirEnIAM` (la del runtime); `NuncaHablarConElModelo` (`bedrock:*`).
  - `RegistroAprobacion`: `AWS::Logs::LogGroup` `/aws/lambda/agente-iam-aprobacion`, 365 dias, `Retain`.
  - `FuncionAprobacion`: `agente-iam-aprobacion`, `python3.12`, `arm64`, `Handler: agente_iam.aprobar.manejador`,
    codigo en `agente-iam-despliegue-${AWS::AccountId}` / `ClaveCodigoAprobacion`, 60 s, 512 MB, entorno
    `ALMACEN=dynamodb`, `TABLA_SOLICITUDES=agente-iam-solicitudes`, `DIR_CACHE_CATALOGO=/var/task/catalogo` (sin
    `AWS_REGION`: la pone Lambda y es reservada).
  - `UrlAprobacion`: `AWS::Lambda::Url`, `AuthType: AWS_IAM`, sin `Cors`. **Ningun `AWS::Lambda::Permission`**: la
    persona y la funcion estan en la misma cuenta y basta la politica de identidad (guia de Lambda, 24-10-2026).
  - Salidas `UrlAprobacion` (`FunctionUrl`), `FuncionAprobacionArn`, `RolAprobacionArn`.
  - Menores: `PoliticaBucketPaquete` con `DeletionPolicy` y `UpdateReplacePolicy` `Retain`; `NuncaReemplazarNiBorrarFilas`
    de los tres roles anade `dynamodb:PartiQL*`, `dynamodb:UpdateTimeToLive` y `dynamodb:UpdateContinuousBackups`.

- [ ] **Step 1: tests que fallan.** `ROLES` pasa a `("RolRuntime", "RolAplicador", "RolAprobacion")`.

```python
def test_solo_la_lambda_de_aprobacion_escribe_la_decision():      # sustituye a test_nadie_escribe_aprobacion
    assert {"aprobacion", "rechazo"} <= lista["RolAprobacion"] and not {"documento", "aplicacion"} & lista["RolAprobacion"]
    assert not {"aprobacion", "rechazo"} & (lista["RolRuntime"] | lista["RolAplicador"])
def test_lo_que_escribe_el_codigo_cabe_en_su_rol(monkeypatch):     # ampliado: guardar_decision de "aprobacion" y de "rechazo" contra RolAprobacion
def test_ningun_rol_puede_reemplazar_ni_borrar_filas():             # ampliado: PartiQL*, UpdateTimeToLive, UpdateContinuousBackups
def test_la_url_exige_firma_y_nadie_mas_la_abre():                 # AuthType AWS_IAM; ningun AWS::Lambda::Permission en la pila
def test_la_funcion_es_la_que_espera_el_codigo():                  # Handler, arm64, python3.12, entorno exacto, sin AWS_REGION
def test_la_aprobacion_no_escribe_en_iam_ni_habla_con_el_modelo():
def test_la_politica_del_bucket_sobrevive_a_la_pila():
def test_confianza_con_cuenta_de_origen():                          # ampliado al tercer rol, SourceArn exacto
```

- [ ] **Step 2:** `./.venv/bin/python -m pytest tests/seguridad/test_pila_base.py tests/seguridad/test_plantillas_cfn.py -q`; FAIL.
- [ ] **Step 3: implementar** en `base.yaml`, con la cabecera del fichero al dia (el reparto de atributos ya nombra a la Lambda).
- [ ] **Step 4:** tests en verde; `validate_cloudformation_template` y `check_cloudformation_template_compliance` del
  MCP `awsiac` sobre `base.yaml` sin errores (los avisos se leen y se dicen).
- [ ] **Step 5: Commit** (con el si de Mateo): `Pila base: Lambda de aprobacion con URL AWS_IAM, su rol y los dos menores (ADR-003)`.

### Tarea 8: el rol de despliegue puede crear la URL

**Files:**
- Modify: `infra/cfn/arranque.yaml` (`LambdaSoloRecursosDelProyecto`), `tests/seguridad/test_plantillas_cfn.py`

**Interfaces:**
- Produces: `AgenteIAM-Despliegue` con las acciones de los manejadores de `AWS::Lambda::Url`, sobre `function:agente-iam-*`.

- [ ] **Step 1: leer el esquema** (lectura, sin escribir): `cloudformation:DescribeType` de `AWS::Lambda::Url` con el MCP
  de AWS; apuntar los `handlers.*.permissions`. Se espera `lambda:CreateFunctionUrlConfig`, `GetFunctionUrlConfig`,
  `UpdateFunctionUrlConfig` y `DeleteFunctionUrlConfig`; si el esquema pide otra (`lambda:AddPermission`, por ejemplo),
  se para y se habla con Mateo, porque la gemela del techo la niega.
- [ ] **Step 2: test que falla**: `test_el_despliegue_puede_crear_urls_solo_del_proyecto` (las acciones del esquema en
  `LambdaSoloRecursosDelProyecto` y en ninguna sentencia con `Resource: "*"`). Correrlo: FAIL.
- [ ] **Step 3: implementar**; `test_el_despliegue_no_tiene_comodines_de_servicio` sigue en verde.
- [ ] **Step 4:** bateria entera y `validate_cloudformation_template` sobre `arranque.yaml`.
- [ ] **Step 5: Commit** (con el si de Mateo): `Arranque: el rol de despliegue crea URLs de funcion del proyecto (ADR-003)`.

### Tarea 9: el permission set del aprobador y el bucket del operador

**Files:**
- Modify: `infra/cfn/identidades.yaml` (`PermisosAprobador` y su comentario, `SubirElPaqueteDelCodigo`), `tests/seguridad/test_plantillas_cfn.py`

**Interfaces:**
- Produces: `PermisosAprobador` con exactamente `LeerLaSolicitud` (`GetItem`), `InvocarLaAprobacion` y
  `NuncaEscribirLaTabla`; el operador sube a `arn:aws:s3:::agente-iam-despliegue-${CuentaAgenteIam}/agente-iam/*`.

- [ ] **Step 1: tests que fallan** (sustituyen a `test_el_aprobador_solo_escribe_su_decision`):

```python
def test_el_aprobador_no_escribe_la_tabla():
    assert {a for s in allow for a in _acciones(s) if a.startswith("dynamodb:")} == {"dynamodb:GetItem"}
    assert {"dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem",
            "dynamodb:PartiQLInsert", "dynamodb:PartiQLUpdate", "dynamodb:PartiQLDelete"} <= denegadas_sobre_la_tabla
def test_el_aprobador_solo_invoca_la_aprobacion_y_solo_por_la_url():
    # recurso exacto arn:aws:lambda:us-east-1:${CuentaAgenteIam}:function:agente-iam-aprobacion en las dos
    assert url["Condition"] == {"StringEquals": {"lambda:FunctionUrlAuthType": "AWS_IAM"}}
    assert invocar["Condition"] == {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}}
def test_el_aprobador_ya_no_revalida():                    # sin iam:* ni access-analyzer:* (decision 4)
def test_el_operador_sube_al_bucket_de_la_pila_base():     # el nombre sale de base.yaml, no se copia en el test
```

- [ ] **Step 2:** `./.venv/bin/python -m pytest tests/seguridad/test_plantillas_cfn.py -q`; FAIL.
- [ ] **Step 3: implementar**, con el comentario de `PermisosAprobador` reescrito (por que solo lee e invoca) y la
  `Description` sin "escribir solo la decision".
- [ ] **Step 4:** bateria entera y `validate_cloudformation_template` sobre `identidades.yaml`.
- [ ] **Step 5: Commit** (con el si de Mateo): `Identidades: el aprobador invoca la Lambda y no escribe la tabla; bucket del operador (ADR-003)`.

### Tarea 10: despliegue y mediciones (cada escritura, con el si de Mateo)

**Files:**
- Create (fuera de git): `evidencias/aprobacion-servidor/<fecha>/` con cada salida
- Modify: `scripts/sonda_atributos.py` y su test solo si M4 lo necesita (casos esperados nuevos)

Orden, y por que: la URL no se puede crear sin la Tarea 8 desplegada; el operador no puede subir el zip sin la Tarea 9
desplegada. Entre el despliegue de identidades y el de la base nadie puede aprobar: hoy no hay solicitudes pendientes
(la unica fila es `sonda-atributos-20261024`).

- [ ] **Step 1:** `scripts/localizar.py` para las copias de `local/` con la cuenta real; leer las pilas
  `agente-iam-arranque`, `agente-iam-base` e identidades (`DescribeStacks`): `*_COMPLETE` y sin deriva.
- [ ] **Step 2 (Mateo, administrador):** conjunto de cambios de `agente-iam-arranque`. Revisarlo juntos: un solo
  `Modify` de la politica del despliegue, sin reemplazo. Con su si, ejecutarlo.
- [ ] **Step 3 (Mateo, administrador, cuenta de gestion):** conjunto de cambios de la pila de identidades: `Modify` de
  `PermisosAprobador` y `PermisosOperador`, nada mas. Con su si, ejecutarlo. Comprobar el reaprovisionamiento
  (`DescribePermissionSetProvisioningStatus` o `ListPermissionSetProvisioningStatus`).
- [ ] **Step 4 (operador, con el si de Mateo):** `scripts/empaquetar.sh aprobacion`, subir el zip a su clave; conjunto
  de cambios `aprobacion` de `agente-iam-base` con `ClaveCodigoAprobacion` y `AgenteIAM-Despliegue`. Revisarlo: 4
  `Add` (`RolAprobacion`, `RegistroAprobacion`, `FuncionAprobacion`, `UrlAprobacion`) y los `Modify` de los menores
  (`PoliticaBucketPaquete`, `RolRuntime`, `RolAplicador`), sin reemplazo de la tabla ni del bucket. Con su si, ejecutarlo.
- [ ] **Step 5: mediciones** (perfil `org-agente-iam-aprobador-demo`; sesion SSO propia, ventana privada, nunca `aws sso logout`; F.6):
  - **M1, el campo del evento (ADR-003, pendiente 1):** `aprobar_cliente.enviar(URL, PeticionAprobacion(id=
    "sonda-atributos-20261024", accion="aprobar", huella="sha256:0"))` desde el `.venv` (el CLI no llegaria: su
    propia lectura rechaza esa fila antes de enviar). Se espera `409` (la fila no tiene `documento`) con `aprobador.arn_llamante` =
    `arn:aws:sts::<cuenta>:assumed-role/AWSReservedSSO_AgenteIAM-Aprobador_<sufijo>/aprobador.demo` y `persona` =
    `aprobador.demo`; el log de la funcion con el mismo `userArn` y `userId`. Si `userArn` trae otra forma, se para:
    `aprobador_desde_evento` se corrige con la forma medida y su test.
  - **M2:** `lambda:Invoke` directo de `agente-iam-aprobacion` con un evento fabricado: `AccessDeniedException`.
  - **M3:** `POST` sin firmar a la URL: `403`.
  - **M4:** la sonda de atributos como `aprobador.demo`: `UpdateItem SET aprobacion` y `PutItem` dan
    `AccessDeniedException` con "explicit deny"; `GetItem` sigue permitido.
  - **M5 (opcional, decide Mateo: escribe una fila de prueba como administrador y cuesta una `CheckNoNewAccess`):** una
    fila `propuesta` de un `ejemplos/` sobre un beneficiario con techo, `aprobar_cliente <id>` y luego
    `--huella H --autoaprobacion-demo`: `200`, `separacion_de_funciones.resultado = SALTADO`, `aprobacion.por.persona =
    aprobador.demo`, y el aplicador en seco la acepta solo con `AGENTE_IAM_PERMITIR_AUTOAPROBACION=si`.
- [ ] **Step 6:** cada resultado en `docs/MEDICIONES.md` F.7 (fecha, cuenta, perfil, llamada, resultado); lo que no
  salga como se esperaba, tambien en §H. Las filas de prueba quedan para que Mateo las borre (§11, paso 6c).

### Tarea 11: documentacion del avance

**Files:**
- Modify: `PLAN-CORRECCIONES.md` (Fase 19), `CONTEXTO.md` §2, §3, §4, §5, §9, §10, §11, `README.md`,
  `docs/DESPLIEGUE.md`, `docs/ADR-003-aprobacion-en-servidor-y-persona.md` (estado: implementado; pendiente 1 medido),
  `ESTUDIO-diseno-y-seguridad.md` (si M1 a M5 dejan una leccion), docstrings de `aprobar.py`, `almacen.py`, `huella.py`.

- [ ] **Step 1:** Claude redacta el encargo cerrado (ficheros, que cambia en cada uno, que no se toca) con lo que de
  verdad quedo: que se midio y que no (pendientes 2 y 3 del ADR siguen abiertos), la consecuencia de la decision 8 y
  el limite que no cierra (el administrador de la cuenta).
- [ ] **Step 2:** subagente Sonnet escribe; Claude revisa el diff contra la tabla de `CLAUDE.md`, busca los
  identificadores reales (`grep`) y quita de §10 y §4 los "pendiente de implementar" que ya no lo son.
- [ ] **Step 3:** `./.venv/bin/python -m pytest tests/ -q` y `./.venv/bin/ruff check .` en verde.
- [ ] **Step 4: Commit** (con el si de Mateo): `Fase 19: aprobacion en servidor y separacion por persona, documentada (ADR-003)`.
