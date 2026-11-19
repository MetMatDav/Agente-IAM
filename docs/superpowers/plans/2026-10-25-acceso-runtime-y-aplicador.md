# Pilas acceso y runtime, aplicador como Lambda, cliente con JWT - plan de implementacion

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** que el analista corra en AgentCore Runtime aceptando solo JWT de Cognito federado con Identity Center, que
el registro lleve la persona que pidio (claims validados), que el aplicador sea una Lambda disparada por el stream de
la tabla con el estado nuevo `bloqueada_al_aplicar`, y que todo ello este en CloudFormation con sus tests.

**Architecture:** dos pilas nuevas en `agente-iam` (`infra/cfn/acceso.yaml`: Cognito; `infra/cfn/runtime.yaml`:
runtime, Lambda del aplicador, disparador, cola de fallos, alarma y trail de datos), una pila pequena que despliega el
administrador (`infra/cfn/beneficiarios.yaml`: un rol de demo con el techo), un cambio minimo en `base.yaml` (el rol
del aplicador puede escribir en la cola de fallos), `servidor.py` leyendo los claims, `aplicador.py` con el manejador
de Lambda, `empaquetar.sh aplicador` y un cliente `scripts/solicitar.py`.

**Tech Stack:** Python 3.12 del `.venv`, boto3/botocore 1.43.82 (`Stubber`), pydantic 2.13.4, pytest,
CloudFormation YAML leido con `yaml.safe_load` y validado con cfn-lint 1.57.2, Lambda arm64 `python3.12`,
AgentCore Runtime `PYTHON_3_12` con `customJWTAuthorizer`.

**Spec:** `docs/ESPECIFICACION-agentcore.md` (requisitos 1.x, 2.x, 3, 4 y 7.x) y `docs/ADR-001-agentcore-identidad.md`.
Decisiones D1 a D8 de Mateo del 25-10-2026 (abajo). Contexto: `CONTEXTO.md` §3, §4, §10 y §11; `docs/MEDICIONES.md`
§D y §F; `infra/cfn/prueba-eco.yaml` (la Prueba B, de la que nace la pila de acceso).

## Global Constraints

- Ningun subagente llama a AWS ni escribe en la cuenta: todo se prueba sin red (`tests/conftest.py` lo vigila). Las
  escrituras en la cuenta las hace Claude con el si de Mateo para cada una.
- Ningun subagente hace commits: Claude revisa cada diff y commitea los ficheros de la tarea. Cada tarea toca SOLO los
  ficheros de su lista; otros subagentes editan otros ficheros a la vez.
- Cada subagente corre solo los ficheros de tests de su tarea mas `./.venv/bin/ruff check <sus ficheros>` y, si toca
  `agente_iam/`, `./.venv/bin/mypy agente_iam`. La bateria completa la corre Claude al cerrar. Un fallo en un test
  ajeno a la tarea (por ejemplo `test_documentacion.py`, que exige que los ficheros nuevos esten en CONTEXTO) no es
  de la tarea: se anota en el informe y no se arregla.
- Codigo, comentarios y docstrings en espanol sin acentos ni enes (como el resto del repositorio: "diseno",
  "politica"). Sin guion largo en ningun sitio. Cada modulo explica el PORQUE en su docstring, no solo el que.
- En lo versionado va la cuenta `111122223333`; nunca la real, ni ids de pool, ni correos, ni `sub`.
- Plantillas YAML sin etiquetas cortas (`!Ref`, `!Sub`): se escriben `Ref:`, `Fn::Sub:`, `Fn::GetAtt:`, porque los
  tests las leen con `yaml.safe_load`. Region `us-east-1`. Nombres de recursos del sistema con prefijo `agente-iam-`
  (Lambda, colas, alarmas, buckets, trail) o `AgenteIAM-` (roles); los recursos de un BENEFICIARIO nunca llevan esos
  prefijos (`config.PREFIJOS_DEL_SISTEMA`).
- Cada arreglo lleva un test que se pone en rojo si se deshace. Los tests de plantillas siguen el estilo de
  `tests/seguridad/test_pila_base.py` y `tests/seguridad/test_prueba_eco.py` (leer el YAML, fijar invariantes).
- El token JWT nunca se imprime, nunca se graba en el registro ni en un log; solo una lista cerrada de claims.
- La duda bloquea: sin claims, persona `None`; una persona `None` hace que la aprobacion bloquee (ya implementado en
  `aprobar._separacion`).

## Decisiones de Mateo (25-10-2026) que este plan ejecuta

- D1: pila `agente-iam-beneficiarios` con un rol de demo `app-finanzas-demo` con el techo como boundary y un bucket de
  prueba `finanzas-demo-<cuenta>`; la despliega el administrador.
- D2: la Lambda del aplicador no lleva `AGENTE_IAM_PERMITIR_AUTOAPROBACION` (puerta cerrada, sin parametro).
- D3: un solo trail de datos, `agente-iam-datos`, con los eventos de datos de AgentCore Runtime y de la Lambda
  `agente-iam-aprobacion`; bucket con caducidad a 90 dias.
- D4: Lambda del aplicador con lote de 1, 2 reintentos, cola de fallos `agente-iam-aplicador-fallos` y alarma
  `agente-iam-aplicador-fallos` que publica en el tema SNS `agente-iam-alarmas` (correo como parametro).
- D7: el cliente del solicitante es `scripts/solicitar.py`, que reutiliza el PKCE de `scripts/prueba_b.py`.
- D8: el grupo de logs del runtime se declara en la pila con el nombre que AgentCore le da.

## Review Focus

1. Un token que llega sin `Bearer`, sin tres partes o con `username` sin el prefijo `IdentityCenter_` deja
   `persona = None` y `ejecutado_por.determinable = False`; nunca se inventa una persona (Tarea 1).
2. El manejador del aplicador relee la fila y no se fia del evento; un evento con `estado = aprobada` cuya fila ya no
   esta en `aprobada` no escribe nada (Tarea 2).
3. Un bloqueo del pre-vuelo escribe `bloqueada_al_aplicar` UNA vez (condicion `estado = aprobada AND
   attribute_not_exists(aplicacion)`) y no se reintenta; un fallo de entorno o de AWS se relanza para que Lambda
   reintente y acabe en la cola de fallos (Tarea 2).
4. El filtro del disparador es exactamente `estado = aprobada` en la imagen nueva, y el rol del aplicador solo puede
   escribir en SU cola de fallos (Tareas 5 y 7).
5. El runtime acepta solo JWT del cliente de la pila de acceso y solo deja pasar `Authorization` (Tarea 5).

---

### Task 1: el servidor graba la persona de los claims validados

**Files:**
- Modify: `agente_iam/servidor.py`
- Test: `tests/unitarios/test_servidor.py`

**Interfaces:**
- Produces: `servidor.claims_validados(context) -> dict | None` y `servidor.persona_de(claims) -> str | None`.
- Consumes: `context.request_headers` del SDK `bedrock-agentcore` 1.22.0 (`RequestContext.request_headers`, un dict
  que trae la cabecera `Authorization` tal cual la allowlist del runtime la deja pasar); `models.SolicitanteVerificado`.

**Por que:** medido en la Prueba B (MEDICIONES D.2): el autorizador JWT de AgentCore valida firma, emisor, caducidad
y cliente antes de dejar pasar la peticion, y el contenedor recibe la cabecera `Authorization` con el token ya
validado. Hoy `servidor.py` graba `ejecutado_por` como no determinable (SigV4) y `solicitante.persona = None`, asi que
toda aprobacion real bloquea. Con los claims, el registro lleva quien pidio (ESPECIFICACION §3) y la separacion por
persona de ADR-003 se vuelve real (§4).

**Diseno:**
- Constantes: `PREFIJO_USERNAME = "IdentityCenter_"`; `CLAIMS_DEL_REGISTRO = ("sub", "username", "jti")`;
  `COMO_SE_VERIFICO_JWT = "JWT validado por el autorizador de AgentCore (customJWTAuthorizer); el contenedor lee los
  claims sin volver a verificar la firma, porque solo es alcanzable a traves del runtime"`.
- `claims_validados(context)`: lee `getattr(context, "request_headers", None)`; busca la clave `Authorization` y, si no
  esta, `authorization`; exige el prefijo `Bearer ` (sin distinguir mayusculas en `Bearer`); parte el token por `.` y
  exige tres partes; decodifica la segunda en base64url con relleno `=` y la carga como JSON objeto; devuelve SOLO
  `{k: v for k in CLAIMS_DEL_REGISTRO if k in carga}`. Ante cualquier fallo devuelve `None`. No verifica la firma
  (es el patron de `infra/pruebas-agentcore/agente_eco.py::claims_sin_verificar`, y el docstring explica por que aqui
  es correcto y donde seria un agujero).
- `persona_de(claims)`: `username` sin `PREFIJO_USERNAME` si lo lleva; `None` si no hay claims, no hay `username`, o
  no empieza por el prefijo. No normaliza nada (la normalizacion `NFKC` + `casefold()` es de `aprobar._misma_persona`).
- `_quien_invoco(context)` pasa a devolver, con claims:
  `{"determinable": True, "sub": ..., "usuario": <username completo>, "jti": ..., "sesion_runtime": context.session_id,
  "request_id": _request_id(), "como_se_verifico": COMO_SE_VERIFICO_JWT}` (las claves que falten en el token van como
  `None`); sin claims devuelve el dict de hoy (`arn: None`, `determinable: False`, `motivo`, `session_id`,
  `request_id`) con el `motivo` actualizado: "sin cabecera Authorization con un JWT; con SigV4 AgentCore no entrega al
  codigo la identidad del principal...".
- `manejar`: `registro["solicitante"] = SolicitanteVerificado(persona=persona_de(claims), como_se_verifico=...)`
  donde `como_se_verifico` es `"claim username del JWT validado por el autorizador de AgentCore (NameID de Identity
  Center, ADR-001)"` con persona, y sin persona explica cual de las tres cosas falto (sin JWT; sin claim `username`;
  `username` sin el prefijo `IdentityCenter_`). `SOLICITANTE_RUNTIME` se renombra a `SIN_JWT` con el texto del caso
  sin JWT. Los claims se calculan UNA vez por peticion y se pasan a las dos funciones.
- El token completo no se guarda en ninguna variable que acabe en el registro ni en un log; `log.info` de
  `manejar` puede anadir `persona=%s` (solo la persona).

- [ ] **Step 1: tests que fallan** (en `tests/unitarios/test_servidor.py`, con un `_jwt(carga)` como el de
  `tests/unitarios/test_prueba_b.py` y una clase `_Contexto` con `request_headers`):
  - con `Authorization: Bearer <jwt>` cuyo `username` es `IdentityCenter_solicitante.demo`: el registro lleva
    `solicitante.persona == "solicitante.demo"`, `ejecutado_por.determinable is True`, `sub`, `usuario`, `jti` y
    `sesion_runtime` correctos; el token NO aparece en `json.dumps(registro)`;
  - la clave `authorization` en minusculas tambien vale;
  - sin cabecera: `persona is None`, `determinable is False` y `como_se_verifico` nombra el JWT ausente;
  - cabecera sin `Bearer`, o token con dos partes, o carga que no es JSON: como sin cabecera;
  - `username` sin prefijo (`solicitante.demo`): `persona is None` y `como_se_verifico` nombra el prefijo;
  - token sin `jti`: `ejecutado_por["jti"] is None` y lo demas se graba;
  - los tests existentes `test_ejecutado_por_se_declara_no_determinable` y
    `test_el_runtime_graba_solicitante_sin_persona` siguen valiendo para el caso sin cabecera (ajustar sus asserts
    de texto si cambian).
- [ ] **Step 2: implementar** lo de arriba en `servidor.py`, actualizando el docstring de cabecera ("Con JWT el
  runtime recibe los claims validados...") y el de `_quien_invoco`.
- [ ] **Step 3: verificar**: `./.venv/bin/python -m pytest tests/unitarios/test_servidor.py -q`,
  `./.venv/bin/ruff check agente_iam/servidor.py tests/unitarios/test_servidor.py`, `./.venv/bin/mypy agente_iam`.

---

### Task 2: el aplicador como Lambda, con `bloqueada_al_aplicar`

**Files:**
- Modify: `agente_iam/aplicador.py`, `agente_iam/models.py` (el literal `Estado`), `agente_iam/aprobar.py` (solo el
  dict de `_por_que_no`)
- Test: `tests/unitarios/test_aplicador.py`, `tests/unitarios/test_modelos.py` (si fija la lista de estados)

**Interfaces:**
- Produces: `aplicador.manejador(evento, contexto) -> dict` (handler `agente_iam.aplicador.manejador`),
  `aplicador.procesar_aprobada(solicitud_id) -> dict`, estado `bloqueada_al_aplicar`.
- Consumes: `almacen.leer`, `almacen.guardar_decision(registro, "aplicacion", estado_esperado, clave=id)`,
  `aplicar(registro)`, `identificar_aprobador()`, `catalogo.no_disponibles`, `SERVICIOS_PERMITIDOS`.

**Por que:** ESPECIFICACION §7. Hoy el aplicador es un CLI que alguien lanza con el rol del aplicador, es decir, una
persona con escritura en IAM (riesgo 1 del bloque 3). Como Lambda disparada por el stream de la tabla, ninguna
persona lo asume. Un bloqueo del pre-vuelo hoy sale con codigo 3 sin escribir; en Lambda reintentaria para siempre,
de ahi el estado nuevo `bloqueada_al_aplicar` (7.5), que es una decision escrita una sola vez.

**Diseno:**
- `models.Estado` gana `"bloqueada_al_aplicar"` (despues de `"aplicada"`). `aprobar._por_que_no` gana la entrada
  `"bloqueada_al_aplicar": "El aplicador la bloqueo en el pre-vuelo; se tramita de nuevo con otro id."`.
- `procesar_aprobada(solicitud_id)` devuelve un dict `{"id": ..., "resultado": ..., ...}` con `resultado` en
  `aplicada | bloqueada_al_aplicar | omitida`:
  1. `almacen.leer(id)`; `RegistroInconsistente` -> `omitida` con `motivo` (log WARNING: una fila con forma imposible
     es un control que salta, S1; no se escribe nada porque no hay registro fiable sobre el que decidir);
     `None` -> `omitida` ("no existe").
  2. `estado_leido = registro["estado"]`; si no es `"aprobada"` -> `omitida` ("el evento es viejo: la fila esta en
     <estado>"). Es el requisito 7.2: se relee la fila y no se confia en el evento.
  3. `resultado, bloqueos, avisos = aplicar(registro)`.
  4. Con bloqueos: `registro["aplicacion"] = {"cuando": _ahora(), "decision": "bloquear", "bloqueos": bloqueos,
     "avisos": avisos, "por": identificar_aprobador().model_dump()}`, `registro["estado"] = "bloqueada_al_aplicar"`,
     `almacen.guardar_decision(registro, "aplicacion", estado_leido, clave=solicitud_id)`. Si salta
     `EstadoCambiado` o `RegistroInconsistente`: `omitida` con motivo (otro proceso decidio). Devuelve
     `bloqueada_al_aplicar` con `bloqueos`.
  5. Sin bloqueos: `guardar_decision(resultado, "aplicacion", estado_leido, clave=solicitud_id)`. Si salta
     `EstadoCambiado` o `RegistroInconsistente` AQUI, la politica ya esta creada y adjunta en AWS: se registra
     `log.error` con el `policy_arn` y se relanza `RuntimeError` con el ARN en el mensaje (va a la cola de fallos:
     alguien tiene que mirar). Devuelve `aplicada` con `policy_arn`.
  Cualquier otra excepcion sube tal cual (Lambda reintenta 2 veces y manda el evento a la cola de fallos).
- `manejador(evento, contexto)`:
  - comprueba el entorno como `aprobar._comprobar_entorno` (ALMACEN es `dynamodb`; los catalogos de
    `SERVICIOS_PERMITIDOS` cargan); con problemas lanza `RuntimeError` ANTES de leer nada (igual que la Lambda de
    aprobacion responde 500: un entorno roto no decide);
  - recorre `evento["Records"]`; de cada uno toma `eventName` (solo `INSERT` y `MODIFY`), `dynamodb.Keys.id.S` y
    `dynamodb.NewImage.estado.S`; si el estado de la imagen no es `aprobada` se omite sin leer la tabla (el filtro
    del disparador ya lo hace; esto es defensa en profundidad y se dice);
  - llama a `procesar_aprobada(id)`; una linea de log por registro con `id` y `resultado` (y `policy_arn` si lo hay),
    nunca el registro;
  - devuelve `{"procesados": [<dict de cada registro>]}`.
- `main()` (el CLI) se conserva para el backend de disco; su docstring dice que en la cuenta el aplicador es la Lambda
  `agente-iam-aplicador` y que el CLI es el camino de desarrollo. El docstring de cabecera del modulo actualiza el
  parrafo "Se corre con AWS_PROFILE=agente-iam-aplicador" y el de la "decision pendiente de Mateo" (ya tomada:
  ADR-003, la aprobacion la escribe el servidor).
- `logging`: `log = logging.getLogger("agente-iam.aplicador")` con `setLevel(logging.INFO)` (mismo motivo que en
  `aprobar.py`: en Lambda el raiz esta en WARNING).

- [ ] **Step 1: tests que fallan** (en `tests/unitarios/test_aplicador.py`, con `monkeypatch` sobre
  `aplicador.aplicar`, `aplicador.almacen.leer`, `aplicador.almacen.guardar_decision`,
  `aplicador.identificar_aprobador` y `aplicador.catalogo.no_disponibles`; `ALMACEN=dynamodb` via
  `monkeypatch.setattr(aplicador.almacen, "ALMACEN", "dynamodb")` o como lo haga `test_aprobacion.py` para la
  Lambda de aprobacion; un `_evento_stream(id, estado, event_name="MODIFY")` que fabrica el evento de DynamoDB
  Streams):
  - `manejador` con un registro `aprobada` y `aplicar` que devuelve resultado: `guardar_decision` recibe bloque
    `aplicacion`, `estado_esperado == "aprobada"`, `clave == id`, y el registro con `estado == "aplicada"`; la
    respuesta lleva `resultado == "aplicada"` y `policy_arn`;
  - `aplicar` devuelve bloqueos: se escribe UNA vez con `estado == "bloqueada_al_aplicar"`, el bloque `aplicacion`
    lleva `decision == "bloquear"`, los `bloqueos` y `por`; la respuesta lleva `bloqueada_al_aplicar`;
  - la fila leida esta en otro estado (`aplicada`): no se llama a `aplicar` ni a `guardar_decision`; `omitida`;
  - la imagen nueva del evento trae `estado = propuesta`: no se lee la tabla (`leer` no se llama);
  - `leer` devuelve `None`: `omitida`; `leer` lanza `RegistroInconsistente`: `omitida`, sin escribir;
  - `aplicar` lanza `ClientError` (cualquier excepcion): `manejador` la deja subir y `guardar_decision` no se llama;
  - `guardar_decision` lanza `EstadoCambiado` tras aplicar: sube `RuntimeError` cuyo mensaje contiene el
    `policy_arn`;
  - `guardar_decision` lanza `EstadoCambiado` al escribir un bloqueo: `omitida`, sin excepcion;
  - entorno no apto (`ALMACEN = disco`, o `no_disponibles` devuelve `["s3"]`): `RuntimeError` antes de llamar a
    `leer`;
  - `eventName == "REMOVE"`: se omite sin leer;
  - `Estado` admite `bloqueada_al_aplicar` y `_por_que_no("bloqueada_al_aplicar")` no es vacio.
  Comprobar que `test_aprobacion.py` o `test_modelos.py` no fijan la lista de estados cerrada; si lo hacen, anadir
  el estado nuevo ahi.
- [ ] **Step 2: implementar.**
- [ ] **Step 3: verificar**: `./.venv/bin/python -m pytest tests/unitarios/test_aplicador.py
  tests/unitarios/test_modelos.py tests/unitarios/test_aprobacion.py -q`, `./.venv/bin/ruff check agente_iam
  tests/unitarios/test_aplicador.py`, `./.venv/bin/mypy agente_iam`.

---

### Task 3: el paquete de la Lambda del aplicador

**Files:**
- Create: `requirements-aplicador.txt`
- Modify: `scripts/empaquetar.sh`
- Test: `tests/seguridad/test_ci.py`

**Interfaces:**
- Produces: `scripts/empaquetar.sh aplicador` -> `dist/agente-iam-aplicador.zip` y la clave S3
  `agente-iam/aplicador-<12 hex del sha256>.zip`; variables `FUERA_DEL_APLICADOR` y `LLEVA_EL_APLICADOR`.
- Consumes: la cadena de imports de `agente_iam/aplicador.py` (importa `almacen`, `huella`, `aprobar`, `coherencia`,
  `config`, `models`; `aprobar` importa `herramientas.catalogo` y `herramientas.validacion`). Handler
  `agente_iam.aplicador.manejador` (Tarea 2; el script no lo necesita).

**Por que:** el zip del runtime no lleva `aplicador.py` ni `huella.py` (a proposito) y el de la aprobacion tampoco
lleva `aplicador.py`; la Lambda del aplicador necesita los dos mas `aprobar.py` (de donde importa `revalidar`,
`comprobar_techo` e `identificar_aprobador`). El limite de Lambda es 250 MB sin comprimir.

**Diseno:**
- `requirements-aplicador.txt`: las mismas cuatro lineas fijadas que `requirements-aprobacion.txt`
  (`strands-agents==1.54.0`, `boto3==1.43.82`, `pydantic==2.13.4`, `botocore==1.43.82`) con una cabecera que explica:
  es la Lambda `agente-iam-aplicador`; `strands-agents` entra por `catalogo.py` y `validacion.py` (la decoracion
  `@tool`) a traves de `aprobar.py`; sin `bedrock-agentcore`; mismas versiones que `constraints.txt`.
- `empaquetar.sh`: tercer caso `aplicador` en el `case`: `REQUISITOS=requirements-aplicador.txt`,
  `FUERA="$FUERA_DEL_APLICADOR"`, `PAQUETE="$DESTINO/agente-iam-aplicador.zip"`, `LIMITE_PLANO=250`.
  `FUERA_DEL_APLICADOR="aprobar_cliente.py cli.py servidor.py orquestador.py agente.py identidad.py simulacion.py"`;
  `LLEVA_EL_APLICADOR="aplicador.py aprobar.py huella.py"`. Generalizar la comprobacion final "lo que SI tiene que
  estar" con una variable `LLEVA` fijada en el `case` (vacia para `runtime`), de modo que el bucle sirva a las dos
  Lambdas; igual con la impresion de la clave S3: `aprobacion-` o `aplicador-` segun el paquete. Actualizar la cabecera
  del script y el mensaje de uso (`[runtime|aprobacion|aplicador]`).
- `tests/seguridad/test_ci.py`: replicar para el aplicador los tres tests de la aprobacion
  (`test_la_lambda_de_aprobacion_lleva_lo_que_importa_y_nada_mas`,
  `test_cada_modulo_esta_en_un_lado_del_paquete_de_la_aprobacion`,
  `test_el_zip_de_la_aprobacion_comprueba_que_lleva_lo_que_necesita`), parametrizando si queda mas limpio, y
  comprobar que `test_constraints_coincide_con_las_directas` y `test_las_dependencias_que_se_importan_estan_declaradas`
  cubren `requirements-aplicador.txt` (si leen `requirements*.txt` por patron ya lo cubren; si enumeran, anadirlo).
- No se construye el zip de verdad en los tests (necesita red): se comprueba el script como texto, como hoy.

- [ ] **Step 1: tests que fallan.**
- [ ] **Step 2: implementar.**
- [ ] **Step 3: verificar**: `./.venv/bin/python -m pytest tests/seguridad/test_ci.py -q`;
  `bash -n scripts/empaquetar.sh`; `./.venv/bin/ruff check tests/seguridad/test_ci.py`.

---

### Task 4: la pila de acceso (Cognito federado con Identity Center)

**Files:**
- Create: `infra/cfn/acceso.yaml`
- Test: `tests/seguridad/test_pila_acceso.py`

**Interfaces:**
- Produces: pila `agente-iam-acceso` (cuenta `agente-iam`, `us-east-1`) con salidas `UserPoolId`, `DiscoveryUrl`,
  `UrlDominio`, `AcsUrlParaIdentityCenter`, `AudienceParaIdentityCenter` y, en el segundo despliegue, `ClienteId`.
- Consumes: `infra/cfn/prueba-eco.yaml` (la Prueba B) como base; `infra/cfn/identidades.yaml` ya tiene el parametro
  `AplicacionSamlArn` y la asignacion `SolicitantesEnLaAplicacion`.

**Por que:** ADR-001: el emisor del JWT es Cognito con Identity Center como unico proveedor SAML; la Prueba B lo
midio con una pila temporal (MEDICIONES D.2) que se borro. Esta es la version definitiva, con proteccion contra
borrado y nombres del proyecto. La aplicacion SAML solo se crea en consola (la API no las crea), por eso hay dos
despliegues: el primero da ACS URL y audience; el segundo recibe la URL de metadatos.

**Diseno** (copiar de `prueba-eco.yaml` solo las piezas de Cognito; nada de bucket, rol, runtime ni trail):
- Parametros: `PrefijoDominio` (`AllowedPattern: "^agente-iam-[0-9a-f]{6}$"`; el sufijo aleatorio existe porque el
  dominio es publico y unico en la region), `MetadataUrl` (`Default: ""`).
- Condition `Federado` (MetadataUrl no vacio).
- `UserPool`: `UserPoolName: agente-iam-acceso`, `UserPoolTier: LITE`, `AdminCreateUserConfig.AllowAdminCreateUserOnly:
  true`, `DeletionProtection: ACTIVE`, `UserPoolTags: {proyecto: agente-iam}`, `DeletionPolicy: Retain`,
  `UpdateReplacePolicy: Retain`.
- `Dominio`: `ManagedLoginVersion: 1`.
- `ProveedorIdentityCenter` (Condition Federado): `ProviderName: IdentityCenter`, `ProviderType: SAML`,
  `ProviderDetails.MetadataURL`, `AttributeMapping: {email: email}`.
- `ClienteCli` (Condition Federado, `DependsOn: ProveedorIdentityCenter`): `ClientName: agente-iam-cli`,
  `GenerateSecret: false`, `AllowedOAuthFlowsUserPoolClient: true`, `AllowedOAuthFlows: [code]`,
  `AllowedOAuthScopes: [openid, email]`, `SupportedIdentityProviders: [IdentityCenter]`,
  `CallbackURLs: [http://localhost:8080/callback]`, `ExplicitAuthFlows: [ALLOW_REFRESH_TOKEN_AUTH]`,
  `PreventUserExistenceErrors: ENABLED`, `EnableTokenRevocation: true`, `AccessTokenValidity: 60`,
  `IdTokenValidity: 60`, `TokenValidityUnits: {AccessToken: minutes, IdToken: minutes}` (ESPECIFICACION 1.6: una hora).
- Outputs: los seis de arriba; `DiscoveryUrl` =
  `Fn::Sub: "https://cognito-idp.${AWS::Region}.amazonaws.com/${UserPool}/.well-known/openid-configuration"`.
- Cabecera de comentarios con el porque, los dos despliegues y los pasos de consola de Mateo (aplicacion SAML en la
  cuenta de gestion: ACS URL y audience de las salidas, `Subject` = `${user:subject}` persistente, `email` =
  `${user:email}`, sesion 4 h, asignar el grupo `agente-iam-solicitantes`; despues la pila de identidades recibe
  `AplicacionSamlArn`).

- [ ] **Step 1: tests que fallan** (`tests/seguridad/test_pila_acceso.py`, mismo estilo que `test_prueba_eco.py`):
  el pool no admite registro propio y tiene `DeletionProtection: ACTIVE` y `Retain`; el cliente es publico con PKCE
  (`code`), sin secreto, sin flujos de contrasena (`ALLOW_USER_PASSWORD_AUTH`, `ALLOW_ADMIN_USER_PASSWORD_AUTH`,
  `ALLOW_USER_SRP_AUTH` ausentes) y solo `IdentityCenter`; la unica URL de retorno es `localhost`; el dominio no
  lleva la cuenta; tokens de 60 minutos; lo federado solo existe con `MetadataUrl`; no hay `AWS::Cognito::UserPoolUser`
  ni ningun recurso que no sea de Cognito; la salida `DiscoveryUrl` acaba en `/.well-known/openid-configuration`.
- [ ] **Step 2: implementar.**
- [ ] **Step 3: verificar**: `./.venv/bin/python -m pytest tests/seguridad/test_pila_acceso.py
  tests/seguridad/test_plantillas_cfn.py -q` y `./.venv/bin/cfn-lint infra/cfn/acceso.yaml`.

---

### Task 5: la pila del runtime (runtime JWT, Lambda del aplicador, cola, alarma, trail)

**Files:**
- Create: `infra/cfn/runtime.yaml`
- Test: `tests/seguridad/test_pila_runtime.py`

**Interfaces:**
- Produces: pila `agente-iam-runtime` (cuenta `agente-iam`, `us-east-1`), salidas `RuntimeArn`, `RuntimeId`,
  `FuncionAplicadorArn`, `ColaFallosArn`, `TrailArn`, `TemaAlarmasArn`.
- Consumes: roles `AgenteIAM-Runtime` y `AgenteIAM-Aplicador` de `base.yaml` (por nombre, con `Fn::Sub`), bucket
  `agente-iam-despliegue-${AWS::AccountId}`, salidas de la pila de acceso (como parametros), `StreamArn` de la pila
  base (parametro), handler `agente_iam.aplicador.manejador` (Tarea 2), zips de `empaquetar.sh` (Tarea 3). El rol
  `AgenteIAM-Despliegue` (`arranque.yaml`) ya tiene las acciones de todos estos tipos de recurso.

**Por que:** ESPECIFICACION 2.x (runtime solo JWT, `requestHeaderAllowlist`, grupo de logs declarado), §5 (trail
propio de eventos de datos: el de Control Tower no los registra y el `sub` solo esta ahi) y §7 (Lambda disparada por
Streams con filtro, relee la fila, 2 reintentos y cola de fallos con alarma). Decisiones D2, D3, D4, D8.

**Diseno:**
- Parametros (todos sin `Default` salvo `ModelId`):
  - `ClaveCodigoRuntime` (`^agente-iam/runtime-[0-9a-f]{12}\.zip$`), `ClaveCodigoAplicador`
    (`^agente-iam/aplicador-[0-9a-f]{12}\.zip$`);
  - `DiscoveryUrl` (`^https://cognito-idp\.us-east-1\.amazonaws\.com/us-east-1_[A-Za-z0-9]+/\.well-known/openid-configuration$`),
    `ClienteId` (`^[a-z0-9]{26}$`);
  - `StreamArn` (`^arn:aws:dynamodb:us-east-1:[0-9]{12}:table/agente-iam-solicitudes/stream/.+$`);
  - `CorreoAlarmas` (patron de correo como en `identidades.yaml`; dato personal, nunca en el repositorio);
  - `ModelId` (`Default: us.anthropic.claude-haiku-4-5-20251001-v1:0`, `AllowedPattern: ^us\.anthropic\.claude-.+$`:
    la SCP solo deja perfiles `us.`).
- `Runtime` (`AWS::BedrockAgentCore::Runtime`): `AgentRuntimeName: agente_iam_analista`, `RoleArn:
  arn:aws:iam::${AWS::AccountId}:role/AgenteIAM-Runtime`, `NetworkConfiguration.NetworkMode: PUBLIC`,
  `ProtocolConfiguration: HTTP`, `AgentRuntimeArtifact.CodeConfiguration` con `Code.S3.Bucket` el de despliegue y
  `Prefix` = `ClaveCodigoRuntime`, `Runtime: PYTHON_3_12`, `EntryPoint: [main.py]`;
  `EnvironmentVariables: {ALMACEN: dynamodb, TABLA_SOLICITUDES: agente-iam-solicitudes, MODEL_ID: <ModelId>}` (sin
  `AWS_REGION` ni `DIR_CACHE_CATALOGO`: `main.py` fija el catalogo desde su propia ruta);
  `AuthorizerConfiguration.CustomJWTAuthorizer: {DiscoveryUrl, AllowedClients: [ClienteId]}` (sin `AllowedAudience`:
  el token de acceso de Cognito no trae `aud`, MEDICIONES D.2); `RequestHeaderConfiguration.RequestHeaderAllowlist:
  [Authorization]`; `Tags: {proyecto: agente-iam}`.
- `RegistroRuntime` (`AWS::Logs::LogGroup`, `DependsOn: Runtime`): `LogGroupName: Fn::Sub:
  "/aws/bedrock-agentcore/runtimes/${Runtime.AgentRuntimeId}-DEFAULT"`, `RetentionInDays: 365`, `Retain` (D8; el
  comentario dice que si AgentCore lo crea antes, el despliegue falla con "already exists" y se importa).
- `ColaFallos` (`AWS::SQS::Queue`): `QueueName: agente-iam-aplicador-fallos`, `MessageRetentionPeriod: 1209600`,
  `SqsManagedSseEnabled: true`.
- `RegistroAplicador` (`AWS::Logs::LogGroup`): `/aws/lambda/agente-iam-aplicador`, 365 dias, `Retain`.
- `FuncionAplicador` (`AWS::Lambda::Function`): `FunctionName: agente-iam-aplicador`, `Runtime: python3.12`,
  `Architectures: [arm64]`, `Handler: agente_iam.aplicador.manejador`, `Role:
  arn:aws:iam::${AWS::AccountId}:role/AgenteIAM-Aplicador`, `Code.S3Bucket` de despliegue y `S3Key` =
  `ClaveCodigoAplicador`, `Timeout: 120`, `MemorySize: 512`, `ReservedConcurrentExecutions: 1` (una aplicacion a la
  vez: la idempotencia converge, pero no hace falta ponerla a prueba), `Environment.Variables: {ALMACEN: dynamodb,
  TABLA_SOLICITUDES: agente-iam-solicitudes, DIR_CACHE_CATALOGO: /var/task/catalogo}`, `LoggingConfig.LogGroup:
  Ref RegistroAplicador`. NUNCA `AGENTE_IAM_PERMITIR_AUTOAPROBACION` (D2).
- `DisparadorAplicador` (`AWS::Lambda::EventSourceMapping`): `EventSourceArn: Ref StreamArn`, `FunctionName: Ref
  FuncionAplicador`, `StartingPosition: LATEST`, `BatchSize: 1`, `MaximumRetryAttempts: 2`,
  `BisectBatchOnFunctionError: false`, `MaximumRecordAgeInSeconds: 3600`, `Enabled: true`,
  `DestinationConfig.OnFailure.Destination: Fn::GetAtt [ColaFallos, Arn]`,
  `FilterCriteria.Filters: [{Pattern: '{"eventName":["INSERT","MODIFY"],"dynamodb":{"NewImage":{"estado":{"S":["aprobada"]}}}}'}]`.
- `TemaAlarmas` (`AWS::SNS::Topic`, `TopicName: agente-iam-alarmas`) y `SuscripcionCorreo` (`AWS::SNS::Subscription`,
  `Protocol: email`, `Endpoint: Ref CorreoAlarmas`).
- `AlarmaFallos` (`AWS::CloudWatch::Alarm`): `AlarmName: agente-iam-aplicador-fallos`, `Namespace: AWS/SQS`,
  `MetricName: ApproximateNumberOfMessagesVisible`, `Dimensions: [{Name: QueueName, Value: GetAtt ColaFallos
  QueueName}]`, `Statistic: Maximum`, `Period: 60`, `EvaluationPeriods: 1`, `Threshold: 0`,
  `ComparisonOperator: GreaterThanThreshold`, `TreatMissingData: notBreaching`, `AlarmActions: [Ref TemaAlarmas]`.
- Trail (D3): `BucketTrail` (`BucketName: agente-iam-trail-datos-${AWS::AccountId}`, cifrado AES256, bloqueo publico,
  `BucketOwnerEnforced`, `LifecycleConfiguration` con una regla `Status: Enabled`, `ExpirationInDays: 90`,
  `DeletionPolicy: Retain`, `UpdateReplacePolicy: Retain`), `PoliticaBucketTrail` (como en `prueba-eco.yaml`:
  `GetBucketAcl` y `PutObject` solo desde `aws:SourceArn` = `arn:aws:cloudtrail:us-east-1:${AWS::AccountId}:trail/agente-iam-datos`,
  mas Deny sin TLS), `TrailDatos` (`TrailName: agente-iam-datos`, `DependsOn: PoliticaBucketTrail`, `IsLogging: true`,
  `IsMultiRegionTrail: false`, `IncludeGlobalServiceEvents: false`, `EnableLogFileValidation: true`,
  `AdvancedEventSelectors` con DOS selectores: uno `eventCategory = Data` y `resources.type =
  AWS::BedrockAgentCore::Runtime`; otro `eventCategory = Data`, `resources.type = AWS::Lambda::Function` y
  `resources.ARN Equals arn:aws:lambda:us-east-1:${AWS::AccountId}:function:agente-iam-aprobacion`).
- Cabecera de comentarios: por que existe cada pieza, el orden de despliegue (acceso 2 antes; `StreamArn` de la salida
  de la base; los dos zips subidos por el operador) y lo que no se despliega aqui (roles: viven en la base).

- [ ] **Step 1: tests que fallan** (`tests/seguridad/test_pila_runtime.py`): el runtime solo acepta JWT del cliente
  del parametro y no tiene `AllowedAudience`; solo deja pasar `Authorization`; su rol es `AgenteIAM-Runtime` y el de la
  Lambda `AgenteIAM-Aplicador` (ninguna `AWS::IAM::Role` en esta pila); `EntryPoint == ["main.py"]` y `ALMACEN ==
  dynamodb` en los dos; el modelo por defecto es un perfil `us.`; el filtro del disparador es exactamente el patron
  de arriba (cargar el JSON y comparar), lote 1, 2 reintentos, destino de fallos la cola; la funcion del aplicador no
  lleva `AGENTE_IAM_PERMITIR_AUTOAPROBACION`, su handler es `agente_iam.aplicador.manejador` y concurrencia reservada
  1; la alarma mira la cola y publica en el tema; el trail solo registra eventos de datos y exactamente de esos dos
  recursos; el bucket del trail es privado, cifrado, solo TLS, con caducidad de 90 dias y `Retain`; los dos grupos de
  logs tienen retencion y `Retain`; no hay `AWS::Lambda::Permission` ni `Principal: "*"` en Allow; sin `Default` en
  `CorreoAlarmas` ni en las claves; los recursos del sistema llevan prefijo `agente-iam-`.
- [ ] **Step 2: implementar.**
- [ ] **Step 3: verificar**: `./.venv/bin/python -m pytest tests/seguridad/test_pila_runtime.py
  tests/seguridad/test_plantillas_cfn.py -q` y `./.venv/bin/cfn-lint infra/cfn/runtime.yaml`.

---

### Task 6: el cliente del solicitante, `scripts/solicitar.py`

**Files:**
- Create: `scripts/solicitar.py`
- Test: `tests/unitarios/test_solicitar.py`

**Interfaces:**
- Consumes: `scripts/prueba_b.py` (`pkce`, `challenge_de`, `url_autorizacion`, `claims`, `visibles`, `guardar_token`,
  `sub_repetido`, `_esperar_codigo`): importarlo por ruta con `importlib` como hace `tests/unitarios/test_prueba_b.py`
  o con `sys.path` de la carpeta `scripts/`; salidas de las pilas `agente-iam-acceso` (`UrlDominio`, `ClienteId`) y
  `agente-iam-runtime` (`RuntimeArn`) leidas con `boto3` `cloudformation.describe_stacks` (perfil `--perfil`,
  por defecto `org-agente-iam`).
- Produces: `scripts/solicitar.py token --usuario <nombre>` (PKCE, codigo en `localhost:8080`, token guardado en
  `local/tokens/<nombre>.json` con permisos 600, sin imprimirlo; se niega a guardar un token cuyo `sub` ya es de otro
  usuario guardado); `scripts/solicitar.py enviar <fichero.json> --usuario <nombre>` (POST al runtime).

**Por que:** con JWT no se invoca con la CLI ni el SDK de AWS (firman con SigV4): hace falta una peticion HTTPS con
`Authorization: Bearer`. `scripts/prueba_b.py` ya hace el PKCE y la invocacion contra el eco; este script es la
version para el runtime real y la pila definitiva (D7: script, no modulo de `agente_iam/`).

**Diseno:**
- `enviar`: URL `https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/{urllib.parse.quote(arn, safe="")}/invocations?qualifier=DEFAULT`;
  cabeceras `Authorization: Bearer <token>`, `Content-Type: application/json`,
  `X-Amzn-Bedrock-AgentCore-Runtime-Session-Id: solicitud-<uuid4>-<uuid4>` (minimo 33 caracteres; una funcion
  `id_de_sesion()` lo garantiza); cuerpo = el JSON del fichero tal cual (se valida que sea un objeto JSON antes de
  enviarlo, nada mas: la forma la valida el servidor); `timeout=180` (una corrida con tres intentos pasa del minuto).
  Imprime el codigo HTTP y, de la respuesta, `resultado`, `registro.estado`, `guardado_en` y `registro.solicitante`;
  con `resultado == "error"` imprime `codigo` y `detalle`. Todo lo que se imprime pasa por `models.imprimible` (S7).
  Codigos de salida: 0 con HTTP 200 y `resultado == "procesada"`, 2 con `forma_invalida` o `registro_existente`, 1 en
  lo demas (401, 403, 424, error de red).
- `token`: como `prueba_b.cmd_token` pero con las salidas de la pila de acceso y `--usuario` libre (el nombre de la
  persona que entra; se usa para el fichero y la comprobacion de `sub` cruzado). Recordar en la ayuda: otra persona
  = ventana privada nueva.
- Sin `argparse` nada se ejecuta al importar: `main(argv)` y `if __name__ == "__main__"`.

- [ ] **Step 1: tests que fallan** (`tests/unitarios/test_solicitar.py`, importando el script por ruta como
  `test_prueba_b.py`): `id_de_sesion()` tiene al menos 33 caracteres y es distinto cada vez; `enviar` construye la URL
  con el ARN codificado (`%3A`, `%2F`) y `qualifier=DEFAULT`, manda `Authorization: Bearer <token>` y el id de sesion
  (monkeypatch de `urllib.request.urlopen` del modulo con un doble que captura la `Request`); el token no aparece en lo
  impreso (capsys) ni con 200 ni con 401; `forma_invalida` sale con 2 y `procesada` con 0; un fichero que no es un
  objeto JSON sale con 2 sin llamar a la red; `--usuario` con un `sub` que ya pertenece a otro fichero de tokens no se
  guarda (reutilizar `sub_repetido`).
- [ ] **Step 2: implementar.**
- [ ] **Step 3: verificar**: `./.venv/bin/python -m pytest tests/unitarios/test_solicitar.py
  tests/unitarios/test_prueba_b.py -q`, `./.venv/bin/ruff check scripts/solicitar.py tests/unitarios/test_solicitar.py`.

---

### Task 7: la pila de beneficiarios de demo y la cola en el rol del aplicador

**Files:**
- Create: `infra/cfn/beneficiarios.yaml`
- Modify: `infra/cfn/base.yaml` (una sentencia nueva en `RolAplicador`)
- Test: `tests/seguridad/test_pila_base.py` (ajustar `test_el_aplicador_es_el_de_su_json_mas_la_tabla` y anadir el
  test de la cola), `tests/seguridad/test_pila_beneficiarios.py` (nuevo)

**Interfaces:**
- Produces: pila `agente-iam-beneficiarios` (la despliega el ADMINISTRADOR: el rol de despliegue solo crea roles con
  `AgenteIAM-LimiteSistema`, y un beneficiario lleva el techo); rol `app-finanzas-demo`; bucket
  `finanzas-demo-${AWS::AccountId}`. `RolAplicador` de `base.yaml` gana `sqs:SendMessage` sobre
  `arn:aws:sqs:us-east-1:${AWS::AccountId}:agente-iam-aplicador-fallos`.
- Consumes: `AgenteIAM-Techo` (pila de arranque), `config.PREFIJOS_DEL_SISTEMA`, `agente_iam.coherencia.del_sistema`
  (si existe con esa firma; si no, comparar prefijos a mano en el test).

**Por que:** D1. Hoy ningun principal de `agente-iam` lleva el techo, asi que el aplicador no puede adjuntar nada
(su `Attach*` exige `iam:PermissionsBoundary = AgenteIAM-Techo`) y la prueba de punta a punta no es posible. Un rol
de aplicacion con el techo es el beneficiario que el diseno de la Fase 10 eligio (roles IAM de aplicaciones). El
cambio en `base.yaml` existe porque el destino de fallos del disparador lo escribe la funcion con su propio rol
(`sqs:SendMessage`), y `AgenteIAM-LimiteSistema` ya lo permite (`ColaDeFallos`).

**Diseno:**
- `beneficiarios.yaml`: `RolDemo` (`AWS::IAM::Role`, `RoleName: app-finanzas-demo`, `Description` que dice que es el
  rol de una aplicacion de demo que recibe permisos del agente, `PermissionsBoundary:
  arn:aws:iam::${AWS::AccountId}:policy/AgenteIAM-Techo`, confianza `lambda.amazonaws.com` con
  `aws:SourceAccount = ${AWS::AccountId}`, SIN `Policies` ni `ManagedPolicyArns`: lo que tenga se lo dara el
  aplicador, `Tags: proyecto=agente-iam`); `BucketDemo` (`AWS::S3::Bucket`, `BucketName: finanzas-demo-${AWS::AccountId}`,
  cifrado, bloqueo publico, `BucketOwnerEnforced`) y `PoliticaBucketDemo` (Deny sin TLS). Sin `Retain`: es demo. Los
  nombres NO empiezan por ningun prefijo de `PREFIJOS_DEL_SISTEMA` (el chequeo 6 y el techo D2 lo rechazarian).
  Outputs: `RolDemoArn`, `BucketDemo`. Cabecera: por que la despliega el administrador y no el operador.
- `base.yaml`: en `RolAplicador.Policies[0].PolicyDocument.Statement`, despues de `ListarStreamsNoTieneRecurso`:
  `Sid: EscribirEnSuColaDeFallos`, `Effect: Allow`, `Action: sqs:SendMessage`, `Resource: Fn::Sub:
  arn:aws:sqs:us-east-1:${AWS::AccountId}:agente-iam-aplicador-fallos`, con un comentario (el disparador manda a la cola
  los eventos que fallan tras 2 reintentos; lo hace con el rol de la funcion).
- `test_pila_base.py`: `test_el_aplicador_es_el_de_su_json_mas_la_tabla` debe seguir en verde: anadir la sentencia
  nueva a la lista de extras que ya tolera para las del stream y los logs (leer como lo hace hoy), y un test
  `test_el_aplicador_solo_escribe_en_su_cola_de_fallos` (una sola sentencia con `sqs:`, accion exacta
  `sqs:SendMessage`, recurso exacto). Comprobar que `test_todo_lo_que_concede_*_cabe_en_el_limite_del_sistema` (si
  existe para el aplicador) sigue en verde.
- `test_pila_beneficiarios.py`: el rol lleva el techo como boundary; no tiene politicas; ningun nombre de recurso
  (rol, bucket) empieza por un prefijo del sistema; el bucket es privado, cifrado y solo TLS; la confianza lleva
  `aws:SourceAccount`.

- [ ] **Step 1: tests que fallan.**
- [ ] **Step 2: implementar.**
- [ ] **Step 3: verificar**: `./.venv/bin/python -m pytest tests/seguridad/test_pila_base.py
  tests/seguridad/test_pila_beneficiarios.py tests/seguridad/test_plantillas_cfn.py -q`;
  `./.venv/bin/cfn-lint infra/cfn/beneficiarios.yaml infra/cfn/base.yaml`.

---

### Task 8: despliegue y mediciones (Claude, cada escritura con el si de Mateo)

No es tarea de subagente. Orden: `localizar.py`; acceso 1 (operador); aplicacion SAML en consola (Mateo) y
`identidades` con `AplicacionSamlArn` (administrador); acceso 2; `beneficiarios` (administrador); base (la cola);
`empaquetar.sh runtime` y `empaquetar.sh aplicador`, subir los zips (operador); runtime. Mediciones: Prueba B contra el
runtime real (200 con token, 401 sin token, 401 firma alterada); una solicitud real de Mateo (`solicitante.persona`
grabada); aprobacion de `aprobador.demo` (separacion con dos personas, 200); la Lambda aplica sola (`aplicada`) o
bloquea (`bloqueada_al_aplicar`); el evento de datos en el trail con el `sub`; D8 (el grupo de logs). Todo a
`docs/MEDICIONES.md` (seccion nueva) en la Tarea 9.

### Task 9: documentacion (subagente Sonnet con encargo cerrado de Claude)

PLAN (Fase 20), CONTEXTO (§2 estados y tests, §3, §5, §6 con los ficheros nuevos, §7 comandos y variables, §10, §11),
README, `docs/DESPLIEGUE.md`, `docs/ESPECIFICACION-agentcore.md` (requisitos que pasan de diseno a medido),
`docs/MEDICIONES.md`, docstrings. El encargo lo redacta Claude con los hechos medidos y sus horas UTC.
