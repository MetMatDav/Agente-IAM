# Techo, decisiones de aprobacion y pila base - plan de implementacion

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** medir `aws:ResourceAccount` con llamadas reales, desplegar el techo del repositorio y la politica del
aplicador, dejar escritas las dos decisiones de la aprobacion (ADR-003) y desplegar la pila `base` con la primera
medicion real de `dynamodb:Attributes`.

**Architecture:** todo lo que toca la cuenta va por CloudFormation (pilas `agente-iam-sonda-cuenta`, temporal;
`agente-iam-arranque`, ya existe; `agente-iam-base`, nueva) o por scripts con `--ejecutar` que sin esa bandera solo
imprimen el plan. Cada medicion clasifica con una funcion pura que se prueba sin red. La fila de DynamoDB sigue el
reparto de `local/mapas/solicitud-por-la-tabla.md`: un atributo por actor, solo `UpdateItem`.

**Tech Stack:** Python 3 del `.venv`, boto3/botocore (`Stubber` en tests), pytest, CloudFormation YAML leido con
`yaml.safe_load`, Access Analyzer y el simulador de IAM.

**Spec:** `CONTEXTO.md` §5, §10 y §11 (pasos 2 a 6); `docs/MEDICIONES.md` E.5, F.4 y J;
`docs/ESPECIFICACION-agentcore.md` §4; `local/mapas/solicitud-por-la-tabla.md`.

## Global Constraints

- Nada se escribe en la cuenta sin el si de Mateo para esa accion concreta; los pasos de consola son suyos.
- No hay commits sin que Mateo los pida: cada "Commit" de abajo es "ensenar el diff y proponer el commit".
- En lo versionado va `111122223333`; lo que necesite la cuenta real sale de `scripts/localizar.py` a `local/`.
- Sin guion largo en nombres ni descripciones de recursos.
- Region `us-east-1`. La CLI de AWS no corre dentro de la app: Claude usa boto3 del `.venv` o el MCP de AWS; `aws sso login` lo corre Mateo.
- Todo avance cierra con su documentacion (tabla de `CLAUDE.md`), escrita por un subagente Sonnet con encargo cerrado y revisada por Claude; fechas absolutas; lo medido separado de lo supuesto.
- Comprobacion de cierre de cada tarea: `./.venv/bin/python -m pytest tests/ -q` en verde y `./.venv/bin/ruff check .`.

## Review Focus

1. Una llamada de la sonda que falla por otra causa (bucket inexistente, politica de recurso ajena) no debe leerse como "la clave nego": sin la sesion de control en verde, el resultado es `no_concluyente` (test en Tarea 2).
2. Si `${aws:PrincipalAccount}` no se resolviera en la politica de sesion, todas las llamadas saldrian "ajena": la sonda aborta si `DescribeTable` sobre su propia tabla no sale `propia` (test en Tarea 2).
3. El conjunto de cambios de `agente-iam-arranque` solo puede modificar `Techo` y `LimiteSistema`, sin reemplazo; cualquier otro cambio para el despliegue (paso de revision en Tarea 3).
4. Una fila creada por un `UpdateItem` sobre un `id` inexistente (sin `documento` o sin `estado`) hoy da `KeyError` en `almacen._dynamo_leer`; debe dar `RegistroInconsistente` y salida 3 (test en Tarea 5).
5. La sonda deja un rol asumible en la cuenta si no se borra: la tarea no cierra hasta que `GetRole` da `NoSuchEntity` (paso en Tarea 2).

---

### Tarea 1: Comprobar lo que Mateo ya hizo y dejarlo escrito

Mateo dijo el 24-10-2026: borro la inline `AgenteIAM-AplicadorPolicy`, quito el perfil `root-mfa-delete-demo` de
`~/.aws/credentials` y confirmo el MFA de `solicitante.demo`.

**Files:**
- Modify: `CONTEXTO.md` §5 (filas "Roles del circuito", "Identity Center") y §11 (pasos 4, 7 y 8)
- Modify: `docs/MEDICIONES.md` G.7 (lectura nueva)

- [ ] **Paso 1: Leer, sin escribir.** Con `org-gestion` (boto3): `iam.list_role_policies(RoleName="AgenteIAM-Aplicador")`. Esperado: `["AgenteIAM-Aplicador-permisos"]`.
- [ ] **Paso 2: Nombres de seccion, nunca valores.** `grep -n '^\[' ~/.aws/credentials ~/.aws/config`. Leido el 24-10-2026 al preparar este plan: `credentials` sin secciones; `config` aun tiene `[profile root-mfa-delete-demo]` (linea 7). Decir a Mateo que esa seccion de `config` sobra (no tiene secreto; la quita el).
- [ ] **Paso 3: El MFA de `solicitante.demo`** no tiene API de lectura conocida; se documenta como "dicho por Mateo el 24-10-2026", no como medido.
- [ ] **Paso 4: Documentar** (subagente): las tres filas de §5, los pasos 4, 7 y 8 de §11 como hechos, y la lectura en G.7 con fecha y perfil.
- [ ] **Paso 5:** pytest en verde. Proponer commit.

---

### Tarea 2: Sonda de `aws:ResourceAccount` (CONTEXTO §11 paso 2)

La pregunta: en cada llamada tipica de los ocho servicios, la clave llega con la cuenta propia, con otra, o no llega.
El Deny `SoloRecursosDeLaPropiaCuenta` (S5) usa `StringNotEqualsIfExists`: niega solo si llega con otra cuenta.

**Diseno.** Un rol `agente-iam-sonda-cuenta` con una inline de solo lectura (las acciones de `LLAMADAS`) y confianza
solo al permission set de administracion en `agente-iam` (mismo `ArnLike` que `infra/rol-agente-confianza.json`).
El script lo asume cuatro veces, cada una con una politica de sesion distinta (`Allow */*` mas, en tres de ellas, un
Deny de prueba), y repite cada llamada en las cuatro:

| Sesion | Deny de prueba | Si la llamada se niega, significa |
|---|---|---|
| `control` | ninguno | la llamada no sirve como prueba (`no_concluyente`) |
| `techo` | la sentencia S5 tal cual (`StringNotEqualsIfExists aws:ResourceAccount ${aws:PrincipalAccount}`), copiada del JSON del techo | el techo nuevo la negaria |
| `ausente` | `Null aws:ResourceAccount true` | la clave no llega |
| `propia` | `StringEquals aws:ResourceAccount ${aws:PrincipalAccount}` | la clave llega con la cuenta propia |

El estado de la clave sale de `ausente` y `propia` (ninguna de las dos niega: llega con otra cuenta). La columna `techo`
es lo que se quiere saber. Segun la guia de operadores de condicion de IAM (leida el 24-10-2026), un Deny con
`StringNotEqualsIfExists` **niega tambien cuando la clave falta**; CONTEXTO §5 y `docs/MEDICIONES.md` E.5 dicen lo
contrario ("una llamada sin la clave pasa", sacado del simulador). La sonda lo decide con llamadas reales.

La pila crea recursos propios vacios para tener contra que llamar: bucket `agente-iam-sonda-${AWS::AccountId}`, tabla
`agente-iam-sonda`, cola, tema y grupo de logs del mismo nombre. Todo coste cero en reposo; se borra al acabar.

**Files:**
- Create: `infra/cfn/sonda-cuenta.yaml` (temporal, como `prueba-eco.yaml`)
- Create: `scripts/sonda_cuenta.py`
- Create: `tests/unitarios/test_sonda_cuenta.py`
- Modify: `tests/seguridad/test_plantillas_cfn.py` (invariantes de la sonda)
- Modify: `docs/MEDICIONES.md` E.5 (resultado), §J; `CONTEXTO.md` §5, §6 (script y test nuevos), §11; `README.md` (script)

**Interfaces:**
- Produces: `clasificar(resultados: dict[str, str]) -> dict`, donde `resultados` mapea `control|techo|ausente|propia` a `"ok"`, `"denegado"` o `"error:<Codigo>"`, y devuelve `{"clave": "propia"|"ajena"|"ausente"|"no_concluyente"|"inconsistente", "techo": "pasa"|"niega"|None}`.
- Produces: `politica_de_sesion(nombre: str) -> dict` y `LLAMADAS: list[Llamada]` con `Llamada(servicio, operacion, params, recurso_de="propio"|"aws"|"ninguno")`.

- [ ] **Paso 1: Tests que fallan** en `tests/unitarios/test_sonda_cuenta.py`:

```python
def test_sin_control_en_verde_no_concluye():
    r = clasificar({"control": "error:NoSuchBucket", "techo": "denegado", "ausente": "ok", "propia": "ok"})
    assert r == {"clave": "no_concluyente", "techo": None}

def test_la_clave_sale_de_ausente_y_propia():
    assert clasificar({"control": "ok", "techo": "ok", "ausente": "ok", "propia": "denegado"})["clave"] == "propia"
    assert clasificar({"control": "ok", "techo": "denegado", "ausente": "ok", "propia": "ok"})["clave"] == "ajena"
    assert clasificar({"control": "ok", "techo": "denegado", "ausente": "denegado", "propia": "ok"}) == {"clave": "ausente", "techo": "niega"}
    assert clasificar({"control": "ok", "techo": "ok", "ausente": "denegado", "propia": "ok"}) == {"clave": "ausente", "techo": "pasa"}

def test_lo_imposible_es_inconsistente():
    assert clasificar({"control": "ok", "techo": "ok", "ausente": "denegado", "propia": "denegado"})["clave"] == "inconsistente"
    assert clasificar({"control": "ok", "techo": "denegado", "ausente": "ok", "propia": "denegado"})["clave"] == "inconsistente"  # propia y el techo niega
    assert clasificar({"control": "ok", "techo": "ok", "ausente": "ok", "propia": "ok"})["clave"] == "inconsistente"  # ajena y el techo pasa

def test_la_sesion_techo_es_la_s5_del_techo():
    # el Deny de prueba es identico a la sentencia SoloRecursosDeLaPropiaCuenta de infra/boundary-agente-iam-techo.json
    ...

def test_las_politicas_de_sesion_caben():  # limite de 2048 caracteres empaquetados
    for n in ("control", "techo", "ausente", "propia"):
        assert len(json.dumps(politica_de_sesion(n), separators=(",", ":"))) <= 2048

def test_la_sonda_aborta_si_su_tabla_no_sale_propia():
    # resultados simulados con DescribeTable propia != "propia" -> salida 1 con motivo "sonda rota"
    ...

def test_sin_ejecutar_no_crea_sesion(monkeypatch):  # mismo patron que test_matriz_regiones.py
    ...
```

- [ ] **Paso 2:** `./.venv/bin/python -m pytest tests/unitarios/test_sonda_cuenta.py -q`. Esperado: FAIL (modulo no existe).
- [ ] **Paso 3: `scripts/sonda_cuenta.py`.** Estructura de `scripts/matriz_regiones.py`: sin `--ejecutar` imprime el plan; boto3 se importa dentro. `LLAMADAS`, como minimo: S3 `ListBuckets`, `ListObjectsV2` (propio), `ListObjectsV2` sobre `noaa-ghcn-pds` (publico de otra cuenta); EC2 `DescribeInstances`, `DescribeRegions`, `DescribeImages(Owners=["amazon"], MaxResults=5)`; Lambda `ListFunctions`, `GetLayerVersionByArn` sobre la capa de AWS Parameters and Secrets de us-east-1 (ARN leido de la guia de Lambda el dia de la corrida, pasado con `--capa`); SNS `ListTopics`, `GetTopicAttributes` (propio); DynamoDB `ListTables`, `DescribeTable` (propio); SQS `ListQueues`, `GetQueueAttributes` (propio); Logs `DescribeLogGroups`, `FilterLogEvents` (propio); CloudWatch `ListMetrics`. Salida: `evidencias/sonda-cuenta/<fecha UTC>/resultado.json` (como `matriz_regiones.py`) y tabla enmascarada (cuentas como `<propia>`/`<aws>`) por pantalla. Esperar 10 s tras `AssumeRole` antes de la primera llamada.
- [ ] **Paso 4: `infra/cfn/sonda-cuenta.yaml`** y sus invariantes en `test_plantillas_cfn.py`: `test_la_sonda_solo_lee` (ninguna accion de la inline fuera de List/Read/Describe/Get segun el catalogo), `test_la_sonda_solo_la_asume_el_administrador`, y que no lleve cuenta (lo cubre `test_sin_cuenta_ids_de_organizacion_ni_correos`).
- [ ] **Paso 5:** pytest completo en verde. Validar la plantilla con `validate_cloudformation_template` (MCP awsiac). Proponer commit.
- [ ] **Paso 6 (Mateo, si):** el administrador (`org-agente-iam`) crea la pila `agente-iam-sonda-cuenta` desde `local/infra/cfn/sonda-cuenta.yaml`.
- [ ] **Paso 7:** `AWS_PROFILE=org-agente-iam ./.venv/bin/python scripts/sonda_cuenta.py --ejecutar --capa <arn>`. Esperado: `DescribeTable` propia = `propia`; ningun `inconsistente`.
- [ ] **Paso 8 (Mateo, si):** borrar la pila; comprobar `iam.get_role("agente-iam-sonda-cuenta")` -> `NoSuchEntity` y que el bucket no existe.
- [ ] **Paso 9: Decision de Mateo** si alguna llamada legitima sale `techo: niega` (una sin la clave, si la guia tiene razon, o una a un recurso de AWS como una AMI o una capa): aceptarlo (el beneficiario no podra usar ese recurso; se documenta en CONTEXTO §10) o anadir una excepcion al techo (Claude propone la sentencia, con su test, en `scripts/generar_techo.py`). Sin decision, no se pasa a la Tarea 3.
- [ ] **Paso 10:** Documentar (subagente) E.5 con fecha, perfil y tabla enmascarada; quitar la fila de §J; §6 con script y test. pytest. Proponer commit.

---

### Tarea 3: Desplegar el techo, `LimiteSistema` sin `PutItem` y la politica del aplicador (paso 3)

Un solo conjunto de cambios en `agente-iam-arranque` lleva el techo nuevo y el arreglo de `LimiteSistema` (el
boundary de los roles del sistema no debe permitir `dynamodb:PutItem`, mapa §5), para que el administrador entre una
sola vez.

**Files:**
- Modify: `infra/cfn/arranque.yaml` (sentencia `RegistroDeSolicitudes` de `LimiteSistema`: sin `dynamodb:PutItem`)
- Modify: `tests/seguridad/test_plantillas_cfn.py`
- Modify: `CONTEXTO.md` §3 (parrafo del techo), §5 (tablas de techo, aplicador y "Cuenta frente a repositorio"), §9 #40, §11; `docs/MEDICIONES.md` E.7 nueva (despliegue), E.5; `docs/DESPLIEGUE.md` (tabla de pilas)

- [ ] **Paso 1: Test que falla:**

```python
def test_el_limite_del_sistema_no_permite_reemplazar_filas():
    acciones = [a for s in _sentencias_de("LimiteSistema") if s["Effect"] == "Allow" for a in _acciones(s)]
    assert "dynamodb:PutItem" not in acciones
    assert "dynamodb:BatchWriteItem" not in acciones
```

- [ ] **Paso 2:** correrlo; esperado FAIL. **Paso 3:** quitar `dynamodb:PutItem`. **Paso 4:** pytest completo en verde y `./.venv/bin/python scripts/generar_techo.py --comprobar` con salida 0.
- [ ] **Paso 5:** `ValidatePolicy` (perfil `org-agente-iam-lectura`) sobre el techo y sobre `LimiteSistema` del repositorio: sin errores ni avisos.
- [ ] **Paso 6 (Mateo, si):** `scripts/localizar.py`; el administrador crea el conjunto de cambios `techo-v3-y-limite` sobre `agente-iam-arranque` con `local/infra/cfn/arranque.yaml`.
- [ ] **Paso 7: Revisar el conjunto de cambios con Mateo.** Esperado: exactamente dos `Modify`, `Techo` y `LimiteSistema`, ambos `Replacement: False`. Cualquier otra fila: parar.
- [ ] **Paso 8 (Mateo, si):** ejecutarlo. Leer: version por defecto del techo, su longitud igual a la del JSON del repositorio; repetir los 8 casos del simulador de E.5 contra la politica real.
- [ ] **Paso 9 (Mateo, si):** en gestion, `put_role_policy` de `AgenteIAM-Aplicador-permisos` con `local/infra/rol-aplicador-permisos.json`; leerla y comparar con el fichero (igual tras normalizar JSON).
- [ ] **Paso 10:** Documentar (subagente). pytest. Proponer commit.

---

### Tarea 4: ADR-003, aprobacion que no se puede fabricar y persona en la separacion (paso 5)

Las decisiones son de Mateo; Claude las redacta cuando el elija. Opciones y recomendacion, para el debate:

**A. Como se hace infalsificable la aprobacion.**

| Opcion | Que cierra | Que no cierra |
|---|---|---|
| A1, MAC con KMS (`GenerateMac` el aprobador, `VerifyMac` el aplicador) | que alguien sin la clave escriba una aprobacion | **al propio aprobador**: tiene `GenerateMac`, asi que firma un bloque inventado con la misma facilidad con que hoy lo escribe |
| A2, aprobacion en servidor (Lambda con URL `AWS_IAM`) | el permission set pierde `UpdateItem`; solo el rol de la Lambda escribe `aprobacion`; la Lambda saca la identidad de la firma SigV4 y corre ella los controles | nada nuevo que abrir; cuesta una Lambda y su paquete |

Recomendacion: **A2** (coincide con lo que propone Mateo). A1 solo anade algo si quien firma no es quien escribe, y en
A2 eso ya lo garantiza IAM. La objecion de `docs/DESPLIEGUE.md` ("aprobar no puede estar en el runtime: el aprobador
seria el rol") no aplica: la Lambda no se identifica por su rol, sino por quien firmo la peticion. Invocar una URL
`AWS_IAM` exige `lambda:InvokeFunctionUrl` y `lambda:InvokeFunction` (guia de Lambda, leida el 24-10-2026). Que el
evento lleve el ARN de quien llama (con el nombre de sesion) esta **por medir**.

**B. Que compara la separacion de funciones.**

| Opcion | Estable | Esta en los dos canales | Coste |
|---|---|---|---|
| B1, ARN del rol (hoy) | si | si | no distingue personas: todo el grupo es el mismo rol |
| B2, nombre de usuario de Identity Center: nombre de sesion del rol `AWSReservedSSO_*` (aprobador) y claim `username` sin el prefijo `IdentityCenter_` (solicitante) | mientras no se renombre al usuario | si (medido en el token: `IdentityCenter_aprobador.demo`, Prueba B) | medir que coinciden letra a letra |
| B3, `UserId` de Identity Center (GUID) | si, no cambia nunca | no: ni el ARN ni el token lo llevan; habria que buscarlo en el identity store de gestion | lectura entre cuentas |

Recomendacion: **B2**, con dos reglas: solo se acepta un nombre de sesion si el rol esta bajo
`/aws-reserved/sso.amazonaws.com/` (el nombre de sesion lo pone Identity Center, no la persona), y la separacion
compara aprobador frente a **solicitante**, no solo frente al beneficiario. B3 queda como mejora si un dia se renombran
usuarios.

**Files:**
- Create: `docs/ADR-003-aprobacion-en-servidor-y-persona.md`
- Modify: `docs/ESPECIFICACION-agentcore.md` §4; `CONTEXTO.md` §4, §10, §11; `ESTUDIO-diseno-y-seguridad.md` (leccion: un MAC que firma quien escribe no anade un control)

- [ ] **Paso 1:** Mateo elige A y B (o propone otra).
- [ ] **Paso 2:** Claude escribe el ADR (contexto, opciones, decision, consecuencias, lo que queda por medir).
- [ ] **Paso 3:** pytest (`test_documentacion.py`). Proponer commit.
- [ ] **Paso 4:** El codigo de A2 y B2 es un **plan propio** (Lambda de aprobacion, `aprobar --servidor`, identidad desde el evento, separacion por persona, permission set sin `UpdateItem`). Se escribe tras el ADR y tras la Tarea 6, que mide `dynamodb:Attributes` con el permission set de hoy.

---

### Tarea 5: Pila `base` (paso 6)

**Files:**
- Create: `infra/cfn/base.yaml`
- Create: `tests/seguridad/test_pila_base.py`
- Modify: `agente_iam/almacen.py` (`_dynamo_leer`), `tests/unitarios/test_almacen.py`
- Delete: `infra/rol-runtime-permisos.json`, `infra/rol-runtime-confianza.json` (los sustituye `base.yaml`); mover su comprobacion de `tests/seguridad/test_perfiles_modelo.py` a `base.yaml`; corregir las menciones en `CONTEXTO.md`, `docs/DESPLIEGUE.md`, `docs/ADR-001-agentcore-identidad.md`, `docs/ESPECIFICACION-agentcore.md`, `docs/PRUEBAS-AGENTCORE.md`, `infra/cfn/arranque.yaml` y `infra/cfn/prueba-eco.yaml` (comentarios)
- Modify: docs segun la tabla de `CLAUDE.md` (CONTEXTO §2, §5, §6, §9 #40, §10, §11; README; DESPLIEGUE)

**Recursos de `base.yaml`:**

| Recurso | Lo que lo define |
|---|---|
| `TablaSolicitudes` `agente-iam-solicitudes` | clave `id` (S), `PAY_PER_REQUEST`, PITR, Streams `NEW_AND_OLD_IMAGES`, `DeletionProtectionEnabled: true`, `DeletionPolicy`/`UpdateReplacePolicy: Retain`, cifrado por defecto (sin `kms:Decrypt` en nadie) |
| `BucketPaquete` `agente-iam-despliegue-${AWS::AccountId}` | versionado, bloqueo publico completo, `BucketOwnerEnforced`, SSE-S3, politica que niega sin TLS, `Retain` |
| `RolRuntime` `AgenteIAM-Runtime` | confianza `bedrock-agentcore.amazonaws.com` con `aws:SourceAccount` y `ArnLike aws:SourceArn arn:aws:bedrock-agentcore:us-east-1:${AWS::AccountId}:*`; boundary `AgenteIAM-LimiteSistema`; permisos del JSON retirado, pero DynamoDB = `UpdateItem` con atributos `id`, `documento`, `estado` (y `GetItem` solo si `grep -n "almacen.leer" agente_iam/servidor.py agente_iam/orquestador.py` encuentra una llamada; el 24-10-2026 no hay) |
| `RolAplicador` `AgenteIAM-Aplicador` | confianza `lambda.amazonaws.com` con `aws:SourceAccount`; boundary `AgenteIAM-LimiteSistema`; permisos de `infra/rol-aplicador-permisos.json` (sin `user/Mateo`) mas `GetItem`, `UpdateItem` con `id`, `estado`, `aplicacion`, y lectura del stream de la tabla |

En los dos roles: cada `UpdateItem` con `ForAllValues:StringEquals dynamodb:Attributes`, `Null dynamodb:Attributes
false` y `StringEqualsIfExists dynamodb:ReturnValues [NONE, UPDATED_OLD, UPDATED_NEW]` (la forma de
`identidades.yaml`), y Deny de `PutItem`, `DeleteItem`, `BatchWriteItem`, `DeleteTable`, `UpdateTable`.

- [ ] **Paso 1: Tests que fallan** en `tests/seguridad/test_pila_base.py`: `test_ningun_rol_puede_reemplazar_ni_borrar_filas` (sin `PutItem`/`BatchWriteItem`/`DeleteItem` en ningun Allow, y en el Deny de los dos), `test_cada_update_lleva_su_lista_de_atributos` (runtime exacto `["id", "documento", "estado"]`, aplicador exacto `["id", "estado", "aplicacion"]`, cada uno con el `Null` en `false`), `test_nadie_escribe_aprobacion` (ningun rol de `base.yaml` tiene `aprobacion` ni `rechazo` en su lista), `test_la_tabla_sobrevive_a_la_pila` (`Retain`, proteccion de borrado, PITR), `test_los_roles_nacen_con_el_limite_del_sistema`, `test_el_runtime_no_escribe_en_iam_ni_tiene_check_no_new_access`, `test_el_aplicador_no_habla_con_el_modelo` (Deny `bedrock:*`), `test_confianza_con_cuenta_de_origen`.
- [ ] **Paso 2: Test que falla** en `test_almacen.py` (Review Focus 4):

```python
@pytest.mark.parametrize("item", [
    {"id": {"S": "req-x"}, "estado": {"S": "aprobada"}, "aprobacion": {"S": "{}"}},   # sin documento
    {"id": {"S": "req-x"}, "documento": {"S": '{"id": "req-x"}'}},                      # sin estado
])
def test_una_fila_a_medio_crear_es_inconsistente(item, ...):
    with pytest.raises(almacen.RegistroInconsistente):
        almacen.leer("req-x")
```

Y en `test_aplicador.py`/`test_aprobacion.py`, que con esa fila los dos salen con codigo 3.
- [ ] **Paso 3:** correrlos; esperado FAIL. **Paso 4:** escribir `base.yaml` y el arreglo en `_dynamo_leer` (comprobar `documento` y `estado` antes de usarlos). **Paso 5:** pytest completo en verde; `validate_cloudformation_template` y `check_cloudformation_template_compliance` (MCP awsiac) sin errores; `ValidatePolicy` de las dos politicas de rol. Proponer commit.
- [ ] **Paso 6 (Mateo):** anadir a `~/.aws/config` el perfil `org-agente-iam-operador` (sesion `agente-iam-org`, permission set `AgenteIAM-Operador`, cuenta `agente-iam`). Claude da el bloque; Mateo lo pega y hace `aws sso login`.
- [ ] **Paso 7 (Mateo, si):** con el operador, conjunto de cambios de creacion `agente-iam-base` con `--role-arn` de `AgenteIAM-Despliegue` y `CAPABILITY_NAMED_IAM`. Revisar con Mateo: solo los cuatro recursos y sus politicas. Ejecutar.
- [ ] **Paso 8:** medir. `CREATE_COMPLETE` es la primera prueba real del rol de despliegue y de que CloudFormation envia `aws:SourceAccount` (F.3): si falla, el evento de CloudTrail dice cual. Leer la tabla (`DescribeTable`, `DescribeContinuousBackups`) y los dos roles (`GetRole`, boundary). `SimulatePrincipalPolicy` sobre los dos roles reales con `ContextEntries` de `dynamodb:Attributes` (aprobacion para el runtime: denegado; documento para el aplicador: denegado).
- [ ] **Paso 9:** Documentar (subagente): F.3 y nueva F.5 (despliegue de la base), §5, §9 #40 cerrado, §11. pytest. Proponer commit.

---

### Tarea 6: `dynamodb:Attributes` contra la tabla real (paso 6, medicion)

Con la tabla creada se mide con el unico principal humano que hoy tiene un `UpdateItem` acotado: el permission set
`AgenteIAM-Aprobador`, como `aprobador.demo`. Se mide antes de cambiar ese permission set (Tarea 4, paso 4).

**Files:**
- Create: `scripts/sonda_atributos.py`, `tests/unitarios/test_sonda_atributos.py`
- Modify: `docs/MEDICIONES.md` F.4, §J, §H si algo resulta falso; `CONTEXTO.md` §4, §6, §10; `README.md`

**Interfaces:**
- Produces: `CASOS: list[Caso]` con `Caso(nombre, operacion, params, esperado: "permitido"|"denegado")` y `veredicto(caso, codigo_error: str | None) -> str` (`cumple|no_cumple|condicion_fallida`).

Casos, todos sobre el id `sonda-atributos-<AAAAMMDD>` (queda en la tabla como rastro; el administrador puede borrarlo):

| Caso | Llamada | Esperado |
|---|---|---|
| 1 | `UpdateItem SET estado` | permitido |
| 2 | `UpdateItem SET aprobacion` | permitido |
| 3 | `UpdateItem SET documento` | denegado |
| 4 | `PutItem` | denegado |
| 5 | `UpdateItem SET aprobacion` con `ConditionExpression attribute_not_exists(documento)` | la respuesta es la medicion: denegado = la condicion cuenta |
| 6 | `UpdateItem SET aprobacion` con `ReturnValues ALL_NEW` | denegado |

- [ ] **Paso 1: Tests que fallan:** `test_veredicto` (AccessDeniedException con esperado denegado -> `cumple`; ConditionalCheckFailedException -> `condicion_fallida`, nunca `cumple`), `test_el_caso_5_no_tiene_esperado_fijo`, `test_sin_ejecutar_no_crea_sesion`.
- [ ] **Paso 2:** FAIL. **Paso 3:** escribir el script (patron de `matriz_regiones.py`; `--perfil` obligatorio con `--ejecutar`). **Paso 4:** pytest en verde. Proponer commit.
- [ ] **Paso 5 (Mateo):** perfil de `aprobador.demo` en `~/.aws/config` con su propia `sso-session` (otro usuario, otra cache de token); `aws sso login` con su MFA.
- [ ] **Paso 6 (Mateo, si: escribe una fila de prueba):** `./.venv/bin/python scripts/sonda_atributos.py --ejecutar --perfil <perfil>`. Guardar tambien el texto de cada `AccessDenied` ("explicit deny" frente a "no identity-based policy allows").
- [ ] **Paso 7:** Documentar (subagente): F.4 con fecha y casos; quitar las dos filas de §J; si el caso 5 sale denegado, anotar en CONTEXTO §4 que las condiciones de `almacen` ya estaban hechas para eso. pytest. Proponer commit.

---

## Fuera de este plan (cada uno, su plan cuando llegue)

- Codigo de la decision A y B (tras ADR-003 y Tarea 6).
- Pilas `acceso` y `runtime` (Cognito, runtime con JWT, Lambda del aplicador por Streams, trail de datos); antes, medir el `NameID`.
- Bloque 4: limpiar la cuenta de gestion.
- Estudio final de arquitectura en `ESTUDIO-diseno-y-seguridad.md`.
