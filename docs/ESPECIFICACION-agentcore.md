# Especificacion: el analista en AgentCore Runtime con JWT

Lo que el bloque 3 tiene que construir para cumplir `docs/ADR-001-agentcore-identidad.md`.
Vigente el 25-10-2026. Cada requisito dice si esta **medido** (con la prueba del
eco, 23-10-2026, §D, o contra la cuenta el 25-10-2026, §K de `docs/MEDICIONES.md`), si esta
**implementado** (codigo o plantilla desplegados, sin medir su efecto) o es **diseno** (sin probar todavia).

## 1. Identidad y token

| # | Requisito | Estado |
|---|---|---|
| 1.1 | User pool de Cognito sin usuarios propios ni registro abierto; un solo proveedor, `IdentityCenter` (SAML, metadatos por URL) | Medido (Prueba B); desplegado en `infra/cfn/acceso.yaml` el 25-10-2026 |
| 1.2 | Aplicacion SAML en Identity Center creada **en consola** (la API solo crea aplicaciones OAuth). Atributos `Subject` = `${user:subject}` (persistente) y `email` = `${user:email}`. Exige asignacion: solo entran los usuarios o grupos asignados | Medido; la aplicacion `agente-iam-cognito` se creo en consola el 25-10-2026 y el grupo `agente-iam-solicitantes` lo asigna la pila de identidades (MEDICIONES K.1) |
| 1.3 | Cliente publico: `code` con PKCE S256, scopes `openid email`, retorno `http://localhost:8080/callback` para la CLI, sin secreto ni flujos de contrasena | Medido; cliente `agente-iam-cli` desplegado el 25-10-2026 |
| 1.4 | El enlace lleva `identity_provider=IdentityCenter` (va directo, sin la pantalla de Cognito) y un `state` aleatorio que se comprueba | Medido |
| 1.5 | La CLI guarda el token con permisos 600, no lo imprime y comprueba el `sub` (quien entro de verdad) antes de usarlo | Medido (`scripts/prueba_b.py`); `scripts/solicitar.py token` lo reutiliza y se niega a guardar un `sub` que ya es de otro usuario |
| 1.6 | Duracion: token de acceso de 1 hora (medido); sesion de la aplicacion SAML de 4 horas | Medido |
| 1.7 | Grupos de Identity Center (solicitantes, aprobadores) como asignaciones de la aplicacion. Si los grupos llegan como claim, o solo `cognito:groups` con el grupo del proveedor (lo medido), esta **sin medir** | Asignacion del grupo de solicitantes: desplegada y medida (25-10-2026); el claim de grupos, sin medir |

## 2. Runtime

| # | Requisito | Estado |
|---|---|---|
| 2.1 | `customJWTAuthorizer` con `discoveryUrl` del pool y `allowedClients` con el id del cliente. No `allowedAudience`: el token de acceso de Cognito no trae `aud` | Medido (Prueba B); `agente_iam_analista-<sufijo>` `READY` con ese autorizador el 25-10-2026 |
| 2.2 | `requestHeaderAllowlist: [Authorization]`. Sin ella el contenedor no ve los claims | Medido; con ella el runtime real grabo la persona (25-10-2026, `req-020`) |
| 2.3 | Rechazos: 401 sin token y con firma alterada, antes de llegar al contenedor | Medido; sin token contra el runtime real, `401 Missing Authentication Token` (25-10-2026); la firma alterada, solo en la Prueba B |
| 2.4 | Rol del runtime: `RolRuntime` de `infra/cfn/base.yaml` (desplegado el 24-10-2026), en CloudFormation. AgentCore lo asume con una sesion por sesion del runtime. En DynamoDB el runtime escribe con `UpdateItem` solo `documento` y `estado`: el rol lleva `dynamodb:Attributes` = [`id`, `documento`, `estado`], sin `PutItem` y sin `GetItem` (no lee). Permite `inference-profile/us.anthropic.claude-*` en cualquier region (el perfil `us.` enruta a otras) | Medido: `AssumeRole` (Prueba B) y la escritura de `documento` y `estado` por el runtime real (`req-020`, `req-021`, 25-10-2026); Bedrock con ese rol dio `AccessDenied` hasta ampliar la region (`docs/MEDICIONES.md`, §K.2, §H 35). La condicion de atributos de este rol, solo con simulador (F.5); medida con llamadas reales para otro principal (F.6) |
| 2.5 | Al borrar el runtime se va su endpoint `DEFAULT`, pero no su grupo de logs. AgentCore crea el grupo `/aws/bedrock-agentcore/runtimes/<id>-DEFAULT` al crear el runtime, asi que la pila **no** lo declara (declararlo da `AlreadyExists` y rollback); su retencion de 365 dias la pone el administrador tras el primer despliegue | Medido (25-10-2026, 20:00:46 UTC, §H 33); la retencion, **pendiente** (Mateo) |
| 2.6 | El intake solo escribe si la fila no existe: `UpdateItem` con `attribute_not_exists(id)` (Fase 17, S6). Un id que ya existe, en el estado que sea, sale como `registro_existente` y no se pisa nada. El runtime no escribe encima de ninguna fila | Codigo y tests (`Stubber`); filas nuevas escritas contra la tabla real el 25-10-2026; el rechazo de un id existente, sin medir contra la tabla |

Detalle: `PLAN-CORRECCIONES.md`, Fase 15, "Bloque 3: aprobacion y rechazo como
atributos propios (24-10-2026)", y Fase 17.

## 3. Que graba el agente

`servidor.py` graba `ejecutado_por` desde los claims que el autorizador de AgentCore ya valido (`claims_validados`,
`persona_de`, `CLAIMS_DEL_REGISTRO`; implementado el 25-10-2026). Sin JWT (el backend local) sigue como no determinable.
Con JWT:

| Campo | De donde | Por que |
|---|---|---|
| `ejecutado_por.sub` | claim `sub` | Identificador estable de la persona; el unico que tambien guarda CloudTrail (evento de datos) |
| `ejecutado_por.usuario` | claim `username` | Legible (`IdentityCenter_<NameID>`). Es la clave para comparar personas entre canales (§4), no el `sub` |
| `ejecutado_por.jti` | claim `jti` | Une este registro con el evento `InvokeAgentRuntime` del trail de datos |
| `ejecutado_por.sesion_runtime` | cabecera `X-Amzn-Bedrock-AgentCore-Runtime-Session-Id` | Agrupa las peticiones de una sesion |
| `ejecutado_por.como_se_verifico` | constante | "JWT validado por el autorizador de AgentCore" |

**El contenedor no vuelve a verificar la firma.** Ya la verifico el
autorizador, y el contenedor solo es alcanzable a traves de AgentCore. Es un
**supuesto de diseno**: si algun dia el contenedor pudiera recibir trafico
por otro camino, habria que verificar la firma tambien dentro.

El token nunca se graba ni se devuelve; solo una lista cerrada de claims
(como el eco, `test_agente_eco.py`). `solicitante.persona` es el `username` sin el prefijo `IdentityCenter_` (`None` sin
JWT, sin `username`, sin prefijo o con resto vacio). Medido el 25-10-2026 contra el runtime real (`req-020`): `persona`
grabada y `ejecutado_por` determinable, con el token de Mateo (`docs/MEDICIONES.md`, §K.2).

## 4. Separacion de funciones

La separacion compara el **nombre de usuario de Identity Center**, aprobador frente a **solicitante** y tambien
frente al beneficiario, tras `NFKC` y `casefold()`; la duda bloquea (decidido en
`docs/ADR-003-aprobacion-en-servidor-y-persona.md`, B2, 24-10-2026; implementado y desplegado, Fase 19). No compara el `sub` (solo existe
en Cognito, es decir, en el token del solicitante; el aprobador entra por SSO con un permission set y no tiene `sub`),
ni el `UserId` de Identity Center (ni el ARN de la sesion ni el token lo llevan), ni el rol (es el mismo para todos,
medido).

| Canal | Donde aparece | Estado |
|---|---|---|
| Solicitante (token) | claim `username` = `IdentityCenter_<NameID>` | Medido: `IdentityCenter_aprobador.demo` (Prueba B, 23-10-2026) y `IdentityCenter_<correo>` con el token de Mateo (25-10-2026, K.2) |
| Aprobador (SSO) | nombre de sesion del rol del permission set, en `arn_llamante`; el `arn_canonico` es el del rol, sin sesion (`iam:GetRole`), asi que no distingue personas | Implementado (ADR-003, B2): se compara el nombre de sesion, solo si el rol es de un permission set; otro principal: persona no determinable. Medido con una persona (M1, 25-10-2026 UTC); con dos, sin medir |

- **Lo que hace el codigo** (`aprobar._separacion`, Fase 19): compara la persona del
  aprobador (nombre de sesion del permission set) con la persona del solicitante (el
  `username` del JWT que grabo el runtime) y con la del beneficiario; persona no
  determinable = bloqueo con motivo.
- **Medido** (ADR-003, punto 1; M1, 25-10-2026 UTC): el evento de una URL `AWS_IAM` trae el ARN de quien firma con el
  nombre de sesion. **Medido** el 24-10-2026 para `aprobador.demo` (`docs/MEDICIONES.md` F.6, punto 2): el `username` del
  token (sin `IdentityCenter_`) y el nombre de sesion del permission set coinciden letra a letra; la forma con correo
  esta medida en el claim `username` del token de Mateo (25-10-2026) y en su nombre de sesion; falta una persona con
  mayusculas y un aprobador con correo. La aplicacion SAML usa `Subject` = `${user:subject}`
  (§1.2).
- El `sub` se guarda en el registro de quien pide (§3) para unir con el evento
  de datos de CloudTrail, que solo guarda el `sub`.
- Una autoaprobacion es: nombre de usuario del aprobador igual al del
  solicitante. En el bloque 3 la comprobacion es ademas **aprobador frente a
  solicitante**, no solo aprobador frente a quien aplico (§7.9).
- El aplicador repite el control: su pre-vuelo exige
  `separacion_de_funciones.resultado == "cumplido"`, o `SALTADO` solo con
  `AGENTE_IAM_PERMITIR_AUTOAPROBACION=si` en su entorno (Fase 17, S4).
- La aprobacion la registra el servidor, no el aprobador (ADR-003, A2).

## 5. Auditoria

| Pregunta | Donde se responde |
|---|---|
| Quien pidio la solicitud N | El registro del agente (§3) |
| Que hizo el rol en AWS | CloudTrail de organizacion (gestion), sesion `BedrockAgentCore-<uuid>` |
| Que persona invoco el runtime | Solo con el trail de eventos de datos (`sub` en `additionalEventData`): trail propio `agente-iam-datos` en `agente-iam`, bucket con caducidad de 90 dias, de AgentCore Runtime y (D3, 25-10-2026) de la funcion `agente-iam-aprobacion`; desplegado el 25-10-2026. Medido el 25-10-2026 (`docs/MEDICIONES.md` M.1): `InvokeAgentRuntime` lleva `sub` y `jti` del token (sin `username` ni cuerpo) y la llamada por la URL de funcion sale como `Invoke` con el rol de Identity Center del aprobador y el host de la URL |
| Intentos sin token | No en CloudTrail. Logs y metricas del runtime |

Opcional y fuera del bloque 3, sin medir: `SourceIdentity` en un segundo rol
(ADR-001, Consecuencias).

## 6. Como se verifica al construirlo

Hecho el 25-10-2026 con `scripts/solicitar.py`: el 401 sin token y el registro con `sub`/`username` de una persona
(`docs/MEDICIONES.md`, §K.2). Falta repetir la Prueba B contra el runtime real con `scripts/prueba_b.py`
(apuntado a la pila nueva) y dos personas, y anadir:

- el registro de una solicitud lleva el `sub` y el `username` correctos;
- una autoaprobacion se rechaza comparando el nombre de usuario de
  Identity Center (§4), y antes se mide que el `NameID` coincide con el
  nombre de sesion del permission set.

## 7. Aplicador (bloque 3)

**Diseno aprobado por Mateo el 23-10-2026; implementado y desplegado el
25-10-2026** (Fase 20): la Lambda `agente-iam-aplicador`, su disparador sobre el
stream, la cola de fallos y la alarma existen en la cuenta. Todavia no ha aplicado
ninguna solicitud real: faltan subir los paquetes con el arreglo de S5
(`docs/MEDICIONES.md`, §K.3). El CLI queda solo para desarrollo con el almacen en disco.

La fila de la solicitud tiene un atributo por actor: `documento` (intake),
`estado` (los tres), `aprobacion` y `rechazo` (aprobador) y `aplicacion`
(aplicador). Nadie usa `PutItem`. El intake solo escribe si la fila no existe (§2.6), asi que no pisa ningun estado.

| # | Requisito | Estado |
|---|---|---|
| 7.1 | Disparo por DynamoDB Streams con filtro `estado = aprobada` (la tabla lleva PITR y Streams). `estado` es un atributo de primer nivel y la fuente de verdad del estado | Implementado: disparador `Enabled` con el filtro exacto, lote 1 (leido el 25-10-2026); un disparo real, sin medir |
| 7.2 | La Lambda **relee la fila** y no se fia del evento: `GetItem` fuertemente consistente, que recompone el registro (documento, estado y bloques) igual que lo ve `aplicar()`. La lectura rechaza (`RegistroInconsistente`) un `documento` que traiga `estado`, un bloque propio o un `id` distinto de la clave (Fase 17, S1): el runtime escribe `documento` y no puede aportar una aprobacion | Implementado y probado con dobles; `procesar_aprobada` rechaza ademas una fila con `aplicacion` o `rechazo` (revision final, 25-10-2026); sin medir contra la tabla |
| 7.3 | Ejecuta el mismo `aplicar()` de `agente_iam/aplicador.py`. Su pre-vuelo (Fase 17, S4) exige huella, separacion de funciones cumplida, techo `PASS`, riesgo confirmado si el riesgo recalculado lo pide, y repite `CheckNoNewAccess` (si no puede, bloquea); despues revalidacion e idempotencia por nombre determinista (reintentar no cambia nada). El rol de la Lambda necesita `access-analyzer:CheckNoNewAccess`, como `infra/rol-aplicador-permisos.json`. Un control que no se pudo ejecutar (`ControlNoEjecutable`) no es un bloqueo: la Lambda lanza, reintenta y el evento acaba en la cola | Implementado y probado con dobles; sin aplicacion real |
| 7.4 | Confianza del rol solo `lambda.amazonaws.com`, con `aws:SourceAccount` y **sin** `aws:SourceArn`: el mapeo de eventos de Lambda no aporta `aws:SourceArn` y rechaza el rol que lo exige. Ninguna persona lo asume | Medido (rechazo 20:06:11 UTC y aceptacion 20:24:06 UTC del 25-10-2026, §H 34) |
| 7.5 | Estado nuevo `bloqueada_al_aplicar`. Hoy un bloqueo sale con codigo 3 sin escribir; con Lambda reintentaria para siempre. Es un estado de decision: el intake solo escribe si la fila no existe (§2.6), asi que no lo pisa. Se escribe una vez, con el bloque `aplicacion` (`decision: "bloquear"`, `bloqueos`, `avisos`, `por`) | Implementado (`models.py`, `aplicador.procesar_aprobada`); sin medir en la cuenta |
| 7.6 | Errores: 2 reintentos (seguros por la idempotencia) y despues la cola de fallos `agente-iam-aplicador-fallos` (14 dias) con la alarma `agente-iam-aplicador-fallos` y el tema `agente-iam-alarmas` | Desplegado y leido (25-10-2026); el reintento, la cola y la alarma, sin medir |
| 7.7 | `ejecutor` = el rol de la Lambda; quien aprobo sigue en `aprobacion.por`. `aplicar()` escribe con `guardar_decision(resultado, "aplicacion", estado_leido, clave=id_leido)`: solo viajan el bloque `aplicacion` y `estado`. El rol lleva `UpdateItem` con `dynamodb:Attributes` = [`id`, `estado`, `aplicacion`], sin `PutItem`, y `GetItem` | Implementado; sin medir (el simulador dio 16 de 16 sobre los roles de la base, F.5) |
| 7.8 | En `aprobar`: ya no se corre el aplicador despues; termina diciendo que la aplicacion va en curso | La Lambda de aprobacion no lo corre ni lo lleva en su zip (Fase 19); que su respuesta diga que la aplicacion va en curso, sin hacer |
| 7.9 | Separacion de funciones: compara ademas aprobador frente a solicitante (§4) | Implementado (Fase 19); medido con una persona (M1) |

- Un registro con `aprobacion` y `rechazo` a la vez no se aplica (el pre-vuelo
  lo bloquea): no sale del flujo normal, porque las dos escrituras se excluyen.
- **Sigue abierto** (`CONTEXTO.md`, §10): un administrador de la cuenta puede
  escribir el atributo `aprobacion` y fabricar una, porque la huella no lleva
  secreto (`docs/MEDICIONES.md`, §H, fila 25); desde ADR-003 el aprobador no puede
  (M4) y solo la Lambda de aprobacion escribe ese bloque. El disparo de 7.1 por
  `estado = aprobada` no lo evita.
- Una fila `aprobada` que ya lleva `aplicacion` o `rechazo` no se aplica nunca: el runtime puede escribir `estado`, y sin
  este control volveria a disparar la Lambda (§H 38).

Motivo y riesgo que reduce: `PLAN-CORRECCIONES.md`, Fase 15, "Bloque 3:
diseno aprobado (23-10-2026)", puntos C y D.
