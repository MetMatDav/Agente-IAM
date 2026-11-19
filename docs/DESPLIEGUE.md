# Despliegue en AgentCore Runtime

Guia corta de **que hay que desplegar y en que orden** segun el diseno actual
(PLAN-CORRECCIONES, Fase 15, "Bloque 3: diseno aprobado"). Todas las pilas de la tabla
estan desplegadas desde el 25-10-2026 (UTC).
Nace como plan de consola de la Fase 8 (la version completa quedo en la historia de git del
repositorio privado de origen, commit `8cb3c42`),
que el bloque 3 dejo atras (pilas de CloudFormation en vez de pasos de consola,
runtime con autorizador JWT, aplicador como Lambda, tabla con un atributo por actor).
Cuenta de ejemplo `111122223333`, region `us-east-1`; la cuenta real la sustituye
`scripts/localizar.py`.

La pila base esta en `infra/cfn/base.yaml` (desplegada el 24-10-2026) y sustituye al JSON de la Fase 8
del rol del runtime, retirado.

## Pilas y orden

Claude escribe cada plantilla; la despliega el operador con CloudFormation y el rol
`AgenteIAM-Despliegue`, con el si de Mateo (el permission set del operador solo
deja crear o cambiar pilas `agente-iam-*` pasando ese rol).

| Pila | Cuenta | Contenido | Estado |
|---|---|---|---|
| `agente-iam-gobierno-regiones` | gestion | SCP y control de regiones para Bedrock con perfil `us.` | Desplegada el 23-10-2026 (MEDICIONES C.2) |
| `agente-iam-identidades` | gestion | Grupos, permission sets, asignaciones | Desplegada el 23-10-2026 (F.2) |
| `agente-iam-arranque` | `agente-iam` | Rol `AgenteIAM-Despliegue`, `AgenteIAM-LimiteSistema` y el techo `AgenteIAM-Techo` | Desplegada el 23-10-2026; techo v2 el mismo dia; techo v3 y `LimiteSistema` sin `PutItem` el 24-10-2026 (F.3, E.4, E.8); Fase 23, bloque 1: `arranque-fase-23`, `UPDATE_COMPLETE` 04:34:46 UTC del 26-10-2026 (MEDICIONES O.1) |
| `agente-iam-base` | `agente-iam` | Bucket del paquete (versionado), tabla con PITR y Streams, roles del runtime y del aplicador, Lambda de aprobacion `agente-iam-aprobacion`, su rol, su URL `AWS_IAM` y su grupo de logs (ADR-003) | Desplegada el 24-10-2026; Lambda de aprobacion el 25-10-2026 (UTC); codigo de la Lambda actualizado el 25-10-2026, `UPDATE_COMPLETE` 22:05:30 UTC (MEDICIONES F.5, F.7, L.1); Fase 23, bloque 1: `base-aplicador-roles-de-persona`, `UPDATE_COMPLETE` 04:40:08 UTC del 26-10-2026 (O.1); Fase 23, bloque 3: `base-rol-avisos` (Add `RolAvisos`), `UPDATE_COMPLETE` 19:33:24 UTC, y `base-rol-avisos-2` (`identity/*`, §H 40), `UPDATE_COMPLETE` 19:39:26 UTC del 26-10-2026 (O.5); Fase 28: `base-remitente-dominio`, `UPDATE_COMPLETE` 04:18:41 UTC (R.3), y `base-fase-28` (codigo de la Lambda de aprobacion y las dos sentencias de existencia en el rol del runtime), `UPDATE_COMPLETE` 22:58:44 UTC del 27-10-2026 (R.9) |
| `agente-iam-acceso` | `agente-iam` | Cognito federado con Identity Center; dos despliegues, con la aplicacion SAML en consola entre medias | Desplegada el 25-10-2026: pool y dominio 19:35:25, proveedor y cliente 19:58:57 UTC (MEDICIONES K.1); Fase 23, bloque 1: `acceso-proveedor-oidc`, `UPDATE_COMPLETE` 04:36:48 UTC del 26-10-2026 (O.1); Fase 23, bloque 2: `acceso-cliente-web`, `UPDATE_COMPLETE` 18:51:06 UTC del 26-10-2026, cliente `agente-iam-web` (O.4) |
| `agente-iam-beneficiarios` | `agente-iam` | Rol `app-finanzas-demo` con el techo como boundary y bucket `finanzas-demo-<cuenta>`; la despliega el administrador | Desplegada el 25-10-2026, 19:41:44 UTC (K.1) |
| `agente-iam-runtime` | `agente-iam` | Runtime con autorizador JWT, Lambda del aplicador con su disparador, cola de fallos, alarma, trail de datos | Desplegada el 25-10-2026 al tercer intento, `CREATE_COMPLETE` 20:24:49 UTC; el grupo de logs del runtime no lo declara la pila (K.1); codigo actualizado el 25-10-2026, `UPDATE_COMPLETE` 22:05:57 UTC, runtime en version 2 (L.1); Fase 23, bloque 1: `runtime-fase-23`, `UPDATE_COMPLETE` 04:40:36 UTC del 26-10-2026, runtime en version 3 (O.1); Fase 23, bloque 2: `runtime-cliente-web`, `UPDATE_COMPLETE` 18:52:22 UTC del 26-10-2026, runtime en version 4 con dos clientes (O.4); Fase 23, bloque 3: `runtime-avisos` (Lambda `agente-iam-avisos`, `RegistroAvisos`, `DisparadorAvisos`), `UPDATE_COMPLETE` 19:33:55 UTC del 26-10-2026 (O.5); Fase 28: `runtime-remitente-dominio`, `UPDATE_COMPLETE` 04:19:13 UTC (R.3), y `runtime-fase-28` (codigo del runtime y del aplicador, `UrlWebAvisos`), `UPDATE_COMPLETE` 22:59:16 UTC del 27-10-2026, runtime en version 5 (R.9); Fase 31: `runtime-prompt-s3` (codigo del runtime), `UPDATE_COMPLETE` 02:11:00 UTC del 28-10-2026, runtime en version 6 (U.2) |
| `agente-iam-web` | `agente-iam` | Bucket privado `agente-iam-web-<cuenta>` (`Retain`), su politica, OAC, politica de cabeceras de seguridad y distribucion de CloudFront con la pagina web (bloque 2) | Creada el 26-10-2026 por el operador: `web-1`, `CREATE_COMPLETE` 18:50:14 UTC (MEDICIONES O.4) |

Despues: codigo y verificacion. Hecho el 25-10-2026: el runtime real sin token da `401` y con el token de Mateo graba la
persona (MEDICIONES K.2); el circuito completo con dos personas distintas, de la peticion con JWT a `aplicada` por la
Lambda del aplicador (`req-022`, L.2). Falta, de las pruebas del bloque 3, los casos 1 a 4 de la matriz de regiones con
los roles reales (C.3).

Desde el 24-10-2026 el techo de la cuenta es el del repositorio (v3) y la politica del aplicador lleva
`access-analyzer:CheckNoNewAccess` (MEDICIONES E.8).

## La Lambda de aprobacion (ADR-003)

La aprobacion la registra una Lambda con URL de funcion (`AuthType: AWS_IAM`), en la pila
`agente-iam-base`. Como se actualiza, en este orden:

- **Orden de las pilas.** Arranque antes que base, porque el rol de despliegue necesita las
  cinco acciones de `AWS::Lambda::Url` para crear la URL; identidades antes que base, por el
  prefijo del bucket del operador (`agente-iam-despliegue-<cuenta>/agente-iam/*`).
- **Paquete.** `scripts/empaquetar.sh aprobacion` deja `dist/agente-iam-aprobacion.zip` e
  imprime la clave `agente-iam/aprobacion-<12 hex del sha256>.zip`.
- **Subida.** El operador sube el zip a `s3://agente-iam-despliegue-<cuenta>/<clave>`; su
  `PutObject` solo vale bajo `agente-iam/`. Su propio `HeadObject` da 403 por su Deny de
  lectura de datos: es normal.
- **Despliegue.** Conjunto de cambios de `agente-iam-base` con el parametro
  `ClaveCodigoAprobacion` y el rol `AgenteIAM-Despliegue`, revisado y ejecutado con el si de
  Mateo. La URL es la salida `UrlAprobacion`; el cliente la toma de `AGENTE_IAM_URL_APROBACION`.
- **Aviso.** El grupo de logs es `Retain` y la funcion y el rol tienen nombre fijo: borrar y
  recrear la pila choca con lo retenido (habria que borrar o importar el grupo).
- **Como se comprueba.** M1 a M4 de MEDICIONES F.7: la peticion firmada de `aprobador.demo` da
  409 sobre la fila de la sonda; sin firma, 403; `Invoke` directo,
  `AccessDeniedException`.

## Pilas de acceso y runtime, y la Lambda del aplicador (Fase 20, 25-10-2026)

Horas en UTC; el detalle de cada despliegue, en `docs/MEDICIONES.md` K.1. Orden real, cada paso con el si de Mateo:

1. **Acceso, primer despliegue** (el operador): user pool y dominio (`PrefijoDominio` = `agente-iam-` y 6 hex). Las
   salidas `AcsUrlParaIdentityCenter` y `AudienceParaIdentityCenter` son los dos datos de la consola.
2. **Aplicacion SAML `agente-iam-cognito`, en consola** (Mateo, cuenta de gestion; la API no crea aplicaciones SAML):
   Application ACS URL y audience, las de esas salidas; atributos `Subject` = `${user:subject}` con formato `persistent`
   y `email` = `${user:email}`; sesion de 4 horas. No se asigna ningun grupo a mano: lo hace la pila de identidades.
3. **Beneficiarios** (`infra/cfn/beneficiarios.yaml`, el administrador): el rol de despliegue solo crea roles con
   `LimiteSistema`, y `app-finanzas-demo` lleva el techo como boundary. Deja el rol y el bucket `finanzas-demo-<cuenta>`.
4. **Base** (el operador): permiso `sqs:SendMessage` del aplicador sobre la cola de fallos y la confianza de su rol (ver
   el aviso sobre `aws:SourceAccount`).
5. **Identidades** (el administrador de gestion): `AplicacionSamlArn` con el ARN de la aplicacion; asigna el grupo
   `agente-iam-solicitantes`.
6. **Acceso, segundo despliegue** (el operador): `MetadataUrl` con la URL de metadatos de la aplicacion; crea el proveedor
   `IdentityCenter` y el cliente `agente-iam-cli`. Sale `ClienteId`.
7. **Paquetes y subida.** Solo `scripts/empaquetar.sh aprobacion` y `scripts/empaquetar.sh aplicador` imprimen su clave
   (`agente-iam/aprobacion-<12 hex>.zip` y `agente-iam/aplicador-<12 hex>.zip`). La del runtime es `agente-iam/runtime-<12 hex>.zip`,
   con los 12 primeros caracteres de `sha256sum dist/agente-iam.zip`; el operador sube los zips al bucket de despliegue.
8. **Runtime** (el operador): parametros `ClaveCodigoRuntime`, `ClaveCodigoAplicador`, `DiscoveryUrl`, `ClienteId`,
   `StreamArn`, `CorreoAlarmas` (dato personal: se pasa al desplegar, nunca va al repositorio) y `ModelId`. Crea el
   runtime, la Lambda `agente-iam-aplicador`, su disparador, la cola de fallos, el tema y la alarma, el grupo de logs de la
   Lambda y el trail `agente-iam-datos` con su bucket.
9. **Despues**: el administrador pone la retencion de 365 dias al grupo de logs del runtime; Mateo confirma por correo la
   suscripcion SNS. Ambos hechos el 25-10-2026 UTC (retencion 22:06:25, suscripcion leida `confirmada` a las 22:10;
   MEDICIONES L.3).

**Actualizar el codigo de las Lambdas y del runtime** (medido el 25-10-2026 UTC con los paquetes con el arreglo de S5,
MEDICIONES L.1): se sube el zip nuevo (el operador, `PutObject`; el bucket es versionado, las claves anteriores siguen) y
se ejecuta un conjunto de cambios con la clave nueva y los demas parametros en `UsePreviousValue`. Sin reemplazo de
recursos (`Replacement=False`): base cambia `FuncionAprobacion` (`ClaveCodigoAprobacion`) y runtime cambia
`FuncionAplicador` y `Runtime` (`ClaveCodigoAplicador`, `ClaveCodigoRuntime`). La URL de funcion sale como `Conditional`
en el conjunto de cambios por depender del ARN de la funcion; el ARN no cambia y la URL no cambio. El runtime pasa a la
version siguiente y `DEFAULT` la sirve. El 25-10-2026: base `base-aprobacion-s5-39bea18e7182` y runtime
`runtime-s5-cd96aac0627e-b3099d652857`; claves `agente-iam/runtime-cd96aac0627e.zip`,
`agente-iam/aprobacion-39bea18e7182.zip` y `agente-iam/aplicador-b3099d652857.zip`. Claves vigentes desde el 26-10-2026
(bloque 1 de la Fase 23): `agente-iam/runtime-1955fbf46385.zip` y `agente-iam/aplicador-6b114251db4a.zip` (04:40 UTC, O.1) y
`agente-iam/aprobacion-346e7b8b0cec.zip` (18:32 UTC, O.3).

Avisos (los cuatro primeros, medidos el 25-10-2026; `docs/MEDICIONES.md` §H 33 a 35 y K.1; el re-drive no se ha probado):

- **El grupo de logs del runtime lo crea AgentCore** (`/aws/bedrock-agentcore/runtimes/<id>-DEFAULT`) al crear el runtime.
  Si la pila lo declara, falla con `AlreadyExists` y hace rollback; no se declara, y sale como `GrupoLogsRuntime`. Su
  retencion es manual: `aws logs put-retention-policy --log-group-name <GrupoLogsRuntime> --retention-in-days 365`
  (administrador). Un rollback deja `Retain` los grupos y el bucket del trail: hay que borrarlos antes de reintentar.
- **El mapeo de eventos rechaza una confianza con `aws:SourceArn`** ("Please add Lambda as a Trusted Entity"): el rol del
  aplicador lleva `aws:SourceAccount` solo.
- **El perfil de inferencia `us.` enruta a otras regiones y se autoriza en la de destino**: el rol del runtime permite
  `inference-profile/us.anthropic.claude-*` en cualquier region. Sin eso, `Converse` da un `AccessDeniedException`
  generico que el simulador no anticipa.
- **Sin concurrencia reservada** en la Lambda del aplicador: la cuota de la cuenta es 10 y Lambda exige 10 sin reservar.
- **Re-drive de la cola de fallos, a mano.** Un evento sintetico a la Lambda del aplicador (`eventName` `MODIFY`,
  `dynamodb.Keys.id.S` con el id, `dynamodb.NewImage.estado.S` = `aprobada`); la Lambda relee la fila y, si ya no esta
  `aprobada` o ya esta decidida, no hace nada o lanza. Sin probar.
- **Como se ve un fallo y como se vuelve a tramitar** (medido el 25-10-2026 con una fila ya decidida reescrita a
  `aprobada`, `docs/MEDICIONES.md` M.2). Un fallo se ve porque la alarma `agente-iam-aplicador-fallos` pasa a `ALARM`
  (unos minutos despues: la metrica de SQS tarda uno o dos) y llega el correo del tema `agente-iam-alarmas`; en la cola
  `agente-iam-aplicador-fallos` queda un mensaje con `requestContext.condition = RetryAttemptsExhausted` y
  `DDBStreamBatchInfo`. Para volver a tramitar, el administrador borra el mensaje de la cola y la fila de la tabla y la
  solicitud se tramita de nuevo con otro id; la alarma vuelve a `OK` sola al siguiente periodo sin mensajes.

## Fase 23, bloque 1: rol por persona

**Estado al 26-10-2026 (UTC): desplegado entre las 04:34 y las 04:41 UTC (`docs/MEDICIONES.md` O.1), cada escritura con el si de
Mateo (el de los change sets de base y runtime, a las 04:38 UTC, tras ensenarselos); la prueba de fuego (O.2 y O.3) se midio el mismo dia: bloque 1 desplegado y medido de punta a punta.** Diseno:
`docs/ADR-004-rol-por-persona-y-confianza-por-token.md`; plan, tarea 12:
`docs/superpowers/plans/2026-10-26-formulario-web-y-rol-por-persona.md`. Lo que se midio antes de escribirlo (la
confianza del rol y el canje del token) esta en `docs/MEDICIONES.md` N.

Prerrequisitos (para repetirlo o para la prueba de fuego; Mateo): `aws sso login` de la sesion `agente-iam-org` en su
terminal; la MFA de `solicitante.demo` registrada en Identity Center; `./.venv/bin/python scripts/localizar.py` con
`AWS_PROFILE=org-agente-iam`. Antes de empezar, releer `docs/MEDICIONES.md` K.1 (grupo de logs del runtime, confianza del mapeo de eventos).

Orden seguido (el de la tarea 12 del plan) y lo que paso:

1. **Comprobaciones, sin escribir** (administrador, 04:30). Con
   `cloudformation:DescribeType` se leyeron los esquemas de `AWS::IAM::OIDCProvider`, `AWS::CloudFront::Distribution`,
   `AWS::CloudFront::OriginAccessControl` y `AWS::CloudFront::ResponseHeadersPolicy` (como en F.7 y la leccion de §H 31). Hallazgo
   (O.1): el manejador `list` del proveedor OIDC pide `iam:ListOpenIDConnectProviders` y los de CloudFront piden tres `List*`, todas sin
   recurso, y se anadieron a `arranque.yaml` antes del change set; `cloudfront:CreateDistributionWithTags` ya no existe como accion de IAM
   (referencia de autorizacion y cfn-lint W3037); las de grupos de conexion y origenes VPC (`CreateConnectionGroup`,
   `GetConnectionGroup`, `GetVpcOrigin`, `UpdateDistributionWithStagingConfig`) no las usa una distribucion con origen S3 (sin
   medir: lo dira el primer despliegue de `web.yaml`). Los permisos de CloudFront y de SES entraron en este mismo change set para los
   bloques 2 y 3, para que arranque se despliegue una sola vez.
2. **Arranque** (el administrador, `org-agente-iam`): change set `arranque-fase-23` con `arranque.yaml`; Modify de
   `LimiteSistema`, `PoliticaBarreras`, `PoliticaComputo` y `PoliticaIdentidad` (`PolicyDocument`, sin reemplazo); ejecutado 04:34:06,
   `UPDATE_COMPLETE` 04:34:46. En `LimiteSistema` (v3, actualizada 04:34:24): crear roles solo bajo `/agente-iam/personas/` y solo con el
   techo, etiquetarlos, `ses:SendEmail` y los Deny `NuncaUnRolFueraDeLaRutaDePersonas` y `NuncaUnRolDePersonaSinElTecho`; en
   `PoliticaIdentidad`, el proveedor OIDC solo del pool de Cognito y `ListarProveedoresOidcNoTieneRecurso`; en `PoliticaComputo`,
   `CloudFrontSinTipoDeRecurso`; en `PoliticaBarreras`, `NuncaOtroProveedorOidc`.
3. **Acceso** (el operador): change set `acceso-proveedor-oidc` con los mismos parametros (`UsePreviousValue`); Add de
   `ProveedorOidc` (`AWS::IAM::OIDCProvider`); ejecutado 04:36:35, `UPDATE_COMPLETE` 04:36:48. `GetOpenIDConnectProvider` (04:41) da la
   URL del pool `agente-iam-acceso`, `ClientIDList` = [`agente-iam-cli`] (igual a la salida `ClienteId`) y una huella. **CloudFormation
   acepto el proveedor sin `ThumbprintList`** (la plantilla no lo lleva) y IAM puso la huella. Salida nueva `ProveedorOidcArn`.
4. **Paquetes** (Claude los construye; el operador los sube con `put_object`, ~04:37): `agente-iam/runtime-1955fbf46385.zip`
   (29 257 697 bytes) y `agente-iam/aplicador-6b114251db4a.zip` (28 510 814 bytes); el ETag es el md5 en los dos. `personas.py` viaja en
   los dos (lo importan el servidor y el aplicador) y queda fuera del zip de la aprobacion. **La Lambda de aprobacion TAMBIEN hay
   que reempaquetarla cuando cambia `aprobar.py` o `models.py`** (revalida la fila con ellos): el plan lo olvido y la primera
   aprobacion dio 409 el 26-10-2026 (`docs/MEDICIONES.md` §H 39, O.3). Se arreglo a las 18:32 UTC con
   `agente-iam/aprobacion-346e7b8b0cec.zip` (28 487 490 bytes, subido por el operador a las 18:30:43) y el change set
   `base-aprobacion-fase-23` en `agente-iam-base` (solo `FuncionAprobacion` por `Code`, sin reemplazo; ejecutado 18:31:51,
   `UPDATE_COMPLETE` 18:32:11). Regla: cada cambio en `agente_iam/` se contrasta con las tres listas de `scripts/empaquetar.sh` y
   se reempaqueta cada Lambda que lo lleve.
5. **Base** (el operador): change set `base-aplicador-roles-de-persona`, que cambia solo `RolAplicador` (`Policies`, sin
   reemplazo); ejecutado 04:39:41, `UPDATE_COMPLETE` 04:40:08. La politica `AgenteIAM-Aplicador-permisos` lleva los Sids
   `CrearRolesDePersonaSoloConElTecho`, `EtiquetarYLeerRolesDePersona`, `ListarRolesNoTieneRecurso` (`iam:ListRoles` sobre `*` para repetir el
   tope al aplicar), `NuncaUnRolFueraDeLaRutaDePersonas` y `NuncaUnRolDePersonaSinElTecho`; `iam:CreateRole` ya no esta en
   `NuncaCrearIdentidadesNiEscalar`. El rol del runtime no cambia.
6. **Runtime** (el operador): change set `runtime-fase-23` con `ClaveCodigoRuntime` y `ClaveCodigoAplicador` nuevas y los demas
   parametros en `UsePreviousValue`; Modify de `FuncionAplicador` (`Code`, `Environment`) y `Runtime` (`AgentRuntimeArtifact`), sin
   reemplazos; ejecutado 04:40:09, `UPDATE_COMPLETE` 04:40:36. **No hay parametro `UserPoolId`**: el id del pool sale de `DiscoveryUrl`
   partida por `/` (indice 3) y llega a la Lambda del aplicador como `AGENTE_IAM_POOL_ID`, junto con `AGENTE_IAM_CLIENTES` (el cliente de
   la CLI); ambas variables presentes. **`ClienteWebId` queda vacio** hasta el bloque 2 (la pagina web): con el vacio el autorizador
   del runtime solo admite el cliente de la CLI. Resultado (04:41): runtime `READY` en la version 3, endpoint `DEFAULT` `READY` con
   `liveVersion` 3, `allowedClients` con una entrada; Lambda `Active` / `Successful` (codigo modificado 04:40:21).
7. **Medicion** (Claude y Mateo; el detalle esta en la tarea 12 del plan), **medida el 26-10-2026** (`docs/MEDICIONES.md` O.2 y
   O.3). `aprobador.demo`, fuera del grupo `agente-iam-solicitantes`, no obtiene token (Identity Center: "No access"). El circuito
   de `solicitante.demo` (`solicitar.py enviar`, `aprobar_cliente`, rol creado, `solicitar.py asumir`) funciono de punta a punta con
   `req-20261026-de924c07`: `propuesta` en 25 s, `aprobada` a las 18:33:07, `aplicada` a las 18:33:12 y canje al primer intento;
   el token de otra persona (`mateo`), una sesion de mas horas que las pedidas y el reenvio con la misma `--clave` dieron el
   rechazo esperado. Mateo sacaba los tokens con MFA en dos ventanas privadas y aprobaba como `aprobador.demo` desde su terminal.

Verificado tras ejecutar (O.1, lectura del administrador, 04:41): las cuatro plantillas desplegadas (`GetTemplate`, `Original`) son
identicas a `infra/cfn/*.yaml`.

Avisos para la prueba de fuego:
- **Compatibilidad del contrato.** El runtime en version 3 (desde las 04:40:36 UTC del 26-10-2026) solo acepta `SolicitudWeb` y
  rechaza por forma `principal_arn_declarado` y `solicitud_id` (el rechazo es comportamiento del codigo; medido contra el runtime el
  26-10-2026, O.3: acepta `SolicitudWeb` y devuelve `propuesta`). Por eso
  `solicitar.py enviar` con los ejemplos de `ejemplos/` ya no vale contra la cuenta y se usa `ejemplos/web/`; el modo anterior queda
  solo en el CLI de desarrollo.
- **Consistencia eventual de IAM.** El primer `AssumeRoleWithWebIdentity` tras crear el rol, o el `AttachRolePolicy` con la
  condicion de boundary, pueden fallar unos segundos con `AccessDenied`: el aplicador reintenta ese adjuntar y `asumir`
  sugiere esperar. Medido el 26-10-2026 (O.3): no se manifesto a los 38 s tras `CreateRole`; a los 10 s, sin medir.
- **Lo que queda sin medir** (`docs/MEDICIONES.md` §J): la consistencia eventual a los 10 s exactos. El vencimiento real de un rol
  creado por el sistema se midio el 26-10-2026 a las 22:33 UTC (O.6).

## Fase 23, bloque 2: la pagina web

**Estado al 26-10-2026 (UTC): desplegado entre las 18:47 y las 18:54 UTC y medido el mismo dia, desde el navegador, hasta el canje en STS
(`docs/MEDICIONES.md` O.4).** Cada change set se comparo con lo esperado antes de ejecutarlo; los hizo el operador con el si de
Mateo al bloque entero ("en orden, parando si un change set trae algo inesperado"). Plan: tareas 14 a 17 de
`docs/superpowers/plans/2026-10-26-formulario-web-y-rol-por-persona.md`; diseno y limites en
`docs/ADR-004-rol-por-persona-y-confianza-por-token.md` (anexo del bloque 2).

Orden (cada paso necesita el anterior):

1. **Web** (el operador): change set `web-1` de `infra/cfn/web.yaml` con `DominioCognito` = la salida `UrlDominio` de la pila de
   acceso; Add de `BucketWeb`, `PoliticaBucketWeb`, `AccesoOrigen`, `CabecerasSeguridad` y `Distribucion` (solo esos cinco); ejecutado
   18:47:12, `CREATE_COMPLETE` 18:50:14. Ningun fallo de permisos del rol de despliegue: bastaron las acciones de CloudFront anadidas en
   `arranque.yaml` en el bloque 1. Salidas: `UrlWeb` (`https://<id>.cloudfront.net`), `BucketWeb` y `DistribucionId`.
2. **Acceso** (el operador): change set `acceso-cliente-web` con `UrlRetornoWeb` = `UrlWeb` + `/` (con la barra final) y los demas
   parametros en `UsePreviousValue`; Add de `ClienteWeb` y Modify de `ProveedorOidc` (`ClientIdList`, sin reemplazo); creado 18:50:54,
   `UPDATE_COMPLETE` 18:51:06. Con `UrlRetornoWeb` vacio no hay cliente web. Salida nueva `ClienteWebId`; el proveedor OIDC lista los dos
   clientes (`GetOpenIDConnectProvider`).
3. **Runtime** (el operador): change set `runtime-cliente-web` con `ClienteWebId` y los demas parametros en `UsePreviousValue`; Modify de
   `FuncionAplicador` (`Environment`) y `Runtime` (`AuthorizerConfiguration`), sin reemplazos; creado 18:51:59, `UPDATE_COMPLETE` 18:52:22.
   Runtime `READY` en la version 4, endpoint `DEFAULT` con `liveVersion` 4, `allowedClients` con dos entradas, y la Lambda del aplicador con
   `AGENTE_IAM_CLIENTES` de dos. **Aviso: la plantilla de `runtime.yaml` del arbol ya lleva el parametro `CorreoRemitente` del bloque 3**,
   asi que este change set se hizo con la plantilla de `HEAD` (`d62c5fc`), que aun no tenia ese parametro. Hoy el bloque 3 esta desplegado
   y un change set de runtime lleva `CorreoRemitente` en `UsePreviousValue`.
4. **Construir la pagina**: `./.venv/bin/python scripts/construir_web.py --perfil org-agente-iam --destino local/web` lee las salidas de las
   pilas y escribe `index.html`, `estilos.css`, `app.js` y `config.js` (una linea con la configuracion publica) en `local/web/`. La carpeta
   `web/` del repositorio no lleva nada de la cuenta.
5. **Subir los ficheros** (el ADMINISTRADOR, con el si de Mateo): `put_object` de los cuatro ficheros al bucket `agente-iam-web-<cuenta>`,
   cada uno con su `Content-Type` correcto (`text/html`, `text/css`, `text/javascript`, con `charset=utf-8`) y
   `Cache-Control: no-cache`. **El operador no puede escribir en ese bucket.** Al resubir un fichero, hay que lanzar tambien
   `CreateInvalidation` con la ruta `/*`; si no, CloudFront sirve la copia vieja. La URL de la pagina es la salida `UrlWeb`.
   Desde la Fase 29 (27-10-2026) son cinco: tambien `vista-previa.png` (`image/png`), la imagen de la vista previa.

Medido (O.4, 26-10-2026): los tres preflight de CORS pasan (el runtime, que admite tambien la cabecera de sesion si se pide; Cognito en
`/oauth2/token`; STS, tambien en el error); la pagina responde `200` con la CSP, HSTS, nosniff, no-referrer y DENY; HTTP redirige a HTTPS; el
bucket por su URL de S3 da `403`; y el flujo entero en el navegador integrado con `solicitante.demo` (MFA) y `aprobador.demo`: dos envios
(2 horas, `redundante_no_requiere_cambio`; 6 horas, `propuesta`), aprobacion, `aplicada` 4 s despues y credenciales de 6 horas desde STS.
Recargar la pagina pierde la sesion.

Avisos:
- **TLS: `MinimumProtocolVersion` queda en `TLSv1`.** Con el certificado por defecto de CloudFront, la distribucion ignora el `TLSv1.2_2021`
  de la plantilla (`GetDistribution`, 26-10-2026, O.4). Fijar TLS 1.2 como minimo exige un certificado en ACM y un dominio propio:
  plantillas escritas el 26-10-2026, despliegue en la seccion Fase 27 de esta guia (`docs/ADR-005-dominio-propio-y-tls.md`).
- **Los roles de persona de la demo quedan vigentes** (los de esta prueba y los del bloque 1 y 3; vencimientos en `CONTEXTO.md` §5); quedan
  inertes al vencer. Mateo decidio dejarlos el 26-10-2026; borrarlos es una fase posterior.

## Fase 23, bloque 3: el correo

**Estado al 26-10-2026 (UTC): desplegado y medido (`docs/MEDICIONES.md` O.5).** Orden seguido, con el si de Mateo a cada escritura:

1. **SES** (identidad del remitente): creada por API por el administrador a las 19:31:15 (`CreateEmailIdentity`), con el si de Mateo.
   Quedo `PENDING` hasta que Mateo pulso el enlace del correo de verificacion; `SUCCESS` leido a las 20:00. SES de `agente-iam` esta en
   modo inicial (medido: `ProductionAccessEnabled` false, 200 por dia): solo manda a direcciones verificadas. Salir de ese modo es una
   peticion aparte a AWS.
2. **Paquete** (Claude; el operador sube): `scripts/empaquetar.sh aplicador`; subido a las 19:31:50 como
   `agente-iam/aplicador-07540418c756.zip` (lleva `avisos.py`, el manejador de la Lambda de avisos, que usa el mismo zip que el aplicador).
3. **Base** (el operador): change set `base-rol-avisos` con `CorreoRemitente`; Add `RolAvisos` (`AgenteIAM-Avisos`) y nada mas; ejecutado
   19:32:50, `UPDATE_COMPLETE` 19:33:24.
4. **Runtime** (el operador): change set `runtime-avisos` con la clave nueva y `CorreoRemitente`; Modify `FuncionAplicador` (`Code`), Add
   `RegistroAvisos` (365 dias), `FuncionAvisos` (`agente-iam-avisos`, `agente_iam.avisos.manejador`, `AGENTE_IAM_REMITENTE`) y
   `DisparadorAvisos` (filtro de los siete estados, lote de 1, 0 reintentos, sin cola); `UPDATE_COMPLETE` 19:33:55.
5. **Correccion del rol** (el operador): change set `base-rol-avisos-2`; Modify `RolAvisos` (`Policies`) y nada mas; ejecutado 19:38:58,
   `UPDATE_COMPLETE` 19:39:26 (hallazgo siguiente).
6. **Medicion O.5** (19:34 a 20:05): ver abajo.

**Hallazgo (`docs/MEDICIONES.md` §H 40).** SES autoriza `ses:SendEmail` tambien sobre la identidad del DESTINATARIO. El rol de avisos
permitia solo `identity/<remitente>` y el primer aviso (19:35 UTC) dio `AccessDenied`. El rol lleva ahora `Resource: identity/*` y la
condicion `ses:FromAddress` = remitente. Regla: antes de escribir un `Resource` estrecho, mirar sobre que recursos evalua el servicio la
accion.

**Regla de operacion: verificar el remitente ANTES del primer evento.** Un aviso no es el circuito: no se reintenta. Los dos avisos de
`req-20261026-1dfe50ff` (`aprobada` y `aplicada`, 19:49 UTC) se perdieron con el remitente aun `PENDING` y no se repiten.

Medido (O.5): la Lambda `agente-iam-avisos` esta `Active` (python3.12, arm64, 256 MB, 30 s, rol `AgenteIAM-Avisos` con `LimiteSistema` como
boundary); el disparador esta `Enabled` con lote 1, 0 reintentos y el filtro de los siete estados; `propuesta` no invoca a la Lambda;
un destinatario sin verificar da `MessageRejected`, que queda en `WARNING` con solo el dominio y sin reintento; y los correos
`rechazada_en_chequeos_previos` (20:01:02), `aprobada` (20:04:58, 0,5 s tras la aprobacion) y `aplicada` (20:05:03, con `Rol:` y
`Vence:`) salieron para `req-20261026-2e923bc5` y `req-20261026-122e10a7`, y Mateo confirmo los tres (`aprobada` y `aplicada` en la
carpeta de spam de Gmail: sin dominio propio con SPF y DKIM, §J). Sin medir: `MailFromDomainNotVerified` y un aviso con otro `ClientError` (throttling).

Que cambios en `agente_iam/` obligan a reempaquetar: ver la regla del bloque 1 (cada cambio se contrasta con las tres listas de
`scripts/empaquetar.sh`; `avisos.py` esta en `FUERA_DEL_RUNTIME`, `FUERA_DE_LA_APROBACION` y `LLEVA_EL_APLICADOR`).

## Fase 27: dominio propio para la pagina (TLS 1.2)

**Estado al 27-10-2026: todos los pasos hechos y medidos (26 y 27-10-2026, `docs/MEDICIONES.md` P.5 a P.7 y Q.1), con el flujo en el navegador incluido.** Diseno y razones en `docs/ADR-005-dominio-propio-y-tls.md`. Cada
escritura, con el si de Mateo. La zona de `mateo.solutions` esta en la cuenta de gestion y no se delega: los registros DNS los pone
Mateo en la consola; la pila web no crea ninguno y el rol de despliegue no gana permisos de ACM ni de Route 53.

1. **Mateo, consola de `agente-iam`, `us-east-1`:** ACM, solicitar un certificado publico para el nombre exacto
   `agente-iam.mateo.solutions` (sin comodin), con validacion DNS. Anota el nombre y el valor del CNAME de validacion y el ARN.
2. **Mateo, consola de la cuenta de gestion:** en la zona `mateo.solutions`, crear ese CNAME de validacion. Se queda para siempre:
   ACM lo usa para renovar. Esperar a que el certificado quede `ISSUED` (minutos).
3. **Operador:** change set de `agente-iam-web` con `DominioWeb` = `agente-iam.mateo.solutions`, `CertificadoArn` = el ARN del paso 1
   y `DominioCognito` en `UsePreviousValue`. Debe mostrar solo Modify de `Distribucion`, sin reemplazo. Medido el 27-10-2026: no hace
   falta ningun permiso de ACM en el rol de despliegue (P.6).
4. **Mateo, consola de gestion:** en la zona `mateo.solutions`, alias A y AAAA de `agente-iam` hacia la salida `DominioCloudFront` de
   la pila web. Desde otra cuenta la consola no lista la distribucion: se escribe su nombre de CloudFront, con el id de zona fijo
   de CloudFront (ADR-005, punto 2).
5. **Operador:** change set de `agente-iam-acceso` con `UrlRetornoWeb` = `https://agente-iam.mateo.solutions/` y lo demas en
   `UsePreviousValue`. Debe mostrar Modify de `ClienteWeb` sin reemplazo. Si dijera reemplazo, cambiaria el id del cliente y habria
   que tocar tambien el runtime y el proveedor OIDC: se para y se revisa.
   Medido: el cambio en Cognito tarda en regir (entre 43 y 74 s el 27-10-2026); probar el login antes de un minuto puede dar el
   resultado al reves.
6. **Medir** lo del punto 8 del ADR-005 (distribucion, `curl`, saludo TLS, preflight de Cognito y flujo en el navegador).

Los pasos 4 y 5 pueden ir en cualquier orden; hasta que esten los dos, el login sigue en la URL de CloudFront. Tras el paso 5 Cognito
rechaza la URL `*.cloudfront.net` como retorno: el login solo funciona en el dominio.

Vuelta atras: `UrlRetornoWeb` a la URL de CloudFront y `DominioWeb` y `CertificadoArn` vacios. El certificado se puede quedar.

Que medir para dar el pendiente de TLS por cerrado: ADR-005, punto 8.

## Fase 28: solicitud en texto, recurso comprobado y motivos

**Estado al 27-10-2026: pasos 1 a 6 desplegados y medidos (`docs/MEDICIONES.md` R.1 a R.11).** Codigo, plantillas y tests listos (`PLAN-CORRECCIONES.md`, Fase 28). Cada escritura lleva el si de Mateo. El rol de despliegue y el limite `AgenteIAM-LimiteSistema` son del administrador. Orden:

1. **SES con dominio propio, primero** (decision de Mateo del 27-10-2026). El administrador, con el si de Mateo, crea la identidad de
   dominio `agente-iam.mateo.solutions` en SES con Easy DKIM. Mateo crea en la zona de gestion los 3 CNAME de DKIM que SES entrega y un TXT
   `_dmarc.agente-iam.mateo.solutions` con `v=DMARC1; p=none`. Se espera a que la identidad quede verificada. Despues, change sets del
   operador de base y de runtime con `CorreoRemitente` = `avisos@agente-iam.mateo.solutions` y lo demas en `UsePreviousValue`. Medir que
   un aviso llega a la bandeja de entrada de Gmail (el del 27-10-2026 no llego, ni a spam: `docs/MEDICIONES.md` Q.2). Hecho el 27-10-2026:
   identidad verificada a las 04:17 UTC, remitente cambiado a las 04:19 UTC y primer aviso en la bandeja de entrada a las 04:23 UTC.
2. **Administrador:** change set de `infra/cfn/arranque.yaml` (el limite `AgenteIAM-LimiteSistema` gana `ComprobarQueElRecursoExiste`). Va
   antes que el rol del runtime: el limite tiene que permitir lo que el rol va a pedir.
3. **Paquetes** (Claude): `scripts/empaquetar.sh` para el runtime, el aplicador (lleva `avisos.py` y `motivos.py`) y la aprobacion (cambian
   `models.py` y `coherencia.py`). `existencia.py` y `motivos.py` quedan fuera de la Lambda de aprobacion y `existencia.py` fuera del
   zip del aplicador. El operador sube los zips.
4. **Operador:** change set de `infra/cfn/base.yaml` (el rol del runtime gana `ComprobarQueElRecursoExiste` y
   `ComprobarQueElRecursoExisteSinTipoDeRecurso`); despues el de `infra/cfn/runtime.yaml` con las claves nuevas del runtime y del
   aplicador y `UrlWebAvisos` = `https://agente-iam.mateo.solutions`; y la clave nueva de la Lambda de aprobacion. En cada change set
   se revisa que no haya reemplazos. Hecho el 27-10-2026: `base-fase-28` (22:58:18 UTC; pila `UPDATE_COMPLETE` 22:58:44) y
   `runtime-fase-28` (22:58:50; pila 22:59:16), ambos con solo Modify y sin reemplazos; el runtime quedo `READY` en la version 5
   (`docs/MEDICIONES.md` R.9).
5. **Pagina:** Claude corre `scripts/construir_web.py`; el administrador sube los ficheros de `local/web/` al bucket y se invalida la
   cache de CloudFront (como en el bloque 2 de la Fase 23). Hecho el 27-10-2026: cinco ficheros subidos con `ChecksumSHA256` y
   `Cache-Control: no-cache` entre las 23:00:48 y las 23:00:50 UTC, invalidacion `/*` `Completed` a las 23:01:12; lo servido es identico
   a `local/web/` (R.10).
6. **Medir** (Claude, en vivo; el resultado va a `docs/MEDICIONES.md`): un recurso inexistente se rechaza con `recurso_no_encontrado` sin
   gastar tokens del modelo; un ARN valido se acepta y uno de otro servicio, region o cuenta se rechaza; el motivo sale en la pagina y en
   el correo; las credenciales se piden por id de solicitud y el `AccessDenied` de STS se traduce; los registros anteriores, con
   `tipo_acceso`, se siguen aprobando y aplicando. Hecho el 27-10-2026 (R.11), salvo lo que R.11 deja sin medir: tres rechazos por
   `recurso_no_encontrado` con 0 tokens, una solicitud con ARN aprobada y aplicada, el motivo en la pagina y en el correo, y las credenciales
   por id de solicitud y el `AccessDenied` traducido.

Que cambios obligan a reempaquetar: la regla del bloque 1 de la Fase 23 (cada cambio de `agente_iam/` se contrasta con las tres listas de
`scripts/empaquetar.sh`).

## Fase 29: etiquetas Open Graph (vista previa en LinkedIn)

**Estado al 27-10-2026: subido y medido (`docs/MEDICIONES.md` S).** Sin cambio en las pilas: solo se subieron dos ficheros al bucket
`agente-iam-web-<cuenta>`.

Se subieron con `put_object` (el administrador, perfil `org-agente-iam`, con el si de Mateo): `index.html` (`text/html; charset=utf-8`,
`Cache-Control: no-cache`) con las etiquetas `description` y `og:` justo despues de `<title>`, y `vista-previa.png` (`image/png`,
`Cache-Control: no-cache`, 1200 x 627), seguidos de un `CreateInvalidation` de `/`, `/index.html` y `/vista-previa.png`.

Regla: si `web/` tiene cambios sin desplegar de otra fase, lo que se sube se construye desde `git show HEAD:web/...` mas el cambio propio, y
se comprueba con un diff contra `HEAD` que solo difieren las lineas propias. Asi se hizo aqui, en `local/web-og/`, porque `web/` tenia la
Fase 28 a medias.

Desde ahora cada subida de la pagina lleva tambien `vista-previa.png` con `Content-Type: image/png`; `scripts/construir_web.py` ya lo
copia a `local/web/`. La subida de la Fase 28 (paso 5) llevo las etiquetas, porque estan en `web/index.html` (R.10).

Pendiente: alargar `og:description` a 100 caracteres o mas (LinkedIn avisa de que las 86 actuales son pocas) en la proxima subida. La
subida de la Fase 28 (27-10-2026) salio sin alargarla, por decision de Mateo: sigue en 86 caracteres.

## Fase 30: la fila "Rol previsto"

**Estado al 27-10-2026: subido y medido (`docs/MEDICIONES.md` T).** Sin cambio en las pilas, el runtime ni el change set: solo se subieron
dos ficheros al bucket `agente-iam-web-<cuenta>`.

Se subieron con `put_object` (el administrador, perfil `org-agente-iam`, con el si de Mateo, con `ChecksumSHA256` y
`Cache-Control: no-cache`): `index.html` y `app.js`, seguidos de un `CreateInvalidation` de `/`, `/index.html` y `/app.js`. Como `web/` en
`HEAD` era lo publicado y el diff contra `HEAD` mostraba solo las lineas de esta fase, se subio desde `web/` directamente.

## Fase 31: prompt de s3

**Estado al 28-10-2026: desplegado (`docs/MEDICIONES.md` U.2).** Cambia solo `agente_iam/agente.py` (la regla 2c de `SYSTEM_PROMPT`), que
viaja unicamente en el zip del runtime: las Lambdas (aprobacion, aplicador y avisos) no llevan `agente.py`, asi que no se reempaquetan ni se
tocan.

Se despliega como cualquier cambio de codigo del runtime (ver "Actualizar el codigo de las Lambdas y del runtime"): `scripts/empaquetar.sh
runtime`, subida del zip por el operador (`agente-iam/runtime-<12 hex>.zip`, con los 12 primeros caracteres de `sha256sum
dist/agente-iam.zip`) y un change set de `agente-iam-runtime` con `ClaveCodigoRuntime` nueva, `RoleARN` de `AgenteIAM-Despliegue` y el resto
de parametros con `UsePreviousValue`, revisado y ejecutado con el si de Mateo. El change set trae un unico Modify de `Runtime`, sin
reemplazo, y el runtime pasa a la version siguiente.

## Fase 33: arreglos de la auditoria (sin desplegar)

**Estado al 18-11-2026: escritos en el codigo y probados en local (`docs/MEDICIONES.md` W.6); nada esta desplegado.** En la cuenta sigue el
codigo anterior: avisan siete estados, la Lambda de aprobacion acepta `autoaprobacion_demo` y las Lambdas admiten el modo
`principal_existente`. Todos los pasos de abajo estan pendientes. Los hace el operador, con el si de Mateo a cada paso (ver "Actualizar el
codigo de las Lambdas y del runtime").

1. Pendiente (operador): empaquetar y subir el zip de aprobacion, que lleva `aprobar.py` (`scripts/empaquetar.sh`; clave
   `agente-iam/aprobacion-<12 hex>.zip`).
2. Pendiente (operador): empaquetar y subir el zip del aplicador, que es tambien el de avisos y lleva `aplicador.py`, `avisos.py` y
   `aprobar.py` (clave `agente-iam/aplicador-<12 hex>.zip`). El zip del runtime no lleva esos modulos, pero tambien hay que
   reempaquetarlo y desplegarlo: el 19-11-2026 UTC `constraints.txt` subio OpenTelemetry (1.45.2 y 0.66b2) por un aviso de pip-audit, y los
   tres zips lo llevan con `strands-agents`. Antes, una corrida del agente contra Bedrock con las versiones nuevas (sin medir).
3. Pendiente (operador): change set de la pila base (`agente-iam-base`) con `ClaveCodigoAprobacion` nueva y el resto de parametros con
   `UsePreviousValue`; revisarlo y ejecutarlo con el si de Mateo.
4. Pendiente (operador): change set de la pila del runtime (`agente-iam-runtime`) con `ClaveCodigoAplicador` nueva y el filtro de cuatro
   estados de `DisparadorAvisos` (`aprobada`, `rechazada_por_aprobador`, `aplicada` y `bloqueada_al_aplicar`); `RoleARN` de
   `AgenteIAM-Despliegue`, el resto de parametros con `UsePreviousValue`; revisarlo y ejecutarlo con el si de Mateo.
5. Pendiente (operador y Claude): medir en la cuenta, despues de desplegar. Una solicitud rechazada en chequeos previos no manda correo; una
   aprobada si. La Lambda de aprobacion responde 409 a `autoaprobacion_demo` y al aprobar una fila que no es del modo rol por persona.

## Antes de desplegar el runtime

- **Bedrock**: el runtime usa el perfil de inferencia `us.` (`MODEL_ID`), lo unico que
  la SCP del proyecto deja pasar. Requisito cumplido el 23-10-2026 (MEDICIONES C.3,
  medido con el administrador; con los roles reales, no medido).
- **Empaquetar**: `scripts/empaquetar.sh` corre los tests unitarios y de seguridad (si
  fallan, no hay paquete), descarga el **catalogo de acciones recien**, en una carpeta
  vacia y sin copiar la cache local, instala las dependencias para **aarch64**
  (`--only-binary`, con `constraints.txt`) y deja `dist/agente-iam.zip`. El zip **no
  lleva** `aprobar.py`, `aplicador.py`, `cli.py` ni `huella.py` (el runtime no los
  importa) y el script falla si los lleva; tampoco `__pycache__`. Comprueba los
  limites (250 MB comprimido, 750 plano) y deja las versiones y huellas del catalogo en
  `VERSIONES.txt`. Camino de zip con runtime gestionado de Python, sin Docker ni ECR.
  La Lambda del aplicador necesita `aplicador.py`, `aprobar.py` y `huella.py`, asi que este
  zip no le sirve. Con `aprobacion` construye el zip de la Lambda de aprobacion (limite
  250 MB plano): lleva `aprobar.py` y `huella.py` y deja fuera el cliente, el aplicador, el
  CLI, el servidor y el agente. Con `aplicador` (25-10-2026, `requirements-aplicador.txt`)
  construye `dist/agente-iam-aplicador.zip` con `aplicador.py`, `aprobar.py` y `huella.py` y
  deja fuera el cliente, el CLI, el servidor, el orquestador y el agente; imprime la clave
  `agente-iam/aplicador-<12 hex>.zip`. En los tres casos el script falla si falta o sobra algo.

## Que mirar en los roles de la pila base

- **No son el rol del Analista**: a ese lo asume un humano un minuto; a estos los
  sostiene un servicio de forma permanente. Lo que lo hace aceptable es el `Deny`
  explicito, no la confianza. Los roles del sistema llevan `AgenteIAM-LimiteSistema`
  como limite (no el techo, que es de los beneficiarios).
- **Confused deputy**: la confianza del runtime lleva `aws:SourceAccount` y
  `aws:SourceArn` (con comodin de recurso: el ARN del runtime no existe al crear el
  rol). La del aplicador lleva `aws:SourceAccount` solo, porque el mapeo de eventos de
  Lambda no aporta `aws:SourceArn` (medido el 25-10-2026); dentro de la cuenta solo el rol
  de despliegue puede pasar roles `AgenteIAM-*` a Lambda.
- **Menos permisos que el Analista**: el runtime solo `access-analyzer:ValidatePolicy`
  (`CheckNoNewAccess` es del aplicador y es la unica llamada de pago, acotada a actos
  humanos; el rol del aplicador tambien puede `sqs:SendMessage` solo a su cola de fallos); DynamoDB solo `UpdateItem` con `dynamodb:Attributes` = `id`, `documento`,
  `estado` (runtime) y `id`, `estado`, `aplicacion` (aplicador), sin `PutItem`.
  Ya esta escrito asi en `base.yaml` y lo vigila `tests/seguridad/test_pila_base.py`.
  Medido el 24-10-2026 con llamadas reales del permission set del aprobador, con la misma
  forma de condicion: `dynamodb:Attributes` frena un `UpdateItem` real y cuenta tambien los
  atributos de la condicion (MEDICIONES F.6). Con el rol del runtime hay escritura real
  (`req-020`, `req-021`, 25-10-2026, K.2); con los roles de la Lambda de aprobacion y de la del aplicador tambien
  (`req-022`, 25-10-2026, L.2).
- **`AgenteIAM-Aprobacion`** (el rol de la Lambda de aprobacion): limite `LimiteSistema`,
  confianza con `aws:SourceArn` de la funcion exacta (no `agente-iam-*`), `UpdateItem` solo
  de `id`, `estado`, `aprobacion` y `rechazo`, y Deny de `PutItem`, `DeleteItem` y
  `BatchWriteItem`. Es el unico que escribe la decision.
- **Deny de `DeleteItem`, `BatchWriteItem`, `DeleteTable` y `UpdateTable`**, la leccion de
  `iam:UntagPolicy`: a quien puede escribir su trazabilidad hay que quitarle la de
  borrarla. Se verifica con el metodo del `AccessDenied` (CONTEXTO §5): el mensaje
  debe decir "explicit deny", no "no identity-based policy allows".

## Detalles de AgentCore que muerden

- El nombre del runtime solo admite `[a-zA-Z][a-zA-Z0-9_]{0,47}`: guiones bajos, no
  guiones (`agente_iam_analista`).
- `entryPoint: ["main.py"]`, no `agente_iam/servidor.py`: es argv, y Python pondria la
  carpeta del script en `sys.path[0]` y `from agente_iam import ...` no resolveria.
- `ALMACEN=dynamodb` no es opcional: sin ella el servidor se niega a arrancar, a
  proposito (con disco el registro moriria con el microVM, sin un error).
- `networkMode: PUBLIC` es la salida hacia Bedrock, IAM y DynamoDB; la entrada la
  decide el autorizador (JWT en el diseno: sin `Authorization` valido, 401). El endpoint
  `DEFAULT` no se puede invocar hasta `READY`.
- Con JWT no se invoca con la CLI ni con el SDK (`docs/PRUEBAS-AGENTCORE.md`, §1); el
  id de sesion tiene minimo 33 caracteres.
- `update-agent-runtime` es un PUT completo (repetir rol, artefacto y red); cada
  version es inmutable y `DEFAULT` pasa a apuntarla sin parada.

## Que no se despliega en el runtime, y por que

**`aprobar` no puede estar en el runtime.** Aprobar es un acto humano: bajo el rol del
runtime el aprobador seria el rol y la separacion de funciones se evaporaria
comparando el rol consigo mismo. Es el peor modo de fallo: el que parece que
funciono. La aprobacion esta en la Lambda `agente-iam-aprobacion` de la pila base, que identifica a
quien firma la peticion (ADR-003, desplegada el 25-10-2026 UTC).

**El `aplicador` tampoco en el mismo proceso que lee texto no confiable**: tiene
escritura en IAM, y juntarlos convierte una inyeccion de prompt en una escalada de
privilegios. Es una Lambda aparte (`agente-iam-aplicador`, desde el 25-10-2026), disparada por
Streams con `estado = aprobada`, a la que no llega ninguna persona.

**Con SigV4 el codigo no sabe quien invoco**: la cabecera de usuario de AgentCore no la
verifica el servicio. Por eso el runtime usa JWT de Cognito (`docs/ADR-001-agentcore-identidad.md`)
y `ejecutado_por` sale de los claims ya validados (desde el 25-10-2026).

Limitaciones vigentes y proximos pasos: CONTEXTO §10 y §11.
