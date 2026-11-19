# ADR-003: aprobacion registrada en el servidor y separacion por persona

- **Estado:** aceptado por Mateo el 24-10-2026 (propuesto el mismo dia); implementado el 24-10-2026 y desplegado y
  medido el 25-10-2026 (UTC), Fase 19.
- **Fase:** 18, tarea 4 (`PLAN-CORRECCIONES.md`; plan en
  `docs/superpowers/plans/2026-10-24-techo-decisiones-y-pila-base.md`); codigo, despliegue y mediciones en la Fase 19
  (plan `docs/superpowers/plans/2026-10-24-aprobacion-en-servidor-y-persona.md`).
- **Medido contra:** la cuenta `agente-iam`, con llamadas reales como `aprobador.demo` (`docs/MEDICIONES.md` F.7, M1 a
  M4, 25-10-2026 UTC). Lo que falta medir esta abajo.
- **Sustituye a:** la pieza pendiente de S1 y S4 (Fase 17) y la pregunta "donde vive la aprobacion cuando entre el
  runtime" (`CONTEXTO.md` §10). Concreta la separacion de `docs/ESPECIFICACION-agentcore.md` §4.

## Contexto

Dos huecos, los dos leidos en el codigo el 24-10-2026 (mapa del flujo: `local/mapas/solicitud-por-la-tabla.md`):

1. **La aprobacion se puede fabricar.** El permission set `AgenteIAM-Aprobador` tiene `dynamodb:UpdateItem` sobre los
   atributos `aprobacion` y `rechazo`. Con la CLI puede escribir el bloque sin pasar por `aprobar.py`. La huella es un
   hash sin secreto: la calcula cualquiera. El aplicador repite `CheckNoNewAccess`, el techo y el riesgo (S4), pero
   la separacion de funciones no la puede repetir: se fia del `"resultado": "cumplido"` escrito en el bloque.
2. **La separacion compara el rol, no la persona.** Para una sesion SSO, `aprobar._separacion` usa el `arn_canonico`
   del rol del permission set, el mismo para todo el grupo de aprobadores. La persona solo esta en el nombre de
   sesion. Ademas compara aprobador con beneficiario, y el beneficiario es un rol de aplicacion: la comparacion que
   importa es aprobador frente a **solicitante**.

## Decision

### A. La aprobacion la registra el servidor (A2)

- Una Lambda de aprobacion con URL de funcion y `AuthType: AWS_IAM`. Su rol, `AgenteIAM-Aprobacion` (con
  `AgenteIAM-LimiteSistema` como boundary), es el **unico** principal con `UpdateItem` sobre `aprobacion` y
  `rechazo` (`dynamodb:Attributes` = `id`, `estado`, `aprobacion`, `rechazo`). El rol va en la pila base, junto a los
  otros duenos de atributos, cuando exista su codigo.
- El permission set `AgenteIAM-Aprobador` conserva `GetItem` (para mostrar la propuesta y su huella) y **pierde
  `UpdateItem`**. Gana `lambda:InvokeFunctionUrl` y `lambda:InvokeFunction` sobre esa funcion, con
  `lambda:FunctionUrlAuthType = AWS_IAM` y `lambda:InvokedViaFunctionUrl = true` (las dos acciones las exige una URL
  `AWS_IAM`: guia de Lambda, leida el 24-10-2026).
- El flujo para la persona no cambia: `aprobar <id>` lee y muestra la huella; `aprobar <id> --huella H` (o
  `--rechazar "motivo"`) firma con SigV4 una peticion a la URL con el id y la huella. La Lambda identifica a quien
  firmo **desde la peticion**, lee la fila, corre los mismos controles que hoy corre `aprobar` (compuerta de estado,
  identidad, separacion, revalidacion, `CheckNoNewAccess` contra el techo, huella igual a `H`) y escribe con
  `almacen.guardar_decision`.
- El aplicador no cambia: su confianza en el bloque `aprobacion` pasa a descansar en IAM (solo la Lambda lo escribe).
- Solo decide el permission set `AgenteIAM-Aprobador` (decision 2 del plan, 24-10-2026): el servidor exige que el rol
  que firma sea `AWSReservedSSO_AgenteIAM-Aprobador_*` con el path de Identity Center y que la persona sea
  determinable, tambien para rechazar y sin que la puerta de autoaprobacion lo salte. Un administrador con permiso de
  invocar recibe 409. El backend de disco (desarrollo) no exige nada de esto.

**Por que no un MAC con KMS (A1).** Con `kms:GenerateMac` en el permission set del aprobador, el aprobador firma un
bloque inventado igual de facil que hoy lo escribe: un MAC solo anade algo si quien firma no es quien escribe. En A2
eso ya lo garantiza IAM, sin clave que gestionar.

**Por que no contradice "aprobar no puede ir en el runtime"** (`docs/DESPLIEGUE.md`). Esa regla dice que bajo el rol
del runtime el aprobador seria el rol. La Lambda no usa su propio rol como identidad del aprobador: usa la de quien
firmo la peticion, que AWS verifica antes de invocarla. Y no es el runtime: no habla con el modelo ni lee texto
libre del solicitante como instruccion.

### B. La separacion compara el nombre de usuario de Identity Center (B2)

- **Aprobador:** el nombre de sesion del ARN de quien firmo, solo si el rol es de un permission set
  (`/aws-reserved/sso.amazonaws.com/`, comprobado con `iam:GetRole` y el `RoleId` como prefijo del `UserId`, el
  patron que ya usa `identificar_aprobador`). Ese nombre lo pone Identity Center, no la persona. Un usuario IAM o
  cualquier otro rol: persona no determinable.
- **Solicitante:** el claim `username` del JWT ya validado por el runtime, quitando exactamente el prefijo del
  proveedor de Cognito (`IdentityCenter_`). El runtime lo graba en el `documento`. Por la CLI de hoy (rol del
  Analista) no hay persona verificada: se graba como no determinable.
- **La comparacion:** aprobador frente a solicitante, y se mantiene aprobador frente a beneficiario. Se comparan tras
  `casefold()`: tomar por la misma persona a dos nombres que solo difieren en mayusculas bloquea una aprobacion
  legitima de forma visible; tomarlos por distintos podria dejar pasar una autoaprobacion.
- **La duda bloquea**, como hoy: si una de las dos personas no es determinable, la separacion no se cumple. La unica
  salida es la puerta explicita que ya existe (`SALTADO`, grabada, y que el aplicador solo acepta con
  `AGENTE_IAM_PERMITIR_AUTOAPROBACION=si`).

**Por que no el `UserId` de Identity Center (B3).** Es estable, pero ni el ARN de la sesion ni el token lo llevan:
habria que buscarlo en el identity store de la cuenta de gestion, una lectura entre cuentas para cada aprobacion.
Queda como mejora si un dia se renombran usuarios. **Por que no el rol (B1, hoy):** todo el grupo es el mismo rol.

## Consecuencias

- El codigo de `aprobar` se parte en dos: cliente (leer, mostrar, firmar la peticion) y servidor (controles y
  escritura). La Lambda necesita su propio paquete, con `aprobar.py` y `huella.py`; el zip del runtime sigue sin
  llevarlos.
- `infra/cfn/identidades.yaml` cambia (permission set sin `UpdateItem`, con la invocacion de la URL), en la cuenta
  de gestion, con un Deny explicito de `PutItem`, `UpdateItem`, `DeleteItem`, `BatchWriteItem`, `PartiQLInsert`, `PartiQLUpdate`
  y `PartiQLDelete` sobre la tabla (desplegado y medido con llamadas reales el 25-10-2026 UTC: F.7, M4).
- El intake graba `solicitante` desde el 24-10-2026, y desde el 25-10-2026 el runtime pone la persona desde el claim
  `username` del JWT (pila `acceso`, `docs/MEDICIONES.md` K.2); sin JWT (CLI) el solicitante no es determinable y
  toda aprobacion real bloquea salvo `SALTADO`.
- El backend de disco (desarrollo) sigue como hoy: sin servidor, sin esta garantia, y se dice.
- Coste: invocaciones de Lambda de un acto humano; despreciable.

## Lo que no cierra

- Un administrador de la cuenta sigue pudiendo escribir cualquier atributo. Este ADR cierra el camino del aprobador,
  no el del administrador; lo que queda como rastro son PITR y Streams de la tabla.
- La Lambda revalida contra el catalogo de AWS: necesita salida a internet (sin VPC, como el runtime).

## Pendiente de medir

1. Medido (F.7, M1, 25-10-2026 UTC): el evento trae `requestContext.authorizer.iam` con `userArn` =
   `arn:aws:sts::<cuenta>:assumed-role/AWSReservedSSO_AgenteIAM-Aprobador_<sufijo>/<nombre de sesion>`, `userId` =
   `<RoleId>:<nombre de sesion>` y `accountId`; el log de la funcion lleva los mismos valores.
2. Que el nombre de sesion de un permission set y el `username` del token (sin prefijo) coincidan para la misma
   persona, letra a letra. Medido para `aprobador.demo`: token `IdentityCenter_aprobador.demo` (Prueba B,
   23-10-2026) y nombre de sesion `aprobador.demo` (`GetCallerIdentity` con `AgenteIAM-Aprobador`, 24-10-2026;
   `docs/MEDICIONES.md` F.6). La forma con correo esta medida en el
   nombre de sesion de Mateo (F.7), que no es aprobador, y en el claim `username` de su token
   (`IdentityCenter_<correo>`, 25-10-2026, `docs/MEDICIONES.md` K.2); falta una con mayusculas y un
   aprobador con correo.
3. Si Identity Center permite renombrar un usuario (afecta a B2: hoy es supuesto que no se renombran).
4. Medido el 25-10-2026 (21:01 UTC): la separacion con dos personas reales dio `cumplido`. En `req-021` el solicitante
   grabado por el runtime era la persona de Mateo y firmo `aprobador.demo`; `aprobar()` acumula los bloqueos y sigue, y
   la respuesta `409` llevaba un unico motivo, el de `CheckNoNewAccess` (K.3): la separacion, que va antes, no bloqueo.
   La escritura de `aprobacion` por la Lambda con dos personas distintas (M5) se midio el 25-10-2026 con `req-022`
   (`docs/MEDICIONES.md` L.2). Lo que sigue sin medir es el bloqueo con la MISMA persona a los dos lados (hace falta
   que `aprobador.demo` pida por el runtime: hoy la aplicacion SAML solo esta asignada al grupo de solicitantes).

El codigo de A2 y B2 esta implementado y desplegado (Fase 19); la pila base y `dynamodb:Attributes` ya estaban (F.5, F.6).
