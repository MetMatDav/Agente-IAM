# Diseno: formulario web, rol por persona con caducidad y aviso por correo (Fase 23)

Fecha: 26-10-2026 (UTC; noche del 25-10 para Mateo). Estado: PROPUESTO, Mateo lo lee. Decisiones de Mateo marcadas
como suyas; lo demas son llamadas de Claude, revisables. Lo que diga "medido" tiene fecha y seccion de
`docs/MEDICIONES.md`; lo que diga "sin medir" se mide antes de construir sobre ello.

## 1. Intencion y por que

Hoy la unica forma de pedir un permiso es la linea de comandos (`scripts/solicitar.py`), el beneficiario es un rol de
aplicacion que ya existe (`app-finanzas-demo`) y el solicitante no recibe aviso de la decision. Mateo quiere (decision
del 25-10-2026):

- que cualquier persona de la empresa pueda pedir desde una pagina web, porque no todo el mundo maneja una terminal y
  porque la demostracion del proyecto lo necesita;
- que el beneficiario sea la propia persona: el permiso se materializa en un rol creado para ella, que solo ella
  puede asumir, con una duracion que ella elige entre 1 y 12 horas;
- que la persona reciba un correo con la decision, se apruebe o se niegue.

El diseno debe poder escalar a una empresa aunque la demostracion la hagan dos personas. En una empresa real el
formulario puede ser el sistema de tickets; aqui es una pagina estatica.

## 2. Objetivos, no objetivos y anti objetivos

Objetivos:
1. Una persona entra con Identity Center desde la pagina, rellena el formulario y envia; el runtime la procesa igual
   que hoy y queda en `propuesta`, `redundante_no_requiere_cambio`, `rechazada_en_chequeos_previos` o
   `requiere_revision_humana`.
2. Solicitante y beneficiario son la misma persona, y lo garantiza el token (Mateo). La solicitud ya no lleva un ARN
   declarado.
3. Tras la aprobacion, el aplicador crea un rol para la persona con la politica propuesta, el techo como boundary,
   confianza solo para ella y vencimiento a la hora elegida (1 a 12 h). La persona lo asume con su token de
   identidad de Cognito (`AssumeRoleWithWebIdentity`, medido en `docs/MEDICIONES.md` N).
4. La redundancia se comprueba contra todo lo que la persona ya puede hacer en ese momento, no solo contra lo que el
   sistema le dio antes (Mateo).
5. La persona recibe un correo con el id de la solicitud y el estado final, en la direccion que escribio en el
   formulario (Mateo); el correo no lleva la politica ni la justificacion (Claude, aceptado por Mateo).

No objetivos (esta fase):
- Aprobar desde la web. El aprobador sigue en la terminal con `aprobar_cliente` firmado con SSO (ADR-003 no cambia).
- Borrar los roles vencidos. Quedan inertes; una fase posterior los borra al vencer o a la semana (Mateo).
- Politicas sobre usuarios IAM o permisos de hasta 7 dias (Mateo: mas adelante, hoy no se puede por como estan las
  cuentas).
- Notificacion en la consola de AWS (AWS User Notifications): es por cuenta, no por persona; se deja como extra.
- Salir del modo inicial de SES: en la demo solo reciben direcciones verificadas.

Anti objetivos (seria un fracaso aunque funcione):
- Que el formulario, o cualquier cliente, pueda decir quien es el beneficiario: solo el token.
- Que un rol creado por el sistema pueda asumirlo otra persona, o pueda asumirse despues de vencer.
- Que el aplicador pueda crear roles fuera de su ruta, sin el techo como boundary, o con una confianza que no sea la
  de la persona.
- Que una direccion de correo equivocada reciba el contenido de una solicitud ajena.
- Que la web guarde el token en algo que no sea la memoria de la pagina, o que lo imprima.

## 3. Restricciones

- Reglas del repositorio (CLAUDE.md): nada se escribe en la cuenta sin el si de Mateo; cada arreglo lleva su test; lo
  que toca AWS se mide contra la cuenta; la documentacion se actualiza en el mismo trabajo; nada de la cuenta real ni
  correos en lo versionado.
- Identity Center sin usuarios IAM de personas (ADR-001, ADR-002): la persona es su nombre de usuario de Identity
  Center, que llega como claim `username` del JWT (sin el prefijo `IdentityCenter_`) y como nombre de sesion SSO.
- El techo (`AgenteIAM-Techo` v3) y `AgenteIAM-LimiteSistema` siguen siendo los limites: el techo acota lo que la
  persona podra hacer; el limite del sistema acota a los roles del sistema.
- SCP de regiones: todo en `us-east-1` salvo la inferencia `us.`.
- Cognito exige HTTPS en la URL de retorno (salvo `localhost`): la pagina va detras de CloudFront.
- Medido el 26-10-2026 01:40 UTC (curl, sin token): el endpoint de AgentCore responde al preflight con
  `access-control-allow-origin: *`, `access-control-allow-headers: authorization,content-type`,
  `access-control-allow-methods: POST` y `access-control-max-age: 172800`, y la respuesta real (403 con token falso)
  tambien lleva `access-control-allow-origin: *`. El navegador puede llamar directo al runtime: no hace falta API
  intermedia. La URL de la Lambda de aprobacion no responde a CORS (403 al OPTIONS); da igual porque la aprobacion
  no va por la web.
- Hoy el grupo `agente-iam-solicitantes` solo esta asignado a la aplicacion SAML; no tiene ningun permission set en
  `agente-iam` (leido en `infra/cfn/identidades.yaml`, 26-10-2026). Con el canje por token (5.2) no hace falta ninguno.

## 4. Lo que ya existe y se reutiliza

Pool de Cognito `agente-iam-acceso` con el proveedor SAML de Identity Center y el cliente PKCE `agente-iam-cli`;
runtime `agente_iam_analista` con autorizador JWT que ya graba `solicitante.persona` desde el claim `username`;
Lambda de aprobacion con separacion de funciones por persona; Lambda del aplicador disparada por el stream; tabla con
un atributo por actor; techo v3; trail de datos; cola, alarma y tema SNS. Todo medido de punta a punta el 25-10-2026
(`docs/MEDICIONES.md` L y M).

## 5. Las decisiones de diseno

### 5.1 El contrato de la solicitud (cambia)

- Desaparece `principal_arn_declarado`. El beneficiario es la persona del token; el servidor lo pone, nunca el cliente.
  Si el JSON trae ese campo, se rechaza por forma (es un intento de elegir beneficiario).
- Campos cerrados, como hoy: `servicio`, `recurso`, `tipo_acceso` (`lectura`, `escritura`, `administracion`), `region`.
- Campo nuevo `horas`: entero de 1 a 12 (Mateo). Es la vida del permiso y la sesion maxima del rol.
- Campo nuevo `correo_aviso`: direccion a la que avisar; forma validada; se guarda en el registro; dato no confiable
  (puede no ser de la persona). Solo se usa para avisar.
- `justificacion`: el unico texto libre, como hoy, con los mismos limites.
- `solicitud_id`: lo forma el servidor (cierra el pendiente "solicitud_id generado por el sistema" de CONTEXTO §11):
  `req-<fecha AAAAMMDD>-<8 hex>`, donde los 8 hex salen de una clave de un solo uso `clave_envio` (UUID) que el cliente
  genera al pulsar enviar y repite si reintenta. Asi un doble clic o un corte de red no crean dos solicitudes: la
  segunda llegada devuelve `registro_existente` con el mismo id. El cliente no elige ids; si manda `solicitud_id`, se
  rechaza por forma. Llamada de Claude (pregunta 9 del revisor).
- Tope por persona (llamada de Claude, pregunta 6 del revisor): un chequeo previo rechaza la solicitud si la persona ya
  tiene 5 roles de persona vigentes (la misma lectura que usa la redundancia, 5.4). Protege las cuotas de IAM (1000
  roles, 1500 politicas gestionadas) y el gasto en el modelo hasta que exista el borrado automatico. El numero es
  configuracion (`config.py`).
- La respuesta del servidor anade el `solicitud_id` generado y el nombre del rol que se crearia.

### 5.2 El rol por persona: la persona lo asume con su token de Cognito (MEDIDO, `docs/MEDICIONES.md` N)

Decision de Mateo del 26-10-2026 ("me gusta mucho mas este camino"), medida ese dia: la persona no asume el rol desde
su sesion de Identity Center (eso seria encadenamiento de roles, limitado a 1 h por CLI y API) sino canjeando su
token de identidad de Cognito con `AssumeRoleWithWebIdentity`. Es el primer salto desde una identidad web: sesiones de
hasta 12 h, medidas.

Nombre: `agente-iam-persona-<usuario>-<solicitud_id>`, ruta `/agente-iam/personas/`. El nombre de usuario va
normalizado como en ADR-003 y recortado para caber en 64 caracteres. Etiquetas: `agente-iam-solicitud`,
`agente-iam-persona` (usuario), `agente-iam-sub`, `agente-iam-vence` (ISO 8601 UTC).

Lo que lleva:
- `PermissionsBoundary` = `AgenteIAM-Techo`. Medido (N.2, 5): la sesion lista el bucket de demo y no toca el bucket
  del sistema.
- La politica propuesta, creada como politica gestionada con el nombre determinista de hoy y adjunta al rol. El codigo
  (no el modelo) anade a cada `Allow` `"DateLessThan": {"aws:CurrentTime": "<vence>"}`: medido (N.2, 7) que corta el
  permiso a la hora exacta aunque la sesion de 12 h siga viva. La simulacion aporta `aws:CurrentTime` como contexto.
- `MaxSessionDuration` = `horas` en segundos: `horas` es a la vez la vida del permiso y la sesion maxima (Mateo).
- Confianza, la forma medida (N.1):

```json
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::<cuenta>:oidc-provider/cognito-idp.us-east-1.amazonaws.com/<pool>"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "cognito-idp.us-east-1.amazonaws.com/<pool>:aud": "<cliente>",
      "cognito-idp.us-east-1.amazonaws.com/<pool>:sub": "<sub de la persona>"
    },
    "DateLessThan": {"aws:CurrentTime": "<vence>"}
  }
}
```

  Medido (N.2): solo el `sub` de la persona entra (3); el token de acceso no sirve, hace falta el de identidad con
  `aud` (2); pasado `vence`, nadie lo asume (8). El `sub` lo graba el runtime en cada solicitud desde el JWT
  (`ejecutado_por.sub`): el aplicador lo lee del registro, nunca del formulario.
- `vence` se calcula al APLICAR: hora de aplicacion mas `horas`. El aprobador ve `horas` y el `vence` que resultaria
  si aplicara en ese momento. Una `propuesta` sin aprobar no caduca en esta fase (llamada de Claude).
- Dos clientes (`aud`): la confianza admite el `aud` del cliente con el que la persona entro; el aplicador escribe el
  que trae el registro (`ejecutado_por` guarda `client_id`; si no, el de la CLI). Llamada de Claude: una lista con
  los dos clientes en `StringEquals` es valida en IAM y evita depender del origen.

Como lo usa la persona:
- Desde la pagina: boton "Obtener credenciales" que llama a STS desde el navegador con el token de identidad
  (STS admite CORS; se mide en el bloque 2) y muestra las tres variables de entorno para copiar, o un enlace de
  consola por el endpoint de federacion (extra, sin medir).
- Desde la terminal: `scripts/solicitar.py asumir <solicitud_id>` hace `AssumeRoleWithWebIdentity` con el
  `id_token` guardado y escribe un perfil temporal o imprime las variables. El `id_token` dura 1 h: si caduco, el
  comando pide volver a entrar (sin medir: renovar con el refresh token).

Pieza nueva de la pila `acceso` (operador): el proveedor OIDC del pool en IAM (`AWS::IAM::OIDCProvider`, URL del
pool, `ClientIdList` con los dos clientes). La sonda lo creo y lo borro (N.1); la pila lo crea de forma definitiva.

### 5.3 Ya no hace falta un permission set de solicitantes

Con el canje por token, la persona no necesita acceso SSO a la cuenta `agente-iam`: su credencial es el token. El
grupo `agente-iam-solicitantes` sigue asignado solo a la aplicacion SAML, y eso basta: quien tiene token esta en el
grupo (llamada de Claude; se comprueba en el bloque 1 que un usuario fuera del grupo no obtiene token). Desaparecen de
este diseno el permission set `AgenteIAM-Solicitante` y la sesion SSO en la cuenta.

### 5.4 Redundancia: contra todo lo que la persona ya puede hacer (Mateo)

La persona no es un principal de IAM; lo que "ya puede hacer" en `agente-iam` es la union de los roles que puede
asumir: los roles de sus permission sets en esta cuenta y los roles de persona vigentes que el sistema le creo. El
chequeo simula la politica propuesta (`SimulatePrincipalPolicy`, como hoy) contra cada uno de esos roles y declara
redundante lo que ALGUNO de ellos ya permite: si la persona puede hacerlo por algun camino, ya lo tiene.

Decision del 26-10-2026 (Mateo: lo que menos tiempo lleve): en esta fase la lista son los roles de persona vigentes
(punto 1); la lectura cruzada de asignaciones en gestion queda como siguiente paso documentado, porque para
`solicitante.demo`, que no tiene permission sets en `agente-iam`, da el mismo resultado y evita una pila y un rol mas.
Como se obtiene la lista:
1. Roles de persona vigentes: `ListRoles` con `PathPrefix=/agente-iam/personas/` filtrados por la etiqueta
   `agente-iam-persona` = usuario y `agente-iam-vence` en el futuro. En la cuenta, lo lee el rol del runtime.
2. Roles de sus permission sets: hace falta saber que permission sets tiene la persona en `agente-iam`. Eso vive en
   Identity Center (cuenta de gestion): `identitystore:GetUserId` + `sso-admin:ListAccountAssignmentsForPrincipal`.
   Propuesta: un rol de solo lectura en gestion (`AgenteIAM-LecturaAsignaciones`, pila `identidades`) que el rol del
   runtime asume con `sts:AssumeRole` y `aws:SourceAccount`; devuelve los ARN de permission set, y de ahi el nombre
   del rol `AWSReservedSSO_<nombre>_<sufijo>` en `agente-iam` (lectura con `ListRoles` por prefijo). Es la "lectura
   simple" de Mateo llevada a lo que AWS permite: dos llamadas de lectura en gestion y una en la cuenta.
   En esta fase: solo (1). La lectura cruzada (M-e) se pospone.
3. Si la lectura de asignaciones falla (red, permiso), la redundancia se declara "no comprobada" y la solicitud sigue
   como acceso nuevo: la duda cae del lado de conceder con aprobacion, nunca de negar en silencio (misma asimetria que
   hoy).

### 5.5 Lo que cambia en el circuito actual

- **Dos modos, uno por camino (decision de Mateo del 26-10-2026: lo que menos tiempo y complejidad lleve).** El
  modo nuevo, rol por persona, es el UNICO del servidor (runtime con JWT): ahi `principal_arn_declarado` se rechaza por
  forma y `horas` es obligatorio. El modo actual, adjuntar a un principal que existe con el techo, sigue solo en el
  CLI de desarrollo sobre disco (`cli.py`, `ALMACEN=disco`), que no tiene token: asi no se reescriben los tests, los
  ejemplos ni las mediciones M.4 y M.5, y el corpus de `ejemplos/` sigue sirviendo para desarrollo. Un test de
  seguridad comprueba que el servidor rechaza el ARN declarado y que el CLI no acepta `horas` sin persona. El rol
  `app-finanzas-demo` y su pila se quedan como estan (el bucket es el recurso de la demo). ADR-004 lo deja escrito:
  un modo en produccion, dos en el repositorio, y por que.
- `chequeos_previos` en el modo nuevo: no verifica un ARN declarado ni su boundary. Verifica que el token trae
  persona y `sub` (si no, rechazo), que `horas` esta en rango y el tope de roles vigentes. El resto (servicio permitido, lista negra, recurso del sistema, EC2 solo lectura) igual.
- `identidad_verificada` pasa a describir a la persona (usuario, `sub`) y al rol que se creara (nombre y ARN
  previstos), no a un principal existente. El prompt del modelo recibe el ARN previsto del rol como `principal_arn`
  para que la politica no lo nombre a el (D4/riesgo de politica sobre si mismo sigue vigente).
- `coherencia` (chequeos posteriores): sin cambios de fondo; S5 igual. Se anade un chequeo: la politica no concede
  `sts:AssumeRole` ni nada sobre `/agente-iam/personas/` (que un rol de persona no pueda saltar a otro).
- Aprobacion (ADR-003): sin cambios. La separacion de funciones compara aprobador y solicitante como hoy; el
  beneficiario ya es el solicitante por construccion, asi que la comparacion queda en dos personas.
- Aplicador: pasa de "adjuntar a un rol que existe" a "crear el rol y adjuntar". Pre-vuelo: el rol no existe (o existe
  con la misma etiqueta de solicitud: idempotencia, se reanuda), la politica no existe o es identica, la hora de
  vencimiento es futura. `CheckNoNewAccess` contra el techo igual que hoy. Orden de escritura: `CreatePolicy`,
  `CreateRole` (con boundary y confianza), `AttachRolePolicy`, `TagRole`; si algo falla a mitad, el reintento converge
  por nombres deterministas (igual que hoy con la politica). El bloque `aplicacion` anade `rol_arn` y `vence`.
- Permisos del aplicador (`base.yaml`, dentro de `LimiteSistema`): `iam:CreateRole`, `iam:TagRole`,
  `iam:AttachRolePolicy`, `iam:GetRole`, `iam:ListRoleTags` solo sobre `role/agente-iam/personas/*`, con
  `iam:PermissionsBoundary` = el techo en `CreateRole` y `iam:PolicyARN` = `policy/agente-iam/*` en `Attach`. Sin
  `UpdateAssumeRolePolicy`, sin `DeleteRole`, sin `PassRole`. El techo mismo debe negarle al rol de persona
  modificar roles de esa ruta (ya niega `iam:*` de escritura: comprobar en tests).
- Permiso del rol del runtime: `iam:ListRoles` y `iam:ListRoleTags` (lectura) para la redundancia y el tope.
- `aprobar_cliente` muestra ademas `horas`, `vence` previsto y el nombre del rol.

### 5.6 La pagina web (pila `web`, operador)

- Pagina estatica (HTML, CSS y JavaScript sin framework ni dependencias de red; llamada de Claude: menos superficie,
  nada que auditar en `node_modules`), en un bucket privado servido por CloudFront con OAC, HTTPS de CloudFront
  (`*.cloudfront.net`; sin dominio propio en esta fase). Cabeceras de seguridad por politica de respuesta de
  CloudFront (CSP que solo permite el origen de Cognito y el endpoint de AgentCore, `frame-ancestors 'none'`).
- Cliente de Cognito nuevo `agente-iam-web` (pila `acceso`): PKCE, sin secreto, URL de retorno = la de CloudFront; el
  autorizador del runtime admite los dos clientes (`allowedClients` en `runtime.yaml`).
- Flujo: boton "Entrar" -> Cognito -> Identity Center (MFA) -> vuelve con `code` -> canje en el navegador -> token en
  memoria (nunca `localStorage`; recargar = volver a entrar). La pagina muestra quien es (claim `username` sin
  prefijo) y el formulario: servicio (lista cerrada, la misma del servidor), recurso, tipo de acceso, region (lista
  cerrada), horas (1 a 12), correo de aviso, justificacion.
- Enviar: `POST` al endpoint `invocations` del runtime con `Authorization: Bearer`. La pagina ensena la respuesta
  escapada: id, estado, y si es `propuesta`, un texto fijo "queda a la espera de un aprobador; te avisaremos a
  <correo>". Errores 401/403/424 con texto fijo. Ninguna otra llamada: la pagina no lee la tabla.
- Lo que la pagina NO hace: consultar el estado despues (el correo lo cubre), aprobar, listar solicitudes.
- Tests (llamada de Claude; el repositorio es Python y no se anade Node): la logica de la pagina se mantiene minima y
  se prueba de dos formas: un test de Python que comprueba que las listas cerradas de la pagina son las mismas que
  las del servidor (se generan desde `config.py` al construir), y la prueba en vivo desde el navegador integrado con
  el token de Mateo (evidencia en MEDICIONES). Mateo decide si quiere mas.

### 5.7 El aviso por correo (pila `runtime` o `base`, operador)

- Lambda `agente-iam-avisos`, disparada por el stream de la tabla con filtro de `estado` en {`aprobada`,
  `rechazada_por_aprobador`, `aplicada`, `bloqueada_al_aplicar`, `requiere_revision_humana`,
  `redundante_no_requiere_cambio`, `rechazada_en_chequeos_previos`}. Llamada de Claude: avisar en cada estado que
  acaba algo para la persona; `propuesta` no avisa (la pagina ya lo dijo).
- Cuerpo fijo: "Solicitud <id>: <estado>. <frase por estado>." Sin politica, sin justificacion, sin nombre del
  aprobador. El de `aplicada` anade el ARN del rol y la hora de vencimiento, que es lo que la persona necesita para
  usarlo y no es secreto: nadie mas puede asumirlo (llamada de Claude, pregunta 8 del revisor). Remitente: una direccion verificada en SES de la cuenta `agente-iam` (Mateo la verifica en consola).
- SES en modo inicial: solo entrega a direcciones verificadas. En la demo se verifican las de Mateo. Si SES rechaza
  (direccion no verificada), la Lambda lo registra y no reintenta: un aviso que no sale no es un fallo del circuito.
- Rol propio `AgenteIAM-Avisos` con `LimiteSistema`: `ses:SendEmail` sobre la identidad remitente y nada mas; lee el
  stream, no la tabla.

### 5.8 Orden del trabajo (tres bloques que se apoyan)

1. **Rol por persona con caducidad** (backend): la forma de la confianza ya esta medida (N); contrato, chequeos,
   aplicador, permisos, proveedor OIDC en la pila `acceso`, `solicitar.py asumir`, tests, despliegue, prueba de fuego
   con dos personas (`solicitante.demo` pide, `aprobador.demo` aprueba, `solicitante.demo` asume el rol y lee el bucket de
   demo; decision de Mateo del 26-10-2026: la demo la hace una persona sin otros permission sets en `agente-iam`,
   porque con administrador casi todo saldria redundante).
2. **Pagina web**: pila `web`, cliente de Cognito, pagina, prueba desde el navegador.
3. **Correo**: identidad SES, Lambda de avisos, prueba.

Cada bloque cierra con su documentacion (PLAN, CONTEXTO, MEDICIONES, DESPLIEGUE, README) y su commit. Un ADR-004
recoge 5.2 a 5.4 (rol por persona, confianza, redundancia) cuando las mediciones den la forma final.

## 6. Lo que queda al constructor

Nombres exactos de recursos y salidas de pila; forma del HTML y CSS; division de modulos en `agente_iam/`; como se
genera la lista cerrada de servicios y regiones para la pagina; el detalle de los tests de mutacion para los chequeos
nuevos; el texto de los correos; el orden interno de las tareas dentro de cada bloque.

## 7. Decisiones tomadas el 26-10-2026 y las que quedan

Tomadas por Mateo: `horas` = vida del permiso con corte exacto por condicion (5.2); la demo la hace
`solicitante.demo` y la redundancia se acota en esta fase a los roles de persona vigentes (5.4); un solo modo en el servidor y el modo actual solo en el CLI de desarrollo (5.5). Criterio declarado: lo que
menos tiempo lleve, porque el proyecto se publica y se sustenta en LinkedIn en cuanto este.

Decidido tambien el 26-10-2026 y medido (N): la persona asume el rol con `AssumeRoleWithWebIdentity` y su token de
identidad de Cognito; `horas` es vida del permiso y sesion maxima; sin permission set de solicitantes.

Quedan de Mateo:
- Si la regla 2c del prompt se corrige en esta fase (hoy toda solicitud de s3 gasta dos intentos, MEDICIONES M.5).
  Recomendacion: no, para no anadir una medicion mas con Bedrock a esta fase.
- Que direcciones se verifican en SES para la demo.

## 8. Llamadas de Claude para revisar al leer

Marcadas en el texto: id formado desde una clave de un solo uso del cliente (5.1); tope de 5 roles vigentes por persona
(5.1); nombre de usuario literal en la confianza y `MaxSessionDuration` de 1 h (5.2); `vence` desde la aplicacion y
`propuesta` sin caducidad (5.2); pertenencia al grupo garantizada por la asignacion de la aplicacion SAML (5.3);
lista con los dos clientes como `aud` en la confianza (5.2); chequeo nuevo que impide conceder `sts:AssumeRole` o nada
sobre la ruta de personas (5.5); pagina sin framework,
token en memoria, CSP estricta (5.6); correo de `aplicada` con el ARN del rol y el vencimiento (5.7); la Lambda de
avisos no reintenta un envio rechazado por SES (5.7).
