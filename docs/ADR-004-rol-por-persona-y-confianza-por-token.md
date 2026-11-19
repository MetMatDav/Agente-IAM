# ADR-004: el permiso es un rol por persona, con caducidad, que la persona asume con su token de Cognito

- **Estado:** los tres bloques de la Fase 23 implementados, desplegados y medidos el 26-10-2026 (UTC, `docs/MEDICIONES.md` O.1 a O.6, vencimiento real incluido). Diseno aprobado por Mateo el 26-10-2026; Fase 23 (plan en
  `docs/superpowers/plans/2026-10-26-formulario-web-y-rol-por-persona.md`, diseno en
  `docs/superpowers/specs/2026-10-26-formulario-web-y-rol-por-persona-design.md`). Lo medido en la prueba de fuego
  esta abajo; lo marcado "sin medir" sigue siendo supuesto.
- **Medido contra:** la cuenta `agente-iam`, con llamadas reales a STS e IAM el 26-10-2026 UTC (`docs/MEDICIONES.md` N:
  sonda de dos roles y un proveedor OIDC, borrada despues). El simulador y `aws:CurrentTime`: `docs/MEDICIONES.md` A.3
  (30-08-2026).
- **Sustituye a:** el beneficiario declarado (`principal_arn_declarado`) como unico camino del sistema (ADR-002 lo daba
  por hecho: un principal que ya existe y lleva el techo). Concreta el pendiente "jerarquia asignar/crear y permisos con
  caducidad" de `CONTEXTO.md` §2 y `docs/MEDICIONES.md` A.3, y el pendiente "`solicitud_id` generado por el sistema" de
  `CONTEXTO.md` §11.

## Contexto

Hasta la Fase 22 el permiso se concedia a un principal que ya existia (`app-finanzas-demo`), elegido por quien pedia
en el campo `principal_arn_declarado`, y el solicitante no era el beneficiario. Para la demostracion y para una empresa
hace falta otra cosa: que cualquier persona de Identity Center pida para si misma, que no pueda elegir otro
beneficiario, y que el permiso dure lo que ella pida (1 a 12 horas) y muera solo.

Las personas de Identity Center no son principales de IAM (ADR-001, ADR-002): no hay a quien adjuntar una politica.
Hay que crear algo que la persona pueda usar y solo ella.

## Decision

### A. El permiso se materializa en un rol creado para la persona

- Nombre `agente-iam-persona-<usuario>-<solicitud_id>`, ruta `/agente-iam/personas/`, 64 caracteres como maximo
  (el usuario, normalizado como en ADR-003 y recortado; el id va entero y es lo que separa a dos personas que
  solo difieren dentro del recorte). Etiquetas `agente-iam-solicitud`, `agente-iam-persona`, `agente-iam-sub`,
  `agente-iam-vence`. Todo determinista: un reintento encuentra lo que ya hizo (`agente_iam/personas.py`).
- `PermissionsBoundary` = `AgenteIAM-Techo`: lo maximo que el sistema concede sigue siendo el techo (ADR-002).
  Medido (N.2, 5): la sesion lista el bucket de demo y no toca el bucket del sistema.
- La politica propuesta por el modelo y aprobada por la persona se crea como politica gestionada con el nombre
  determinista de siempre y se adjunta al rol. Al APLICAR, el codigo (no el modelo) anade a cada `Allow`
  `DateLessThan aws:CurrentTime = <vence>`. Medido (N.2, 7): corta el permiso a la hora exacta aunque la sesion siga
  viva.
- `MaxSessionDuration` = `horas * 3600`: `horas` es a la vez la vida del permiso y la sesion maxima (decision de
  Mateo). `vence` = hora de aplicacion mas `horas`; una `propuesta` sin aprobar no caduca en esta fase.

### B. La persona lo asume canjeando su token de identidad de Cognito

- Confianza del rol: `Principal.Federated` = el proveedor OIDC del pool `agente-iam-acceso` en IAM,
  `sts:AssumeRoleWithWebIdentity`, `StringEquals` `<emisor>:aud` = los clientes del pool (CLI y web) y `<emisor>:sub` =
  el `sub` de la persona, `DateLessThan aws:CurrentTime` = `vence`. Medido (N.2): solo su `sub` entra (3); el token de
  acceso no sirve, hace falta el de identidad con `aud` (2); sesiones de hasta 12 horas (1); vencido, nadie lo asume (8).
- Por que no desde la sesion de Identity Center: eso seria encadenamiento de roles, que AWS limita a 1 hora por CLI y
  API (documentado, leido el 26-10-2026). El canje del token es el primer salto desde una identidad web y admite 12
  horas.
- El `sub` lo graba el runtime en cada solicitud desde el JWT validado (`ejecutado_por.sub`); el aplicador lo lee del
  registro, nunca del formulario. Lo mismo `client_id`, que se contrasta con la lista configurada
  (`AGENTE_IAM_CLIENTES`) como defensa en profundidad: el autorizador JWT ya solo deja pasar esos clientes.
- Proveedor OIDC definitivo en la pila `acceso` (`AWS::IAM::OIDCProvider`), con los dos clientes. La sonda lo creo y lo
  borro (N.1).
- Dos tokens, dos usos: el `access_token` (claims `username`, `client_id`) va al runtime; el `id_token` (claim `aud`)
  va a STS. Cruzarlos falla (N.2, 2).

### C. Un solo modo en el servidor; el modo anterior solo en el CLI de desarrollo

- El servidor del runtime acepta un unico contrato (`models.SolicitudWeb`): sin `principal_arn_declarado` ni
  `solicitud_id` (se rechazan por forma: son un intento de elegir beneficiario o id), con `horas`, `correo_aviso` y
  `clave_envio`. El beneficiario lo pone el servidor desde el token.
- El modo "adjuntar a un principal que existe y lleva el techo" (ADR-002) sigue en el CLI de desarrollo sobre disco
  (`cli.py`, `ALMACEN=disco`), que no tiene token. Asi no se reescriben los tests, los ejemplos ni las mediciones M.4 y
  M.5, y el corpus de `ejemplos/` sigue sirviendo para desarrollo. Un test de seguridad (`tests/seguridad/test_modos.py`)
  fija que el servidor rechaza el ARN declarado y que el CLI rechaza `horas` y `persona`.
- `solicitud_id` lo forma el servidor: `req-<AAAAMMDD UTC>-<8 hex de sha256(clave_envio)>`. La misma clave el mismo dia
  da el mismo id, asi que un doble clic o un corte de red devuelven `registro_existente` con ese id en vez de abrir una
  segunda solicitud.

### D. Redundancia y tope contra los roles de persona vigentes

- "Lo que la persona ya puede hacer" es la union de los roles que puede asumir. En esta fase (decision de Mateo: lo que
  menos tiempo lleve) son los roles de persona vigentes que el sistema le creo: `ListRoles` por la ruta,
  `ListRoleTags`, filtro por persona, por `sub` (dos personas pueden normalizar al mismo texto) y por `vence`. La lectura de sus permission sets en Identity Center (dos llamadas en la
  cuenta de gestion) queda como siguiente paso documentado; para `solicitante.demo`, sin permission sets en
  `agente-iam`, da lo mismo.
- La redundancia compara solo contra roles vigentes cuyo vencimiento es igual o posterior al del permiso pedido: un rol que
  vence antes no lo cubre, porque la persona se quedaria sin permiso entre las dos horas.
- La simulacion aporta `aws:CurrentTime` como contexto: medido (A.3) que el simulador no tiene valor implicito para esa
  clave y, sin aportarla, toda politica con `DateLessThan` sale `implicitDeny`; sin esto la redundancia seria siempre
  "acceso nuevo".
- Si la lectura de roles falla, la redundancia se declara no comprobada y la solicitud sigue como acceso nuevo: la duda
  cae del lado de conceder con aprobacion, nunca de negar en silencio.
- Tope: 5 roles vigentes por persona (`config.MAX_ROLES_VIGENTES_POR_PERSONA`); protege las cuotas de IAM hasta que exista
  el borrado de roles vencidos. No acota el gasto en el modelo: las solicitudes que no llegan a rol no cuentan, y no hay tope
  de solicitudes por persona (pista 4 de la Fase 33, `docs/MEDICIONES.md` W.2).

### E. Permisos del aplicador y del limite del sistema

- `AgenteIAM-Aplicador`: `iam:CreateRole` solo sobre `role/agente-iam/personas/*` y solo con `iam:PermissionsBoundary`
  = el techo; `iam:TagRole` y `iam:ListRoleTags` sobre esa ruta; el `AttachRolePolicy` de siempre (politica bajo
  `policy/agente-iam/*`, destino con el techo); `iam:ListRoles` sobre `*` (`ListarRolesNoTieneRecurso`: la accion no admite
  recurso, y el aplicador lista la ruta de personas para repetir el tope). Dos Deny lo cierran aunque manana alguien amplie un Allow: `CreateRole`
  fuera de la ruta (`NotResource`) y `CreateRole` sin el techo (`StringNotEquals`: con la clave ausente, deniega; la
  leccion de `docs/MEDICIONES.md` §H 11 y 30). Sin `UpdateAssumeRolePolicy`, `DeleteRole` ni `PassRole`.
- `AgenteIAM-LimiteSistema` (pila de arranque, la despliega el administrador) permite lo mismo y lleva los mismos dos
  Deny. El rol de despliegue puede crear el proveedor OIDC solo si es el de Cognito en `us-east-1`.
- El rol del runtime no cambia: `iam:List*` ya cubre la lectura de roles y etiquetas.
- Defensa en profundidad del aplicador: antes de crear nada repite el tope de roles vigentes por persona (entre aprobar y
  aplicar pueden haberse aplicado otras), cruza los bloques del registro entre si (`_coherencia_de_modo`) y, en un
  reintento, solo adopta un `vence` ya existente si es futuro y no pasa de las horas pedidas (`_vence_valido`).

## Desviaciones del diseno, y por que

- `scripts/solicitar.py asumir` recibe el ARN del rol, no el `solicitud_id`: la persona no puede leer la tabla. El ARN
  lo imprime `enviar` (`rol_previsto`) y lo trae el correo de `aplicada`.
- Las etiquetas van dentro de `CreateRole` (una llamada, atomica) en vez de un `TagRole` posterior; `iam:TagRole` sigue
  permitido para converger en un reintento.
- El id es idempotente para el registro, no para el coste: el modelo corre antes de guardar, asi que dos envios
  simultaneos con la misma clave gastan dos corridas y el segundo muere en `registro_existente`. El runtime no lee la
  tabla a proposito (el intake solo crea). La pagina deshabilita Enviar mientras hay una peticion en vuelo.
- Un reintento con la misma clave que cruce la medianoche UTC da otro id (la fecha va en el id). Se acepta: es raro, y
  el coste es una solicitud repetida, no un permiso de mas.

## Consecuencias

- Nadie elige el beneficiario: ni el formulario, ni el modelo, ni el aprobador. Lo fija el token.
- Un rol de persona no puede saltar a otro: la lista negra niega `sts:AssumeRole*`, el servicio de la propuesta tiene
  que ser el del formulario y la ruta `/agente-iam/personas/` es un recurso del sistema (chequeo 6). El techo no concede
  ninguna escritura de IAM.
- Los roles vencidos quedan inertes (ni se asumen ni conceden) y ocupan hueco: una fase posterior los borra al vencer o
  a la semana (decision de Mateo).
- El aprobador ve, ademas de la politica, `horas`, el `vence` que resultaria si aplicara ahora y el nombre del rol.
- La respuesta del servidor es una vista reducida del registro (`servidor.vista_publica`): la ve cualquier persona con token
  desde la web, y el registro completo (propuesta, validacion, identidad, quien invoco) vive en la tabla.
- Las cuotas de IAM (1000 roles, 1500 politicas gestionadas) son ahora un limite del sistema, de ahi el tope por persona.

## Lo que no cierra

- `iam:TagRole` sobre la ruta de personas va sin condicion: lo exige `CreateRole` con etiquetas, y permite que el
  aplicador reetiquete `agente-iam-vence` en un rol ya creado. Lo contiene que el aplicador no habla con el modelo y
  solo ejecuta su codigo; la etiqueta es informativa (la lee la redundancia y el tope), el corte real lo dan las
  condiciones `DateLessThan` de la confianza y de la politica, que `TagRole` no toca.

- La redundancia no ve los permission sets de la persona en `agente-iam` (lectura cruzada pendiente).
- Una `propuesta` no caduca: una solicitud aprobada semanas despues se aplica con `vence` desde ese momento.
- Renovar la sesion con el refresh token de Cognito, y la consola por el endpoint de federacion: sin medir.
- TLS 1.2 como minimo real en la pagina web exige certificado propio: con el certificado por defecto de CloudFront la distribucion
  queda en `TLSv1` (medido el 26-10-2026, `docs/MEDICIONES.md` O.4). Hace falta un certificado en ACM y un dominio propio; decision de Mateo.
- La Lambda de aprobacion revalida la fila con el contrato vigente (`models.py`, `aprobar.py`), asi que cambia de zip con cada
  cambio de contrato: el 26-10-2026 se olvido y la primera aprobacion dio 409 (`docs/MEDICIONES.md` §H 39, O.3).

## Medido en el despliegue (26-10-2026, MEDICIONES O.1)

- CloudFormation crea el proveedor OIDC del pool sin `ThumbprintList` (IAM pone una huella) y su `ClientIDList` es el cliente de la CLI.
- Los manejadores de `AWS::IAM::OIDCProvider` y de CloudFront piden acciones sin recurso (`iam:ListOpenIDConnectProviders`, tres `List*`
  de CloudFront); la referencia de autorizacion confirma que `iam:CreateOpenIDConnectProvider` autoriza sobre `oidc-provider`.
- La politica del aplicador y `LimiteSistema` desplegadas llevan crear roles solo bajo `/agente-iam/personas/` y solo con el techo.

## Medido en la prueba de fuego (26-10-2026, MEDICIONES O.2 y O.3)

- Circuito completo, medido: `solicitante.demo` pide (`propuesta` en 25 s), `aprobador.demo` aprueba, el aplicador crea el rol
  (`aplicada` 5 s despues), la persona canjea su `id_token` al primer intento y lista el bucket de demo; el token de otra persona
  (`mateo`) da `AccessDenied` y una sesion de mas horas que las pedidas da `ValidationError` (O.3). La Lambda de aprobacion
  tuvo que reempaquetarse para que el circuito pasara (§H 39).
- Un usuario fuera del grupo `agente-iam-solicitantes` no obtiene token: Identity Center responde "No access" antes de que
  Cognito emita nada (5.3 del diseno; O.2).
- Consistencia eventual entre `CreateRole`, el `AttachRolePolicy` con condicion de boundary y el primer
  `AssumeRoleWithWebIdentity`: no se manifesto a los 38 s; a los 10 s, sin medir.
- El vencimiento real de un rol creado por el sistema, medido (O.6, 26-10-2026 22:33 UTC): a los 8 s de `vence` la sesion viva
  pierde el permiso (`AccessDenied`) y un canje nuevo con un token valido da `AccessDenied`, mientras el rol vigente sigue
  entrando con el mismo token. Lo mismo que la sonda N midio con roles a mano.

## Anexo: la pagina web (bloque 2, medido el 26-10-2026)

- **La web no elige beneficiario.** Como el CLI, la pagina manda el contrato `SolicitudWeb` (sin ARN ni id) y el servidor pone la
  persona y el `sub` desde el token. El cliente web de Cognito (`agente-iam-web`) entra en la lista `aud` del autorizador del runtime y
  de la confianza del rol, junto al de la CLI: el rol creado para una solicitud hecha desde la pagina lleva los dos clientes en
  `:aud` y sigue atado al `sub` de quien pidio (`docs/MEDICIONES.md` O.4).
- **El canje en STS desde el navegador esta medido.** STS admite CORS (`Access-Control-Allow-Origin: *`, tambien en el error) y la
  pagina canjea su `id_token` con `AssumeRoleWithWebIdentity` y recibe credenciales de 6 horas al primer intento, 26 s despues de
  `CreateRole` (O.4). Los preflight del runtime y de Cognito tambien pasan.
- **Los tokens solo viven en la memoria de la pestana.** `app.js` no usa `localStorage`, cookies ni `innerHTML`; `sessionStorage` guarda
  solo el `verifier` de PKCE y el `state`, y recargar la pagina pierde la sesion (medido, O.4). El `id_token` solo viaja a STS y el
  `access_token` solo al runtime. La CSP de la distribucion limita `connect-src` a Cognito, AgentCore y STS.
- **La redundancia por persona, medida contra un rol vigente en la cuenta.** Un envio de 2 horas que cabe en el rol de la manana (que
  vence despues) dio `redundante_no_requiere_cambio` y no creo rol; uno de 6 horas, cuyo vencimiento pasa el del rol vigente, dio
  `propuesta` con `roles_comparados` vacio (la regla "vence >= nuevo" del apartado D, O.4).

## Anexo: el aviso por correo (bloque 3, medido el 26-10-2026)

- **Que viaja en el correo y que no.** El cuerpo lleva el id de la solicitud, el estado y una frase fija por estado; en `aplicada`,
  ademas, el rol (`Rol:`) y el vencimiento (`Vence:`). Nunca la politica, la justificacion ni el aprobador. Lo medido: los correos
  `rechazada_en_chequeos_previos`, `aprobada` y `aplicada` salieron para `req-20261026-2e923bc5` y `req-20261026-122e10a7`
  (`docs/MEDICIONES.md` O.5); Mateo confirmo los tres correos; `aprobada` y `aplicada` llegaron a la carpeta de spam de Gmail (sin dominio propio con SPF y DKIM: §J).
- **SES autoriza el envio tambien sobre la identidad del destinatario.** El rol `AgenteIAM-Avisos` permitia solo la identidad del
  remitente y el primer aviso dio `AccessDenied` (19:35 UTC). Ahora el recurso es `identity/*` y la condicion `ses:FromAddress`
  acota el remitente (`docs/MEDICIONES.md` §H 40; ESTUDIO §23). Es un permiso mas ancho en el recurso y igual de estrecho en lo que
  importa: el rol solo manda desde el remitente y no toca la tabla, IAM ni Bedrock.
- **Un aviso no es el circuito.** No se reintenta (lote de 1, 0 reintentos, sin cola): si SES rechaza el envio (`MessageRejected`
  con un destinatario sin verificar, medido), queda un `WARNING` con solo el dominio y la solicitud sigue su camino. Por eso el
  remitente se verifica antes del primer evento: los dos avisos de `req-20261026-1dfe50ff` se perdieron con el remitente `PENDING` y
  no se repiten. SES de la cuenta esta en modo inicial (200 por dia, solo a direcciones verificadas).
