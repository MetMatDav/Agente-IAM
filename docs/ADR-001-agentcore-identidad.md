# ADR-001: AgentCore Runtime con Cognito federado con Identity Center

- **Estado:** aceptado por Mateo el 23-10-2026 (propuesto por Claude el mismo dia).
- **Fase:** 15, bloque 2 (`PLAN-CORRECCIONES.md`).
- **Medido contra:** la cuenta `agente-iam` (`Workloads`) y la de gestion
  (Identity Center), el 23-10-2026. Evidencia sin tokens fuera de git; las
  tablas completas estan en `docs/MEDICIONES.md`, §D.
- **Sustituye a:** nada. Concreta la decision 7 de la Fase 10 ("computo del
  analista: AgentCore Runtime con autorizador JWT"), que dejaba abierto si
  hacia falta Cognito.

## Contexto

El analista correra en AgentCore Runtime (Fase 10, decision 7). Para que el
endpoint no quede abierto ni dependa de SigV4, el runtime valida un JWT con
su autorizador (`customJWTAuthorizer`). Los humanos viven en IAM Identity
Center (Fase 10, decision 2). Habia dos preguntas:

1. **Quien emite el JWT.** El autorizador necesita un emisor con documento
   de descubrimiento OIDC y tokens JWT firmados.
2. **Si la identidad de la persona llega a AWS.** El proyecto exige que el
   aprobador sea la persona y no el rol (requisito de Mateo del
   22-10-2026), y que la auditoria compare personas.

Las pruebas de `docs/PRUEBAS-AGENTCORE.md` respondieron las dos.

## Lo que se midio (23-10-2026; detalle en `docs/MEDICIONES.md`, §D.1 a §D.4)

**Prueba A, tokens de Identity Center directos: no viable.** No hay documento
de descubrimiento (404 `NoSuchKey` en la Issuer URL, 403 en el OIDC regional) y
los `accessToken` de la cache de SSO tienen una sola parte: son opacos, no JWT.

**Prueba B, Cognito federado con Identity Center por SAML: pasa.** Con dos
personas distintas, Mateo y `aprobador.demo`:

| Invocacion | Mateo | Aprobador |
|---|---|---|
| Con token | 200 | 200 |
| Sin token | 401 `Missing Authentication Token` | 401 |
| Firma alterada | 401 `Invalid Signature for bearerToken` | 401 |

**Donde queda la identidad:**

| Lugar | Que hay |
|---|---|
| Dentro del runtime (cabecera `Authorization`) | Los claims validados: `sub`, `username` (`IdentityCenter_<NameID>`), `cognito:groups`, `client_id` |
| Credenciales AWS del runtime | El rol del runtime, sesion `BedrockAgentCore-<uuid>`: una por sesion del runtime, la misma forma para los dos usuarios |
| `AssumeRole` en CloudTrail (gestion) | Invocado por `bedrock-agentcore.amazonaws.com`, **sin `sourceIdentity`** |
| `InvokeAgentRuntime` (evento de datos, trail propio) | `userIdentity` `anonymous`; el `sub`, el `jti` y el `iss` en `additionalEventData.jwt.claims`; sin `username` |
| Llamada sin token | **Ningun evento de datos** |

## Decision

1. **Emisor: Amazon Cognito, con Identity Center como proveedor SAML.** El
   user pool no tiene usuarios ni contrasenas propios: todos entran por
   Identity Center, con su MFA. Identity Center sigue siendo la unica fuente
   de personas.
2. **Cliente publico con codigo de autorizacion y PKCE (S256)**, sin secreto
   y sin flujos de contrasena. La CLI lo hace como `scripts/prueba_b.py
   token`: retorno a `localhost`, `state`, y token en un fichero con
   permisos 600, nunca en la shell. La web usara el mismo cliente o uno
   gemelo.
3. **El runtime acepta solo JWT** (`customJWTAuthorizer`, con
   `allowedClients` y el `discoveryUrl` del pool) y solo deja pasar la
   cabecera `Authorization`. La CLI ya no firma con IAM.
4. **La atribucion a la persona la hace el codigo del agente.** AgentCore no
   la propaga a AWS (ver Consecuencias). El agente graba en su registro los
   claims que el autorizador ya valido.

## Alternativas descartadas

| Alternativa | Por que no |
|---|---|
| Tokens de Identity Center directos | Medido: sin descubrimiento y tokens opacos. El autorizador no puede validarlos |
| SigV4 (IAM) en el runtime | El runtime no recibe la identidad del llamante (`servidor.py`, `_quien_invoco`). La cabecera `X-Amzn-Bedrock-AgentCore-Runtime-User-Id` la escribe el llamante y AWS no la verifica |
| Cognito con usuarios propios | Segunda fuente de personas, con sus contrasenas y su MFA. Rompe la decision 2 de la Fase 10 |
| Otro emisor OIDC (IdP externo) | Otra cuenta y otro proveedor para dos usuarios. Cognito ya es de AWS, entra en CloudFormation y cuesta 0 con menos de 50 MAU federados |

## Consecuencias

**La identidad no llega al rol. Es la consecuencia central.** Lo que el
runtime haga en AWS (leer IAM, simular, invocar Bedrock, escribir el
registro) queda en CloudTrail a nombre del rol, con una sesion que no dice
para quien trabajaba. El unico rastro de la persona en AWS es el `sub` del
evento de datos, y ese evento solo existe con un trail propio de eventos de
datos (el de Control Tower no los registra). Ademas, nada une ese evento con
lo que hizo el rol salvo la hora: el `runtimeSessionId` no es el nombre de
la sesion del rol.

Por eso:

- **El registro de cada solicitud lleva la persona.** Hay que guardar `sub`,
  `username`, `jti` y el id de sesion del runtime. Hoy `servidor.py` graba
  `ejecutado_por` como "no determinable" (SigV4); con JWT pasa a leerse de
  los claims ya validados (`docs/ESPECIFICACION-agentcore.md`, §3). Ese
  registro es la fuente de verdad de "quien pidio", no CloudTrail.
- **La separacion de funciones debe comparar el nombre de usuario de Identity
  Center, no el `sub` ni el rol.** (Decision; hoy `aprobar` compara el ARN
  del rol del permission set y no distingue personas: CONTEXTO §10.) El `sub` solo existe en Cognito, es decir,
  en el token del solicitante; el aprobador entra por SSO con un permission
  set y no tiene `sub`, y el rol es el mismo para todos. Lo comun a los dos
  canales es el nombre de usuario: sale en el claim `username`
  (`IdentityCenter_<NameID>`; medido el 23-10-2026:
  `IdentityCenter_aprobador.demo`) y en el nombre de sesion del permission
  set. El `sub` se graba para unir el registro con el evento de datos de
  CloudTrail, no para comparar con el aprobador.
  - **Lo que hace el codigo hoy** (`aprobar._separacion`, comprobado el
    24-10-2026): compara el ARN canonico del aprobador (resuelto con STS e IAM)
    con el ARN canonico del principal beneficiario de la solicitud. No lee
    claims ni nombres de usuario de Identity Center, y no compara contra quien
    pidio. La comparacion por nombre de usuario es lo previsto para cuando la
    aprobacion entre por el runtime (bloque 3). (Decidido en ADR-003.)
  - **Sin medir:** que el `NameID` de la aplicacion SAML sea exactamente el
    nombre de usuario de Identity Center. Se mide con una persona real antes
    de dar la comparacion por buena (`docs/MEDICIONES.md`, §D.6; detalle en
    `docs/ESPECIFICACION-agentcore.md`, §4).
- **Una llamada sin token no deja rastro en AWS.** Para contar intentos
  anonimos hacen falta los logs del propio runtime o metricas, no CloudTrail.
- **El trail de datos va, propio** (decidido el 23-10-2026): solo de AgentCore
  Runtime, en `agente-iam`, con caducidad de 90 dias en su bucket. Cuesta un
  bucket mas.
- **Sesion del navegador:** el enlace de inicio de sesion reutiliza la sesion
  abierta de Identity Center. El primer token del aprobador salio con el
  usuario de Mateo. La CLI comprueba quien entro (el `sub`), y la guia de uso
  pide una ventana privada nueva para cambiar de persona.

**Opcion abierta: `SourceIdentity`.** Si se quiere ver a la persona en el
CloudTrail de gestion, el codigo puede asumir un segundo rol fijando
`SourceIdentity` con el `sub` o el `username` del token. Exige
`sts:SetSourceIdentity` en la confianza de ese rol y quitar `sts:AssumeRole`
del Deny del rol `RolRuntime` de `infra/cfn/base.yaml`, que hoy lo prohibe. Ese Deny
existe para que el analista no pueda saltar a otro rol: aflojarlo es un
cambio de seguridad, no un detalle. **Sin medir**; queda fuera del bloque 3,
con un diseno propio revisado por Mateo y despues la prueba con los roles
reales (requisito de Mateo del 23-10-2026).

**Coste medido:** la Prueba B entera, por debajo de 0,10 USD (precios en
`docs/MEDICIONES.md`, §D.5). En produccion: Cognito a 0 USD con menos de 50
MAU federados al mes; el runtime, por consumo.

## Pendiente

Quien lo hace y en que orden esta en `CONTEXTO.md`, §11. Hecho el 25-10-2026:
la plantilla definitiva del pool y el cliente (`infra/cfn/acceso.yaml`), el
runtime (`infra/cfn/runtime.yaml`, `agente_iam_analista-<sufijo>`) y leer los claims
en `servidor.py`, todo desplegado y con la persona medida con un token real
(`docs/MEDICIONES.md`, §K.2). Pendiente: el diseno del segundo rol con
`SourceIdentity` (Claude lo disena, Mateo lo revisa antes de medir) y repetir la
Prueba B contra el runtime real con dos personas.
