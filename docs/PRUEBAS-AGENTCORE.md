# Pruebas de AgentCore con Identity Center

Fase 10, paso 2. Dos pruebas, una pregunta: **hace falta Cognito, o basta con los
tokens de Identity Center.** Ejecutadas el 23-10-2026 (cuenta `agente-iam` y la de
gestion): **la A no es viable; la B pasa.** El camino es Cognito federado con
Identity Center por SAML (decision: `docs/ADR-001-agentcore-identidad.md`).
Resultados y mediciones: `docs/MEDICIONES.md`, seccion D. Aqui quedan el
razonamiento y lo minimo para repetirlas; la guia larga, con todos los comandos,
quedo en la historia de git del repositorio privado de origen (commit `8cb3c42`).
Cuenta de ejemplo: `111122223333`.

---

## 1. Las piezas

AgentCore Runtime admite dos entradas y **un runtime acepta una sola**: SigV4 o
token JWT. El JWT se configura al crear el runtime con `--authorizer-configuration`,
que hoy solo tiene `customJWTAuthorizer` (botocore 1.43.116): `discoveryUrl`
(obligatorio; debe acabar en `/.well-known/openid-configuration`, de ahi salen el
emisor y las claves), y opcionales `allowedAudience` (claim `aud`), `allowedClients`
(claim `client_id`), `allowedScopes` y `customClaims`. No existe un modo "Identity
Center": si sirve, sera como un emisor JWT mas.

Con JWT **no se invoca con la CLI ni con el SDK** (firman con SigV4): se hace una
peticion HTTPS directa a
`https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/<ARN codificado>/invocations`
con `Authorization: Bearer <token>`. El id de sesion
(`X-Amzn-Bedrock-AgentCore-Runtime-Session-Id`) tiene minimo 33 caracteres.

*JWT*: `cabecera.carga.firma` en base64url; la carga lleva claims (`iss`, `aud`,
`sub`, `exp`) que lee cualquiera, y solo el dueno de la clave publica comprueba la
firma. *Documento de descubrimiento*: JSON publico con el `issuer` y la `jwks_uri`.
*Token opaco*: cadena sin significado salvo para su emisor; AgentCore no puede usarla.

Un emisor sirve a AgentCore si cumple **tres cosas**: (1) publica un documento de
descubrimiento en una URL publica; (2) entrega al usuario un **JWT firmado**, no un
token opaco; (3) el JWT lleva un `aud` o `client_id` estable. La A las comprueba
para Identity Center; Cognito las cumple por diseno y la B lo confirma.

## 2. Para repetirlas

Hacen falta la landing zone (`docs/CONTROL-TOWER-CHECKLIST.md`), la
cuenta `agente-iam`, los perfiles SSO `org-agente-iam` y `org-gestion`, Mateo y
`aprobador.demo` con MFA y el venv; la B entera cuesta menos de 0,10 USD si se
deshace el mismo dia (MEDICIONES D.5).

## 3. El agente eco

Las pruebas miran que le llega al agente y con que identidad corre, no lo que hace;
por eso un eco (`infra/pruebas-agentcore/agente_eco.py`) en vez del agente IAM:
devuelve los claims que AgentCore ya valido y el ARN de la sesion del rol, nunca el
token (`tests/unitarios/test_agente_eco.py`). Cumple el contrato HTTP de AgentCore
(puerto 8080, `POST /invocations`, `GET /ping`). Corre con un rol propio,
`AgenteIAM-PruebaEco-Runtime` (solo logs, trazas, metricas y lectura de su paquete:
`infra/pruebas-agentcore/rol-eco-permisos.json`) y la confianza del runtime del
sistema (rol `RolRuntime` de `infra/cfn/base.yaml`: `aws:SourceAccount` y `aws:SourceArn`
contra el confused deputy; sin `sts:SetSourceIdentity`).

---

## 4. Prueba A: tokens de Identity Center directos

**Objetivo.** Saber si el autorizador JWT valida un token que Identity Center
entrega al usuario, sin Cognito. Si valiera, la CLI usaria el token de `aws sso
login`; si no, hace falta un emisor JWT en medio.

Opciones de Identity Center contra las tres condiciones (doc, 20-10-2026):
`CreateToken` (`aws sso login`) da un `accessToken` no documentado como JWT y sin
claves publicas, con acceso a todas las cuentas del usuario (su `idToken` figura como
no soportado); `CreateTokenWithIAM` da un `idToken` JWT pero se firma con SigV4 (solo
un backend con credenciales IAM) y no hay JWKS publico documentado; el trusted token
issuer va en la direccion contraria; una aplicacion SAML da una asercion, no un JWT
(es la pieza de la B).

**Pasos (solo lectura, 0 USD).** A.1: Issuer URL de la instancia. A.2: `curl` a
`<issuer>/.well-known/openid-configuration`. A.3: describir, sin imprimirlo, el
`accessToken` de `~/.aws/sso/cache/` (longitud y numero de partes).

**Criterio.** Sin descubrimiento o con token opaco: fracaso, hace falta Cognito.
Ambos positivos pero AgentCore rechaza el emisor: fracaso, anotar el error. Una
invocacion 200 con los claims del usuario: exito, contradice la doc; documentarlo.

**Resultado (23-10-2026, cuenta de gestion, solo lectura): no viable.** La Issuer
URL real da 404 y el OIDC regional 403; los dos `accessToken` son opacos (230
caracteres, una parte). **Supuesto:** que no haya otra ruta de descubrimiento (la
doc no documenta ninguna). Detalle: MEDICIONES D.1.

---

## 5. Prueba B: Cognito federado con Identity Center por SAML

**Objetivo.** Montar la cadena y medir donde queda la identidad:

```
usuario en Identity Center (MFA) -> asercion SAML -> user pool de Cognito (SAML a JWT)
  -> token de acceso -> autorizador JWT de AgentCore -> agente eco -> CloudTrail
```

Los usuarios viven solo en Identity Center; Cognito no tiene propios. La parte de
CloudTrail es una medicion, no aprobado o suspenso.

**Hipotesis (doc) y resultado.** (a) Cognito publica descubrimiento y el token de
acceso lleva `client_id` y no `aud`, asi que se usa `allowedClients`: asi salio.
(b) La identidad no llega sola al rol (haria falta `sourceIdentity` y
`sts:SetSourceIdentity` en la confianza): asi salio, `sourceIdentity` vacio.
(c) `InvokeAgentRuntime` es un evento de datos (`AWS::BedrockAgentCore::Runtime`) y
el trail de organizacion registra solo gestion (doc; no comprobado alli): se uso un
trail de datos propio y temporal.

**Montaje.** La pila temporal `infra/cfn/prueba-eco.yaml` (`agente-iam-prueba-eco`)
se despliega **dos veces**: la primera con `MetadataUrl` vacio (bucket, rol, user
pool, dominio); con sus salidas se crea en consola, en la cuenta de gestion, la
aplicacion SAML (la API solo crea las OAuth) y se sube el paquete del eco; la
segunda con la URL de metadatos (proveedor, cliente, runtime, trail). En la
aplicacion: ACS URL y audience son las salidas de la pila; atributo `Subject` =
`${user:subject}` formato `persistent` (id interno que no cambia; con el correo, el
federado no podria entrar si cambia) y `email` = `${user:email}`; sesion de 4
horas; asignar a Mateo y `aprobador.demo`. El proveedor se llama `IdentityCenter`
(sin guiones bajos); el cliente es publico, con PKCE y solo ese proveedor. El
runtime se llama `agente_iam_eco` (`[a-zA-Z][a-zA-Z0-9_]{0,47}`), usa
`allowedClients` y `requestHeaderAllowlist: [Authorization]` (sin ella la cabecera
no llega al contenedor; solo se permite con `customJWTAuthorizer`).

**Repetir lo que pide un humano o lectura: `scripts/prueba_b.py`** (perfil
`org-agente-iam` por defecto, salidas leidas de la pila):

```bash
./.venv/bin/python scripts/prueba_b.py token --usuario mateo       # B.5, lo corre Mateo
./.venv/bin/python scripts/prueba_b.py token --usuario aprobador   # ventana privada NUEVA
./.venv/bin/python scripts/prueba_b.py invocar --usuario mateo     # B.7: con token, sin token, firma alterada
./.venv/bin/python scripts/prueba_b.py cloudtrail --horas 3        # B.8 y B.9
```

`token` hace PKCE, recibe el codigo en `localhost:8080` y guarda el token fuera de
git, con permisos 600, sin imprimirlo; si el `sub` coincide con el del otro usuario
(el navegador reutilizo la sesion) no lo guarda: cerrar todas las ventanas privadas.
`invocar` altera el **primer** caracter de la firma (el ultimo, en base64url, puede
ser relleno y dejarla identica). `cloudtrail` pagina los `AssumeRole` del rol del eco
y lee los `InvokeAgentRuntime` del trail de datos.

**Criterio.** Pasa si el token trae el `iss` del pool y el `client_id` del cliente,
la invocacion con token da 200 con los claims del usuario, y las de sin token y
firma alterada se rechazan (aceptarlas seria un fallo grave). Con el aprobador
cambian los claims y no el ARN del rol.

**Resultado (23-10-2026): la B pasa** con los dos usuarios: 200 con token, 401 sin
token y con la firma alterada. La identidad vive en el token y no llega al rol:
`AssumeRole` sin `sourceIdentity`, una sesion de rol por sesion del runtime y no por
usuario; el evento de datos lleva el `sub` en `additionalEventData.jwt.claims` con
`userIdentity` anonimo, y la llamada sin token no deja evento. Detalle, hallazgos
operativos y desmontaje: MEDICIONES D.2 a D.4.

**Lo que decide para el diseno.** Como la identidad no llega sola al rol, la
atribucion la construye el codigo: lee los claims ya validados y los graba en el
registro (`ejecutado_por`). Verla ademas en CloudTrail exigiria un segundo rol con
`SourceIdentity` (`sts:SetSourceIdentity` en su confianza y aflojar el Deny de
`sts:AssumeRole` del rol del runtime): sin medir (MEDICIONES D.6).

**Deshacer.** `cloudtrail stop-logging`, vaciar los dos buckets y borrar la pila;
borrar a mano el grupo de logs `/aws/bedrock-agentcore/runtimes/<id>-DEFAULT` (no es
de la pila); quitar las asignaciones de la aplicacion SAML antes de borrarla.
Hecho el 23-10-2026 (MEDICIONES D.4).

---

## 6. Que decide el resultado

| Prueba A | Prueba B | Decision |
|---|---|---|
| No viable (resultado) | Pasa (resultado) | **Cognito federado con Identity Center por SAML**; la CLI obtiene el token con codigo de autorizacion y PKCE |
| Viable | Pasa | Sin Cognito, con la advertencia de que el token de la CLI da acceso a todas las cuentas del usuario |
| No viable | Falla | Ni lo uno ni lo otro: volver a la comparativa del computo |
