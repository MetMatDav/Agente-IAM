# ADR-005: la pagina web pasa a un subdominio de mateo.solutions para fijar TLS 1.2

- **Estado:** decidido por Mateo el 26-10-2026 (decisiones 1 y 2); decisiones 3 y 4 tomadas como se propusieron, a
  confirmar por Mateo (son parametros). Plantillas y tests escritos el 26-10-2026. Todos los pasos hechos y medidos el 26 y el
  27-10-2026 (`docs/MEDICIONES.md` P.5 a P.7), con el flujo en el navegador desde el dominio incluido (Q.1). Fase 27 de
  `PLAN-CORRECCIONES.md`.
- **Medido contra:** lecturas de solo lectura del 26-10-2026 en la cuenta de gestion y en `agente-iam` (`docs/MEDICIONES.md`
  P). Lo que dice la documentacion de AWS lleva su fuente al final; lo marcado "sin medir" es supuesto.
- **Cierra, cuando se despliegue y se mida:** el pendiente "TLS 1.2 como minimo real en la pagina" de `docs/MEDICIONES.md`
  §J y `CONTEXTO.md` §10.

## Contexto

La pagina de la Fase 23 vive en `https://<id>.cloudfront.net` con el certificado por defecto de CloudFront. La plantilla
pide `TLSv1.2_2021`, pero con ese certificado CloudFront aplica `TLSv1` (medido, O.4). La documentacion lo dice igual: con
`CloudFrontDefaultCertificate` CloudFront fija la politica en TLSv1, y las politicas TLS 1.2 solo se pueden elegir con un
certificado propio en modo `sni-only`.

Mateo ya tiene el dominio `mateo.solutions`. Lo medido el 26-10-2026 (P):

- El dominio esta registrado en Route 53 y su zona publica esta en la **cuenta de gestion**, no en `agente-iam`.
- La zona tiene siete registros: el apice y `www` como alias A y AAAA a la distribucion de CloudFront de la pagina personal,
  NS, SOA y el CNAME de validacion de un certificado. No hay registros CAA (cualquier autoridad puede emitir, ACM incluida)
  ni MX.
- En gestion hay un certificado de ACM emitido para `mateo.solutions` y `*.mateo.solutions`, en uso por esa distribucion,
  que tiene `TLSv1.2_2021`. No sirve para la pagina del agente: un certificado de ACM es de una cuenta y una region, y la
  distribucion del agente esta en `agente-iam`.
- La distribucion `agente-iam-web` tiene IPv6 activado: el subdominio necesita alias A y AAAA.

## Decision

### Por que dos distribuciones y no una

La pagina personal y el agente siguen en distribuciones distintas, cada una en su cuenta. El dominio es solo una lista de
nombres: el apice y `www` apuntan a una, `agente-iam` a la otra. Juntarlas no ahorra: CloudFront cobra por datos y
peticiones, no por distribucion, y el nivel gratuito es por cuenta. Y juntarlas costaria tres cosas:

- **El mismo origen.** Servir el agente en una ruta de `mateo.solutions` haria que el navegador tratara las dos paginas
  como un solo sitio: un script de la pagina personal alcanzaria lo que guarda la del agente. Un subdominio es otro origen.
- **Las cabeceras.** La CSP del agente solo deja hablar con Cognito, AgentCore y STS; la de la pagina personal es otra.
- **La cuenta de gestion.** El agente pasaria a vivir donde no deben vivir cargas de trabajo, y un fallo suyo podria tumbar
  la pagina personal.

### 1. El nombre: `agente-iam.mateo.solutions` (decidido por Mateo)

La pagina personal sigue en el apice y en `www`, sin cambios.

### 2. Los registros DNS van en la zona de gestion, y los pone Mateo (decidido por Mateo)

Mateo eligio el 26-10-2026 no delegar una subzona: sin zona nueva y sin su coste (0,50 USD al mes). Lo que hace falta en
DNS lo pone el en la consola de la cuenta de gestion, en la zona `mateo.solutions`:

- el CNAME de validacion del certificado (punto 3), que se queda para siempre: ACM lo usa para renovar;
- los alias A y AAAA de `agente-iam.mateo.solutions` hacia la distribucion del agente. Desde otra cuenta, la consola no
  lista la distribucion: se escribe su nombre de CloudFront (salida `DominioCloudFront` de la pila web), con el id de zona
  fijo de CloudFront `Z2FDTNDATAQYW2`.

Consecuencia buena: los roles del agente no tienen ningun permiso de DNS, ni en su cuenta ni en gestion. Consecuencia mala:
cada cambio de DNS del agente y la renovacion del certificado dependen de un registro en la cuenta de gestion; si alguien
borra el CNAME de validacion, el certificado no se renueva.

La alternativa descartada era delegar `agente-iam.mateo.solutions` a una zona en `agente-iam` y crear zona, certificado y
registros con CloudFormation.

### 3. El certificado lo pide Mateo en la consola de `agente-iam`

En la cuenta `agente-iam` (no en gestion), region `us-east-1` (CloudFront solo acepta certificados de esa region):
certificado publico para el nombre exacto, sin comodin, con validacion DNS. ACM no puede crear el CNAME por su cuenta porque
la zona esta en otra cuenta: Mateo lo copia a la zona de gestion. Sin pila de CloudFormation para el certificado: es un
recurso unico, se renueva solo y asi el rol de despliegue no necesita permisos de ACM para crearlo.

### 4. `infra/cfn/web.yaml`: el dominio y el certificado, condicionales (escrito el 26-10-2026)

- Parametros `DominioWeb` y `CertificadoArn`, vacios por defecto. El dominio solo admite `agente-iam.mateo.solutions`; el
  certificado, un ARN de ACM de `us-east-1`. La regla `DominioYCertificadoVanJuntos` exige los dos o ninguno.
- Sin ellos, la distribucion queda como en la Fase 23: actualizar la pila sin parametros no la toca.
- Con ellos (condicion `ConDominio`): `Aliases` = el dominio, y `ViewerCertificate` = `AcmCertificateArn`,
  `SslSupportMethod: sni-only` y `MinimumProtocolVersion: TLSv1.2_2021`.
- `UrlWeb` pasa a `https://agente-iam.mateo.solutions`. Salida nueva `DominioCloudFront`: el destino de los alias.
- La pila no crea registros DNS.

La CSP y las cabeceras no cambian: la CSP usa `'self'`, que sigue a la URL, y la pagina construye su URL de retorno con
`location.origin`. No hace falta reconstruir ni volver a subir los ficheros.

### 5. Cognito acepta solo el dominio (propuesta de Claude, a confirmar por Mateo; escrito el 26-10-2026)

El patron de `UrlRetornoWeb` en `infra/cfn/acceso.yaml` admitia solo `https://<id>.cloudfront.net/`. Ahora admite eso o,
exactamente, `https://agente-iam.mateo.solutions/`. Ningun otro dominio: la URL de retorno es a donde Cognito manda el
codigo de login, y un patron abierto dejaria que un error o un rol de despliegue comprometido lo mandara a otro sitio.

Al desplegar, `UrlRetornoWeb` pasa al dominio. El login solo funciona ahi, donde rige TLS 1.2. La URL `*.cloudfront.net`
sigue sirviendo la pagina (CloudFront no la apaga), pero Cognito rechaza esa URL de retorno: ningun token pasa por ese
nombre. Medido el 27-10-2026 (`docs/MEDICIONES.md` P.6): `*.cloudfront.net` tambien rechaza TLS 1.0 y 1.1, asi que una funcion de CloudFront
que redirija ese nombre al dominio seria solo por comodidad, no por TLS.

### 6. La politica de seguridad: `TLSv1.2_2021` (propuesta de Claude, a confirmar por Mateo)

Es la que la plantilla ya declaraba, la que AWS recomienda como minimo y la que usa la pagina personal. Con `sni-only`
existen tambien `TLSv1.2_2025` y `TLSv1.3_2025`. Cambiarla es una linea de la plantilla y su test.

### 7. Orden de despliegue

Cada escritura, con el si de Mateo.

1. **Mateo, consola de `agente-iam`, `us-east-1`:** ACM, solicitar certificado publico para `agente-iam.mateo.solutions`,
   validacion DNS. Anota el nombre y el valor del CNAME y el ARN.
2. **Mateo, consola de gestion:** en la zona `mateo.solutions`, el CNAME de validacion. Espera a que el certificado quede
   `ISSUED` (minutos).
3. **Operador:** change set de `agente-iam-web` con `DominioWeb`, `CertificadoArn` y `DominioCognito` en `UsePreviousValue`. Se
   espera solo Modify de `Distribucion`, sin reemplazo. Si falla por permisos del rol de despliegue sobre el certificado (sin
   medir, punto 9), se para y el administrador anade lo que diga el error.
4. **Mateo, consola de gestion:** alias A y AAAA de `agente-iam` hacia la salida `DominioCloudFront`.
5. **Operador:** change set de `agente-iam-acceso` con `UrlRetornoWeb` = `https://agente-iam.mateo.solutions/` y lo demas en
   `UsePreviousValue`. Se espera Modify de `ClienteWeb` sin reemplazo: si el change set dijera reemplazo, cambiaria el id del
   cliente y habria que tocar tambien el runtime y el proveedor OIDC. Se para y se revisa.
6. **Medir** (punto 8).

Los pasos 4 y 5 pueden ir en cualquier orden; hasta los dos, el login sigue en la URL de CloudFront. Vuelta atras:
`UrlRetornoWeb` a la URL de CloudFront y los dos parametros de la web vacios. El certificado se puede quedar.

### 8. Que se mide para dar el pendiente por cerrado

- `GetDistribution`: `Aliases` con el dominio y `ViewerCertificate` con el ARN, `sni-only` y `TLSv1.2_2021`.
- `curl -I https://agente-iam.mateo.solutions/`: `200` con la CSP y las demas cabeceras; HTTP redirige a HTTPS.
- El saludo TLS: un cliente que ofrezca solo TLS 1.0 o 1.1 no conecta al dominio. En O.4 el OpenSSL local no negociaba TLS
  1.1, asi que el resultado negativo no probaba nada; hay que usar una herramienta que si lo ofrezca (por ejemplo
  `openssl s_client -tls1_1` con `@SECLEVEL=0`, o `testssl.sh`) y anotar cual.
- Lo mismo contra `*.cloudfront.net`, para saber que politica le queda a ese nombre (punto 5).
- Preflight `OPTIONS` a `/oauth2/token` de Cognito con el origen nuevo: medido (P.7), devuelve el dominio, pero devuelve tambien
  cualquier otro origen; no es una barrera (ESTUDIO §25). La barrera es la URL de retorno: con la vieja, `redirect_mismatch`.
- El flujo entero en el navegador desde el dominio, y el login desde `*.cloudfront.net` rechazado por Cognito.

### 9. Permisos del rol de despliegue

Ninguno nuevo para ACM ni Route 53: el certificado y los registros los hace Mateo. Medido el 27-10-2026 (`docs/MEDICIONES.md` P.6):
asociar el certificado a la distribucion no exige al rol de despliegue ningun permiso de ACM; el change set se ejecuto sin errores
de permisos.

### 10. Tests que lo atan (escritos el 26-10-2026)

- `tests/seguridad/test_pila_web.py`: sin parametros, certificado por defecto; con ellos, ACM, `sni-only` y TLSv1.2_2021; el
  alias solo con dominio; dominio y certificado juntos o ninguno; el dominio solo admite el subdominio del agente; el
  certificado, solo un ARN de ACM de `us-east-1`; las salidas, con `DominioCloudFront`. Se pusieron en rojo cambiando
  `sni-only` y abriendo el patron del dominio.
- `tests/seguridad/test_pila_acceso.py`: el patron acepta CloudFront y el dominio con `https` y barra final, y rechaza `http`,
  la falta de barra, una ruta, el apice, `www` y cualquier otro nombre.

## Consecuencias

- La pagina queda con TLS 1.2 como minimo en su nombre publico, con certificado de renovacion automatica.
- El agente depende de tres registros en la zona de gestion. Si se borran los alias, el dominio deja de resolver; si se
  borra el CNAME de validacion, ACM no renueva.
- El nombre del dominio de Mateo entra en lo versionado (patrones y documentacion). Es publico; el numero de cuenta y los
  ids de zona, certificado y distribucion siguen fuera, en `local/`. Cambiar de dominio es cambiar los dos patrones y sus
  tests, a proposito.
- Para SES con dominio propio (otro pendiente) habria que anadir sus CNAME de DKIM tambien en la zona de gestion. Es otra
  fase y otra decision.

## Lo que no cierra

- La URL `*.cloudfront.net` sigue existiendo (punto 5).
- La pagina personal y su distribucion no se tocan ni se revisan aqui.
- SES con dominio propio y la salida del modo inicial de SES.

## Fuentes

- CloudFront, ajustes de la distribucion (certificado por defecto = TLSv1; politicas disponibles con `sni-only`):
  https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/DownloadDistValuesGeneral.html
- CloudFront, nombres de dominio alternativos (el certificado tiene que cubrir el nombre):
  https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html
- Certificado de ACM para CloudFront en us-east-1: https://repost.aws/knowledge-center/migrate-ssl-cert-us-east
- Alias de Route 53 a CloudFront (`Z2FDTNDATAQYW2`; A y AAAA con IPv6):
  https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-route53.html y https://aws.amazon.com/cloudfront/faqs/
- Alias hacia un recurso de otra cuenta (se escribe el nombre de CloudFront): https://repost.aws/knowledge-center/route-53-no-targets
- Precio de CloudFront por uso y nivel gratuito por cuenta: https://aws.amazon.com/cloudfront/pricing/pay-as-you-go/
- Permisos para asociar un certificado en la consola: https://repost.aws/knowledge-center/install-ssl-cloudfront
