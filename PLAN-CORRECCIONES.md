# Plan de correcciones: Agente IAM

Acordado el 28-08-2026, tras la revision completa del proyecto. Complementa a
`CONTEXTO.md`: este archivo lleva el plan y el estado de cada fase; el CONTEXTO
lleva la arquitectura, las decisiones y los pendientes vigentes (§11).

- Una entrada de 5 a 25 lineas por fase (regla de `CLAUDE.md`): que, por que,
  como se verifico y que queda pendiente, con su responsable. La Fase 15, que
  reune los bloques citados desde fuera, es mas larga.
- Las mediciones contra la cuenta o servicios reales viven en
  `docs/MEDICIONES.md`; aqui queda una frase y el enlace a su seccion.
- Reparto: el codigo se escribe y se explica pieza por pieza; la parte de
  consola es de Mateo. El historial completo de este documento esta en git
  (commit `8cb3c42`).

## Los 7 hallazgos que este plan corrige

1. El `principal_arn` de la propuesta no se verifica contra la identidad.
2. Campos "confiables" no cerrados (`recurso`, `region` son str libres) y
   delimitador de la justificacion falsificable.
3. Sin coherencia entre servicio solicitado y acciones propuestas.
4. Lista negra con huecos de escalada; Deny del rol sin varios verbos.
5. La identidad compara solo el nombre, nunca el ARN completo (la cuenta
   declarada no se contrasta; los principals con path fallan).
6. Un error en vuelo no deja registro (sin try/except antes de guardar).
7. El simulador corre sin `ContextEntries` y sin leer `MissingContextValues`:
   las `Condition` no se ejercen de verdad.

## Tabla de fases (estado al 18-11-2026)

Las fases 0 a 9 estan en el primer commit del repositorio (`cb7b7ec`, 20-10-2026). Los hashes de commit de esta tabla y de los demas
documentos son del repositorio privado de origen: la version publica nace de un solo commit (Fase 33) y no los contiene.

| Fase | Que | Estado | Fecha | Commit |
|---|---|---|---|---|
| 0 | Red de seguridad: tests | Hecha | 28-08-2026 | `cb7b7ec` |
| 1 | Contratos de entrada | Hecha | 28-08-2026 | `cb7b7ec` |
| 2 | Chequeos deterministas posteriores | Hecha | 28-08-2026 | `cb7b7ec` |
| 3 | Identidad con fuente de verdad | Hecha | 28-08-2026 | `cb7b7ec` |
| 4 | Registro siempre, incluso en fallo | Hecha | 28-08-2026 | `cb7b7ec` |
| 5 | Simulador con contexto real | Hecha | 28-08-2026 | `cb7b7ec` |
| 5b | Deteccion propia de condiciones sin evaluar | Hecha | 28-08-2026 | `cb7b7ec` |
| 5c | `redundancia` deja de leer el reporte ajeno | Hecha | 29-08-2026 | `cb7b7ec` |
| 5d | El agregado pesimista del simulador | Hecha | 30-08-2026 | `cb7b7ec` |
| 6 | Listas de bloqueo | Hecha; Deny aplicado en consola y verificado | 28-08-2026 | `cb7b7ec` |
| 7a | Aprobacion humana | Hecha | 29-08-2026 | `cb7b7ec` |
| 7b.0 | `principal_id` | Hecha | 30-08-2026 | `cb7b7ec` |
| 7b.1 | El aplicador | Hecha y ejecutada en la cuenta | 30-08-2026 | `cb7b7ec` |
| 7b.4 | Jerarquia asignar/crear | Absorbida por 7b.1; la jerarquia sigue sin hacer | 30-08-2026 | |
| 8 | Servidor, empaquetado y plan de despliegue | Hecha en codigo; nada existe en la cuenta | 31-08-2026 | `cb7b7ec` |
| 9 | Revision contra la logica de evaluacion de IAM | Hecha en codigo; pendientes de consola | 20-10-2026 | `cb7b7ec` |
| 9b | Documentacion al dia y regla de mantenerla | Hecha | 20-10-2026 | `4fbb1a9` |
| 9c | Higiene del repositorio | Hecha; pendiente de Mateo | 20-10-2026 | `9845101`, `c4887aa` |
| 10 | Diseno de la version de portafolio | Decisiones tomadas; se ejecuta en 10a, 10b y 15 | 20-10-2026 | `9845101` |
| 10a | Guia de las pruebas de AgentCore | Hecha; ejecutada el 23-10-2026 (Fase 15) | 20-10-2026 | `32933b6`, `d954b40` |
| 10b | Landing zone con Control Tower | Hecha; quedan pasos de Mateo | 22-10-2026 | `3975846`, `1aa0d2d` |
| 11 | Tres tipos de tests, con su evidencia | Hecha; funcionales sin revisar | 20-10-2026 | `75cb0ef` |
| 12 | CI en GitHub y analisis estatico | Hecha | 22-10-2026 | `95014f3` |
| 13 | Versiones exactas, ruff y mypy | Hecha | 22-10-2026 | `b4f6c85` |
| 14 | Tests que pueden fallar | Hecha | 22-10-2026 | `ae2f182`, `753ab35` |
| 15 | Pruebas en `agente-iam`, ADR e IaC | Hecha: bloques 1 a 4; el bloque 3 se cerro en las Fases 18 a 20 | 22-10-2026 | `fffd177` a `10ff080` |
| 16 | Orden del repositorio | Hecha y fusionada | 23-10-2026 | `7d21e12`, `093de75` |
| 17 | Revision del 24-10-2026 | Hecha | 24-10-2026 | `7968aac`, `8cb3c42`, `a8f8a78`, `33dfd82` |
| 18 | Techo, decisiones de aprobacion y pila base | Hecha: tareas 1 a 6; el codigo de ADR-003 es la Fase 19 | 24-10-2026 | |
| 19 | Aprobacion en servidor y separacion por persona (ADR-003) | Hecha: codigo, revision, despliegue y M1 a M4; M5 y pendientes 2 y 3 del ADR abiertos | 24-10-2026 y 25-10-2026 (UTC) | `c9be954` a `cb19328`, `156f03e` |
| 20 | Pilas acceso y runtime, aplicador como Lambda y bloque 4 | Hecha y fusionada (`58e085d`) | 25-10-2026 (UTC) | `93e1142` a `60eea2b` |
| 21 | Prueba de fuego de punta a punta y remates | Hecha: paquetes con S5 desplegados, req-022 aplicada por la Lambda, retencion, SNS y filas de prueba | 25-10-2026 (UTC) | |
| 22 | Trail de datos, camino de fallo del aplicador, ejemplos y ESTUDIO §19 | Hecha; funcionales corridos con la puerta nueva (M.4) y los doce casos de §8 por el runtime (M.5); decision de Mateo: el prompt (con el si de Mateo) | 25-10-2026 (UTC) | |
| 23 | Formulario web, rol por persona con caducidad y aviso por correo | Hecha: los tres bloques desplegados y medidos, vencimiento real incluido (O.1 a O.6); TLS 1.2 con dominio propio y spam de Gmail pendientes | 26-10-2026 (UTC) | |
| 24 | Guia visual de la arquitectura | Hecha | 26-10-2026 | `f4b7865` |
| 25 | Version en ingles de la guia visual | Hecha | 26-10-2026 | `a6db5ef` |
| 26 | Carpeta del portafolio | Hecha | 26-10-2026 | `0a8812d` |
| 27 | Dominio propio para la pagina y TLS 1.2 | Hecha: TLS 1.2, dominio, Cognito y flujo en el navegador medidos (P y Q.1) | 27-10-2026 | `0a8812d` |
| 28 | Solicitud en texto, recurso comprobado y motivo de cada estado | Desplegada y medida el 27-10-2026 (R.1 a R.11); quedan pendientes menores | 27-10-2026 | `0a8812d` |
| 29 | Vista previa de la pagina en LinkedIn (Open Graph) | Hecha: etiquetas e imagen subidas y medidas (S) | 27-10-2026 | `0a8812d` |
| 30 | La fila "Rol previsto" solo donde puede haber rol | Hecha: pagina subida y medida (T); vista en el navegador con una solicitud rechazada el 02-11-2026 (V.2) | 27-10-2026 | `404f67a` |
| 31 | Prompt de s3: un intento en vez de dos | Hecha: medida en local (U.1), runtime v6 desplegado (U.2) y medida en vivo el 02-11-2026 (V.1) | 28-10-2026 | `7750f28` |
| 32 | Video de demostracion de punta a punta | Hecha: grabado, montado, revisado y en portafolio (V) | 02-11-2026 | `785e390` |
| 33 | Auditoria de seguridad y revision para publicar el repositorio | Hecha: pasada parcial, 0 confirmados y 4 pistas sin confirmar (W); el repositorio de origen no se publica y la version publica nace de un solo commit; arreglos de codigo de la pista 3 y de tres notas escritos, sin desplegar | 18-11-2026 | `06b3785` |

## Fases

### Fase 0 - Red de seguridad: tests

`pytest` sobre las funciones puras de las barandas, sin red ni cuenta AWS (el
catalogo se sustituye con monkeypatch). Los casos adversarios de `ejemplos/`
quedan congelados como tests. Nuevos: `tests/`, `conftest.py`,
`requirements-dev.txt`. Por que: ninguna fase siguiente se toca sin poder detectar
que algo se rompe. Pendiente: nada.

### Fase 1 - Contratos de entrada

Principio: cerrar lo cerrable, restringir lo que no, aislar lo libre. `models.py`
fija patrones estrictos para `solicitud_id` (tambien tapa el path traversal),
`principal_arn_declarado`, `servicio`, `region` y `recurso`, y un tope a
`justificacion`. La validacion semantica (servicio permitido, principal existe)
queda en `chequeos_previos`, que deja registro; Pydantic solo rechaza la forma
invalida. `orquestador._prompt` inserta la justificacion con `json.dumps`, y un
salto de linea real pasa a `\n` literal: el delimitador no se puede falsificar.
`cli.py` da mensaje legible y salida 2. Pendiente: nada.

### Fase 2 - Chequeos deterministas posteriores

`chequeos_posteriores()` (hoy en `coherencia.py`) alimenta el mismo loop de
reparacion: (1) el `principal_arn` de la propuesta es el ARN verificado; (2) toda
accion Allow pertenece al servicio solicitado; (3) el nivel de acceso encaja con
el catalogo (`IsWrite`/`IsPermissionManagement`; `lectura` no admite ninguna).
Pendiente: nada.

### Fase 3 - Identidad con fuente de verdad

`identidad.py` toma el nombre del ultimo segmento del path, llama a
`get_user`/`get_role` y compara el `Arn` que devuelve la API con el declarado; si
difieren (cuenta, path) queda `existe=False` con motivo. Lo demas usa el ARN
devuelto por IAM, nunca el declarado. Pendiente: nada.

### Fase 4 - Registro siempre, incluso en fallo

`try/except` por fase en `procesar()`: ante una excepcion queda un registro con
`estado: "error"`, fase, tipo, detalle, traza, historial parcial y propuesta si
existia. No relanza (`guardar()` no correria) y captura `Exception`, no
`BaseException`. Salidas del CLI: 0 procesada, 1 error de corrida, 2 forma
invalida. Pendiente: nada.

### Fase 5 - Simulador con contexto real

`simulacion.py` simula con `ContextEntries`: `aws:RequestedRegion` (formulario),
`aws:PrincipalAccount` y `aws:PrincipalArn` (identidad verificada). El tipo de cada
clave sale de `_TIPO_DE_CLAVE`; lo que no esta en la tabla no se aporta. Con
`ResourceArns` las claves faltantes salen en `ResourceSpecificResults`, asi que se
leen los dos sitios. Entro tambien la paginacion.

La asimetria, lo importante de la fase: la misma duda se resuelve al reves en cada
funcion. En `eficacia`, una accion permitida con claves sin resolver va a
`acciones_condicionales` (concede algo, con aviso); bloquearla seria un falso
positivo. En `redundancia` queda en `acceso_nuevo`; declarar redundante por error
deja sin acceso a quien lo necesita.

Medido contra la cuenta el 28-08-2026 (cinco pruebas): las `Condition` se evaluan
cuando llega el contexto, el simulador deniega y reporta la clave que falta, y
`aws:RequestedRegion` tiene un valor implicito (la region del endpoint) que da
`allowed` sin reportar nada (`docs/MEDICIONES.md`, seccion A.1). Pendiente: repetir
la prueba 1 con otra region (no medido, sin fecha).

### Fase 5b - Deteccion propia de condiciones sin evaluar

Por el valor implicito de `aws:RequestedRegion`, la deteccion la hace nuestro
codigo: `_claves_de_condicion()` lee los bloques `Condition` y `_sin_aportar()` resta
las claves aportadas; lo que reporte el simulador se suma. Con claves sin resolver
ninguna decision es concluyente: la accion va a `acciones_condicionales`, nunca a
`acciones_sin_efecto`. Los `...IfExists` no cuentan como duda. Pendiente: nada.

### Fase 5c - `redundancia` deja de leer el reporte ajeno

Salio de la verificacion en vivo: las corridas marcaban el 100 % de las acciones como
no concluyentes por `aws:CalledViaLast`, venida de una politica gestionada de
`ana.gomez` que condiciona un statement de SageMaker. `MissingContextValues` lista las
claves de los statements que el simulador considero, no las que decidieron
(`eficacia` usa `SimulateCustomPolicy`, donde todo lo considerado es nuestro
documento; `redundancia` usa `SimulatePrincipalPolicy`). Segunda pieza: un `allowed`
es concluyente por construccion, porque con una clave sin valor el simulador deniega.
Por eso `redundancia` ya no lee el reporte y queda con dos cubos: `allowed` es
`ya_tenia`, todo lo demas `acceso_nuevo`. La asimetria de la Fase 5 sobrevive. Leccion:
una advertencia encendida el 100 % de las veces equivale a no tener advertencia.
Medido el 29-08-2026 (`docs/MEDICIONES.md`, seccion A.2). Pendiente: nada.

### Fase 5d - El agregado pesimista del simulador

Salio de verificar `req-012-jose`. Con varios `ResourceArns`, el `EvalDecision` de nivel
superior deniega si deniega para alguno; la verdad por recurso esta en
`ResourceSpecificResults` (`docs/MEDICIONES.md`, seccion A.4). Importa porque en S3
`ListBucket` aplica al ARN del bucket y `GetObject` al del objeto, y el modelo a veces
los funde. En `eficacia` no mordia; en `redundancia` subdeclaraba `ya_tenia` (direccion
segura, pero incorrecta). Arreglo en `_permitida_en_algun_recurso()`, usada por las
dos. Pendiente: nada.

### Fase 6 - Listas de bloqueo

- `config.py`: `ACCIONES_PROHIBIDAS` crece con 13 acciones de escalada (entre ellas
  `iam:AddUserToGroup`, `iam:CreateLoginProfile`, los cuatro verbos de permission
  boundary, `iam:SetDefaultPolicyVersion`, `sts:AssumeRoleWith*`,
  `lambda:UpdateFunctionCode`, `lambda:AddPermission`).
- `infra/` (consola, Mateo): el Deny del rol `AgenteIAM-Analista` suma `iam:Upload*`,
  `Change*`, `Enable*`, `Deactivate*`, `Reset*`, `Resync*`, `iam:PassRole` y
  `sts:AssumeRoleWith*`.

Verificado contra la cuenta el 28-08-2026: el error pasa de "no identity-based policy
allows" a "explicit deny" (`docs/MEDICIONES.md`, seccion B.2). Pendiente: nada.

### Fase 7a - Aprobacion humana

`python -m agente_iam.aprobar <id>`, con credenciales de humano. Ocho pasos: (1) una
sola lectura, de la que salen la pantalla y la huella (dos serian un TOCTOU); (2)
compuerta de estado por lista blanca; (3) identidad del aprobador desde
`sts:GetCallerIdentity` (usuario, rol asumido confirmado con `iam:GetRole` y `RoleId`, o
no determinable); (4) separacion de funciones: iguales o no determinable bloquea, y
`--autoaprobacion-demo` es la unica puerta y graba que control se salto; (5)
revalidacion con las reglas de hoy; (6) `CheckNoNewAccess` contra `AgenteIAM-Techo`, la
unica llamada de pago; (7) huella SHA-256 del registro menos `aprobacion`, `aplicacion`
y `estado`; (8) escritura que no pisa una decision humana. Ademas, friccion por
`nivel_riesgo` (solo puede anadirla).

Bug que los unitarios no cogieron: `estado` entraba en la huella y luego cambiaba a
`aprobada`, asi que la huella guardada no verificaba nunca y el aplicador habria
rechazado el 100 %. El estado no debe entrar en la firma. Hoy hay test de integracion.
Verificado contra la cuenta el 29-08-2026 (`docs/MEDICIONES.md`, seccion B.3).
Pendiente: nada.

### Fase 7b.0 - `principal_id`

`IdentidadVerificada` gana `principal_id` (el `UserId`/`RoleId` que `GetUser`/`GetRole`
ya devuelven, sin llamadas nuevas), que entra en la huella. Cierra la ventana
borrar-y-recrear: entre aprobar y aplicar, alguien puede borrar `ana.gomez` y crear
otra con el mismo ARN. En la Fase 3 el nombre no bastaba; aqui el ARN no basta.
Pendiente: nada.

### Fase 7b.1 - El aplicador

`agente_iam/aplicador.py`: pre-vuelo (lectura), observar AWS, decidir, actuar,
registrar. Sin marcador de intencion: el nombre determinista `agente-iam-<solicitud_id>`
y la verificacion del contenido hacen que converja desde cualquier punto de muerte. Sin
`iam:DeletePolicy` (una politica sin adjuntar no concede nada).

- La `Description` (con id y huella) es la unica evidencia que sobrevive a reescribir el
  JSON: no existe `UpdatePolicy` y es inmutable. Los tags no valen como evidencia
  (`TagPolicy` y `UntagPolicy` existen); sirven de compuerta con
  `aws:RequestTag/agente-iam-solicitud`.
- El permission boundary va en los principals destino, no en el aplicador: un boundary
  sobre el aplicador limita lo que este hace, no lo que concede. Lo cierran `iam:PolicyARN`
  (solo politicas de nuestro path) e `iam:PermissionsBoundary` (solo principals con el
  techo).
- Tres huecos hallados contra la documentacion: el nombre de politica es unico en la
  cuenta y no por path (cuarto estado de `crear()`); no distingue mayusculas (se
  normaliza y se comprueba la procedencia); la cuota puede estar ampliada (el pre-vuelo
  solo avisa; manda el `LimitExceeded`).
- Solo aparece ejecutando: `CreatePolicy` con `Tags` exige ademas `iam:TagPolicy`. Se
  anadio al rol, con un Deny de `iam:UntagPolicy`.

Ejecutado el 30-08-2026 contra la cuenta (`docs/MEDICIONES.md`, secciones B.4 y B.5):
`req-012-jose` recorrio intake, aprobacion y aplicacion (comprobado con el simulador sobre
sus permisos reales), y el reintento tras morir a mitad convergio sin duplicar nada.
Pendiente: la cuota de politicas de la cuenta no esta medida.

### Fase 7b.4 - Jerarquia asignar/crear

Lo previsto aqui (leer solo `aprobada`, recalcular la huella, revalidar, `CreatePolicy`
bajo `/agente-iam/`, `AttachUserPolicy`, registrar, sin hablar con el LLM) es el
aplicador de la 7b.1, ya hecho. Sin hacer: la jerarquia asignar/crear y los permisos con
caducidad (implementables como `Condition`, `docs/MEDICIONES.md`, seccion A.3); viven en
`CONTEXTO.md` §11.

### Fase 8 - Servidor, empaquetado y plan de despliegue

Preparacion del despliegue del analista en AgentCore Runtime (31-08-2026), sin desplegar.

- `agente_iam/servidor.py`: el entrypoint HTTP. Es la misma pieza que `cli.py` con otra
  puerta, sin reglas de negocio, para que la version desplegada y la local sean el mismo
  sistema. `main.py` es el `entryPoint` (por `sys.path`) y fija el catalogo desde
  `__file__`; un test vigila el orden de sus imports.
- `scripts/empaquetar.sh` (en la raiz hasta la Fase 16): zip aarch64 con el catalogo
  dentro, sin Docker ni ECR. `infra/rol-runtime-*.json` (retirados el 24-10-2026; los sustituye
  `infra/cfn/base.yaml`) y `docs/DESPLIEGUE.md` (7 pasos).
- Decision: solo se despliega el analista. `aprobar` es un acto humano (bajo el rol del
  runtime el aprobador seria el rol) y `aplicador` escribe en IAM (junto a texto no
  confiable, una inyeccion seria una escalada).
- Hallazgos: el SDK comprueba el nombre del parametro `context`, no su posicion; con
  `ALMACEN=disco` desplegado el rastro se perderia con el microVM, por eso el servidor para
  al arrancar; con SigV4 el codigo no sabe quien invoco (la cabecera de usuario no esta
  verificada), asi que `ejecutado_por` queda como no determinable (lo resuelve el JWT del
  ADR-001).

Verificado con `tests/unitarios/test_servidor.py` (sin servidor ni SDK); el empaquetado
entero se probo el 24-10-2026 en una copia fuera del repo (Fase 17, O5). Nada de esta
fase existe en la cuenta (`CONTEXTO.md` §5). Pendiente: la guia y los JSON de rol se
sustituyen por las pilas del bloque 3 (Fase 15), que escribe Claude y despliega el
operador con el si de Mateo.

### Fase 9 - Revision contra la logica de evaluacion de IAM

Salio de cruzar techo, lista negra, catalogo y coherencia. Permisos efectivos = politica de
identidad interseccion boundary, menos cualquier Deny.

Hallazgo de fondo: el techo v1 no recortaba. Permitia enteros los mismos ocho servicios que
`SERVICIOS_PERMITIDOS`, asi que toda propuesta coherente era subconjunto suyo; su Deny era
el unico recorte, y `CheckNoNewAccess` contra el solo fallaba con lo que la lista negra ya
bloquea (`docs/MEDICIONES.md`, seccion E.1).

Arreglado en codigo:
1. Recurso (`coherencia.fuera_del_recurso`): nada comparaba `Resource` con `campos.recurso`.
2. Nivel: ningun `tipo_acceso` concede `IsPermissionManagement`.
3. `lambda:UpdateFunctionConfiguration` y `ec2:ModifyInstanceAttribute` (escalada sin
   PassRole) a la lista negra y al Deny del techo.
4. Requisito de alta: rechazo en `chequeos_previos` si el principal no lleva el techo; el
   aplicador lo repite.
5. `eficacia` simula bajo el boundary del principal.
6. La huella ata lo leido con lo firmado: `aprobar` exige `--huella` igual a la del registro
   que acaba de leer.
7. Aplicador: `NameError` tras toda aplicacion exitosa; `crear` adjuntaba sin decidir si otro
   proceso creaba la politica; quien aplica se identifica antes de escribir.
8. `techo()` solo cae al archivo local con `NoSuchEntity`; `chequeos_posteriores` pasa a
   `coherencia.py`.

Verificado el 20-10-2026: 190 tests, cada arreglo deshecho pone el suyo en rojo; intake en
vivo (`ana.gomez` rechazada sin invocar al modelo por no llevar el techo; `jose.torres`
`redundante_no_requiere_cambio`).

La inline vieja `AgenteIAM-AplicadorPolicy` del rol Aplicador la borro Mateo el 24-10-2026
(`docs/MEDICIONES.md`, seccion G.7). El techo antiguo de gestion se retiro en el bloque 4 de la Fase 15 (25-10-2026,
Fase 20; no se publico una v3), con `ana.gomez` y `jose.torres`. De Claude: redirigir a beneficiarios con techo
los ejemplos que apuntan a `user/Mateo`, `ana.gomez` o `jose.torres`, que se paran en chequeos previos
(`ejemplos/solicitud-finanzas-demo.json` ya apunta a `role/app-finanzas-demo`).

### Fase 9b - Documentacion al dia y regla de mantenerla

README, CONTEXTO y DESPLIEGUE puestos al dia, y P16 ("un techo que contiene todo lo que concedes
no es un techo") en la seccion 2 del ESTUDIO, desarrollado en la 16. La regla queda en `CLAUDE.md`: ningun
avance se cierra sin actualizar la documentacion. `tests/unitarios/test_documentacion.py`
vigila lo mecanico (cada modulo en README y CONTEXTO, cada fichero de tests en CONTEXTO §6,
el orden de imports de `main.py`); verificado que falla si se quita un modulo del README o
se sube el import. Hallazgo: casi todo el corpus de `ejemplos/` apuntaba a `ana.gomez` o a
`user/Mateo`, que entonces no llevaban el techo (Fase 9). Pendiente: nada.

### Fase 9c - Higiene del repositorio

El primer commit (`cb7b7ec`, GitHub privado) se reviso entero: sin credenciales, tokens,
claves ni `.env`; lo unico publicable de mas era el numero de cuenta, en 32 archivos. La
cuenta real se sustituye por `111122223333` en todo lo versionado y `scripts/localizar.py`
genera en `local/` las copias con la real. `.gitignore` suma `local/`, `respuesta*.json`,
`*.zip`, `*.p12` y `*.tfstate*`. `tests/seguridad/test_secretos.py` vigila credenciales
conocidas y la cuenta real (verificado plantando una clave falsa y la cuenta: los dos en
rojo). El pre-commit lleva gitleaks. Secret scanning y push protection de GitHub no estan
disponibles en repositorios privados de cuentas personales: la barrera es gitleaks, en
pre-commit y en CI. Pendiente, de Mateo: decidir si reescribir el historial (el commit
inicial conserva la cuenta real, que no es un secreto; solo importa si el repositorio se
hace publico) y el correo `noreply` de GitHub; al final, con confirmacion explicita.

### Fase 10 - Diseno de la version de portafolio

Objetivo (20-10-2026): dejar el agente listo para un portafolio y una entrevista tecnica;
pilares, en palabras de Mateo: menos administracion manual y seguridad.

| # | Decision | Motivo |
|---|---|---|
| 1 | Beneficiario: roles IAM de aplicaciones | Una politica adjunta a un rol es permanente. El acceso temporal de personas (permission sets) queda para despues: el agente crea el permiso una vez y las elevaciones siguientes lo reutilizan sin llamar al modelo |
| 2 | Humanos: IAM Identity Center en una Organization | La instancia de cuenta no admite permission sets (doc). La cuenta actual es la de gestion, sin cargas; el sistema corre en una cuenta miembro |
| 3 | Interfaz: linea de comandos con SSO primero | La web, despues |
| 4 | TEAM (AWS Samples) no se usa | Exige CloudTrail Lake (cerrado a clientes nuevos desde 31-05-2026) y cuenta delegada propia, es mas pesado que el sistema entero y solo asigna permisos existentes. Queda como referencia |
| 5 | Auditoria: trail de organizacion y cuenta Log Archive con Control Tower | La practica recomendada por AWS (`docs/CONTROL-TOWER-CHECKLIST.md`) |
| 6 | La web entra como entregable | Decision de Mateo, valide o no AgentCore los tokens de Identity Center |
| 7 | Computo del analista: AgentCore Runtime con autorizador JWT | El emisor de tokens de la web se reutiliza; la CLI tambien obtendra un token. Va como ADR |

Sin decidir: el canal de entrada de solicitudes (por ahora CLI). La IaC se resolvio en la
Fase 15 (CloudFormation). Coste previsto de Config: `docs/MEDICIONES.md`, seccion G.6;
estado de partida de la cuenta: seccion G.1. Pendiente: la reescritura del historial de git
(Fase 9c).

### Fase 10a - Guia de las pruebas de AgentCore

Escrita el 20-10-2026 sin tocar ninguna cuenta; ejecutada el 23-10-2026 (Fase 15).
`docs/PRUEBAS-AGENTCORE.md` define dos pruebas, cada una con objetivo, pasos, criterio,
coste y como deshacerla: la A (tokens de Identity Center directos, comprobacion corta y sin
coste) y la B (Cognito federado con Identity Center por SAML, runtime del eco con
`customJWTAuthorizer`, tres invocaciones: token valido, sin token, token alterado).
`infra/pruebas-agentcore/agente_eco.py` devuelve los claims validados y el ARN de sesion
del rol, nunca el token; su rol es un subconjunto literal del del runtime
(`tests/unitarios/test_agente_eco.py`). Segun la documentacion, la A no era viable; el
resultado medido esta en `docs/MEDICIONES.md`, seccion D.1. Verificado: nombres de API
contra botocore 1.43.116, precios con la API de precios, fragmentos con datos falsos en
local. Lo no verificado queda marcado **(sin verificar)** en la guia (seccion D.5).
Pendiente: nada de esta fase.

### Fase 10b - Landing zone con Control Tower

Paso 1 del orden de la Fase 10, con `docs/CONTROL-TOWER-CHECKLIST.md`. Consola: Mateo.
Lecturas y la politica de la clave KMS: Claude, a peticion de Mateo.

- Landing zone 4.0 lanzada el 22-10-2026, `ACTIVE` e `IN_SYNC`: `us-east-1` sola, archivo de
  logs y auditoria en cuentas aparte, clave `control-tower-logs` (rotacion cada 90 dias),
  retencion de 365 dias, trail de organizacion entregando de las cuatro cuentas
  (`docs/MEDICIONES.md`, secciones G.2 y G.3). La clave vieja `rare-trails-kms`, desactivada,
  se borra el 29-10-2026 (seccion G.6).
- Unidad `Workloads` registrada con la linea base 5.0 y cuenta `agente-iam` creada desde la
  consola (por API no respondio); acceso raiz centralizado; Account Factory sin VPC
  (seccion G.4).
- Identity Center y perfiles SSO `org-*` (seccion G.5). `AgenteIAM-Analista` y
  `AgenteIAM-Aplicador` confian solo en el permission set `AWSAdministratorAccess`
  (`test_confianza_roles.py`); los perfiles `agente-iam` y `agente-iam-aplicador` salen de
  `org-gestion`. La clave de acceso de `Mateo` se desactivo el 22-10-2026 y esta borrada
  (lectura del 24-10-2026); la raiz no tiene claves y tiene MFA. Los MCP de AWS usan
  perfiles SSO de solo lectura.
- Modelo: Haiku 4.5 por defecto tras 70 corridas contra Sonnet 4.6 (mismas reglas criticas,
  3,5 veces mas barato; seccion C.5), y el riesgo alto lo fija el codigo
  (`coherencia.riesgo_minimo`: administracion, otro principal en la justificacion,
  IAM/STS/Organizations, politica amplia o accion prohibida; `aprobar` lo recalcula; 11
  tests, 6 mutaciones en rojo). El riesgo que escribe el modelo solo anade friccion. El
  registro guarda `uso_modelo`; `scripts/comparar_modelos.py` repite la comparacion.
- Haiku 5.5 no responde: la cuota esta en 0, el aumento por Service Quotas da
  `IllegalArgumentException` y el camino es soporte (seccion C.4).
- Requisito para el ADR: la identidad del aprobador es la persona, no el rol del permission
  set. Orden acordado: pruebas de AgentCore, ADR, IaC con minimo privilegio, SCP del proyecto.

Haiku 5.5: AWS no lo aprobo para la cuenta (27-10-2026, segun Mateo); se sigue con Haiku 4.5 y 5.5 queda como
posibilidad futura (CONTEXTO §11).

Pendiente, de Mateo: decidir si el usuario IAM `Mateo`
conserva el acceso a consola con contrasena (decidido el 25-10-2026, bloque 4: lo conserva, hoy entra con el). Sin confirmar: que se borro la copia
local de las credenciales antiguas de `~/.aws` y que los MCP toman el perfil SSO al reiniciar
la app. Sin verificar: Config dentro de `audit` y `validate-logs` (seccion G.3).

### Fase 11 - Tres tipos de tests, con su evidencia

Que: los tests pasan a `unitarios/` (sin red, con dobles), `seguridad/` (los controles que
impiden conceder de mas, y el repositorio sin secretos) y `funcionales/` (el sistema contra
la cuenta real). Por que: separar lo que corre en cada commit de lo que toca la cuenta, y
llevarlo a CI sin redisenar. La carpeta manda y el marcador se deduce (`tests/conftest.py`);
evidencia en JUnit y texto en `evidencias/<tipo>/<fecha>/` (ignorada), con
`scripts/pruebas.sh <tipo>`. `tests/puerta.py`: los funcionales abren solo con
`AGENTE_IAM_FUNCIONALES=si`, `AWS_PROFILE` en lista blanca (`agente-iam`) y sin claves en el
entorno, en dos capas; ninguno escribe en la cuenta. `tests/dobles.py` reune las ayudas.

Hallazgos: `test_cada_fichero_de_tests_aparece_en_el_contexto` pasaba en vacio con `glob`
tras mover los ficheros (ahora `rglob` y lista no vacia); "todos sin red" era falso para el
test de la cuenta real, que llamaba a STS.

Verificado el 20-10-2026: 195 tests antes y 225 despues (223 pasan, 2 funcionales se
saltan); cada guardia nueva deshecha se pone en rojo. Los funcionales no se han corrido con
la puerta abierta; existe una carpeta de evidencia del 20-10-2026 cuyo contenido no se ha
releido (`docs/MEDICIONES.md`, seccion J). Pendiente: de Mateo, correr los funcionales y
revisar su evidencia; los del aprobador y el aplicador escriben en la cuenta y necesitan
puerta propia.

### Fase 12 - CI en GitHub y analisis estatico

`.github/workflows/pruebas.yml`: matriz `unitarios`/`seguridad` que llama a
`scripts/pruebas.sh` igual que en local y sube `evidencias/` como artifact; permisos
`contents: read`, checkout sin guardar el token, cada accion fijada por commit; los
funcionales no corren en CI. `scripts/pruebas.sh seguridad` suma bandit (SAST) y pip-audit.
Por que: el pre-commit se salta con `--no-verify`; el CI no.

Hallazgo (bandit B310, CONTEXTO §9 #31): el prefijo de servicio que escribe el modelo
acababa sin validar en una ruta y una URL; con `../secreto:Get` se leia un `.json` fuera de
la cache. Arreglo en `catalogo._cargar` con `[a-z0-9]+(-[a-z0-9]+)*` (`docs/MEDICIONES.md`,
seccion I). Verificado el 22-10-2026: sin el arreglo, 10 de los 14 tests de
`test_catalogo.py` en rojo; cada guardia de `tests/seguridad/test_ci.py` deshecha se pone en
rojo; simulacion del CI en local con copia limpia, sin credenciales ni catalogo. El CI corre
en GitHub desde ese dia. Pendiente: funcionales en CI (OIDC y rol propio), a decidir mas
adelante.

### Fase 13 - Versiones exactas, ruff y mypy

Por que: sin fijar las transitivas, el `.venv`, el CI y el paquete de AgentCore instalaban
versiones distintas; y faltaba analisis de correccion. Como: `constraints.txt` con la version
exacta de todo lo que se instala (con `-c` en el `.venv`, el CI y `empaquetar.sh`); pip-audit
audita ese fichero con `--no-deps`; ruff (`F`, `E9`, `B`, `PLE`) en el pre-commit y en
`scripts/pruebas.sh unitarios`; mypy poco estricto; runner `ubuntu-24.04` fijo.

Hallazgos (CONTEXTO §9 #33 a #35): auditando las versiones exactas aparecieron
vulnerabilidades en pyjwt, urllib3, certifi, mcp y opentelemetry-api que la auditoria anterior
no veia (`docs/MEDICIONES.md`, seccion I); ruff cazo 3 imports sin usar y un
`pytest.raises(Exception)` que aceptaba cualquier error; mypy dio 17 avisos (10 contratos
implicitos, ahora comprobados con test).

Verificado el 22-10-2026: 259 tests pasan y 2 se saltan; cada guardia nueva deshecha se pone
en rojo. No verificado: el agente contra el modelo real con mcp 1.30.0 y opentelemetry
1.45.1. Pendiente: hashes en `constraints.txt` (decision de Mateo, Fase 17) y endurecer mypy
por pasos (el paso 1 esta hecho, Fase 17 O7).

### Fase 14 - Tests que pueden fallar

Que: auditoria de la bateria por un agente, a peticion de Mateo, y relleno de huecos. Mateo
creia que sobraban tests; sobraban unos 8 duplicados exactos, pero varias compuertas de
seguridad no tenian ningun test que se pusiera rojo al borrarlas.

Verificado con un barrido de mutaciones (deshacer una linea de `agente_iam/`, correr la
bateria, restaurar con sha256) en copia aislada: 68 mutaciones de controles de seguridad, las
68 en rojo (`docs/MEDICIONES.md`, seccion I). Lineas que se podian borrar sin que nada se
pusiera rojo: el `if accion == "parar"` del aplicador (sin el, una politica existente con otro
documento se adjuntaba), seis controles de `aprobar.py`, `Action` o `Resource` como cadena en
`validacion.py` (recorridos letra a letra), la duda del catalogo, recursos que no son ARN y los
codigos de salida del CLI. Ningun bug destapado en `agente_iam/`.

Guardian contra AWS en `tests/conftest.py`: unitarios y seguridad cortan el envio HTTP de
botocore, con credenciales falsas, sin perfil, sin IMDS y sin ficheros de configuracion. El CI
dio 20 errores en `test_almacen.py` que en local no salian (habia perfiles SSO); reproducido con
un entorno vacio. Recuento (22-10-2026): 313 pasados y 2 saltados. Pendiente: nada; los bloques
de la auditoria sobre repetidos y tests de poco valor se trataron en la Fase 17, paso 2.

### Fase 15 - Pruebas en `agente-iam`, ADR e IaC

Estado (25-10-2026): los cuatro bloques hechos. Bloque 3: pilas de gobierno, identidades, arranque, base,
acceso, runtime y beneficiarios desplegadas (Fases 18 a 20); bloque 4: cuenta de gestion limpia, queda el usuario
IAM `Mateo` (Fase 20, `docs/MEDICIONES.md` K.4).

Que: el orden acordado al final de la Fase 10b, en cuatro bloques: (1) pruebas en `agente-iam`
(region de Bedrock, Prueba A, Prueba B); (2) ADR de AgentCore y especificacion, con el aprobador
como persona y no como rol; (3) infraestructura como codigo (roles del agente con minimo
privilegio, permission sets, usuarios de demo, SCP del proyecto); (4) limpiar la cuenta de gestion
cuando lo nuevo funcione. Decision de Mateo (22-10-2026): CloudFormation (YAML) y no CDK, por
evitar el bootstrap de CDK (bucket y roles en cada cuenta, tambien la de gestion) y por plantillas
legibles como los JSON de `infra/`. Los recursos de prueba se borran al terminar.

#### Bloque 1: Bedrock frente a la denegacion de regiones (22-10-2026 y 23-10-2026)

- Paso 0 (lectura): `agente-iam` vacia de lo nuestro; `AWSReadOnlyAccess` no lee AgentCore,
  `ListInferenceProfiles` ni Service Quotas (`docs/MEDICIONES.md`, seccion F.1); la SCP
  `GRREGIONDENY` no incluye acciones de Bedrock (seccion C.1).
- Paso 1: la prediccion (doc) se cumplio. Desde `agente-iam`, `Converse` con el perfil `global.`
  y con el `us.` de Haiku 4.5 fallan por SCP, ni con administrador; Haiku 4.5 solo va por perfil.
  En la cuenta de gestion funcionaba porque las SCP no le aplican (seccion C.1; ESTUDIO §13).
- Decision de Mateo (23-10-2026): la opcion (b), el control configurable `CT.MULTISERVICE.PV.1`
  con exencion de las dos acciones de invocacion de Bedrock y una SCP propia que solo deja pasar
  perfiles `us.` (datos en EE. UU., `global.` denegado); no la (a), gobernar `us-east-2` y
  `us-west-2`. Una SCP que "permita" no sirve: el Deny de Control Tower gana. La trampa de la SCP
  es una condicion `Null: false`; un Deny con operador negado e `IfExists` sigue denegando si falta
  la clave (ESTUDIO §14).
- `infra/cfn/gobierno-regiones.yaml` (una SCP y dos `EnabledControl`) con
  `tests/seguridad/test_gobierno_regiones.py` (25 tests, nueve mutaciones en rojo). Etapa 1:
  conjunto de cambios `etapa-1-pv1-y-scp-v2`, ejecutado con el si de Mateo, puerta en verde. Etapa
  2: Mateo apago en consola la denegacion de la landing zone. Matriz de 12 casos con
  `scripts/matriz_regiones.py`: **12 de 12** como se esperaba (`docs/MEDICIONES.md`, secciones C.2 y
  C.3). `MODEL_ID` pasa al perfil `us.` y los roles autorizan `inference-profile/us.anthropic.claude-*`
  (`test_perfiles_modelo.py`). La primera invocacion suscribe el acuerdo de Marketplace (seccion C.4).
- Limite: la matriz se hizo con el administrador SSO; con los roles reales (casos 1 a 4) es criterio
  de aceptacion del bloque 3, no medido entera. El 25-10-2026 el rol del runtime invoco el perfil `us.` y hubo que
  permitirlo en cualquier region (`docs/MEDICIONES.md` K.2, §H fila 35). Haiku 5.5: AWS no lo aprobo (27-10-2026); si algun dia se habilita, repetir
  `scripts/matriz_regiones.py --modelo us.anthropic.claude-haiku-5-5 --ejecutar` y la comparacion.

#### Bloque 1: Prueba A y Prueba B (23-10-2026)

- Prueba A: **no viable**; sin documento de descubrimiento y con tokens opacos, AgentCore no puede
  validar tokens de Identity Center: hace falta Cognito (`docs/MEDICIONES.md`, seccion D.1).
- Prueba B: pila temporal `agente-iam-prueba-eco` (`infra/cfn/prueba-eco.yaml`, dos despliegues con
  la aplicacion SAML en consola entre medias) y `scripts/prueba_b.py`. **Pasa** con Mateo y con
  `aprobador.demo` (200 con token; 401 sin token y con firma alterada). Hallazgo: la persona no llega
  al rol del runtime, solo viaja en los claims del JWT, y el evento de datos de CloudTrail guarda su
  `sub`; las llamadas sin token no dejan evento (secciones D.2 y D.3). Desmontada del todo, sin dejar
  nada en la cuenta (seccion D.4). Commit `2d48ec2`.
- La pila `agente-iam-identidades` (`infra/cfn/identidades.yaml`, gestion) crea `aprobador.demo`, que
  es definitivo (`DeletionPolicy: Retain`) y cuyo correo entra como parametro, fuera del repositorio.
  A Mateo no le llegan los correos de Identity Center: entra con una contrasena de un solo uso que
  genera el (hecho el 23-10-2026, con MFA).

#### Bloque 2: ADR y especificacion (23-10-2026)

`docs/ADR-001-agentcore-identidad.md`, aceptado por Mateo sin cambios: Cognito federado con Identity
Center por SAML, cliente publico con PKCE, runtime solo con JWT; alternativas descartadas con su
motivo; el registro lleva `sub`, `username` y `jti`. `docs/ESPECIFICACION-agentcore.md`: requisitos
de identidad, runtime, registro, separacion de funciones y auditoria, cada uno marcado como medido o
de diseno. Leccion en ESTUDIO §15. El segundo rol con `SourceIdentity` (exigiria aflojar el Deny de
`sts:AssumeRole` del rol del runtime; sin medir) es un diseno aparte, fuera del bloque 3.

#### Bloque 3: diseno aprobado (23-10-2026)

Mateo aprobo el diseno de la IaC. Al aprobarlo no habia nada escrito ni desplegado.

- Los roles beneficiarios viven en `agente-iam` y el aplicador escribe en el IAM de esa cuenta. Trail
  propio de eventos de datos de AgentCore Runtime en `agente-iam`, 90 dias: Identity Center registra el
  inicio de sesion pero no cada invocacion; el evento de datos lleva el `sub`.
- Permission sets en la pila `agente-iam-identidades`, todos asignados a grupos, nunca a personas:
  `solicitantes` (solo la aplicacion SAML, sin acceso a AWS), `aprobadores` (`AgenteIAM-Aprobador`, 1 h:
  lee y escribe solo `estado` y `aprobacion`/`rechazo`) y `operadores` (`AgenteIAM-Operador`, 1 h, y
  `AgenteIAM-Lectura`, 4 h: despliega las pilas `agente-iam-*` solo con el rol `AgenteIAM-Despliegue`).
  Mateo va en operadores y solicitantes, no en aprobadores (quien despliega no aprueba);
  `AWSAdministratorAccess` queda como acceso de emergencia.
- `AgenteIAM-Despliegue` va en una pila de arranque que solo despliega el administrador, una vez; no
  puede modificarse a si mismo, ni crear usuarios de Cognito, ni cambiar su proveedor. Los roles del
  sistema llevan el limite `AgenteIAM-LimiteSistema`, no el techo, que es de los beneficiarios; el rol de
  despliegue solo crea roles `AgenteIAM-*` con ese limite.
- El aplicador pasa a Lambda, disparado por DynamoDB Streams con filtro `estado = aprobada`, con el mismo
  `aplicar()`; confianza solo `lambda.amazonaws.com` con `aws:SourceArn`; estado nuevo
  `bloqueada_al_aplicar`; 2 reintentos y cola de fallos con alarma; `aprobar` ya no lo corre
  (`docs/ESPECIFICACION-agentcore.md`, §7). Pilas, en orden: identidades (gestion), arranque, base,
  acceso (Cognito, dos despliegues) y runtime; despues, verificacion con los roles reales.
- La separacion de funciones debe comparar el nombre de usuario de Identity Center, no el `sub`, que solo existe
  en Cognito (diseno, no implementado: hoy `aprobar` compara el ARN del rol del permission set; CONTEXTO §10) (ADR-001 y especificacion §4). **Sin medir:** que el `NameID` de la aplicacion SAML sea ese
  nombre.

| # | Riesgo que queda (23-10-2026, de mas a menos grave) | Mitigacion |
|---|---|---|
| 1 | Quien asume el rol del aplicador escribe en IAM saltandose el flujo | Aplicador como Lambda: ninguna persona lo asume |
| 2 | El aprobador reescribe la propuesta antes de aprobar | Solo escribe `estado` y `aprobacion`/`rechazo`; la huella detecta cambios |
| 3 | El operador controla el codigo y Cognito: podria falsear quien pidio | El rol de despliegue no crea usuarios de Cognito ni cambia su proveedor; revision de conjuntos de cambios. No basta: quien escriba el atributo `aprobacion` fabrica una mientras la huella no lleve secreto (Fase 17, S1) |
| 4 | Quien administra Identity Center se mete en `aprobadores` | Alarma ante `CreateGroupMembership` y grupos en la pila (drift) |
| 5 | Administrador de emergencia | MFA, uso excepcional, alarma de uso |
| 6 | Robo del token | Dura 1 hora y pedir no aplica nada |
| 7 | Con una sola persona, la separacion de funciones es demostracion y no control real | Sin mitigacion tecnica hoy; escala con otra persona |

Antes y despues de la Lambda (juicio de Claude, no medido): con una sola persona reduce poco el riesgo
real; su valor es alinear privilegio con papel y quitar un paso manual. Lo que mas reduce el impacto es
estrechar el techo (hecho: techo v2). Pendiente de Claude, al final del proyecto: en el ESTUDIO, un visual
de la arquitectura con todos sus recursos y el analisis, pieza por pieza, de si la complejidad compensa el
riesgo que reduce (no escrito).

#### Bloque 3, etapa 1 desplegada (23-10-2026)

`infra/cfn/identidades.yaml` ampliada: `solicitante.demo`, tres grupos, tres permission sets y
asignaciones solo a grupos y solo en `agente-iam`. Conjunto de cambios `bloque-3-etapa-1-identidades`
(commits `a8ab2e2` y `2e25bff`), revisado por Mateo: 14 recursos, todos `Add`, sin eventos fallidos.
Simulador contra los tres roles reales: **22 de 22 casos** como se esperaba (`docs/MEDICIONES.md`, seccion
F.2); es el simulador, no una llamada real.
- Lectura = `SecurityAudit` v94 + `ViewOnlyAccess` v47 mas un Deny de lecturas de datos. Aprobador: base de
  IAM Policy Autopilot 0.3.0, recortada: sin `PutItem` (reemplaza la fila entera), solo `UpdateItem` limitado
  con `dynamodb:Attributes` y `Null` en falso. Operador: CloudFormation solo con `cloudformation:RoleArn`
  igual a `AgenteIAM-Despliegue`, sin tocar la pila de arranque.
- Hallazgo: el registro era un unico JSON (`documento`), asi que IAM no podia separar "escribir la
  aprobacion" de "reescribir la propuesta": lo resuelve el cambio de atributos propios (abajo).
- Verificado: cfn-lint y `ValidatePolicy` limpios; 10 tests de invariantes y 8 mutaciones en rojo
  (`test_plantillas_cfn.py`); 436 tests pasan y 2 se saltan (23-10-2026).
- Contrasena y MFA de `solicitante.demo`: puestos, segun Mateo (24-10-2026, no medido). Pendiente, de
  Mateo: quitar `tiene_aprobacion` del permission set del aprobador en la proxima actualizacion; con la etapa de acceso, asignar los solicitantes a la aplicacion SAML.

#### Bloque 3, etapa 2 desplegada (23-10-2026)

`infra/cfn/arranque.yaml`, pila `agente-iam-arranque` (`agente-iam`, `us-east-1`), conjunto de cambios
`bloque-3-etapa-2-arranque` (commits `bea1df9` y `c2a9049`): 8 recursos, todos `Add`; proteccion contra
borrado activada despues (un conjunto de cambios de pila nueva no la admite).
- Rol `AgenteIAM-Despliegue` (confianza solo `cloudformation.amazonaws.com`, cinco politicas gestionadas;
  las unas 300 acciones de Almacen, Cognito y Computo salen de los esquemas de los 16 tipos de recurso,
  nunca `servicio:*`), `AgenteIAM-LimiteSistema` (union de los permisos de runtime y aplicador mas un Deny de
  todo lo que escala) y `AgenteIAM-Techo`. El operador no puede cambiar la pila (Deny explicito).
- Simulador: **35 de 35 casos**: ni con permiso total escala un rol que lleve el limite (`docs/MEDICIONES.md`,
  seccion F.3). 9 tests y 10 mutaciones en rojo; 448 tests pasan y 2 se saltan (23-10-2026).
- Verificado el 24-10-2026 con el despliegue de la pila base (Fase 18, `docs/MEDICIONES.md` F.5): CloudFormation
  envia `aws:SourceAccount` con un rol de servicio de pila y los permisos de los esquemas bastaron.

#### Techo v2 escrito y desplegado (23-10-2026)

Mateo acepto `docs/ADR-002-techo-beneficiarios.md` con D1 (Deny de 53 acciones de gestion de permisos), D2
(Deny de todo sobre recursos `agente-iam-*`), D3 (el mismo bloqueo en el codigo) y D4 como opcion B (EC2 solo
inventario). Motivo: el techo v1 solo frenaba lo que el codigo ya frenaba, y nada impedia pedir permisos sobre
los recursos del propio sistema, abierto por el flujo normal con aprobacion.
- Codigo: `config.py` (`SOLO_LECTURA`, `PREFIJOS_DEL_SISTEMA`, 10 `ec2:Describe*` con secretos prohibidas),
  dos chequeos nuevos en `coherencia.py` (solo `Describe*` en EC2; ningun componente de ARN con prefijo del
  sistema) y `scripts/generar_techo.py`, que genera el techo desde `config.py` y la referencia de AWS (el
  techo ya no se edita a mano; `--comprobar`). Techo v2 de seis sentencias y 3422 caracteres (limite 6144).
- Medido el 23-10-2026: son 53 acciones y no 77; hay 10 `Describe` con secretos; `ec2:ModifyImageAttribute`
  es Write y lo cierra la opcion B (`docs/MEDICIONES.md`, seccion E.2).
- Desplegado con el si de Mateo: conjunto de cambios `techo-v2-adr-002` sobre `agente-iam-arranque`, unico
  cambio `Modify` de `Techo`. `ValidatePolicy` sin hallazgos y simulador **30 de 30**; ningun principal lo usa
  (secciones E.3 y E.4). Commits `60ee550`, `131a19f` y `1ef256f`.
- Verificado: 40 tests (`test_techo_v2.py`) y uno funcional (`test_techo_en_vivo.py`); 16 mutaciones en rojo;
  488 tests pasan y 3 se saltan (23-10-2026). Lo que no cierra: seccion E.6.
- Sin medir: `CheckNoNewAccess` contra el v2 con una solicitud real, y el modelo contra
  `ejemplos/solicitud-ec2*.json` (si propone `ec2:Describe*` entero ahora se bloquea y debe repararlo; cuesta
  Bedrock, con el si de Mateo). El techo desplegado desde el 24-10-2026 es el del repositorio (v3): Fase 18, seccion E.8.

#### Bloque 3: aprobacion y rechazo como atributos propios (24-10-2026)

Commit `10ff080` (subido a origin el 24-10-2026); no se llamo a AWS. Por que: `dynamodb:Attributes` no limita
`PutItem` (guia de DynamoDB; Access Analyzer lo marca) y el permission set del aprobador solo permite
`UpdateItem` de ciertos atributos; con el codigo anterior no habria podido aprobar nada. Mateo aprobo el
diseno, incluido que el intake tambien deje `PutItem`.
- `almacen.py`: un atributo por actor (`id` la clave; `documento` el intake; `estado` los tres;
  `aprobacion`/`rechazo` el aprobador; `aplicacion` el aplicador), todo con `UpdateItem` condicional y sin
  `ReturnValues`. `guardar_decision(registro, bloque, estado_esperado)` solo envia ese bloque y `estado`; cada
  condicion nombra solo atributos del actor que escribe. Disco: las mismas reglas sobre el fichero.
- `aprobar.py`: `rechazo` es un bloque propio (`cuando`, `por`, `huella`, `motivo`); aprobar y rechazar se
  bloquean si ya hay uno de los dos. `aplicador.py` escribe `aplicacion`. `CAMPOS_FUERA_DE_LA_HUELLA` incluye
  `rechazo`; las huellas existentes no cambian.
- Verificado el 24-10-2026 contra el repositorio y dobles (`Stubber`): 505 pasan y 3 se saltan; 16 mutaciones en
  rojo (dos vivas en la primera pasada llevaron a dos tests). Sin migracion: la tabla no existe.
- Limites: `estado` lo comparten los tres actores (ponerlo a un valor no aplica nada, porque el aplicador exige
  `aprobacion` con huella); IAM no puede exigir "solo si el bloque no existe", lo pone cada condicion;
  `dynamodb:Attributes` frena un `UpdateItem` real y cuenta los atributos de la condicion (medido el 24-10-2026,
  `docs/MEDICIONES.md`, seccion F.6). Leccion: ESTUDIO §17.

#### Pendientes de la fase

- Hecho: la pila base (24-10-2026; tabla con PITR y Streams, bucket del paquete, roles de runtime y aplicador con
  `UpdateItem` y `dynamodb:Attributes` [`id`, `documento`, `estado`] y [`id`, `estado`, `aplicacion`], sin
  `PutItem`), y acceso y runtime (25-10-2026, Fase 20). Queda la prueba de escritura de los roles del runtime y del
  aplicador contra la tabla real (`docs/MEDICIONES.md` K.5). `infra/rol-runtime-permisos.json` (Fase 8; retirado el 24-10-2026, lo
  sustituye `infra/cfn/base.yaml`) concedia solo `PutItem` y negaba `UpdateItem`: contradecia al codigo.
  Decision al escribirla: `AgenteIAM-LimiteSistema` aun permite `PutItem` (es el boundary; estrecharlo es opcional).
- Bloque 4 (limpiar la cuenta de gestion): hecho el 25-10-2026 (Fase 20, `docs/MEDICIONES.md` K.4): techo antiguo,
  usuarios de prueba, roles `AgenteIAM-Analista` y `AgenteIAM-Aplicador` y sus inline. El usuario IAM `Mateo` se
  queda (decision de Mateo). Fuera del bloque: el segundo rol con `SourceIdentity`.

### Fase 16 - Orden del repositorio

Mateo dijo que la carpeta "estaba en caos otra vez". Medido el 23-10-2026 sobre `fffd177` (99 ficheros
versionados): sin restos generados, pero `infra/` mezclaba artefactos que se despliegan con tres guias largas, la
raiz tenia un script suelto y el `.gitignore` no cubria `.claude/worktrees/`.

- Con `git mv`: `DESPLIEGUE.md`, `CONTROL-TOWER-CHECKLIST.md` y `PRUEBAS-AGENTCORE.md` de `infra/` a `docs/`;
  `empaquetar.sh` a `scripts/`, que ahora hace `cd "$(dirname "$0")/.."`. Referencias actualizadas; reglas nuevas
  en `.gitignore`.
- No se movio: los JSON de `infra/` (`aprobar.py` lee el techo por la ruta relativa `_RUTA_TECHO_LOCAL`),
  `ejemplos/` (tests y `cli.py` dependen de su estructura) ni la configuracion de la raiz, que las herramientas
  buscan ahi.
- Hecho por un subagente (Sonnet) en un worktree y fusionado el 23-10-2026 a peticion de Mateo (`7d21e12`,
  `093de75`). Hallazgo: `CLAUDE.md` citaba rutas de tests anteriores a la Fase 11.
- Verificado el 23-10-2026: tests de rutas citadas y de `empaquetar.sh` (hoy en
  `tests/unitarios/test_documentacion.py`), con mutaciones en rojo; 418 pasan y 2 se saltan; ruff, mypy y
  cfn-lint limpios.

Pendiente: de quien toque `agente_iam/`, calcular `_RUTA_TECHO_LOCAL` desde `__file__` si se quiere
`infra/politicas/` y arreglar el mensaje de `servidor.py` que nombra `empaquetar.sh` sin su carpeta; de Mateo, fundir
`pytest.ini`, `mypy.ini` y `ruff.toml` en un `pyproject.toml` (aplazado).

### Fase 17 - Revision del 24-10-2026

Estado: hecha, sus tres pasos commiteados y subidos.

Paso 1, seguridad (`7968aac`). Origen: la revision de solo lectura sobre `10ff080` (hallazgos S1 a S10 y O1 a O3;
informes fuera de git). Mateo aprobo aplicar los trece, cada uno con un test que se pone en rojo si se deshace y
sin AWS (`Stubber` y dobles).

| # | Hueco | Arreglo |
|---|---|---|
| S1 | Un `documento` con su propia `aprobacion` llegaba al aplicador | La lectura lanza `RegistroInconsistente`; `guardar_decision` exige la clave leida |
| S2 | El nombre del formulario valia en cualquier componente del ARN | `_FORMA_DEL_RECURSO` por servicio y `PALABRAS_DEL_ARN` |
| S3 | `Resource: "*"` con cualquier Condition dejaba pasar escrituras de alcance de cuenta | Con `"*"` solo List o Read; en el techo, Deny `SinEscriturasDeAlcanceDeCuenta` |
| S4 | El aplicador solo miraba la huella | Exige separacion cumplida, techo PASS y riesgo confirmado, y repite `CheckNoNewAccess` |
| S5 | Un bucket de otra cuenta pasaba (el ARN de S3 no lleva cuenta) | `s3:ResourceAccount` en cada Allow de s3; en el techo, Deny `SoloRecursosDeLaPropiaCuenta` |
| S6 | El intake pisaba todo registro no decidido | Solo escribe si no existe; error `registro_existente` |
| S7 | Secuencias de terminal en la pantalla del aprobador | Sin caracteres de control (tambien C1) en la justificacion; `models.imprimible` escapa |
| S8, S9 | `revalidar` no repetia los chequeos previos; lo revalidado no era lo aplicado | `coherencia.chequeos_formulario` comun; `extra="forbid"`; el aplicador usa el documento validado |
| S10, O1 | gitleaks por etiqueta y un paso de CI que no escaneaba | `rev` por SHA; gitleaks 8.21.2 con sha256 y `gitleaks git` en CI |
| O2, O3 | La cache del catalogo no caducaba; un test "sin red" la descargaba | Caduca a los 7 dias; el zip lleva un catalogo recien descargado; el guardian corta `urlopen` |

- Cambios observables: `ya_aprobada` pasa a `registro_existente` en el servidor; `aprobar` y el aplicador salen con 3
  ante una fila inconsistente; una justificacion con caracteres de control sale con 2; las propuestas de s3 sin la
  condicion de cuenta y las escrituras con `"*"` se bloquean; el aplicador necesita `access-analyzer:CheckNoNewAccess`;
  el techo niega `lambda:CreateEventSourceMapping` a todo beneficiario.
- El techo del repositorio pasa a 5575 caracteres (limite 6144): las 80 escrituras sin tipo de recurso se agrupan por
  prefijo solo si el techo ya niega todo el prefijo. Queda poco margen si el catalogo de cloudwatch sigue creciendo.
- Verificado el 24-10-2026: 648 pasan y 3 se saltan; 59 mutaciones, 59 en rojo (`docs/MEDICIONES.md`, seccion I). El
  techo del repositorio y el de la cuenta difieren, y nada de la diferencia esta desplegado: seccion E.5.

Paso 2, limpieza y tests (`8cb3c42`). Mateo aprobo O4 a O7, O12 a O17 y O21: 19 paquetes sobrantes desinstalados
(`sympy` y `mpmath` no sobraban y se fijaron en `constraints.txt`); `empaquetar.sh` quita `aprobar.py`, `aplicador.py`,
`cli.py` y `huella.py` del zip y comprueba que no viajan; textos desfasados y 15 `# noqa` inutiles fuera (RUF100); mypy
paso 1; `test_mios.py` fundido en `test_barandas.py`; compuerta de estado y vectores de la Fase 6 parametrizados;
ayudas comunes en `tests/dobles.py`; modelos sin uso borrados; dependencias importadas declaradas. Cifras del
24-10-2026: 656 pasan y 3 se saltan; 26 mutaciones nuevas en rojo. No se hicieron O8 a O11, O18 a O20 ni O22.

Paso 3, compresion de la documentacion (24-10-2026, `a8f8a78`): plan aprobado por Mateo (D1 a D8, menos D6);
`docs/MEDICIONES.md` como sede unica de lo medido; PLAN, CONTEXTO, ESTUDIO y las guias de `docs/` resumidos.

Desplegar el techo nuevo y la politica del aplicador con `CheckNoNewAccess`, despues de medir que las llamadas de los
ocho servicios llevan `aws:ResourceAccount` (E.7): hecho el 24-10-2026 (Fase 18, `docs/MEDICIONES.md` E.8).
La mitigacion de fondo de S1 y S4 (la huella no tiene secreto, asi que quien escriba `aprobacion` fabrica una aprobacion
valida) la decidio Mateo despues: aprobacion registrada por una pieza de servidor (ADR-003, Fase 19). Que el
`solicitud_id` lo genere el sistema se hizo en la Fase 23. Pendiente de Mateo: hashes en `constraints.txt`. De Claude: que el aplicador sepa desde que estado se aprobo (la huella no
incluye `estado`) y comprobar el id antes de invocar al modelo (hoy el coste de esa corrida se pierde). El paso de
gitleaks del CI se ejecuto despues en GitHub (leido el 18-11-2026 con `gh`: la ultima ejecucion, del 02-11-2026, lo da en `success`). El hook con `rev` por SHA no se comprobo en esa lectura.

### Fase 18 - Techo, decisiones de aprobacion y pila base

Plan: `docs/superpowers/plans/2026-10-24-techo-decisiones-y-pila-base.md`, seis tareas: 1, comprobar lo hecho por
Mateo; 2, sonda de `aws:ResourceAccount`; 3, desplegar el techo, `LimiteSistema` sin `PutItem` y la politica del
aplicador; 4, ADR-003 con la decision A (aprobacion en servidor frente a MAC con KMS) y la B (persona en la
separacion de funciones); 5, pila base; 6, `dynamodb:Attributes` contra la tabla real.

Tarea 1, hecha el 24-10-2026 (lectura con `org-gestion`; `docs/MEDICIONES.md` G.7):
- Medido: el rol Aplicador tiene una sola inline, `AgenteIAM-Aplicador-permisos`, sin `CheckNoNewAccess`; la vieja la
  borro `user/Mateo` el 24-10-2026 a las 19:14 UTC (CloudTrail).
- Medido: `~/.aws/credentials` no existe; `~/.aws/config` conserva `[profile root-mfa-delete-demo]`, sin secreto (Mateo).
- Dicho por Mateo, no medido: el MFA de `solicitante.demo` esta registrado.
- Regla de proceso: las copias de `local/infra/` estaban desfasadas; regenerar con `scripts/localizar.py` antes de
  comparar con la cuenta o desplegar desde `local/`.

Tarea 2, medida el 24-10-2026 (perfil `org-agente-iam`; `docs/MEDICIONES.md` E.7, fila 30 de §H):
- Sonda (`scripts/sonda_cuenta.py`, `infra/cfn/sonda-cuenta.yaml`, `tests/unitarios/test_sonda_cuenta.py`): pila
  temporal creada a las 20:09:54 UTC y borrada a las 20:12:17 UTC, sin restos; sonda a las 20:10:54 UTC, salida 0,
  evidencia en `evidencias/sonda-cuenta/20261024T201054Z/resultado.json` (fuera de git).
- Medido, 18 llamadas: 15 con la clave de la cuenta propia y pasan; 2 con la clave de otra cuenta (bucket publico de
  Registry of Open Data, capa de Lambda de AWS) y se niegan; 1 no concluyente (tema publico de SNS, denegado tambien
  en la sesion de control); 0 sin la clave.
- Hallazgo: la guia de IAM dice que un Deny con `StringNotEqualsIfExists` niega aunque falte la clave; el simulador
  dio `allowed` (E.5) porque rellena `aws:ResourceAccount` con la cuenta de quien llama (E.8). CONTEXTO §5 y E.5
  decian lo contrario (fila 11 de §H ya lo advertia).
- Decision de Mateo (24-10-2026, paso 9): acepta que el techo niegue todo recurso de otra cuenta, sin excepcion,
  tambien los publicos de AWS (la capa de Lambda no importa: `UpdateFunctionConfiguration` ya esta en
  `ACCIONES_PROHIBIDAS`; el bucket publico es lo que S5 quiere cerrar).

Tarea 3, hecha el 24-10-2026 (perfil `org-agente-iam` y `org-gestion`, con el si de Mateo; `docs/MEDICIONES.md` E.8):
- Codigo: `AgenteIAM-LimiteSistema` ya no permite `dynamodb:PutItem`; lo vigila
  `test_el_limite_del_sistema_no_permite_reemplazar_filas` (rojo antes del arreglo, verde despues). 678 tests pasan y 3
  se saltan (24-10-2026).
- Medido antes: `generar_techo.py --comprobar` al dia (5575 caracteres); `ValidatePolicy` sin hallazgos.
- Desplegado: conjunto de cambios `techo-v3-y-limite` (dos `Modify`, sin reemplazo), `UPDATE_COMPLETE` a las 20:22 UTC;
  la politica del aplicador con `CheckNoNewAccess` (`PutRolePolicy`, 20:23 UTC), igual a la del repositorio.
- Medido despues: techo v3 por defecto, igual al repositorio; `LimiteSistema` v2 sin `PutItem`; 0 principales los
  llevan; simulador 8 de 8 como en E.5. El `allowed` del simulador para `s3:PutObject` se explico: rellena
  `aws:ResourceAccount` por su cuenta.

Tarea 4, hecha el 24-10-2026: ADR-003 aceptado por Mateo (A2 y B2); codigo en un plan propio.
(`docs/ADR-003-aprobacion-en-servidor-y-persona.md`.)

Tarea 5, hecha el 24-10-2026: `infra/cfn/base.yaml` (pila `agente-iam-base`) escrita, probada sin AWS y
desplegada por el operador con `AgenteIAM-Despliegue` (primera prueba real de ese rol). Simulador 16 de 16 sobre
los roles reales y `aws:SourceAccount` verificado (CloudFormation lo envia): `docs/MEDICIONES.md` F.5.
- Tabla `agente-iam-solicitudes` (PITR, Streams, proteccion contra borrado, `Retain`), bucket
  `agente-iam-despliegue-<cuenta>` (versionado, sin acceso publico, TLS obligatorio, `Retain`) y roles
  `AgenteIAM-Runtime` y `AgenteIAM-Aplicador` con `AgenteIAM-LimiteSistema`, confianza con cuenta de origen y
  `UpdateItem` solo de sus atributos (con el `Null`); Deny de `PutItem`, `DeleteItem`, `BatchWriteItem`,
  `DeleteTable` y `UpdateTable`. Nadie escribe `aprobacion` ni `rechazo`.
- Retirados `infra/rol-runtime-permisos.json` y `infra/rol-runtime-confianza.json` (siguen en git).
- Arreglo en `almacen._dynamo_leer`: fila sin `documento` o `estado` es `RegistroInconsistente` (salida 3),
  no `KeyError`.
- Verificado: cfn-lint sin errores; `ValidatePolicy` del runtime sin hallazgos y del aplicador con 2 sugerencias
  `EQUIVALENT_TO_NULL_FALSE` (las de su JSON); simulador de `AgenteIAM-Despliegue`: 26 de 27, falta
  `s3:GetBucketLocation`, que el despliegue real no necesito.
  Tests nuevos en `tests/seguridad/test_pila_base.py`.

Tarea 6, hecha el 24-10-2026: sonda escrita y probada sin AWS (`scripts/sonda_atributos.py`,
`tests/unitarios/test_sonda_atributos.py`) y corrida con llamadas reales como `aprobador.demo`. El primer intento
dio `ForbiddenException: No access` porque el navegador traia la sesion de Mateo; repetido en una ventana privada.
Medido (cuenta `agente-iam`, 21:32:40 UTC): 6 de 6 casos como se esperaba (leer, `estado` y `aprobacion`
permitidos; `documento`, `PutItem` y `ReturnValues ALL_NEW`, `AccessDeniedException`), y una condicion sobre
`documento` en la `ConditionExpression` tambien se deniega: `dynamodb:Attributes` cuenta los atributos de la
condicion. Las cuatro denegaciones son implicitas: el permission set del aprobador no tiene Deny explicito de
`PutItem`, `DeleteItem` ni `BatchWriteItem`. Queda la fila de prueba `sonda-atributos-20261024`, que `almacen.leer`
rechaza. Detalle en `docs/MEDICIONES.md` F.6.

El plan del codigo de ADR-003 es la Fase 19 (hecha). Sigue pendiente borrar la fila de prueba (Mateo). Mapa del
flujo: `local/mapas/solicitud-por-la-tabla.md` (fuera de git).

### Fase 19 - Aprobacion en servidor y separacion por persona (ADR-003)

Plan: `docs/superpowers/plans/2026-10-24-aprobacion-en-servidor-y-persona.md`, once tareas: 1, el intake graba quien
pidio; 2, el aprobador con persona, desde STS o desde el evento; 3, separacion por persona; 4, `decidir` y el
manejador de la Lambda; 5, el cliente de la persona; 6, el paquete de la Lambda; 7, la pila base con la Lambda, su rol
y los dos menores; 8, el rol de despliegue puede crear la URL; 9, el permission set del aprobador y el bucket del
operador; 10, despliegue y mediciones; 11, documentacion. Por que: el bloque `aprobacion` lo escribia cualquiera con
`UpdateItem` sobre la tabla y la separacion de funciones comparaba el rol del permission set, no la persona.

Codigo, tareas 1 a 9 (24-10-2026, `c9be954` a `46db6b1`, `c98eaf1`):
- El intake graba `solicitante` (`persona` solo cuando llegue el JWT; hoy `None`). `aprobar.py` es el servidor:
  `manejador`, `aprobador_desde_evento` (la identidad sale de `requestContext.authorizer.iam`, nunca del cuerpo),
  `decidir` (una lectura, una escritura) e `identificar_aprobador` (STS, para el modo disco). La persona es el nombre
  de sesion de un rol `AWSReservedSSO_AgenteIAM-Aprobador_*` con el path de Identity Center, comprobado con
  `iam:GetRole`. La separacion compara personas (`NFKC` + `casefold()`), aprobador frente a solicitante y frente a
  beneficiario; persona no determinable o fila antigua sin `solicitante` = bloqueo con motivo, no `KeyError`.
- Codigos de la Lambda: `200` decidida, `400` peticion fuera de contrato o sin identidad firmada, `409` bloqueada por
  un control, `500` entorno o fallo; nada se escribe en 400, 409 ni 500. El cliente (`agente_iam/aprobar_cliente.py`)
  lee, ensena la huella y firma con SigV4; `python -m agente_iam.aprobar` ya no es comando.
- `scripts/empaquetar.sh aprobacion` deja `dist/agente-iam-aprobacion.zip` (python3.12, arm64, catalogo dentro).
- Infra: `base.yaml` gana `RolAprobacion`, `RegistroAprobacion`, `FuncionAprobacion` y `UrlAprobacion` (`AWS_IAM`, sin
  politica de recurso); `arranque.yaml` da al rol de despliegue las acciones de `AWS::Lambda::Url`;
  `identidades.yaml` deja al aprobador con `GetItem`, la invocacion de la URL y Deny explicito de escribir la tabla, y
  corrige el bucket del operador.
- Hallazgos del diseno: cinco manejadores de `AWS::Lambda::Url`, no cuatro (`ListFunctionUrlConfigs`); la URL no
  exige la cabecera `x-amz-content-sha256` (supuesto que resulto falso, M1b); y la decision 2 no se exigia en el
  servidor (ver la revision final). Las dos primeras, en `docs/MEDICIONES.md` §H filas 31 y 32.

Revision final del codigo (24-10-2026, `93ca54a` a `cb19328`), 7 arreglos: (F1) la decision 2 no se exigia en el
servidor: un firmante sin persona aprobaba por `SALTADO` y rechazaba sin identidad; (F2) campos fuera de contrato
daban 500 y no 400; (F3) el cliente seguia redirecciones; (F4) el aviso del 403 culpaba solo al permiso; (F5) un rol
asumido de otra cuenta no se rechazaba antes de preguntar a IAM; (F6) las listas del paquete eran solo de exclusion;
(F7) una cabecera de `identidades.yaml` decia que el aprobador escribia.

Tarea 10, despliegue y mediciones (25-10-2026 UTC, `156f03e`; detalle en `docs/MEDICIONES.md` F.7): tres conjuntos de
cambios (arranque, identidades, base) ejecutados sin fallos, cada uno con el si de Mateo; el de la base lo creo y
ejecuto el operador con `AgenteIAM-Despliegue`, que creo la primera Lambda y la primera URL. M1: `409` con `persona =
aprobador.demo` y el log con el mismo `userArn` (pendiente 1 del ADR medido). M1b: la URL no exige
`x-amz-content-sha256`. M2: invocacion directa con evento fabricado, `AccessDeniedException`. M3: `POST` sin firmar,
`403`. M4: sonda `--solo-lectura`, 7 de 7, Deny explicito. M5 no corrida. Tests: 893 pasados y 3 saltados
(25-10-2026 UTC).

Tarea 11, documentacion (24-10-2026, fechas del despliegue de 25-10-2026 UTC): PLAN, CONTEXTO, README,
`docs/DESPLIEGUE.md`, ADR-003, ESTUDIO §21 y los docstrings de `almacen.py` y `huella.py`; escrita por un modelo menor
con encargo cerrado, y se revisa contra la tabla de documentacion del proyecto.

Decisiones del plan aceptadas por Mateo el 24-10-2026:
1. Nombres de modulo: el servidor se queda en `aprobar.py` y el cliente es `aprobar_cliente.py`; el comando de la
   persona cambia.
2. Solo el permission set `AgenteIAM-Aprobador` aprueba; ni un administrador con permiso de invocar.
3. La comparacion de personas es `NFKC` + `casefold()`, que bloquea mas.
4. El permission set del aprobador pierde la lectura de IAM y Access Analyzer, y su Deny anade `PartiQLInsert`,
   `PartiQLUpdate` y `PartiQLDelete`.
5. La Lambda tiene dependencias propias (`requirements-aprobacion.txt`, sin `bedrock-agentcore`); limite de 250 MB.
6. Se arregla el bucket del operador (`agente-iam-despliegue-<cuenta>`, antes `agente-iam-paquete-<cuenta>`).
7. El rol de despliegue gana las acciones de `AWS::Lambda::Url`, desplegadas por el administrador en la pila de
   arranque.
8. Hasta que el runtime grabe la persona del JWT (pila `acceso`), toda aprobacion real bloquea salvo `SALTADO`
   (desde el 25-10-2026 el runtime ya la graba, Fase 20; la separacion con dos personas sigue sin medir).

Pendiente (quien): pendientes 2 y 3 del ADR-003 (nombre con mayusculas; renombrar usuarios), Mateo; M5, opcional,
Mateo; borrar la fila `sonda-atributos-20261024`, Mateo como administrador; eventos de datos de
CloudTrail para `agente-iam-aprobacion`: decidido en la Fase 20 (D3, trail `agente-iam-datos`), falta medir que lo
registre; hashes en `constraints.txt` y `solicitud_id` del sistema, decide Mateo (ya
en CONTEXTO §11). Limite que no cierra: un administrador de la cuenta sigue pudiendo escribir cualquier atributo
(rastro: PITR y Streams).

### Fase 20 - Pilas acceso y runtime, aplicador como Lambda y bloque 4

Plan: `docs/superpowers/plans/2026-10-25-acceso-runtime-y-aplicador.md`, siete tareas de codigo y plantillas, el
despliegue con mediciones (T8) y esta documentacion (T9). Por que: el runtime aun no existia, el solicitante no
quedaba grabado (`persona` era `None`), el aplicador era un CLI con un perfil de la cuenta de gestion y la cuenta de
gestion seguia alojando el circuito medido. Rama `claude/acceso-runtime` (worktree), 13 commits (`93e1142` a `60eea2b`)
sobre `58413b3`; fusionada y subida el 25-10-2026 (`58e085d`). Metodo: siete tareas con implementadoras y revisoras Sonnet
en paralelo, y revision final de la rama con Opus (25-10-2026), que encontro dos hallazgos importantes (abajo).

Codigo (25-10-2026):
- `servidor.py` lee los claims del JWT que el autorizador de AgentCore ya valido; `ejecutado_por` pasa a
  determinable (`sub`, `usuario`, `jti`, `sesion_runtime`, `request_id`) y `solicitante.persona` es el `username` sin
  el prefijo `IdentityCenter_` (`None` si falta algo). El token nunca entra en el registro ni en el log.
- `aplicador.py`: `manejador` (Lambda `agente-iam-aplicador`, disparada por el stream con filtro `estado = aprobada`) y
  `procesar_aprobada`: comprueba el entorno antes de leer, relee la fila sin fiarse del evento y escribe UNA vez,
  `aplicada` o el estado nuevo `bloqueada_al_aplicar` (bloque `aplicacion` con `decision: "bloquear"`). Hallazgos de la
  revision final: (I1) un `CheckNoNewAccess` o `ValidatePolicy` que no se pudo ejecutar (throttling, red) se tomaba por
  bloqueo permanente; ahora es `ControlNoEjecutable`: la Lambda reintenta (2) y el evento acaba en la cola, y el CLI
  sale con 1. (I2) el runtime puede escribir `estado`, asi que ponia `aprobada` sobre una fila ya decidida y el
  stream la re-aplicaba; una fila con `aplicacion` o `rechazo` no se aplica (WARNING y `RuntimeError`, a la cola; en
  el CLI, bloqueo). Un bloqueo determinista no se esconde tras la llamada de pago (no se llama a `comprobar_techo` si
  ya hay bloqueos). Tras aplicar, el ARN de la politica queda siempre en el log aunque falle el guardado.
- S5 exige la clave `aws:ResourceAccount` con el valor `config.VALOR_CUENTA_DEL_RECURSO = "${aws:PrincipalAccount}"`
  (la forma de la sentencia `SoloRecursosDeLaPropiaCuenta` del techo); el prompt del modelo sale de la misma
  constante. Motivo medido en el despliegue (abajo); decision de Mateo: variable, el techo no cambia.
- `scripts/empaquetar.sh aplicador` (tercer zip, `requirements-aplicador.txt`), `scripts/solicitar.py` (D7: `token` y
  `enviar`; codigos 0, 2 y 1), `ejemplos/solicitud-finanzas-demo.json`.
- Plantillas: `infra/cfn/acceso.yaml` (pool, dominio, proveedor SAML y cliente PKCE), `runtime.yaml` (runtime,
  Lambda del aplicador, disparador, cola de fallos, alarma, tema, grupo de logs de la Lambda y trail `agente-iam-datos`)
  y `beneficiarios.yaml` (D1: rol `app-finanzas-demo` con el techo y bucket `finanzas-demo-<cuenta>`; la despliega el
  administrador). `base.yaml`: `sqs:SendMessage` del aplicador solo sobre su cola; confianza del aplicador con
  `aws:SourceAccount` solo; el rol del runtime permite `inference-profile/us.anthropic.claude-*` en cualquier region.

Decisiones de Mateo (25-10-2026): D1 beneficiarios en pila aparte; D2 la Lambda del aplicador sin
`AGENTE_IAM_PERMITIR_AUTOAPROBACION`; D3 un solo trail de datos (AgentCore Runtime y `agente-iam-aprobacion`); D4 lote
de 1, 2 reintentos, cola de fallos y alarma con tema `agente-iam-alarmas`; D7 `solicitar.py` reutiliza el PKCE de
`prueba_b.py`; D8 el grupo de logs del runtime, que el plan queria declarar, ya no se declara (AgentCore lo crea;
MEDICIONES §H fila 33); confianza del aplicador con `aws:SourceAccount` solo (fila 34); S5 variable y no literal
(filas 36 y 37). Sin `ReservedConcurrentExecutions` (cuota de cuenta de 10).

Como se verifico:
- Tests: la cifra con su fecha esta en `CONTEXTO.md` §2 (unica sede); `test_pila_acceso.py`, `test_pila_runtime.py`,
  `test_pila_beneficiarios.py` y `test_solicitar.py` son nuevos.
- Despliegues, cada uno con el si de Mateo (`docs/MEDICIONES.md` K.1): acceso (dos despliegues con la aplicacion SAML
  `agente-iam-cognito` en consola entre medias), beneficiarios, identidades (grupo asignado a la aplicacion), base
  (tres cambios) y runtime, que necesito tres intentos: rollback por el grupo de logs (`AlreadyExists`, 20:01:54) y
  por la confianza del aplicador (el mapeo de eventos rechaza `aws:SourceArn`, 20:09:54); el tercero,
  `CREATE_COMPLETE` 20:24:49.
- Mediciones (K.2, K.3): sin token `401`; el token de Mateo da `username` = `IdentityCenter_<correo>`; `req-020` fallo
  en Bedrock (`AccessDeniedException` generico: faltaba el perfil `us.` en las regiones de destino); `req-021` dio
  `propuesta` en 16 s y su aprobacion la bloqueo `CheckNoNewAccess` contra el techo; biseccion con 13 llamadas: toda
  propuesta de s3 falla salvo la que lleva `aws:ResourceAccount = ${aws:PrincipalAccount}`. El techo contiene de verdad.
- Bloque 4 de la Fase 15 hecho el 25-10-2026 (K.4): borrados `ana.gomez`, `jose.torres`, el techo antiguo, los roles
  `AgenteIAM-Analista` y `AgenteIAM-Aplicador`, el bucket `finanzas-2026` y tres perfiles de `~/.aws/config`. Queda el
  usuario IAM `Mateo`.

Pendiente (quien):
- Claude: redirigir los ejemplos que nombran `user/Mateo`, `ana.gomez` o `jose.torres`.
- Claude, con el si de Mateo: medir el trail de datos y el reintento, la cola y la alarma ante un fallo real
  (MEDICIONES K.5, §J).
- Claude: el estudio final de arquitectura. `ESTUDIO-diseno-y-seguridad.md` §19 existe desde el 25-10-2026 y hay que
  rehacerlo ahora que la prueba de punta a punta esta medida (Fase 21).
- Limites que no cierra: "aplicada sin registrar" (la politica se creo y el guardado fallo) solo se ve en los logs,
  porque el rol de despliegue no tiene `logs:PutMetricFilter` y anadirlo toca la pila de arranque; el re-drive de la
  cola es a mano, con un evento sintetico; la separacion por persona con la misma persona a los dos lados sigue sin medir (con dos distintas: Fase 21).

### Fase 21 - Prueba de fuego de punta a punta y remates

Que: se subieron los tres paquetes con el arreglo de S5 (runtime `cd96aac0627e`, aprobacion `39bea18e7182`, aplicador
`b3099d652857`), se actualizaron `agente-iam-base` y `agente-iam-runtime` con change sets sin reemplazo de recursos y se
corrio el circuito completo con una solicitud nueva, `req-022-finanzas-demo`, el 25-10-2026 (UTC). Por que: hasta
entonces el codigo desplegado pedia `s3:ResourceAccount` y toda aprobacion de s3 bloqueaba (Fase 20), y el aplicador
como Lambda no habia aplicado nunca una solicitud real.

Como se verifico (llamadas reales a la cuenta `agente-iam`, cada escritura con el si de Mateo; el detalle y las horas
estan en `docs/MEDICIONES.md` L):
- L.1: tres zips subidos con el ETag igual al md5 local; change sets `base-aprobacion-s5-39bea18e7182` y
  `runtime-s5-cd96aac0627e-b3099d652857` en `UPDATE_COMPLETE`; el runtime pasa a la version 2 y el endpoint `DEFAULT`
  la sirve.
- L.2: la peticion con JWT al runtime da `propuesta` en 23 s; `aprobador.demo` aprueba con la huella y la Lambda de
  aprobacion escribe `aprobacion` (separacion de funciones `cumplido`, `CheckNoNewAccess` contra el techo v3 `PASS`);
  la Lambda del aplicador deja la solicitud en `aplicada` 5 s despues, con la politica
  `agente-iam-req-022-finanzas-demo` adjunta a `app-finanzas-demo`. Cierra M5.
- L.3: retencion de 365 dias en el grupo de logs del runtime, filas de prueba borradas y suscripcion SNS confirmada.
- L.4: el permission set del aprobador no puede leer las salidas de la pila; la URL de aprobacion se la da el operador
  o el administrador.
- La cifra de tests, con su fecha, vive en `CONTEXTO.md` §2 (unica sede); el funcional que queda, `test_techo_en_vivo`, sale a la
  red).

Codigo retirado (L.5): `tests/funcionales/test_intake_en_vivo.py` y las fixtures `intake` y `entorno_vivo` de
`tests/funcionales/conftest.py`. Corria el CLI con el rol del analista de la cuenta de gestion, que se borro en el
bloque 4; el camino real es el runtime con JWT, que necesita el inicio de sesion de una persona y por eso no es un
test automatico. Quedan `evidencia` y la guardia `solicitudes_intactas`. El comentario de `scripts/pruebas.sh` ya no
dice `AWS_PROFILE=agente-iam`.

Pendiente (quien):
- Hecho en la Fase 22: medir el trail `agente-iam-datos`; medir el reintento, la cola y la alarma ante un fallo real;
  redirigir los ejemplos que apuntan a principales borrados; rehacer el estudio final de arquitectura.

### Fase 22 - Trail de datos, camino de fallo del aplicador, ejemplos y ESTUDIO §19

Que: se leyo el trail `agente-iam-datos`, se provoco un fallo del aplicador para medir el reintento, la cola y la
alarma, se redirigieron los ejemplos versionados a un principal que existe y se rehizo el estudio final de arquitectura.
Todo el 25-10-2026 (UTC). Por que: eran los pendientes de la Fase 21, y dos eran conclusiones sin medir (que el trail
registrara la persona; que el camino de fallo avisara de verdad).

Como se verifico (el detalle y las horas estan en `docs/MEDICIONES.md` M):
- M.1, trail (lectura con el administrador): `IsLogging: true`, con dos selectores (AgentCore Runtime y la Lambda
  `agente-iam-aprobacion`). Cinco eventos entre las 20:52 y las 22:08. `InvokeAgentRuntime` lleva el `sub` y el `jti` del
  token en `additionalEventData.jwt`, pero no `username` ni `client_id`; para pasar del `sub` al nombre hace falta el
  registro o Cognito. La Lambda de aprobacion se ve como `Invoke` (no existe un evento `InvokeFunctionUrl`) con la
  sesion `AssumedRole` de `aprobador.demo` y el host de la URL de funcion.
- M.2, fallo provocado (administrador, con el si de Mateo): una fila `req-023-fallo-provocado` ya decidida y reescrita a
  `aprobada` (el caso I2 de la Fase 20). El aplicador no toco IAM, hizo tres intentos en dos segundos y el evento llego
  a la cola `agente-iam-aplicador-fallos` con `RetryAttemptsExhausted`. La alarma paso a `ALARM` a las 22:37:34 y a `OK`
  sola a las 22:41:34, ya limpia la cola y la fila. Volver a tramitar es a mano: borrar mensaje y fila y pedir con otro id.
- M.3, ejemplos (codigo, sin tocar la cuenta): ocho ficheros de `ejemplos/` pasan a `role/app-finanzas-demo`;
  `solicitud-mateo.json` se retira (no hay en `agente-iam` un principal sin techo que valga de ejemplo; el caso vive en
  los tests unitarios); `scripts/comparar_modelos.py` usa el perfil `org-agente-iam`. Los tests que leen los ejemplos
  estan en verde.
- `ESTUDIO-diseno-y-seguridad.md` §19 lo rehizo Claude el 25-10-2026 con lo medido en L y M.
- La cifra de tests, con su fecha, vive en `CONTEXTO.md` §2 (unica sede).

Lo que no se midio: un fallo pasajero de AWS (`ControlNoEjecutable`) ni la rama `bloqueada_al_aplicar` en la cuenta. Que
el correo de la alarma llego a Mateo (confirmado el 25-10-2026, M.2).

Pendiente (quien):
- Mateo: decidir si se cambia la regla 2c del prompt para que el modelo copie `${aws:PrincipalAccount}` tal cual (hoy toda solicitud de s3
  gasta dos intentos: medido en M.5; el cambio exige medirlo otra vez con Bedrock).
- Fase 22 commiteada y subida (`8c401d0`, `14c1671`, `d0c7d29`).

### Fase 23 - Formulario web, rol por persona con caducidad y aviso por correo

Que: tres bloques que se apoyan y no se empieza el siguiente sin medir el anterior (plan en
`docs/superpowers/plans/2026-10-26-formulario-web-y-rol-por-persona.md`, decision en `docs/ADR-004-rol-por-persona-y-confianza-por-token.md`).
(1) Backend: cada solicitud aprobada se materializa en un rol creado para la persona (techo como boundary, confianza
solo para su `sub`, 1 a 12 horas con corte exacto) que ella asume con su token de Cognito. (2) Pagina web estatica tras
CloudFront (pila `web`, cliente de Cognito `agente-iam-web`). (3) Correo con la decision (Lambda de avisos y SES).
Por que: el permiso iba a un principal que ya existia, elegido por quien pedia (`principal_arn_declarado`); para la
demostracion y para una empresa hace falta que cualquiera de Identity Center pida para si, sin elegir beneficiario, y
que el permiso muera solo. Las personas de Identity Center no son principales de IAM, asi que hay que crear algo que
solo ellas puedan usar.

Estado del bloque 1 al 26-10-2026 (UTC): **desplegado el 26-10-2026 (04:34 a 04:41 UTC, `docs/MEDICIONES.md` O.1) y medido de punta a
punta el mismo dia (O.2 y O.3); commit `a40851b` del bloque 1, subido a origin.** Medido antes y citado como tal: la confianza y el canje con `AssumeRoleWithWebIdentity` (`docs/MEDICIONES.md` N) y que el simulador no tiene
valor implicito para `aws:CurrentTime` (A.3). Lo que se implemento, por tarea del plan:
- T1 `agente_iam/personas.py` (id, nombre y ARN del rol, `vence`, vencimiento en cada `Allow`, confianza) con
  `tests/unitarios/test_personas.py`; `personas.py` entra en `FUERA_DE_LA_APROBACION` de `scripts/empaquetar.sh`.
- T2 `models.py`: `SolicitudWeb`, `PersonaDelToken`, los dos modos de `SolicitudEstructurada` y de `IdentidadVerificada`.
- T3 `config.py`: `MAX_ROLES_VIGENTES_POR_PERSONA` (5), `REGIONES_PERMITIDAS`, `POOL_ID`, `CLIENTES_COGNITO`; la region fuera de la
  lista se rechaza en `chequeos_formulario`.
- T4 `personas.roles_vigentes`, `personas.cuenta_actual` y `simulacion.redundancia_persona` (con `aws:CurrentTime`).
- T5 `orquestador.py` con los dos modos (`identidad_de_persona`, tope de roles, redundancia por persona) con
  `tests/unitarios/test_rol_por_persona.py`.
- T6 `servidor.py` con un solo contrato: el codigo `sin_persona`, el `solicitud_id` formado desde la `clave_envio`, la
  respuesta con `solicitud_id` y `rol_previsto`. T7 `cli.py` solo en el modo del principal existente y
  `tests/seguridad/test_modos.py`.
- T8 `aplicador.py` crea el rol por persona (politica, rol y adjuntar; bloque `aplicacion` con `rol_arn`, `rol_id`, `vence` y
  `documento_aplicado`). T9 `aprobar_cliente.py` muestra rol, horas y vencimiento al aprobador.
- T10 plantillas: `base.yaml` y `infra/rol-aplicador-permisos.json` (crear roles solo bajo `/agente-iam/personas/` y
  solo con el techo), `arranque.yaml` (mismas reglas en `LimiteSistema`, proveedor OIDC y, para los bloques 2 y 3,
  CloudFront y `ses:SendEmail`), `acceso.yaml` (`ProveedorOidc`), `runtime.yaml` (`ClienteWebId`, el pool sale de
  `DiscoveryUrl`). T11 `scripts/solicitar.py` (`enviar --clave`, `asumir`) y `ejemplos/web/persona-finanzas-demo.json`.

Como se verifico: tests unitarios y de seguridad sin red, en verde el 26-10-2026 (la cifra, con su fecha, vive en
`CONTEXTO.md` §2). **Desplegado el 26-10-2026 (UTC, `docs/MEDICIONES.md` O.1), con el si de Mateo a cada change set y a cada
zip:** `DescribeType` leido antes (04:30); arranque `arranque-fase-23` ejecutado 04:34:06, `UPDATE_COMPLETE` 04:34:46
(administrador); acceso `acceso-proveedor-oidc` 04:36:35, `UPDATE_COMPLETE` 04:36:48 (operador); zips `runtime-1955fbf46385` y
`aplicador-6b114251db4a` subidos ~04:37; base `base-aplicador-roles-de-persona` 04:39:41, `UPDATE_COMPLETE` 04:40:08; runtime
`runtime-fase-23` 04:40:09, `UPDATE_COMPLETE` 04:40:36, runtime y endpoint `DEFAULT` en la version 3 (`READY`), Lambda del aplicador
`Active`. Leido a las 04:41: las cuatro plantillas desplegadas son identicas a `infra/cfn/*.yaml`; el proveedor OIDC existe con
`agente-iam-cli` como unico cliente. Hallazgos del despliegue: los manejadores de `AWS::IAM::OIDCProvider` y de CloudFront piden
`iam:ListOpenIDConnectProviders` y tres `List*` de CloudFront (sin recurso, se anadieron a `arranque.yaml`);
`cloudfront:CreateDistributionWithTags` ya no existe como accion de IAM; y CloudFormation acepto el proveedor OIDC sin
`ThumbprintList` (IAM puso una huella). **Prueba de fuego medida el 26-10-2026 (UTC; `docs/MEDICIONES.md` O.2 y O.3):** `aprobador.demo`, fuera de
`agente-iam-solicitantes`, no obtiene token (Identity Center responde "No access"); `solicitante.demo` envio
`persona-finanzas-demo.json` y obtuvo `propuesta` en 25 s (`req-20261026-de924c07`; el reenvio con la misma `--clave` dio
`registro_existente` con el mismo id); `aprobador.demo` la aprobo a las 18:33:07 y el aplicador la dejo `aplicada` 5 s
despues (politica con `DateLessThan` en los dos `Allow`, rol con boundary `AgenteIAM-Techo`, cuatro etiquetas y confianza por
`aud` y `sub`); `asumir` funciono al primer intento 38 s despues de `CreateRole`, y con otro `sub` o con mas horas que las
pedidas se rechazo. Hallazgo (`docs/MEDICIONES.md` §H 39): la primera aprobacion dio 409 porque la Lambda
`agente-iam-aprobacion` seguia con el zip del 25-10; el despliegue no la habia reempaquetado aunque la tarea 9 cambio
`aprobar.py`. Se arreglo a las 18:32 UTC con `aprobacion-346e7b8b0cec.zip` y el change set `base-aprobacion-fase-23`. Regla
que deja: cada cambio en `agente_iam/` se contrasta con las tres listas de `scripts/empaquetar.sh` y se reempaqueta cada
Lambda que lo lleve (`aprobar.py` viaja en la aprobacion y en el aplicador). Sin medir (`docs/MEDICIONES.md` §J): el
vencimiento real del rol a las 22:33:12 UTC y la consistencia eventual a los 10 s exactos.

Revision del bloque 1 (26-10-2026): una revision de codigo posterior encontro ocho puntos de severidad media y se
corrigieron todos, cada uno con su test: (1) el tope de roles vigentes solo se comprobaba en el intake, y ahora el aplicador
lo repite al aplicar (entre aprobar y aplicar pueden haberse aplicado otras solicitudes); (2) la redundancia daba por
cubierto el permiso con un rol vigente que vencia antes que el pedido, y ahora compara solo contra roles que vencen a la misma
hora o despues; (3) una coma en el usuario pasaba el nombre del rol pero no el patron de etiqueta de IAM, y ahora el alfabeto
del usuario normalizado es `[a-z0-9+=.@_-]`; (4) `client_id` era opcional en `PersonaDelToken` y el servidor sin
`client_id` en el token responde `sin_persona`; (5) la respuesta al navegador llevaba el registro entero, y ahora lleva una
vista reducida (`servidor.vista_publica`); (6) `correo_aviso` tenia un patron laxo y ahora es ASCII estricto; (7) el aplicador
no cruzaba los bloques del registro, y ahora lo hace (`_coherencia_de_modo`); (8) el `vence` leido de la politica de un
reintento se adoptaba sin mirarlo, y ahora tiene que ser futuro y no pasar de las horas pedidas. Ademas, `roles_vigentes`
filtra por `sub` (dos personas con el mismo usuario normalizado no se cuentan entre si), el aplicador trata
`CLIENTES_COGNITO_INVALIDOS` como entorno roto y las plantillas ganan `iam:ListRoles` del aplicador (`base.yaml`) y las
sentencias con `*` de CloudFront (Create) y de `iam:ListOpenIDConnectProviders` (`arranque.yaml`), porque la referencia de
autorizacion dice que esas acciones no admiten recurso. La cifra de la suite, ver `CONTEXTO.md` §2. Esas plantillas y ese codigo son los
que se desplegaron el 26-10-2026 (O.1) y se midieron de punta a punta (O.2, O.3).

Bloque 2 (pagina web), desplegado y medido el 26-10-2026 (UTC, `docs/MEDICIONES.md` O.4). Se implemento en las tareas 14 y 15:
`web/index.html`, `web/estilos.css` y `web/app.js` (sin dependencias; tokens solo en la memoria de la pestana; texto con
`textContent`; el `id_token` solo va a STS y el `access_token` solo al runtime; PKCE con `crypto.subtle`; `sessionStorage` solo
para `verifier` y `state`), `scripts/construir_web.py` (genera `config.js` desde las salidas de las pilas), `infra/cfn/web.yaml`
(bucket privado `agente-iam-web-<cuenta>` con `Retain`, politica que solo deja leer a su distribucion por `aws:SourceArn` y
niega sin TLS, OAC con sigv4, politica de cabeceras con CSP cerrada, HSTS, nosniff, no-referrer y DENY, distribucion con HTTPS
obligatorio, GET y HEAD, CachingOptimized y `PriceClass_100`), el cliente `agente-iam-web` en `acceso.yaml` (con
`UrlRetornoWeb` vacio no hay cliente; el proveedor OIDC lista los dos clientes) y los tests `tests/unitarios/test_web.py` (17) y
`tests/seguridad/test_pila_web.py` (18), con `tests/seguridad/test_pila_acceso.py` adaptado. Se desplego en este orden (el
operador, salvo los ficheros): pila `web` (18:47 a 18:50 UTC, sin fallo de permisos), `acceso` con `UrlRetornoWeb` (18:51),
`runtime` con `ClienteWebId` (18:52, runtime en la version 4 con dos clientes admitidos) y, por ultimo, los cuatro ficheros de
`web/` mas `config.js`, que sube el administrador con su `Content-Type` (el operador no puede escribir en ese bucket) y una
invalidacion `/*` cada vez que se resube. Medido: los tres preflight de CORS pasan (el del runtime admite tambien la cabecera de
sesion si se pide, asi que `app.js` la manda; Cognito en `/oauth2/token`; STS tambien, incluso en el error); la pagina responde
con todas las cabeceras; HTTP redirige a HTTPS; el bucket por su URL de S3 da 403; y el flujo entero en el navegador integrado
con `solicitante.demo` (MFA): entrada, formulario con las listas del servidor, envio de 2 horas ->
`redundante_no_requiere_cambio` (`req-20261026-9c08d5d7`), envio de 6 horas -> `propuesta` (`req-20261026-08a49e27`),
aprobacion por `aprobador.demo`, `aplicada` 4 s despues con la confianza con `aud` de dos clientes y "Obtener credenciales":
STS responde desde el navegador con credenciales de 6 horas. Recargar la pagina pierde la sesion (nada en `sessionStorage`,
`localStorage` ni cookies). Tres hallazgos: (1) el runtime admite la cabecera de sesion en el preflight si se pide; (2)
CloudFront aplica `MinimumProtocolVersion: TLSv1` e ignora `TLSv1.2_2021` con el certificado por defecto (TLS 1.2 real exige
certificado en ACM y dominio propio); (3) la redundancia por persona contra un rol vigente funciona en la cuenta (primera
medicion: el rol de la manana cubre la lectura de 2 horas y vence despues; con 6 horas el rol vigente vence antes y no
cuenta). Hallazgo menor corregido: con `redundante_no_requiere_cambio` la pagina mostraba el boton de credenciales; ahora solo
lo muestra con `propuesta` y lleva un mensaje fijo por estado. Sin medir (`docs/MEDICIONES.md` §J): el vencimiento real de los
dos roles de persona vigentes y TLS 1.2 como minimo real.

Bloque 3 (correo), desplegado y medido el 26-10-2026 (UTC, `docs/MEDICIONES.md` O.5). Se escribio y probo sin red en las
tareas 18 y 19: `agente_iam/avisos.py` (Lambda `agente-iam-avisos`, mismo zip que el aplicador; siete estados avisan; el
cuerpo lleva solo id, estado, una frase fija y, en `aplicada`, rol y vencimiento; `MessageRejected` y
`MailFromDomainNotVerified` quedan en WARNING sin relanzar; `AGENTE_IAM_REMITENTE` es obligatoria),
`tests/unitarios/test_avisos.py`, `scripts/empaquetar.sh` (`avisos.py` en las tres listas), `base.yaml` (parametro
`CorreoRemitente` y rol `AgenteIAM-Avisos`) y `runtime.yaml` (`CorreoRemitente`, `RegistroAvisos`, `FuncionAvisos` y
`DisparadorAvisos` con filtro de los siete estados, lote de 1, sin reintentos ni cola), con tests en `test_pila_base.py` y
`test_pila_runtime.py`. Desplegado en este orden, con el si de Mateo a cada escritura: identidad de SES del remitente creada
por API (19:31:15 UTC; `SUCCESS` a las 20:00 tras pulsar Mateo el enlace); zip `agente-iam/aplicador-07540418c756.zip` (19:31:50,
lleva `avisos.py`); change set `base-rol-avisos` (Add `RolAvisos`, `UPDATE_COMPLETE` 19:33:24); change set `runtime-avisos`
(Modify `FuncionAplicador` Code, Add `RegistroAvisos`, `FuncionAvisos`, `DisparadorAvisos`, `UPDATE_COMPLETE` 19:33:55). SES en
`agente-iam` esta en modo inicial (medido: `ProductionAccessEnabled` false, 200 por dia).

Hallazgo (`docs/MEDICIONES.md` §H 40): SES autoriza `ses:SendEmail` tambien sobre la identidad del DESTINATARIO. El rol solo
permitia la del remitente y el primer aviso (19:35 UTC) dio `AccessDenied`. Se corrigio con `Resource: identity/*` y la
condicion `ses:FromAddress` = remitente (change set `base-rol-avisos-2`, `UPDATE_COMPLETE` 19:39:26; el test
`test_el_rol_de_avisos_solo_manda_desde_el_remitente_y_no_toca_tabla_ni_iam` se adapto). Regla: antes de escribir un
`Resource` estrecho, mirar sobre que recursos evalua el servicio la accion y poner la restriccion en la condicion que la
expresa. Segunda regla, de operacion: verificar el remitente ANTES del primer evento, porque los avisos no se reintentan y
los dos de `req-20261026-1dfe50ff` (`aprobada` y `aplicada`, 19:49 UTC) se perdieron con el remitente aun `PENDING`.

Medido (O.5): tras la correccion, un destinatario sin verificar da `MessageRejected`, que queda en WARNING con solo el
dominio y sin reintento (`req-20261026-83b510fc`, 19:39 UTC); `propuesta` no invoca a la Lambda (filtro, 0 invocaciones);
los correos reales `rechazada_en_chequeos_previos` (20:01:02), `aprobada` (20:04:58, 0,5 s tras la aprobacion) y `aplicada`
(20:05:03, con `Rol:` y `Vence:`) salieron para `req-20261026-2e923bc5` y `req-20261026-122e10a7`. Lambda: python3.12 arm64,
256 MB, 30 s, rol `AgenteIAM-Avisos` (boundary `LimiteSistema`; Allow `ses:SendEmail` sobre `identity/*` con
`ses:FromAddress`, leer el stream, logs; Deny tabla, filas, IAM y Bedrock). Sin medir: `MailFromDomainNotVerified` (SES
respondio `MessageRejected` tambien con el remitente sin verificar) y un aviso con otro `ClientError` (throttling). La tabla
queda con 9 filas. Los roles de persona de la demo siguen vigentes (decision de Mateo): `...-de924c07` (vence 26-10-2026 a
las 22:33:12 UTC), `...-1dfe50ff` (22:49:42 UTC del 26-10-2026), `...-122e10a7` (27-10-2026 a las 01:05:02 UTC) y `...-08a49e27`
(27-10-2026 a las 01:20:12 UTC). Suite: 1361 pasados y 1 saltado (26-10-2026).

Pendiente (quien):
- Mateo: decidir si un dominio propio verificado en SES (DKIM) para que los avisos no caigan en spam (los dos de `req-20261026-122e10a7`
  llegaron a spam de Gmail; O.5); decidir si se compra un dominio
  propio y un certificado en ACM para fijar TLS 1.2 en la pagina; decidir si algun dia hay destinatarios reales y entonces
  salir del modo inicial de SES; decidir el borrado de roles vencidos (fase posterior).
- Claude: nada; el vencimiento real se midio a las 22:33 UTC del 26-10-2026 (O.6: el permiso corta a los 8 s de `vence` con la
  sesion viva, y el canje nuevo da `AccessDenied` mientras el rol vigente sigue entrando).

Lecciones: `ESTUDIO-diseno-y-seguridad.md` §23.

### Fase 24 - Guia visual de la arquitectura

Que: una carpeta `docs/arquitectura/` con la arquitectura dibujada y animada. Fuente `agente-iam-arquitectura.drawio` con dos
paginas ("1 Contexto", modelo C4 nivel 1 sin iconos; "2 Despliegue en AWS", con los iconos oficiales de AWS, las dos cuentas y la
region, los pasos 1 a 9 y F con su leyenda); las dos paginas exportadas a PNG y SVG; una animacion de un solo fichero y sin
dependencias (`agente-iam-animacion.html`, construida desde `animacion-plantilla.html` con los 11 pasos en un bloque JSON: vista
general, 1 a 9 y F; reproducir, paso a paso, teclado, y con `prefers-reduced-motion` resalta sin mover nada); y la guia
`GUIA-VISUAL.md` (metodo, como se hizo, como se edita, lista de revision, pendientes para portafolio, fuentes).
`scripts/construir_arquitectura.py` exporta con el CLI de draw.io de escritorio, quita del SVG las imagenes PNG de reserva que
draw.io pone tras cada `foreignObject` (medido el 26-10-2026: de 2,4 MB a 184 KB) y construye la animacion; con `--sin-exportar`
solo reconstruye la animacion. Salida 0 si se hizo, 1 si falta draw.io o fallo la exportacion.
Por que: peticion de Mateo del 26-10-2026, estudiar la arquitectura con una parte visual y aprender a hacerla.

Verificacion: `tests/unitarios/test_arquitectura_visual.py` (7 tests): cada flecha de la pagina 2 pertenece a un paso y cada flecha
citada existe; cada caja e insignia citada existe; los pasos son 0, 1 a 9 y F en orden; la animacion construida lleva los mismos
pasos que la plantilla; `quitar_reservas` solo quita la imagen tras `foreignObject`; `construir_animacion` quita la cabecera XML y
exige una sola marca; los SVG del repositorio no llevan reservas. Se puso en rojo quitando una flecha de un paso (fallan 2 tests).
La animacion se probo en el navegador integrado el 26-10-2026: paso 6, paso F con el camino en rojo, reproduccion, ancho de movil de
375 px sin scroll horizontal de la pagina y movimiento reducido forzado (sin punto que se mueva y 51 elementos atenuados).
Entorno: draw.io de escritorio 32.3.0 (`CONTEXTO.md` §12). No toca la cuenta AWS.

Pendiente (quien):
- Mateo: decidir la version de portafolio (con tildes, version de un minuto, GIF o video para el README).
- Claude: nada.

Lecciones: `ESTUDIO-diseno-y-seguridad.md` §24.

### Fase 25 - Version en ingles de la guia visual

Que: peticion de Mateo del 26-10-2026, traducir las imagenes y anadir un boton de idioma a la animacion. La tabla
`docs/arquitectura/traduccion-en.json` (111 entradas: los 109 textos del .drawio y los 2 nombres de pagina, por texto exacto en
espanol) alimenta a `scripts/construir_arquitectura.py`, que antes de exportar genera `agente-iam-arquitectura-en.drawio` desde el
espanol (no se edita a mano; paginas "1 Context" y "2 AWS deployment") y exporta las dos paginas de los dos .drawio
(`agente-iam-contexto-en` y `agente-iam-despliegue-en`, .png y .svg). Si falta una traduccion, el script sale con 1 y lista los
textos que faltan sin escribir nada. La animacion (`animacion-plantilla.html` y `agente-iam-animacion.html`) lleva un boton ES/EN
arriba a la derecha, el texto en ingles de cada paso y los dos SVG; elige idioma por este orden: `?lang=es` o `?lang=en` en la URL,
el ultimo elegido (localStorage, con try/catch) y el del navegador (espanol si empieza por "es", si no ingles). Cambiar de idioma a
mitad de un paso lo repite en el otro idioma. Los valores reales del codigo (propuesta, aprobada, aplicada, AgenteIAM-Techo,
aprobar_cliente) no se traducen. `--sin-exportar` regenera el .drawio en ingles y la animacion sin draw.io.
Por que: que la guia pueda leerla quien no lee espanol, sin mantener dos dibujos a mano.

Verificacion: `tests/unitarios/test_arquitectura_visual.py` pasa de 7 a 11 tests; los nuevos: cada texto del .drawio tiene
traduccion y ninguna sobra; el .drawio en ingles del repositorio es el que sale de traducir el espanol; `traducir_drawio` conserva
ids y geometria y avisa de lo que falta; cada paso lleva su texto en ingles. Se puso en rojo quitando una traduccion (fallan 2 tests
y el script sale con 1 nombrando el texto que falta). Las dos paginas en ingles se revisaron a ojo exportadas a PNG (una etiqueta se
acorto: "creates role + policy"). En el navegador integrado (26-10-2026): cambio a ingles a mitad del paso 2 (panel, titulo del
documento, atributo `lang`, etiqueta del punto y diagrama en ingles; el paso se repite), vuelta a espanol sin restos y ancho de
movil de 375 px sin scroll horizontal. Servida por http://127.0.0.1 con un servidor temporal: `?lang=en` abre en ingles y la eleccion
guardada gana al idioma del navegador. Hallazgo menor: el navegador integrado convierte los ficheros locales en una URL `data:`,
que pierde los parametros y no deja usar localStorage; la pagina no falla (try/catch) y el boton funciona. Tests al cerrar
(26-10-2026): 1372 pasados y 1 saltado. No toca la cuenta AWS.

Pendiente (quien):
- Mateo: lo que sigue abierto de la version de portafolio (tildes en la version en espanol, version de un minuto, GIF o video para el
  README).
- Claude: nada.

### Fase 26 - Carpeta del portafolio

Que: peticion de Mateo del 26-10-2026, una carpeta solo para las piezas que se publican fuera del repositorio (LinkedIn y su
pagina personal). Se creo `portafolio/` en la raiz con `README.md` (proposito, reglas y pendientes) y `diagrama-arq.png`, el diagrama
de la pagina "2 Despliegue en AWS" de `docs/arquitectura/agente-iam-arquitectura.drawio` con su leyenda paso a paso, en espanol,
4361 x 2150 px, exportado por Mateo desde draw.io el 26-10-2026. Es una copia: la fuente sigue en `docs/arquitectura/` y, si cambia
el .drawio, la imagen se vuelve a exportar a mano (ningun test vigila esta carpeta).
Por que: separar lo que se muestra al publico de lo que sirve para estudiar y mantener el sistema, y tener un sitio donde mirar cada
pieza antes de publicarla.

Verificacion: la imagen se reviso a ojo entera antes de moverla; no se ve numero de cuenta, ARN, correo ni token.
`tests/seguridad/test_secretos.py` solo lee ficheros de texto, asi que una imagen solo se comprueba asi. Tests al cerrar
(26-10-2026): 1372 pasados y 1 saltado. No toca codigo ni la cuenta AWS.

Pendiente (quien):
- Mateo: decidir lo que lista `portafolio/README.md`: tildes y enes en la version en espanol, version de un minuto, GIF o video de la
  animacion, si el diagrama muestra lo pendiente y la imagen en ingles.
- Claude: nada.

### Fase 27 - Dominio propio para la pagina y TLS 1.2

Que: peticion de Mateo del 26-10-2026, fijar TLS 1.2 en la pagina web. Decisiones de Mateo el 26-10-2026: (1) el nombre es
`agente-iam.mateo.solutions`; (2) no se delega una subzona: los registros DNS (CNAME de validacion de ACM, alias A y AAAA) van en la
zona `mateo.solutions` de la cuenta de gestion y los crea Mateo en la consola, y el certificado de ACM lo pide el en la consola de
`agente-iam`, en `us-east-1`. Decisiones 3 (Cognito acepta solo el dominio) y 4 (`TLSv1.2_2021`) tomadas como las propuso Claude, a
confirmar por Mateo (son parametros y patrones). Escrito: `infra/cfn/web.yaml` con `DominioWeb` y `CertificadoArn` (vacios por
defecto, regla `DominioYCertificadoVanJuntos`, condicion `ConDominio`; con ellos `Aliases` y certificado de ACM en `sni-only` con
`TLSv1.2_2021`; `UrlWeb` pasa al dominio; salida nueva `DominioCloudFront`) e `infra/cfn/acceso.yaml` con `UrlRetornoWeb` aceptando
la URL de CloudFront o exactamente `https://agente-iam.mateo.solutions/`. Tests en `test_pila_web.py` (cinco nuevos y los demas
ajustados) y `test_pila_acceso.py` (patron ampliado). No hay pila de DNS ni permisos nuevos en el rol de despliegue. La pagina
personal y el agente siguen en dos distribuciones por el origen, las cabeceras y la cuenta de gestion (ADR-005, "Por que dos
distribuciones").
Por que: la distribucion queda en `TLSv1` con el certificado por defecto (medido en O.4) y las politicas TLS 1.2 solo rigen con
certificado propio en `sni-only`; Mateo ya tiene el dominio (`docs/MEDICIONES.md` P.1).

Verificacion: lecturas de solo lectura contra la cuenta el 26-10-2026 (`docs/MEDICIONES.md` P.1 a P.4). Tests (26-10-2026): 1376
pasados y 1 saltado. Prueba de mutacion: cambiar `sni-only` y abrir el patron del dominio pone los tests en rojo. `cfn-lint` sin
avisos en las dos plantillas. Certificado pedido y validado: Mateo lo pidio el 26-10-2026 en la consola de `agente-iam` (`us-east-1`,
`agente-iam.mateo.solutions`, RSA-2048, validacion DNS) y creo el CNAME en la zona de gestion; `ISSUED` a las 02:12 UTC del
27-10-2026 (`docs/MEDICIONES.md` P.5). Paso 3 del ADR-005 (27-10-2026, UTC, `docs/MEDICIONES.md` P.6): change set `web-dominio` de
`agente-iam-web` ejecutado a las 02:17:32 con solo Modify de `Distribucion` sin reemplazo, pila `UPDATE_COMPLETE` a las 02:20:44 y sin
fallos de permisos (el rol de despliegue no necesita ACM). `GetDistribution`: alias, certificado de ACM, `sni-only`, `TLSv1.2_2021`.
Saludo TLS con OpenSSL 3.0.13 (se confirmo con `-msg` el ClientHello de TLS 1.1 y la alerta `protocol_version`): TLS 1.0 y 1.1
rechazados y 1.2 y 1.3 aceptados, tanto con el dominio como con `*.cloudfront.net` por SNI. `curl` con `--connect-to`: `200` con CSP y
cabeceras, HTTP `301`.
Pasos 4 y 5 (27-10-2026, UTC, `docs/MEDICIONES.md` P.7): alias A y AAAA de `agente-iam.mateo.solutions` en la zona de gestion (leidos con
`ListResourceRecordSets` a las 02:22; `dig` da tres IPv4 y tres IPv6 de CloudFront; `curl` por DNS real: `200` con HSTS, HTTP `301`).
Change set `acceso-dominio` de `agente-iam-acceso` con solo Modify de `ClienteWeb` sin reemplazo, ejecutado con el si de Mateo a las
02:25:09 (`UPDATE_COMPLETE` 02:25:15): `CallbackURLs` y `LogoutURLs` = solo el dominio; el id del cliente no cambio (runtime y proveedor
OIDC intactos). `/oauth2/authorize` sin token: la URL nueva va a Identity Center y la vieja da `redirect_mismatch`, pero el cambio en
Cognito tardo entre 43 y 74 s en aplicarse. Preflight de `/oauth2/token` con tres origenes (el dominio, CloudFront y
`https://evil.example.org`): los tres dan `200` y se reflejan. Creencia falsa corregida: el CORS de Cognito NO esta atado a la URL de
retorno; la barrera es la URL exacta y PKCE (`docs/MEDICIONES.md` §H 41; ESTUDIO §25).

Flujo en el navegador (27-10-2026, `docs/MEDICIONES.md` Q.1): Mateo entro en https://agente-iam.mateo.solutions como `solicitante.demo` (login,
MFA y envio) y el flujo funciona; dos solicitudes quedaron en el registro. Con ello se cierra el pendiente de TLS de §J.

Pendiente (quien):
- Mateo: confirmar las decisiones 3 y 4 (la 3 ya esta desplegada). Pasos 1 a 5 hechos (certificado, P.5; distribucion, P.6; alias DNS y
  Cognito, P.7) y flujo en el navegador hecho (Q.1).
- Claude: cerrar §J (hecho el 27-10-2026).
- Operador: nada.

### Fase 28 - Solicitud en texto, recurso comprobado y motivo de cada estado

Que: las cinco observaciones de Mateo del 27-10-2026 tras probar la pagina, con el diseno aprobado por el mismo dia
(`docs/superpowers/specs/2026-10-27-solicitud-en-texto-y-motivos-design.md`; con `nivel_entendido`, el ejemplo tal cual y el correo con
dominio propio primero). Escrito en codigo y plantillas el 27-10-2026; el paso 1 (correo con dominio propio) se desplego y midio ese
mismo dia (R.1 a R.5); los pasos 1 a 6 estan desplegados y medidos (R.1 a R.11).
- Punto 1, sin tipo de acceso: `tipo_acceso` pasa a opcional en `CamposEstructurados` (los registros anteriores lo conservan y se
  revalidan con el). La propuesta lleva `nivel_entendido` (`lectura` o `modificacion`), declarado por el modelo;
  `coherencia.chequeos_posteriores` aplica la barrera del catalogo contra ese nivel si no hay `tipo_acceso` y bloquea la propuesta que
  no trae ninguno. `coherencia.nivel_real(documento)` (`lectura`, `modifica`, `borra` o `None`) lo calcula el codigo con el catalogo ya
  en memoria (`catalogo.nivel_en_memoria` y `acciones_en_memoria`, sin descargar), se guarda en el registro como `nivel_real` y
  `riesgo_minimo` (parametro nuevo `nivel_real`) anade "la propuesta modifica datos" o "la propuesta puede borrar datos", de modo que el
  aprobador tiene que confirmar el riesgo; `aprobar`, `aplicador` y `aprobar_cliente` pasan el `nivel_real` guardado. La regla 1b del
  prompt pide `nivel_entendido` y el prompt omite los campos vacios. El limite del texto sube de 1000 a 1500 caracteres. La pagina ya no
  tiene "Tipo de acceso": la etiqueta es "Solicitud", con ayuda y el ejemplo; `config.js` ya no lleva `tiposAcceso`.
- Punto 2, ARN: `recurso` admite el nombre o el ARN; `models.nombre_desde_arn` saca el nombre por servicio (s3, dynamodb, lambda, sqs,
  sns, logs y cloudwatch; ec2 no admite ARN) y el ARN se guarda en `recurso_arn`. **Desviacion del diseno:** el servicio o la region
  distintos son un error del formulario (HTTP 422, "Revisa estos campos") y no `arn_no_coincide`, porque se pueden comprobar sin
  conocer la cuenta; solo la cuenta distinta se rechaza en los chequeos previos con `arn_no_coincide`
  (`coherencia.motivos_de_la_cuenta_del_arn`).
- Punto 3, existencia: `agente_iam/existencia.py` busca el recurso antes del modelo (`existe`, `no_existe`, `no_comprobado`,
  `no_aplica`). `no_existe` rechaza con `recurso_no_encontrado` sin llamar a Bedrock; `no_comprobado` sigue y anade el aviso
  `RECURSO_NO_COMPROBADO` para el aprobador; se salta si otro chequeo previo ya fallo. Interruptor `AGENTE_IAM_COMPROBAR_EXISTENCIA`
  (activo por defecto; `tests/conftest.py` lo pone a `0` en los tests sin red). El registro lleva `recurso_comprobado`. Los motivos de
  los chequeos previos tienen ahora codigo (`coherencia.chequeos_formulario_con_codigo`, `orquestador._chequeos_con_codigo`) y un
  registro rechazado lleva `motivos_codigos` ademas de `motivos`.
- Punto 4, motivo: `agente_iam/motivos.py`, `motivo_publico(registro)` -> {codigo, texto}, con frases fijas y nunca texto del modelo ni
  del solicitante. Sale en la respuesta del servidor (`vista_publica` gana `motivo`) y en el correo (`avisos.cuerpo_del_correo` gana
  `motivo` y `url_web`; `avisos.registro_de` rearma el registro desde la imagen del stream). Variable `AGENTE_IAM_URL_WEB` para el
  enlace `?solicitud=<id>` del correo `aplicada`; parametro `UrlWebAvisos` en `infra/cfn/runtime.yaml` (vacio por defecto; solo admite la
  URL de CloudFront o `https://agente-iam.mateo.solutions`).
- Punto 5, credenciales: la pagina ya no las ata a la respuesta del envio; hay una seccion "Usar un acceso aprobado" con el campo del id de
  la solicitud; arma el ARN del rol como `personas.nombre_de_rol` (con test de paridad contra node, si esta); el id del enlace del correo
  cruza el login dentro del `state` de OAuth; el `AccessDenied` de STS se traduce.
- Infra (desplegada el 27-10-2026, R.6 y R.9): el rol del runtime en `infra/cfn/base.yaml` gana `ComprobarQueElRecursoExiste` (dynamodb:DescribeTable,
  sqs:GetQueueUrl, sns:GetTopicAttributes, cloudwatch:DescribeAlarms y lambda:ListTags, con ARN de la cuenta) y
  `ComprobarQueElRecursoExisteSinTipoDeRecurso` (s3:ListAllMyBuckets y logs:DescribeLogGroups sobre `*`); el limite
  `AgenteIAM-LimiteSistema` en `infra/cfn/arranque.yaml` gana `ComprobarQueElRecursoExiste`. Empaquetado: `existencia.py` y `motivos.py`
  fuera de la Lambda de aprobacion, `existencia.py` fuera del zip del aplicador y `motivos.py` obligatorio en el (lo usa `avisos`).
- Ejemplos: `ejemplos/web/persona-finanzas-demo.json` sin `tipo_acceso`; nuevos `ejemplos/web/persona-recurso-inexistente.json` y
  `ejemplos/web/persona-con-arn.json`. Los ejemplos del modo de principal en `ejemplos/` conservan `tipo_acceso` a proposito (CLI de
  desarrollo; ejercitan el camino antiguo).
- Lo que se pierde, dicho claro (spec punto 1 y `ESTUDIO-diseno-y-seguridad.md` §26): sin el campo, el techo de nivel lo pone el modelo
  leyendo el texto.

Por que: `docs/MEDICIONES.md` Q.1 (una solicitud sin motivo visible, otra con un bucket inexistente y el boton de credenciales en
`propuesta`) y Q.2 (el aviso de `requiere_revision_humana` no llego ni a spam).

Verificacion (27-10-2026, sin red ni cuenta): `./.venv/bin/python -m pytest tests/ -q` da 1472 pasados y 1 saltado; cuatro ficheros de
tests nuevos (`test_recurso_arn.py`, `test_existencia.py`, `test_motivos.py`, `test_nivel_entendido.py`). Mutaciones: quitar la barrera de
`nivel_entendido` pone 2 tests en rojo; cambiar `MAX_NOMBRE_ROL` en `web/app.js` pone en rojo el test de paridad. ruff, bandit y cfn-lint
sin avisos. **Esa verificacion no midio nada contra la cuenta ni desplego nada**: lo de existencia, motivos y correo esta probado con
Stubber y registros de prueba, no en vivo. Paso 1 desplegado el 27-10-2026 (R.1 a R.5): identidad de dominio verificada con DKIM a las
04:17 UTC, remitente `avisos@agente-iam.mateo.solutions` en el rol y en la Lambda a las 04:19 UTC, primer aviso en la bandeja de entrada
de Gmail a las 04:23 UTC, y rechazo de `req-20261027-00a77ee2` (Q.3) a las 04:23 UTC.

Pasos 4 a 6 (27-10-2026, UTC; detalle en `docs/MEDICIONES.md` R.9 a R.11): change sets `base-fase-28` y `runtime-fase-28` sin
reemplazos (pilas `UPDATE_COMPLETE` 22:58:44 y 22:59:16; runtime `READY` en la version 5); pagina subida a las 23:00 e identica a
`local/web/`; en vivo, tres recursos inexistentes rechazados con `recurso_no_encontrado` y 0 tokens, una solicitud con ARN del bucket real
aprobada (exigio `--riesgo-alto-confirmado`, porque modifica datos) y aplicada, motivo en la pagina y en el correo, y credenciales por id
de solicitud con su `AssumeRoleWithWebIdentity` en CloudTrail. La captura de Mateo llevaba las credenciales completas y se compartio en la sesion de trabajo; Mateo
decidio dejarlas caducar (28-10-2026 01:19:55 UTC) y no se revocaron.

Pendiente (quien):
- Hecho en la Fase 30: Mateo eligio que solo la pagina esconda la fila "Rol previsto" fuera de los estados con rol; subida y medida (T.1).
- Mateo: el texto de `og:description` (86 caracteres; decidio subir sin alargarla, ver Fase 29).
- Claude, en la proxima prueba (R.11, "Sin medir"): `arn_no_coincide` y el 422 de servicio o region distintos en vivo, un registro anterior
  con `tipo_acceso` aprobado, las cabeceras DKIM y DMARC del correo, el uso real de las credenciales (listar, subir y un borrado que debe
  fallar), el intento denegado de `req-20261027-24c6c57f` que no aparece en CloudTrail, y `lambda:ListTags` sin recurso.
- Claude: el commit de la documentacion, hecho el 27-10-2026 (`e688214`).

### Fase 29 - Vista previa de la pagina en LinkedIn (Open Graph)

**Que.** El 27-10-2026 Mateo pidio que la pagina del agente tuviera etiquetas Open Graph: LinkedIn decia "We couldn't load a preview for
this link" porque la pagina solo traia `<title>`. En `web/index.html`, justo despues de `<title>`, van un `<meta name="description">` y 9
`<meta property="og:...">` (`og:type` website, `og:locale` es_CO, `og:title` "Agente IAM: pedir un permiso en AWS", `og:description`,
`og:url`, `og:image`, `og:image:width` 1200, `og:image:height` 627 y `og:image:alt`), todo en ASCII. La imagen es `web/vista-previa.png`
(1200 x 627, unos 99 KB): banda oscura con el titulo y la frase, una linea naranja y debajo `docs/arquitectura/agente-iam-despliegue.png`
sin su leyenda; pie con `agente-iam.mateo.solutions`. Se genero con Pillow en un entorno temporal de `uvx` (nada instalado en el
proyecto; el generador no esta en el repositorio). `scripts/construir_web.py` ahora copia `vista-previa.png` con el resto (`FICHEROS`).

**Por que.** Sin las etiquetas el enlace del perfil de LinkedIn no mostraba tarjeta. Las URL absolutas de `og:` son lo unico absoluto de la
pagina y los navegadores no las cargan, asi que la regla de "ninguna URL externa" se mantiene para todo lo demas.

**Verificacion.** `tests/unitarios/test_web.py`: el test que prohibe URL externas quita antes las etiquetas `og:`; test nuevo
`test_las_etiquetas_open_graph_apuntan_solo_al_dominio_y_a_una_imagen_propia` (claves obligatorias, toda URL empieza por el dominio, la
imagen existe, es un PNG de 1200 x 627 igual al ancho y alto declarados y esta en `FICHEROS`); el test de `escribir` comprueba todos los
ficheros de `FICHEROS`. Mutaciones: apuntar `og:image` a otro dominio pone en rojo 1 test; anadir un `<script>` externo, 2. Tests al
cierre: 1472 pasados y 1 saltado (27-10-2026). En vivo (`docs/MEDICIONES.md` S.1): el administrador (`org-agente-iam`) subio
el 27-10-2026 `index.html` a las 04:27:04 UTC y `vista-previa.png` a las 04:27:05 UTC, con el si de Mateo, e invalido `/`, `/index.html` y
`/vista-previa.png` (Completed 04:27:27 UTC). Como `web/` tenia los cambios sin terminar de la Fase 28 (formulario, `app.js`), no se
construyo desde `web/`: se armo en `local/web-og/` la pagina publicada (identica a `git show HEAD:web/index.html` y a lo que servia
CloudFront) mas solo esas 10 lineas, y el diff contra `HEAD` mostro nada mas que ellas. Despues: la pagina sirve las 9 etiquetas,
`/vista-previa.png` responde 200 `image/png` de 98729 bytes, el formulario sigue siendo el viejo (ningun cambio web de la Fase 28 salio) y
el Post Inspector de LinkedIn muestra titulo, imagen y descripcion, con un solo aviso: la descripcion deberia tener al menos 100 caracteres
(la nuestra, 86). La vista previa funciono despues en el formulario de Proyectos del perfil. Los textos del perfil (titular, Acerca de y
una entrada de Proyectos) se publicaron el mismo dia desde `portafolio/` y estan registrados alli.

Pendiente (quien):
- Mateo: el texto de `og:description` a 100 caracteres o mas; la subida de la Fase 28 salio sin alargarla (decision de Mateo, 27-10-2026).
- Operador y administrador: toda subida de la pagina incluye `vista-previa.png` (`image/png`); `construir_web.py` ya lo copia. La subida
  de la Fase 28 (27-10-2026, R.10) llevo las etiquetas, porque estan en `web/index.html`.
- Mateo: nada.

### Fase 30 - La fila "Rol previsto" solo donde puede haber rol

**Que.** El 27-10-2026 la pagina deja de mostrar la fila "Rol previsto" en las solicitudes que no pueden acabar con un rol. En
`web/app.js` hay una constante nueva, `ESTADOS_CON_ROL = ["propuesta", "aprobada", "aplicada"]` (lista de permitidos: un estado nuevo sale
con la fila oculta hasta que se anada). `pintarResultado` pone `hidden` en la etiqueta y en el valor de la fila cuando el estado no esta en
esa lista, y lo quita cuando si esta (una solicitud nueva vuelve a mostrar la fila que la anterior escondio). En `web/index.html` la
etiqueta `<dt>` de la fila lleva ahora `id="rol_previsto_etiqueta"`; el CSS ya tenia `[hidden] { display: none !important; }`. El servidor
(`agente_iam/servidor.py`, `vista_publica` y la respuesta de `manejar`) no cambia: sigue devolviendo `rol_previsto` en todos los estados.

**Por que.** `docs/MEDICIONES.md` R.11 ("Observacion"): en una solicitud rechazada (`req-20261027-24c6c57f`) la pagina mostraba "Rol
previsto" con el ARN de un rol que no existe ni existira. No era un fallo de seguridad (no hay nada que canjear), pero confundia. Claude
explico dos opciones y Mateo eligio la (a) el 27-10-2026: (a) solo la pagina esconde la fila; (b) el servidor deja de devolver
`rol_previsto` en esos estados y la pagina esconde la fila si no llega (cambia el contrato de salida, obliga a reempaquetar el runtime y a un
change set). Claude recomendo (a) y Mateo la eligio: es un problema de presentacion; el dato del servidor no es falso (dice que rol tendria la persona
si se aplica) y lo usa tambien `scripts/solicitar.py`; el ARN no es secreto (la pagina ya sabe armarlo con `nombreDeRol`), asi que (b) no
anadia seguridad.

**Verificacion.** `tests/unitarios/test_web.py`, seccion "Fase 30": `test_en_un_estado_sin_rol_la_pagina_esconde_la_fila_del_rol`
(parametrizado: `rechazada_en_chequeos_previos`, `rechazada_por_aprobador`, `redundante_no_requiere_cambio`, `requiere_revision_humana`,
`bloqueada_al_aplicar`, `error` y un estado inventado), `test_en_un_estado_que_puede_acabar_en_rol_la_fila_vuelve_y_lleva_el_arn`
(`propuesta`, `aprobada`, `aplicada`, despues de un rechazo) y `test_la_etiqueta_del_rol_tiene_id_para_poder_esconderla`. Los dos primeros
ejecutan la funcion real `pintarResultado` de `app.js` con node sobre un DOM de mentira (se saltan si no hay node, como el test de paridad
de `nombreDeRol`). Antes del cambio en `app.js` e `index.html`, los 7 casos de estado sin rol y el del id estaban en rojo (8 fallos,
`assert False is True`); despues, en verde. Tests al cierre: 1483 pasados y 1 saltado (27-10-2026; el saltado es
`tests/funcionales/test_techo_en_vivo.py`, cerrado por diseno); ruff limpio en el test. Subida el 27-10-2026 (`index.html` y `app.js`,
invalidacion `Completed`; lo servido es identico a `web/`): detalle en `docs/MEDICIONES.md` T.1.

Pendiente (quien):
- Mateo: ver en el navegador una solicitud rechazada sin la fila "Rol previsto": hecho el 02-11-2026 con `req-20261102-d7c5aa51`, sin la
  fila (visto por Claude en el fotograma de la toma del video, no por una lectura del DOM; `docs/MEDICIONES.md` V.2).
- Claude: el commit, hecho el 27-10-2026 (`404f67a`).

### Fase 31 - Prompt de s3: un intento en vez de dos

**Que.** El 28-10-2026 el prompt del modelo deja de gastar dos intentos en cada solicitud de s3. En `agente_iam/agente.py` hay una funcion
nueva, `aviso_variable_de_cuenta(valor)`, que usa la regla 2c de `SYSTEM_PROMPT`: dice que `${aws:PrincipalAccount}` es una variable de
politica que AWS resuelve al evaluar, que se copia tal cual (con el dolar y las llaves) y que no se sustituye por el numero de cuenta de
los datos verificados. Con `VALOR_CUENTA_DEL_RECURSO = None` (techo de cuenta literal) el aviso no aplica y la funcion devuelve "", porque
entonces el modelo recibe `<cuenta>` y si debe sustituirlo. El resto del prompt, los chequeos (S5 incluido) y el contrato no cambian.

**Por que.** `CONTEXTO.md` §8 y `docs/MEDICIONES.md` M.5 (25-10-2026) y R.11 (27-10-2026, 24 316 tokens de entrada): en s3 el modelo escribia
la cuenta literal en `aws:ResourceAccount` en el primer intento aunque la regla 2c le daba `${aws:PrincipalAccount}`; S5 lo bloqueaba y el
segundo intento ponia la variable. La propuesta final salia bien, pero cada solicitud de s3 costaba una llamada al modelo de mas. Claude lo
propuso el 27-10-2026 como la unica decision abierta de `CONTEXTO.md` §11.2 que mejora el producto (las demas son endurecimientos: pendientes
2 y 3 del ADR-003, hashes en `constraints.txt`, casos 1 a 4 de la matriz de regiones, segundo rol con `SourceIdentity`) y Mateo pidio hacerlo
el mismo dia.

**Verificacion.** Test nuevo en `tests/seguridad/test_revision_2026_10.py`,
`test_la_regla_2c_pide_copiar_la_variable_de_cuenta_sin_sustituirla`: en rojo antes de existir la funcion; una mutacion que quita el aviso
del prompt lo pone en rojo. Tests: 1484 pasados y 1 saltado (28-10-2026); ruff, mypy y bandit limpios. Medido en local con Bedrock real
(Haiku 4.5, perfil administrador, por el CLI, registros en disco, nunca en DynamoDB) con `ejemplos/solicitud-finanzas-demo.json`, 5 veces
sin el cambio y 5 con el cambio (`docs/MEDICIONES.md` U.1):

| | Intentos | Tokens de entrada (media) | Tokens de salida (media) | Latencia del modelo |
|---|---|---|---|---|
| Antes | 2 (en las 5 corridas) | 23 239 a 23 633 (23 459) | 2 216 a 2 280 (2 251) | 15,1 a 15,8 s |
| Despues | 1 (en las 5 corridas) | 12 473 a 12 675 (12 614) | 1 298 a 1 536 (1 469) | 8,8 a 9,7 s |

La propuesta final fue identica en los 10 registros. Revision independiente antes de desplegar (28-10-2026, un agente revisor de solo
lectura con el modelo Fable, a peticion de Mateo): sin bloqueantes; confirmo los registros, los tests y que `agente.py` solo viaja en el zip
del runtime. Desplegado el 28-10-2026 con el si de Mateo: zip `agente-iam/runtime-304f3085faca.zip` y change set `runtime-prompt-s3` de
`agente-iam-runtime`, un solo Modify de `Runtime`, sin reemplazo; runtime en la version 6, `READY` (`docs/MEDICIONES.md` U.2;
`docs/DESPLIEGUE.md`, Fase 31). La revision encontro tambien un error de `docs/DESPLIEGUE.md` sobre la clave del zip del runtime, ya
corregido alli.

Pendiente (quien):
- Medida en vivo una solicitud de s3 por el runtime v6: hecho el 02-11-2026 con `req-20261101-7edd7bd0` (la pagina, `solicitante.demo`),
  un intento y 12 637 tokens de entrada, como en local (`docs/MEDICIONES.md` V.1).
- Claude, cuando haya ocasion: un s3 de modificacion, un caso que no sea s3 y `ejemplos/solicitud-servicio-cruzado.json`, que el revisor
  sugirio medir en vivo (U.1 solo cubre una lectura de s3, por el CLI y no por el runtime en modo `rol_por_persona`).
- Claude: el commit, hecho el 28-10-2026 (`7750f28`).

### Fase 32 - Video de demostracion de punta a punta

**Que.** El 02-11-2026 se graba, se monta y se revisa el video corto que muestra el sistema funcionando contra la cuenta real, y queda en
`portafolio/demo-agente-iam-es.mp4` (72,27 s, 1920x1080 a 30 fps, sin voz, rotulos en espanol). Se ve: un rechazo antes del modelo (un
bucket que no existe), una solicitud de lectura de `finanzas-demo` que acaba en propuesta, la revision y la aprobacion en la terminal del
aprobador, el correo `aplicada` y las credenciales en "Usar un acceso aprobado". Cuatro tomas (dos de Mateo en el navegador, dos de Claude en
la terminal con el si de Mateo), montadas por un agente con un script reproducible que vive en `local/video/` (fuera del repositorio). El guion,
la forma de grabar, los cortes por escena y lo tapado estan en `docs/VIDEO-DEMO.md`. No cambia codigo, tests ni infraestructura.

**Por que.** Decision de Mateo del 31-10-2026: una pieza para LinkedIn, sin voz, de 60 a 90 segundos, que muestre una peticion real de punta a
punta y la respuesta con su porque, con el sistema funcionando contra la cuenta real.

**Verificacion.** El agente del montaje miro los 72 fotogramas (uno por segundo) y corrigio un fallo propio (se veian cuatro digitos del
nombre del bucket en el JSON); no hubo OCR (no habia `tesseract`). Claude reviso seis fotogramas clave. Mateo vio el video entero y lo dio por
bueno. Tapado con desenfoque: numero de cuenta, correo de Mateo y el bloque de credenciales. Se aparta del guion en dos cosas: la portada dura
7 s (no 8) y la escena de la revision, 19 s. Lo medido contra la cuenta (la Fase 31 en vivo, la Fase 30 en el navegador y la solicitud de
punta a punta) esta en `docs/MEDICIONES.md` V; las herramientas de grabacion, en `docs/VIDEO-DEMO.md`. Los tests no cambian (no hay codigo).

Pendiente (quien):
- Mateo: publicarlo en LinkedIn.
- Mateo: decidir si se tapan o se dejan visibles el sufijo del permission set del aprobador, la huella y la hora de aprobacion (se ven, no
  son datos prohibidos), y si se rehace la escena de credenciales, donde el bloque "Tu solicitud" sigue diciendo "Estado: propuesta".
- Claude: el commit, hecho el 02-11-2026 (`785e390`).

### Fase 33 - Auditoria de seguridad y revision para publicar el repositorio

**Que.** Peticion de Mateo del 18-11-2026: revisar todo el proyecto para poder hacer publico el repositorio y, de paso, hacerle pruebas
adversariales. Dos frentes. Uno, la revision de publicacion: el arbol en `ba2adb2`, la historia completa, los binarios y lo que GitHub guarda
ademas del codigo. Otro, la auditoria adversarial con la skill `security-aws-audit`: reconocimiento, 20 unidades de cobertura, una ola de 9
cazadores, un critico y un verificador independiente por pista. Los informes viven fuera del repositorio, en
`~/security-aws-audit/Agente-IAM/run-1/` (`REPORT.md`, `PUBLICACION.md`, `provider-facts.md`). No cambia codigo, tests, infraestructura ni la
cuenta.

Resultado. El repositorio de origen no se publica tal cual, por dos bloqueos: la historia de git conserva la cuenta real en el commit inicial y el correo personal del
autor en los 88 commits, y `origin/main` apunta a ese commit inicial; y tres borradores de LinkedIn en `portafolio/` nombraban a una tercera
persona real y llevaban reglas privadas (sacados del arbol ese mismo dia, ver "Limpieza"; siguen en la historia). `CONTEXTO.md` §5 decia que la cuenta real nunca iba en lo versionado; se corrige en esta fase (vale para el arbol, no para
la historia). Hallazgos confirmados: 0. Pistas sin confirmar (`needs_validation`, sin severidad), cada una con traza y resultado local, a la
que le falta un hecho de la cuenta o de AWS:
- Pista 1, `infra/cfn/identidades.yaml` y `infra/cfn/arranque.yaml`: por las plantillas, quien despliega (permission set del operador) puede
  llegar a escribir `aprobacion` saltandose la Lambda de aprobacion.
- Pista 2, `agente_iam/coherencia.py` y `agente_iam/herramientas/catalogo.py`: una concesion de escritura como `sns:Subscribe` configura una
  entrega de datos a un destino que elige el beneficiario.
- Pista 3, `agente_iam/avisos.py` y `agente_iam/servidor.py`: el correo de aviso va a la direccion que escriba quien pide, sin compararla con
  la persona del token.
- Pista 4, `agente_iam/servidor.py` y `agente_iam/orquestador.py`: no hay tope de solicitudes por persona, y cada clave nueva es una corrida
  del modelo.

**Por que.** El repositorio es privado y se quiere publicar como portafolio.

**Verificacion.** Todo en local y sin tocar la cuenta: sandbox sin red con la autoprueba pasada; ningun agente llamo a AWS; dos validadores
de la skill en verde (4 registros, 23 unidades); cada pista paso por un verificador que intento refutarla y no pudo; hechos de AWS comprobados
contra documentacion (PF1 a PF6; PF7 sin resolver), todo en `docs/MEDICIONES.md` W. Es una pasada parcial: un limite de uso corto la ola de
cazadores a mitad, hubo que relanzarla (9 agentes interrumpidos sin resultado y 9 relanzados) y la validacion se bajo al perfil `quick`.
Agentes: tope 30, gastados 27 (4 de reconocimiento, 9 interrumpidos, 9 relanzados, 1 critico, 4 verificadores), mas 3 revisores de
publicacion fuera del libro de cobertura; la ola relanzada, el critico y los verificadores corrieron con Opus. Quedaron sin cubrir una unidad
bloqueada por un hecho de la cuenta y dos aplazadas por el critico. Los tests no cambian (no hay codigo); corridos el 18-11-2026: 1484
pasados y 1 saltado, primero con el rodeo de `docs/MEDICIONES.md` W.5 y, reparado el `.venv`, con el comando normal. Con los arreglos de codigo: 1496 pasados y 1 saltado.

**Limpieza para publicar (18-11-2026, con el si de Mateo).** Sin tocar codigo, infraestructura, GitHub ni la cuenta:
- El `.venv` se reparo sin reinstalar nada: su `bin/python` apuntaba al Python del sistema (hoy 3.14) y ahora apunta al Python 3.12 de `uv`
  (W.5). `./.venv/bin/python -m pytest tests/ -q` vuelve a dar 1484 pasados y 1 saltado.
- Los tres borradores de LinkedIn (perfil, proyecto y post) salieron del arbol a `local/portafolio/`, y `portafolio/README.md` ya no los lista.
- Se quitaron el prefijo real del dominio de Cognito (CONTEXTO §5 y MEDICIONES K) y el nombre de un presupuesto (CONTEXTO §5), y se
  reescribio la nota de la captura con credenciales (MEDICIONES R.11 y Fase 28 de este plan) sin cambiar el hecho.
- `docs/DESPLIEGUE.md` y `docs/PRUEBAS-AGENTCORE.md` ya no mandan al lector a un commit que no estara en el repositorio publico.
- Textos que daban por abierto algo ya cerrado, puestos al dia: ESTUDIO §5, §16 y §18 (mitigacion de la huella, estado del techo), la fila
  25 de MEDICIONES §H, los pendientes de la Fase 17, dos frases del README (Fases 27 y 28) y el paso de gitleaks del CI en CONTEXTO §10
  (leido con `gh`: se ejecuta, y la ultima vez dio `success`).

**Arreglos de codigo (18-11-2026, sin desplegar).** Cuatro arreglos, cada uno con su test escrito antes y visto en rojo. En la cuenta sigue
el codigo anterior hasta que se suban los zips y los change sets.
- La Lambda de aprobacion ya no acepta `autoaprobacion_demo`. `aprobar.decidir` con `exigir_persona=True` (solo lo pone `manejador`)
  responde 409 antes de leer si la peticion la trae, al aprobar y al rechazar. Antes dejaba la fila `aprobada` con separacion `SALTADO`, que
  el aplicador bloqueaba despues. El cliente en disco conserva la puerta. Test: `test_el_servidor_no_tiene_puerta_de_autoaprobacion`
  (`tests/unitarios/test_aprobacion.py`).
- El rol del aprobador se reconoce por nombre exacto, no por prefijo. `aprobar._ROL_APROBADOR` exige
  `AWSReservedSSO_AgenteIAM-Aprobador_` seguido solo de letras y cifras; un permission set llamado `AgenteIAM-Aprobador_Extra` ya no da
  persona. No se fija longitud ni hexadecimal: la guia de AWS lo da asi en sus ejemplos, no como contrato (en los ficheros locales los 16
  nombres reales observados llevan 16 hexadecimales). Test: `test_un_permission_set_que_solo_empieza_igual_no_da_persona`.
- Las Lambdas rechazan el modo `principal_existente`. `aplicador.procesar_aprobada` (el camino de la Lambda; el CLI de desarrollo llama a
  `aplicar` directamente y no cambia) deja `bloqueada_al_aplicar` una fila cuya `identidad_verificada.modo` no es `rol_por_persona`, sin
  llamar a `aplicar` ni a IAM. `aprobar.decidir` con `exigir_persona=True` responde 409 al aprobar una fila de otro modo y si deja
  rechazarla. Tests: `test_la_lambda_no_aplica_una_fila_del_modo_principal_existente` (`tests/unitarios/test_aplicador.py`),
  `test_el_servidor_no_aprueba_una_fila_del_modo_principal_existente` y `test_el_servidor_si_deja_rechazar_una_fila_del_modo_principal_existente`.
  Atiende la primera de las dos unidades que el critico dejo aplazadas, pero solo en el codigo: la revision de esa unidad sigue sin hacerse.
- El correo solo sale tras una decision humana (pista 3). `avisos.ESTADOS_QUE_AVISAN` pasa de siete estados a cuatro: `aprobada`,
  `rechazada_por_aprobador`, `aplicada` y `bloqueada_al_aplicar`. Ya no avisan los que decide el intake solo
  (`rechazada_en_chequeos_previos`, `requiere_revision_humana`, `redundante_no_requiere_cambio`): su resultado lo da la respuesta del
  servidor, como `propuesta`. El filtro de `DisparadorAvisos` en `infra/cfn/runtime.yaml` lleva los mismos cuatro. Decision de Claude
  (Mateo delego las decisiones de diseno ese dia). Por que: `correo_aviso` lo escribe quien pide; atarlo a la identidad no se puede sin
  tocar infraestructura, porque el token de acceso no trae correo y el nombre de usuario de Identity Center no tiene por que ser un correo
  (`solicitante.demo` no lo es); y con el alta de una solicitud mandando correo, una persona con sesion escribia a un tercero sin que nadie
  mas interviniera. Ahora cada correo exige la accion de un aprobador, que ve la direccion (`aprobar_cliente` la muestra). Se pierde el
  correo de los tres estados del intake, medido en O.5 y R.11. Tests: `test_un_estado_que_decide_el_intake_no_manda_correo`,
  `test_solo_avisan_los_estados_que_siguen_a_una_decision_humana` (`tests/unitarios/test_avisos.py`) y
  `test_el_disparador_de_avisos_filtra_los_cuatro_estados_sin_reintentos` (`tests/seguridad/test_pila_runtime.py`).

Verificacion (18-11-2026, local, sin tocar la cuenta): `./.venv/bin/python -m pytest tests/ -q` da 1496 pasados y 1 saltado (antes 1484:
12 tests nuevos); `ruff check .`, `mypy` y cfn-lint sobre `infra/cfn/runtime.yaml` pasan. Detalle en `docs/MEDICIONES.md` W.6.

Lo que no se arreglo:
- Pista 4 (tope por persona): necesita un contador compartido y el rol del runtime solo puede `UpdateItem` sobre `id`, `documento` y
  `estado`; hay un diseno propuesto, sin escribir, que anade un atributo a la pila base. Pendiente de que Mateo lo pida.
- Pista 2 (escrituras que configuran entrega): cambia `ACCIONES_PROHIBIDAS` y regenera el techo, que hay que desplegar. Pendiente.
- Pista 1 (operador): es rediseno de los limites por rol. Pendiente de la postura de Mateo.

**Publicacion (rama preparada el 18-11-2026; subida a un repositorio nuevo, todavia privado, el 19-11-2026 UTC).** Mateo decidio publicar con
historia nueva. Queda preparada la rama `publico`:
un solo commit sin padres, hecho con `git commit-tree` sobre el mismo arbol que la rama de trabajo, con autor y committer en la direccion
`noreply` de GitHub. Para eso se anadio la licencia MIT (`LICENSE`, decision de Claude por delegacion de Mateo; se puede cambiar antes de
subir), una nota en el README y en este plan de que los hashes de commit citados son del repositorio privado de origen, y se enmascaro el id
real del runtime de AgentCore en cuatro documentos. Las busquedas de W.1 se repitieron sobre el arbol final y salieron limpias
(`docs/MEDICIONES.md` W.7). Se dejan como estan, a la vista de quien lea: `CLAUDE.md`, `docs/superpowers/` y las menciones al trabajo con el
asistente; el usuario IAM `Mateo` nombrado en los documentos; y el video, donde se lee el `sub` de un usuario de demostracion (ya publico
en LinkedIn).

Subida (19-11-2026 UTC, con el si de Mateo; `docs/MEDICIONES.md` W.8). Mateo renombro el repositorio de origen a `Agente-IAM-privado`. El
remoto `origin` de la copia local se apunto a ese nombre antes de crear nada, porque con el nombre viejo un `git push` de la rama de trabajo
habria subido la historia antigua al repositorio nuevo. Se creo `MetMatDav/Agente-IAM` en privado y se subio solo la rama `publico`, como
`main`, por un remoto aparte (`publico`) configurado para empujar solo esa rama. Un clon en espejo del repositorio nuevo da un commit, sin
la cuenta real ni el correo personal. Dos cosas no salieron: las tres protecciones (secret scanning, proteccion de `main` y aprobacion de PR
de forks) no se pueden activar mientras el repositorio es privado, y la primera ejecucion del CI alli fallo en `seguridad` porque pip-audit
encontro una vulnerabilidad conocida en una dependencia (`opentelemetry-api` 1.45.1, arreglada en 1.45.2); gitleaks, los tests, bandit y
cfn-lint pasaron.

Pendiente (quien):
- Mateo: en GitHub, activar el correo `noreply` y el bloqueo de pushes que exponen el correo; y, cuando lo decida, pasar el repositorio
  nuevo a publico. El de origen (`Agente-IAM-privado`) no se borra hasta comprobar el nuevo.
- Claude, justo despues del paso a publico: activar secret scanning con push protection, la proteccion de `main` con los checks `unitarios`
  y `seguridad`, y la aprobacion de PR de forks; hoy GitHub las rechaza por ser privado.
- Claude, cuando Mateo lo pida: subir `opentelemetry-api` y los paquetes que lo fijan (`opentelemetry-sdk`, `opentelemetry-semantic-conventions`
  y las dos instrumentaciones) en `constraints.txt`, reinstalar, correr la suite y `pip-audit`. Afecta al zip del runtime.
- Claude: llevar cada cambio de la rama de trabajo a `publico` con un commit normal encima (mismo arbol, autor `noreply`, sin forzar la
  subida), hasta que se trabaje directamente sobre el repositorio nuevo.
- Mateo: decidir lo que queda de "Conviene": el `sub` visible en el video de 0:30 a 0:39, `docs/superpowers/` y cuanto del trabajo con el
  asistente se ve, el usuario IAM `Mateo` nombrado en los documentos, la nota del envio a AWS Support y la licencia.
- Mateo: su postura sobre el operador (pista 1): si la autoridad del operador sobre los roles y el codigo es una limitacion aceptada o se
  arregla.
- Mateo, solo lectura y con su sesion: las cuatro comprobaciones de la cuenta que resuelven las pistas (simulacion de IAM sobre
  `AgenteIAM-Despliegue` y lectura de `AgenteIAM-LimiteSistema`; `sesv2 GetAccount`; cuotas de Bedrock y AgentCore y acciones del
  presupuesto; configuracion del autorizador del runtime desplegado). Claude puede hacerlas con el si de Mateo.
- Mateo: la prueba de la pista 2 en una cuenta de pruebas (si la entrega sigue cuando el rol caduca).
- Claude, cuando Mateo lo pida: lo que falta de los arreglos de codigo, cada uno con su test: la clase de acciones prohibidas para las que
  configuran entrega (pista 2) y el tope de solicitudes por `sub` (pista 4, con el change set de la pila base).
- Operador, con el si de Mateo: desplegar los arreglos (dos zips y dos change sets, `docs/DESPLIEGUE.md`, Fase 33) y medirlos en la cuenta.
- Claude: una segunda pasada que empiece por las dos unidades aplazadas (el modo `principal_existente` en las Lambdas desplegadas; la
  politica de la clave KMS de los logs de Control Tower).
- Claude: el commit, hecho el 18-11-2026 (`06b3785`), sin subir a GitHub.

## Fuera de estos 7 (backlog corto)

- `no_evaluable` (`simulacion.py`) no se usa en el mensaje del orquestador.
- Endurecer mypy por pasos (`disallow_untyped_defs`).
- Propuestas de la revision de optimizacion no aprobadas: O8 a O11, O18 a O20 y O22.
