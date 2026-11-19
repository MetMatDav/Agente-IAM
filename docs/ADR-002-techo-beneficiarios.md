# ADR-002: el techo de los beneficiarios (`AgenteIAM-Techo` v2)

- **Estado:** aceptado por Mateo el 23-10-2026 (D1, D2, D3 y D4 como opcion B,
  EC2 solo inventario) y **desplegado el 23-10-2026** en la cuenta
  `agente-iam` (conjunto de cambios `techo-v2-adr-002` sobre la pila
  `agente-iam-arranque`). Despues, el 24-10-2026, el techo del repositorio
  gano dos Deny (S3 y S5, Fase 17) y se **desplego como v3** en la cuenta
  (`docs/MEDICIONES.md`, §E.8).
- **Fase:** 15, bloque 3. El estrechamiento es un paso propio antes del
  runtime: opcion (a) aprobada por Mateo el 23-10-2026 al disenar la pila de
  arranque.
- **Medido contra:** la cuenta `agente-iam` (lecturas y simulador de IAM), el
  codigo del repositorio en el commit `c2a9049` y la referencia programatica
  de autorizacion de servicios de AWS, el 23-10-2026.
- **Relacion:** se apoya en ADR-001 (`docs/ADR-001-agentcore-identidad.md`) y
  en el diseno del bloque 3 (`PLAN-CORRECCIONES.md`, Fase 15).

## Contexto

El 23-10-2026 se termino la Prueba B (la persona no llega al rol, ADR-001), se
aprobo el diseno del bloque 3 y se desplegaron las pilas de identidades y de
arranque. El analisis de riesgo de ese diseno concluyo que lo que mas reduce
el impacto de un aplicador comprometido es estrechar el techo, y de ahi este
ADR. Lo hecho ese dia: `PLAN-CORRECCIONES.md`, Fase 15, y `docs/MEDICIONES.md`,
§D y §F.

El techo (`infra/boundary-agente-iam-techo.json`, copiado en la pila de
arranque como `AgenteIAM-Techo`) es el permissions boundary obligatorio de todo
beneficiario: lo maximo que el aplicador puede conceder. El v1, que hubo en la
cuenta hasta el 23-10-2026, tenia tres sentencias:

| Sentencia | Efecto |
|---|---|
| `TechoIgualAlAlcanceDelSistema` | Allow de `s3:*`, `dynamodb:*`, `sqs:*`, `sns:*`, `logs:*`, `cloudwatch:*`, `ec2:*` y `lambda:*` |
| `AutoservicioMinimoDelUsuario` | Cambiar su contrasena y leer su propio usuario |
| `GemelaDeAccionesProhibidasDelCodigo` | Deny de `lambda:UpdateFunctionCode`, `AddPermission`, `UpdateFunctionConfiguration` y `ec2:ModifyInstanceAttribute` |

**El problema** (hallazgo de la revision del 20-10-2026,
`docs/MEDICIONES.md`, §E.1). El techo permitia enteros los mismos 8 servicios
que concede el codigo (`SERVICIOS_PERMITIDOS`). Solo frenaba lo que el codigo
ya frena, y no aportaba nada en el caso en que importa: **cuando alguien se
salta el codigo**, por las puertas traseras del analisis de riesgo (quien
asuma el rol del aplicador, o quien despliegue un aplicador alterado) o por un
error en el propio codigo.

### Dos huecos (medidos el 23-10-2026, `docs/MEDICIONES.md`, §E.2)

**Hueco 1: gestion de permisos.** La referencia de autorizacion de AWS marca
54 acciones de 7 de los 8 servicios como "Permissions management" (s3 27,
cloudwatch 8, lambda 8, dynamodb 3, sqs 3, sns 3, logs 2). Ejemplos:
`s3:PutBucketPolicy`, `s3:PutBucketAcl`, `lambda:AddPermission`,
`sqs:AddPermission`, `sns:SetTopicAttributes`, `dynamodb:PutResourcePolicy`.
Con ellas un beneficiario puede hacer publico un bucket o abrir una cola, un
tema o una funcion a otra cuenta. **El codigo no las concede** (regla de la
Fase 9: ningun nivel concede `IsPermissionManagement`); el techo si las
permitia.

En EC2 la gestion de permisos no cubre la exposicion: `ec2:ModifyImageAttribute`
(publicar una AMI o compartirla) es de nivel Write, y
`ec2:AuthorizeSecurityGroupIngress` tambien; `ec2:ModifySnapshotAttribute` si
es de gestion de permisos. Por eso la exposicion de EC2 la cierra la opcion B
de D4, no D1.

**Hueco 2: los recursos del propio sistema.** Leido en `coherencia.py` y
`orquestador.py` (commit `c2a9049`): ningun chequeo impedia pedir permisos
sobre los recursos del agente. Una solicitud normal de escritura en `s3` sobre
el bucket del paquete (`agente-iam-paquete-<cuenta>`) daria al beneficiario la
capacidad de sustituir el codigo del agente antes del siguiente despliegue. Lo
mismo con la tabla `agente-iam-solicitudes` (falsear aprobaciones), la cola de
fallos, la funcion del aplicador y los logs del runtime (borrar rastro). Solo
lo frenaria que el aprobador lo notara al leer la propuesta. Este hueco es
independiente de las puertas traseras: se abre por el flujo normal, con
aprobacion.

## Decision

Mateo eligio D1, D2, D3 y D4 como opcion B el 23-10-2026, y pidio escribirlo
todo en **un solo techo v2**, con tests y mutaciones. Cada decision es
independiente y reversible (una version nueva de la politica o del codigo).

| | Elegido | Cierra | Coste y riesgo |
|---|---|---|---|
| **D1** | Deny de las acciones de gestion de permisos: **53** | Hueco 1, en IAM. Refleja una regla que el codigo ya cumple, asi que no cambia lo que el sistema concede | Unos 2.500 caracteres (limite de IAM: 6.144). La lista se genera desde la referencia, no a mano; un test vigila que siga reflejando la regla del codigo. Si AWS anade acciones nuevas, no estaran hasta regenerar; el codigo las sigue frenando |
| **D2** | Deny de todo sobre los recursos del sistema | Hueco 2, en IAM: ningun beneficiario, por ninguna via, toca los recursos del sistema dentro de los 8 servicios. Los patrones son los mismos con los que el rol de despliegue puede crearlos (`infra/cfn/arranque.yaml`). Cognito y AgentCore no estan entre los 8 servicios | Pocas lineas. Exige que los recursos del sistema sigan esos nombres. Un test cubre cada patron Allow del rol de despliegue, para que no se separen. Sin riesgo conocido |
| **D3** | El mismo bloqueo en el codigo | Hueco 2 en el flujo normal: la solicitud se rechaza en los chequeos previos, antes del modelo, y queda registrada con su motivo. Sin esto, D2 haria que la aplicacion fallara al final con un AccessDenied poco claro | Un chequeo en `coherencia.py`, su test y su mutacion. Cada capa cubre el fallo de la otra |
| **D4** | **Opcion B: EC2 solo inventario** (no quitar EC2) | La mayor superficie de los 8 (826 acciones): lanzar instancias, abrir grupos de seguridad, publicar AMI. Con B, fuera de `Describe*` el techo no deja nada de EC2 | La demo conserva un caso de lectura de EC2. Alternativa descartada: quitar `ec2` por completo (la demo perderia el caso de inventario) |

Tres puntos de D4:

- *Leer no es inofensivo.* 10 `ec2:Describe*` devuelven user data o un secreto
  en la respuesta y el nivel `List` del catalogo no lo dice. Por eso B no es
  solo `Describe*`: esas 10 se niegan.
- *Efecto en los ejemplos.* `ejemplos/solicitud-ec2.json` y
  `ejemplos/solicitud-ec2-ana.json` son de lectura y siguen entrando; lo que se
  rechaza antes del modelo es EC2 con cualquier otro `tipo_acceso`. Sus
  chequeos previos pasan (test).
- *Riesgo de comportamiento, no medido.* Si el modelo propone `ec2:Describe*`
  entero, ahora se bloquea (cubre una prohibida) y debe repararlo listando
  acciones. No se ha corrido el modelo contra `ejemplos/solicitud-ec2*.json`
  tras el cambio (cuesta Bedrock; pendiente, con el si de Mateo).

## El techo v2

`infra/boundary-agente-iam-techo.json` y su copia en el recurso `Techo` de
`infra/cfn/arranque.yaml`. Se genera con `scripts/generar_techo.py` desde
`config.py` y la referencia de autorizacion, que descarga en el momento. El v2
del 23-10-2026, el de la cuenta, tiene 3422 caracteres y seis sentencias:

| Sentencia | Efecto | Origen |
|---|---|---|
| `AlcanceDelSistema` | Allow de los 8 servicios; en EC2, solo `ec2:Describe*` | D4 |
| `AutoservicioMinimoDelUsuario` | Igual que en el v1 | |
| `GemelaDeAccionesProhibidasDelCodigo` | Deny de 14 acciones: las 4 del v1 mas las 10 Describe de EC2 que devuelven secretos | D4 |
| `SinGestionDePermisos` | Deny de 53 acciones de gestion de permisos | D1 |
| `NadaSobreLosRecursosDelSistema` | Deny de `Action: "*"` sobre 9 patrones `agente-iam-*` / `agente_iam*` | D2 |
| `NiLosDisparadoresDelSistema` | Deny de `Create/Delete/Get/UpdateEventSourceMapping` con `ArnLike` sobre `lambda:FunctionArn` = `arn:aws:lambda:*:*:function:agente-iam-*` | D2 |

La ultima existe porque los disparadores (event source mappings) no llevan
nombre: el rol de despliegue los crea sobre `event-source-mapping:*`, y un
patron de nombre no los alcanza. Se reconocen por la funcion a la que apuntan.

**En el codigo (D3 y D4):**

- `config.py`: `SOLO_LECTURA = {"ec2": "Describe*"}` y
  `PREFIJOS_DEL_SISTEMA = ("agente-iam", "agente_iam", "agenteiam")`; 10
  acciones `ec2:Describe*` en `ACCIONES_PROHIBIDAS`.
- `orquestador.chequeos_previos` (antes del modelo): EC2 con `tipo_acceso`
  distinto de `lectura` se rechaza; un recurso del formulario con un
  componente que empiece por un prefijo del sistema se rechaza.
- `coherencia.py`, dos comprobaciones posteriores (ahora seis): (5) en un
  servicio de `SOLO_LECTURA`, toda accion Allow encaja en su patron (el nivel
  del catalogo no basta: `lectura` admite 52 acciones Read de EC2, como
  `GetConsoleOutput` y `GetPasswordData`). (6) Ningun componente de un ARN
  Allow, partido por `:` y `/`, empieza por un prefijo del sistema; la
  coherencia de recurso no lo cubria.
- `agente.py`: una frase en la regla 1b del prompt (en EC2, acciones `ec2:Describe...` concretas, nunca `ec2:Describe*`).

## Lo medido el 23-10-2026

Detalle y tablas en `docs/MEDICIONES.md`, §E.2 a §E.4.

1. **Son 53 acciones negadas, no 77.** EC2 tiene 826 acciones (194 Describe);
   la gestion de permisos de los otros 7 servicios son 54, y `lambda:AddPermission`
   ya esta en la gemela. Las 23 de EC2 sobran: el Allow solo deja `Describe*`.
   La cache local del catalogo era de agosto (807 acciones de EC2), por eso el
   generador descarga siempre.
2. **Las Describe de EC2 con secretos son 10** (campo `UserData` o forma
   sensible en el modelo de servicio de botocore 1.43.82): user data (4), secreto
   de cliente OIDC, claves de VPN, URL prefirmadas de S3 (3) y politica de
   subida firmada. `DescribeInstanceSqlHaStates` trae el ARN del secreto, no el
   secreto: no se niega.
3. **Dos Describe del catalogo no tienen operacion en botocore 1.43.82**
   (`DescribeLocalGatewayRouteTablePermissions` y
   `DescribeVerifiedAccessInstanceWebAclAssociations`): el test derivado de
   botocore no puede revisarlas. Por el nombre no parecen devolver secretos;
   **es un supuesto, no medido**.
4. **Verificacion antes de desplegar** (perfil `org-agente-iam`, solo lectura):
   `ValidatePolicy` sin hallazgos; simulador de IAM con permiso total y el
   techo v2 como boundary, 29 de 30 casos como se esperaba. El caso restante
   (`logs:DeleteLogStream` con un grupo cuyo nombre lleva `/`) es una limitacion
   del simulador, que no reconoce el ARN de flujo ni sin boundary. Barrido de
   16 mutaciones del codigo y del JSON, las 16 en rojo.
5. **Tests nuevos:** `tests/seguridad/test_techo_v2.py` y
   `tests/funcionales/test_techo_en_vivo.py` (corre `generar_techo.py
   --comprobar` contra la referencia del dia; sale a la red, sin credenciales).

## Despliegue y estado actual

**23-10-2026**, con el si de Mateo, perfil `org-agente-iam`
(`AWSAdministratorAccess`), `us-east-1`. El conjunto de cambios
`techo-v2-adr-002` tuvo un unico cambio, `Modify` de `Techo`
(`AWS::IAM::ManagedPolicy`), sin reemplazo; pila `UPDATE_COMPLETE`, sin
eventos fallidos. Medido despues, en lectura y con el simulador, contra la
cuenta:

- `AgenteIAM-Techo` tiene `v2` por defecto y `v1` no por defecto. El `v2` es
  identico a `infra/boundary-agente-iam-techo.json` del commit `60ee550`. El
  ARN no cambia, asi que la condicion `iam:PermissionsBoundary` del aplicador
  sigue valiendo. 0 adjuntos y 0 principales lo usan como boundary: el cambio
  no afecto a nadie.
- `ValidatePolicy` sobre el documento en vigor: sin hallazgos. Simulador:
  **30 de 30** casos como se esperaba (el de `logs:DeleteLogStream` probado
  con la forma `log-group:...:*`).
- **Limites:** es el simulador, no una llamada real, y se simulo el documento
  en vigor, no un principal real (ninguno lleva todavia el techo en
  `agente-iam`). `aprobar.py` lee el techo de la cuenta antes que el JSON
  local, asi que `CheckNoNewAccess` compara ahora contra el v2: es como esta
  escrito el codigo, **no esta medido con una solicitud real**.
- Volver a poner el `v1` por defecto seria otra actualizacion de la pila.

**24-10-2026, techo v3 desplegado** (`docs/MEDICIONES.md`, §E.8). El techo del repositorio (8 sentencias, 5575
caracteres) se desplego como v3 con el conjunto de cambios `techo-v3-y-limite`; lleva dos Deny que el v2 no tenia:
`SinEscriturasDeAlcanceDeCuenta` (S3: escrituras sin tipo de recurso, que con `Resource "*"` no deben pasar) y
`SoloRecursosDeLaPropiaCuenta` (S5: `aws:ResourceAccount` distinta de la cuenta del principal). La politica del
aplicador lleva ahora `access-analyzer:CheckNoNewAccess`. Medido el 24-10-2026: `ValidatePolicy` sin hallazgos y
simulador 8 de 8 contra la v3 real (simulador, no llamada real); con llamadas reales (E.7), las llamadas propias
llevan la clave y pasan, y S5 niega los recursos de otras cuentas, tambien publicos de AWS.

## Lo que este techo no cierra

- **Leer recursos ajenos al sistema** dentro de los servicios permitidos (por
  ejemplo, cualquier bucket de la cuenta que no sea `agente-iam-*`). El codigo
  limita cada concesion al recurso pedido, pero el techo no. Cerrarlo exige que
  los recursos de los beneficiarios lleven una etiqueta que el techo pueda
  exigir: otro cambio, no propuesto aqui.
- **Recursos de otras cuentas, tambien publicos de AWS**: la S5 los cierra sin
  excepciones (buckets publicos, capas de Lambda de AWS; `docs/MEDICIONES.md` E.7).
  Aceptado por Mateo el 24-10-2026.
- **El techo antiguo de la cuenta de gestion** (version v2 de IAM, usado como
  boundary por `ana.gomez` y `jose.torres`, lectura del 24-10-2026,
  `docs/MEDICIONES.md`, §G.7). Se retira en el bloque 4; este ADR solo trata
  el de `agente-iam`.
- **`Describe*` deja pasar las Describe futuras.** Lo vigilan el test derivado
  de botocore (fijado en `constraints.txt`) y el funcional.
- **Las 2 Describe sin operacion en botocore** (punto 3 de lo medido): supuesto.

## Pendiente

Con responsable y fecha, en `CONTEXTO.md`, §11: correr el modelo contra
`ejemplos/solicitud-ec2*.json` (Bedrock, con el si de Mateo). Commits del techo
v2: `60ee550` y `131a19f`, subidos a `origin/docs/fase-9-y-gitignore` el
24-10-2026.
