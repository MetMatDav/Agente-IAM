# Landing zone con AWS Control Tower

Fase 10, paso 1. **Lanzada y verificada el 22-10-2026**: landing zone 4.0 `ACTIVE`
e `IN_SYNC`, cuenta `agente-iam` creada en la unidad `Workloads`. Este documento
era la lista para montarla; ahora recoge lo decidido, lo hecho y lo que sigue
pendiente. Lo medido (estado de partida, asistente, verificacion, red, Identity
Center): `docs/MEDICIONES.md`, seccion G. La cuenta de gestion solo debe tener
Organizations, Control Tower e Identity Center; nada de cargas de trabajo.

---

## Decisiones que no se pueden deshacer

- **Region de origen**: `us-east-1`, donde estan el modelo de Bedrock, AgentCore e
  Identity Center. No se cambia despues.
- **Cuentas compartidas** (version 4.0: "CloudTrail Administrator" y "Aggregator
  account"; antes "Log Archive" y "Audit"): `log-archive` y `audit`. Los nombres
  se pueden cambiar con la Organization en modo *all features* y el acceso de
  confianza de AWS Account Management (`account:PutAccountName`, doc); el correo
  no. Sin verificar: si Control Tower marca deriva al renombrar una cuenta que
  gestiona. El asistente crea la Organization y la cuenta de archivo antes de
  terminar, y esas cuentas quedan aunque se cancele.
- **Correos**: uno nuevo por cuenta, nunca usado en AWS; con Gmail sirven alias
  `+log-archive`, `+audit`, `+agente-iam`. Cerrar una cuenta no la borra al
  instante: conviene acertar a la primera.

## Antes de lanzar (hecho)

- **Presupuesto**: `monthly-infra-iam-agent`, 10 USD al mes, avisos al 50, 80 y 99 %
  del gasto real, sin aviso de gasto previsto (decision de Mateo, 20-10-2026).
  Excluye las compras puntuales (dominio, Skill Builder) con `FilterExpression`
  `Not`; pasara a plantilla (`AWS::Budgets::Budget` lo admite).
- **Clave KMS** administrada por el cliente (22-10-2026), alias `control-tower-logs`,
  en la cuenta de gestion y `us-east-1`; politica en
  `infra/kms-control-tower-logs-politica.json` (las sentencias por defecto mas las de
  Config y CloudTrail de la guia de Control Tower), aplicada con `PutKeyPolicy` e
  identica al leerla; `ValidatePolicy` sin avisos; rotacion cada 90 dias (la primera,
  el 20-01-2027). **El orden importa**: la politica va antes de lanzar, porque la
  comprobacion previa de Control Tower exige los permisos. La clave anterior
  (`rare-trails-kms`) esta desactivada, con borrado previsto el 29-10-2026 (sin
  confirmar; habria que leerlo).
- **Correos**, acceso de confianza de Config y CloudTrail (no debia estar activado
  antes de lanzar), MFA de la cuenta raiz y lanzar con el usuario IAM
  administrador: todo cumplido. La raiz sigue con MFA y sin claves de acceso
  (MEDICIONES G.7).

## Valores del asistente

| Opcion | Valor | Por que |
|---|---|---|
| Region de origen | `us-east-1` | Ver arriba |
| Regiones adicionales | Ninguna | Config cobra por region |
| Denegacion de regiones | Activada (despues se apago la de la landing zone y se sustituyo por la pila `gobierno-regiones`; MEDICIONES C.1 a C.3) | Impide recursos fuera de la region |
| Unidades | `Security` y `Sandbox` (esta se renombro `Workloads` en el paso 3a) | `log-archive` y `audit`; la cuenta del agente |
| Cuentas compartidas | `log-archive` y `audit` | Ver arriba |
| Identity Center | Lo configura Control Tower | Base de la identidad del proyecto |
| Trail de organizacion | Activado | Auditoria |
| AWS Config | Activado | Controles de deteccion; coste abajo |
| Roles de seguridad | Activados | Acceso de auditoria entre cuentas, sin coste |
| AWS Backup | Desactivado | Nada que respaldar |
| Retencion de logs | 1 ano | Basta para una demo |
| Clave KMS | `control-tower-logs` | Cifrado de los logs |

## Despues de lanzar

| Paso | Que | Fecha |
|---|---|---|
| 1 | Red de Account Factory: se desmarco `us-east-1` (solo consola; no se lee por API). Efecto medido: el StackSet `AWSControlTowerBP-VPC-ACCOUNT-FACTORY-V1` no existe y no se creo ninguna VPC | 22-10-2026 |
| 2 | Acceso raiz centralizado (credenciales y sesiones raiz) por API; las dos cuentas miembro no tenian nada que borrar | 22-10-2026 |
| 3a | Renombrar `Sandbox` a `Workloads` (mismo ID) | 22-10-2026 |
| 3b | Registrar `Workloads`: `EnableBaseline` con `AWSControlTowerBaseline` 5.0 y el parametro de Identity Center; `SUCCEEDED`, `IN_SYNC`, 10 controles obligatorios | 22-10-2026 |
| 3c | Crear `agente-iam` con Account Factory desde la consola (`ProvisionProduct` por API no salio) | 22-10-2026 |
| 4 | Identity Center: usuario de administracion existente renombrado a "Mateo Cortes"; MFA en "cada vez que inician sesion" | 22-10-2026 |
| 5 | Perfiles SSO `org-gestion`, `org-agente-iam`, `org-log-archive`, `org-audit`; `GetCallerIdentity` correcto en los cuatro | 22-10-2026 |
| 6 | Trail: llegan logs de las cuatro cuentas al bucket de `log-archive` | 22-10-2026 |
| 7 | Clave de acceso del usuario IAM de Mateo: desactivada el 22-10-2026 y **borrada** (`ListAccessKeys` vacio, leido el 24-10-2026) | 22-10-2026 y 24-10-2026 |
| 8 | Documentacion actualizada (CONTEXTO §5 y PLAN, Fase 10b) | 22-10-2026 |

**Hallazgos que cambian el diseno** (detalle en MEDICIONES G):

- La landing zone 4.0 **no registra ninguna unidad**: ni `Sandbox` ni `Security`
  tenian linea base, y Account Factory la exige en la unidad destino (G.4).
- Registrar `Workloads` heredo la denegacion de regiones, que deniega Bedrock en
  `agente-iam`; se resolvio en la Fase 15 (MEDICIONES C).
- Con el acceso raiz centralizado, las cuentas nuevas nacen sin credenciales
  raiz y no pueden recuperarlas por correo, lo que cierra el riesgo del Gmail.
  Sin administrador delegado: la gestion queda en la cuenta de gestion.
- Account Factory reutilizo el usuario de Identity Center creado por Control
  Tower; la primera contrasena de Identity Center fallo y se restablecio desde el
  portal; un `aws sso login` sin contrasena valida no guarda token (G.5).
- Cambiar el MFA dejo "Deshabilitado" las sesiones en segundo plano y las de Kiro;
  causa **sin verificar**. Control Tower asigna `AWSOrganizationsFullAccess` en
  `agente-iam` a `AWSControlTowerAdmins`.
- El trail de organizacion cifra con la clave `control-tower-logs` (el cifrado por
  defecto del bucket es `AES256`; manda la clave del trail), con versionado, sin
  acceso publico y ciclo de vida de 365 dias.

## Pendiente

- **Mateo**: `aws cloudtrail validate-logs` (CLI v2) para validar la integridad con
  los digest, y revisar el bucket de logs de acceso. Ninguno consta como hecho (MEDICIONES G.3).
- **Decision de Mateo**: delegar o no la gestion del acceso raiz centralizado en una
  cuenta de seguridad (la guia de AWS lo recomienda); conservar o borrar AWS Config
  de la cuenta de gestion (la regla `restricted-ssh` cuesta centimos; no se ha
  vuelto a leer); revisar `AWSOrganizationsFullAccess` al definir los permission
  sets; el acceso a la consola con contrasena del usuario IAM de Mateo (G.4).
- **Sin verificar**: Config dentro de `audit`; deriva al renombrar cuentas; por que
  quedaron deshabilitadas las sesiones en segundo plano y de Kiro.
- **Claude, para la infraestructura como codigo**: averiguar la via por API que
  sustituye al producto de Account Factory en la landing zone 4.0.

## Coste esperado

Precios de `us-east-1` de la API de precios (20-10-2026): 0,003 USD por cambio
registrado en Config y 0,001 USD por evaluacion de regla. Estimaciones, no facturas.

| Concepto | Estimacion |
|---|---|
| Control Tower, Organizations e Identity Center | Sin coste propio |
| AWS Config en tres cuentas, una region, controles obligatorios, actividad de demo | 1,5 a 3,5 USD al mes |
| Registro inicial de recursos | 0,30 a 0,75 USD, una vez |
| Clave KMS (precios del 22-10-2026) | 1 USD al mes, mas 1 USD por cada una de las dos primeras rotaciones; con rotacion cada 90 dias, 3 USD al mes desde la segunda |
| Trail de organizacion, eventos de gestion | Sin coste: es la primera copia |
| Logs en S3 | Centimos |

Lo que puede disparar el coste: VPC con NAT de Account Factory, regiones gobernadas de
mas, trails duplicados y controles de deteccion opcionales activados en bloque.
