"""Configuracion central del agente IAM."""

import os
import re

# --- Modelo y region -------------------------------------------------------
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
# Perfil de inferencia geografico "us.": enruta entre las regiones de EE. UU.
# La SCP de la cuenta agente-iam solo deja invocar Bedrock desde us-east-1 a
# traves de perfiles `us.` de Claude; el perfil `global.` queda denegado
# (23-10-2026). AWS no aprobo Haiku 5.5 (us.anthropic.claude-haiku-5-5) para
# esta cuenta (27-10-2026): queda como posibilidad futura y se activaria solo
# con MODEL_ID.
# Haiku 4.5 desde el 22-10-2026: en 70 corridas con los casos de ejemplos/
# cumplio las mismas reglas criticas que Sonnet 4.6, con politicas mas
# ajustadas y unas 3,5 veces menos coste (PLAN, Fase 10b;
# scripts/comparar_modelos.py). La familia 5.x no esta habilitada en esta
# cuenta. Se cambia sin tocar codigo, p. ej.:
#   export MODEL_ID=us.anthropic.claude-sonnet-4-6
MODEL_ID = os.getenv("MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0")

# Regiones en las que este sistema concede permisos. La SCP de la cuenta
# agente-iam solo deja operar en us-east-1 (salvo la inferencia del perfil
# `us.`), asi que pedir otra region acabaria en un AccessDenied despues del
# modelo y de una aprobacion. Es la lista cerrada que el formulario web copia
# desde aqui; una solicitud de otra region se rechaza antes del modelo, con el
# motivo en el registro (`coherencia.chequeos_formulario`).
REGIONES_PERMITIDAS = ["us-east-1"]

# --- Barandas deterministas -------------------------------------------------
# Estas listas NO dependen de que el modelo se comporte bien. Se evaluan
# en codigo, despues de que el agente propone. Si algo de aqui aparece en
# la propuesta, la propuesta queda bloqueada sin importar lo que diga el LLM.

# Acciones concretas que este sistema nunca debe conceder: son las que
# permiten escalar privilegios o reescribir las reglas del juego.
# Se bloquea toda accion propuesta que CUBRA alguna de estas: pedir "iam:*"
# choca aqui porque cubre "iam:CreateUser".
ACCIONES_PROHIBIDAS = [
    # Crear o adjuntar credenciales y politicas: escalada directa.
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "iam:PassRole",
    # Fase 6: unirse a un grupo privilegiado ya existente.
    "iam:AddUserToGroup",
    # Fase 6: tomar control de la consola de OTRO usuario (crear o
    # cambiarle la contrasena de acceso web).
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    # Fase 6: quitar o reemplazar el permission boundary es quitar el
    # techo de permisos; concederlo anula la contencion.
    "iam:PutUserPermissionsBoundary",
    "iam:PutRolePermissionsBoundary",
    "iam:DeleteUserPermissionsBoundary",
    "iam:DeleteRolePermissionsBoundary",
    # Fase 6: activar una version vieja (mas amplia) de una politica
    # sin crear nada nuevo.
    "iam:SetDefaultPolicyVersion",
    # Fase 6: escalada via Lambda sin necesitar PassRole — cambiar el
    # codigo de una funcion que YA tiene un rol privilegiado, o abrirla
    # a invocaciones ajenas. Lambda esta en SERVICIOS_PERMITIDOS, asi
    # que estas dos necesitan bloqueo explicito.
    "lambda:UpdateFunctionCode",
    "lambda:AddPermission",
    # Revision 2026-10: las otras dos formas de ejecutar codigo propio bajo
    # un rol que YA esta puesto, sin necesitar PassRole. Cambiar capas,
    # handler o AWS_LAMBDA_EXEC_WRAPPER de una funcion es cambiar su codigo;
    # reescribir el user data de una instancia parada y arrancarla ejecuta
    # bajo su perfil de instancia. Las dos son IsWrite, asi que el nivel de
    # acceso solo las frenaba bajo 'lectura'.
    "lambda:UpdateFunctionConfiguration",
    "ec2:ModifyInstanceAttribute",
    # ADR-002 (23-10-2026): las Describe de EC2 cuya respuesta trae user
    # data o un secreto. Son de nivel List, asi que `lectura` las dejaba
    # pasar. Salen del modelo de servicio de botocore (campo `UserData` o
    # forma marcada sensible); tests/seguridad/test_techo_v2.py lo recalcula
    # y se pone en rojo si aparece otra.
    # User data, que suele llevar contrasenas o tokens:
    "ec2:DescribeInstanceAttribute",
    "ec2:DescribeLaunchTemplateVersions",
    "ec2:DescribeSpotFleetRequests",
    "ec2:DescribeSpotInstanceRequests",
    # Secreto de cliente OIDC:
    "ec2:DescribeVerifiedAccessTrustProviders",
    # Claves precompartidas de los tuneles VPN:
    "ec2:DescribeVpnConnections",
    # URL prefirmadas de S3 (discos y manifiestos de importacion):
    "ec2:DescribeConversionTasks",
    "ec2:DescribeImportImageTasks",
    "ec2:DescribeImportSnapshotTasks",
    # Politica de subida a S3 firmada:
    "ec2:DescribeBundleTasks",
    "organizations:CreateAccount",
    "organizations:LeaveOrganization",
    # Toda variante de asuncion/federacion de identidad, no solo la basica.
    "sts:AssumeRole",
    "sts:AssumeRoleWithSAML",
    "sts:AssumeRoleWithWebIdentity",
    "sts:GetFederationToken",
]
# NOTA: una lista negra nunca esta "completa". La defensa primaria sera la
# coherencia de servicio y de nivel de acceso (Fase 2); esto es profundidad.
# Al revisarla, contrastar con una fuente curada de vectores de escalada.

# Bloquea acciones comodin de servicio completo ("*", "s3:*"). Un comodin
# de prefijo mas estrecho como "s3:Get*" si se permite.
BLOQUEAR_ACCION_WILDCARD = True

# Bloquea ARNs con comodin en region o cuenta ("arn:aws:dynamodb:*:123:table/x").
# Un comodin de region concede el permiso en todas las regiones a la vez.
# El comodin de ruta al final ("bucket/*") si se permite: es normal en S3.
BLOQUEAR_ARN_COMODIN = True

# Servicios que este sistema puede conceder. Lo que no este aqui se rechaza
# antes de invocar al modelo: es un chequeo de codigo, no una instruccion.
SERVICIOS_PERMITIDOS = [
    "s3",
    "dynamodb",
    "sqs",
    "sns",
    "logs",
    "cloudwatch",
    "ec2",
    "lambda",
]

# Servicios que solo se conceden para leer, y con que acciones (ADR-002,
# opcion B de Mateo, 23-10-2026). EC2 queda en inventario: el riesgo de
# sus 826 acciones no es escalar sino coste (lanzar instancias) y
# exposicion (abrir grupos de seguridad, publicar una AMI). Una solicitud
# de otro tipo se rechaza antes del modelo, y una accion fuera del patron,
# despues. El techo permite exactamente lo mismo.
SOLO_LECTURA = {"ec2": "Describe*"}

# Acciones de escritura SIN tipo de recurso que aun asi se pueden conceder
# con `Resource: "*"` (revision del 24-10-2026, S3). Lista blanca y no
# negra: una accion que no admite ARN casi siempre actua sobre la CUENTA
# entera (`logs:PutAccountPolicy`, `dynamodb:PurchaseReservedCapacityOfferings`,
# `sns:SetSMSAttributes`...), y ahi los chequeos de recurso y de recursos
# del sistema no pueden juzgar nada, porque el recurso es "*". Con "*" solo
# pasan las de nivel List o Read segun el catalogo; las demas, solo si
# estan aqui con su motivo. Empieza vacia a proposito. Quedan fuera por
# ahora `lambda:CreateEventSourceMapping` (disparadores: el catalogo no le
# da tipo de recurso y solo se acota por `lambda:FunctionArn`),
# `lambda:CreateCodeSigningConfig` y similares: si hace falta alguna, se
# anade aqui con el porque, y el techo la deja pasar al regenerarlo
# (`scripts/generar_techo.py` lee esta misma lista).
ESCRITURAS_SIN_RECURSO_PERMITIDAS: dict[str, str] = {}

# Prefijos de los recursos del propio sistema (ADR-002, D3). Ningun
# beneficiario los recibe: con escritura en el bucket del paquete podria
# cambiar el codigo del agente; en la tabla, falsear aprobaciones; en los
# logs, borrar rastro. Se comparan en minusculas sobre cada componente del
# ARN. El techo (D2) niega lo mismo en IAM, con los patrones del rol de
# despliegue.
PREFIJOS_DEL_SISTEMA = ("agente-iam", "agente_iam", "agenteiam")

# El permission boundary que todo beneficiario debe llevar ANTES de pedir
# nada. Lo exige el rol del aplicador con la condicion
# `iam:PermissionsBoundary` en el Attach, asi que un principal sin el no
# puede recibir nada de este sistema: es el requisito de alta.
# Hasta el techo v2 (ADR-002) no recortaba nada de lo que el sistema
# concede. Ahora lo genera `scripts/generar_techo.py` desde estas listas y
# la referencia de autorizacion: EC2 solo `Describe*`, ninguna accion de
# gestion de permisos, nada sobre los recursos del sistema, y sus Deny
# espejan la parte de ACCIONES_PROHIBIDAS que cae dentro de los servicios
# permitidos.
NOMBRE_TECHO = "AgenteIAM-Techo"

# La puerta de demostracion de la autoaprobacion, del lado del APLICADOR
# (revision del 24-10-2026, S4). `aprobar --autoaprobacion-demo` deja
# grabado `separacion_de_funciones.resultado = SALTADO`; hasta esta fecha el
# aplicador no miraba ese campo y aplicaba igual. Ahora un SALTADO solo se
# aplica si quien corre el aplicador abre esta puerta a proposito, en SU
# entorno, con el valor exacto "si". No sustituye a un control: el
# aprobador puede escribir el bloque a mano (decision pendiente, ver PLAN,
# Fase 17), pero ya no basta con que el aprobador decida saltarselo.
PERMITIR_AUTOAPROBACION = os.getenv("AGENTE_IAM_PERMITIR_AUTOAPROBACION") == "si"

# Intentos maximos del loop de reparacion antes de escalar a un humano.
MAX_INTENTOS = 3

# --- Almacen de solicitudes -------------------------------------------------
# Donde vive el registro. "disco" es el de desarrollo y sigue siendo el
# valor por defecto a proposito: correr los comandos en tu maquina no debe
# escribir en la tabla de la cuenta sin que lo hayas pedido.
#
# El desplegado usa "dynamodb", porque el sistema de ficheros de AgentCore
# Runtime es efimero. Los detalles y por que hay dos, en `almacen.py`.
ALMACEN = os.getenv("ALMACEN", "disco")

# Carpeta donde se guardan las solicitudes y su estado (backend "disco").
DIR_SOLICITUDES = os.getenv("DIR_SOLICITUDES", "solicitudes")

# Tabla de DynamoDB (backend "dynamodb"). Clave de particion: `id`.
TABLA_SOLICITUDES = os.getenv("TABLA_SOLICITUDES", "agente-iam-solicitudes")

# La URL de funcion de la Lambda de aprobacion (ADR-003, A2), a donde manda
# `aprobar_cliente` su peticion firmada con SigV4. Vacia a proposito: sin ella,
# en DynamoDB el cliente no decide nada, porque aprobar es cosa de la Lambda y
# de nadie mas. Es una salida de la pila que despliega esa Lambda.
URL_APROBACION = os.getenv("AGENTE_IAM_URL_APROBACION", "")

# Donde vive el catalogo oficial de acciones de AWS. En local es una cache
# que se rellena sola por HTTP; en el paquete desplegado viaja DENTRO y el
# directorio es de solo lectura, asi que `catalogo.py` separa leer de
# escribir. Que no este disponible apaga el chequeo de nivel de acceso, y
# por eso `servidor.py` lo comprueba al arrancar en vez de descubrirlo
# cuando ya no bloquea nada.
DIR_CACHE_CATALOGO = os.getenv("DIR_CACHE_CATALOGO", ".cache/servicereference")

# Cuantos dias vale la cache local del catalogo antes de volver a
# descargarlo (revision del 24-10-2026, O2). El catalogo decide el nivel de
# acceso de cada accion y si un `Resource "*"` es legitimo, y AWS lo cambia:
# el 23-10-2026 la cache de agosto tenia 807 acciones de EC2 y la referencia
# 826. Una accion que la cache no conoce no se expande en un comodin, asi
# que una cache vieja deja pasar justo lo nuevo. Siete dias es un compromiso:
# una descarga por semana como mucho, y nunca un catalogo de meses. Si la
# descarga falla, se usa la vieja avisando (sin catalogo el chequeo de nivel
# se apagaria, que es peor). En el paquete desplegado no caduca: alli el
# directorio es de solo lectura y el catalogo es el que se empaqueto.
CADUCIDAD_CATALOGO_DIAS = 7

# Valor con el que una propuesta de S3 acota la cuenta del recurso (S5):
# `"aws:ResourceAccount": VALOR_CUENTA_DEL_RECURSO`. Es el mismo valor que
# usa la sentencia S5 del techo (`SoloRecursosDeLaPropiaCuenta`). Para
# CheckNoNewAccess la propuesta y el techo tienen que restringir la cuenta
# del recurso con la MISMA forma (medido el 25-10-2026: la literal falla
# contra un techo con la variable y viceversa). Si el techo pasa a llevar la
# cuenta literal, este valor pasa a ser `None`, que significa "la cuenta
# verificada literal".
VALOR_CUENTA_DEL_RECURSO: str | None = "${aws:PrincipalAccount}"

# --- Rol por persona (Fase 23) ----------------------------------------------
# Tope de roles de persona vigentes (no vencidos) por persona. Protege las
# cuotas de IAM de la cuenta (1000 roles y 1500 politicas gestionadas): cada
# solicitud aprobada crea un rol y una politica, hasta que exista el borrado
# automatico de los roles vencidos nada limpia lo que se acumula, y sin tope
# una sola persona podria agotar las cuotas para todas (diseno Fase 23, 5.1).
# Tambien acota cuantos roles tiene a la vez una persona. Al llegar al tope hay
# que esperar a que venza alguno. Se corta antes del modelo en los chequeos
# previos, pero el modelo corre antes de que se aplique nada: el tope no
# limita el gasto en el, solo los roles.
MAX_ROLES_VIGENTES_POR_PERSONA = 5

# Vida del permiso por persona, en horas: es tambien la sesion maxima del rol
# (`personas.vence_desde` la aplica y `models` la valida en el contrato de
# entrada). Viven aqui y no en `personas` porque `models` viaja en la Lambda de
# aprobacion, que no lleva `personas`: importar
# `personas` desde `models` la dejaria sin arrancar. `personas` los reexporta.
HORAS_MIN = 1
HORAS_MAX = 12

# El user pool de Cognito. Lo necesita el aplicador para escribir la confianza
# del rol por persona (el proveedor OIDC del pool). Vacio a proposito: sin el
# no se puede aplicar en ese modo, y es preferible que falle a que escriba una
# confianza a medias. Es una salida de la pila que lo crea, no un secreto.
POOL_ID = os.getenv("AGENTE_IAM_POOL_ID", "")

# Forma de un id de cliente de Cognito: 26 caracteres en minuscula y digitos.
_PATRON_CLIENTE_COGNITO = re.compile(r"[a-z0-9]{26}")

# Los clientes de Cognito cuyo `aud` admite la confianza del rol por persona:
# el de la CLI y el de la web, separados por coma en AGENTE_IAM_CLIENTES (cada
# id sin espacios alrededor). Un token de cualquier otro cliente del pool no
# puede asumir el rol. Vacia por defecto, por la misma razon que POOL_ID.
CLIENTES_COGNITO: tuple[str, ...] = tuple(
    c for c in (e.strip() for e in os.getenv("AGENTE_IAM_CLIENTES", "").split(",")) if c
)

# Los ids de CLIENTES_COGNITO que no tienen la forma de un cliente de Cognito.
# No se descartan en silencio: un id mal escrito (un espacio, una letra de mas)
# dejaria la confianza sin el cliente que se queria o con uno que no existe, y
# el error aparece al intentar entrar, lejos de la causa. Quien escribe la
# confianza (el aplicador) se niega a aplicar si esta tupla no esta vacia.
CLIENTES_COGNITO_INVALIDOS: tuple[str, ...] = tuple(
    c for c in CLIENTES_COGNITO if not _PATRON_CLIENTE_COGNITO.fullmatch(c)
)
