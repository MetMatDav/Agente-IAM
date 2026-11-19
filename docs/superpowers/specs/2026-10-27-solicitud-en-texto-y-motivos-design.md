# Diseno: la solicitud en texto, el recurso comprobado y el motivo de cada estado

Fecha: 27-10-2026. Estado: aprobado por Mateo el 27-10-2026 (con nivel_entendido, el ejemplo tal cual y el correo con dominio propio primero); codigo y plantillas escritos el 27-10-2026, sin desplegar. Fase 28 de `PLAN-CORRECCIONES.md`.
Excluido a proposito: el diseno visual de la pagina, que se rehara para que concuerde con el portafolio.

## De donde sale

Mateo probo la pagina en `https://agente-iam.mateo.solutions` el 27-10-2026 con `solicitante.demo`. Dos solicitudes:

| Solicitud | Estado | Lo que paso, leido en la tabla |
|---|---|---|
| "porque quiero hacer estragos" (s3, administracion) | `requiere_revision_humana` | El modelo se nego a conceder nada; tres intentos y ninguna politica valida |
| analisis con Redshift (s3, `bucket-de-ejemplo`, administracion) | `propuesta` | Politica valida; nadie comprobo que el bucket existe (el modelo lo anoto como supuesto) |

Sus observaciones, y lo que decidio el 27-10-2026:

1. El campo "Tipo de acceso" sobra: un solicitante no sabe que es lectura o escritura. Todo va en el texto, que pasa a
   llamarse "Solicitud", con un ejemplo de solicitud completa.
2. El recurso deberia admitir tambien su ARN, si el cambio es breve.
3. Comprobar que el recurso existe era requisito: no gastar modelo ni tiempo de solicitante y aprobador en algo invalido.
4. Cada estado debe decir el porque en una frase corta, para el solicitante y para quien tenga que resolverlo.
5. Las credenciales no deben ofrecerse si no hay nada que canjear.

Ademas: el correo de la primera solicitud no llego, ni en spam. SES lo entrego (un intento a las 02:37 UTC, cero rebotes,
direccion no suprimida); Gmail lo descarto o lo escondio. El remitente es una direccion de gmail.com enviada por SES, sin DKIM
propio: Gmail no puede comprobar que sea legitima.

## 1. Sin "Tipo de acceso": el nivel lo deduce el sistema y lo comprueba el codigo

**Lo que protege hoy el campo.** No es solo una opcion: es una barrera determinista. `coherencia.py` compara cada accion de la
politica propuesta con el nivel pedido, con el catalogo oficial de AWS (`catalogo.excede_tipo_acceso`), y bloquea lo que lo
exceda. Medido en el codigo: "escritura" y "administracion" solo excluyen la gestion de permisos, que el techo prohibe igual,
asi que son la misma cosa. La unica distincion que protege es **solo leer** frente a **modificar**. Y EC2 se corta antes del
modelo si no se pide lectura.

**Quitar el campo sin perder la barrera:**

- **El modelo declara el nivel que entendio.** La salida del agente gana un campo `nivel_entendido`: `lectura` o
  `modificacion`. El codigo aplica la misma barrera de hoy contra ese nivel: si el modelo dice `lectura` y propone una
  escritura, se bloquea. Atrapa la incoherencia del modelo consigo mismo, que es el fallo mas comun.
- **El nivel real lo calcula el codigo, no el modelo.** Con el catalogo, el codigo clasifica la politica propuesta: solo
  lectura, modifica, o puede borrar. Eso es lo que ven el solicitante, el aprobador y el correo, en palabras llanas:
  "Esta propuesta permite ver y modificar objetos de `finanzas-2026`; no permite borrar".
- **El riesgo sube solo.** El motivo de riesgo "se pide nivel de administracion" se sustituye por "la propuesta modifica
  datos" y "la propuesta puede borrar". Con cualquiera de los dos, el aprobador tiene que confirmar el riesgo, como hoy.
- **EC2 sigue en solo lectura**, comprobado despues del modelo con el patron `Describe*` que ya existe.

**Lo que se pierde, dicho claro:** hoy el solicitante fija un techo propio ("solo lectura") que ni el modelo ni una
justificacion maliciosa pueden subir. Sin el campo, ese techo lo pone el modelo leyendo el texto. Un texto que lo manipule
puede pedir modificar; lo paran el techo del sistema, la lista de bloqueo y el aprobador, que ve el nivel real calculado por el
codigo. Es la decision de Mateo; queda escrita para el ADR.

**El texto.** La etiqueta pasa a "Solicitud". Por dentro el campo sigue llamandose `justificacion` (contrato del runtime, CLI,
registros y tests): cambiar el nombre visible no obliga a cambiar el contrato. El limite sube de 1000 a 1500 caracteres. Ejemplo
que se muestra bajo el campo:

> Necesito ver y subir archivos CSV en la carpeta `cierres/` del bucket `finanzas-reportes-2026` para preparar el cierre
> mensual. No necesito borrar nada ni tocar otras carpetas.

La ayuda dice que debe llevar: que recurso, que necesitas hacer (ver, subir, modificar, borrar), para que, y lo que NO
necesitas. La duracion sigue en su campo de horas.

## 2. El recurso admite nombre o ARN

Breve: un validador en `models.py` y una tabla por servicio.

- Si el texto empieza por `arn:`, el codigo lo separa: el servicio del ARN debe ser el del formulario, la region la del
  formulario (vacia en S3) y la cuenta la de esta cuenta (vacia en S3). Si algo no coincide, se rechaza antes del modelo con
  el motivo `arn_no_coincide`.
- De un ARN valido se saca el nombre, que es lo que usa todo lo demas: `arn:aws:s3:::finanzas` da `finanzas`;
  `...:table/Ventas` da `Ventas`; `...:function:cobros` da `cobros`; y lo mismo para SQS, SNS, Logs y alarmas de CloudWatch.
- El registro guarda lo que escribio el solicitante y el nombre que se saco.
- EC2 no tiene recurso unico (es inventario): se sigue aceptando el texto de hoy.

## 3. El recurso tiene que existir antes de llamar al modelo

Nuevo chequeo previo, en `orquestador.chequeos_previos`, despues de los del formulario y antes de Bedrock. Lecturas que no
revelan contenido:

| Servicio | Como se comprueba | Permiso nuevo del runtime |
|---|---|---|
| S3 | `ListBuckets` y buscar el nombre: solo lista los buckets de esta cuenta | `s3:ListAllMyBuckets` |
| DynamoDB | `DescribeTable` | `dynamodb:DescribeTable` sobre `table/*` |
| SQS | `GetQueueUrl` con la cuenta propia | `sqs:GetQueueUrl` |
| SNS | `GetTopicAttributes` del ARN armado con cuenta y region | `sns:GetTopicAttributes` |
| Logs | `DescribeLogGroups` con el nombre exacto | ya lo tiene |
| CloudWatch | `DescribeAlarms` con el nombre | `cloudwatch:DescribeAlarms` |
| Lambda | `ListTags` del ARN armado (no devuelve variables de entorno, que pueden llevar secretos) | `lambda:ListTags` |
| EC2 | no aplica | ninguno |

- **No existe:** `rechazada_en_chequeos_previos` con el motivo `recurso_no_encontrado`. No se llama al modelo.
- **No se pudo comprobar** (permiso denegado, servicio caido): se sigue, y el registro y el aprobador lo ven como aviso. Un
  fallo de la comprobacion no debe tumbar todas las solicitudes.
- Para S3 no basta con que el nombre exista en el mundo: tiene que ser de esta cuenta. `ListBuckets` lo garantiza.
- Los permisos nuevos van en el rol `AgenteIAM-Runtime` (`infra/cfn/base.yaml`) y en su limite `AgenteIAM-LimiteSistema`.
  Son metadatos, no datos. Sin medir: que `ListTags` de Lambda de `ResourceNotFoundException` para una funcion que no existe y
  que el limite actual no tape alguna; se mide al desplegar, como siempre.

## 4. Un motivo corto en cada estado

Cada registro gana `motivo` = `{codigo, texto}`. Lo arma el codigo a partir de datos del registro, con frases fijas: nunca se
copia texto del modelo ni del solicitante a la pagina o al correo, para que una solicitud maliciosa no pueda colar mensajes. El
detalle completo sigue en el registro para quien lo resuelva.

| Estado | Codigo | Texto para la persona |
|---|---|---|
| `rechazada_en_chequeos_previos` | `recurso_no_encontrado` | No se encontro el recurso en esta cuenta. Revisa el nombre. |
| | `arn_no_coincide` | El ARN no corresponde al servicio, la region o la cuenta elegidos. |
| | `servicio_no_admitido` / `region_no_admitida` | El sistema no concede accesos en ese servicio o region. |
| | `recurso_del_sistema` | Ese recurso es del propio sistema y no se concede. |
| | `tope_de_roles` | Ya tienes el maximo de accesos vigentes; espera a que venza alguno. |
| | `solo_lectura` | Ese servicio solo se concede para consultar. |
| `redundante_no_requiere_cambio` | `ya_tiene_el_acceso` | Ya tienes ese acceso con un rol vigente; no hace falta otro. |
| `requiere_revision_humana` | `riesgo_alto` | La solicitud se marco de riesgo alto; la revisara una persona. |
| | `excede_limites` | Lo pedido supera lo que el sistema puede conceder; la revisara una persona. |
| | `sin_politica_valida` | No se pudo armar un permiso seguro con lo descrito; la revisara una persona. |
| `propuesta` | `confirmar_riesgo` | Permite modificar (o borrar) datos: el aprobador tendra que confirmarlo. |
| | `espera_aprobacion` | Espera la aprobacion de una persona. |
| `rechazada_por_aprobador` | `rechazada` | El aprobador la rechazo: (su motivo, escapado; lo escribio una persona del sistema). |
| `bloqueada_al_aplicar` | `bloqueada` | Algo cambio entre la aprobacion y la aplicacion; no se creo nada. |
| `aplicada` | `aplicada` | Acceso creado: rol, permisos en palabras llanas y hora en que vence. |

Para `requiere_revision_humana` el codigo se elige con datos: `riesgo_alto` si la propuesta del modelo trae `nivel_riesgo`
alto, `excede_limites` si algun bloqueo es de la lista de bloqueo o del techo, y `sin_politica_valida` en lo demas. Para eso
`chequeos_formulario` devuelve pares (codigo, texto) en vez de solo textos; los textos actuales siguen en el registro. El motivo
va en la respuesta del runtime, en la pagina y en el correo.

## 5. Las credenciales, solo cuando hay algo que canjear

- **En `propuesta`:** sin boton. En su lugar: "Cuando se apruebe te avisaremos por correo. Entonces vuelve aqui y usa el id
  de la solicitud".
- **Seccion nueva "Usar un acceso aprobado":** un campo con el id de la solicitud y el boton "Obtener credenciales". La pagina
  arma el ARN del rol con el usuario del token, el id y la cuenta: el mismo nombre determinista que usa el aplicador. No da nada
  a nadie mas, porque la confianza del rol solo acepta el `sub` de esa persona.
- **El correo de `aplicada` lleva el enlace** `https://agente-iam.mateo.solutions/?solicitud=<id>`, que rellena el campo.
- **El `AccessDenied` se traduce:** "Ese acceso todavia no esta aprobado, ya vencio o no es tuyo".
- En los demas estados no aparece nada de credenciales, como hoy.

## 6. El correo con dominio propio (propuesta de Claude, decision de Mateo)

La causa del correo perdido no se arregla del lado de Gmail. Con `mateo.solutions` ya hay donde firmar:

- Identidad de dominio en SES para `agente-iam.mateo.solutions`, con DKIM facil: tres CNAME que Mateo pone en la zona de
  gestion, como el de ACM.
- Remitente `avisos@agente-iam.mateo.solutions`: el parametro `CorreoRemitente` de las pilas y la condicion `ses:FromAddress`
  del rol de avisos.
- DMARC pasa con DKIM alineado. SES sigue en modo inicial: solo puede mandar a direcciones verificadas, y la de Mateo ya lo esta.

Es independiente de los puntos 1 a 5 y se puede hacer antes.

## Lo que cambia, por fichero

| Fichero | Cambio |
|---|---|
| `web/index.html`, `web/app.js` | Sin tipo de acceso; "Solicitud" con ejemplo y ayuda; motivo en el resultado; seccion "Usar un acceso aprobado"; error de STS traducido |
| `agente_iam/models.py` | `tipo_acceso` sale de los campos; validador de recurso con ARN; `motivo` en el registro |
| `agente_iam/agente.py` | El prompt pide `nivel_entendido` y deja de leer el tipo del formulario |
| `agente_iam/coherencia.py` | Barrera contra `nivel_entendido`; nivel real calculado; riesgo por modificar o borrar; codigos de motivo |
| `agente_iam/orquestador.py` | Chequeo de existencia antes del modelo |
| `agente_iam/servidor.py`, `agente_iam/avisos.py` | El motivo en la respuesta y en el correo; enlace en `aplicada` |
| `agente_iam/cli.py`, `ejemplos/` | Sin `tipo_acceso`; casos de recurso inexistente y de ARN |
| `infra/cfn/base.yaml`, `infra/cfn/arranque.yaml` | Lecturas nuevas del runtime y de su limite |

Los registros viejos llevan `tipo_acceso`: aprobar y aplicar tienen que seguir leyendolos. La revalidacion usa el campo si esta
y `nivel_entendido` si no.

## Tests que lo atan

- Una politica con escritura bajo `nivel_entendido = lectura` se bloquea; con `modificacion` pasa a riesgo con confirmacion.
- La clasificacion del codigo: solo lectura, modifica, borra, con acciones reales del catalogo.
- ARN: nombre sacado bien por servicio; servicio, region o cuenta distintos dan `arn_no_coincide`.
- Existencia con stubs: existe, no existe (no se llama al modelo) y no se pudo comprobar (se sigue con aviso).
- Cada estado tiene su motivo; ningun motivo contiene texto del modelo o del solicitante.
- La pagina no muestra credenciales en `propuesta` y arma el ARN del rol igual que el aplicador.
- Un registro viejo con `tipo_acceso` se sigue aprobando y aplicando.

## Despliegue

1. Codigo y tests en el repositorio.
2. Administrador: limite `AgenteIAM-LimiteSistema` en `arranque.yaml`, con las lecturas nuevas.
3. Operador: change set de `base.yaml` con los permisos del runtime.
4. Paquetes del runtime, del aplicador (lleva `avisos.py`) y de la aprobacion (lleva `coherencia.py`), y sus change sets.
5. Pagina: construir y subir (el administrador), e invalidar la cache.
6. Medir: recurso inexistente rechazado sin llamada a Bedrock; ARN; los motivos en pagina y correo; credenciales por id.

## Lo que decide Mateo

1. Quitar el tipo de acceso con la barrera sustituida por `nivel_entendido` y el nivel calculado (recomendado), o dejar una
   pregunta en lenguaje llano ("Solo ver" / "Ver y modificar").
2. Si el punto 6 (correo con dominio propio) va primero o despues.
3. El texto del ejemplo de solicitud.

## Desviaciones al implementar (27-10-2026)

- El servicio o la region distintos de un ARN son un error del formulario (HTTP 422, "Revisa estos campos"), no el rechazo
  `arn_no_coincide`: se pueden comprobar sin conocer la cuenta. Solo la cuenta distinta da `arn_no_coincide`, en los chequeos previos.
- `tipo_acceso` sigue siendo opcional en el modelo, para los registros anteriores (que se revalidan con el) y para el CLI de desarrollo.
  Los ejemplos del modo de principal en `ejemplos/` lo conservan a proposito, para ejercitar el camino antiguo.
- El id del enlace del correo cruza el login dentro del `state` de OAuth, porque la pagina solo guarda el verificador PKCE y el `state`.
- El ARN del rol se arma en la pagina, igual que `personas.nombre_de_rol`; un test de paridad lo comprueba contra node cuando esta disponible.
