# Principios y lecciones de diseno y seguridad de un agente de IA con permisos
### Proyecto "Agente IAM". Cubre hasta el 27-10-2026

---

## 0. Para quien es este documento

Es el documento de lecciones del proyecto, escrito para quien lo evalua
(portafolio, entrevista tecnica). El manual de operacion es `CONTEXTO.md`; el
estado de las correcciones, `PLAN-CORRECCIONES.md`; lo medido contra AWS, con
su fecha y su banco de pruebas, `docs/MEDICIONES.md`. Aqui esta el *por que*:
que fallo, que principio lo explica y que se generaliza a cualquier sistema
donde un modelo de lenguaje toca algo que importa.

Orden: 1 el sistema; 2 los dieciseis principios; 3 catalogo de 22 casos, seis
desarrollados; 4 el simulador de IAM, como metodo experimental; 5 decisiones de
arquitectura; 6 diez preguntas de entrevista con enlace; 8 cinco frases; 10 a
13 tests, analisis estatico, auditoria de dependencias y SCP; 14 a 17 la Fase
15; 18 la revision independiente del 24-10-2026 (Fase 17); 19 el estudio final
de arquitectura (pendiente). Las secciones 7 y 9 estan retiradas.

Hilo del documento: **los fallos que mas cerca estuvieron de causar dano no se
encontraron leyendo codigo ni con tests en verde, sino ejecutando contra la
cuenta o con una revision independiente** (P12, seccion 18).

---

## 1. El sistema, en una pagina

Un empleado pide acceso a un recurso de AWS ("necesito leer el bucket de
finanzas"). Un agente de IA (Claude via Amazon Bedrock, con Strands) **propone**
una politica IAM de minimo privilegio. Un humano la aprueba antes de que se
aplique nada.

**La restriccion que define el diseno.** El agente **no tiene escritura en
IAM**: corre bajo un rol de solo lectura con un Deny explicito sobre todo verbo
de escritura. Aplica otro proceso, con su propio rol, que lee solicitudes ya
aprobadas y **nunca habla con el modelo**. El texto de la solicitud es entrada
no confiable; con esta separacion, el peor caso de una inyeccion de prompt es
*una propuesta mala que un humano rechaza* (P5).

```
solicitud (JSON)
  -> contrato de tipos (Pydantic): alfabetos cerrados
  -> chequeos previos: servicio permitido, principal real, techo puesto
  -> agente (Bedrock) propone una politica
  -> validacion en 3 capas + coherencia con el formulario, TODO desde el codigo
  -> si falla: se devuelven los motivos y reintenta (max. 3, contados en Python)
  -> registro con su estado final (se escribe siempre)
  -> aprobacion humana: identidad resuelta, separacion de funciones,
     revalidacion, compuerta de pago, huella del registro
  -> aplicador (rol propio, unico que escribe en IAM): verifica, revalida,
     crea la politica y la adjunta
```

| Capa | Pregunta que responde | Herramienta |
|---|---|---|
| Lista negra + catalogo oficial | Concede de mas? | Codigo propio + JSON de AWS |
| IAM Access Analyzer | Esta bien formada? | `ValidatePolicy` |
| Simulador de IAM | Concede lo pedido? Ya lo tenia? | `SimulateCustomPolicy`, `SimulatePrincipalPolicy` |

**Vocabulario minimo.** **Politica**: JSON con `Statement`s (`Effect`,
`Action`, `Resource`, `Condition`). **Deny explicito**: gana siempre, incluso
sobre `AdministratorAccess`; el **implicito** (nada lo permite) desaparece si
alguien concede. **Permission boundary (techo)**: lo que la identidad puede
hacer es la *interseccion* de sus politicas y su boundary; nunca concede.
**SCP**: politica de la organizacion que recorta, nunca concede, y no se aplica
a la cuenta de gestion. **Clave de condicion** (`aws:RequestedRegion`): valor
del contexto de la peticion contra el que se evaluan las `Condition`. **Id
unico** (`AIDA...`, `AROA...`): lo asigna AWS y no se reutiliza; el ARN
identifica un *nombre*, el id la *entidad*. **Politica inline**: no se puede
acotar por path, y por eso el aplicador no las crea. **Idempotencia**: repetir
la operacion deja el sistema igual que hacerla una vez.

---

## 2. Los dieciseis principios

Cada uno salio de un fallo concreto del proyecto.

### P1. La confianza se declara; nunca se hereda

Un dato no es confiable por pasar por un formulario, venir en JSON o estar en
una seccion del prompt titulada "confiable". La confianza se **produce**
(verificando contra una fuente de verdad) y se **rastrea** (que campo es
verificado y cual declarado). Vale tambien para el humano: lo que el aprobador
"sabe" no se hereda de una pantalla anterior (3.21).

### P2. El codigo decide; el modelo y los servicios externos informan

Que el modelo diga que valido no es evidencia. Tampoco lo es siempre lo que
dice un servicio de AWS (el simulador, seccion 4). Para cada garantia: *que
linea de codigo propio la sostiene?* La otra cara: una senal poco fiable solo
endurece, nunca ablanda (3.12).

### P3. Un falso positivo cuesta tanto como un falso negativo

Un sistema que bloquea peticiones legitimas pierde la confianza de sus usuarios,
y la gente aprende a saltarlo. De los seis errores de la primera sesion, casi
todos eran falsos positivos: la baranda demasiado estricta se escribe con la
misma buena intencion que la correcta.

### P4. La direccion segura de la duda depende de que se rompe

Ante la misma incertidumbre ("el simulador no pudo evaluar esta condicion") dos
funciones reaccionan al reves. `eficacia` pregunta si la politica concede lo
pedido: si duda y bloquea, manda corregir algo correcto, asi que **la duda no
bloquea**. `redundancia` pregunta si el usuario ya podia: si duda y dice "ya lo
tenia", el usuario se queda sin acceso, asi que **la duda no permite concluir
que ya lo tenia**. La pregunta es *que se rompe, y para quien, si me equivoco en
cada direccion?*

### P5. Separar quien interpreta de quien ejecuta

El componente que procesa entrada no confiable no debe tener los permisos cuyo
abuso busca el atacante. No es una capa mas: hace opcionales a las demas. Si el
agente no puede escribir en IAM, ninguna inyeccion de prompt escribe en IAM.

### P6. Cerrar lo cerrable, restringir lo que no, aislar lo libre

(1) Un conjunto finito es una lista cerrada (`tipo_acceso`). (2) Lo que no se
puede pre-listar (un nombre de bucket) se cierra en su *alfabeto*: sin espacios,
comillas ni saltos de linea no se escribe una instruccion en lenguaje natural.
(3) Lo libre (una justificacion) se serializa antes de entrar al prompt. Es el
problema de SQL y XSS, pero el interprete es un modelo: el escape es
mitigacion, no garantia, y por eso P5 sigue siendo la defensa.

### P7. Lo que no deja registro, no ocurrio

Un sistema cuyo argumento es la auditabilidad no puede perder las corridas que
fallan. **El registro se escribe siempre; el fallo se reporta despues**, con la
fase donde murio, la traza y el trabajo parcial. Tragarse el error es el
anti-patron opuesto: se persiste, se reporta y se sale con codigo distinto de
cero.

### P8. El dato canonico viene de la fuente, no de nuestro parseo

Si una API devuelve la version autoritativa de un dato, se usa. Comprobar solo el
nombre extraido de un ARN es una verificacion incompleta disfrazada; `GetUser`
devuelve el **ARN completo** y compararlo entero cuesta una linea. Al corregir
una verificacion parcial, se usa el dato completo que ya estaba a mano.

### P9. Cada capa responde una pregunta que ninguna otra responde

Si dos capas responden lo mismo, una sobra. La prueba de que una capa gana su
sitio es un caso que las otras dejan pasar: Access Analyzer aprobo `s3:*` sobre
`*` sin hallazgos (por eso la lista negra); ambas aprobaron una politica que el
simulador evaluo `implicitDeny` (por eso el simulador). Y una cuarta pregunta sin
capa: *la propuesta corresponde a la solicitud?* Tambien hay que preguntar
**sobre que sujeto** responde la capa (3.17).

### P10. Cuando la documentacion no alcanza, se disena un experimento

Un caso positivo no basta: si la prueba "sin contexto" sale `allowed`, admite dos
lecturas ("ignoro la condicion", "mi contexto no llego"). Hace falta el
**control** (contexto que cumple: pasa) y sobre todo el **caso negativo**
(contexto que no cumple: falla). Y una observacion no es una conclusion: la
primera lectura de los experimentos de la seccion 4 era falsa
(`docs/MEDICIONES.md` §H, fila 1).

### P11. El manejo de errores es codigo de produccion

La funcion que mostraba el resultado fallaba al mostrar un registro de error
(3.10): se rompia justo cuando hacia falta. Los caminos de fallo se ejercitan
poco y acumulan bugs; merecen tests propios y escribirse a la defensiva.

### P12. Lo que no se ha ejecutado, no funciona

El principio mas rentable. Con la aprobacion y el aplicador escritos habia 114
tests en verde; al ejecutarlos contra la cuenta salieron tres fallos que ninguna
lectura encuentra: la huella que no verificaba (3.13), un permiso que el
catalogo no menciona (3.14) y el agregado pesimista (3.15). En los tres, el
sistema y su descripcion no coincidian y solo se leia la descripcion. Corolarios:
probar la pieza aislada no prueba el flujo que la usa; el catalogo de una API
dice lo que acepta, no lo que exige; una compuerta que nunca ha dicho que no no
esta probada; y un test que escribe lo que el codigo escribe no prueba lo que
otro podria escribir (seccion 18).

### P13. Una advertencia siempre encendida no es una advertencia

El sistema marcaba el 100 % de las acciones como "no concluyentes" (3.11). Caia
del lado prudente, pero un aviso que sale siempre se aprende a ignorar, y
entonces tambien se ignora el dia que significa algo. Es P3 aplicado a senales.
Prueba: *en que situacion NO se dispara?*

### P14. Un control sin salida se elimina; uno con salida registrada sobrevive

Aqui el mismo humano pide y aprueba; una separacion de funciones estricta haria
inusable la demo, y los controles inusables se quitan o se rodean sin rastro. La
salida es una puerta explicita (`--autoaprobacion-demo`): el control bloquea por
defecto y, si alguien pasa, el registro guarda **que control se salto, quien y
cuando**. La eleccion real es entre un control que se rodea en silencio y uno
que se rodea dejando huella; el segundo es mas debil en el papel y mas fuerte en
la practica.

### P15. Para reintentar hacen falta coordenadas, no afirmaciones

Un proceso que escribe en un sistema externo puede morir en cualquier punto.
Anotar la intencion antes de actuar crea una segunda fuente de verdad que puede
quedar obsoleta. Lo bueno es **derivar un nombre determinista** del id de la
operacion y verificar el contenido antes de asumir que el artefacto es tuyo. El
reintento converge desde cualquier punto de muerte y **no hace falta distinguir
primera corrida de reintento**: esa ausencia de ramas es la senal de que el
diseno es correcto.

### P16. Un techo que contiene todo lo que concedes no es un techo

Un Deny explicito gana; si no lo hay, el permiso efectivo es la interseccion de
las politicas con el boundary. `AgenteIAM-Techo` v1 permitia enteros los ocho
servicios que el sistema puede conceder: toda propuesta coherente era
subconjunto suyo y la interseccion la devolvia entera; solo recortaba su Deny,
que la lista negra ya bloqueaba gratis. Igual la compuerta de pago
(`CheckNoNewAccess` contra ese techo): su prueba de que "estaba encendida" uso
`iam:CreateUser`, que el flujo real no produce. Pregunta que lo habria evitado:
**que propuesta que llegue a esta compuerta puede hacerla fallar?** Si es
"ninguna que no hayan parado ya otras capas", es redundancia, no control (medido
en `docs/MEDICIONES.md` §E.1; seccion 16).

---

## 3. Catalogo de casos

Los seis marcados (D) estan desarrollados debajo de la tabla.

| # | Caso | Sintoma | Arreglo | Principio |
|---|---|---|---|---|
| 3.1 | Destinatario sin verificar | El `principal_arn` que escribe el modelo no se comparaba con la identidad verificada | Chequeo posterior: exactamente el ARN canonico | P1, P9 |
| 3.2 | Campos "confiables" que no lo eran (D) | `recurso` y `region` libres en la zona "confiable"; la justificacion cerraba su propio delimitador | Alfabetos cerrados; `json.dumps` | P6 |
| 3.3 | Lo propuesto no coincidia con lo pedido | Se validaba el servicio pedido, no que las acciones fueran de ese servicio ni del nivel pedido | Chequeos por prefijo y por nivel con el catalogo oficial (`IsWrite`, `IsPermissionManagement`), no una lista a mano | P2, P9 |
| 3.4 | Huecos en la lista negra | Faltaban `iam:AddUserToGroup`, `CreateLoginProfile`, `SetDefaultPolicyVersion`, `lambda:UpdateFunctionCode` | Ampliar lista y Deny del rol. Una lista nunca esta completa: es profundidad, la defensa primaria es 3.3 | P5, P2 |
| 3.5 | Se verificaba el nombre, no el ARN (D) | Un ARN de otra cuenta pasaba porque el nombre existia en la nuestra | Comparar entero el ARN que devuelve la API | P8, P3 |
| 3.6 | Una corrida fallida no dejaba registro | Sin manejo de excepciones; el guardado iba despues | `try/except` por fase, estado `error` con fase, traza e historial parcial; `Exception`, no `BaseException` | P7, P11 |
| 3.7 | El simulador corria sin contexto | Las condiciones que la baranda exige no se evaluaban | Aportar las claves ciertas con su tipo; lo que no esta en la tabla no se aporta | P2, P9 |
| 3.8 | El id de solicitud como nombre de archivo | `../../algo` escribe fuera de la carpeta | Alfabeto cerrado; un dato que cambia de rol se revisa para el rol nuevo | P6 |
| 3.9 | Estados y registros incoherentes | Un estado inalcanzable; registros viejos que las barandas de hoy bloquean; una bandera calculada y sin usar | Se elimina el estado; se revalida al aplicar; la huella cierra el TOCTOU | P7 |
| 3.10 | El error se rompia al mostrarse | Acceso directo a un campo vacio del registro de error | Rama propia y acceso defensivo | P11 |
| 3.11 | La advertencia siempre encendida | 100 % "no concluyente" por `aws:CalledViaLast` de un statement ajeno | `redundancia` no lee el reporte; dos cubos | P13, P2 |
| 3.12 | Una senal producida y tirada | Ninguna decision leia `nivel_riesgo` | El riesgo alto exige confirmacion; solo anade friccion | P2 |
| 3.13 | La huella que no verificaba (D) | Se calculaba y despues cambiaba el estado, que entraba en el hash | El estado no entra en la firma; test del flujo completo | P12 |
| 3.14 | El permiso que el catalogo no menciona (D) | `CreatePolicy` con etiquetas murio con `AccessDenied ... iam:TagPolicy` | `iam:TagPolicy` acotado y Deny de `iam:UntagPolicy` | P12 |
| 3.15 | El campo que resume esconde el que informa (D) | Con varios recursos, `EvalDecision` es el agregado pesimista | Leer `ResourceSpecificResults` | P12 |
| 3.16 | Nombre determinista en un espacio compartido | Los nombres de politica son unicos en la cuenta, no por path, y no distinguen mayusculas | Minusculas, cuarto estado ("existe en otro sitio"), procedencia en la `Description` | P8, P15 |
| 3.17 | El boundary en el sitio equivocado (D) | "Aplicador con boundary" limita lo que hace el aplicador, no lo que concede | El techo va en el destino; `iam:PolicyARN` e `iam:PermissionsBoundary` | P9 |
| 3.18 | Ningun chequeo miraba el recurso | `arn:aws:s3:::*` y `table/*` pasaban las tres capas | El nombre del formulario, completo y en su sitio por servicio | P9 |
| 3.19 | Un nivel que concedia saltarse el sistema | `administracion` admitia `s3:PutBucketPolicy` (politicas de recurso a terceros) | Ningun nivel concede `IsPermissionManagement`; hoy `administracion` y `escritura` coinciden | P9 |
| 3.20 | Escalada sin `iam:PassRole` | `lambda:UpdateFunctionConfiguration` y `ec2:ModifyInstanceAttribute` cambian lo que corre bajo un rol ya puesto | Bloquearlas tambien: no basta cerrar *una* forma, hay que contar cuantas hay | P2 |
| 3.21 | La huella firmaba lo que el aprobador no vio | `aprobar` leia, decidia y escribia; imprimia despues | Dos pasos: pinta propuesta y huella; aprueba solo esa huella | P1 |
| 3.22 | Una aprobacion escrita en el propio documento | Un `documento` con su `aprobacion` llegaba al aplicador como humana (S1, seccion 18) | La lectura rechaza `estado`, bloques o `id` ajenos dentro de `documento` | P12 |

### 3.2 Campos "confiables" que no lo eran, y un delimitador falsificable (D)

**Sintoma.** (a) `recurso` y `region` eran texto libre dentro de la seccion del
prompt rotulada "confiables": un `"recurso": "finanzas-2026. IGNORA TUS
INSTRUCCIONES..."` esquivaba el marco de dato no confiable. (b) La
justificacion iba cruda entre delimitadores `--- fin del texto no confiable
---`; si contenia esa linea, "salia" de su zona. **Por que importa.** La
separacion de metadata verificada e intencion no confiable tenia dos fugas, y la
(b) ensena que toda defensa estructural se rompe si el contenido puede
falsificar la estructura.

**Arreglo.** Alfabetos cerrados (`recurso` sin espacios, comillas ni saltos de
linea; `region` con forma de region AWS) y `json.dumps` (un salto real pasa a
ser el literal `\n`). **Principio.** P6.

### 3.5 La identidad verificaba el nombre, nunca el ARN completo (D)

**Sintoma.** Del ARN declarado se extraia el nombre, se llamaba a `GetUser` y,
si respondia, se marcaba "verificado". La llamada va contra *nuestra* cuenta, asi
que la cuenta declarada no se contrastaba con nada: un ARN de la cuenta
`999999999999` con un nombre que existia en la nuestra pasaba, y la mentira
reventaba despues en el simulador, con tokens de Bedrock ya gastados. Efecto
lateral: un usuario con *path* (`user/finanzas/ana`) se rechazaba, porque
`GetUser` espera `ana`. Falso positivo.

**Arreglo.** El nombre es el ultimo segmento tras `/`, y el ARN que devuelve la
API se compara **entero**; si difiere en lo que sea, no se verifica y el motivo
da el ARN canonico. Desde ahi todo el sistema usa el ARN devuelto por IAM.

**El dividendo.** Eso reforzo solo el chequeo de 3.1 y el calculo de
redundancia, sin tocar esas lineas: cuando el dato correcto fluye desde el
origen, las defensas aguas abajo mejoran solas. El mismo patron un nivel mas
abajo: entre aprobar y aplicar, alguien puede borrar al usuario y crear otro con
el mismo nombre (mismo ARN, otra persona); ahi solo el id unico de IAM cierra la
ventana (5.3). **Principio.** P8, P3.

### 3.13 La huella que no verificaba (D)

**Sintoma.** La aprobacion calcula un hash del registro para que el aplicador
compruebe que nada cambio. **Nunca verificaba**: el codigo la calculaba y
despues cambiaba el estado a `aprobada`; como el estado entraba en el hash, la
firma quedaba hecha sobre `propuesta` y guardada junto a `aprobada`. El
aplicador habria rechazado el 100 % de los aprobados. **Por que no lo cogieron
los tests.** Habia tests de la huella y pasaban: el bug estaba en el **orden de
quien la llamaba**.

**Arreglo.** No reordenar lineas: el estado no debe entrar en la firma, porque
es justo lo que el flujo cambia por diseno (`propuesta`, `aprobada`,
`aplicada`). Mas un test del flujo completo. **Principio.** P12 y una regla
propia: **no firmes lo que va a cambiar por diseno**; la firma cubre el
contenido, no la posicion en el flujo.

### 3.14 El permiso que el catalogo no menciona (D)

**Sintoma.** La primera ejecucion real del aplicador murio con `AccessDenied ...
iam:TagPolicy`, pese a tener `iam:CreatePolicy` concedido (30-08-2026, cuenta;
`docs/MEDICIONES.md` §B.5). **Por que importa.** El catalogo lista
`aws:RequestTag` como clave de `CreatePolicy`, lo que sugiere que etiquetar al
crear va incluido. No va: es el patron *tag-on-create*, que exige ademas el
permiso de etiquetado y aparece en muchos servicios.

**Arreglo.** `iam:TagPolicy` acotado como la creacion (nuestro path, nuestra
etiqueta) **y un Deny de `iam:UntagPolicy`**: un aplicador que puede borrar su
propia trazabilidad convierte la compuerta en decorado. La baranda funciono:
fallo *antes* de crear nada, sin politicas huerfanas. **Principio.** P12.

### 3.15 El campo que resume esconde el que informa (D)

**Sintoma.** Verificando la aplicacion real, el simulador respondia que el
usuario **no** podia leer el bucket, segundos despues de haber respondido que
si. **Causa.** La forma de preguntar: con varios `ResourceArns`, el
`EvalDecision` de nivel superior es el **agregado pesimista** (deniega si
deniega para alguno) y la verdad por recurso esta en `ResourceSpecificResults`.
Con el ARN de objeto solo da `allowed`, con el del bucket solo `implicitDeny`, y
con los dos `implicitDeny` y el objeto `allowed` por dentro (30-08-2026,
simulador; `docs/MEDICIONES.md` §A.4).

**Por que importa.** En S3, `ListBucket` aplica al ARN del bucket y `GetObject`
al del objeto, y el modelo los funde en un statement: leyendo el nivel superior,
una politica correcta salia como "no concede nada" y se mandaba al agente a
arreglar lo que no estaba roto (P3). En `eficacia` no mordia; en `redundancia`
si. Aun asi el codigo hacia lo contrario de lo que prometia su comentario, y eso
es tan grave como un bug. **Arreglo.** Leer `ResourceSpecificResults`: la accion
es efectiva si sale `allowed` para al menos un recurso. **Principio.** P12 y la
leccion de la seccion 4.

### 3.17 El permission boundary estaba planeado en el sitio equivocado (D)

**Sintoma.** El plan original era "rol del aplicador **con** permission
boundary". Un boundary sobre el aplicador limita **lo que el aplicador puede
hacer**, no **lo que puede conceder a un tercero**: con `AttachUserPolicy`, un
aplicador perfectamente acotado puede adjuntar `AdministratorAccess` a otra
persona, y eso no es una accion suya, es una concesion.

**Arreglo.** El techo va en los **principals destino**, y dos claves de
condicion cierran el hueco: `iam:PolicyARN` (solo politicas de nuestro path) e
`iam:PermissionsBoundary` (solo principals que lleven el techo), mas los Deny
que impiden al aplicador quitar o reescribir ese techo, sin los cuales la
segunda condicion no valdria nada. **Principio.** P9 con un giro: no basta
preguntar que responde la capa, sino **sobre que sujeto**. Que el techo
*recorte* algo es otra pregunta (P16, seccion 16).

---

## 4. El hallazgo empirico: como se comporta el simulador de IAM

Ejemplo de P10. Las tablas completas estan en `docs/MEDICIONES.md` §A (28 a
30-08-2026, simulador); aqui, los hallazgos y lo que cambiaron en el codigo.

**1. Condiciones sin clave aportada (28-08-2026, cinco pruebas).** La
documentacion no dice que hace `SimulateCustomPolicy` con una condicion cuya
clave no se aporto. Sobre `aws:RequestedRegion = us-east-1`, simulando desde un
endpoint en us-east-1: sin contexto, `allowed` y nada reportado; con `us-east-1`,
`allowed` (control); con `eu-west-1`, `implicitDeny` (caso negativo). Las
condiciones **si se evaluan**.

La prueba 1 sola admite una lectura falsa ("el simulador no reporta las claves
que le faltan"). Las pruebas 4 y 5 (`aws:RequestedRegion = eu-west-1` y
`aws:PrincipalTag/equipo = finanzas`, sin contexto) dan `implicitDeny` **y la
clave reportada**. Lo que encaja con las cinco: **el simulador tiene un valor
implicito para `aws:RequestedRegion`, la region del endpoint contra el que
simulas**, y da por satisfecha en silencio una condicion que coincide. Es
peligroso justo aqui: el permiso *parece* verificado y solo se comprobo la region
de *nuestra* llamada, no la del solicitante.

**Consecuencias en el codigo.** (1) `aws:RequestedRegion` se aporta desde el
formulario. (2) La deteccion de condiciones sin evaluar la hace nuestro codigo,
leyendo los `Condition` del documento y restando las claves aportadas; lo que
reporte el simulador es complemento (los `...IfExists` no cuentan como duda). (3)
Un `implicitDeny` con claves sin resolver significa "no se pudo evaluar", no "no
concede nada" (P3). Detalle de la API: con una lista de recursos, las claves
faltantes aparecen dentro de `ResourceSpecificResults`; leer solo el campo de
arriba habria dado "no falta nada" siempre.

**2. `MissingContextValues` (29-08-2026).** Lista las claves de los statements
que el simulador *considero*, no las que *determinaron* el resultado (3.11). Como
a una clave sin valor el simulador deniega, un `allowed` es concluyente por
construccion.

**3. Caducar un permiso (30-08-2026).** Una politica puede expirar sola con
`aws:CurrentTime`, sin un revocador que necesitaria `Detach` y `Delete` (el poder
destructivo que el aplicador no tiene). Cuatro pruebas con el par futuro/pasado:
`aws:CurrentTime` **no tiene valor implicito** (sin contexto deniega y avisa) y,
aportada, la condicion se evalua de verdad. Avisos: el vencimiento lo calcula
nuestro codigo (si lo escribe el modelo, escribe 2099) y caducar quita el acceso
pero no el hueco (10 politicas por usuario). Sin implementar.

**4. El agregado pesimista (30-08-2026)**: el caso 3.15.

**La leccion de los tres: el campo que resume no es el campo que informa.** Un
campo agregado incorpora una decision de diseno que no es la tuya (que significa
"el resultado" cuando hay varios); si una garantia se apoya en un resumen,
apoyala en el detalle. **Limites del simulador:** no evalua SCP, no es una
llamada real y no reconoce los ARN de flujos de logs en grupos con `/` (§A.5).

---

## 5. Decisiones de arquitectura de nivel superior

### 5.1 Donde vive el estado

El registro de cada solicitud cumple dos funciones que conviene separar:

| Funcion | Que necesita | Donde va |
|---|---|---|
| **Estado operativo** (la cola) | Consulta por estado, escrituras condicionales, disparar al aplicador | **DynamoDB**: indice por estado, `ConditionExpression`, Streams |
| **Evidencia inmutable** (que se propuso y por que) | Que nadie reescriba la historia | **S3** con versionado y Object Lock en modo compliance (diseno, no construido) |

El almacen escribe en disco o en DynamoDB (probado con dobles; la tabla no
existe todavia en la cuenta, 24-10-2026, `docs/MEDICIONES.md` §F.4). S3 *si*
tiene escrituras condicionales (`If-None-Match`, `If-Match`): DynamoDB gana como
cola por las consultas por atributo y los streams. Las trazas de error van a
CloudWatch Logs y CloudTrail registra por su cuenta las llamadas reales: el
registro del sistema es el rastro de **la decision**, CloudTrail el de **la
accion**, y juntos son la auditoria.

### 5.2 La aprobacion humana

Aprobar convierte una propuesta en un compromiso, y concentra controles.

1. **Lectura unica.** El registro se lee una vez; de ese objeto salen lo que se
   pinta y lo que se firma (leer dos veces es un TOCTOU dentro del comando).
2. **La identidad se resuelve, no se declara** (`sts:GetCallerIdentity`). El ARN
   de un rol asumido (`arn:aws:sts::123:assumed-role/Aprobadores/sesion-1`) no es
   comparable con un ARN de IAM: un `==` falla en silencio. Se parsea el nombre
   del rol como hipotesis, se pregunta a IAM y se comprueba que el `RoleId` sea
   el prefijo del `UserId` de la sesion (P8).
3. **La duda bloquea, y bloquear es visible.** Verificado y distinto pasa;
   verificado e igual bloquea; no verificable bloquea (P4).
4. **Revalidacion con las reglas de hoy.** Nadie aprueba a ciegas lo que las
   barandas actuales rechazan.
5. **La compuerta de pago.** `CheckNoNewAccess` cobra por invocacion: una llamada
   al aprobar, con el coste acotado por actos humanos y no por vueltas del
   bucle. La herramienta gratuita para iterar, la costosa como compuerta final.
6. **La huella.** SHA-256 del registro serializado de forma determinista.
   Responde *es esto lo que se aprobo?*, no *sigue siendo aceptable?*, que es la
   revalidacion: hacen falta las dos. El aprobador ve la propuesta y su huella y
   aprueba **esa** huella (3.21); cubre el registro menos los bloques posteriores
   y el estado (3.13). **Limite:** la huella no tiene secreto, asi que detecta
   deriva y accidente, no a quien pueda escribir el atributo `aprobacion` y
   recalcularla. Lo que impide el desastre es el rol del aplicador y el techo
   del destino. Mitigacion de fondo: la aprobacion en servidor (ADR-003,
   desplegada el 25-10-2026; seccion 21).

### 5.3 El aplicador

La pieza con escritura en IAM, y por eso la que menos hace. **No habla con el
modelo**, y eso es un **Deny explicito de `bedrock:*`** en su rol: el invariante
puesto donde IAM lo impone, aunque alguien escriba el import por error.

**Idempotencia sin marcador** (P15): nombre determinista mas verificacion de
contenido y procedencia; el mismo codigo observa AWS y decide entre crear,
adjuntar o parar.

**Trazabilidad.** La `Description` es inmutable (no existe `UpdatePolicy`),
lleva el id y la huella y es la unica evidencia que **sobrevive a que alguien
reescriba el registro local**. Los tags son mutables y su valor es otro: la
**compuerta** (`aws:RequestTag` impide crear sin etiquetar).

**Sin `iam:DeletePolicy`.** Si la corrida muere entre crear y adjuntar queda una
politica sin adjuntar, y esa **no concede nada**: no se da poder destructivo por
un fallo inerte. Pregunta previa a un permiso "por si acaso": *que dano hace el
estado que este permiso vendria a limpiar?*

**Reintento selectivo.** Backoff solo para lo que mejora esperando
(`NoSuchEntity` por consistencia eventual, `ConcurrentModification`), nunca para
`AccessDenied` ni `LimitExceeded`. **Misma entidad:** que el beneficiario siga
siendo el mismo solo lo cierra el id unico de IAM (3.5).

### 5.4 Coste como criterio de diseno

Los chequeos deterministas van **antes** del modelo (un servicio no permitido se
rechaza con cero llamadas al LLM). Dar al modelo por adelantado las reglas que el
codigo va a exigir no es la defensa pero reduce vueltas: un caso real paso de 3
intentos y escalada a humano a 1 intento. La unica llamada de pago esta en la
aprobacion (5.2).

**Un caso donde el coste dice que NO midas.** El modelo se salta una regla del
prompt unas 3 de cada 4 veces; cambiar la redaccion era una optimizacion, no un
control (el codigo atrapo el fallo 3 de 3 veces). Con ese 75 %, tres aciertos
seguidos salen por azar el 1,6 % de las veces, sobre cuatro observaciones;
concluir con rigor pedia 15 a 20 corridas, mas de lo que ahorra el cambio.
**El rigor de una medicion debe ser proporcional a lo que se rompe si te
equivocas:** en un control de seguridad, mide hasta estar seguro; en una
optimizacion, mide barato y etiqueta el resultado como evidencia debil.

---

## 6. Diez preguntas de entrevista

**1. Por que separar el agente del aplicador no es "una capa mas"?** Hace
opcionales a las demas, y lo impone IAM (Deny de `bedrock:*` en el aplicador). P5,
5.3.

**2. Un campo admite un nombre de bucket y no hay lista cerrada. Que haces?**
Cerrar su alfabeto y aislar lo libre; es mitigacion, la garantia es P5. P6, 3.2.

**3. Una herramienta dice "no pude evaluar": bloqueas o permites?** Depende de que
se rompe: en `eficacia` la duda no bloquea, en `redundancia` no permite concluir
que ya tenia el acceso. P4, 3.11.

**4. Que fallo no vieron 505 tests ni 16 mutaciones?** Un `documento` con su
propia `aprobacion` llegaba al aplicador como aprobacion humana: probaban lo que
el codigo escribe, no lo que otro actor podria escribir. Lo encontro una revision
independiente. Seccion 18, P12.

**5. Por que un boundary que permite lo mismo que concedes no recorta nada?** La
interseccion devuelve la propuesta entera; solo recorta su Deny. P16, seccion 16.

**6. Un Deny con `ArnNotLike` sobre una clave que la llamada no trae: deniega o
pasa?** Deniega, tambien con `IfExists`; la trampa es anadir `Null: false` "por
seguridad". Seccion 14.
El 24-10-2026 se volvio a escribir lo contrario en la S5 ("una llamada sin la clave
pasa"), un dia despues de dejarlo en MEDICIONES §H, fila 11. Leccion: antes de afirmar
como evalua IAM una condicion, mirar §H y la guia; y si el simulador y la guia no
coinciden, medir con llamadas reales (MEDICIONES E.7, fila 30 de §H). El `allowed` del
simulador se debia a que rellena `aws:ResourceAccount` con la cuenta de quien llama
(MEDICIONES E.8): igual que con `aws:RequestedRegion`, el simulador aporta valores que
nadie le dio.

**7. Si el token autentica a la persona, por que CloudTrail no dice quien hizo la
llamada?** El contenedor actua con un solo rol; quien entro y quien hizo esto son
preguntas distintas, y la segunda la responde el codigo. Seccion 15.

**8. Por que IAM no separa a quien aprueba de quien propone con `PutItem`?**
`PutItem` reemplaza la fila y `dynamodb:Attributes` no limita esa operacion; con
un atributo por actor y `UpdateItem`, si. Seccion 17.

**9. Por que no te fias del campo resumen de una API?** Incorpora una decision de
diseno que no es la tuya (`EvalDecision` es el agregado pesimista). 3.15,
seccion 4.

**10. Como disenas un proceso que escribe en un sistema externo para poder
reintentar?** Nombre determinista del id de la operacion y verificacion de
contenido y procedencia, no anotar la intencion. P15, 3.16, 5.3.

---

## 7. (retirada)

## 8. Si tuviera que quedarme con cinco frases

1. **Separa quien interpreta de quien ejecuta.** Convierte las demas capas en
   opcionales en vez de criticas.
2. **La direccion segura de la duda depende de que se rompe si te equivocas**, y
   no siempre es la misma dentro del mismo sistema.
3. **Un falso positivo cuesta tanto como un falso negativo**, porque ensena a
   saltarse la validacion.
4. **El dato canonico viene de la fuente**, no de tu parseo; si hay una
   autoridad sobre un hecho, se le pregunta en vez de llevar una copia.
5. **Lo que no se ha ejecutado, no funciona.** Los fallos mas graves estaban en
   codigo revisado y con los tests en verde.

## 9. (retirada: P16 esta en la seccion 2 y los casos 3.18 a 3.21, en el catalogo)

---

## 10. Tres tipos de tests (Fase 11, 20-10-2026)

**"Automatico" no es un tipo de test.** Los tres se lanzan solos; los separa lo
que necesitan y lo que preguntan. Unitarios: sin nada, si cada pieza hace lo que
dice. Seguridad: sin nada, si se puede saltar un control. Funcionales: la cuenta,
si el sistema funciona de verdad. Los dos primeros corren en cada commit; el
tercero, solo si alguien lo pide.

**Un test que recorre una lista pasa en vacio.**
`test_cada_fichero_de_tests_aparece_en_el_contexto` comprobaba que ningun
fichero faltara en CONTEXTO; al mover los tests a carpetas su `glob` dejo de
encontrar ficheros y el test siguio en verde (sin ficheros, no falta ninguno;
`docs/MEDICIONES.md` §H, fila 24). Un test "para todo x, se cumple P" tiene que
afirmar tambien que hay algun x.

**Una puerta con dos capas tiene que decir cual salto.** Los funcionales se
paran al recogerlos (`tests/conftest.py`) y en la fixture. Si la primera se
rompe, la segunda sigue parandolos y nada se pone rojo: la defensa en
profundidad tapa su propio fallo. La segunda capa firma su motivo y un test
exige que esa firma no aparezca. Una capa redundante solo cuenta si su fallo se
puede ver.

**Lo que se dice de los tests tambien se mide.** "Ningun test necesita red"
estaba en README y CONTEXTO y uno llamaba a STS con las credenciales del equipo;
salio al contar los saltos: 0, cuando sin credenciales tendria que haber uno
(§H, fila 8).

## 11. El analisis estatico encontro lo que el diseno daba por cerrado (Fase 12, 22-10-2026)

Todo el diseno parte de que el modelo no es de fiar, pero las *tools* que el
modelo llama se trataban como codigo propio y sus argumentos como datos limpios.
`consultar_acciones` recibe acciones como `s3:GetObject`; lo que va antes de `:`
acababa en una ruta de disco y en una URL: con `../secreto:Get`, el catalogo leia
un `.json` de fuera de su carpeta y lo daba por oficial. Lo encontro bandit al
entrar en la bateria, con un aviso generico (B310) que apuntaba a la URL; la ruta
salio al leer la linea de arriba. Sin el arreglo, 10 de los 14 tests de
`test_catalogo.py` se ponen en rojo (22-10-2026, tests; `docs/MEDICIONES.md` §I).

**Por que importa.** El catalogo es la fuente de verdad del nivel de acceso: si
el modelo eligiera de que fichero se lee, podria hacer pasar una gestion de
permisos por lectura, y las barandas posteriores usan el mismo catalogo.
**Principio.** Los argumentos de una tool son entrada del modelo, y la entrada
del modelo es entrada del usuario: se validan en la tool con una forma cerrada
(`[a-z0-9]+(-[a-z0-9]+)*`), no con una lista de caracteres prohibidos. Un aviso
de SAST no es un veredicto: se valida la entrada y solo entonces se marca `#
nosec B310` con el motivo; silenciar sin arreglar quita el aviso y deja el fallo.

## 12. La auditoria que revisaba otras versiones (Fase 13, 22-10-2026)

pip-audit respondia "No known vulnerabilities found" en local y en el CI, y era
verdad, pero sobre otros paquetes: con `-r requirements.txt` resolvia su propia
instalacion con la ultima version de cada transitiva. El `.venv` donde corrian
los tests tenia pyjwt 2.13.0 (unos quince avisos, varios de verificacion de
tokens) y cuatro paquetes mas afectados (22-10-2026; `docs/MEDICIONES.md` §I y
§H, fila 9). Salio al fijar las transitivas en `constraints.txt` y auditar
exactamente esa lista.

**Principio.** Un control solo vale para lo que de verdad mira: antes de fiarte
de un verde, pregunta sobre que objeto se calculo. Fijar versiones no es solo
reproducibilidad, es lo que hace que la auditoria hable de tu sistema.

## 13. Lo que funcionaba en la cuenta de gestion no prueba nada en la miembro (Fase 15, 22-10-2026)

El agente llevaba semanas llamando a Haiku 4.5 con el perfil `global.` desde la
cuenta de gestion, sin un error. Desde la cuenta miembro `agente-iam`, con el
administrador de Identity Center, la misma llamada dio:

```
not authorized to perform: bedrock:InvokeModel on resource:
arn:aws:bedrock:::foundation-model/anthropic.claude-haiku-4-5-...
with an explicit deny in a service control policy
```

Con el perfil `us.`, lo mismo sobre el ARN de `us-east-2`. Las dos las niega
`GRREGIONDENY`, la denegacion de regiones de Control Tower, que solo permite
`us-east-1` (`docs/MEDICIONES.md` §C.1).

**Por que no fallaba antes.** Las SCP no se aplican a la cuenta de gestion: todo
lo medido alli (permisos, modelos, cuotas) se midio sin el techo de la
organizacion (§H, fila 21). Y ni un administrador se libra, porque una SCP no
concede, solo recorta, y su Deny gana sobre cualquier Allow. **Dos ARN:** con un
perfil de inferencia, Bedrock comprueba tambien el modelo en cada region a la que
puede enrutar (con `us.`, `us-east-1`, `us-east-2` y `us-west-2`; con `global.`,
un ARN sin region que la condicion ve como `aws:RequestedRegion = unspecified`);
basta que una caiga en el Deny. Haiku 4.5 solo se invoca por perfil.
**Principio.** Una prueba vale para el entorno en que se hizo: mover el sistema
de cuenta es cambiar las leyes que le aplican, y se mide alli.

## 14. Lo que parece reforzar una SCP puede abrirla (Fase 15, 23-10-2026)

Para que Bedrock salga de `us-east-1` solo por perfiles `us.`, la SCP del
proyecto deniega la invocacion cuando se cumplen a la vez dos cosas: la region
no es `us-east-1` y `bedrock:InferenceProfileArn` no es un perfil `us.` de
Claude. Esa clave solo viene cuando Bedrock evalua el modelo de destino de un
perfil; en una llamada directa no viene. Un operador negado (`ArnNotLike`) sobre
una clave ausente da verdadero, asi que la llamada directa fuera de `us-east-1`
se deniega: es lo que se quiere, y es contraintuitivo (una condicion "sobre
perfiles" afecta a la llamada que no lleva perfil). Con `...IfExists` una clave
ausente tambien da verdadero y un Deny con operador negado sigue denegando
(guia de IAM; §H, fila 11).

**La trampa de verdad** es anadir "por seguridad" `Null:
{"bedrock:InferenceProfileArn": "false"}`, "solo si la clave existe": la llamada
directa, que no la trae, deja de casar con el Deny y pasa.
`test_un_null_false_abriria_la_llamada_directa` lo demuestra con el evaluador
del test.

**Principio.** En un Deny, pregunta que pasa cuando la clave no viene: es lo que
hara quien quiera saltarselo. Comprueba la respuesta en la guia, no de memoria.
Como el simulador no evalua SCP, la respuesta se escribe en un test y se
confirma con llamadas reales (matriz de 12 casos, 23-10-2026, con el
administrador; con los roles reales del agente, sin medir; `docs/MEDICIONES.md`
§C.3). **Capas:** el control de Control Tower exime la accion en todas las
regiones, la SCP propia la vuelve a cerrar salvo por el camino permitido, y los
roles, sin el perfil `global.`, son la tercera por si alguien afloja la SCP.
Ninguna basta sola.

## 15. Autenticar a la persona no es atribuirle lo que hace el rol (Fase 15, 23-10-2026)

La Prueba B demostro que el autorizador JWT de AgentCore funciona: sin token,
401; con la firma alterada, 401; con un token valido de Mateo o del aprobador,
200 y los claims de cada uno dentro del contenedor (`docs/MEDICIONES.md` §D.2).
Pero lo que el contenedor hace en AWS lo hace con **un solo rol**, y CloudTrail
lo ve asi: una sesion `BedrockAgentCore-<uuid>` y sin `sourceIdentity`, igual
para los dos usuarios. La persona solo aparece en el evento de datos
`InvokeAgentRuntime`, como `sub`, y solo si alguien monto un trail de eventos de
datos; nada lo une a las llamadas del rol salvo la hora. Son dos preguntas:

- **Quien entro.** La responde el autorizador, con criptografia.
- **Quien hizo esto en AWS.** CloudTrail responde "el rol". Si hace falta "a
  peticion de quien", lo responde el codigo, grabando los claims ya validados en
  su propio registro.

**Por que importa.** Si la separacion de funciones comparara roles, todos son el
mismo y la regla no compararia nada: hay que comparar personas. Por `sub` no es
posible, porque el aprobador entra por SSO y no tiene `sub`; lo previsto es
comparar la persona (el nombre de sesion o el `NameID` de Identity Center, sin
medir si coincide exactamente) y grabar el `sub` para unir el registro con el
evento de datos (ADR-001; §H, fila 13).

**Limitacion vigente.** Hoy `aprobar` (`_separacion`, `identificar_aprobador`)
compara el `arn_canonico` del aprobador con el del beneficiario, y para una
sesion SSO el `arn_canonico` es el ARN del rol (`iam:GetRole`), sin el nombre de
sesion; la persona solo esta en `arn_llamante`. Dos personas con el mismo
permission set no se distinguen. Leido en el codigo el 24-10-2026, sin medir con
dos personas (`docs/ESPECIFICACION-agentcore.md` §4; `docs/MEDICIONES.md` §J).

**El mismo error en pequeno:** el primer token "del aprobador" era de Mateo,
porque el navegador reutilizo su sesion (fila 12). La identidad es lo que viene
firmado, no la etiqueta que pone el programa; desde entonces
`scripts/prueba_b.py` compara el `sub` antes de guardar.

**Principio.** Autenticar en la puerta no deja la identidad pegada a todo lo que
pasa despues. En cada salto (token, contenedor, rol, CloudTrail) pregunta que
identidad sobrevive y donde queda escrita, y mide la respuesta: la ausencia de
`sourceIdentity` y que la llamada sin token no deje evento se supieron mirando
los eventos.

## 16. Leer no es inofensivo, y un techo que permite lo mismo no recorta nada (Fase 15, 23-10-2026)

Al escribir el techo v2 (ADR-002) salieron tres lecciones.

**(a) En EC2, leer no es inofensivo.** El nivel de acceso del catalogo dice que
*tipo de operacion* es una accion, no que *devuelve*. Diez `ec2:Describe*` son de
nivel `List` y devuelven user data (a menudo contrasenas o tokens), claves de VPN,
un secreto OIDC o URL prefirmadas de S3, y `lectura` admite 52 acciones Read de
EC2, como `GetPasswordData`. Por eso EC2 se concede solo como inventario
(`Describe*`), con esas diez prohibidas (`docs/MEDICIONES.md` §E.2; §H, fila 16).

**(b) Medir por nombre de campo se quedo corto.** La busqueda por nombre dio 5; la
completa dio 10: campo `UserData` o forma marcada como sensible en el modelo de
servicio de botocore, medido contra botocore 1.43.82. Dos Describe del catalogo
no tienen operacion alli: para esas dos solo hay un supuesto, no una medicion. Si
la fuente trae la marca, se usa; no se reconstruye adivinando nombres. Y se dice
contra que version se midio.

**(c) Un boundary que permite lo mismo que el codigo no recorta nada (P16).** El
v2 refleja las reglas del codigo en IAM (EC2 solo `Describe*`, ninguna gestion
de permisos, nada sobre los recursos del propio sistema) y se **genera desde la
misma fuente** (`config.py` y la referencia de autorizacion) con
`scripts/generar_techo.py`: escribirlo a mano era escribir la misma regla dos
veces y esperar que coincidan.

**Estado (18-11-2026).** El v3, con los Deny S3 y S5 (seccion 18), esta
desplegado en la cuenta `agente-iam` desde el 24-10-2026 (`docs/MEDICIONES.md`
§E.8). Lo llevan como boundary `app-finanzas-demo` (25-10-2026) y cada rol por
persona (Fase 23). El 30 de 30 del simulador (§E.3 y §E.4) se midio contra el v2.

## 17. Un `PutItem` reemplaza la fila, y por eso IAM no puede separar a quien aprueba de quien propone (Fase 15, 24-10-2026)

El permission set del aprobador estaba bien escrito y el codigo no encajaba con
el. Arreglarlo dejo una leccion de modelado para cualquier tabla con mas de un
actor.

**El problema.** La tabla guardaba cada solicitud como una fila con un unico
atributo `documento` y toda escritura era `PutItem`, que **reemplaza la fila
entera**; la condicion `dynamodb:Attributes` no limita a `PutItem` (guia de
DynamoDB sobre control de acceso detallado; Access Analyzer lo senala con
`DYNAMODB_REPLACE_OPERATION_WITH_ATTRIBUTES`). Quien podia escribir la
aprobacion podia, con la misma llamada, reescribir la propuesta aprobada. IAM no
podia distinguirlo: la separacion de funciones se sostenia solo en el codigo de
`aprobar`.

**La solucion.** Cada actor tiene **atributos propios** y escribe solo con
`UpdateItem`: `documento` el intake, `aprobacion` y `rechazo` el aprobador,
`aplicacion` el aplicador, y `estado` compartido. Cada rol lleva
`dynamodb:Attributes` con los suyos. El rechazo es su propio bloque: uno llamado
"aprobacion" que dice que no es una trampa para quien lo lea. **Principio.** Si
quieres que IAM separe a dos actores, no pueden compartir el atributo ni la
operacion: "un documento por fila" es comodo y deja el control de acceso en
manos del codigo.

**Dos matices.** (1) Las condiciones solo nombran atributos propios: la
documentacion no aclara si `dynamodb:Attributes` cuenta tambien los de la
`ConditionExpression`, asi que se diseno para que la respuesta no importe. Cuando
no puedes medir, elige el diseno cuyo resultado no depende de la respuesta. (2) IAM limita *que atributos* toca un
rol, no "solo si el bloque no existe"; eso lo pone la condicion de cada
escritura. `estado` lo comparten los tres: un valor falso no aplica nada (el
aplicador exige `aprobacion` con huella) pero puede bloquear una solicitud. Un
control que parece mas fuerte de lo que es es el peor modo de fallo.

**Medido y no medido (24-10-2026).** Medido: el codigo escribe solo esos
atributos con parametros exactos y lo que nombra el aprobador cabe en el
permission set desplegado (`Stubber` de botocore: 505 pasados y 3 saltados, 16
mutaciones en rojo; simulador, 22 de 22, 23-10-2026). Esos 505 tests y 16
mutaciones no encontraron el fallo de la seccion 18.

**Medido despues (24-10-2026, llamadas reales con el permission set del
aprobador, `docs/MEDICIONES.md` §F.6).** `dynamodb:Attributes` frena un
`UpdateItem` sobre un atributo fuera de la lista y cuenta tambien los atributos
que solo aparecen en la `ConditionExpression`. Las condiciones de `almacen` se
habian escrito para que no importara, y si importaba: disenar para la duda que la
guia deja abierta evito un `AccessDenied` en la primera aprobacion real.

## 18. La revision independiente del 24-10-2026 (Fase 17)

Una revision de solo lectura sobre el commit `10ff080` encontro 13 hallazgos
(seguridad S1 a S10, optimizacion O1 a O3), aplicados en `7968aac` (paso 1) y
`8cb3c42` (paso 2); cada arreglo lleva un test que se pone en rojo si se
deshace. El informe de la revision esta fuera de git.

**S1, el hallazgo que importa.** La lectura de DynamoDB recomponia el registro
desde `documento` y solo sobrescribia un bloque si su atributo existia. Un
`documento` con su propia `aprobacion` (con una huella calculada por el runtime)
llegaba al aplicador como aprobacion humana; con otro `id`, la decision se
escribia en otra fila. Era un error de diseno, y las afirmaciones "el runtime no
toca decisiones" y "nada se aplica sin aprobacion" eran falsas
(`docs/MEDICIONES.md` §H, fila 25).

**Por que no lo vieron 505 tests ni 16 mutaciones.** Comprobaban que el codigo
escribe los atributos que debe y solo esos. Ninguno fabricaba lo que *otro actor*
podria escribir (un `documento` hostil) y miraba que la lectura lo rechazara. Una
mutacion demuestra que el test notaria deshacer una linea, no que las lineas
sean las que hacen falta. Lo encontro quien no habia escrito el codigo: la regla
"cada arreglo lleva un test que se pone en rojo si se deshace" es necesaria y no
basta.

**Arreglo.** `_dynamo_leer` lanza `RegistroInconsistente` si `documento` trae
`estado`, un bloque o un `id` distinto de la clave; los bloques solo salen de sus
atributos; la decision se escribe en el id leido. **Cerrado el 25-10-2026
(ADR-003):** la aprobacion la escribe la Lambda `agente-iam-aprobacion` y el
aprobador ya no escribe el atributo `aprobacion` (Deny explicito en su
permission set, `docs/MEDICIONES.md` M4). La huella sigue sin secreto: queda
quien pueda escribir el atributo por otro camino, que es el administrador de
la cuenta (CONTEXTO §10) y, sin confirmar, el operador (pista 1 de la Fase 33).

**Otros hallazgos con leccion.**

- **S2:** el chequeo de recurso de 3.18 seguia laxo (el nombre valia en
  cualquier componente del ARN). Ahora debe estar en su posicion por servicio.
- **S3 y S5:** `Resource: "*"` con cualquier `Condition` dejaba pasar escrituras
  de alcance de cuenta, y el ARN de S3 no lleva cuenta, asi que un bucket ajeno
  pasaba. Ahora `"*"` solo admite List y Read y toda propuesta de S3 lleva la
  condicion de cuenta. El techo del repositorio gana dos Deny: **sin
  desplegar**, con una medicion pendiente de Mateo (que las llamadas lleven
  `aws:ResourceAccount`; `docs/MEDICIONES.md` §E.5 y §J).
- **S4:** el aplicador solo miraba la huella. Ahora exige separacion de
  funciones, techo en PASS y riesgo confirmado, y repite `CheckNoNewAccess`. Un
  control que vive solo en `aprobar` no protege si algo escribe sin pasar por
  `aprobar`.
- **O1:** el paso de gitleaks del CI no escaneaba nada (`protect --staged` en un
  checkout limpio): un control en verde que no mira, como en la seccion 12.

**Metodo (24-10-2026).** Seguridad: 59 mutaciones, 59 en rojo; en la primera
pasada quedaron dos vivas, que dieron dos tests nuevos. La propia revision se
equivoco dos veces en optimizacion (`sympy` y `mpmath` no sobraban, los exige
`cfn-lint`; eran cinco los tests que usaban el catalogo real, no uno; §H,
fila 26): tambien las conclusiones de una revision se miden. Tests hoy: 656
pasados y 3 saltados (24-10-2026).

**Principio.** Los tests de quien escribe el codigo comparten su modelo del
problema. Para un invariante ("nada se aplica sin aprobacion humana") hay que
probar la **entrada hostil en la frontera donde se lee**, no solo la salida de
quien escribe, y pedir una revision a quien no escribio el codigo.

## 19. Estudio final de arquitectura (25-10-2026)

Peticion de Mateo del 23-10-2026: el mapa de todo lo que existe en la cuenta y, pieza por pieza, si la complejidad
compensa el riesgo que reduce. Escrito el 25-10-2026 con las tres pilas desplegadas y rehecho ese mismo dia (UTC)
despues de medir el circuito completo con `req-022` (`docs/MEDICIONES.md` L), el trail de datos y el camino de fallo
del aplicador con una fila provocada (`docs/MEDICIONES.md` M). Lo que dice "medido" se midio ese dia o antes; lo demas
es juicio de diseno. Lo unico de la tabla que sigue sin medir es que la separacion de funciones bloquee con la misma
persona a los dos lados (§J).

### 19.1 El mapa

```
CUENTA DE GESTION (Organization, Control Tower 4.0)
  Identity Center ............ usuarios: Mateo, aprobador.demo, solicitante.demo
                               grupos: solicitantes [Mateo, solicitante.demo], aprobadores [aprobador.demo],
                                       operadores [Mateo]   (pila agente-iam-identidades)
                               permission sets, solo en agente-iam: Operador (1 h), Lectura (4 h), Aprobador (1 h)
                               aplicacion SAML agente-iam-cognito -> grupo solicitantes (consola + pila)
  SCP (pila agente-iam-gobierno-regiones): region us-east-1 + PV.1 exime Bedrock; solo perfiles us. de Claude
  Trail de organizacion (Control Tower), clave KMS control-tower-logs; usuario IAM Mateo (admin de emergencia)

CUENTA agente-iam (OU Workloads)
  arranque (administrador) .. rol AgenteIAM-Despliegue (solo CloudFormation, 5 politicas desde esquemas)
                               AgenteIAM-LimiteSistema (boundary de los roles del sistema)
                               AgenteIAM-Techo v3 (boundary de los beneficiarios; 8 sentencias, 5575 caracteres)
  base (operador) ........... tabla agente-iam-solicitudes (PITR, Streams, un atributo por actor, solo UpdateItem)
                               bucket agente-iam-despliegue-<cuenta> (zips)
                               roles AgenteIAM-Runtime, AgenteIAM-Aplicador, AgenteIAM-Aprobacion (con LimiteSistema)
                               Lambda agente-iam-aprobacion + URL AWS_IAM (escribe aprobacion/rechazo)
  acceso (operador) ......... user pool agente-iam-acceso (sin usuarios propios) + dominio + proveedor SAML + cliente CLI
  runtime (operador) ........ AgentCore Runtime agente_iam_analista (JWT del cliente; rol Runtime)
                               Lambda agente-iam-aplicador <- stream de la tabla (estado = aprobada)
                               cola agente-iam-aplicador-fallos + alarma -> tema agente-iam-alarmas (correo)
                               trail agente-iam-datos (eventos de datos del runtime y de la aprobacion), bucket 90 d
  beneficiarios (admin) ..... rol app-finanzas-demo (boundary Techo, sin politicas), bucket finanzas-demo-<cuenta>

FLUJO   persona (Identity Center, MFA) -> SAML -> Cognito -> JWT -> runtime (lee IAM, Bedrock, escribe documento)
        -> aprobador.demo (permission set) -> URL AWS_IAM -> Lambda de aprobacion (controles, escribe aprobacion)
        -> stream -> Lambda del aplicador (releer, prevuelo, CreatePolicy + Attach bajo el Techo, escribe aplicacion)
```

### 19.2 Pieza por pieza

| Pieza | Riesgo que reduce | Lo que cuesta | Veredicto |
|---|---|---|---|
| Agente sin escritura en IAM; aplicador aparte (P5) | Una inyeccion de prompt no escala: quien interpreta texto no escribe | Dos procesos, dos roles, dos paquetes | Gana su sitio. Es el invariante del sistema |
| Tres capas de validacion + seis chequeos posteriores (P9) | Cada capa atrapo algo que las otras no (B.1, §3 de CONTEXTO) | Codigo y tests; cero coste en AWS | Gana su sitio |
| Techo v3 como boundary de los beneficiarios (P16) | Lo que el aplicador concede no sale del techo aunque el codigo falle; medido el 25-10-2026 que `CheckNoNewAccess` contra el techo rechaza una cuenta ajena y una propuesta sin condicion de cuenta | 5575 de 6144 caracteres; obliga a que las propuestas usen la misma forma (`aws:ResourceAccount = ${aws:PrincipalAccount}`) | Gana su sitio, con una servidumbre: Access Analyzer razona en simbolico y techo y propuesta tienen que hablar igual |
| Aprobacion en servidor (Lambda con URL `AWS_IAM`, ADR-003) | El aprobador no puede fabricar una aprobacion: solo el rol de la Lambda escribe el bloque, con Deny explicito en el permission set (M4); medido el 25-10-2026 que la Lambda escribe `aprobacion` con la persona del aprobador y `CheckNoNewAccess` en `PASS` (L.2) | Una Lambda, su rol, un cliente firmado, un zip propio | Gana su sitio. Era el hueco mas grave que quedaba (la huella no tiene secreto) |
| Separacion de funciones por persona (ADR-003 B2) | Autoaprobacion con dos cuentas del mismo permission set | Nombre de sesion + claim del JWT; `NFKC` + `casefold()` | Gana su sitio en cuanto hay dos personas; medido `cumplido` con la persona de Mateo pidiendo y `aprobador.demo` aprobando (L.2); el bloqueo con la misma persona sigue sin medir |
| Cognito federado con Identity Center + runtime solo JWT (ADR-001) | El endpoint no esta abierto ni depende de SigV4; la persona viaja en el token y queda en el registro (medido el 25-10-2026: `solicitante.persona` = nombre de usuario) | Un user pool, un dominio, una aplicacion SAML en consola, dos despliegues, un cliente PKCE | Gana su sitio. Es el unico camino medido para saber quien pidio (D.1, D.2) |
| Aplicador como Lambda disparada por el stream (7.1 a 7.7) | Ninguna persona asume el rol con escritura en IAM (riesgo 1); quita un paso manual | Mapeo de eventos, cola, alarma, un estado nuevo, un zip mas; dos rollbacks el 25-10-2026 para aprender dos cosas (K.1) | Vale, con una persona reduce poco riesgo real (dicho el 23-10-2026 y sigue siendo cierto); su valor es alinear privilegio con papel. Medido el 25-10-2026: aplica 5 s despues de la aprobacion (L.2) y, ante una fila ya decidida con el estado reescrito a `aprobada`, no toca IAM, lanza tres veces y deja el evento en la cola (M) |
| `AgenteIAM-LimiteSistema` como boundary de los roles del sistema | Un rol del sistema no escala aunque su politica cambie (35 de 35 en simulador) | Una politica mas; el rol de despliegue solo crea roles con ella | Gana su sitio: es lo que deja al operador desplegar sin ser administrador. Pista 1 de la Fase 33 (18-11-2026, sin confirmar): el limite es la union de lo que necesita cada rol y no lleva el reparto por atributos de la tabla, que solo vive en las politicas en linea |
| Rol de despliegue desde los esquemas de CloudFormation + permission set del operador | Quien despliega no aprueba ni toca la pila de arranque | Unas 300 acciones generadas; cada tipo de recurso nuevo exige revisarlas (ocurrio con `AWS::Lambda::Url`) | Gana su sitio, caro de mantener. Pista 1 de la Fase 33 (sin confirmar): por las plantillas, el rol de despliegue puede crear o modificar un rol `AgenteIAM-*` que escriba `aprobacion`; "quien despliega no aprueba" queda por demostrar o por arreglar |
| Tabla con un atributo por actor y solo `UpdateItem` (seccion 17) | IAM distingue aprobar de reescribir la propuesta (F.6) | Un almacen poco natural (cadenas JSON por atributo) | Gana su sitio |
| PITR y Streams en la tabla | Rastro de lo que un administrador reescriba; el stream dispara el aplicador | Coste por escritura, minimo | Gana su sitio (el stream es funcional, no solo rastro) |
| Trail propio de eventos de datos (D3) | Saber que persona invoco el runtime (el `sub`) y quien invoco la aprobacion | Un trail, un bucket, 0,000001 USD por evento | Medido el 25-10-2026 (M.1): `InvokeAgentRuntime` lleva `sub`, `jti`, emisor y caducidad del token, no el `username` ni el cuerpo; el `Invoke` por la URL lleva el rol de Identity Center del aprobador y su `userId`. Sigue siendo dudoso con una persona: el registro del agente guarda el mismo `sub`; lo que anade el trail es que ese rastro no lo escribe el propio sistema. Si se simplifica, es lo primero |
| Cola de fallos + alarma por correo | Un evento que falla no se pierde en silencio | Cola, tema, suscripcion, alarma | Vale: es la salida registrada que exige P14. Medido el 25-10-2026 (M.2): tres intentos en dos segundos, el evento en la cola con `RetryAttemptsExhausted`, la alarma en `ALARM` dos minutos y medio despues y una notificacion publicada; volver a tramitar es a mano (borrar el mensaje y la fila). Lo que no cubre ("aplicada sin registrar") solo esta en los logs |
| SCP de regiones y PV.1 con exencion de Bedrock | Nada fuera de `us-east-1` salvo la inferencia `us.` | Una pila en gestion; medido que la region de destino se evalua (C.1, K.2) | Gana su sitio; fue el origen de dos hallazgos sobre perfiles de inferencia |
| Permission set `AgenteIAM-Lectura` | Lecturas de auditoria y MCP sin datos | Uno mas que mantener | Prescindible si no se usa; hoy lo usan los MCP de lectura |
| Catalogo oficial dentro del zip y caducidad de 7 dias | El chequeo de nivel de acceso juzga con el catalogo del dia | Descarga en cada empaquetado | Gana su sitio (hallazgo 38 de CONTEXTO §9) |

### 19.3 Balance

Lo que de verdad sostiene el sistema son cuatro cosas: el agente no escribe en IAM; el techo limita lo que el
aplicador puede conceder; solo el servidor escribe la aprobacion; y la persona viene de Identity Center por un token
que AgentCore valida. Todo lo demas existe para que esas cuatro sigan siendo ciertas cuando cambie el codigo (el
boundary del sistema, el rol de despliegue, la tabla por atributos) o para dejar rastro (PITR, trail, cola).

Lo que es sobreingenieria para un sistema de una persona, y se sabe: el trail de datos propio y la separacion de
funciones son controles de dos personas; la Lambda del aplicador quita un paso manual mas que un riesgo. Se
mantienen porque el proyecto se defiende como diseno que escala, no como el minimo para una demo, y cada pieza tiene
una medicion detras que dice que hace lo que dice: desde el 25-10-2026 (UTC) tambien la aplicacion automatica, el
camino de fallo y el trail, que hasta ese dia eran las tres piezas de la tabla que se defendian por diseno.

Lo que no compensa y se ha pagado: tres rollbacks y seis horas el 25-10-2026 por cuatro supuestos no medidos (grupo
de logs del runtime, confianza del mapeo de eventos, perfil `us.` en la region de destino, forma de la condicion de
cuenta). Ninguno era de diseno; todos estaban en la lista de "sin medir" (§J) y se midieron el dia que tocaba.

## 20. Un MAC que firma quien escribe no anade un control (24-10-2026)

El MAC con KMS parecia cerrar la aprobacion falsificable: la huella no tiene secreto y un MAC si. Pero la clave
(`kms:GenerateMac`) la tendria el mismo permission set que hoy escribe el bloque `aprobacion`: quien puede escribir
un bloque inventado puede firmarlo. Lo que cierra el hueco es quitarle la escritura al aprobador y que la registre
una pieza que identifica a quien firma la peticion y corre los controles (una Lambda de aprobacion, ADR-003, A2).
Entonces la confianza del aplicador descansa en IAM y no en una clave que gestionar.

**Leccion.** Antes de anadir criptografia, preguntar quien tiene la clave y si es el mismo de quien se desconfia.

## 21. Quien firma se lee del evento, y las puertas de desarrollo tienen que saber donde corren (ADR-003, 25-10-2026)

Tres cosas que dejo el despliegue de la aprobacion en servidor.

**La identidad que vale es la que pone el servicio, no la que viene en el cuerpo.** La Lambda saca quien firma de
`requestContext.authorizer.iam`, que rellena la URL de funcion con `AWS_IAM` tras verificar la firma, y nunca de un
campo del JSON. Un `userArn` fabricado solo podria llegar por la API de Lambda, y ahi lo para IAM antes que el codigo:
el `InvokeFunction` del permission set vale solo con `lambda:InvokedViaFunctionUrl` (M2, F.7). El control esta en la
politica, no en una comprobacion que alguien podria olvidar.

**Una puerta de desarrollo que no sabe en que camino corre acaba abierta en produccion.** `--autoaprobacion-demo`
(`SALTADO`) nacio para probar en disco sin dos personas. La revision final del codigo encontro que en el servidor un
firmante sin persona podia aprobar por esa puerta, y que `rechazar` no miraba la identidad. El arreglo (`decidir(...,
exigir_persona=True)` solo en el camino del servidor) deja la puerta en disco y la cierra en la Lambda. Regla: cada
atajo de desarrollo lleva un test que lo intenta por el camino de produccion y espera el bloqueo.

**Los supuestos marcados se midieron; uno era incompleto y otro falso.** "Cuatro permisos para `AWS::Lambda::Url`"
eran cinco (`ListFunctionUrlConfigs`, leido del esquema con `DescribeType` antes de desplegar), y "la URL exige
`x-amz-content-sha256`" no era cierto (M1b). Ninguno habria roto nada grave; lo que importa es que estaban marcados
como supuestos y por eso se midieron. Regla, ya en CLAUDE.md: lo supuesto se escribe como supuesto, con la fecha, y
se mide en la primera llamada real.

## 22. Cuatro supuestos que solo se midieron al desplegar (25-10-2026)

El mismo dia que las pilas de acceso y runtime, cuatro cosas que estaban escritas como ciertas o como "sin medir"
resultaron distintas al tocar la cuenta. Las cuatro estan en `docs/MEDICIONES.md` K y §H.

**El servicio crea lo que la plantilla queria crear.** AgentCore crea el grupo de logs del runtime al crear el
runtime; una pila que lo declara choca con `AlreadyExists` y arrastra todo al rollback. La retencion la pone el
administrador una vez. Regla: antes de declarar un recurso "auxiliar" de un servicio gestionado, mirar si el servicio
ya lo crea (el 23-10-2026 se midio que no lo borra; nadie midio que lo crea).

**Una confianza que vale para la funcion no vale para el disparador.** `aws:SourceArn` exacto en la confianza del
rol del aplicador deja crear la funcion y hace fallar el mapeo de eventos del stream, que valida la confianza sin
aportar esa clave. Queda `aws:SourceAccount`: dentro de la cuenta, solo el rol de despliegue puede pasar roles a
Lambda. Regla: el confused deputy se protege por cada camino que asume el rol, y los caminos no siempre llevan las
mismas claves.

**La matriz con el administrador no cubria a los roles.** El perfil geografico `us.` enruta a `us-east-2` y
`us-west-2` y la autorizacion se repite en la region de destino; el rol permitia el perfil solo en `us-east-1` y
Bedrock devolvia un `AccessDenied` generico que ni el simulador ni CloudTrail explicaban. El administrador, con `*`,
nunca lo vio. Regla: un criterio de aceptacion "con los roles reales" no se cumple midiendo con otro principal.

**Access Analyzer razona en simbolico.** `s3:ResourceAccount` y `aws:ResourceAccount` son claves distintas para
`CheckNoNewAccess`, y `${aws:PrincipalAccount}` no es "nuestra cuenta" sino una variable: una propuesta con la cuenta
literal "concede mas" que un techo con la variable. El techo contiene de verdad (la cuenta ajena y la propuesta sin
condicion fallan), pero techo y propuesta tienen que restringir con la misma forma. Regla: cuando un control compara
dos politicas, las dos se escriben con las mismas claves y los mismos valores, y la primera solicitud real es la que
lo demuestra.

## 23. Tres supuestos de la Fase 23 que solo se midieron al desplegar (26-10-2026)

Los tres bloques de la Fase 23 (rol por persona, pagina web, correo) se desplegaron y midieron el mismo dia, y tres cosas
escritas como ciertas resultaron distintas al tocar la cuenta. Estan en `docs/MEDICIONES.md` O y §H (filas 39 y 40).

**Desplegar un cambio de contrato es desplegarlo en cada sitio que lo revalida.** La Lambda de aprobacion vuelve a validar
la fila con `models.py` antes de escribir la decision: es la defensa contra una propuesta aprobada bajo reglas viejas. Esa
misma defensa hizo que, con el contrato nuevo en el runtime y el zip del 25-10 en la aprobacion, la primera aprobacion
valida diera 409 "el registro no cumple el contrato de hoy". El plan reempaqueto runtime y aplicador y olvido la
aprobacion, aunque la tarea 9 habia tocado `aprobar.py`. Regla: cada modulo cambiado se contrasta con las listas de
`scripts/empaquetar.sh` y se reempaqueta cada Lambda que lo lleve; "desplegado" significa las tres Lambdas y el runtime.

**Una accion se autoriza sobre recursos que no aparecen en su nombre.** `ses:SendEmail` sugiere "desde una identidad" y el
rol de avisos permitia solo `identity/<remitente>`. SES evalua la accion tambien sobre la identidad del destinatario, asi
que todo envio dio `AccessDenied ... on resource identity/<correo de aviso>`. El recurso pasa a `identity/*` y lo que
acota al remitente es la condicion `ses:FromAddress`, que es la que de verdad importa. Regla: antes de escribir un
`Resource` estrecho, mirar en la referencia de autorizacion sobre que recursos evalua el servicio la accion, y poner
la restriccion que se quiere en la condicion que la expresa.

**Lo que la plantilla declara no siempre es lo que el servicio aplica.** `MinimumProtocolVersion: TLSv1.2_2021` paso
cfn-lint y CloudFormation, y CloudFront la ignoro: con el certificado por defecto (`*.cloudfront.net`) la distribucion
queda en `TLSv1`, y solo un certificado propio en ACM permite fijar el minimo. El test de la plantilla fija lo escrito,
no lo aplicado. Regla: una propiedad de seguridad que el servicio condiciona a otra (aqui, al certificado) se lee de
vuelta con la API tras desplegar, y lo que se documenta es lo leido.

Y una cuarta, de operacion y no de diseno: los avisos no se reintentan a proposito (un correo no es el circuito), asi que
los dos eventos de una solicitud aprobada mientras el remitente de SES seguia sin verificar se perdieron. El orden importa:
verificar el remitente antes del primer evento.

## 24. Un diagrama que no se puede comprobar se queda viejo (26-10-2026)

La guia visual (`docs/arquitectura/GUIA-VISUAL.md`) dejo dos lecciones que valen para cualquier documentacion de
arquitectura, no solo para esta.

**El dibujo sale del inventario, no de la memoria.** Antes de dibujar se listaron los recursos de cada plantilla de
`infra/cfn/` y se comprobaron en el codigo las tres llamadas que no se ven en las plantillas (el canje en STS desde la
pagina, la firma SigV4 del aprobador, el simulador y Access Analyzer desde el runtime). Es la misma regla que el resto del
proyecto aplica a AWS: lo que se afirma se ha leido de la fuente, y la fuente de un diagrama son la IaC y el codigo.

**Una sola fuente y un test que ata lo derivado.** La imagen y la animacion salen del mismo `.drawio`, y la animacion
encuentra cajas y flechas por el id de celda; `tests/unitarios/test_arquitectura_visual.py` falla si una flecha queda
fuera de todo paso o un paso cita algo que ya no existe. Un diagrama a mano sin esa atadura deja de ser cierto el dia
que cambia la arquitectura, y nadie lo nota porque nada falla. Y una tercera, de oficio: el validador de XML paso a la
primera con cinco fallos que solo se veian mirando el PNG (flechas que cruzaban cajas, insignias encima de etiquetas).
Un diagrama se revisa mirandolo, igual que una pagina web se prueba en el navegador.

## 25. Lo que protege un login en el navegador no es el CORS (27-10-2026)

Al pasar la pagina a `agente-iam.mateo.solutions` (Fase 27, `docs/ADR-005-dominio-propio-y-tls.md`) se dio por hecho que el
CORS de Cognito en `/oauth2/token` estaba atado a la URL de retorno del cliente: en O.4 devolvia el origen de CloudFront exacto, y
de ahi se dedujo que, sin cambiar la URL, el canje del codigo fallaria por CORS. Medido el 27-10-2026 (`docs/MEDICIONES.md` P.7):
Cognito devuelve en el preflight el origen que se le pida, tambien uno ajeno como `https://evil.example.org`. El CORS no separa
nada aqui.

Lo que si separa es la URL de retorno exacta: Cognito solo entrega el codigo a la URL registrada (con otra responde
`redirect_mismatch`, medido en los dos sentidos al cambiarla), y canjear ese codigo exige el verificador de PKCE que solo tiene
la pagina que lo pidio. Por eso el patron de `UrlRetornoWeb` en `acceso.yaml` admite solo dos URL concretas y no un dominio
cualquiera: es la barrera real, y abrirlo mandaria el codigo a donde diga quien despliega.

La regla general: el CORS decide que pagina puede LEER una respuesta en el navegador; no autentica a nadie, y un servidor
puede responder a cualquier origen sin perder seguridad si lo que devuelve exige un secreto (aqui, el codigo y su verificador).
Antes de apoyar una decision en el CORS de un servicio ajeno, se mide con un origen que no deberia pasar. Y un cambio en la
configuracion de Cognito no rige al instante: la URL nueva tardo entre 43 y 74 segundos en aplicarse; una prueba hecha
justo despues del change set habria dado el resultado al reves.

## 26. Un campo del formulario puede ser una barrera (27-10-2026)

En la Fase 28 Mateo pidio quitar "Tipo de acceso" del formulario: un solicitante no sabe que es lectura o escritura. Visto
desde la pagina era una pregunta de mas. Visto desde el codigo era una barrera: `coherencia` comparaba cada accion de la
politica con el nivel pedido, con el catalogo oficial, y bloqueaba lo que lo excediera. El solicitante fijaba un tope que ni el
modelo ni una justificacion manipulada podian subir. Quitar el campo sin mirar eso habria apagado un control sin que ningun
test fallara por la razon correcta.

Lo que se hizo: el modelo declara el nivel que entendio (`nivel_entendido`) y la misma barrera se aplica contra el, de modo que
el modelo que dice "lectura" y propone escribir sigue bloqueado; y el codigo calcula lo que concede la politica de verdad
(`nivel_real`), lo ensena en palabras llanas y sube el riesgo si modifica o borra, para que el aprobador lo confirme. Lo que se
pierde queda escrito: el tope ya no lo pone la persona sino el modelo leyendo su texto, y lo compensan el techo, la lista de
bloqueo y el aprobador. Mirando la barrera aparecio tambien que "escritura" y "administracion" eran identicas en el codigo:
la opcion de mas no protegia nada.

La regla: antes de quitar un campo, buscar donde lo lee el codigo y que decide con el. Un campo de entrada puede ser un dato o
un limite; si es un limite, se sustituye por otro o se escribe que se pierde.

## 27. Lo que una auditoria encuentra en los bordes (18-11-2026)

La auditoria del 18-11-2026 (PLAN, Fase 33) no rompio el circuito principal: ni quien pide ni un modelo hostil consiguieron, en
pruebas locales, una propuesta aprobable que concediera de mas. Lo que quedo abierto esta en los bordes, y las cuatro pistas
son sin confirmar: a cada una le falta un hecho de la cuenta o de AWS.

Un limite que es la union de todos los roles no separa a nadie. `AgenteIAM-LimiteSistema` contiene lo que necesita cada rol
del sistema, asi que un rol nuevo bajo ese limite puede hacer lo de cualquiera de ellos. El reparto por actor (quien escribe
`aprobacion`) estaba solo en las politicas en linea, que escribe quien despliega.

El nivel de acceso del catalogo no dice a donde van los datos. `sns:Subscribe` y `s3:PutBucketNotification` son escrituras
como otras para el catalogo, pero lo que hacen es fijar un destino de entrega. La condicion de cuenta del techo mira el recurso
sobre el que se actua, no ese destino.

Un campo libre que decide un destino es un rele. `correo_aviso` se valida por forma y nadie lo compara con la persona del token. No se pudo atar a la identidad sin tocar infraestructura (el token de acceso no trae correo), asi
que el arreglo fue otro: en el codigo, desde el 18-11-2026 y sin desplegar, el correo solo sale tras la decision de un aprobador, que ve la
direccion antes de actuar.

Un tope que cuenta resultados no acota intentos. El tope de roles vigentes cuenta lo aplicado; lo que gasta es cada intento.

El arbol limpio no es el repositorio limpio. El test de secretos mira `git ls-files`; la cuenta real estaba en la historia, y
GitHub guarda ademas las refs de los PR y los artefactos de Actions.

La regla: al cerrar un control, escribir que mira exactamente (que recurso, que momento, que copia) y buscar el camino que
consigue el mismo efecto sin pasar por ahi.
