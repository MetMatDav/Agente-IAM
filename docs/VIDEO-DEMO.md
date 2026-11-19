# Video de demostracion de punta a punta (LinkedIn)

Escrito el 31-10-2026; grabado y montado el 02-11-2026 (Fase 32). Guion, forma de grabar y forma de montar el
video corto que muestra el sistema funcionando contra la cuenta real, para la publicacion de LinkedIn. Lo decidio Mateo el 31-10-2026: una
persona pide un permiso en la pagina, se ve lo esencial del proceso interno y al final la respuesta con su
porque. Sin voz, con rotulos en pantalla, entre 60 y 90 segundos. La pieza terminada va a `portafolio/`;
este documento es la fuente para repetirla.

## Guion, escena por escena

| # | Segundos | Que se ve | Rotulo (texto publico, con tildes) | Quien lo hace |
|---|---|---|---|---|
| 1 | 0 a 8 | Portada: diagrama de contexto quieto | "Pedir un permiso en AWS con IA y aprobación humana" | Montaje |
| 2 | 8 a 18 | Pagina `agente-iam.mateo.solutions`, sesion de `solicitante.demo`. Se pide en texto libre un bucket que no existe y se envia | "Texto libre. La persona no elige nada técnico" y despues "Rechazada antes de llamar al modelo: 0 tokens" | Mateo (navegador) |
| 3 | 18 a 30 | La misma pagina: se pide `finanzas-demo` 4 horas. Respuesta `propuesta` con el rol previsto | "El sistema entiende el permiso y propone" | Mateo (navegador) |
| 4 | 30 a 55 | Terminal del aprobador: `aprobar_cliente <id>` muestra la REVISION (pedido, nivel entendido por el modelo frente a lo que concede segun el codigo, justificacion marcada como dato no confiable, documento, huella) | "El modelo propone", "El código valida en 3 capas: lista negra, Access Analyzer, simulador de IAM", "Nada se aplica sin una persona" | Claude (terminal, con el perfil SSO del aprobador y el si de Mateo) |
| 5 | 55 a 65 | Terminal: `aprobar_cliente <id> --huella sha256:...` responde `aprobada`; corte a la bandeja de correo con el aviso `aplicada` | "Una Lambda aparte crea un rol temporal: el único proceso que escribe en IAM" | Claude (terminal) y Mateo (correo) |
| 6 | 65 a 85 | Pagina: el enlace del correo lleva a "Usar un acceso aprobado"; se obtienen credenciales (la salida se tapa) | "Rol de 4 horas que vence solo" y cierre: "agente-iam.mateo.solutions · Strands · Amazon Bedrock · AgentCore · Lambda · CloudFormation" | Mateo (navegador) |

Los segundos de la tabla son los del guion; los cortes del video terminado estan en "Como se monto". 
Lo que no sale: el numero de cuenta, los ARN, el correo real y las credenciales. Se tapan en el montaje
(`portafolio/README.md`, regla "Nada de la cuenta real").

## Como se graba

Los guiones de grabacion y de montaje viven en `local/video/` (fuera del repositorio, ignorado por git); este
documento es la fuente para rehacerlos. Los del 31-10-2026 estaban en el area temporal de la sesion y se perdieron
cuando se vacio `/tmp`; se rehicieron el 02-11-2026.

- Grabador de GNOME (Ubuntu, Wayland) por D-Bus (`org.gnome.Shell.Screencast`), 1920x1080 a 30 fps, en `.webm`
  (VP8), con `local/video/grabar.py`. Hallazgo del 31-10-2026: una llamada suelta con `gdbus call` graba 2
  fotogramas, porque GNOME corta la grabacion cuando quien la pidio se va del bus; hace falta un proceso que
  mantenga la conexion abierta. `grabar.py` usa un proxy Gio y un bucle GLib que no suelta la conexion hasta
  recibir SIGTERM; las opciones son `framerate` 30 y `draw-cursor`, y se pasan como diccionario de `GLib.Variant`
  (pasarlas como un solo `Variant` `a{sv}` falla). Una grabacion por escena.
- Hallazgo del 02-11-2026: las grabaciones de GNOME son de fotogramas variables (solo graban cuando algo cambia;
  `revision.webm` dura 18 s y tiene 108 fotogramas). Cortar con `-ss` sobre ellas no es exacto: el montaje pasa
  cada toma a 30 fps constantes y corta con `trim`.
- Las escenas de terminal van en `gnome-terminal --maximize --zoom=1.4 --wait`, lanzado por
  `local/video/escena-terminal.sh` con el perfil SSO del aprobador (junto a `local/video/escena.sh`); se
  lee en un fotograma de 1920x1080. El ultimo segundo y medio de cada toma de terminal muestra el escritorio y se
  corta al montar.
- Las de navegador y correo las hace Mateo en su navegador (Brave), con la ventana maximizada.
- Las tomas del 02-11-2026 estan en `local/video/tomas/`: `navegador.webm` (289 s, Mateo, solicitudes),
  `revision.webm` (18 s, terminal, Claude), `aprobacion.webm` (18 s, terminal, Claude, con el si de Mateo) y
  `correo-y-acceso.webm` (271 s, Mateo: Gmail y la pagina de credenciales).
- Las sesiones SSO caducan a la hora del login (medido los dos dias, 01-11 y 02-11-2026, con `agente-iam-org` y con
  el perfil del aprobador de la demo): hay que renovar la del aprobador entre la toma del navegador y la de la
  revision.
- ffmpeg 9.0.2 estatico (paquete `imageio-ffmpeg` en el venv `local/video/.venv-ffmpeg`, con Pillow y numpy, sin
  tocar el sistema): corta (`trim`), acelera las esperas (`setpts`), recorta la terminal (`crop`), tapa zonas
  (`boxblur` con `enable`), quema los rotulos (`ass`, fuente Ubuntu) y une las escenas (`concat`). No tiene
  `drawtext`: por eso los rotulos van como subtitulos ASS.

## Como se monto

Lo hizo un agente (modelo Opus) el 02-11-2026 con `local/video/salida/montaje.py`, que es reproducible: vuelve a
sacar el mismo video desde las cuatro tomas. Sus notas estan en `local/video/salida/NOTAS-MONTAJE.md`. Resultado:
`local/video/salida/demo-agente-iam.mp4`, 72,27 s, 7,5 MB, H.264 1920x1080 a 30 fps, con pista de audio silenciosa.

| Escena | Segundos | Toma |
|---|---|---|
| Portada (diagrama de contexto quieto) | 0 a 7 | Montaje |
| Rechazo de un recurso que no existe | 7 a 17,7 | `navegador.webm` |
| Propuesta de `finanzas-demo` | 17,7 a 28,8 | `navegador.webm` |
| Revision en la terminal del aprobador | 28,8 a 47,8 | `revision.webm` |
| Aprobacion y correo `aplicada` | 47,8 a 60,2 | `aprobacion.webm` y `correo-y-acceso.webm` |
| Credenciales en "Usar un acceso aprobado" | 60,2 a 67,3 | `correo-y-acceso.webm` |
| Cierre con el nombre del sitio y las tecnologias | 67,3 a 72,3 | Montaje |

- Rotulos: ASS quemado (fuente Ubuntu, 46 px) con los seis textos del guion literales, mas recuadros de color en
  las lineas clave de la terminal.
- Terminal: recorte `crop` de 1844x1000 desde (66,80), que deja fuera la barra de GNOME y el dock.
- Tapado con desenfoque por zonas fijas: el numero de cuenta (en ARN, en el nombre del bucket, en la justificacion y
  en los supuestos), el correo de Mateo y el bloque entero de credenciales (solo queda visible la linea
  `# caduca: ...`). No entran el login, la bandeja de Gmail, los correos "aprobada" y "rechazada" ni un desplegable
  del navegador con historial de otra cuenta.
- Revision: el agente miro los 72 fotogramas (uno por segundo) y corrigio un fallo propio (se veian cuatro digitos
  del nombre del bucket en el JSON). No habia `tesseract`, asi que no hubo OCR. Claude reviso seis fotogramas clave y
  Mateo vio el video entero y lo dio por bueno.

## Estado

- 02-11-2026: hecho. Grabado, montado y revisado; la pieza esta en `portafolio/demo-agente-iam-es.mp4` (72,27 s,
  7,5 MB, mismo fichero que `local/video/salida/demo-agente-iam.mp4`). La solicitud que se ve es real y esta
  medida en `docs/MEDICIONES.md` V.2 y V.3 (`req-20261102-d7c5aa51` rechazada y `req-20261102-48256a02` aprobada y
  aplicada).
- Lo que se aparta del guion: la portada dura 7 s (no 8) y la escena de la revision dura 19 s (28,8 a 47,8). El
  motivo de rechazo que se ve en la pagina es "No se encontro el recurso en esta cuenta"; el rotulo "Rechazada antes
  de llamar al modelo: 0 tokens" es coherente con el (el rechazo ocurre antes del modelo: 0 intentos).
- Decisiones abiertas de Mateo (no estan tapadas, ninguna es dato prohibido): se ven el sufijo del permission set
  del aprobador, la huella y la hora de aprobacion; y en la escena de credenciales el bloque "Tu solicitud" sigue
  diciendo "Estado: propuesta", porque esa parte de la pagina no se refresco. Si Mateo quiere taparlos o rehacer la
  escena, se cambia `montaje.py` y se vuelve a montar.
- Pendiente: publicarlo en LinkedIn (Mateo). El commit del video y de este documento, cuando Mateo lo pida
  (Claude).
