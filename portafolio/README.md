# Portafolio

Carpeta creada el 26-10-2026, a peticion de Mateo, para guardar solo lo que se presenta fuera del repositorio: publicaciones
de LinkedIn y la pagina personal. Lo que sirve para estudiar o mantener el sistema no va aqui: los diagramas se editan en
`docs/arquitectura/` y la guia para leerlos es `docs/arquitectura/GUIA-VISUAL.md`.

## Que hay

| Fichero | Que es | De donde sale |
|---|---|---|
| `diagrama-arq.png` | El diagrama de despliegue en AWS con su leyenda paso a paso, en espanol, 4361 x 2150 px | Pagina "2 Despliegue en AWS" de `docs/arquitectura/agente-iam-arquitectura.drawio`, exportada por Mateo desde draw.io el 26-10-2026 |
| `demo-agente-iam-es.mp4` | Video de demostracion de punta a punta, 72 s, 1920x1080, sin voz, rotulos en espanol | Grabado el 02-11-2026 (Mateo en el navegador, Claude en la terminal con el si de Mateo) y montado ese dia por un agente con `local/video/salida/montaje.py` (fuera del repositorio) segun `docs/VIDEO-DEMO.md`; cuenta, ARNs, correo y credenciales tapados; revisado fotograma a fotograma y visto entero por Mateo |

## Reglas de esta carpeta

- **Solo piezas para publicar.** Imagenes, GIF o video. Nada de borradores de estudio. Los textos de trabajo de LinkedIn
  (perfil, proyecto y post) no se versionan desde el 18-11-2026: viven en `local/portafolio/`.
- **Es una copia, no la fuente.** Si cambia el `.drawio`, la imagen de aqui se queda vieja: se vuelve a exportar desde
  draw.io y se reemplaza. El test de `docs/arquitectura/` no vigila esta carpeta.
- **Nada de la cuenta real.** Ni el numero de cuenta, ni ARNs, correos, nombres de personas, tokens o URLs de la Lambda.
  `tests/seguridad/test_secretos.py` solo lee ficheros de texto: una captura de pantalla con la cuenta real pasaria sin
  aviso. Cada imagen se mira entera antes de meterla aqui.
- **Nombres que se entienden fuera.** Un fichero nuevo lleva en el nombre que muestra y su idioma, por ejemplo
  `despliegue-aws-en.png`.

## Pendiente para el portafolio (con Mateo)

Viene de `docs/arquitectura/GUIA-VISUAL.md`, seccion "Para la version de portafolio":

- Tildes y enes en la version en espanol.
- Una version de un minuto: menos texto en las cajas y una leyenda corta.
- Un GIF o un video corto de la animacion, porque GitHub y LinkedIn no ejecutan el HTML.
- Decidir si el diagrama muestra lo pendiente (TLS 1.2 con dominio propio, SES fuera del modo inicial).
- La version en ingles de la imagen para LinkedIn (`docs/arquitectura/agente-iam-despliegue-en.png` ya existe; falta decidir si
  va aqui tal cual o pulida).
