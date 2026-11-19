# Guia visual de la arquitectura

Escrita el 26-10-2026 con el sistema tal como esta desplegado y medido ese dia (Fase 23, `CONTEXTO.md` §2). Sirve para
dos cosas: leer los diagramas de esta carpeta y aprender a hacer (y mantener) los siguientes.

## Que hay en esta carpeta

| Fichero | Que es | Se edita a mano |
|---|---|---|
| `agente-iam-arquitectura.drawio` | La fuente. Dos paginas: "1 Contexto" y "2 Despliegue en AWS" | Si, en draw.io |
| `traduccion-en.json` | La traduccion al ingles de cada texto del .drawio, por texto exacto en espanol | Si |
| `agente-iam-arquitectura-en.drawio` | La version en ingles ("1 Context" y "2 AWS deployment"): el mismo dibujo con los textos traducidos | No: lo genera el script |
| `agente-iam-contexto.png` / `.svg` y `-en` | Pagina 1 exportada, en espanol y en ingles | No: lo genera el script |
| `agente-iam-despliegue.png` / `.svg` y `-en` | Pagina 2 exportada, en espanol y en ingles | No: lo genera el script |
| `animacion-plantilla.html` | La animacion sin el dibujo: estilos, motor y los pasos en JSON, con su texto en los dos idiomas | Si: los textos y los pasos |
| `agente-iam-animacion.html` | La animacion construida, un unico fichero sin dependencias, con boton ES/EN. Se abre con doble clic | No: lo genera el script |

Para regenerar todo despues de tocar el `.drawio` o la plantilla:

```bash
./.venv/bin/python scripts/construir_arquitectura.py
```

Con `--sin-exportar` no exporta: regenera el .drawio en ingles y la animacion (cuando solo cambiaron textos de la plantilla
o de la traduccion). Exportar necesita draw.io de escritorio (`drawio` en el PATH o su ruta en `DRAWIO`).

## Tres vistas, tres preguntas

Un diagrama responde a una pregunta para un publico. Meterlo todo en uno da un dibujo que nadie lee. Aqui hay tres:

1. **Contexto** (pagina 1). Pregunta: quien usa el sistema y con que habla. Es el nivel 1 del modelo C4: el sistema es
   una sola caja, alrededor van las personas y los sistemas externos. Sin iconos de AWS a proposito: es una vista logica,
   y los iconos de proveedor distraen de la idea. Es la primera frase en una entrevista.
2. **Despliegue en AWS** (pagina 2). Pregunta: que piezas de AWS existen y por donde pasa una solicitud. Iconos oficiales,
   cuentas y region como cajas, pasos numerados y una leyenda que cuenta cada paso. Es la vista para estudiar.
3. **Recorrido animado** (`agente-iam-animacion.html`). Pregunta: en que orden pasa todo y por que. Es lo que C4 llama
   diagrama dinamico (interacciones numeradas en el orden en que ocurren), con el dibujo de la pagina 2 debajo. Cada paso
   dice que pasa, por que se hizo asi y donde mirarlo en el repositorio.

Lo que no esta, a proposito: el bucket de paquetes, el rol de despliegue y los permission sets Operador y Lectura (son de
construir el sistema, no de usarlo; lo dice la leyenda). Un diagrama de componentes del agente (nivel 3 de C4: orquestador,
coherencia, simulacion) seria el siguiente si hiciera falta.

## El metodo, regla por regla

Cada regla viene de una fuente (al final) y al lado va como se aplico aqui.

| Regla | Aqui |
|---|---|
| Todo diagrama lleva titulo que dice que muestra y su alcance | "Agente IAM: contexto" y "Agente IAM: despliegue en AWS", con la fecha del estado |
| Todo diagrama lleva leyenda: colores, lineas, siglas | Pagina 1: tipos de caja y que dice una flecha. Pagina 2: los diez pasos y los tipos de linea |
| Cada elemento dice su tipo y, si es una pieza, su tecnologia | `[Persona]`, `[Sistema externo]`; en la pagina 2, la caja dice el papel ("Login") y el icono el servicio ("Amazon Cognito") |
| Cada flecha va en un solo sentido y lleva etiqueta; "usa" no vale | "POST + access_token (JWT)", "stream: estado = aprobada". La tecnologia entre corchetes en la pagina 1 |
| Los pasos se numeran en el orden en que ocurren | Insignias azules 1 a 9 cerca del origen de cada paso; la roja F es el camino de fallo |
| Iconos oficiales de AWS, de la version vigente, sin cambiar colores, nombre debajo | La libreria `mxgraph.aws4` de draw.io 32.3.0; color por categoria (computo naranja, base de datos morada, seguridad roja) |
| Las fronteras se dibujan: cuenta, region | Dos cuentas (borde rosa) y la region `us-east-1` (turquesa discontinuo) |
| Un diagrama, uno o dos recorridos | El recorrido feliz y el de fallo; lo demas va a la leyenda o fuera |
| Las discontinuas son para lo asincrono o el fallo | Solo el camino de fallo va discontinuo (y en rojo) |
| La fuente editable se guarda junto a la imagen | El `.drawio` esta en el repositorio; PNG y SVG se regeneran desde el |
| La animacion respeta a quien pide menos movimiento | Con `prefers-reduced-motion: reduce` no se mueve nada: se resaltan las flechas una a una con su etiqueta |
| El color no es el unico canal | El fallo es rojo y ademas discontinuo y con la letra F |

## Como se hizo, paso a paso

Este es el orden que conviene repetir la proxima vez.

1. **Inventario desde la verdad, no de memoria.** Se listaron los recursos de cada plantilla de `infra/cfn/` y se
   comprobaron tres detalles en el codigo: que la pagina canjea en STS con `AssumeRoleWithWebIdentity` (`web/app.js`), que
   el aprobador firma con SigV4 y que el runtime llama a Access Analyzer y al simulador (permisos de `base.yaml`). Un
   diagrama que se dibuja de memoria acaba ensenando lo que se creia, no lo que hay.
2. **Elegir las vistas** antes de dibujar (la seccion anterior).
3. **Cuadricula primero.** Seis columnas y cuatro filas fijas; cada servicio cae en una celda. Las flechas largas van por
   carriles entre filas o columnas, nunca por encima de una caja. El dibujo se genero con un script de coordenadas para
   poder mover todo a la vez; el resultado es un `.drawio` normal que se edita a mano.
4. **Mirarlo, no solo validarlo.** El validador de XML paso a la primera y el dibujo tenia cinco fallos que solo se ven
   mirando: dos insignias encima una de otra, una flecha atravesando la caja de SES, otra atravesando la de auxiliares, el
   aprobador montado sobre el borde de la cuenta de gestion y etiquetas sin sitio junto a la persona. Se exporto a PNG, se
   miro, se corrigio y se volvio a exportar hasta que no quedo ninguno.
5. **Exportar** a PNG (para leer y para el README) y a SVG (para la animacion). draw.io mete en el SVG una copia en PNG de
   cada etiqueta, para visores que no pintan HTML; el script las quita (de 2,4 MB a 184 KB, medido el 26-10-2026).
6. **Animar sobre el mismo dibujo.** La animacion no tiene un dibujo propio: usa el SVG de la pagina 2 y encuentra cada
   caja y cada flecha por su id de celda del `.drawio` (`data-cell-id`). Asi la imagen y la animacion no pueden contar
   cosas distintas.
7. **Atar con un test.** `tests/unitarios/test_arquitectura_visual.py` falla si una flecha del diagrama no esta en ningun
   paso, si un paso cita una caja o flecha que no existe o si la animacion construida no lleva los pasos de la plantilla.
   Se comprobo que se pone en rojo quitando una flecha de un paso.

## La version en ingles

Traducir copiando el dibujo daria dos dibujos que se separan en cuanto se mueve una caja. Por eso el ingles no se dibuja:
el script lee el .drawio en espanol y cambia cada texto por el de `traduccion-en.json`, con la posicion, los ids y los
estilos intactos. Tres consecuencias:

- Mover algo en el .drawio en espanol mueve tambien el ingles la proxima vez que corre el script.
- Cambiar o anadir un texto en espanol sin traducirlo para el script con codigo 1 y la lista de lo que falta, y el test
  `test_cada_texto_del_drawio_tiene_traduccion_y_ninguna_sobra` se pone en rojo. Una traduccion de un texto que ya no
  existe tambien lo pone en rojo, para que la tabla no acumule restos.
- Los valores reales del codigo (`propuesta`, `aprobada`, `aplicada`, `AgenteIAM-Techo`, `aprobar_cliente`) no se traducen:
  son lo que se ve en la tabla de DynamoDB y en IAM. Donde cabe, el ingles anade el significado entre parentesis.

La animacion lleva los dos SVG y un boton ES/EN arriba a la derecha. Elige el idioma por este orden: `?lang=es` o
`?lang=en` en la URL, el ultimo elegido (se guarda en el navegador) y, si no hay ninguno, el del navegador (espanol si
empieza por `es`, ingles si no). Cambiar de idioma a mitad de un paso lo repite en el otro idioma. Abierta con doble clic
desde el disco, la URL y la memoria pueden no funcionar segun el navegador; el boton funciona siempre.

## Como se edita

- **Mover o retocar** cajas, flechas y textos: abrir el `.drawio` en draw.io (escritorio o app.diagrams.net), guardar y
  correr el script. Mover no rompe nada.
- **Anadir un servicio o una flecha**: en draw.io, y despues anadir su flecha a un paso de `animacion-plantilla.html`
  (bloque JSON `pasos`, campo `tramos`). El id de una celda se ve en draw.io con Editar datos (Ctrl+M).
- **No renombrar ids** sin cambiarlos tambien en la plantilla: el test lo detecta, pero mejor no llegar ahi.
- **Cambiar un texto de la animacion**: en la plantilla, en espanol y en su bloque `en`; despues `--sin-exportar`.
- **Cambiar un texto del dibujo**: en el .drawio en espanol y su traduccion en `traduccion-en.json` (la clave es el texto
  exacto en espanol, con su HTML); despues el script entero.
- La pagina 2 tiene ademas la leyenda dentro del dibujo; la animacion la oculta y usa su panel. Si cambia un paso, se
  cambian los dos textos.

## Antes de dar un diagrama por bueno

- Tiene titulo con alcance y fecha, y leyenda.
- Cada flecha tiene sentido y etiqueta concreta; ninguna atraviesa una caja ni una etiqueta.
- Ninguna insignia tapa una etiqueta.
- Lo que dibuja coincide con `infra/cfn/` y con el estado medido de `CONTEXTO.md` §2 (nada que exista solo en un plan).
- Se lee en blanco y negro: el significado no depende solo del color.
- PNG, SVG y animacion regenerados, y los tests en verde.

## Para la version de portafolio (pendiente, con Mateo)

Las piezas terminadas van a `portafolio/`, en la raiz del repositorio (creada el 26-10-2026); esta carpeta guarda la fuente.

- Tildes y enes en la version en espanol: el texto va sin ellas por coherencia con el resto del repositorio; en una pieza
  publica conviene ponerlas. La version en ingles ya esta (26-10-2026).
- Una version de un minuto: menos texto en las cajas y la leyenda corta.
- Un GIF o un video corto de la animacion para el README, porque GitHub no ejecuta el HTML.
- Decidir si el diagrama muestra lo pendiente (TLS 1.2 con dominio propio, SES fuera del modo inicial).

## Fuentes

- Modelo C4, notacion: https://c4model.com/diagrams/notation (titulo, leyenda, tipo y tecnologia de cada elemento,
  flechas en un sentido y etiquetadas).
- Modelo C4, diagrama dinamico: https://c4model.com/diagrams/dynamic (interacciones numeradas en orden).
- AWS Architecture Icons: https://aws.amazon.com/architecture/icons/ (uso permitido en diagramas, publicacion trimestral,
  draw.io como herramienta).
- AWS Community Builders, guia de diagramas: https://dev.to/aws-builders/aws-architecture-diagrams-guidelines-595d
  (frontera de cuenta, uno o dos flujos por diagrama, colores con significado, no mezclar versiones de iconos).
- MDN, `prefers-reduced-motion`: https://developer.mozilla.org/en-US/docs/Web/CSS/@media/prefers-reduced-motion
- Skill `aws-architecture-diagram` (plugin deploy-on-aws): estilo de los diagramas de referencia de AWS (titulo con
  separador naranja, cajas por categoria, insignias numeradas y leyenda lateral).
