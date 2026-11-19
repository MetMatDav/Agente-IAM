# Agente IAM: reglas del proyecto

Antes de trabajar aqui, lee `CONTEXTO.md` (traspaso) y la ultima fase de
`PLAN-CORRECCIONES.md`. Mateo hace los pasos de consola y quiere entender
cada pieza: explica el diseno antes de escribirlo.

## Regla obligatoria: todo avance importante se documenta

Un avance no esta terminado hasta que la documentacion lo refleja. Se
actualiza en el mismo trabajo, antes de darlo por cerrado, no "despues".

**Que cuenta como avance importante:**
- una fase nueva o un cambio de comportamiento observable (estados,
  codigos de salida, comandos, flags, contratos de entrada o salida);
- un modulo, test, archivo de `infra/` o variable de entorno nuevo o
  retirado;
- un hallazgo: un bug, una medicion contra la cuenta, una conclusion
  sobre como se comporta AWS, o una conclusion anterior que resulto falsa;
- un cambio en el estado real de la cuenta, o descubrir que no coincide
  con lo documentado;
- una decision de diseno, tomada o aplazada.

**Donde va cada cosa:**

| Documento | Que se actualiza |
|---|---|
| `PLAN-CORRECCIONES.md` | Una fase por avance: que, por que, como se verifico, que queda pendiente. Corta: lo medido va a `docs/MEDICIONES.md` |
| `CONTEXTO.md` | Estado (§2), arquitectura (§3), cuenta (§5), mapa del codigo (§6), como correr (§7), errores (§9), limitaciones (§10), proximos pasos (§11) |
| `README.md` | Estructura, uso y variables, si cambian |
| `ESTUDIO-diseno-y-seguridad.md` | Si el avance deja una leccion o corrige una anterior |
| `docs/DESPLIEGUE.md` | Si cambia lo que hay que desplegar o lo que existe en la cuenta |
| `docs/ADR-*.md`, `docs/ESPECIFICACION-agentcore.md` | Si una decision de diseno se toma, cambia o se aplaza |
| `docs/MEDICIONES.md` | Toda medicion contra la cuenta o un servicio real, con su fecha y contra que se midio; y, en §H, una fila por cada conclusion que resulto falsa |
| Docstrings | Si el porque de un modulo cambia |

**Como se escribe:**
- Fechas absolutas (`20-10-2026`), nunca "ayer" ni "la ultima sesion".
- Lo medido se distingue de lo supuesto, y se dice contra que se midio.
- Un numero que cambia solo (tests, versiones) va con su fecha.
- Lo que resulto falso se corrige donde estaba, sin dejar historia en el texto
  vigente. La constancia del error va en una fila de `docs/MEDICIONES.md` §H
  (fecha, lo que se creyo, lo que resulto), no dentro del texto vigente.
- Lo pendiente se nombra como pendiente, con quien lo tiene que hacer.

**Como se documenta con subagente.** Un modelo menor (Sonnet; Haiku solo para
cambios mecanicos) escribe la documentacion a partir de un encargo cerrado que
redacta Claude: ficheros que puede tocar, que cambia en cada uno y que no puede
tocar. Claude revisa el diff contra la tabla de arriba, corre los tests y busca
los identificadores reales antes de darlo por cerrado; las decisiones y el
diseno los redacta Claude.

**Como se comprueba:** `./.venv/bin/python -m pytest tests/ -q`.
`tests/unitarios/test_documentacion.py` falla si un modulo de `agente_iam/` no
aparece en el README y en CONTEXTO, o un fichero de tests no aparece en
CONTEXTO §6. Lo demas lo comprueba quien cierra el avance, repasando la
tabla de arriba.

## Secretos y datos de la cuenta

El repositorio esta en GitHub. Nada que no deba publicarse entra en un
commit:

- Credenciales, tokens, `.env`, claves privadas: nunca. Si una llega a un
  commit, se da por expuesta y se rota; borrarla del archivo no basta.
- La cuenta real tampoco: en lo versionado va `111122223333`. Lo que
  necesite la real se genera en `local/` con `scripts/localizar.py`.
- Registros de `solicitudes/`, salidas del runtime y el catalogo cacheado
  se quedan fuera (ver `.gitignore`).
- `tests/seguridad/test_secretos.py` lo comprueba; si salta, se arregla antes de
  seguir.

## Otras reglas que ya rigen

- Lo que no se ha ejecutado no funciona: cada arreglo lleva un test que se
  pone en rojo si se deshace, y lo que toca AWS se prueba contra la cuenta.
- Las pruebas en vivo escriben en una carpeta aparte (`DIR_SOLICITUDES`),
  nunca encima de `solicitudes/`.
- Nada de escribir en la cuenta AWS sin que Mateo lo pida; los pasos de
  consola son suyos.
- No se hacen commits sin que se pidan.
