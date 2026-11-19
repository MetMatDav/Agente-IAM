#!/usr/bin/env bash
#
# Construye el paquete de despliegue para AgentCore Runtime (camino de zip
# con runtime gestionado de Python: sin Docker, sin ECR, sin contenedor).
#
#   scripts/empaquetar.sh [runtime]   (desde cualquier carpeta)
#   scripts/empaquetar.sh aprobacion
#   scripts/empaquetar.sh aplicador
#
# Sin argumento (o `runtime`) deja dist/agente-iam.zip, listo para subir a S3.
# Con `aprobacion` (ADR-003, 24-10-2026) deja dist/agente-iam-aprobacion.zip,
# el de la Lambda `agente-iam-aprobacion` (python3.12, arm64, manejador
# agente_iam.aprobar.manejador), e imprime la clave S3 con la que subirlo.
# Con `aplicador` (25-10-2026) deja dist/agente-iam-aplicador.zip, el de la
# Lambda `agente-iam-aplicador` (python3.12, arm64, manejador
# agente_iam.aplicador.manejador): lleva lo de la aprobacion mas aplicador.py,
# porque el aplicador importa de aprobar.py. Imprime tambien su clave S3.
# Los tres zips se construyen igual (mismas ruedas aarch64, mismo catalogo
# dentro); cambian los requisitos, lo que se borra de agente_iam/, si lleva
# main.py y el limite de tamano plano (750 MB el runtime, 250 MB cada Lambda).
#
# TRES COSAS QUE NO SON OBVIAS:
#
#   1. ARM64. AgentCore corre sobre Graviton y solo acepta aarch64. Se usa
#      `--platform manylinux2014_aarch64` con `--only-binary=:all:`, que
#      baja wheels ya compilados y FALLA RUIDOSAMENTE si algun paquete solo
#      publica codigo fuente. Preferimos ese fallo a un paquete que se
#      construye aqui y no arranca alli.
#
#   2. El catalogo viaja DENTRO. En local se rellena solo por HTTP y se
#      cachea; en el paquete no puede depender de la red ni de poder
#      escribir. Si falta, el chequeo de nivel de acceso no falla: se
#      degrada a advertencia y deja de bloquear. Por eso se descarga aqui
#      y el servidor lo comprueba al arrancar. Se descarga ENTERO, en una
#      carpeta vacia, y no se copia la cache local (24-10-2026, O2): hasta
#      esa fecha se empaquetaba `.cache/servicereference` tal cual, que
#      tenia dos meses, y el techo (que siempre descarga) y el agente
#      juzgaban con catalogos distintos.
#
#   3. Nada de __pycache__. Es bytecode de ESTA arquitectura; colarlo en un
#      paquete aarch64 es basura en el mejor caso.
#
set -euo pipefail
cd "$(dirname "$0")/.."   # la raiz del repo; el script vive en scripts/ desde la Fase 16

PYTHON_VERSION=3.12          # debe coincidir con `runtime` del create-agent-runtime y de la Lambda
PLATAFORMA=manylinux2014_aarch64
DESTINO=dist
VENV=./.venv/bin

# Que paquete se construye. Se decide antes de cualquier paso: un argumento
# desconocido sale sin correr los tests ni tocar la red.
DESTINO_PAQUETE="${1:-runtime}"
# El cliente de la persona (aprobar_cliente.py) no viaja a ninguno de los tres:
# firma con las credenciales de quien aprueba, desde su equipo.
FUERA_DEL_RUNTIME="aprobar.py aplicador.py avisos.py cli.py huella.py aprobar_cliente.py"
# La Lambda solo lleva lo que importa aprobar.py (almacen, coherencia, config,
# herramientas, huella, models). Fuera: el cliente, el aplicador (escribe en
# IAM), el CLI, el servidor de AgentCore y el agente con su orquestador.
# Ninguno puede estar en la cadena de imports de aprobar.py: lo vigila
# test_ci.py::test_la_lambda_de_aprobacion_lleva_lo_que_importa_y_nada_mas.
FUERA_DE_LA_APROBACION="aprobar_cliente.py aplicador.py avisos.py cli.py servidor.py orquestador.py agente.py identidad.py simulacion.py personas.py existencia.py motivos.py"
# Y lo que SI tiene que estar en el zip de la Lambda: sin su manejador o sin la
# huella no arranca (revision final, F6). Se comprueba en el zip, abajo.
LLEVA_LA_APROBACION="aprobar.py huella.py"
# La Lambda del aplicador (25-10-2026) escribe en IAM; por eso es otra Lambda
# con otro rol y otro zip, no la de la aprobacion con un modulo mas. Lleva lo
# de la aprobacion (aplicador.py importa de aprobar.py `revalidar`,
# `comprobar_techo` e `identificar_aprobador`) y por eso aprobar.py viaja, pero
# se borra el mismo resto: cliente, CLI, servidor y agente con su orquestador.
# Lo vigilan los tests de test_ci.py sobre la cadena de imports de aplicador.py.
FUERA_DEL_APLICADOR="aprobar_cliente.py cli.py servidor.py orquestador.py agente.py identidad.py simulacion.py existencia.py"
# Sin su manejador, sin aprobar.py o sin la huella no arranca. Se comprueba en el zip.
LLEVA_EL_APLICADOR="aplicador.py avisos.py aprobar.py huella.py motivos.py"
# Lo que el `case` fija ademas de requisitos y limites: LLEVA (lo que tiene que
# estar en el zip; vacio en el runtime, que arranca por main.py) y PREFIJO_S3
# (con que nombre se sube la Lambda; vacio en el runtime, que no va a S3 asi).
case "$DESTINO_PAQUETE" in
    runtime)
        REQUISITOS=requirements.txt
        FUERA="$FUERA_DEL_RUNTIME"
        PAQUETE="$DESTINO/agente-iam.zip"
        LIMITE_PLANO=750
        LLEVA=""
        PREFIJO_S3=""
        ;;
    aprobacion)
        REQUISITOS=requirements-aprobacion.txt
        FUERA="$FUERA_DE_LA_APROBACION"
        PAQUETE="$DESTINO/agente-iam-aprobacion.zip"
        LIMITE_PLANO=250       # el de Lambda: 250 MB sin comprimir, no se amplia
        LLEVA="$LLEVA_LA_APROBACION"
        PREFIJO_S3="aprobacion"
        ;;
    aplicador)
        REQUISITOS=requirements-aplicador.txt
        FUERA="$FUERA_DEL_APLICADOR"
        PAQUETE="$DESTINO/agente-iam-aplicador.zip"
        LIMITE_PLANO=250       # tambien una Lambda: mismo limite, tampoco se amplia
        LLEVA="$LLEVA_EL_APLICADOR"
        PREFIJO_S3="aplicador"
        ;;
    *)
        echo "Uso: scripts/empaquetar.sh [runtime|aprobacion|aplicador]   (sin argumento: runtime)" >&2
        exit 2
        ;;
esac

echo "==> 1/6  Los tests, antes de empaquetar nada"
# Un paquete que no se sabe si funciona no deberia poder construirse.
# Unitarios y seguridad: empaquetar no depende de la cuenta ni la toca.
"$VENV/python" -m pytest tests/unitarios tests/seguridad -q

echo "==> 2/6  Catalogo oficial de acciones, recien descargado, para que viaje dentro"
# Se baja con el MISMO codigo que lo usa: si el formato cambiara, falla
# aqui y no en la primera solicitud de produccion. La carpeta empieza
# vacia, asi que todo sale de la red hoy: nada de la cache local.
CATALOGO="$DESTINO/catalogo-recien-descargado"
rm -rf "$CATALOGO"
mkdir -p "$CATALOGO"
DIR_CACHE_CATALOGO="$CATALOGO" "$VENV/python" - <<'PY'
from agente_iam.config import SERVICIOS_PERMITIDOS
from agente_iam.herramientas import catalogo

faltan = catalogo.no_disponibles(SERVICIOS_PERMITIDOS)
if faltan:
    raise SystemExit(f"No se pudo obtener el catalogo de: {faltan}")
print(f"    {len(SERVICIOS_PERMITIDOS)} servicios disponibles")
PY

echo "==> 3/6  Limpiando $DESTINO/"
rm -rf "$DESTINO/paquete" "$PAQUETE"
mkdir -p "$DESTINO/paquete"

echo "==> 4/6  Dependencias compiladas para aarch64"
"$VENV/pip" install \
    --quiet \
    --target "$DESTINO/paquete" \
    --platform "$PLATAFORMA" \
    --python-version "$PYTHON_VERSION" \
    --implementation cp \
    --only-binary=:all: \
    -r "$REQUISITOS" \
    -c constraints.txt

# Queda constancia de lo que se metio de verdad, no de lo que se pidio.
# Desde la Fase 13, `constraints.txt` fija tambien las transitivas, asi que
# esta lista deberia coincidir con el; si no, algo se instalo distinto.
"$VENV/python" - "$DESTINO/paquete" > "$DESTINO/paquete/VERSIONES.txt" <<'PY'
import pathlib, sys
raiz = pathlib.Path(sys.argv[1])
for d in sorted(raiz.glob("*.dist-info")):
    print(d.name.removesuffix(".dist-info").replace("-", "==", 1))
PY

echo "==> 5/6  Nuestro codigo, el entrypoint y el catalogo"
cp -r agente_iam "$DESTINO/paquete/"
# El aprobador y el aplicador no viajan al runtime (24-10-2026, revision O5).
# El runtime no los importa (la cadena de main.py la comprueba
# test_ci.py::test_el_runtime_no_importa_lo_que_no_viaja), y servidor.py
# explica por que no pueden estar ahi: aprobar es un acto humano y el
# aplicador escribe en IAM, en el mismo proceso que lee texto no confiable.
# cli.py y huella.py tampoco los importa (decision de Mateo, 24-10-2026): el
# CLI es la entrada local y la huella solo la usan aprobar y el aplicador.
# Lo que no se ejecuta en el runtime no tiene por que viajar a el.
for m in $FUERA; do
    rm "$DESTINO/paquete/agente_iam/$m"
done
# main.py es el entrypoint del runtime; las Lambdas arrancan en su manejador
# (agente_iam.aprobar y agente_iam.aplicador).
if [ "$DESTINO_PAQUETE" = runtime ]; then
    cp main.py "$DESTINO/paquete/"
fi
mkdir -p "$DESTINO/paquete/catalogo"
cp "$CATALOGO"/*.json "$DESTINO/paquete/catalogo/"
# Con que catalogo juzgara el paquete: fecha de descarga y huella de cada uno.
{
    echo "# catalogo descargado el $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    ( cd "$DESTINO/paquete/catalogo" && sha256sum ./*.json )
} >> "$DESTINO/paquete/VERSIONES.txt"

# Bytecode de x86 dentro de un paquete aarch64.
find "$DESTINO/paquete" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$DESTINO/paquete" -name '*.pyc' -delete

# Permisos POSIX que exige el runtime: 755 directorios, 644 ficheros. Los
# ejecutables de dependencias (bin/) conservan el suyo.
find "$DESTINO/paquete" -type d -exec chmod 755 {} +
find "$DESTINO/paquete" -type f -not -path "*/bin/*" -exec chmod 644 {} +

echo "==> 6/6  Comprimiendo"
( cd "$DESTINO/paquete" && zip -qr "../$(basename "$PAQUETE")" . )

# Y se comprueba en el zip, no en la carpeta: es lo que se sube.
for m in $FUERA; do
    if "$VENV/python" -c 'import sys, zipfile; sys.exit(0 if ("agente_iam/" + sys.argv[2]) in zipfile.ZipFile(sys.argv[1]).namelist() else 1)' "$PAQUETE" "$m"; then
        echo "    El zip lleva agente_iam/$m, que no puede ir en el paquete $DESTINO_PAQUETE"; exit 1
    fi
done

# El otro sentido: lo que la Lambda necesita para arrancar tiene que ir. Un
# FUERA_* que borrara de mas daria un zip que solo falla en la nube. LLEVA lo
# fija el `case` (vacio en el runtime: el bucle no hace nada).
for m in $LLEVA; do
    if ! "$VENV/python" -c 'import sys, zipfile; sys.exit(0 if ("agente_iam/" + sys.argv[2]) in zipfile.ZipFile(sys.argv[1]).namelist() else 1)' "$PAQUETE" "$m"; then
        echo "    El zip NO lleva agente_iam/$m, que la Lambda de $DESTINO_PAQUETE necesita"; exit 1
    fi
done

# Los limites del runtime son 250 MB comprimido y 750 MB sin comprimir; los de
# la Lambda, 250 MB sin comprimir. No se pueden ampliar. Mejor enterarse aqui
# que en el CreateAgentRuntime o el CreateFunction.
comprimido=$(du -m "$PAQUETE" | cut -f1)
plano=$(du -sm "$DESTINO/paquete" | cut -f1)
echo
echo "    $PAQUETE"
echo "    comprimido: ${comprimido} MB (limite 250)"
echo "    plano:      ${plano} MB (limite ${LIMITE_PLANO})"
[ "$comprimido" -lt 250 ] || { echo "    EXCEDE el limite comprimido"; exit 1; }
[ "$plano" -lt "$LIMITE_PLANO" ] || { echo "    EXCEDE el limite plano"; exit 1; }

echo
echo "Comprobacion rapida de que es de verdad ARM:"
find "$DESTINO/paquete" -name '_pydantic_core*.so' -exec file -b {} \; | cut -d, -f2

if [ -n "$PREFIJO_S3" ]; then
    # La clave con la que se sube a S3: lleva la huella del zip, asi que un
    # zip distinto es siempre una clave distinta y Lambda no mezcla versiones.
    huella_zip=$(sha256sum "$PAQUETE" | cut -c1-12)
    echo
    echo "Clave S3 para subirlo:"
    echo "    agente-iam/${PREFIJO_S3}-${huella_zip}.zip"
fi
