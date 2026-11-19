#!/usr/bin/env bash
#
# Corre un tipo de tests y guarda la evidencia fuera de git.
#
#   scripts/pruebas.sh unitarios      sin red; en cada commit
#   scripts/pruebas.sh seguridad      controles y secretos; en cada commit
#   scripts/pruebas.sh funcionales    contra la cuenta real; solo si se pide
#
# Lo que venga detras se pasa a pytest (por ejemplo: -m "not bedrock").
#
# Cada ejecucion deja en evidencias/<tipo>/<fecha>/ (ignorada por git):
#   junit.xml     el resultado, en el formato que leen GitHub Actions y otros
#   salida.txt    la consola completa
#   entorno.txt   commit, python, dependencias y, en funcionales, el perfil
# y los funcionales, ademas, los registros de solicitudes de esa ejecucion
# y la salida de cada intake. Llevan ARNs reales: por eso no van a git.
#
# Los funcionales sin la puerta abierta (tests/puerta.py) salen saltados y
# con el motivo; para abrirla:
#   AGENTE_IAM_FUNCIONALES=si scripts/pruebas.sh funcionales
#
# En CI: PYTHON=python scripts/pruebas.sh unitarios, y subir evidencias/
# como artifact.
#
set -euo pipefail
cd "$(dirname "$0")/.."

TIPO="${1:-}"
case "$TIPO" in
  unitarios|seguridad|funcionales) shift ;;
  *) sed -n '3,9p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac

PYTHON="${PYTHON:-./.venv/bin/python}"
SELLO="$(date -u +%Y-%m-%d_%H%M%SZ)"
EVIDENCIA="evidencias/$TIPO/$SELLO"
mkdir -p "$EVIDENCIA"

{
  echo "tipo:      $TIPO"
  echo "fecha_utc: $SELLO"
  echo "commit:    $(git rev-parse --short HEAD 2>/dev/null || echo '?')$(git diff --quiet HEAD 2>/dev/null || echo ' (con cambios sin commitear)')"
  echo "python:    $("$PYTHON" --version 2>&1)"
  if [ "$TIPO" = funcionales ]; then
    # Nunca las claves: solo que perfil y region se pidieron.
    echo "puerta:    AGENTE_IAM_FUNCIONALES=${AGENTE_IAM_FUNCIONALES:-(sin poner)}"
    echo "perfil:    ${AWS_PROFILE:-(sin poner)}"
    echo "region:    ${AWS_REGION:-(por defecto)}"
  fi
  echo
  echo "dependencias:"
  "$PYTHON" -m pip freeze 2>/dev/null | sed 's/^/  /'
} > "$EVIDENCIA/entorno.txt"

# tests/funcionales/conftest.py escribe aqui los registros (nunca en solicitudes/).
export DIR_EVIDENCIA="$PWD/$EVIDENCIA"

set +e
"$PYTHON" -m pytest "tests/$TIPO" -q -rs \
  --junitxml="$EVIDENCIA/junit.xml" -o junit_suite_name="$TIPO" "$@" 2>&1 \
  | tee "$EVIDENCIA/salida.txt"
CODIGO="${PIPESTATUS[0]}"

# Unitarios, ademas de los tests (Fase 13): analisis estatico de
# correccion. ruff busca errores sin ejecutar (nombres sin definir, imports
# sin usar, trampas conocidas); mypy comprueba los tipos (mypy.ini).
if [ "$TIPO" = unitarios ]; then
  echo
  echo "==> Analisis estatico: ruff"
  "$PYTHON" -m ruff check . 2>&1 | tee "$EVIDENCIA/ruff.txt"
  RUFF="${PIPESTATUS[0]}"

  echo
  echo "==> Tipos: mypy"
  "$PYTHON" -m mypy 2>&1 | tee "$EVIDENCIA/mypy.txt"
  MYPY="${PIPESTATUS[0]}"

  echo "pytest: exit $CODIGO   ruff: exit $RUFF   mypy: exit $MYPY" \
    | tee -a "$EVIDENCIA/salida.txt"
  for c in "$RUFF" "$MYPY"; do
    if [ "$CODIGO" -eq 0 ] && [ "$c" -ne 0 ]; then CODIGO="$c"; fi
  done
fi

# Seguridad, ademas de los tests (Fase 12): analisis estatico del codigo y
# dependencias con vulnerabilidades conocidas. Cada uno deja su informe en
# la evidencia y, si falla, la ejecucion entera falla. pip-audit necesita
# red (instala los requirements en un entorno aparte y consulta la base de
# vulnerabilidades); por eso no esta en el pre-commit.
if [ "$TIPO" = seguridad ]; then
  echo
  echo "==> SAST: bandit"
  "$PYTHON" -m bandit -r agente_iam main.py scripts -q \
    -f txt -o "$EVIDENCIA/bandit.txt"
  BANDIT="$?"
  cat "$EVIDENCIA/bandit.txt"

  echo
  echo "==> Dependencias: pip-audit"
  # Sobre constraints.txt, las versiones EXACTAS que se instalan (Fase 13).
  # Con -r requirements.txt, pip-audit resolvia por su cuenta la ultima
  # version de cada transitiva y revisaba paquetes que no usamos: el
  # 22-10-2026 daba "sin vulnerabilidades" mientras el .venv probado tenia
  # pyjwt, urllib3, certifi, mcp y opentelemetry-api vulnerables.
  # --no-deps: constraints.txt ya es el cierre completo, no hay que resolver.
  # Por consola y no con -o: sin hallazgos, -o no escribe nada.
  "$PYTHON" -m pip_audit -r constraints.txt --no-deps \
    --progress-spinner off 2>&1 | tee "$EVIDENCIA/pip-audit.txt"
  AUDIT="${PIPESTATUS[0]}"

  echo
  echo "==> Plantillas de CloudFormation: cfn-lint"
  # Fase 15: valida infra/cfn/*.yaml contra la especificacion de cada
  # recurso (propiedades, tipos, referencias). Sin red.
  # cfn-lint no trae __main__: se llama a su punto de entrada.
  "$PYTHON" -c "import sys; from cfnlint.runner import main; sys.exit(main())" \
    infra/cfn/*.yaml 2>&1 | tee "$EVIDENCIA/cfn-lint.txt"
  CFNLINT="${PIPESTATUS[0]}"

  echo
  echo "pytest: exit $CODIGO   bandit: exit $BANDIT   pip-audit: exit $AUDIT   cfn-lint: exit $CFNLINT" \
    | tee -a "$EVIDENCIA/salida.txt"
  for c in "$BANDIT" "$AUDIT" "$CFNLINT"; do
    if [ "$CODIGO" -eq 0 ] && [ "$c" -ne 0 ]; then CODIGO="$c"; fi
  done
fi
set -e

echo
echo "Evidencia en $EVIDENCIA (exit $CODIGO)"
exit "$CODIGO"
