# Formulario web, rol por persona con caducidad y aviso por correo (Fase 23) - plan de implementacion

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** que cualquier persona de Identity Center pida un permiso desde una pagina web, que el permiso se materialice
en un rol creado para ella (techo como boundary, confianza solo para su `sub`, vida de 1 a 12 horas con corte exacto),
que lo asuma canjeando su token de identidad de Cognito con `AssumeRoleWithWebIdentity`, y que reciba un correo con la
decision.

**Architecture:** tres bloques que se apoyan, en este orden y sin empezar el siguiente hasta medir el anterior.
(1) Backend: el servidor del runtime acepta un unico contrato (`SolicitudWeb`: sin ARN declarado, con `horas`,
`correo_aviso` y `clave_envio`), pone el beneficiario desde el JWT, genera el `solicitud_id`, comprueba el tope y la
redundancia contra los roles de persona vigentes, y el aplicador crea el rol por persona (modulo nuevo
`agente_iam/personas.py`, compartido por runtime y aplicador). El modo actual (adjuntar a un principal con techo) queda
solo en el CLI de desarrollo sobre disco. Infra: proveedor OIDC del pool en `acceso.yaml`, permisos del aplicador en
`base.yaml`, `LimiteSistema` y el rol de despliegue en `arranque.yaml` (un solo cambio del administrador que cubre los
tres bloques), parametros nuevos en `runtime.yaml`. (2) Web: pila `web.yaml` (S3 privado tras CloudFront con OAC y CSP),
cliente de Cognito `agente-iam-web`, pagina estatica sin dependencias (`web/`), `scripts/construir_web.py` genera la
configuracion desde `config.py` y las salidas de las pilas. (3) Correo: Lambda `agente-iam-avisos`
(`agente_iam/avisos.py`, mismo zip que el aplicador, rol propio) disparada por el stream con filtro de estados finales,
que manda con SES un cuerpo fijo.

**Tech Stack:** Python 3.12 del `.venv`, boto3/botocore 1.43.82 (`Stubber`), pydantic 2.13.4, pytest, CloudFormation
YAML leido con `yaml.safe_load` y validado con cfn-lint, Lambda arm64 `python3.12`, AgentCore Runtime con
`customJWTAuthorizer`, Cognito (PKCE), STS `AssumeRoleWithWebIdentity`, CloudFront con OAC, SES (modo inicial), HTML,
CSS y JavaScript sin framework.

**Spec:** `docs/superpowers/specs/2026-10-26-formulario-web-y-rol-por-persona-design.md` (aprobado por Mateo el
26-10-2026). Mediciones de partida: `docs/MEDICIONES.md` N (la confianza y el canje, medidos), K.1 y §H (lecciones
antes de tocar `runtime.yaml` y `base.yaml`), L y M (el circuito actual). Contexto: `CONTEXTO.md` §2, §5, §6, §7, §11.

## Global Constraints

- Ningun subagente llama a AWS ni escribe en la cuenta: todo se prueba sin red (`tests/conftest.py` lo vigila, y
  `Stubber` responde antes). Cada escritura en la cuenta (change set, zip, rol, identidad SES) la hace Claude con el si
  explicito de Mateo para esa accion, ensenando antes el change set.
- Ningun subagente hace commits: Claude revisa cada diff y Mateo pide los commits. Cada tarea toca SOLO los ficheros de
  su lista; tareas marcadas "paralelas" editan ficheros distintos a la vez.
- Cada subagente corre los ficheros de tests de su tarea mas `./.venv/bin/ruff check <sus ficheros>` y, si toca
  `agente_iam/` o `scripts/`, `./.venv/bin/mypy agente_iam`. La suite completa (`./.venv/bin/python -m pytest tests/ -q`)
  la corre Claude al cerrar cada tarea. Un fallo en `tests/unitarios/test_documentacion.py` por un fichero nuevo que
  aun no esta en CONTEXTO no es de la tarea: se anota y lo cierra la tarea de documentacion del bloque. Lo mismo con
  `tests/seguridad/test_ci.py::test_cada_modulo_esta_en_un_lado_del_paquete_del_runtime` y
  `..._del_aplicador` entre la tarea 1 y las tareas 6 y 8: se ponen en verde solos cuando `servidor.py`/`orquestador.py` y
  `aplicador.py` importan `personas.py`.
- Dos tokens, dos usos, nunca cruzados: el `access_token` (claims `username`, `client_id`, `sub`) es el que se manda al
  runtime con `Authorization: Bearer`; el `id_token` (claims `aud`, `sub`, `cognito:username`) es el UNICO que vale para
  `AssumeRoleWithWebIdentity` (MEDICIONES N.2, fila 2). Vale para `solicitar.py` y para `app.js`.
- Estado al 26-10-2026 22:40 UTC: las tareas 1 y 3 ya estan hechas (ficheros en el arbol, sin commit); los
  implementadores de las demas no las reescriben.
- Codigo, comentarios y docstrings en espanol sin acentos ni enes (como el resto del repositorio). Sin guion largo en
  ningun sitio (`tests/seguridad/test_plantillas_cfn.py` lo comprueba en las plantillas). Cada modulo explica el
  PORQUE en su docstring.
- En lo versionado va la cuenta `111122223333`; nunca la real, ni ids de pool o de cliente, ni correos, ni `sub`.
  Las plantillas reciben esos datos por parametro sin valor por defecto.
- Plantillas YAML sin etiquetas cortas (`Ref:`, `Fn::Sub:`, `Fn::GetAtt:`, `Fn::If:`), region `us-east-1`, recursos
  del sistema con prefijo `agente-iam-` o `AgenteIAM-`, etiqueta `proyecto: agente-iam`.
- Contrato del servidor (diseno 5.1): `servicio`, `recurso`, `tipo_acceso` (`lectura|escritura|administracion`),
  `region`, `horas` (entero de 1 a 12), `correo_aviso`, `justificacion` (1 a 1000, sin control salvo `\n`),
  `clave_envio` (UUID). `principal_arn_declarado` y `solicitud_id` en el payload se rechazan por forma.
- `solicitud_id` = `req-<AAAAMMDD UTC>-<8 primeros hex de sha256(clave_envio)>`. Nombre del rol =
  `agente-iam-persona-<usuario normalizado y recortado>-<solicitud_id>`, ruta `/agente-iam/personas/`, 64 caracteres
  como maximo. Etiquetas del rol: `agente-iam-solicitud`, `agente-iam-persona`, `agente-iam-sub`, `agente-iam-vence`.
- Tope: 5 roles de persona vigentes por persona (`config.MAX_ROLES_VIGENTES_POR_PERSONA`). `vence` se calcula al
  aplicar (hora de aplicacion mas `horas`), en ISO 8601 UTC con segundos y `Z` (`2026-10-26T15:04:51Z`), y va en la
  confianza, en cada `Allow` de la politica y en la etiqueta `agente-iam-vence`. `MaxSessionDuration` = `horas * 3600`.
- La confianza es la medida en MEDICIONES N.1: `Principal.Federated` = proveedor OIDC del pool,
  `sts:AssumeRoleWithWebIdentity`, `StringEquals` `<host>/<pool>:aud` = lista de clientes y `<host>/<pool>:sub` = el
  `sub` del registro (`ejecutado_por.sub`), `DateLessThan aws:CurrentTime` = `vence`.
- La redundancia y el tope se miden solo contra los roles de persona vigentes (decision de Mateo, 5.4). Si la lectura
  de roles falla en la redundancia, se declara `no_comprobada` y la solicitud sigue como acceso nuevo.
- La pagina no guarda tokens fuera de la memoria de la pestana (ni `localStorage`, ni `sessionStorage`, ni cookies) y
  pinta con `textContent`, nunca `innerHTML`. El correo lleva solo id y estado (y, en `aplicada`, ARN del rol y
  `vence`); nunca politica, justificacion ni aprobador.

## Review Focus

Entradas que el diseno implica y que ninguna medicion previa ejercita; cada una tiene su test en la tarea que la posee.

1. Doble clic o reintento con la misma `clave_envio`: el servidor forma el mismo id y devuelve `registro_existente`
   con ese id; nunca dos registros ni dos roles (tarea 6).
2. Un nombre de usuario largo (correo) o con caracteres fuera del alfabeto de IAM: el nombre del rol cabe en 64, solo
   lleva `[a-z0-9+=,.@_-]` y es determinista; dos usuarios distintos no colisionan si difieren dentro del recorte
   (tarea 1).
3. El aplicador reintenta despues de crear la politica y antes de crear el rol: `vence` sale de la `Description` de la
   politica ya creada, el documento coincide y la corrida converge en vez de parar por "documento distinto" (tarea 8).
4. Un `Allow` que ya lleva `Condition` (la S5 `aws:ResourceAccount`): el vencimiento se anade sin perder la condicion
   existente y sin tocar los `Deny` (tarea 1).
5. Un token sin `sub` o sin persona: el servidor rechaza antes del modelo (tarea 6). Que `client_id` sea uno de los
   clientes admitidos lo garantiza el autorizador JWT (`allowedClients`); el aplicador lo repite contra
   `CLIENTES_COGNITO` como defensa en profundidad antes de escribir la confianza (tarea 8).
6. Un evento del stream que modifica otro atributo sin cambiar `estado`: la Lambda de avisos no manda un segundo correo
   (tarea 18).

---

# Bloque 1: rol por persona con caducidad (backend)

### Tarea 1: `agente_iam/personas.py`, las piezas puras (HECHA el 26-10-2026)

**Files:**
- Create: `agente_iam/personas.py`
- Test: `tests/unitarios/test_personas.py`
- Modify: `scripts/empaquetar.sh` (`personas.py` entra en `FUERA_DE_LA_APROBACION`: `aprobar.py` no lo importa y
  `test_ci.py` exige que cada modulo este en un lado del zip de la aprobacion)

**Interfaces:**
- Consumes: `agente_iam.config.NOMBRE_TECHO`, `AWS_REGION`.
- Produces (lo usan las tareas 4 a 8 y 11):
  - `PATH_PERSONAS = "/agente-iam/personas/"`, `PREFIJO_ROL = "agente-iam-persona-"`, `TAG_SOLICITUD =
    "agente-iam-solicitud"`, `TAG_PERSONA = "agente-iam-persona"`, `TAG_SUB = "agente-iam-sub"`, `TAG_VENCE =
    "agente-iam-vence"`, `HORAS_MIN = 1`, `HORAS_MAX = 12`, `FORMATO_VENCE = "%Y-%m-%dT%H:%M:%SZ"`.
  - `normalizar_usuario(usuario: str) -> str`: NFKC + `casefold` (igual que `aprobar._misma_persona`), y todo caracter
    fuera de `[a-z0-9+=,.@_-]` pasa a `-`.
  - `nombre_de_rol(usuario: str, solicitud_id: str) -> str`: `PREFIJO_ROL + usuario_recortado + "-" +
    solicitud_id.lower()`, recortando el usuario normalizado para que el total no pase de 64.
  - `arn_de_rol(cuenta: str, usuario: str, solicitud_id: str) -> str` =
    `arn:aws:iam::<cuenta>:role/agente-iam/personas/<nombre>`.
  - `id_de_solicitud(clave_envio: str, ahora: datetime) -> str` = `req-<AAAAMMDD>-<sha256(clave_envio)[:8]>`.
  - `vence_desde(ahora: datetime, horas: int) -> str` (ISO con `FORMATO_VENCE`; `ValueError` fuera de 1..12).
  - `documento_con_vencimiento(documento: dict, vence: str) -> dict`: copia del documento con
    `"DateLessThan": {"aws:CurrentTime": vence}` fusionado en el `Condition` de cada `Allow`; los `Deny` intactos; no
    muta la entrada; si un `Allow` ya tiene `DateLessThan` con otra clave, la conserva y anade la nuestra.
  - `emisor(pool_id: str, region: str = AWS_REGION) -> str` = `cognito-idp.<region>.amazonaws.com/<pool_id>`.
  - `proveedor_oidc(cuenta: str, pool_id: str, region: str = AWS_REGION) -> str` =
    `arn:aws:iam::<cuenta>:oidc-provider/<emisor>`.
  - `confianza(cuenta: str, pool_id: str, clientes: Sequence[str], sub: str, vence: str, region: str = AWS_REGION)
    -> dict`: el documento exacto del diseno 5.2, con `:aud` como lista de los clientes (uno o dos).

- [ ] **Paso 1: escribir los tests que fallan**

```python
# tests/unitarios/test_personas.py
from datetime import datetime, timezone
import json, re
import pytest
from agente_iam import personas

AHORA = datetime(2026, 10, 26, 3, 4, 51, tzinfo=timezone.utc)

def test_el_id_sale_de_la_fecha_y_de_la_clave_y_es_repetible():
    a = personas.id_de_solicitud("1b4e28ba-2fa1-11d2-883f-0016d3cca427", AHORA)
    assert re.fullmatch(r"req-20261026-[0-9a-f]{8}", a)
    assert a == personas.id_de_solicitud("1b4e28ba-2fa1-11d2-883f-0016d3cca427", AHORA)
    assert a != personas.id_de_solicitud("otra-clave", AHORA)

def test_el_nombre_del_rol_cabe_en_64_y_es_determinista():
    nombre = personas.nombre_de_rol("Solicitante.Demo", "req-20261026-ab12cd34")
    assert nombre == "agente-iam-persona-solicitante.demo-req-20261026-ab12cd34"
    largo = personas.nombre_de_rol("persona.con.un.correo.muy.largo@ejemplo-empresa.com", "req-20261026-ab12cd34")
    assert len(largo) <= 64
    assert largo.startswith("agente-iam-persona-persona.con.un.correo")
    assert largo.endswith("-req-20261026-ab12cd34")
    assert re.fullmatch(r"[a-z0-9+=,.@_-]{1,64}", largo)

def test_normalizar_usuario_quita_lo_que_iam_no_admite():
    assert personas.normalizar_usuario("Ana Gomez/ñ") == "ana-gomez--"
    assert personas.normalizar_usuario("ＡNA") == "ana"  # NFKC

def test_vence_desde_formatea_en_utc_con_z_y_acota_las_horas():
    assert personas.vence_desde(AHORA, 12) == "2026-10-26T15:04:51Z"
    for horas in (0, 13):
        with pytest.raises(ValueError):
            personas.vence_desde(AHORA, horas)

def test_el_vencimiento_entra_en_cada_allow_y_respeta_la_s5_y_los_deny():
    doc = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::b"],
         "Condition": {"StringEquals": {"aws:ResourceAccount": "${aws:PrincipalAccount}"}}},
        {"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": ["*"]},
    ]}
    copia = json.loads(json.dumps(doc))
    salida = personas.documento_con_vencimiento(doc, "2026-10-26T15:04:51Z")
    assert doc == copia  # no muta
    allow, deny = salida["Statement"]
    assert allow["Condition"] == {
        "StringEquals": {"aws:ResourceAccount": "${aws:PrincipalAccount}"},
        "DateLessThan": {"aws:CurrentTime": "2026-10-26T15:04:51Z"},
    }
    assert "Condition" not in deny

def test_la_confianza_es_la_medida_en_mediciones_n():
    doc = personas.confianza("111122223333", "us-east-1_AbC123", ["cli26", "web26"], "sub-1", "2026-10-26T15:04:51Z")
    [st] = doc["Statement"]
    emisor = "cognito-idp.us-east-1.amazonaws.com/us-east-1_AbC123"
    assert st["Principal"] == {"Federated": f"arn:aws:iam::111122223333:oidc-provider/{emisor}"}
    assert st["Action"] == "sts:AssumeRoleWithWebIdentity"
    assert st["Condition"]["StringEquals"] == {f"{emisor}:aud": ["cli26", "web26"], f"{emisor}:sub": "sub-1"}
    assert st["Condition"]["DateLessThan"] == {"aws:CurrentTime": "2026-10-26T15:04:51Z"}
    assert personas.arn_de_rol("111122223333", "x", "req-1") == "arn:aws:iam::111122223333:role/agente-iam/personas/agente-iam-persona-x-req-1"
```

- [ ] **Paso 2: correr y ver que fallan**

Run: `./.venv/bin/python -m pytest tests/unitarios/test_personas.py -q`. Expected: `ModuleNotFoundError: agente_iam.personas`.

- [ ] **Paso 3: escribir `agente_iam/personas.py` con las firmas de arriba**

Docstring: por que el modulo existe (lo comparten runtime y aplicador sin importar el agente ni escribir en IAM; el
nombre y el id son deterministas porque de ellos depende la idempotencia, igual que `aplicador.nombre_de_politica`),
y que la forma de la confianza esta medida (MEDICIONES N). Sin boto3 en esta tarea (las funciones con red van en la 4).

- [ ] **Paso 4: verde, ruff y mypy**

Run: `./.venv/bin/python -m pytest tests/unitarios/test_personas.py -q && ./.venv/bin/ruff check agente_iam/personas.py tests/unitarios/test_personas.py && ./.venv/bin/mypy agente_iam`.

### Tarea 2: el contrato (`models.py`) (HECHA el 26-10-2026)

**Files:**
- Modify: `agente_iam/models.py` (`SolicitudEstructurada`, `IdentidadVerificada`, nuevo `PersonaDelToken`, nuevo
  `SolicitudWeb`)
- Modify: `tests/unitarios/test_modelos.py`
- Modify: `tests/dobles.py` (anadir `_solicitud_persona`)

**Interfaces:**
- Produces:
  - `PersonaDelToken(BaseModel)`: `usuario: str` (`min_length=1, max_length=128`, sin control: reutiliza
    `_sin_caracteres_de_control`), `sub: str` (`pattern=r"^[A-Za-z0-9-]{1,64}$"`), `client_id: str | None`
    (`pattern=r"^[a-z0-9]{26}$"`).
  - `SolicitudWeb(BaseModel)`, `extra="forbid"`: `clave_envio: str` (`pattern=r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"`, la forma de un UUID sin exigir version),
    `campos: CamposEstructurados`, `horas: int = Field(ge=1, le=12, strict=True)`, `correo_aviso: str`
    (`pattern=r"^[^@\s]{1,64}@[^@\s]{1,189}$"`, `max_length=254`), `justificacion` (mismo validador que hoy).
  - `SolicitudEstructurada` gana: `principal_arn_declarado: str | None = None`, `persona: PersonaDelToken | None =
    None`, `horas: int | None = Field(default=None, ge=1, le=12)`, `correo_aviso: str | None = None` (mismo patron),
    `clave_envio: str | None = None`; `model_validator(mode="after")` exige exactamente uno de `principal_arn_declarado`
    o `persona`, y `horas` presente si y solo si hay `persona`; `correo_aviso` y `clave_envio` solo con `persona`.
    Propiedad `modo -> Literal["principal_existente", "rol_por_persona"]`.
  - `IdentidadVerificada` gana `modo: Literal["principal_existente", "rol_por_persona"] = "principal_existente"`,
    `persona: PersonaDelToken | None = None`, `horas: int | None = None`.
  - `Modo = Literal["principal_existente", "rol_por_persona"]` exportado.
  - `tests/dobles.py`: `_solicitud_persona(servicio="s3", recurso="finanzas-demo-111122223333", tipo="lectura", *,
    solicitud_id="req-20261026-ab12cd34", usuario="solicitante.demo", sub="sub-1234", client_id="a"*26, horas=4,
    correo="persona@example.com", justificacion="prueba") -> SolicitudEstructurada`.

- [ ] **Paso 1: tests que fallan** (en `test_modelos.py`, al final)

```python
def test_solicitud_web_rechaza_arn_declarado_e_id_por_forma():
    base = {"clave_envio": "1b4e28ba-2fa1-41d2-883f-0016d3cca427", "campos": {...s3 lectura...},
            "horas": 4, "correo_aviso": "p@example.com", "justificacion": "x"}
    SolicitudWeb.model_validate(base)
    for extra in ({"principal_arn_declarado": "arn:aws:iam::111122223333:role/x"}, {"solicitud_id": "req-1"}):
        with pytest.raises(ValidationError):
            SolicitudWeb.model_validate({**base, **extra})

@pytest.mark.parametrize("horas", [0, 13, "4", 4.0])
def test_horas_solo_entero_de_1_a_12(horas): ...  # ValidationError

@pytest.mark.parametrize("correo", ["sin-arroba", "a@b c", "a@", "@b"])
def test_correo_aviso_con_forma(correo): ...  # ValidationError

def test_solicitud_estructurada_exige_un_modo_y_solo_uno():
    # ni ARN ni persona -> error; los dos -> error; persona sin horas -> error; ARN con horas -> error
    # persona con horas -> ok y .modo == "rol_por_persona"; ARN solo -> .modo == "principal_existente"

def test_identidad_verificada_por_defecto_es_principal_existente(): ...
```

- [ ] **Paso 2: rojo.** Run: `./.venv/bin/python -m pytest tests/unitarios/test_modelos.py -q`.

- [ ] **Paso 3: implementar en `models.py` y `dobles.py`.** Los tests existentes de `test_modelos.py` que validan el
  payload de hoy (con `principal_arn_declarado`) siguen pasando sin tocarlos: es el modo del CLI.

- [ ] **Paso 4: verde.** Run: `./.venv/bin/python -m pytest tests/unitarios/test_modelos.py tests/unitarios -q`
  (la suite unitaria entera, porque `SolicitudEstructurada` la usan muchos tests; nada debe romperse).

### Tarea 3: configuracion y la region como lista cerrada (`config.py`, `coherencia.py`) (HECHA el 26-10-2026)

**Files:**
- Modify: `agente_iam/config.py`
- Modify: `agente_iam/coherencia.py` (`chequeos_formulario`)
- Test: `tests/seguridad/test_barandas.py` (anadir), `tests/unitarios/test_posteriores.py` (anadir)

**Interfaces:**
- Produces: `config.MAX_ROLES_VIGENTES_POR_PERSONA = 5`; `config.REGIONES_PERMITIDAS = ["us-east-1"]` (la SCP de la
  cuenta solo deja `us-east-1`; es la lista cerrada que la pagina copia); `config.POOL_ID =
  os.getenv("AGENTE_IAM_POOL_ID", "")`; `config.CLIENTES_COGNITO: tuple[str, ...]` = los ids separados por coma en
  `AGENTE_IAM_CLIENTES` (vacio por defecto). `chequeos_formulario` anade el motivo
  `"La region '<r>' no esta entre las regiones permitidas por este sistema"` si `campos.region` no esta en la lista.

- [ ] **Paso 1: tests.** En `test_posteriores.py`: `test_una_region_fuera_de_la_lista_se_rechaza_en_el_formulario`
  (`chequeos_formulario(CamposEstructurados(servicio="s3", recurso="b", tipo_acceso="lectura", region="eu-west-1"))`
  devuelve un motivo que nombra `eu-west-1`; con `us-east-1` no). En `test_barandas.py`:
  `test_las_constantes_de_persona_tienen_los_valores_del_diseno` (tope 5; regiones == ["us-east-1"]; `CLIENTES_COGNITO`
  es tupla y con `AGENTE_IAM_CLIENTES="a,b"` recargando el modulo da `("a","b")`).
- [ ] **Paso 2: rojo.** `./.venv/bin/python -m pytest tests/unitarios/test_posteriores.py tests/seguridad/test_barandas.py -q`.
- [ ] **Paso 3: implementar.** Comentario en `config.py` de cada constante con su porque (cuotas de IAM, SCP).
- [ ] **Paso 4: verde**, y `./.venv/bin/python -m pytest tests/unitarios tests/seguridad -q` porque `revalidar` usa
  `chequeos_formulario` y los registros de los tests llevan `us-east-1`.

### Tarea 4: roles vigentes y redundancia por persona (`personas.py`, `simulacion.py`) (HECHA el 26-10-2026)

**Files:**
- Modify: `agente_iam/personas.py` (anadir las funciones con red)
- Modify: `agente_iam/simulacion.py` (anadir `redundancia_persona`)
- Test: `tests/unitarios/test_personas.py` (anadir), `tests/unitarios/test_simulacion.py` (anadir)

**Interfaces:**
- Produces:
  - `personas.roles_vigentes(usuario: str, ahora: datetime, iam=None) -> list[dict]`: `ListRoles(PathPrefix=
    PATH_PERSONAS)` paginado; de los devueltos solo pide `ListRoleTags(RoleName)` a los que empiezan por el prefijo
    que `nombre_de_rol` daria a este usuario (`PREFIJO_ROL + usuario normalizado y recortado + "-"`), para no pedir las
    etiquetas de los roles de todas las personas; las etiquetas siguen siendo la fuente de verdad: devuelve los que
    tienen `TAG_PERSONA == normalizar_usuario(usuario)` y `TAG_VENCE` posterior a `ahora`, cada uno como `{"arn",
    "nombre", "vence", "solicitud_id"}`. `iam` es el cliente, inyectable: por defecto el cliente cacheado del modulo
    (como `identidad.py`); el aplicador (tarea 8) le pasa SIEMPRE su propio `_iam()` para que el `Stubber` unico de
    `test_aplicador.py` cubra `ListRoles`/`ListRoleTags`/`GetRole`.
  - `personas.cuenta_actual(sts=None) -> str`: `GetCallerIdentity().Account`, cacheado en el modulo.
  - `simulacion._TIPO_DE_CLAVE` gana `"aws:CurrentTime": "date"`. MEDIDO (MEDICIONES A.3): el simulador NO tiene
    valor implicito para esa clave; sin aportarla, toda politica de un rol de persona (que lleva `DateLessThan
    aws:CurrentTime`) sale `implicitDeny` y la redundancia seria siempre "acceso nuevo". `eficacia` NO la aporta (la
    propuesta del modelo no lleva vencimiento; se anade al aplicar).
  - `simulacion.redundancia_persona(usuario: str, documento: dict, contexto: dict | None, ahora: datetime) -> dict`:
    `{"ya_tenia": [...], "acceso_nuevo": [...], "es_totalmente_redundante": bool, "roles_comparados": [arns],
    "no_comprobada": str | None}`. Para cada rol vigente llama a `redundancia(arn, documento, contexto_del_rol)` con
    `contexto_del_rol = {**contexto, "aws:CurrentTime": ahora.strftime(FORMATO_VENCE), "aws:PrincipalArn": arn}` (el
    ARN del rol que se simula, no el del rol previsto) y une `ya_tenia`; redundante si todas las acciones del documento
    estan en la union. Si `roles_vigentes` lanza
    `ClientError`/`BotoCoreError`, devuelve todo como acceso nuevo con `no_comprobada` = el mensaje (diseno 5.4.3).
    Sin roles vigentes: `roles_comparados == []`, nada redundante.

- [ ] **Paso 1: tests con `Stubber`** (patron de `test_identidad.py`): un `ListRoles` con tres roles en la ruta (uno de
  la persona vigente, uno de la persona vencido, uno de otra persona), tres `ListRoleTags`, y comprobar que
  `roles_vigentes` devuelve solo el primero con su `vence` y `solicitud_id`; con tres roles en la ruta de los que solo
  dos llevan el prefijo del usuario, solo dos `ListRoleTags` (el `Stubber` falla si se pide un tercero); `cuenta_actual`
  cachea (segunda llamada sin `GetCallerIdentity`); `redundancia_persona` pasa a `redundancia` un contexto con
  `aws:CurrentTime` (formato `FORMATO_VENCE`) y `aws:PrincipalArn` = el ARN del rol vigente (comprobado con un doble
  que captura los argumentos); `_context_entries({"aws:CurrentTime": "2026-10-26T15:04:51Z"})` produce una entrada de
  `ContextKeyType` `date`; `eficacia` con un documento sin vencimiento no manda `aws:CurrentTime`; `redundancia_persona` sin roles -> no redundante y `roles_comparados == []`; con un rol que ya
  permite todo -> redundante; `ListRoles` que lanza `AccessDenied` -> `no_comprobada` no vacio y `acceso_nuevo` = todas.
  Para `redundancia_persona` sustituye `simulacion.redundancia` y `personas.roles_vigentes` con `monkeypatch`.
- [ ] **Paso 2: rojo. Paso 3: implementar. Paso 4: verde + ruff + mypy.**

### Tarea 5: el orquestador con los dos modos (`orquestador.py`) (HECHA el 26-10-2026)

**Files:**
- Modify: `agente_iam/orquestador.py` (`chequeos_previos`, `procesar`, `_contexto`, `_prompt`)
- Test: `tests/unitarios/test_rol_por_persona.py` (nuevo: el intake en modo persona, sin red)

**Interfaces:**
- Consumes: tareas 1 a 4.
- Produces: `orquestador.identidad_de_persona(sol: SolicitudEstructurada, cuenta: str) -> IdentidadVerificada` con
  `modo="rol_por_persona"`, `principal_arn=personas.arn_de_rol(cuenta, usuario, solicitud_id)`, `tipo="role"`,
  `existe=True` (documentar: en este modo `existe` significa "beneficiario verificado", por el token), `cuenta`,
  `principal_id=""`, `permissions_boundary=arn del techo`, `politicas_actuales=[]`, `detalle="rol por persona: se
  crea al aplicar con el techo como boundary; la persona la verifico el token"`, `persona`, `horas`.
  `chequeos_previos` en modo persona: no llama a `identidad.verificar`; cuenta `len(personas.roles_vigentes(usuario,
  ahora))` y si `>= MAX_ROLES_VIGENTES_POR_PERSONA` anade el motivo `f"La persona ya tiene {n} roles de persona vigentes
  (tope {MAX_ROLES_VIGENTES_POR_PERSONA}): espera a que venza alguno"` (la constante, no el literal). `procesar`: en modo persona la redundancia es `redundancia_persona(...)` y un
  `no_comprobada` entra en `veredicto["menores"]` como `WARNING` `REDUNDANCIA_NO_COMPROBADA`. `_prompt` anade en modo
  persona una linea fija tras los datos verificados: "El beneficiario es un rol que se creara al aplicar; su ARN es el
  de arriba y no debes nombrarlo en la politica."

- [ ] **Paso 1: tests** (sustituyendo con `monkeypatch` `orquestador.verificar`, `orquestador.construir_agente`,
  `orquestador.redundancia`, `orquestador.redundancia_persona`, `personas.roles_vigentes`, `personas.cuenta_actual`,
  como hace `test_errores.py`): `test_en_modo_persona_no_se_verifica_ningun_arn_y_la_identidad_es_el_rol_previsto`;
  `test_el_tope_de_roles_vigentes_rechaza_antes_del_modelo` (5 vigentes -> `rechazada_en_chequeos_previos`, el agente no
  se construye); `test_la_redundancia_por_persona_decide_el_estado` (redundante -> `redundante_no_requiere_cambio`;
  `no_comprobada` -> `propuesta` con el aviso); `test_el_modo_principal_existente_sigue_igual` (el camino de hoy con
  `_solicitud()` no toca `roles_vigentes`).
- [ ] **Paso 2: rojo. Paso 3: implementar. Paso 4: verde**, y la suite unitaria entera.

### Tarea 6: el servidor con un solo contrato (`servidor.py`) (HECHA el 26-10-2026)

**Files:**
- Modify: `agente_iam/servidor.py`
- Modify: `tests/unitarios/test_servidor.py`

**Interfaces:**
- Consumes: `SolicitudWeb`, `PersonaDelToken`, `personas.id_de_solicitud`.
- Produces: `CLAIMS_DEL_REGISTRO = ("sub", "username", "jti", "client_id")`; `_quien_invoco` graba `client_id`.
  `manejar(payload, context)`: (1) `SolicitudWeb.model_validate(payload)` -> `forma_invalida` con los campos (un
  `principal_arn_declarado` o `solicitud_id` sale como campo extra); (2) claims -> si `persona_de(claims)` es None o
  falta `sub`: `_error("sin_persona", detalle=<la constante que explique cual falto>)` sin registro ni modelo;
  (3) `solicitud_id = personas.id_de_solicitud(sol_web.clave_envio, datetime.now(UTC))`; (4) construye la
  `SolicitudEstructurada` con `persona=PersonaDelToken(usuario, sub, client_id)`; (5) `procesar`, `ejecutado_por`,
  `solicitante` y guardar como hoy; (6) la respuesta `procesada` anade `"solicitud_id"` y `"rol_previsto"`
  (`registro["identidad_verificada"]["principal_arn"]`); `registro_existente` devuelve el mismo `id`.

- [ ] **Paso 1: tests.** Reescribir `_payload()` a la forma web (sin ARN, con `clave_envio`, `horas`,
  `correo_aviso`). Estos diez tests existentes cambian de sentido y se reescriben, no se borran: los que hoy afirman
  que SIN JWT se guarda registro (`test_ejecutado_por_se_declara_no_determinable`,
  `test_el_runtime_graba_solicitante_sin_persona`, `test_sin_cabecera_no_hay_persona...`,
  `test_una_cabecera_que_no_es_un_jwt...`, `test_una_cabecera_que_no_es_texto...`, `test_username_sin_el_prefijo...`,
  `test_jwt_sin_claim_username...`) pasan a comprobar `codigo == "sin_persona"`, el detalle que explica cual de las tres
  cosas falto y `sin_efectos == []`; los del camino feliz (`test_una_solicitud_valida_se_procesa_y_se_guarda`,
  `test_un_registro_de_error_tambien_se_guarda`, `test_no_pisar_un_registro_existente...`) reciben
  `_Contexto(request_headers=...)` con `CLAIMS_OK`, que gana `"client_id": "a" * 26`. Nuevos: `test_el_arn_declarado_y_el_id_se_rechazan_por_forma`; `test_sin_sub_o_sin_persona_no_hay_
  registro_ni_modelo`; `test_el_id_lo_forma_el_servidor_desde_la_clave_y_se_repite` (dos llamadas con la misma clave:
  la segunda `registro_existente` con el mismo `id`, usando el almacen en disco de `tmp_path` como hoy);
  `test_la_respuesta_lleva_el_id_y_el_rol_previsto`; `test_el_client_id_se_graba_en_ejecutado_por`. Actualizar
  `test_el_detalle_nombra_los_campos_para_poder_corregir` (ahora `horas`, `correo_aviso`, `clave_envio`).
  Limite aceptado, escrito en el docstring de `manejar` y en ADR-004: `procesar` (el modelo, 30 a 90 s) corre ANTES de
  `guardar_propuesta`, asi que dos envios casi simultaneos con la misma clave gastan dos corridas y el segundo muere en
  `registro_existente`; el id es idempotente para el registro, no para el coste (el runtime no tiene `GetItem` a
  proposito: el intake no lee). La pagina deshabilita Enviar mientras hay una peticion en vuelo (tarea 14).
- [ ] **Paso 2: rojo. Paso 3: implementar. Paso 4: verde** + suite unitaria.

### Tarea 7: el CLI solo en modo principal existente, y el test de seguridad de los dos modos (`cli.py`) (HECHA el 26-10-2026)

**Files:**
- Modify: `agente_iam/cli.py`
- Modify: `tests/unitarios/test_cli.py`
- Create: `tests/seguridad/test_modos.py`

**Interfaces:**
- Produces: `cli.main` sale con 2 y el mensaje "El CLI de desarrollo solo tramita solicitudes con
  `principal_arn_declarado`; `horas`, `persona` y `correo_aviso` son del servidor con JWT" si el fichero trae
  `persona`, `horas`, `correo_aviso` o `clave_envio`, o no trae ARN.

- [ ] **Paso 1: tests.** `test_cli.py`: `test_el_cli_rechaza_horas_y_persona_con_2_sin_procesar`. `test_modos.py`
  (seguridad, sin red): `test_el_servidor_rechaza_el_arn_declarado_por_forma` (via `servidor.manejar`);
  `test_el_servidor_nunca_toma_el_beneficiario_del_payload` (un payload con `persona` dentro se rechaza por `extra`);
  `test_una_propuesta_sobre_la_ruta_de_personas_se_bloquea` (`chequeos_posteriores` con
  `arn:aws:iam::111122223333:role/agente-iam/personas/x` como recurso -> bloqueo por recurso del sistema);
  `test_la_lista_negra_cierra_toda_asuncion_de_roles` (las cuatro `sts:*` en `ACCIONES_PROHIBIDAS`);
  `test_el_techo_no_deja_a_un_rol_de_persona_tocar_roles_ni_asumir_otros` (sobre
  `infra/boundary-agente-iam-techo.json`: ningun `Allow` concede una accion `iam:*` de escritura, `iam:PassRole` ni
  `sts:AssumeRole*`; hoy solo `AutoservicioMinimoDelUsuario` y `sts:GetCallerIdentity`; diseno 5.5).
- [ ] **Paso 2: rojo. Paso 3: implementar. Paso 4: verde** + `pytest tests/unitarios tests/seguridad -q`.

### Tarea 8: el aplicador crea el rol por persona (`aplicador.py`) (HECHA el 26-10-2026)

**Files:**
- Modify: `agente_iam/aplicador.py`
- Modify: `tests/unitarios/test_aplicador.py`

**Interfaces:**
- Consumes: `personas.*`, `config.POOL_ID`, `config.CLIENTES_COGNITO`, `config.NOMBRE_TECHO`.
- Produces:
  - `TAG_SOLICITUD` pasa a importarse de `personas` (mismo valor).
  - `observar_rol(nombre: str) -> dict`: `{"existe": False}` o `{"existe": True, "arn", "role_id", "boundary",
    "tags": {k: v}, "max_session": int}` (`GetRole` + `ListRoleTags`).
  - `vence_de_la_descripcion(descripcion: str) -> str | None` (regex `vence=(\S+)`).
  - `prevuelo(registro)`: tras los controles comunes (huella, S4, S9, revalidar, `CheckNoNewAccess`), si
    `identidad_verificada.modo == "rol_por_persona"` delega en `_prevuelo_persona(registro, congelada, avisos)` y NO
    llama a `_identidad_actual`. `_prevuelo_persona` bloquea si: `persona.sub` falta o no coincide con
    `ejecutado_por.sub`; `horas` fuera de 1..12; `ejecutado_por.client_id` no esta en `CLIENTES_COGNITO`; el rol ya
    existe sin la etiqueta `TAG_SOLICITUD == id` (nombre ocupado) o con otro boundary. Lanza `ControlNoEjecutable` si
    `POOL_ID` o `CLIENTES_COGNITO` estan vacios (entorno, no bloqueo). Devuelve `actual = {"principal_arn": arn_de_rol,
    "principal_id": role_id o "", "rol": observado}`.
  - `crear(registro, documento, cuenta, vence: str | None = None)`: con `vence`, la `Description` anade
    ` | vence=<vence>`.
  - `crear_rol(registro, congelada, vence, cuenta, documento_confianza) -> dict` (`{"arn", "role_id"}`): `CreateRole`
    con `RoleName`, `Path=PATH_PERSONAS`, `AssumeRolePolicyDocument`, `PermissionsBoundary` = techo,
    `MaxSessionDuration = horas*3600`, `Description = "agente-iam | solicitud=<id> | persona=<usuario> |
    vence=<vence>"`, `Tags` = las cuatro; ante `EntityAlreadyExists` vuelve a `observar_rol` y acepta solo si la
    etiqueta de solicitud es la suya (si no, `RuntimeError`).
  - `_con_reintento(operacion, *, intentos=4, tambien: tuple[str, ...] = ())`: `tambien` anade codigos reintentables
    solo para esa llamada. El `AttachRolePolicy` que sigue a un `CreateRole` de la MISMA corrida se llama con
    `tambien=("AccessDenied",)`: IAM es de consistencia eventual y la condicion `iam:PermissionsBoundary` sobre un rol
    recien creado puede evaluarse antes de que el rol se propague (riesgo del revisor; se mide en la tarea 12). Las
    funciones de `personas` con red reciben `iam=_iam()`.
  - `aplicar(registro)` en modo persona: `observado = observar(cuenta, id)`; `vence = vence_de_la_descripcion(
    observado["descripcion"])` si la politica existe, si no `personas.vence_desde(ahora, horas)`;
    `documento_final = personas.documento_con_vencimiento(documento, vence)`; `decidir(observado, documento_final, id)`
    como hoy; orden de escritura `CreatePolicy` (con `vence`), `CreateRole` (si no existe), `AttachRolePolicy`;
    el bloque `aplicacion` anade `"rol_arn"`, `"rol_id"`, `"vence"`, `"documento_aplicado"` (el final) y
    `principal_id_confirmado = rol_id`. `manejador` loguea tambien `rol_arn`.

- [ ] **Paso 1: tests** (con `Stubber` y `monkeypatch`, patron de los tests actuales del aplicador; registro aprobado
  en modo persona construido con `_solicitud_persona` y un bloque `aprobacion` valido):
  `test_en_modo_persona_el_prevuelo_no_relee_ningun_principal_y_exige_sub_y_client_id`;
  `test_un_client_id_fuera_de_la_lista_bloquea_antes_de_escribir`; `test_sin_pool_id_el_control_no_es_ejecutable`;
  `test_el_orden_es_politica_rol_adjuntar_y_el_bloque_lleva_rol_y_vence` (tres llamadas con `expected_params`:
  `CreatePolicy` con el documento que lleva `DateLessThan`, `CreateRole` con la confianza exacta, boundary y
  `MaxSessionDuration=14400`, `AttachRolePolicy`); `test_el_reintento_toma_el_vence_de_la_politica_ya_creada`
  (politica existente con `vence=` en la descripcion y documento con ese `vence` -> `adjuntar`, se crea solo el rol);
  `test_un_rol_con_el_mismo_nombre_pero_otra_solicitud_bloquea`; `test_el_attach_tras_crear_el_rol_reintenta_un_
  access_denied_y_el_attach_de_hoy_no`; `test_el_modo_principal_existente_no_cambia` (`req-022` de hoy sigue por
  `_identidad_actual`).
- [ ] **Paso 2: rojo. Paso 3: implementar. Paso 4: verde** + suite unitaria + mypy.

### Tarea 9: lo que ve el aprobador (`aprobar_cliente.py`, `aprobar.py`) (HECHA el 26-10-2026)

**Files:**
- Modify: `agente_iam/aprobar_cliente.py` (`_mostrar_propuesta`)
- Modify: `agente_iam/aprobar.py` (solo si `_separacion` o `revalidar` necesitan el modo; se espera que no)
- Modify: `tests/unitarios/test_aprobar_cliente.py`, `tests/unitarios/test_aprobacion.py`

**Interfaces:**
- Produces: en modo persona `_mostrar_propuesta` imprime `Beneficiario: rol por persona <arn> (se crea al aplicar)`,
  `Persona: <usuario> (sub <sub>)`, `Horas: <n>; venceria el <vence si se aplicara ahora>` (con
  `personas.vence_desde(now, horas)`), `Correo de aviso: <correo>`; todo con `imprimible`.

- [ ] **Paso 1: tests.** `test_aprobar_cliente.py`: `test_la_revision_de_un_rol_por_persona_muestra_horas_vence_y_rol`
  (capsys). `test_aprobacion.py`: `test_aprobar_en_modo_persona_separa_a_aprobador_y_solicitante_y_pasa` (un registro
  persona con `solicitante.persona = "solicitante.demo"` y aprobador `aprobador.demo` -> sin bloqueos de separacion;
  mismo nombre -> bloqueo de autoaprobacion) y `test_revalidar_en_modo_persona_juzga_el_formulario_y_la_propuesta`.
- [ ] **Paso 2: rojo. Paso 3: implementar. Paso 4: verde.**

### Tarea 10: la infraestructura del bloque 1 (cuatro plantillas y el JSON del aplicador) (HECHA el 26-10-2026)

**Files:**
- Modify: `infra/cfn/base.yaml` (`RolAplicador`), `infra/rol-aplicador-permisos.json` (mismas sentencias)
- Modify: `infra/cfn/arranque.yaml` (`LimiteSistema`, `PoliticaIdentidad`, `PoliticaBarreras`, `PoliticaComputo`)
- Modify: `infra/cfn/acceso.yaml` (proveedor OIDC y su salida)
- Modify: `infra/cfn/runtime.yaml` (parametros `UserPoolId`, `ClienteWebId`; variables del aplicador; `AllowedClients`)
- Modify: `tests/seguridad/test_pila_base.py`, `tests/seguridad/test_plantillas_cfn.py`,
  `tests/seguridad/test_pila_acceso.py`, `tests/seguridad/test_pila_runtime.py`
- Tarea paralela a las 1 a 9 (no toca Python de `agente_iam/`).

**Interfaces:**
- Produces, `base.yaml` `RolAplicador`:
  - Allow `CrearRolesDePersonaSoloConElTecho`: `iam:CreateRole` sobre
    `arn:aws:iam::${AWS::AccountId}:role/agente-iam/personas/*` con `StringEquals iam:PermissionsBoundary` = el techo.
  - Allow `EtiquetarYLeerRolesDePersona`: `iam:TagRole`, `iam:ListRoleTags` sobre la misma ruta.
  - Deny `NuncaUnRolFueraDeLaRutaDePersonas`: `iam:CreateRole` con `NotResource` esa ruta.
  - Deny `NuncaUnRolDePersonaSinElTecho`: `iam:CreateRole` sobre `*` con `StringNotEquals iam:PermissionsBoundary` =
    el techo (clave ausente -> Deny, la leccion de §H 11 y 30).
  - `NuncaCrearIdentidadesNiEscalar` pierde `iam:CreateRole` y conserva todo lo demas (sin `DeleteRole`,
    `UpdateAssumeRolePolicy` ni `PassRole` en ningun Allow).
  - El Attach existente ya cubre `AttachRolePolicy` al rol nuevo (condicion de boundary = techo).
  - `infra/rol-aplicador-permisos.json`: las mismas sentencias con `111122223333`
    (`test_el_aplicador_es_el_de_su_json_mas_la_tabla` las compara Sid a Sid).
- `arranque.yaml`:
  - `LimiteSistema`: Allow `CrearRolesDePersonaSoloConElTecho` (CreateRole, ruta y condicion de boundary), Allow
    `EtiquetarRolesDePersona` (`iam:TagRole` sobre la ruta), Allow `AvisarPorCorreo` (`ses:SendEmail` sobre
    `arn:aws:ses:us-east-1:${AWS::AccountId}:identity/*`; lo usa el bloque 3 y se mete ahora para que el
    administrador despliegue arranque una sola vez); `NuncaEscalar` pierde `iam:CreateRole` y se anaden los dos Deny
    de arriba (fuera de la ruta; sin el techo).
  - `PoliticaIdentidad`: Allow `ProveedorOidcSoloDelPoolDeCognito`: `iam:CreateOpenIDConnectProvider`,
    `iam:DeleteOpenIDConnectProvider`, `iam:GetOpenIDConnectProvider`, `iam:UpdateOpenIDConnectProviderThumbprint`,
    `iam:AddClientIDToOpenIDConnectProvider`, `iam:RemoveClientIDFromOpenIDConnectProvider`,
    `iam:TagOpenIDConnectProvider`, `iam:UntagOpenIDConnectProvider`, `iam:ListOpenIDConnectProviderTags` sobre
    `arn:aws:iam::${AWS::AccountId}:oidc-provider/cognito-idp.us-east-1.amazonaws.com/*`.
  - `PoliticaBarreras`: `NuncaIdentidadesHumanasNiPoliticasNuevas` pierde `iam:CreateOpenIDConnectProvider`; nuevo
    Deny `NuncaOtroProveedorOidc`: `iam:CreateOpenIDConnectProvider` con `NotResource` el patron de Cognito.
  - `PoliticaComputo` (para el bloque 2, mismo change set): Allow `CloudFrontSoloRecursosDelProyecto`:
    `cloudfront:CreateDistribution`, `UpdateDistribution`, `DeleteDistribution`, `GetDistribution`,
    `GetDistributionConfig`, `TagResource`, `UntagResource`, `ListTagsForResource`, `CreateOriginAccessControl`,
    `GetOriginAccessControl`, `GetOriginAccessControlConfig`, `UpdateOriginAccessControl`,
    `DeleteOriginAccessControl`, `CreateResponseHeadersPolicy`, `GetResponseHeadersPolicy`,
    `GetResponseHeadersPolicyConfig`, `UpdateResponseHeadersPolicy`, `DeleteResponseHeadersPolicy` sobre
    `arn:aws:cloudfront::${AWS::AccountId}:distribution/*`, `.../origin-access-control/*`,
    `.../response-headers-policy/*`. (La lista se contrasta con la referencia de autorizacion de CloudFront antes
    del change set; lo que falte lo dira el primer despliegue de `web.yaml` y se anota en MEDICIONES.)
- `acceso.yaml`: `ProveedorOidc` (`AWS::IAM::OIDCProvider`, `Condition: Federado`, `Url:
  https://cognito-idp.${AWS::Region}.amazonaws.com/${UserPool}`, `ClientIdList: [Ref ClienteCli]`, etiqueta
  `proyecto`; sin `ThumbprintList` si cfn-lint lo admite, y si no, la huella del certificado raiz de Amazon que uso la
  sonda N.1, con comentario). Salida `ProveedorOidcArn`.
- `runtime.yaml`: SIN parametro nuevo para el pool: el id sale de `DiscoveryUrl` con `Fn::Select: [3, Fn::Split: ["/",
  Ref DiscoveryUrl]]` (`https:`, vacio, host, pool: indice 3), con comentario; parametro `ClienteWebId` (`Default: ""`,
  `AllowedPattern: ^([a-z0-9]{26})?$`), `Condition ConWeb`; `AllowedClients` = `Fn::If [ConWeb, [ClienteId,
  ClienteWebId], [ClienteId]]`; `FuncionAplicador.Environment` anade `AGENTE_IAM_POOL_ID` (el `Fn::Select`) y
  `AGENTE_IAM_CLIENTES: Fn::If [ConWeb, Fn::Sub "${ClienteId},${ClienteWebId}", Ref ClienteId]`. El `Runtime` NO recibe
  variables nuevas (`test_el_runtime_guarda_en_dynamodb_y_usa_el_modelo_del_parametro` fija su dict exacto).
- `RolRuntime` en `base.yaml`: SIN cambios y sin Sid nuevo (`iam:List*` ya cubre `ListRoles` y `ListRoleTags`;
  `test_el_runtime_tiene_exactamente_sus_sentencias...` fija la lista exacta).
- Antes del change set (tarea 12, administrador): `cloudformation:DescribeType` de `AWS::IAM::OIDCProvider`,
  `AWS::CloudFront::Distribution`, `AWS::CloudFront::OriginAccessControl` y `AWS::CloudFront::ResponseHeadersPolicy`
  (como en F.7 y la leccion §H 31: el manejador `list` del proveedor OIDC pedira `iam:ListOpenIDConnectProviders` con
  `Resource "*"`); lo que digan los manejadores se anade a `PoliticaIdentidad`/`PoliticaComputo` y, si es una accion de
  lista con `*`, a la tolerancia de `test_lo_que_va_con_recurso_estrella_no_lee_ni_escribe_datos_ni_iam`.

- [ ] **Paso 1: tests que fallan.** `test_pila_base.py`: `test_el_aplicador_crea_roles_solo_en_la_ruta_de_personas_y_
  solo_con_el_techo` (los dos Allow y los dos Deny, y que ningun Allow lleve `UpdateAssumeRolePolicy`, `DeleteRole` ni
  `PassRole`); adaptar `test_el_aplicador_es_el_de_su_json_mas_la_tabla` (sigue valiendo si el JSON se actualiza).
  `test_plantillas_cfn.py`: `test_el_limite_del_sistema_impide_escalar` se queda como esta (el Deny condicionado sigue
  listando `iam:CreateRole`); nuevo `test_el_limite_crea_roles_de_persona_solo_en_su_ruta_y_con_el_techo` (todo Deny
  con `iam:CreateRole` lleva `NotResource` la ruta o `StringNotEquals iam:PermissionsBoundary` = techo, nunca
  `...IfExists` (§H 11 y 30); el unico Allow de `iam:CreateRole` lleva `StringEquals` con el techo); nuevo
  `test_el_despliegue_solo_crea_el_proveedor_oidc_de_cognito`; nuevo
  `test_el_despliegue_puede_crear_cloudfront_solo_del_proyecto`; adaptar
  `test_lo_que_va_con_recurso_estrella_no_lee_ni_escribe_datos_ni_iam` solo con lo que diga `DescribeType`.
  `test_pila_acceso.py`: `test_el_proveedor_oidc_apunta_al_pool_y_lista_a_los_clientes`; adaptar
  `test_la_pila_solo_tiene_recursos_de_cognito_y_ningun_usuario` (admite `AWS::IAM::OIDCProvider`),
  `test_las_salidas_son_las_que_espera_el_resto` (`ProveedorOidcArn`) y `test_lo_federado_solo_existe_con_metadata_url`
  (`ProveedorOidc`). `test_pila_runtime.py`: `test_el_runtime_admite_el_cliente_web_solo_si_llega_el_parametro`,
  `test_el_aplicador_recibe_el_pool_desde_la_discovery_url_y_los_clientes`; adaptar
  `test_el_runtime_solo_acepta_jwt_del_cliente_del_parametro` y
  `test_el_aplicador_nunca_lleva_el_interruptor_de_autoaprobacion` (fija el dict exacto de variables del aplicador).
- [ ] **Paso 2: rojo.** `./.venv/bin/python -m pytest tests/seguridad -q`.
- [ ] **Paso 3: editar las plantillas y el JSON.** Comentario en cada sentencia nueva con su porque (por que la ruta,
  por que el `NotResource`, por que el techo como condicion; §H 11 y 30 sobre claves ausentes).
- [ ] **Paso 4: verde y cfn-lint.** `./.venv/bin/python -m pytest tests/seguridad -q &&
  ./.venv/bin/cfn-lint infra/cfn/base.yaml infra/cfn/arranque.yaml infra/cfn/acceso.yaml infra/cfn/runtime.yaml`.

### Tarea 11: el cliente de la persona (`scripts/solicitar.py`) (HECHA el 26-10-2026)

**Files:**
- Modify: `scripts/solicitar.py`
- Modify: `tests/unitarios/test_solicitar.py`
- Create: `ejemplos/web/persona-finanzas-demo.json` (el nuevo contrato: `campos`, `horas: 4`, `correo_aviso:
  "persona@example.com"`, `justificacion`; SIN `clave_envio`: la genera el script). En subcarpeta porque
  `test_modelos.py::test_todos_los_ejemplos_siguen_parseando` valida `ejemplos/*.json` con `SolicitudEstructurada`
  (glob de primer nivel); anadir en `test_modelos.py` `test_los_ejemplos_web_validan_con_solicitud_web` (lee
  `ejemplos/web/*.json`, les anade una `clave_envio` y valida con `SolicitudWeb`). Comprobar que `scripts/localizar.py`
  copia subcarpetas de `ejemplos/` (la tarea 12 usa `local/ejemplos/web/...`); si no, hacerlo en esta tarea.

**Interfaces:**
- Produces:
  - `cmd_enviar`: si el JSON no trae `clave_envio`, el script anade `str(uuid.uuid4())` antes de mandar (y lo imprime
    para poder reintentar con `--clave`); opcion `--clave <uuid>` para repetir el mismo envio. Imprime ademas
    `solicitud_id:` y `rol_previsto:` de la respuesta.
  - `cmd_asumir(args)`: `asumir <rol_arn> --usuario <u> [--horas N (1..12, por defecto 1)] [--listar <bucket>]`:
    lee `id_token` de `local/tokens/<u>.json` (si falta: codigo 1 y "vuelve a entrar con `token`"), llama a
    `AssumeRoleWithWebIdentity` sin credenciales (`boto3.client("sts", config=Config(signature_version=UNSIGNED))`),
    `RoleSessionName = "agente-iam-" + usuario normalizado` (recortado a 64), `DurationSeconds = horas*3600`; escribe
    las credenciales en `local/credenciales/<u>-<nombre del rol>.json` con permisos 600 e imprime la ruta y
    `Expiration`, NUNCA las claves; con `--listar`, hace `ListObjectsV2(Bucket, MaxKeys=5)` con esas credenciales e
    imprime el numero de objetos (prueba de vida). Codigos: 0 ok; 1 error (`AccessDenied`, token caducado,
    `ExpiredTokenException`), 2 argumentos malos. El mensaje de `AccessDenied` anade "si el rol se acaba de crear,
    espera unos segundos y repite" (consistencia eventual de IAM). Desviacion del diseno, que ADR-004 recoge: `asumir`
    recibe el ARN del rol y no el `solicitud_id`, porque la persona no puede leer la tabla; el ARN lo imprime `enviar`
    (`rol_previsto`) y lo trae el correo de `aplicada`.
  - `_asumir(sts, rol_arn, token, sesion, segundos) -> dict` y `_guardar_credenciales(ruta, credenciales) -> None`:
    piezas puras, probables con `Stubber`.

- [ ] **Paso 1: tests.** `test_enviar_genera_la_clave_de_envio_si_falta_y_la_imprime`;
  `test_enviar_con_clave_la_repite_tal_cual`; `test_enviar_imprime_id_y_rol_previsto`;
  `test_asumir_llama_a_sts_sin_firmar_y_guarda_con_600_sin_imprimir_claves` (Stubber con `expected_params`, capsys no
  contiene `SecretAccessKey` ni `SessionToken`); `test_asumir_sin_id_token_sale_con_1`;
  `test_asumir_access_denied_sale_con_1_y_no_escribe`; `test_asumir_con_listar_cuenta_objetos`.
- [ ] **Paso 2: rojo. Paso 3: implementar. Paso 4: verde + ruff.**

### Tarea 12: despliegue y prueba de fuego del bloque 1 (Claude con el si de Mateo; Mateo en consola y navegador)

**Files:** ninguno nuevo en el repo salvo `docs/MEDICIONES.md` (seccion O, la escribe Claude al medir).

Prerrequisitos de Mateo: `aws sso login` de `agente-iam-org` en su terminal; MFA de `solicitante.demo` registrada en
Identity Center; `./.venv/bin/python scripts/localizar.py` con `AWS_PROFILE=org-agente-iam`.

- [x] **Paso 1: suite entera en verde y cfn-lint de las cuatro plantillas** (Claude). `DescribeType` de los cuatro
  tipos nuevos con el administrador (lectura) y ajuste de `arranque.yaml` si falta alguna accion.
- [x] **Paso 2: arranque (administrador, `org-agente-iam`).** Change set `arranque-fase-23` con `arranque.yaml`;
  ensenar a Mateo las sentencias que cambian; ejecutar con su si; leer `UPDATE_COMPLETE`.
- [x] **Paso 3: acceso (operador).** Change set `acceso-proveedor-oidc` con los mismos parametros (`UsePreviousValue`):
  crea solo `ProveedorOidc`; ejecutar con su si; leer la salida `ProveedorOidcArn` y comprobar con
  `GetOpenIDConnectProvider` que `ClientIDList` = [`agente-iam-cli`].
- [x] **Paso 4: paquetes.** `scripts/empaquetar.sh` y `scripts/empaquetar.sh aplicador` (y `scripts/empaquetar.sh aprobacion`: la Lambda de aprobacion revalida con `models.py` y `aprobar.py`; el 26-10-2026 se olvido y la primera aprobacion dio 409, MEDICIONES §H 39); subir los dos zips
  (operador, `put_object`) con su si; anotar claves y bytes.
- [x] **Paso 5: base (operador).** Change set `base-aplicador-roles-de-persona` (solo `RolAplicador`); ejecutar.
- [x] **Paso 6: runtime (operador).** Change set `runtime-fase-23` con `ClaveCodigoRuntime` y `ClaveCodigoAplicador`
  nuevas y los demas parametros con `UsePreviousValue` (`ClienteWebId` queda vacio hasta el bloque 2; el pool sale de
  `DiscoveryUrl`); ejecutar; leer runtime `READY` version 3 y la Lambda
  `Successful`. Releer MEDICIONES K.1 antes (grupo de logs, confianza del mapeo).
- [x] **Paso 7: medicion 5.3 (Mateo en navegador).** `solicitar.py token --usuario aprobador.demo` en ventana privada:
  se espera que Identity Center no deje entrar (no esta en `agente-iam-solicitantes`). Anotar el mensaje exacto.
- [x] **Paso 8: prueba de fuego.** Mateo: `solicitar.py token --usuario solicitante.demo` en una ventana privada y,
  cerradas todas, `solicitar.py token --usuario mateo` en OTRA ventana privada (§H 12: el navegador reutiliza sesiones;
  el token de Mateo es el negativo del paso 9). Claude:
  `solicitar.py enviar local/ejemplos/web/persona-finanzas-demo.json --usuario solicitante.demo` -> `propuesta`, anotar
  `solicitud_id` y `rol_previsto`. Mateo (perfil `org-agente-iam-aprobador-demo`, `AGENTE_IAM_URL_APROBACION`):
  `aprobar_cliente <id>` y despues con `--huella`. Claude lee la fila (`aplicada`, `aplicacion.rol_arn`, `vence`),
  el rol (`GetRole`: boundary, `MaxSessionDuration`, confianza, etiquetas) y la politica adjunta.
- [x] **Paso 9: canje.** Diez segundos despues de `aplicada` (consistencia eventual; anotar si el primer intento da
  `AccessDenied`), `solicitar.py asumir <rol_arn> --usuario solicitante.demo --horas 4 --listar
  finanzas-demo-<cuenta>` -> credenciales hasta `Expiration` y N objetos. Negativo: el mismo comando con
  `--usuario mateo` -> `AccessDenied` (otro `sub`). Negativo 2: `enviar` otra vez con la misma `--clave` ->
  `registro_existente` con el mismo id.
- [x] **Paso 10: MEDICIONES O.1 a O.3** (Claude): tablas con horas UTC, cada change set, cada llamada y su resultado;
  lo que no se midio (el vencimiento real: se mide al cumplirse las horas si Mateo quiere esperar; si no, queda en §J).
  El rol de la demo se queda (inerte al vencer) o se borra con el si de Mateo: anotar la decision.

### Tarea 13: documentacion del bloque 1 y ADR-004 (subagente Sonnet con encargo cerrado; Claude revisa)

**Files:**
- Modify: `PLAN-CORRECCIONES.md` (Fase 23, bloque 1), `CONTEXTO.md` (§2, §3, §5, §6, §7, §10, §11), `README.md`
  (estructura, uso de `solicitar.py enviar/asumir`, variables `AGENTE_IAM_POOL_ID`, `AGENTE_IAM_CLIENTES`),
  `docs/DESPLIEGUE.md` (parametros nuevos, orden del bloque 1), `docs/MEDICIONES.md` §J (lo que queda sin medir)
- Create: `docs/ADR-004-rol-por-persona-y-confianza-por-token.md` (lo redacta Claude: contexto, decisiones 5.2 a 5.5,
  dos modos en el repositorio y uno en produccion, alternativas descartadas, consecuencias, pendientes)

- [x] **Paso 1:** Claude redacta el ADR-004 y el encargo (ficheros, que cambia en cada uno, que no se toca). El ADR
  recoge tambien las tres desviaciones del diseno: `asumir <rol_arn>` en vez de `<solicitud_id>`; las etiquetas van
  dentro de `CreateRole` (atomico; `iam:TagRole` sigue permitido para el reintento); el id es idempotente para el
  registro y no para el coste del modelo. MEDICIONES O gana ademas la medicion de CORS del runtime del 26-10-2026 01:40
  UTC (hoy solo esta en el diseno) y §J el cambio de dia UTC entre un envio y su reintento (dos ids).
- [x] **Paso 2:** el subagente escribe; Claude revisa el diff contra la tabla de `CLAUDE.md`, busca los identificadores
  reales (`personas.py`, `test_personas.py`, `test_rol_por_persona.py`, `test_modos.py`, `asumir`, `SolicitudWeb`) y corre
  `./.venv/bin/python -m pytest tests/ -q` (incluye `test_documentacion.py`).
- [x] **Paso 3:** pedir a Mateo el commit del bloque 1 (mensaje propuesto: "Fase 23, bloque 1: rol por persona con
  caducidad, un solo contrato en el servidor, proveedor OIDC y canje con el token").

---

# Bloque 2: la pagina web

### Tarea 14: la pagina y su constructor (`web/`, `scripts/construir_web.py`) (HECHA el 26-10-2026)

**Files:**
- Create: `web/index.html`, `web/estilos.css`, `web/app.js`
- Create: `scripts/construir_web.py`
- Create: `tests/unitarios/test_web.py`
- Modify: `.gitignore` (`local/web/`)

**Interfaces:**
- Produces:
  - `construir_web.configuracion(salidas_acceso: dict, salidas_runtime: dict, cliente_web: str, cuenta: str) -> dict`:
    `{"region", "dominioCognito" (UrlDominio), "clienteId" (cliente web), "poolId", "urlRuntime"
    (`scripts.solicitar.url_runtime(RuntimeArn)`), "servicios": SERVICIOS_PERMITIDOS, "regiones":
    REGIONES_PERMITIDAS, "tiposAcceso": ["lectura", "escritura", "administracion"], "horasMin": 1, "horasMax": 12,
    "cuenta"}`.
  - `construir_web.escribir(configuracion: dict, destino: Path) -> Path`: copia `web/*` a `destino` y escribe
    `destino/config.js` = `window.AGENTE_IAM = <JSON>;` (una sola linea, `json.dumps(ensure_ascii=True)`).
  - `main(argv)`: `--perfil org-agente-iam --destino local/web` lee las salidas de `agente-iam-acceso`
    (`UserPoolId`, `UrlDominio`, `ClienteWebId`) y `agente-iam-runtime` (`RuntimeArn`) y escribe.
  - `web/app.js` (sin dependencias, un fichero, `"use strict"`): PKCE con `crypto.subtle`, `state` aleatorio, redirige
    a `${dominioCognito}/oauth2/authorize?...&identity_provider=IdentityCenter&redirect_uri=<origen>/`; al volver con
    `code` canjea en `${dominioCognito}/oauth2/token` (POST `application/x-www-form-urlencoded`), guarda `access_token`
    e `id_token` en variables de la closure (ni `localStorage`, ni `sessionStorage`, ni `document.cookie`), limpia la
    URL con `history.replaceState`, muestra `username` sin `IdentityCenter_` (claim del `access_token`); el formulario
    rellena las listas desde `window.AGENTE_IAM`; al enviar genera `clave_envio = crypto.randomUUID()` una vez por
    formulario (se conserva hasta un `procesada`), deshabilita el boton Enviar mientras la peticion esta en vuelo y hace `fetch(urlRuntime, {method: "POST",
    headers: {Authorization: "Bearer " + access_token, "Content-Type": "application/json"}})`. SIN la cabecera
    `X-Amzn-Bedrock-AgentCore-Runtime-Session-Id`: el preflight medido (diseno §3) solo admite `authorization` y
    `content-type`, y el servicio genera el id de sesion si no llega; si la medicion de la tarea 16 dice que si la
    admite, se anade despues y pinta con `textContent` el `solicitud_id`,
    el `estado`, el `rol_previsto` y, si `propuesta`, el texto fijo "queda a la espera de un aprobador; te avisaremos a
    <correo>"; 401/403 -> "la sesion no vale o caduco: vuelve a entrar", 424 -> "el servicio no pudo atender la
    solicitud", `forma_invalida` -> lista de campos. Boton "Obtener credenciales" (visible con un `rol_previsto`):
    POST a `https://sts.us-east-1.amazonaws.com/` con `Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn=
    ...&RoleSessionName=...&WebIdentityToken=<id_token>&DurationSeconds=<horas*3600>`; la respuesta es XML: se lee con `DOMParser` los nodos
    `AccessKeyId`, `SecretAccessKey`, `SessionToken` y `Expiration` de `AssumeRoleWithWebIdentityResult/Credentials`
    y se muestran las tres variables en un `<pre>` con `textContent` (son credenciales de la propia persona; aviso de
    no pegarlas en otro sitio); un `<Error><Code>` se pinta con `textContent`. El `id_token` solo se usa ahi.
  - `web/index.html`: sin `<script>` inline (dos `<script src>`: `config.js` y `app.js`), sin URLs externas, `<meta
    name="referrer" content="no-referrer">`, `lang="es"`.

- [x] **Paso 1: tests** (`test_web.py`, sin red): `test_las_listas_de_la_pagina_son_las_del_servidor`
  (`configuracion(...)["servicios"] == SERVICIOS_PERMITIDOS`, regiones, horas 1..12);
  `test_escribir_deja_config_js_con_el_json_en_una_linea` (tmp_path); `test_la_pagina_no_lleva_script_inline_ni_urls_
  externas` (regex sobre `index.html`); `test_app_js_no_guarda_tokens_fuera_de_la_memoria` (`localStorage`,
  `sessionStorage`, `document.cookie`, `innerHTML` ausentes de `app.js`); `test_app_js_llama_solo_a_cognito_runtime_y_
  sts` (toda URL literal en `app.js` es `sts.us-east-1.amazonaws.com` o sale de `window.AGENTE_IAM`);
  `test_el_id_token_solo_viaja_a_sts_y_el_access_token_al_runtime` (regex: `id_token` solo aparece en la funcion que
  llama a STS; `Bearer` solo con `access_token`); `test_enviar_se_deshabilita_en_vuelo` (`disabled = true` antes del
  `fetch` al runtime); `test_no_manda_la_cabecera_de_sesion` (la cadena `Runtime-Session-Id` no esta en `app.js`);
  `test_main_sin_argumentos_no_toca_la_red` (`--help`).
- [x] **Paso 2: rojo. Paso 3: escribir `web/*` y el constructor.** Paso 4: verde + ruff.

### Tarea 15: la pila `web` y el cliente de Cognito de la web (HECHA el 26-10-2026)

**Files:**
- Create: `infra/cfn/web.yaml`
- Modify: `infra/cfn/acceso.yaml` (parametro `UrlRetornoWeb`, `ClienteWeb`, `ClientIdList` del proveedor OIDC con los
  dos, salida `ClienteWebId`)
- Create: `tests/seguridad/test_pila_web.py`; Modify: `tests/seguridad/test_pila_acceso.py`
- Tarea paralela a la 14.

**Interfaces:**
- `web.yaml`: parametro `DominioCognito` (`AllowedPattern: ^https://agente-iam-[0-9a-f]{6}\.auth\.us-east-1\.
  amazoncognito\.com$`). Recursos: `BucketWeb` (`agente-iam-web-${AWS::AccountId}`, cifrado AES256, acceso publico
  bloqueado, `BucketOwnerEnforced`, versionado), `PoliticaBucketWeb` (Allow `s3:GetObject` a
  `cloudfront.amazonaws.com` con `aws:SourceArn` = `arn:aws:cloudfront::${AWS::AccountId}:distribution/${Distribucion}`;
  Deny sin TLS), `AccesoOrigen` (`AWS::CloudFront::OriginAccessControl`, s3, sigv4, always), `CabecerasSeguridad`
  (`AWS::CloudFront::ResponseHeadersPolicy`: CSP `default-src 'none'; script-src 'self'; style-src 'self'; connect-src
  <DominioCognito> https://bedrock-agentcore.us-east-1.amazonaws.com https://sts.us-east-1.amazonaws.com; img-src
  'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, `Strict-Transport-Security` 1 ano,
  `X-Content-Type-Options nosniff`, `Referrer-Policy no-referrer`, `X-Frame-Options DENY`), `Distribucion`
  (`Enabled`, `DefaultRootObject index.html`, `HttpVersion http2`, `PriceClass_100`, origen S3 con
  `OriginAccessControlId`, `ViewerProtocolPolicy redirect-to-https`, `AllowedMethods [GET, HEAD]`, `Compress`,
  `CachePolicyId 658327ea-f89d-4fab-a63d-7e88639e58f6` (CachingOptimized), `ResponseHeadersPolicyId`,
  `MinimumProtocolVersion TLSv1.2_2021`, etiqueta `proyecto`). Salidas `UrlWeb` (`https://${Distribucion.DomainName}`),
  `BucketWeb`, `DistribucionId`.
- `acceso.yaml`: parametro `UrlRetornoWeb` (`Default: ""`, `AllowedPattern: ^(https://[a-z0-9]+\.cloudfront\.net/)?$`),
  `Condition ConWeb` (Federado y no vacio); `ClienteWeb` como `ClienteCli` pero `ClientName agente-iam-web`,
  `CallbackURLs [Ref UrlRetornoWeb]`, `LogoutURLs` igual; `ProveedorOidc.ClientIdList` = `Fn::If [ConWeb,
  [ClienteCli, ClienteWeb], [ClienteCli]]`; salida `ClienteWebId` (Condition ConWeb).

- [x] **Paso 1: tests.** `test_pila_web.py`: bucket privado, cifrado y con TLS; solo CloudFront lee y solo esa
  distribucion; OAC sigv4 always; HTTPS obligatorio y TLS 1.2; CSP sin `unsafe-inline`, con los tres `connect-src` y
  `frame-ancestors 'none'`; sin recursos fuera de S3 y CloudFront; nombres con prefijo del sistema; sin cuenta ni
  correos (ya lo cubre `test_plantillas_cfn.py`). `test_pila_acceso.py`: `test_el_cliente_web_es_publico_pkce_y_solo_
  vuelve_a_su_cloudfront`, `test_sin_url_de_retorno_no_hay_cliente_web`, adaptar `test_la_unica_url_de_retorno_es_
  localhost` (el de la CLI sigue siendo solo localhost), `test_las_salidas_son_las_que_espera_el_resto` (`ClienteWebId`)
  y `test_lo_federado_solo_existe_con_metadata_url` (`ClienteWeb`).
- [x] **Paso 2: rojo. Paso 3: escribir. Paso 4: verde + `cfn-lint infra/cfn/web.yaml infra/cfn/acceso.yaml`.**

### Tarea 16: despliegue y prueba desde el navegador (Claude con el si de Mateo) (HECHA el 26-10-2026)

- [x] **Paso 1: web (operador).** Change set `web-1` de `web.yaml` con `DominioCognito`; ejecutar; leer `UrlWeb`.
- [x] **Paso 2: acceso (operador).** Change set `acceso-cliente-web` con `UrlRetornoWeb = <UrlWeb>/`; ejecutar; leer
  `ClienteWebId`; comprobar `GetOpenIDConnectProvider.ClientIDList` con los dos clientes.
- [x] **Paso 3: runtime (operador).** Change set `runtime-cliente-web` con `ClienteWebId`; ejecutar; `AllowedClients`
  con dos entradas (`GetAgentRuntime`); la Lambda del aplicador con `AGENTE_IAM_CLIENTES` de dos.
- [x] **Paso 4: ficheros.** `construir_web.py --perfil org-agente-iam --destino local/web`; el administrador sube
  `index.html`, `estilos.css`, `app.js`, `config.js` al bucket (`Content-Type` correcto) con el si de Mateo (el
  operador no puede escribir en ese bucket: anotar en DESPLIEGUE); `CreateInvalidation /*` si se vuelve a subir.
- [x] **Paso 5: medicion O.4.** Primero, con `curl` (sin token), los tres preflight: el del runtime con
  `Access-Control-Request-Headers: authorization,content-type,x-amzn-bedrock-agentcore-runtime-session-id` (si lo
  admite, `app.js` recupera la cabecera de sesion), el de `${dominioCognito}/oauth2/token` y el de
  `https://sts.us-east-1.amazonaws.com/` desde el origen de CloudFront. Despues, en el navegador integrado: `UrlWeb`
  responde 200 con las cabeceras de seguridad (leer `content-security-policy`); "Entrar" como `solicitante.demo` (Mateo teclea la MFA); el nombre aparece; enviar una
  solicitud -> `propuesta` con id; preflight y respuesta del runtime desde el origen de CloudFront (consola de red);
  `aprobador.demo` aprueba en la terminal; "Obtener credenciales" -> STS responde desde el navegador (medir CORS: si
  STS no lo admite, anotarlo y dejar el boton como "copia este comando: `solicitar.py asumir ...`", decision de Claude
  reversible). Negativo: recargar la pagina pierde la sesion (token solo en memoria).

### Tarea 17: documentacion del bloque 2 (subagente Sonnet; Claude revisa)

- [x] PLAN Fase 23 bloque 2; CONTEXTO §3 (la pagina en el mapa), §5 (pila `web`, cliente `agente-iam-web`), §6
  (`web/`, `construir_web.py`, `test_web.py`, `test_pila_web.py`), §7 (como se construye y se sube), §10; README;
  DESPLIEGUE (orden web -> acceso -> runtime -> ficheros); MEDICIONES O.4; ADR-004 (anexo: la web no elige
  beneficiario). Suite en verde. Pedir el commit a Mateo.

---

# Bloque 3: el aviso por correo

### Tarea 18: la Lambda de avisos (`agente_iam/avisos.py`) (HECHA el 26-10-2026)

**Files:**
- Create: `agente_iam/avisos.py`
- Create: `tests/unitarios/test_avisos.py`
- Modify: `scripts/empaquetar.sh`: `avisos.py` entra en `FUERA_DEL_RUNTIME` y en `FUERA_DE_LA_APROBACION` (no viaja
  ahi) y en `LLEVA_EL_APLICADOR` (viaja en el zip del aplicador aunque `aplicador.py` no lo importe: es el manejador de
  la otra Lambda que usa ese zip). `tests/seguridad/test_ci.py`:
  `test_cada_modulo_esta_en_un_lado_del_paquete_del_aplicador` pasa a `== cadena | fuera | {"aplicador.py",
  "avisos.py"}` y `test_el_zip_del_aplicador_comprueba_que_lleva_lo_que_necesita` exige `avisos.py` en `LLEVA`.

**Interfaces:**
- Produces:
  - `ESTADOS_QUE_AVISAN = ("aprobada", "rechazada_por_aprobador", "aplicada", "bloqueada_al_aplicar",
    "requiere_revision_humana", "redundante_no_requiere_cambio", "rechazada_en_chequeos_previos")` y `FRASES: dict[str,
    str]` con una frase fija por estado (p. ej. `aplicada`: "El permiso esta activo. Asume el rol con tu token de
    identidad antes de la hora de vencimiento.").
  - `cuerpo_del_correo(solicitud_id: str, estado: str, aplicacion: dict | None) -> tuple[str, str]` -> (asunto
    `"Agente IAM: solicitud <id> <estado>"`, cuerpo `"Solicitud <id>: <estado>. <frase>"` y, si `aplicada`, dos lineas
    mas: `Rol: <rol_arn>` y `Vence: <vence>`). Sin politica, justificacion ni aprobador: el cuerpo se forma SOLO con
    esos tres datos.
  - `correo_de(imagen_nueva: dict) -> str | None`: `json.loads(imagen["documento"]["S"])["solicitud"]["correo_aviso"]`
    o None; `estado_de(imagen) -> str | None`.
  - `manejador(evento, contexto) -> dict`: por registro `INSERT`/`MODIFY`, si `estado_de(NewImage)` esta en
    `ESTADOS_QUE_AVISAN` y es distinto de `estado_de(OldImage)`, y hay correo, llama a `SendEmail(Source=REMITENTE,
    Destination={"ToAddresses": [correo]}, Message=...)`; `MessageRejected` y `MailFromDomainNotVerified` se
    registran en WARNING y no se relanzan (diseno 5.7); otros `ClientError` suben. `REMITENTE =
    os.getenv("AGENTE_IAM_REMITENTE", "")`; sin remitente, el manejador lanza `RuntimeError` (entorno). Devuelve
    `{"avisados": [...ids], "omitidos": [...]}`. Log por registro: id, estado y si se aviso; nunca el correo entero
    (solo su dominio).

- [x] **Paso 1: tests** (Stubber de `ses`): `test_el_cuerpo_lleva_solo_id_estado_y_en_aplicada_rol_y_vence`;
  `test_un_cambio_de_estado_a_aplicada_manda_un_correo_con_expected_params`;
  `test_un_modify_sin_cambio_de_estado_no_manda_nada`; `test_propuesta_no_avisa`; `test_sin_correo_se_omite`;
  `test_message_rejected_no_relanza`; `test_sin_remitente_no_arranca`.
- [x] **Paso 2: rojo. Paso 3: implementar. Paso 4: verde**, `pytest tests/seguridad/test_ci.py -q` (listas del zip).

### Tarea 19: rol, funcion y disparador de los avisos (`base.yaml`, `runtime.yaml`) (HECHA el 26-10-2026)

**Files:**
- Modify: `infra/cfn/base.yaml` (`RolAvisos`, parametro `CorreoRemitente`)
- Modify: `infra/cfn/runtime.yaml` (`CorreoRemitente`, `RegistroAvisos`, `FuncionAvisos`, `DisparadorAvisos`)
- Modify: `tests/seguridad/test_pila_base.py`, `tests/seguridad/test_pila_runtime.py`
- Paralela a la 18.

**Interfaces:**
- `base.yaml`: parametro `CorreoRemitente` (sin defecto, patron de correo). `RolAvisos` (`AgenteIAM-Avisos`,
  boundary `LimiteSistema`, confianza `lambda.amazonaws.com` con `aws:SourceAccount` solo, como el aplicador):
  Allow `EnviarSoloDesdeElRemitente` (`ses:SendEmail` sobre `arn:aws:ses:us-east-1:${AWS::AccountId}:identity/
  ${CorreoRemitente}` con `StringEquals ses:FromAddress = CorreoRemitente`), Allow stream (las tres acciones +
  `ListStreams`), Allow logs de `/aws/lambda/agente-iam-avisos:*`; Deny `NuncaLeerNiEscribirLaTabla`
  (`dynamodb:GetItem`, `Query`, `Scan`, `UpdateItem` sobre `*`), Deny `NuncaReemplazarNiBorrarFilas` (la misma lista
  que los otros roles: `PutItem`, `DeleteItem`, `BatchWriteItem`, `DeleteTable`, `UpdateTable`, `PartiQL*`,
  `UpdateTimeToLive`, `UpdateContinuousBackups`; lo exige `test_ningun_rol_puede_reemplazar_ni_borrar_filas`), Deny
  `NuncaEscribirEnIAM` (la lista del rol de aprobacion), Deny `bedrock:*`. Salida `RolAvisosArn`.
- `runtime.yaml`: parametro `CorreoRemitente`; `RegistroAvisos` (365 dias, Retain); `FuncionAvisos`
  (`agente-iam-avisos`, python3.12 arm64, `Handler agente_iam.avisos.manejador`, `Code.S3Key = Ref
  ClaveCodigoAplicador` (mismo zip), `Role` `AgenteIAM-Avisos`, `Timeout 30`, `MemorySize 256`, env
  `AGENTE_IAM_REMITENTE`); `DisparadorAvisos` (`StartingPosition LATEST`, `BatchSize 1`, `MaximumRetryAttempts 0`,
  `BisectBatchOnFunctionError false`, sin `DestinationConfig` (un aviso que no sale no es un fallo del circuito:
  queda en el log), filtro `{"eventName": ["INSERT", "MODIFY"], "dynamodb": {"NewImage": {"estado": {"S":
  [...los siete...]}}}}`).

- [x] **Paso 1: tests.** `test_pila_base.py`: la tupla `ROLES` se queda como esta (alimenta `_update(rol)`, y el rol de
  avisos no tiene `UpdateItem`); se define `ROLES_SIN_TABLA = ("RolAvisos",)` y se recorre `ROLES + ROLES_SIN_TABLA`
  solo en `test_ningun_rol_puede_reemplazar_ni_borrar_filas`, `test_los_roles_nacen_con_el_limite_del_sistema` y
  `test_todo_lo_que_concede_la_aprobacion_cabe_en_el_limite_del_sistema` (generalizado al rol de avisos); nuevos
  `test_el_rol_de_avisos_solo_manda_desde_el_remitente_y_no_toca_tabla_ni_iam` y
  `test_el_rol_de_avisos_lee_el_stream_y_nada_mas_de_dynamodb`. `test_pila_runtime.py`:
  `test_la_funcion_de_avisos_usa_el_zip_del_aplicador_su_rol_y_su_remitente`,
  `test_el_disparador_de_avisos_filtra_los_siete_estados_sin_reintentos`; adaptar
  `test_la_pila_no_declara_el_grupo_de_logs_del_runtime` (`{"RegistroAplicador", "RegistroAvisos"}`),
  `test_los_recursos_del_sistema_llevan_prefijo_agente_iam` y `test_correo_y_claves_de_codigo_no_tienen_valor_por_
  defecto` (`CorreoRemitente`).
- [x] **Paso 2: rojo. Paso 3: escribir. Paso 4: verde + cfn-lint.**

### Tarea 20: SES, despliegue y medicion del correo (Mateo en consola; Claude con su si) (HECHA el 26-10-2026)

- [x] **Paso 1 (Mateo, consola SES `us-east-1`):** crear y verificar la identidad del remitente (su direccion) y las
  direcciones de prueba que recibiran (la de `solicitante.demo` y la suya). Mateo decide cuales (pendiente de la
  seccion 7 del diseno).
- [x] **Paso 2 (operador):** `scripts/empaquetar.sh aplicador` (ahora con `avisos.py`), subir el zip con el si de
  Mateo y pasar la `ClaveCodigoAplicador` nueva. Change sets `base-rol-avisos` (`CorreoRemitente`) y `runtime-avisos`
  (`CorreoRemitente`, clave del zip); ejecutar con su si (y `base-rol-avisos-2`: `identity/*`, MEDICIONES §H 40).
- [x] **Paso 3: medicion O.5.** Desde la web, `solicitante.demo` pide con `correo_aviso` verificado; `aprobador.demo`
  aprueba: llegan los correos `aprobada` y `aplicada` (este con rol y vence). Un rechazo previo (recurso
  `agente-iam-x` por el CLI `enviar`) -> correo `rechazada_en_chequeos_previos`. Un `correo_aviso` no verificado ->
  `MessageRejected` en el log y nada mas. Horas UTC de cada `SendEmail` (log) y `MessageId`.

### Tarea 21: documentacion del bloque 3, cierre de la fase y commits

- [x] PLAN Fase 23 completa (los tres bloques, pendientes con quien); CONTEXTO §2 (estado, estados que avisan), §3,
  §5 (SES, Lambda de avisos), §6 (`avisos.py`, `test_avisos.py`), §7, §10, §11; README (variables
  `AGENTE_IAM_REMITENTE`); DESPLIEGUE; MEDICIONES O.5 y §J (vencimiento real si no se espero; consola por
  federacion; refresh token; borrado de roles vencidos); ADR-004 cerrado; ESTUDIO (una leccion si la hay: p. ej. que
  STS admite o no CORS); memoria de Claude (`estado-real-cuenta-aws`, `diseno-fase-10` -> hecho).
- [x] Suite entera en verde (1361 pasados y 1 saltado, 26-10-2026); `ruff`; `mypy`.
- [x] Pedir a Mateo el commit del bloque 3 y el PR (MetMatDav/Agente-IAM#2 ya
  esta abierto sobre esta rama). Queda abierto hasta que Mateo pida los commits.

---

## Notas para la ejecucion

- Revisado el 26-10-2026 por un agente revisor (28 puntos, todos incorporados arriba): entre ellos `aws:CurrentTime`
  en la redundancia (MEDICIONES A.3), la cabecera de sesion fuera del `fetch` por el preflight medido, el pool desde
  `DiscoveryUrl`, los tests existentes que cada tarea adapta, `avisos.py` en `LLEVA_EL_APLICADOR` y el reintento de
  `AccessDenied` tras `CreateRole`.

- Orden dentro del bloque 1: tareas 1, 2 y 3 primero (contratos); 4 y 10 en paralelo con ellas (no se tocan); 5, 6, 7,
  8, 9 y 11 despues (dependen del contrato); 12 y 13 al final. Bloque 2: 14 y 15 en paralelo, 16 y 17 despues.
  Bloque 3: 18 y 19 en paralelo, 20 y 21 despues.
- Cada tarea de codigo la ejecuta un subagente implementador y la revisa otro (Sonnet), y Claude corre la suite entera
  antes de dar la tarea por cerrada. Los subagentes no reciben la cuenta real, ids ni correos.
- Riesgos conocidos y su salida: (a) cfn-lint puede exigir `ThumbprintList` en el proveedor OIDC (usar la huella de
  N.1); (b) la lista de acciones de CloudFront del rol de despliegue puede quedarse corta (el primer change set de
  `web.yaml` lo dira: se anade y se repite, anotando en MEDICIONES); (c) STS puede no responder a CORS (el boton pasa a
  ensenar el comando `asumir`); (d) `test_ci.py` fija que cada modulo este en un lado de cada zip: `personas.py` y
  `avisos.py` entran en las listas de `empaquetar.sh`.
