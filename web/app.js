(() => {
  "use strict";

  // La pagina de Agente IAM: entra con Cognito (PKCE), manda la solicitud al
  // runtime y, si hay rol previsto, canjea el token de identidad por las
  // credenciales del rol en STS.
  //
  // Reglas que fijan los tests (tests/unitarios/test_web.py):
  //  - Los tokens viven solo en variables de esta closure. Recargar la pagina
  //    es volver a entrar. Del almacen de sesion solo salen el verificador PKCE
  //    y el state, que no son tokens y se borran nada mas leerlos.
  //  - Todo se pinta con textContent, nunca como HTML.
  //  - El access token solo viaja al runtime; el id token solo viaja a STS.
  //  - Las listas cerradas y las direcciones salen de config.js, que genera
  //    scripts/construir_web.py; en este fichero no hay nada de la cuenta.
  //  - Fase 28: las credenciales se piden con el id de una solicitud aplicada
  //    (el del correo, o el del enlace ?solicitud=<id>). El id cruza el login
  //    dentro del `state` de OAuth, que Cognito devuelve tal cual: asi el
  //    almacen de sesion sigue guardando solo el verificador y el state.

  const CFG = window.AGENTE_IAM;
  const URL_STS = "https://sts.us-east-1.amazonaws.com/";
  const PREFIJO_USUARIO = "IdentityCenter_";

  let accessToken = null;
  let idToken = null;
  let usuario = "";
  let claveEnvio = null;
  let solicitudDelEnlace = "";

  // El id que forma el servidor: req-AAAAMMDD-8 hex (personas.id_de_solicitud).
  const PATRON_ID = /^req-[0-9]{8}-[0-9a-f]{8}$/;
  // Lo mismo que personas.nombre_de_rol y personas.arn_de_rol: si cambia alli,
  // cambia aqui (lo comprueba tests/unitarios/test_web.py con node).
  const PREFIJO_ROL = "agente-iam-persona-";
  const PATH_PERSONAS = "/agente-iam/personas/";
  const MAX_NOMBRE_ROL = 64;

  const $ = (id) => document.getElementById(id);

  function limpiarError() {
    $("error").textContent = "";
  }

  function mostrarError(texto) {
    $("error").textContent = texto;
  }

  function aleatorioBase64url(bytes) {
    const datos = new Uint8Array(bytes);
    crypto.getRandomValues(datos);
    return base64url(datos);
  }

  function base64url(datos) {
    let texto = "";
    for (const b of datos) {
      texto += String.fromCharCode(b);
    }
    return btoa(texto).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function cargaDelJwt(token) {
    // Solo para pintar el nombre: la firma la valida el servidor.
    const parte = token.split(".")[1] || "";
    const base64 = parte.replace(/-/g, "+").replace(/_/g, "/");
    const relleno = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    const binario = atob(relleno);
    const bytes = Uint8Array.from(binario, (c) => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  }

  function nombreDeUsuario(token) {
    const bruto = String(cargaDelJwt(token).username || "");
    return bruto.startsWith(PREFIJO_USUARIO) ? bruto.slice(PREFIJO_USUARIO.length) : bruto;
  }

  function rellenar(selectId, valores) {
    const select = $(selectId);
    select.textContent = "";
    for (const valor of valores) {
      const opcion = document.createElement("option");
      opcion.value = valor;
      opcion.textContent = valor;
      select.appendChild(opcion);
    }
  }

  function prepararFormulario() {
    rellenar("servicio", CFG.servicios);
    rellenar("region", CFG.regiones);
    const horas = $("horas");
    horas.min = String(CFG.horasMin);
    horas.max = String(CFG.horasMax);
    horas.value = String(CFG.horasMin);
    const horasSesion = $("horas_sesion");
    horasSesion.min = String(CFG.horasMin);
    horasSesion.max = String(CFG.horasMax);
    $("usuario").textContent = usuario;
    $("quien").hidden = false;
    $("formulario").hidden = false;
    $("credenciales").hidden = false;
    if (solicitudDelEnlace) {
      $("solicitud_usar").value = solicitudDelEnlace;
    }
    $("entrar").hidden = true;
  }

  async function entrar() {
    limpiarError();
    try {
      const verifier = aleatorioBase64url(48);
      // El id del enlace del correo viaja en el state (ver arriba): base64url no lleva ".".
      const state = aleatorioBase64url(24) + (solicitudDelEnlace ? "." + solicitudDelEnlace : "");
      const resumen = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
      sessionStorage.setItem("agente-iam.verifier", verifier);
      sessionStorage.setItem("agente-iam.state", state);
      const params = new URLSearchParams({
        response_type: "code",
        client_id: CFG.clienteId,
        redirect_uri: location.origin + "/",
        scope: "openid email",
        identity_provider: "IdentityCenter",
        code_challenge: base64url(new Uint8Array(resumen)),
        code_challenge_method: "S256",
        state: state,
      });
      location.assign(CFG.dominioCognito + "/oauth2/authorize?" + params.toString());
    } catch (e) {
      mostrarError("No se pudo iniciar la entrada: el navegador no admite lo que hace falta.");
    }
  }

  async function volverDeCognito(params) {
    const code = params.get("code");
    const state = params.get("state");
    const hayError = params.has("error");
    const esperado = sessionStorage.getItem("agente-iam.state");
    const verifier = sessionStorage.getItem("agente-iam.verifier");
    sessionStorage.removeItem("agente-iam.state");
    sessionStorage.removeItem("agente-iam.verifier");
    history.replaceState(null, "", location.pathname);
    if (hayError) {
      mostrarError("No se pudo entrar: vuelve a intentarlo.");
      return;
    }
    if (!code || !state || !esperado || state !== esperado || !verifier) {
      mostrarError("La respuesta de entrada no es valida: vuelve a entrar.");
      return;
    }
    const idEnElState = state.split(".")[1] || "";
    solicitudDelEnlace = PATRON_ID.test(idEnElState) ? idEnElState : "";
    try {
      const cuerpo = new URLSearchParams({
        grant_type: "authorization_code",
        client_id: CFG.clienteId,
        code: code,
        redirect_uri: location.origin + "/",
        code_verifier: verifier,
      });
      const respuesta = await fetch(CFG.dominioCognito + "/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: cuerpo.toString(),
      });
      if (!respuesta.ok) {
        mostrarError("No se pudo canjear la entrada: vuelve a entrar.");
        return;
      }
      const datos = await respuesta.json();
      if (!datos.access_token || !datos.id_token) {
        mostrarError("La respuesta de entrada no trae los tokens: vuelve a entrar.");
        return;
      }
      accessToken = datos.access_token;
      idToken = datos.id_token;
      usuario = nombreDeUsuario(accessToken);
      prepararFormulario();
    } catch (e) {
      mostrarError("No se pudo hablar con el servicio de entrada: vuelve a intentarlo.");
    }
  }

  // Un texto fijo por estado (medido el 26-10-2026, MEDICIONES O.4: una
  // peticion que ya cubre un rol vigente sale redundante y no crea nada).
  const MENSAJES = {
    propuesta: "Cuando se decida te avisaremos a ",
    redundante_no_requiere_cambio: "Ya tienes ese acceso con un rol vigente: no hace falta un permiso nuevo.",
    rechazada_en_chequeos_previos: "La solicitud no pasa las reglas del sistema y no se tramita.",
    requiere_revision_humana: "El sistema no pudo proponer una politica segura; una persona la revisara.",
    error: "La solicitud no se pudo procesar; vuelve a intentarlo.",
  };

  // Fase 30: los unicos estados que pueden acabar en un rol. En los demas la
  // fila "Rol previsto" se esconde (MEDICIONES R.11); un estado nuevo sale
  // oculto hasta que se anada aqui.
  const ESTADOS_CON_ROL = ["propuesta", "aprobada", "aplicada"];

  function mensajeDelEstado(estado, correo) {
    if (estado === "propuesta") {
      return MENSAJES.propuesta + correo +
        ". Si se aplica, usa el id de la solicitud en \"Usar un acceso aprobado\".";
    }
    // Fase 28: los demas estados ya dicen su porque en el motivo.
    return "";
  }

  function pintarResultado(cuerpo, correo) {
    const registro = cuerpo.registro || {};
    $("solicitud_id").textContent = String(cuerpo.solicitud_id || "");
    $("estado").textContent = String(registro.estado || "");
    $("rol_previsto").textContent = String(cuerpo.rol_previsto || "ninguno");
    const sinRol = !ESTADOS_CON_ROL.includes(registro.estado);
    $("rol_previsto_etiqueta").hidden = sinRol;
    $("rol_previsto").hidden = sinRol;
    const motivo = registro.motivo || {};
    $("motivo").textContent = String(motivo.texto || MENSAJES[registro.estado] || "");
    $("mensaje").textContent = mensajeDelEstado(registro.estado, correo);
    $("resultado").hidden = false;
    // Solo una propuesta puede acabar en un rol: se deja su id listo para cuando se aplique.
    if (registro.estado === "propuesta" && PATRON_ID.test(String(cuerpo.solicitud_id || ""))) {
      $("solicitud_usar").value = String(cuerpo.solicitud_id);
    }
  }

  function pintarErrorDelServidor(cuerpo) {
    if (cuerpo.codigo === "forma_invalida") {
      mostrarError("Revisa estos campos: " + String(cuerpo.detalle));
    } else if (cuerpo.codigo === "registro_existente") {
      mostrarError("Esta solicitud ya se envio: " + String(cuerpo.id));
    } else {
      mostrarError(String(cuerpo.codigo));
    }
  }

  async function enviar(evento) {
    evento.preventDefault();
    limpiarError();
    $("resultado").hidden = true;
    $("salida_credenciales").textContent = "";
    if (!accessToken) {
      mostrarError("La sesion no vale o caduco: vuelve a entrar.");
      return;
    }
    if (!claveEnvio) {
      claveEnvio = crypto.randomUUID();
    }
    const horas = Number($("horas").value);
    const correo = $("correo_aviso").value;
    const carga = {
      campos: {
        servicio: $("servicio").value,
        recurso: $("recurso").value,
        region: $("region").value,
      },
      horas: horas,
      correo_aviso: correo,
      justificacion: $("justificacion").value,
      clave_envio: claveEnvio,
    };
    $("enviar").disabled = true;
    try {
      const respuesta = await fetch(CFG.urlRuntime, {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + accessToken,
          "Content-Type": "application/json",
          // Medido el 26-10-2026 (MEDICIONES O.4): el preflight del runtime admite
          // esta cabecera si se pide. Id de sesion de 33+ caracteres, como solicitar.py.
          "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": idDeSesion(),
        },
        body: JSON.stringify(carga),
      });
      if (respuesta.status === 401 || respuesta.status === 403) {
        mostrarError("La sesion no vale o caduco: vuelve a entrar.");
        return;
      }
      if (respuesta.status === 424) {
        mostrarError("El servicio no pudo atender la solicitud.");
        return;
      }
      const cuerpo = await respuesta.json();
      if (cuerpo.resultado === "error") {
        pintarErrorDelServidor(cuerpo);
      } else if (cuerpo.resultado === "procesada") {
        pintarResultado(cuerpo, correo);
        claveEnvio = null;
      } else {
        mostrarError("El servicio respondio algo inesperado.");
      }
    } catch (e) {
      mostrarError("No se pudo hablar con el servicio: vuelve a intentarlo.");
    } finally {
      $("enviar").disabled = false;
    }
  }

  function idDeSesion() {
    return "solicitud-" + crypto.randomUUID() + "-" + crypto.randomUUID();
  }

  function nombreDeSesion() {
    const normal = usuario.normalize("NFKC").toLowerCase().replace(/[^a-z0-9+=,.@_-]/g, "-");
    return ("agente-iam-" + normal).slice(0, 64);
  }

  function nombreDeRol(nombreDeUsuario, solicitudId) {
    // personas.nombre_de_rol: prefijo, usuario normalizado (NFKC, minusculas,
    // fuera del alfabeto a "-") recortado para que quepa en 64, y el id entero.
    // toLowerCase no es casefold de Python: difieren en letras raras (la eszett);
    // con ellas el ARN sale distinto y STS responde AccessDenied, que se dice.
    const sufijo = "-" + solicitudId.toLowerCase();
    const normal = nombreDeUsuario.normalize("NFKC").toLowerCase().replace(/[^a-z0-9+=.@_-]/g, "-");
    const margen = Math.max(MAX_NOMBRE_ROL - PREFIJO_ROL.length - sufijo.length, 0);
    return PREFIJO_ROL + normal.slice(0, margen) + sufijo;
  }

  function arnDeRol(solicitudId) {
    return "arn:aws:iam::" + CFG.cuenta + ":role" + PATH_PERSONAS + nombreDeRol(usuario, solicitudId);
  }

  function errorDeSts(codigo, mensaje) {
    if (codigo === "AccessDenied") {
      return "Ese acceso todavia no esta aplicado, ya vencio o no es tuyo.";
    }
    if (codigo === "ValidationError" && /DurationSeconds/.test(mensaje)) {
      return "Pide menos horas: el acceso dura menos que eso.";
    }
    return codigo + ": " + mensaje;
  }

  function leerTexto(documento, etiqueta) {
    const nodo = documento.getElementsByTagName(etiqueta)[0];
    return nodo ? nodo.textContent : "";
  }

  async function obtener() {
    limpiarError();
    $("salida_credenciales").textContent = "";
    if (!idToken) {
      mostrarError("La sesion no vale o caduco: vuelve a entrar.");
      return;
    }
    const solicitudId = $("solicitud_usar").value.trim();
    if (!PATRON_ID.test(solicitudId)) {
      mostrarError("Escribe el id de la solicitud, con la forma req-AAAAMMDD-xxxxxxxx.");
      return;
    }
    const rol = arnDeRol(solicitudId);
    const horasSesion = Number($("horas_sesion").value);
    if (!Number.isInteger(horasSesion) || horasSesion < CFG.horasMin || horasSesion > CFG.horasMax) {
      mostrarError("Las horas de la sesion van de " + String(CFG.horasMin) + " a " + String(CFG.horasMax) + ".");
      return;
    }
    const campos = [
      ["Action", "AssumeRoleWithWebIdentity"],
      ["Version", "2011-06-15"],
      ["RoleArn", rol],
      ["RoleSessionName", nombreDeSesion()],
      ["WebIdentityToken", idToken],
      ["DurationSeconds", String(horasSesion * 3600)],
    ];
    const cuerpo = campos
      .map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v))
      .join("&");
    $("obtener").disabled = true;
    try {
      const respuesta = await fetch(URL_STS, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: cuerpo,
      });
      const texto = await respuesta.text();
      const documento = new DOMParser().parseFromString(texto, "application/xml");
      const codigo = leerTexto(documento, "Code");
      if (codigo) {
        mostrarError(errorDeSts(codigo, leerTexto(documento, "Message")));
        return;
      }
      const clave = leerTexto(documento, "AccessKeyId");
      const secreto = leerTexto(documento, "SecretAccessKey");
      const sesion = leerTexto(documento, "SessionToken");
      if (!clave || !secreto || !sesion) {
        mostrarError("STS respondio algo inesperado.");
        return;
      }
      $("salida_credenciales").textContent = [
        "export AWS_ACCESS_KEY_ID=" + clave,
        "export AWS_SECRET_ACCESS_KEY=" + secreto,
        "export AWS_SESSION_TOKEN=" + sesion,
        "# caduca: " + leerTexto(documento, "Expiration"),
      ].join("\n");
    } catch (e) {
      mostrarError(
        "El navegador no pudo hablar con STS; usa en tu terminal: " +
        "./.venv/bin/python scripts/solicitar.py asumir " + rol +
        " --usuario <tu usuario> --horas " + String(horasSesion));
    } finally {
      $("obtener").disabled = false;
    }
  }

  function iniciar() {
    if (!CFG) {
      mostrarError("Falta config.js: la pagina se construye con scripts/construir_web.py.");
      $("entrar_boton").disabled = true;
      return;
    }
    $("entrar_boton").addEventListener("click", entrar);
    $("formulario").addEventListener("submit", enviar);
    $("obtener").addEventListener("click", obtener);
    const params = new URLSearchParams(location.search);
    if (params.has("code") || params.has("error")) {
      volverDeCognito(params);
    } else if (PATRON_ID.test(params.get("solicitud") || "")) {
      // El enlace del correo de `aplicada`: se recuerda para despues de entrar.
      solicitudDelEnlace = params.get("solicitud");
    }
  }

  iniciar();
})();
