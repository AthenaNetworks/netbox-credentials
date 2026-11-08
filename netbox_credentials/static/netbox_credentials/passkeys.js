// netbox-credentials: passkey enrolment and per-read secret reveal.
// Plain navigator.credentials, no build step. Loaded by several panels, so guard against double init.
(function () {
  "use strict";
  if (window.__nbcPasskeys) return;
  window.__nbcPasskeys = true;

  const HIDE_AFTER_MS = 60000;

  function b64urlToBuf(value) {
    const pad = "=".repeat((4 - (value.length % 4)) % 4);
    const b64 = (value + pad).replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function creationOptions(json) {
    const opts = Object.assign({}, json);
    opts.challenge = b64urlToBuf(json.challenge);
    opts.user = Object.assign({}, json.user, { id: b64urlToBuf(json.user.id) });
    opts.excludeCredentials = (json.excludeCredentials || []).map((c) => Object.assign({}, c, { id: b64urlToBuf(c.id) }));
    return opts;
  }

  function requestOptions(json) {
    const opts = Object.assign({}, json);
    opts.challenge = b64urlToBuf(json.challenge);
    opts.allowCredentials = (json.allowCredentials || []).map((c) => Object.assign({}, c, { id: b64urlToBuf(c.id) }));
    return opts;
  }

  function credentialJSON(cred) {
    const r = cred.response;
    const response = { clientDataJSON: bufToB64url(r.clientDataJSON) };
    if (r.attestationObject) {
      response.attestationObject = bufToB64url(r.attestationObject);
      if (typeof r.getTransports === "function") response.transports = r.getTransports();
    }
    if (r.authenticatorData) {
      response.authenticatorData = bufToB64url(r.authenticatorData);
      response.signature = bufToB64url(r.signature);
      if (r.userHandle) response.userHandle = bufToB64url(r.userHandle);
    }
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: response,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: typeof cred.getClientExtensionResults === "function" ? cred.getClientExtensionResults() : {},
    };
  }

  function csrfToken() {
    if (window.CSRF_TOKEN) return window.CSRF_TOKEN;
    const input = document.querySelector("input[name=csrfmiddlewaretoken]");
    return input ? input.value : "";
  }

  async function postJSON(url, body) {
    const resp = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken(), Accept: "application/json" },
      body: JSON.stringify(body || {}),
    });
    let data = {};
    try {
      data = await resp.json();
    } catch (e) {
      data = { error: "Unexpected response from server (HTTP " + resp.status + ")." };
    }
    return { ok: resp.ok, status: resp.status, data: data };
  }

  function describeError(err) {
    if (err && err.name === "NotAllowedError") return "Cancelled, or the passkey prompt timed out.";
    if (err && err.name === "InvalidStateError") return "That authenticator is already registered.";
    if (err && err.name === "SecurityError") return "The browser refused: the site's domain does not match the passkey settings.";
    return (err && err.message) || String(err);
  }

  function alertHTML(kind, text) {
    const div = document.createElement("div");
    div.className = "alert alert-" + kind + " mb-0";
    div.setAttribute("role", "alert");
    div.textContent = text;
    return div;
  }

  // Run an assertion ceremony against a begin endpoint. Returns {challenge_id, credential}.
  async function assert(beginUrl) {
    const begin = await postJSON(beginUrl);
    if (!begin.ok) throw new Error(begin.data.error || "Could not start passkey check.");
    const cred = await navigator.credentials.get({ publicKey: requestOptions(begin.data.options) });
    return { challenge_id: begin.data.challenge_id, credential: credentialJSON(cred) };
  }

  //
  // Reveal
  //

  async function reveal(button) {
    const target = document.getElementById(button.dataset.target);
    if (!target) return;
    const original = target.innerHTML;
    button.disabled = true;
    try {
      const assertion = await assert(button.dataset.beginUrl);
      const finish = await postJSON(button.dataset.finishUrl, assertion);
      if (finish.data.html === undefined) throw new Error(finish.data.error || "Reveal failed.");
      target.innerHTML = finish.data.html;
      target.dataset.nbcOriginal = original;
      if (finish.ok) {
        target._nbcTimer = window.setTimeout(() => hide(target), HIDE_AFTER_MS);
      }
    } catch (err) {
      target.replaceChildren(alertHTML("danger", describeError(err)));
      target.dataset.nbcOriginal = original;
      window.setTimeout(() => hide(target), 8000);
    }
  }

  function hide(target) {
    if (target._nbcTimer) window.clearTimeout(target._nbcTimer);
    if (target.dataset.nbcOriginal !== undefined) {
      target.innerHTML = target.dataset.nbcOriginal;
      delete target.dataset.nbcOriginal;
    }
  }

  //
  // Passkey enrolment and removal
  //

  function status(html) {
    const el = document.getElementById("nbc-passkey-status");
    if (el) el.replaceChildren(html);
  }

  async function register(button) {
    const nameInput = document.getElementById(button.dataset.nameInput);
    const name = nameInput ? nameInput.value.trim() : "";
    button.disabled = true;
    try {
      let body = {};
      if (button.dataset.hasPasskeys === "1") {
        status(alertHTML("info", "Confirm with one of your existing passkeys first."));
        body = await assert(button.dataset.stepupUrl);
      }
      const begin = await postJSON(button.dataset.beginUrl, body);
      if (!begin.ok) throw new Error(begin.data.error || "Could not start registration.");
      status(alertHTML("info", "Follow your browser's prompt to create the passkey."));
      const cred = await navigator.credentials.create({ publicKey: creationOptions(begin.data.options) });
      const finish = await postJSON(button.dataset.finishUrl, {
        challenge_id: begin.data.challenge_id,
        credential: credentialJSON(cred),
        name: name,
      });
      if (!finish.ok) throw new Error(finish.data.error || "Registration failed.");
      window.location.reload();
    } catch (err) {
      status(alertHTML("danger", describeError(err)));
      button.disabled = false;
    }
  }

  async function removePasskey(button) {
    if (!window.confirm("Remove passkey \"" + button.dataset.name + "\"? You will confirm with a passkey.")) return;
    button.disabled = true;
    try {
      const assertion = await assert(button.dataset.stepupUrl);
      const result = await postJSON(button.dataset.deleteUrl, assertion);
      if (!result.ok) throw new Error(result.data.error || "Could not remove passkey.");
      window.location.reload();
    } catch (err) {
      status(alertHTML("danger", describeError(err)));
      button.disabled = false;
    }
  }

  //
  // Event delegation
  //

  document.addEventListener("click", function (event) {
    const el = event.target.closest("[data-nbc-reveal],[data-nbc-copy],[data-nbc-hide],[data-nbc-passkey-register],[data-nbc-passkey-delete]");
    if (!el) return;
    if (!window.PublicKeyCredential && !el.hasAttribute("data-nbc-copy") && !el.hasAttribute("data-nbc-hide")) {
      window.alert("This browser does not support passkeys.");
      return;
    }
    event.preventDefault();
    if (el.hasAttribute("data-nbc-reveal")) {
      reveal(el);
    } else if (el.hasAttribute("data-nbc-copy")) {
      const input = el.closest(".nbc-revealed").querySelector("input");
      navigator.clipboard.writeText(input.value).then(() => {
        el.classList.add("btn-success");
        window.setTimeout(() => el.classList.remove("btn-success"), 1200);
      });
    } else if (el.hasAttribute("data-nbc-hide")) {
      const target = el.closest("[id^=nbc-secret-]");
      if (target) hide(target);
    } else if (el.hasAttribute("data-nbc-passkey-register")) {
      register(el);
    } else if (el.hasAttribute("data-nbc-passkey-delete")) {
      removePasskey(el);
    }
  });
})();
