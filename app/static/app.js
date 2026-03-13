const state = {
  token: null,
  currentScanId: null,
};

function setStatus(message) {
  document.getElementById("status-line").textContent = message;
}

function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBuffer(value) {
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = (value + padding).replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

function decodeRegistrationOptions(options) {
  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64UrlToBuffer(options.user.id),
    },
    excludeCredentials: (options.excludeCredentials || []).map((credential) => ({
      ...credential,
      id: base64UrlToBuffer(credential.id),
    })),
  };
}

function decodeAuthenticationOptions(options) {
  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((credential) => ({
      ...credential,
      id: base64UrlToBuffer(credential.id),
    })),
  };
}

function serializeRegistrationCredential(credential) {
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToBase64Url(credential.response.attestationObject),
      clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
      transports: credential.response.getTransports ? credential.response.getTransports() : [],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment || null,
  };
}

function serializeAuthenticationCredential(credential) {
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToBase64Url(credential.response.authenticatorData),
      clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
      signature: bufferToBase64Url(credential.response.signature),
      userHandle: credential.response.userHandle ? bufferToBase64Url(credential.response.userHandle) : null,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment || null,
  };
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (state.token) {
    headers.set("Authorization", `Bearer ${state.token}`);
  }
  const response = await fetch(path, { ...options, headers });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.detail || `Request failed with status ${response.status}`);
  }
  return payload;
}

function setSession(authPayload) {
  state.token = authPayload.access_token;
  document.getElementById("profile-name").textContent = `${authPayload.display_name} (${authPayload.username})`;
  document.getElementById("profile-role").textContent = authPayload.role;
  document.getElementById("profile-method").textContent = "passkey";
}

async function registerPasskey() {
  const username = document.getElementById("register-username").value.trim();
  const displayName = document.getElementById("register-display-name").value.trim();
  const role = document.getElementById("register-role").value;
  if (!username || !displayName) {
    throw new Error("Username and display name are required");
  }

  setStatus("Generating passkey registration options...");
  const options = await api("/auth/register/options", {
    method: "POST",
    body: JSON.stringify({ username, display_name: displayName, role }),
  });

  const credential = await navigator.credentials.create({ publicKey: decodeRegistrationOptions(options) });
  const authPayload = await api("/auth/register/verify", {
    method: "POST",
    body: JSON.stringify({ username, credential: serializeRegistrationCredential(credential) }),
  });
  setSession(authPayload);
  setStatus("Passkey registered and session established.");
}

async function loginWithPasskey() {
  const username = document.getElementById("login-username").value.trim();
  if (!username) {
    throw new Error("Username is required");
  }

  setStatus("Generating passkey login options...");
  const options = await api("/auth/login/options", {
    method: "POST",
    body: JSON.stringify({ username }),
  });

  const credential = await navigator.credentials.get({ publicKey: decodeAuthenticationOptions(options) });
  const authPayload = await api("/auth/login/verify", {
    method: "POST",
    body: JSON.stringify({ username, credential: serializeAuthenticationCredential(credential) }),
  });
  setSession(authPayload);
  setStatus("Passkey login successful.");
}

async function startScan() {
  const targetUrl = document.getElementById("scan-target").value.trim();
  const engine = document.getElementById("scan-engine").value;
  const fallback = document.getElementById("scan-fallback").checked;
  if (!targetUrl) {
    throw new Error("Target URL is required");
  }

  setStatus(`Launching ${engine.toUpperCase()} scan...`);
  const payload = await api(`/scans?engine=${encodeURIComponent(engine)}&fallback_to_simulated=${fallback}`, {
    method: "POST",
    body: JSON.stringify({ target_url: targetUrl }),
  });
  state.currentScanId = payload.scan_id;
  document.getElementById("report-scan-id").value = payload.scan_id;
  document.getElementById("scan-output").textContent = JSON.stringify(payload, null, 2);
  setStatus(`Scan complete. Scan ID: ${payload.scan_id}`);
}

async function loadReport() {
  const scanId = document.getElementById("report-scan-id").value.trim() || state.currentScanId;
  if (!scanId) {
    throw new Error("Scan ID is required");
  }

  setStatus("Loading report...");
  const payload = await api(`/reports/${encodeURIComponent(scanId)}`);
  document.getElementById("report-output").textContent = JSON.stringify(payload, null, 2);
  setStatus("Report loaded.");
}

async function loadAudit() {
  setStatus("Loading audit log...");
  const payload = await api("/audit");
  document.getElementById("report-output").textContent = JSON.stringify(payload, null, 2);
  setStatus("Audit log loaded.");
}

function wireEvents() {
  document.getElementById("register-button").addEventListener("click", async () => {
    try {
      await registerPasskey();
    } catch (error) {
      setStatus(error.message);
    }
  });

  document.getElementById("login-button").addEventListener("click", async () => {
    try {
      await loginWithPasskey();
    } catch (error) {
      setStatus(error.message);
    }
  });

  document.getElementById("scan-button").addEventListener("click", async () => {
    try {
      await startScan();
    } catch (error) {
      setStatus(error.message);
    }
  });

  document.getElementById("report-button").addEventListener("click", async () => {
    try {
      await loadReport();
    } catch (error) {
      setStatus(error.message);
    }
  });

  document.getElementById("audit-button").addEventListener("click", async () => {
    try {
      await loadAudit();
    } catch (error) {
      setStatus(error.message);
    }
  });
}

wireEvents();