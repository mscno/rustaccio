(() => {
  const cfg = window.__RUSTACCIO_CONFIG__ || {};
  const prefix = cfg.urlPrefix && cfg.urlPrefix !== "/" ? cfg.urlPrefix : "";

  const state = {
    token: localStorage.getItem("rustaccio_token") || "",
    me: null,
    searchText: "",
    packages: [],
  };

  const els = {
    searchForm: document.getElementById("searchForm"),
    searchInput: document.getElementById("searchInput"),
    viewRoot: document.getElementById("viewRoot"),
    flash: document.getElementById("flash"),
    accountState: document.getElementById("accountState"),
    loginLink: document.getElementById("loginLink"),
    logoutBtn: document.getElementById("logoutBtn"),
    registryPrefix: document.getElementById("registryPrefix"),
    registryWebLogin: document.getElementById("registryWebLogin"),
    registryExternalAuth: document.getElementById("registryExternalAuth"),
  };

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function routePath() {
    let p = window.location.pathname;
    if (prefix && p.startsWith(prefix)) {
      p = p.slice(prefix.length) || "/";
    }
    return p;
  }

  function navigate(path) {
    const url = `${prefix}${path}`;
    window.history.pushState({}, "", url);
    renderRoute();
  }

  function setFlash(message, type = "ok") {
    if (!message) {
      els.flash.className = "flash hidden";
      els.flash.textContent = "";
      return;
    }
    els.flash.className = `flash ${type}`;
    els.flash.textContent = message;
  }

  function setAccountState() {
    if (state.me) {
      els.accountState.textContent = `Signed in as ${state.me.username}`;
      els.loginLink.classList.add("hidden");
      els.logoutBtn.classList.remove("hidden");
    } else {
      els.accountState.textContent = "Not signed in";
      els.loginLink.classList.remove("hidden");
      els.logoutBtn.classList.add("hidden");
    }
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (!headers.has("Accept")) {
      headers.set("Accept", "application/json");
    }
    if (state.token && !headers.has("Authorization")) {
      headers.set("Authorization", `Bearer ${state.token}`);
    }

    const res = await fetch(`${prefix}${path}`, {
      method: options.method || "GET",
      headers,
      body: options.body,
    });

    const contentType = res.headers.get("content-type") || "";
    let payload = null;
    if (contentType.includes("application/json")) {
      payload = await res.json().catch(() => null);
    } else {
      const text = await res.text();
      payload = text ? { message: text } : null;
    }

    if (!res.ok) {
      const message = (payload && (payload.error || payload.message)) || res.statusText;
      throw new Error(message || `HTTP ${res.status}`);
    }

    return payload;
  }

  async function refreshWhoami() {
    if (!state.token) {
      state.me = null;
      setAccountState();
      return;
    }

    try {
      const body = await api("/-/whoami");
      if (body && body.username) {
        state.me = { username: body.username };
      } else {
        state.me = null;
      }
    } catch {
      state.me = null;
      state.token = "";
      localStorage.removeItem("rustaccio_token");
    }
    setAccountState();
  }

  function latestVersion(manifest) {
    const latest = manifest?.["dist-tags"]?.latest;
    return latest || "-";
  }

  function packageReadme(manifest) {
    return manifest?.readme || "No README";
  }

  async function loadSearch(text) {
    const query = new URLSearchParams({ text, size: "100", from: "0" });
    const body = await api(`/-/v1/search?${query.toString()}`);
    state.packages = Array.isArray(body?.objects) ? body.objects : [];
    return state.packages;
  }

  function renderHome() {
    const cards = state.packages.map((entry) => {
      const pkg = entry.package || {};
      const name = escapeHtml(pkg.name || "unknown");
      const version = escapeHtml(pkg.version || "-");
      const description = escapeHtml(pkg.description || "No description");
      const packagePath = `/-/web/detail/${encodeURIComponent(pkg.name || "")}`;

      return `<article class="card">
        <div class="pkg-header">
          <a class="pkg-name" href="${prefix}${packagePath}">${name}</a>
          <span class="pkg-meta">v${version}</span>
        </div>
        <p class="pkg-meta">${description}</p>
      </article>`;
    });

    els.viewRoot.innerHTML = `
      <section class="card">
        <div class="pkg-header">
          <h1 class="pkg-name">Packages</h1>
          <span class="pkg-meta">${cards.length} result(s)</span>
        </div>
      </section>
      ${cards.join("") || '<section class="card"><p class="muted">No packages found.</p></section>'}
    `;

    els.viewRoot.querySelectorAll("a.pkg-name").forEach((link) => {
      link.addEventListener("click", (event) => {
        event.preventDefault();
        const href = link.getAttribute("href") || `${prefix}/`;
        const path = href.startsWith(prefix) ? href.slice(prefix.length) || "/" : href;
        navigate(path);
      });
    });
  }

  async function renderPackage(packageName) {
    const manifest = await api(`/${encodeURIComponent(packageName)}`);
    const versions = Object.keys(manifest.versions || {}).sort().reverse();
    const tags = Object.entries(manifest["dist-tags"] || {});
    const latest = latestVersion(manifest);
    const latestDist = manifest.versions?.[latest]?.dist?.tarball || "";

    els.viewRoot.innerHTML = `
      <section class="card">
        <div class="pkg-header">
          <h1 class="pkg-name">${escapeHtml(manifest.name || packageName)}</h1>
          <span class="pkg-meta">latest: ${escapeHtml(latest)}</span>
        </div>
        <p class="pkg-meta">${escapeHtml(manifest.versions?.[latest]?.description || "")}</p>
      </section>

      <section class="grid two">
        <article class="card">
          <h2 class="panel-title">Dist Tags</h2>
          <ul class="list">${tags
            .map(([tag, version]) => `<li><code>${escapeHtml(tag)}</code> -> <strong>${escapeHtml(String(version))}</strong></li>`)
            .join("") || "<li>None</li>"}</ul>
        </article>
        <article class="card">
          <h2 class="panel-title">Versions</h2>
          <ul class="list">${versions.map((v) => `<li>${escapeHtml(v)}</li>`).join("") || "<li>None</li>"}</ul>
          ${latestDist ? `<p><a href="${escapeHtml(latestDist)}">Download latest tarball</a></p>` : ""}
        </article>
      </section>

      <section class="card">
        <h2 class="panel-title">README</h2>
        <pre>${escapeHtml(packageReadme(manifest))}</pre>
      </section>
    `;
  }

  function parseSessionId(loginUrl) {
    const match = loginUrl.match(/\/-\/v1\/login_cli\/([^/?]+)/);
    return match ? match[1] : null;
  }

  async function loginWithCredentials(username, password) {
    const loginFlow = await api("/-/v1/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    const sessionId = parseSessionId(loginFlow?.loginUrl || "");
    if (!sessionId) {
      throw new Error("invalid login flow response");
    }

    const body = await api(`/-/v1/login_cli/${encodeURIComponent(sessionId)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    const token = body?.token;
    if (!token) {
      throw new Error("login did not return token");
    }

    state.token = token;
    localStorage.setItem("rustaccio_token", token);
    await refreshWhoami();
  }

  async function registerUser(username, password) {
    const body = await api(`/-/user/org.couchdb.user:${encodeURIComponent(username)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: username, password }),
    });

    const token = body?.token;
    if (!token) {
      throw new Error("registration did not return token");
    }

    state.token = token;
    localStorage.setItem("rustaccio_token", token);
    await refreshWhoami();
  }

  async function renderSettings() {
    await refreshWhoami();

    const tokenSection = !state.me || cfg.externalAuthMode
      ? '<p class="muted">Token management is unavailable.</p>'
      : '<div id="tokensList" class="grid"></div>';

    const passwordSection = !state.me || cfg.externalAuthMode
      ? '<p class="muted">Password updates are unavailable.</p>'
      : `<form id="changePasswordForm" class="form">
          <div class="row"><label for="oldPassword">Old Password</label><input id="oldPassword" type="password" required /></div>
          <div class="row"><label for="newPassword">New Password</label><input id="newPassword" type="password" required /></div>
          <button class="btn" type="submit">Change Password</button>
        </form>`;

    const createTokenSection = !state.me || cfg.externalAuthMode
      ? ""
      : `<form id="createTokenForm" class="form">
          <div class="row"><label for="tokenPassword">Password</label><input id="tokenPassword" type="password" required /></div>
          <div class="row"><label><input id="tokenReadonly" type="checkbox" /> Read only</label></div>
          <button class="btn alt" type="submit">Create Token</button>
        </form>`;

    els.viewRoot.innerHTML = `
      <section class="card">
        <h1 class="pkg-name">Settings</h1>
        <p class="pkg-meta">Manage account and tokens.</p>
      </section>

      <section class="grid two">
        <article class="card">
          <h2 class="panel-title">Tokens</h2>
          ${createTokenSection}
          ${tokenSection}
        </article>
        <article class="card">
          <h2 class="panel-title">Password</h2>
          ${passwordSection}
        </article>
      </section>
    `;

    const tokensList = document.getElementById("tokensList");
    if (tokensList) {
      const tokenBody = await api("/-/npm/v1/tokens");
      const tokens = tokenBody?.objects || [];
      tokensList.innerHTML = tokens.length
        ? tokens
            .map((item) => `<div class="token-row"><code>${escapeHtml(item.key || "")}</code><button data-token="${escapeHtml(item.key || "")}" class="btn alt" type="button">Delete</button></div>`)
            .join("")
        : '<p class="muted">No tokens yet.</p>';

      tokensList.querySelectorAll("button[data-token]").forEach((button) => {
        button.addEventListener("click", async () => {
          const tokenKey = button.getAttribute("data-token");
          if (!tokenKey) return;
          try {
            await api(`/-/npm/v1/tokens/token/${encodeURIComponent(tokenKey)}`, { method: "DELETE" });
            setFlash("Token deleted", "ok");
            renderSettings();
          } catch (error) {
            setFlash(error.message || "Failed to delete token", "error");
          }
        });
      });
    }

    const createTokenForm = document.getElementById("createTokenForm");
    if (createTokenForm) {
      createTokenForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const password = document.getElementById("tokenPassword").value;
        const readonly = document.getElementById("tokenReadonly").checked;
        try {
          await api("/-/npm/v1/tokens", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password, readonly }),
          });
          setFlash("Token created", "ok");
          renderSettings();
        } catch (error) {
          setFlash(error.message || "Failed to create token", "error");
        }
      });
    }

    const changePasswordForm = document.getElementById("changePasswordForm");
    if (changePasswordForm) {
      changePasswordForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const oldPassword = document.getElementById("oldPassword").value;
        const newPassword = document.getElementById("newPassword").value;
        try {
          await api("/-/npm/v1/user", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: { old: oldPassword, new: newPassword } }),
          });
          setFlash("Password changed", "ok");
          changePasswordForm.reset();
        } catch (error) {
          setFlash(error.message || "Failed to change password", "error");
        }
      });
    }
  }

  async function renderLogin() {
    els.viewRoot.innerHTML = `
      <section class="card">
        <h1 class="pkg-name">Sign In</h1>
        <p class="pkg-meta">Use credentials, register, or provide an existing token.</p>
      </section>

      <section class="grid two">
        <article class="card">
          <h2 class="panel-title">Credentials</h2>
          <form id="loginForm" class="form">
            <div class="row"><label for="loginUser">Username</label><input id="loginUser" required /></div>
            <div class="row"><label for="loginPassword">Password</label><input id="loginPassword" type="password" required /></div>
            <div class="row">
              <button class="btn" type="submit">Login</button>
              <button id="registerBtn" class="btn alt" type="button">Register</button>
            </div>
          </form>
          <p class="muted">${cfg.webLoginEnabled ? "Web login flow enabled." : "Web login flow disabled; registration still works for new users."}</p>
        </article>

        <article class="card">
          <h2 class="panel-title">Token</h2>
          <form id="tokenForm" class="form">
            <div class="row"><label for="tokenInput">Bearer token</label><textarea id="tokenInput" rows="4" required></textarea></div>
            <button class="btn alt" type="submit">Use Token</button>
          </form>
        </article>
      </section>
    `;

    const loginForm = document.getElementById("loginForm");
    const registerBtn = document.getElementById("registerBtn");
    const tokenForm = document.getElementById("tokenForm");

    loginForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const username = document.getElementById("loginUser").value.trim();
      const password = document.getElementById("loginPassword").value;
      try {
        if (!cfg.webLoginEnabled) {
          throw new Error("web login flow disabled by registry config");
        }
        await loginWithCredentials(username, password);
        setFlash("Signed in", "ok");
        navigate("/");
      } catch (error) {
        setFlash(error.message || "Login failed", "error");
      }
    });

    registerBtn.addEventListener("click", async () => {
      const username = document.getElementById("loginUser").value.trim();
      const password = document.getElementById("loginPassword").value;
      try {
        await registerUser(username, password);
        setFlash("User created and signed in", "ok");
        navigate("/");
      } catch (error) {
        setFlash(error.message || "Registration failed", "error");
      }
    });

    tokenForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const token = document.getElementById("tokenInput").value.trim();
      state.token = token;
      localStorage.setItem("rustaccio_token", token);
      await refreshWhoami();
      if (!state.me) {
        setFlash("Token rejected", "error");
        return;
      }
      setFlash("Signed in with token", "ok");
      navigate("/");
    });
  }

  async function renderRoute() {
    setFlash("");
    const path = routePath();

    try {
      if (path === "/" || path === "/-/web" || path === "/-/web/") {
        await loadSearch(state.searchText || "");
        renderHome();
        return;
      }

      if (path.startsWith("/-/web/detail/")) {
        const packageName = decodeURIComponent(path.slice("/-/web/detail/".length));
        await renderPackage(packageName);
        return;
      }

      if (path === "/-/web/login") {
        await renderLogin();
        return;
      }

      if (path === "/-/web/settings") {
        await renderSettings();
        return;
      }

      navigate("/");
    } catch (error) {
      setFlash(error.message || "Request failed", "error");
    }
  }

  els.registryPrefix.textContent = cfg.urlPrefix || "/";
  els.registryWebLogin.textContent = String(Boolean(cfg.webLoginEnabled));
  els.registryExternalAuth.textContent = String(Boolean(cfg.externalAuthMode));

  els.searchForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    state.searchText = els.searchInput.value.trim();
    if (routePath() !== "/" && routePath() !== "/-/web" && routePath() !== "/-/web/") {
      navigate("/");
      return;
    }
    try {
      await loadSearch(state.searchText);
      renderHome();
    } catch (error) {
      setFlash(error.message || "Search failed", "error");
    }
  });

  els.logoutBtn.addEventListener("click", async () => {
    state.token = "";
    state.me = null;
    localStorage.removeItem("rustaccio_token");
    setAccountState();
    setFlash("Signed out", "ok");
    navigate("/");
  });

  window.addEventListener("popstate", () => {
    renderRoute();
  });

  refreshWhoami().then(renderRoute);
})();
