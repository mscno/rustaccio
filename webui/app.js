(() => {
  const cfg = window.__RUSTACCIO_CONFIG__ || {};
  const prefix = cfg.urlPrefix && cfg.urlPrefix !== "/" ? cfg.urlPrefix : "";

  const state = {
    searchText: "",
    packages: [],
  };

  const els = {
    searchForm: document.getElementById("searchForm"),
    searchInput: document.getElementById("searchInput"),
    viewRoot: document.getElementById("viewRoot"),
    flash: document.getElementById("flash"),
    registryPrefix: document.getElementById("registryPrefix"),
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
    let path = window.location.pathname;
    if (prefix && path.startsWith(prefix)) {
      path = path.slice(prefix.length) || "/";
    }
    return path;
  }

  function toAbsolute(path) {
    return `${prefix}${path}`;
  }

  function isSpaPath(path) {
    return path === "/" || path === "/-/web" || path.startsWith("/-/web/");
  }

  function navigate(path) {
    const normalized = path || "/";
    window.history.pushState({}, "", toAbsolute(normalized));
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

  function renderLoading(label = "Loading...") {
    els.viewRoot.innerHTML = `<section class="card"><p class="pkg-meta">${escapeHtml(label)}</p></section>`;
  }

  function scoreBadge(entry) {
    const score = entry?.score?.final;
    if (typeof score !== "number") {
      return "";
    }
    return `<span class="badge">score ${score.toFixed(2)}</span>`;
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (!headers.has("Accept")) {
      headers.set("Accept", "application/json");
    }

    const res = await fetch(toAbsolute(path), {
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

  function latestVersion(manifest) {
    return manifest?.["dist-tags"]?.latest || "-";
  }

  function parseSemverish(value) {
    const raw = String(value || "");
    const withoutBuild = raw.split("+")[0];
    const [core, prereleaseRaw] = withoutBuild.split("-", 2);
    const parts = core.split(".");
    if (parts.length !== 3) {
      return null;
    }

    const parsed = parts.map((part) => Number.parseInt(part, 10));
    if (parsed.some((part) => Number.isNaN(part) || part < 0)) {
      return null;
    }

    return {
      core: parsed,
      stable: prereleaseRaw == null,
      prerelease: prereleaseRaw || "",
    };
  }

  function compareVersionsDesc(a, b) {
    const left = parseSemverish(a);
    const right = parseSemverish(b);

    if (left && right) {
      for (let index = 0; index < left.core.length; index += 1) {
        if (left.core[index] !== right.core[index]) {
          return right.core[index] - left.core[index];
        }
      }
      if (left.stable !== right.stable) {
        return left.stable ? -1 : 1;
      }
      if (left.prerelease !== right.prerelease) {
        return right.prerelease.localeCompare(left.prerelease, undefined, { numeric: true });
      }
      return String(b).localeCompare(String(a), undefined, { numeric: true });
    }

    if (left && !right) {
      return -1;
    }
    if (!left && right) {
      return 1;
    }

    return String(b).localeCompare(String(a), undefined, { numeric: true });
  }

  function packageVersions(manifest) {
    const versions = new Set();

    Object.keys(manifest?.versions || {}).forEach((version) => versions.add(String(version)));

    Object.values(manifest?.["dist-tags"] || {}).forEach((version) => {
      if (typeof version === "string" && version.trim()) {
        versions.add(version);
      }
    });

    Object.keys(manifest?.time || {}).forEach((version) => {
      if (version !== "created" && version !== "modified") {
        versions.add(version);
      }
    });

    return Array.from(versions).sort(compareVersionsDesc);
  }

  function packageReadme(manifest) {
    return manifest?.readme || "No README published.";
  }

  async function loadSearch(text) {
    const query = new URLSearchParams({ text, size: "100", from: "0" });
    const body = await api(`/-/v1/search?${query.toString()}`);
    state.packages = Array.isArray(body?.objects) ? body.objects : [];
    return state.packages;
  }

  function renderHome() {
    const queryActive = Boolean(state.searchText);
    const queryLabel = queryActive ? `for "${escapeHtml(state.searchText)}"` : "across all packages";

    const cards = state.packages.map((entry) => {
      const pkg = entry.package || {};
      const name = escapeHtml(pkg.name || "unknown");
      const version = escapeHtml(pkg.version || "-");
      const description = escapeHtml(pkg.description || "No description available.");
      const packagePath = `/-/web/detail/${encodeURIComponent(pkg.name || "")}`;
      const maintainers = Array.isArray(pkg.maintainers) ? pkg.maintainers.length : 0;
      const keywords = Array.isArray(pkg.keywords) ? pkg.keywords.length : 0;

      return `<article class="card">
        <div class="pkg-header">
          <a class="pkg-name" data-nav="${escapeHtml(packagePath)}" href="${toAbsolute(packagePath)}">${name}</a>
          <span class="pkg-meta">v${version}</span>
        </div>
        <p class="pkg-desc pkg-meta">${description}</p>
        <div class="badge-row">
          ${scoreBadge(entry)}
          <span class="badge">${maintainers} maintainer${maintainers === 1 ? "" : "s"}</span>
          <span class="badge">${keywords} keyword${keywords === 1 ? "" : "s"}</span>
        </div>
      </article>`;
    });

    const emptyState = `<section class="card empty-state">
      <h2 class="card-heading">No matches found</h2>
      <p class="pkg-meta">Try a broader query, a package scope like <code>@scope</code>, or clear the search box.</p>
    </section>`;

    els.viewRoot.innerHTML = `
      <section class="card">
        <h1 class="card-heading">Packages</h1>
        <p class="pkg-meta">Showing ${state.packages.length} result(s) ${queryLabel}.</p>
        <div class="stat-grid">
          <div class="stat"><span>Results</span><strong>${state.packages.length}</strong></div>
          <div class="stat"><span>Search</span><strong>${queryActive ? "Filtered" : "All"}</strong></div>
        </div>
      </section>
      ${cards.join("") || emptyState}
    `;

    els.viewRoot.querySelectorAll("a[data-nav]").forEach((link) => {
      link.addEventListener("click", (event) => {
        event.preventDefault();
        const path = link.getAttribute("data-nav");
        if (path) {
          navigate(path);
        }
      });
    });
  }

  async function renderPackage(packageName) {
    const manifest = await api(`/${encodeURIComponent(packageName)}`);
    const versions = packageVersions(manifest);
    const tags = Object.entries(manifest["dist-tags"] || {});
    const latest = latestVersion(manifest);
    const latestManifest = manifest.versions?.[latest] || {};
    const latestDist =
      latestManifest?.dist?.tarball ||
      versions.map((version) => manifest.versions?.[version]?.dist?.tarball).find(Boolean) ||
      "";
    const homepage = latestManifest.homepage || "";

    const tagsByVersion = tags.reduce((acc, [tag, version]) => {
      const key = String(version);
      const row = acc.get(key) || [];
      row.push(tag);
      acc.set(key, row);
      return acc;
    }, new Map());

    const versionRows = versions
      .map((version) => {
        const versionManifest = manifest.versions?.[version] || {};
        const tarball = versionManifest?.dist?.tarball || "";
        const matchingTags = tagsByVersion.get(version) || [];
        const publishedAt = manifest?.time?.[version] || "";

        return `<li class="version-row">
          <div>
            <div class="version-topline">
              <code>${escapeHtml(version)}</code>
              ${matchingTags
                .map((tag) => `<span class="badge">tag ${escapeHtml(tag)}</span>`)
                .join("")}
            </div>
            ${publishedAt ? `<div class="pkg-meta">published ${escapeHtml(publishedAt)}</div>` : ""}
          </div>
          <div class="version-actions">
            ${tarball ? `<a class="btn alt" href="${escapeHtml(tarball)}" download>Tarball</a>` : '<span class="pkg-meta">No tarball URL</span>'}
          </div>
        </li>`;
      })
      .join("");

    els.viewRoot.innerHTML = `
      <section class="card">
        <div class="pkg-header">
          <h1 class="card-heading">${escapeHtml(manifest.name || packageName)}</h1>
          <span class="pkg-meta">latest ${escapeHtml(latest)}</span>
        </div>
        <p class="pkg-meta">${escapeHtml(latestManifest.description || "No description available.")}</p>
        <div class="badge-row">
          <span class="badge">${versions.length} version${versions.length === 1 ? "" : "s"}</span>
          <span class="badge">${tags.length} dist-tag${tags.length === 1 ? "" : "s"}</span>
          ${latestDist ? '<span class="badge">tarball available</span>' : ""}
        </div>
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
          <ul class="list version-list">${versionRows || "<li>None</li>"}</ul>
          <div class="form-actions">
            ${latestDist ? `<a class="btn alt" href="${escapeHtml(latestDist)}">Download latest tarball</a>` : ""}
            ${homepage ? `<a class="btn alt" href="${escapeHtml(homepage)}" target="_blank" rel="noreferrer">Homepage</a>` : ""}
          </div>
        </article>
      </section>

      <section class="card">
        <h2 class="panel-title">README</h2>
        <pre>${escapeHtml(packageReadme(manifest))}</pre>
      </section>
    `;
  }

  async function renderRoute() {
    setFlash("");
    const path = routePath();
    renderLoading();

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

      navigate("/");
    } catch (error) {
      setFlash(error.message || "Request failed", "error");
    }
  }

  els.registryPrefix.textContent = cfg.urlPrefix || "/";

  els.searchForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    state.searchText = els.searchInput.value.trim();
    if (!isSpaPath(routePath()) || routePath().startsWith("/-/web/detail/")) {
      navigate("/");
      return;
    }

    renderLoading("Searching packages...");
    try {
      await loadSearch(state.searchText);
      renderHome();
    } catch (error) {
      setFlash(error.message || "Search failed", "error");
    }
  });

  document.addEventListener("click", (event) => {
    const anchor = event.target.closest("a[href]");
    if (!anchor) {
      return;
    }
    if (anchor.target === "_blank" || anchor.hasAttribute("download")) {
      return;
    }
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
      return;
    }

    const url = new URL(anchor.href, window.location.origin);
    if (url.origin !== window.location.origin) {
      return;
    }

    let path = url.pathname;
    if (prefix && path.startsWith(prefix)) {
      path = path.slice(prefix.length) || "/";
    }

    if (!isSpaPath(path)) {
      return;
    }

    event.preventDefault();
    navigate(path);
  });

  window.addEventListener("popstate", () => {
    renderRoute();
  });

  renderRoute();
})();
