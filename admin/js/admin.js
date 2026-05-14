(function () {
  const state = { cy: null, focusUid: "", loading: false, findingFilter: "all", graphSpacing: "comfortable" , graphLoaded: false, graphDirty: true, graphLayoutReady: false, graphActivating: false , graphVisibleLayoutReady: false };

  const WPIG_DEFAULT_GRAPH_NODE_TYPES = [
    "post", "page", "term", "user",
    "file", "function", "method", "class", "trait", "interface",
    "duplicate_group", "refactor_opportunity", "finding",
    "malware_indicator", "malware_risk", "malware_scanner",
    "thirdparty_script", "api_endpoint", "cron_job", "open_port",
    "external_domain", "internal_url", "plugin", "theme", "option",
    "surface_issue", "wp_security_issue", "supply_chain_issue",
    "legacy_php", "seo_issue"
  ];

  const WPIG_ROOT_GRAPH_NODE_TYPES = ["root", "root_file", "root_config", "folder"];



  function api(path, options = {}) {
    return fetch(`${WPIG_CONFIG.restUrl}${path}`, {
      ...options,
      headers: { "Content-Type": "application/json", "X-WP-Nonce": WPIG_CONFIG.nonce, ...(options.headers || {}) },
    }).then(async (response) => {
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data?.message || "Request failed");
      return data;
    });
  }

  function setNotice(message, type = "info") {
    const el = document.getElementById("wpig-notice");
    if (!el) return;
    el.hidden = false;
    el.className = `wpig-notice wpig-notice-${type}`;
    el.textContent = message;
  }

  function setSiteScanProgress(percent, step, message) {
    const progress = Math.max(0, Math.min(100, Number(percent || 0)));
    const bar = document.getElementById("wpig-progress-bar");
    const label = document.getElementById("wpig-progress-percent");
    const msg = document.getElementById("wpig-progress-message");

    if (bar) bar.style.width = `${progress}%`;
    if (label) label.textContent = `${Math.round(progress)}%`;
    if (msg && message) msg.textContent = message;

    const order = ["graph", "malware", "quality", "root", "exposure", "results"];
    const activeIndex = Math.max(0, order.indexOf(step));
    document.querySelectorAll(".wpig-progress-step").forEach((el) => {
      const idx = order.indexOf(el.dataset.progressStep);
      el.classList.toggle("is-active", idx === activeIndex);
      el.classList.toggle("is-complete", idx >= 0 && idx < activeIndex);
    });
  }

  function startSiteScanProgress() {
    const shell = document.querySelector(".wpig-app-shell");
    const panel = document.getElementById("wpig-site-scan-progress");
    shell?.classList.add("is-site-scan-running");
    if (panel) panel.hidden = false;
    setSiteScanProgress(5, "graph", "Starting Site Graph Scan…");
  }

  function finishSiteScanProgress(success = true) {
    const shell = document.querySelector(".wpig-app-shell");
    if (success) {
      setSiteScanProgress(100, "results", "Scan complete. Loading results…");
    }
    setTimeout(async () => {
      shell?.classList.remove("is-site-scan-running");
      const panel = document.getElementById("wpig-site-scan-progress");
      if (panel) panel.hidden = true;

      const graphPanel = document.querySelector('.wpig-tab-panel[data-panel="graph"]');
      if (success && graphPanel?.classList.contains("is-active")) {
        await nextFrame();
        await resetFullGraphView({ reload: false, showLoader: false, forceLayout: true });
      }
    }, success ? 900 : 0);
  }

  function failSiteScanProgress(message) {
    setSiteScanProgress(100, "results", message || "Scan failed. Review the error message.");
    finishSiteScanProgress(false);
  }

  function startProgressTicker() {
    const stages = [
      [12, "graph", "Building site graph from posts, pages, links, and taxonomy…"],
      [28, "malware", "Running malware scanner across plugins, themes, uploads, and MU-plugins…"],
      [46, "quality", "Running code quality, SQL, nonce, capability, and refactor checks…"],
      [64, "root", "Reviewing root/config files like wp-config.php and .htaccess…"],
      [78, "exposure", "Checking cron hooks, REST routes, third-party scripts, and ports…"],
      [91, "results", "Saving findings, nodes, edges, and preparing dashboards…"]
    ];

    let index = 0;
    return window.setInterval(() => {
      if (index >= stages.length) return;
      const [percent, step, message] = stages[index];
      setSiteScanProgress(percent, step, message);
      index++;
    }, 2200);
  }

  function nextFrame() {
    return new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  }

  function idlePause(timeout = 250) {
    return new Promise(resolve => {
      if ("requestIdleCallback" in window) {
        requestIdleCallback(resolve, { timeout });
      } else {
        setTimeout(resolve, 40);
      }
    });
  }


  async function fitFullGraphInView() {
    if (!state.cy) return;

    state.cy.resize();
    await nextFrame();

    const visible = state.cy.elements().filter(ele => ele.style("display") !== "none");
    if (visible.length) {
      try {
        state.cy.fit(visible, 95);
        state.cy.center(visible);
      } catch (_) {}
    }

    await nextFrame();
  }



  function showGraphLoading(message = "Loading nodes, edges, and layout…") {
    const loader = document.getElementById("wpig-graph-loading");
    const msg = document.getElementById("wpig-graph-loading-message");
    const card = document.getElementById("wpig-graph-card");

    if (msg) msg.textContent = message;
    if (loader) loader.hidden = false;
    if (card) card.classList.add("is-graph-loading");
  }

  function hideGraphLoading() {
    const loader = document.getElementById("wpig-graph-loading");
    const card = document.getElementById("wpig-graph-card");

    if (loader) loader.hidden = true;
    if (card) card.classList.remove("is-graph-loading");
  }

  async function resetFullGraphView({ reload = false, showLoader = true, forceLayout = false } = {}) {
    if (state.graphActivating) return;
    state.graphActivating = true;
    state.focusUid = "";

    const graphPanel = document.querySelector('.wpig-tab-panel[data-panel="graph"]');
    const graphIsVisible = graphPanel?.classList.contains("is-active");
    const needsFetch = reload || state.graphDirty || !state.graphLoaded || !state.cy;
    const needsLayout = forceLayout || !state.graphLayoutReady || !state.graphVisibleLayoutReady || needsFetch;

    if (showLoader && (needsFetch || needsLayout)) {
      showGraphLoading(needsFetch ? "Fetching graph nodes and edges…" : "Organizing graph on screen…");
    }

    try {
      const ctx = document.getElementById("wpig-graph-context");
      if (ctx) ctx.textContent = "Showing all graph nodes found.";

      if (typeof ensureDefaultGraphNodeFiltersChecked === "function") {
        ensureDefaultGraphNodeFiltersChecked();
      } else if (typeof ensureAllNodeFiltersChecked === "function") {
        ensureAllNodeFiltersChecked();
      }

      if (needsFetch) {
        await loadGraph();
      }

      await nextFrame();

      if (state.cy) {
        state.cy.resize();
        await nextFrame();

        if (needsLayout) {
          if (showLoader) showGraphLoading("Applying the same layout as Reset Graph…");
          applyFilters();
          await nextFrame();

          await runGraphLayoutAndWait(getFullGraphLayout(), 105);

          if (typeof fitFullGraphInView === "function") {
            if (showLoader) showGraphLoading("Fitting graph into view…");
            await fitFullGraphInView();
          }

          state.graphLayoutReady = true;
          state.graphVisibleLayoutReady = !!graphIsVisible;
        } else {
          if (showLoader) showGraphLoading("Restoring graph view…");
          await fitFullGraphInView();
        }
      }

      await nextFrame();
    } finally {
      state.graphActivating = false;
      if (showLoader) setTimeout(hideGraphLoading, 120);
    }
  }

  async function loadGraphAndWaitReady() {
    setSiteScanProgress(94, "results", "Loading graph data from the scan…");
    await loadGraph();

    setSiteScanProgress(96, "results", "Rendering graph nodes and edges…");
    await nextFrame();

    const graphPanelVisibleDuringScan = document.querySelector('.wpig-tab-panel[data-panel="graph"]')?.classList.contains('is-active');

    if (state.cy) {
      state.cy.resize();
      await nextFrame();

      setSiteScanProgress(98, "results", "Organizing graph layout and fitting all nodes into view…");

      if (state.focusUid) {
        await runGraphLayoutAndWait(getFocusedGraphLayout(), 90);
      } else {
        await resetFullGraphView({ reload: false, showLoader: false, forceLayout: true });
        state.graphVisibleLayoutReady = !!graphPanelVisibleDuringScan;
      }

      await idlePause(500);
    }

    setSiteScanProgress(99, "results", "Graph is organized and ready. Finalizing dashboards…");
    await nextFrame();
  }

  function setText(id, value) { const el = document.getElementById(id); if (el) el.textContent = value; }

  function updateFindingsBadges(count) {
    const value = Number(count || 0).toLocaleString();
    setText("wpig-findings-badge", value);
    setText("wpig-graph-findings-count", value);
  }
  function fmt(n) { return new Intl.NumberFormat().format(Number(n || 0)); }
  function esc(v) { return String(v || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;"); }
  function trunc(v, l) { v = String(v || ""); return v.length > l ? `${v.slice(0, l - 1)}…` : v; }

  function activateTab(name) {
    document.querySelectorAll(".wpig-tab").forEach(btn => btn.classList.toggle("is-active", btn.dataset.tab === name));
    document.querySelectorAll(".wpig-tab-panel").forEach(panel => panel.classList.toggle("is-active", panel.dataset.panel === name));

    if (name === "graph") {
      if (state.focusUid) {
        // Focused finding views manage their own graph load/layout.
        return;
      }

      const needsFetch = state.graphDirty || !state.graphLoaded || !state.cy;
      const needsVisibleLayout = !state.graphVisibleLayoutReady;

      if (needsFetch || needsVisibleLayout) {
        showGraphLoading(needsFetch ? "Loading Graph Explorer…" : "Structuring graph like Reset Graph…");
      }

      // Important: wait until the tab panel is visible before measuring and fitting.
      setTimeout(async () => {
        await resetFullGraphView({
          reload: needsFetch,
          showLoader: needsFetch || needsVisibleLayout,
          forceLayout: needsVisibleLayout
        });
      }, 160);
    }
  }

  function applyGraphTheme(theme) {
    const selected = theme === "dark" ? "dark" : "light";
    const card = document.getElementById("wpig-graph-card");
    const graph = document.getElementById("wpig-graph");
    const panel = graph ? graph.closest(".wpig-panel") : null;

    [card, panel].forEach(el => {
      if (!el) return;
      el.classList.toggle("is-graph-dark", selected === "dark");
      el.classList.toggle("is-graph-light", selected !== "dark");
    });

    document.querySelectorAll(".wpig-theme-option").forEach(btn => {
      btn.classList.toggle("is-active", btn.dataset.graphTheme === selected);
    });

    try {
      localStorage.setItem("wpig_graph_theme", selected);
    } catch (_) {}

    if (state.cy) {
      const labelColor = selected === "dark" ? "#e2e8f0" : "#111827";
      const edgeColor = selected === "dark" ? "#475569" : "#cbd5e1";
      const edgeLabelColor = selected === "dark" ? "#cbd5e1" : "#64748b";
      const borderColor = selected === "dark" ? "#0f172a" : "#ffffff";

      state.cy.nodes().style({
        color: labelColor,
        "border-color": borderColor
      });

      state.cy.edges().style({
        "line-color": edgeColor,
        "target-arrow-color": edgeColor,
        color: edgeLabelColor,
        "text-background-color": selected === "dark" ? "#020617" : "#ffffff"
      });
    }
  }

  function initGraphTheme() {
    let saved = "light";
    try {
      saved = localStorage.getItem("wpig_graph_theme") || "light";
    } catch (_) {}
    applyGraphTheme(saved);
  }

  function graphSpacingSettings() {
    return {
      nodeRepulsion: 52000,
      idealEdgeLength: 235,
      edgeElasticity: 48,
      gravity: 0.045,
      numIter: 2800,
      fitPadding: 90,
    };
  }

  function getGraphLayout() {
    const s = graphSpacingSettings();
    return {
      name: "cose",
      animate: false,
      nodeRepulsion: s.nodeRepulsion,
      idealEdgeLength: s.idealEdgeLength,
      edgeElasticity: s.edgeElasticity,
      gravity: s.gravity,
      numIter: s.numIter,
      padding: s.fitPadding,
      nestingFactor: 1.2,
      componentSpacing: 120,
      nodeOverlap: 25,
      refresh: 20,
      randomize: true,
    };
  }

  function getFullGraphLayout() {
    return {
      name: "cose",
      animate: false,
      randomize: true,
      nodeRepulsion: 72000,
      idealEdgeLength: 260,
      edgeElasticity: 42,
      gravity: 0.028,
      numIter: 3600,
      padding: 110,
      nestingFactor: 1.2,
      componentSpacing: 220,
      nodeOverlap: 45,
      refresh: 20
    };
  }

  function getFocusedGraphLayout() {
    return {
      name: "breadthfirst",
      directed: true,
      padding: 80,
      spacingFactor: 1.35,
      animate: false
    };
  }

  function runGraphLayoutAndWait(layoutOptions, fitPadding = 90) {
    return new Promise(resolve => {
      if (!state.cy) return resolve();

      let done = false;
      const finish = async () => {
        if (done) return;
        done = true;

        try {
          state.cy.resize();
          await nextFrame();

          const visible = state.cy.elements().filter(ele => ele.style("display") !== "none");
          if (visible.length) {
            state.cy.fit(visible, fitPadding);
            state.cy.center(visible);
          } else {
            state.cy.fit(undefined, fitPadding);
          }

          await nextFrame();
        } catch (_) {}

        resolve();
      };

      try {
        const visible = state.cy.elements().filter(ele => ele.style("display") !== "none");
        const layout = visible.length ? visible.layout(layoutOptions) : state.cy.layout(layoutOptions);
        state.cy.one("layoutstop", finish);
        layout.run();
        setTimeout(finish, 4200);
      } catch (_) {
        finish();
      }
    });
  }


  function initGraphSpacing() {
    // Comfortable spacing is now the fixed default.
  }


  function activateSubtab(name) {
    document.querySelectorAll(".wpig-subtab").forEach(btn => btn.classList.toggle("is-active", btn.dataset.subtab === name));
    document.querySelectorAll(".wpig-subpanel").forEach(panel => panel.classList.toggle("is-active", panel.dataset.subpanel === name));
  }


  function graphIsLarge() {
    return state.cy && state.cy.nodes().filter(n => n.style("display") !== "none").length > 180;
  }

  function applyLargeGraphMode() {
    if (!state.cy) return;
    const large = graphIsLarge();

    if (large) {
      state.cy.nodes().style({
        label: "",
        "font-size": 0
      });
      state.cy.edges().style({
        label: "",
        opacity: 0.68
      });
    }
  }

  function nodeColor(type) {
    const map = {
      post: "#0f172a",
      page: "#0f172a",
      term: "#64748b",
      user: "#475569",
      media: "#16a34a",
      media_issue: "#22c55e",

      file: "#f59e0b",
      root: "#6d28d9",
      root_file: "#9333ea",
      root_config: "#7e22ce",
      folder: "#94a3b8",
      uploads: "#14b8a6",

      function: "#2563eb",
      method: "#3b82f6",
      class: "#1d4ed8",
      trait: "#60a5fa",
      interface: "#93c5fd",

      duplicate_group: "#16a34a",
      refactor_opportunity: "#22c55e",

      finding: "#dc2626",
      malware_indicator: "#991b1b",
      malware_risk: "#7f1d1d",
      malware_scanner: "#ef4444",

      code_quality: "#2563eb",
      code_quality_scan: "#2563eb",
      legacy_php: "#0ea5e9",
      seo_issue: "#06b6d4",

      surface_issue: "#f97316",
      thirdparty_script: "#fb923c",
      api_endpoint: "#ea580c",
      cron_job: "#fdba74",
      open_port: "#c2410c",

      plugin: "#8b5cf6",
      theme: "#a855f7",
      option: "#7c3aed",
      supply_chain_issue: "#be185d",
      wp_security_issue: "#db2777",

      external_domain: "#64748b",
      internal_url: "#475569"
    };

    return map[type] || "#64748b";
  }

  function nodeShape(type) {
    if (type === "finding") return "diamond";
    if (type === "malware_indicator" || type === "malware_scanner") return "hexagon";
    if (type === "duplicate_group") return "octagon";
    if (type === "refactor_opportunity") return "star";
    if (["function","method","class","trait","interface"].includes(type)) return "round-rectangle";
    if (type === "file") return "round-rectangle";
    if (type === "plugin" || type === "theme") return "barrel";
    return "ellipse";
  }


  function graphFindingMatchesFilter(f, filter) {
    if (!filter || filter === "all") return true;
    if (filter === "critical" || filter === "high") return String(f.severity || "").toLowerCase() === filter;
    if (filter === "code_quality") return String(f.finding_type || "").includes("code_quality") || String(f.evidence?.scanner || "").includes("code_quality");
    if (filter === "root_config") return String(f.finding_type || "").includes("root_config") || String(f.evidence?.scanner || "").includes("root_config");
    if (filter === "malware") {
      const type = String(f.finding_type || "");
      const scanner = String(f.evidence?.scanner || "");
      return type.includes("file_security") || type.includes("yara") || type.includes("clamav") || type.includes("maldet") || scanner.includes("builtin") || scanner.includes("advanced") || scanner.includes("regex") || scanner.includes("ast") || scanner.includes("entropy");
    }
    return true;
  }

  function renderGraphFindings(findings, filter = "all") {
    const list = document.getElementById("wpig-graph-findings-list");
    const count = document.getElementById("wpig-graph-findings-count");
    if (!list) return;

    const filtered = (findings || []).filter(f => graphFindingMatchesFilter(f, filter));

    if (count) count.textContent = String((findings || []).length);

    if (!filtered.length) {
      list.innerHTML = '<div class="wpig-graph-findings-empty">No findings match this filter.</div>';
      return;
    }

    list.innerHTML = filtered.map(f => {
      const file = f.source_file || f.evidence?.path || "";
      const line = f.line_number ? `:${f.line_number}` : "";
      const sev = String(f.severity || "low").toLowerCase();
      const scanner = f.evidence?.scanner || f.finding_type || "";
      const editor = findingEditorUrl(f);
      return `
        <div class="wpig-graph-finding-wrap">
          <button type="button" class="wpig-graph-finding-item" data-focus-finding="${esc(f.uid)}">
            <span class="wpig-graph-finding-sev wpig-sev-${esc(sev)}">${esc(sev)}</span>
            <strong>${esc(f.title || "Finding")}</strong>
            ${file ? `<small>${esc(file)}${esc(line)}</small>` : ""}
            ${scanner ? `<em>${esc(scanner)}</em>` : ""}
          </button>
          ${editor ? `<a class="button button-small wpig-graph-editor-link" href="${esc(editor)}" target="_blank" rel="noopener">Open in WP Editor</a>` : ""}
        </div>
      `;
    }).join("");

    list.querySelectorAll("[data-focus-finding]").forEach(btn => btn.addEventListener("click", async () => {
      const uid = btn.dataset.focusFinding;
      list.querySelectorAll(".wpig-graph-finding-item").forEach(item => item.classList.toggle("is-active", item === btn));
      await focusFindingInGraph(uid);
      setNotice("Graph isolated to this finding, its affected file/code node, direct indicator, and parent folder path.", "success");
    }));
  }

  async function loadGraphFindings(filter = "all") {
    const findings = await api("/findings?status=open");
    window.WPIG_GRAPH_FINDINGS = findings || [];
    updateFindingsBadges(window.WPIG_GRAPH_FINDINGS.length);
    renderGraphFindings(window.WPIG_GRAPH_FINDINGS, filter);
  }


  async function loadGraphFindingCount() {
    try {
      const findings = await api("/findings?status=open");
      window.WPIG_GRAPH_FINDINGS = findings || [];
      updateFindingsBadges(window.WPIG_GRAPH_FINDINGS.length);
      const panel = document.getElementById("wpig-graph-findings-panel");
      if (panel && !panel.hidden) renderGraphFindings(window.WPIG_GRAPH_FINDINGS, "all");
    } catch (_) {}
  }

  async function toggleGraphFindings(forceOpen = null) {
    const panel = document.getElementById("wpig-graph-findings-panel");
    const btn = document.getElementById("wpig-toggle-graph-findings");
    if (!panel) return;

    const isOpen = !panel.hidden && !panel.hasAttribute("hidden");
    const shouldOpen = forceOpen === null ? !isOpen : !!forceOpen;

    if (shouldOpen) {
      panel.hidden = false;
      panel.removeAttribute("hidden");
    } else {
      panel.hidden = true;
      panel.setAttribute("hidden", "hidden");
    }

    if (btn) {
      btn.classList.toggle("is-active", shouldOpen);
      btn.setAttribute("aria-expanded", shouldOpen ? "true" : "false");
    }

    if (shouldOpen) {
      await loadGraphFindings();
    }
  }


  function findingCategory(f) {
    const type = String(f.finding_type || "").toLowerCase();
    const scanner = String(f.evidence?.scanner || "").toLowerCase();

    if (type === "code_quality_scan" || scanner.includes("code_quality")) return "code_quality";
    if (type.startsWith("advanced_") || scanner.startsWith("advanced")) return "malware";
    if (type === "root_config" || scanner.includes("root_config")) return "root_config";
    if (type === "surface_scan" || scanner.includes("surface")) return "surface";
    if (type === "media_scan" || scanner.includes("media")) return "media";
    if (
      type.includes("malware") ||
      type.includes("file_security") ||
      type.includes("yara") ||
      type.includes("clamav") ||
      type.includes("maldet") ||
      scanner.includes("builtin") ||
      scanner.includes("advanced") ||
      scanner.includes("regex") ||
      scanner.includes("ast") ||
      scanner.includes("entropy")
    ) return "malware";

    return "other";
  }

  function categoryLabel(key) {
    return {
      malware: "Malware",
      code_quality: "Code Quality",
      root_config: "Root / Config",
      surface: "Exposure",
      media: "Media",
      other: "Other"
    }[key] || key;
  }

  function severityLabel(key) {
    return {
      critical: "Critical",
      high: "High",
      medium: "Medium",
      low: "Low",
      info: "Info"
    }[key] || key;
  }

  function countBy(items, getKey, keys) {
    const out = {};
    keys.forEach(k => out[k] = 0);
    items.forEach(item => {
      const key = getKey(item);
      out[key] = (out[key] || 0) + 1;
    });
    return out;
  }

  function getScanSummaryForOverview() {
    return getStoredSiteScanResults?.() || {};
  }

  function renderOverviewDonut(counts) {
    const donut = document.getElementById("wpig-overview-donut");
    const legend = document.getElementById("wpig-overview-type-legend");
    if (!donut || !legend) return;

    const order = ["malware", "code_quality", "root_config", "surface", "media", "other"];
    const colors = {
      malware: "#dc2626",
      code_quality: "#2563eb",
      root_config: "#7e22ce",
      surface: "#f97316",
      media: "#16a34a",
      other: "#64748b"
    };
    const total = order.reduce((sum, key) => sum + Number(counts[key] || 0), 0);

    if (!total) {
      donut.style.background = "#e2e8f0";
      donut.innerHTML = "<span>0</span>";
      legend.innerHTML = '<div class="wpig-chart-empty">No findings yet.</div>';
      return;
    }

    let start = 0;
    const segments = order.map(key => {
      const value = Number(counts[key] || 0);
      if (!value) return "";
      const degrees = (value / total) * 360;
      const segment = `${colors[key]} ${start}deg ${start + degrees}deg`;
      start += degrees;
      return segment;
    }).filter(Boolean).join(", ");

    donut.style.background = `conic-gradient(${segments})`;
    donut.innerHTML = `<span>${total.toLocaleString()}</span>`;

    legend.innerHTML = order.map(key => `
      <button class="wpig-chart-legend-row" data-overview-filter="${esc(key === "surface" ? "surface" : key)}">
        <i style="background:${colors[key]}"></i>
        <strong>${esc(categoryLabel(key))}</strong>
        <span>${Number(counts[key] || 0).toLocaleString()}</span>
      </button>
    `).join("");

    legend.querySelectorAll("[data-overview-filter]").forEach(btn => btn.addEventListener("click", async () => {
      const filter = btn.dataset.overviewFilter;
      await openFindingsFilter(filter === "other" ? "all" : filter);
    }));
  }

  function renderOverviewSeverityBars(counts) {
    const box = document.getElementById("wpig-overview-severity-bars");
    if (!box) return;

    const order = ["critical", "high", "medium", "low", "info"];
    const total = Math.max(1, order.reduce((sum, key) => sum + Number(counts[key] || 0), 0));

    box.innerHTML = order.map(key => {
      const value = Number(counts[key] || 0);
      const percent = Math.round((value / total) * 100);
      return `
        <div class="wpig-overview-severity-row wpig-sev-${esc(key)}">
          <div><strong>${esc(severityLabel(key))}</strong><span>${value.toLocaleString()}</span></div>
          <b style="--v:${percent}%"></b>
        </div>
      `;
    }).join("");
  }


  function isMediaFinding(f) {
    const type = String(f.finding_type || "").toLowerCase();
    const scanner = String(f.evidence?.scanner || "").toLowerCase();
    return type.includes("media") || scanner.includes("media") || String(f.source_file || "").includes("/uploads/");
  }

  function wpEditorUrlForPath(path) {
    const clean = String(path || "").replace(/^\/+/, "");
    if (!clean) return "";

    const adminBase = (window.ajaxurl || "").replace(/admin-ajax\.php.*$/, "");
    if (!adminBase) return "";

    if (clean.startsWith("wp-content/themes/")) {
      const parts = clean.split("/");
      const theme = parts[2] || "";
      const file = parts.slice(3).join("/");
      if (theme && file) {
        return `${adminBase}theme-editor.php?theme=${encodeURIComponent(theme)}&file=${encodeURIComponent(file)}`;
      }
    }

    if (clean.startsWith("wp-content/plugins/")) {
      const file = clean.replace(/^wp-content\/plugins\//, "");
      if (file) {
        return `${adminBase}plugin-editor.php?file=${encodeURIComponent(file)}`;
      }
    }

    return "";
  }

  function findingEditorUrl(f) {
    if (isMediaFinding(f)) return "";
    return f.evidence?.editor_url || wpEditorUrlForPath(f.source_file || f.evidence?.path || "");
  }

  function overviewFindingCard(f) {
    const file = f.source_file || f.evidence?.path || "";
    const line = f.line_number ? `:${f.line_number}` : "";
    const editor = findingEditorUrl(f);
    const category = findingCategory(f);
    const scanner = f.evidence?.scanner || categoryLabel(category);

    return `
      <article class="wpig-overview-finding wpig-severity-${esc(f.severity || "low")}">
        <div class="wpig-overview-finding-main">
          <span class="wpig-overview-severity-pill">${esc(f.severity || "low")}</span>
          <div>
            <strong>${esc(f.title || "Finding")}</strong>
            <p>${esc(f.description || "")}</p>
            ${file ? `<code>${esc(file)}${esc(line)}</code>` : ""}
          </div>
        </div>
        <div class="wpig-overview-finding-meta">
          <span>${esc(scanner)}</span>
          <span>Score ${Number(f.score || 0)}</span>
        </div>
        <div class="wpig-overview-finding-actions">
          ${editor ? `<a class="button button-small button-primary" href="${esc(editor)}" target="_blank" rel="noopener">Open in WP Editor</a>` : `<span class="wpig-editor-unavailable">WP Editor unavailable for this item</span>`}
        </div>
      </article>
    `;
  }

  function renderOverviewPriorityFindings(findings) {
    const box = document.getElementById("wpig-overview-priority-list");
    if (!box) return;

    const priority = findings
      .filter(f => ["critical", "high"].includes(String(f.severity || "").toLowerCase()))
      .sort((a, b) => Number(b.score || 0) - Number(a.score || 0))
      .slice(0, 6);

    if (!priority.length) {
      box.innerHTML = '<div class="wpig-empty-state"><strong>No critical/high findings.</strong><span>Great. Use the finding queues below for medium/low review.</span></div>';
      return;
    }

    box.innerHTML = priority.map(overviewFindingCard).join("");
}

  function renderOverviewCoverage(stats, summary) {
    const box = document.getElementById("wpig-overview-coverage");
    if (!box) return;

    const rows = [
      ["Graph Nodes", stats.nodes || 0, "Objects mapped"],
      ["Graph Edges", stats.edges || 0, "Relationships found"],
      ["Files Scanned", summary.files || 0, "Non-media full scan total"],
      ["Malware Files", summary.malware_files || summary.results?.malware?.files || 0, "Security file coverage"],
      ["Code Files", summary.code_quality_files || summary.results?.code_quality?.files || 0, "PHP quality coverage"],
      ["Root Files", summary.root_config_files || summary.results?.root_config?.files || 0, "Config/root coverage"],
    ];

    box.innerHTML = rows.map(([label, value, help]) => `
      <div class="wpig-overview-coverage-card">
        <span>${esc(label)}</span>
        <strong>${Number(value || 0).toLocaleString()}</strong>
        <small>${esc(help)}</small>
      </div>
    `).join("");
  }

  function renderOverviewQueues(counts) {
    const box = document.getElementById("wpig-overview-queues");
    if (!box) return;

    const queues = [
      ["malware", "Malware", counts.malware || 0, "Security indicators and suspicious file behavior"],
      ["code_quality", "Code Quality", counts.code_quality || 0, "SQL, nonce, duplicate/refactor, PHP quality checks"],
      ["root_config", "Root / Config", counts.root_config || 0, "wp-config.php, .htaccess, root files"],
      ["surface", "Exposure", counts.surface || 0, "REST endpoints, cron jobs, scripts, ports"],
      ["media", "Media", counts.media || 0, "Alt text, title, size, dimensions"],
    ];

    box.innerHTML = queues.map(([filter, title, count, desc]) => `
      <button class="wpig-overview-queue" data-overview-queue="${esc(filter)}">
        <div>
          <strong>${esc(title)}</strong>
          <span>${esc(desc)}</span>
        </div>
        <em>${Number(count || 0).toLocaleString()}</em>
      </button>
    `).join("");

    box.querySelectorAll("[data-overview-queue]").forEach(btn => btn.addEventListener("click", async () => {
      await openFindingsFilter(btn.dataset.overviewQueue || "all");
    }));
  }


  function normalizeFindingFilter(filter) {
    const allowed = ["all", "malware", "code_quality", "media", "surface", "root_config", "high"];
    return allowed.includes(filter) ? filter : "all";
  }

  async function openFindingsFilter(filter) {
    state.findingFilter = normalizeFindingFilter(filter);
    document.querySelectorAll(".wpig-finding-filter").forEach(btn => {
      btn.classList.toggle("is-active", btn.dataset.findingFilter === state.findingFilter);
    });
    await loadFindings();
    activateTab("findings");
  }

  async function focusFindingInGraph(uid) {
    if (!uid) return;
    state.focusUid = uid;
    state.graphDirty = true;
    state.graphLayoutReady = false;
      state.graphVisibleLayoutReady = false;
    activateTab("graph");
    showGraphLoading("Loading selected finding in Graph Explorer…");
    setTimeout(async () => {
      try {
        await loadGraph(uid);
        if (state.cy) {
          await runGraphLayoutAndWait(getFocusedGraphLayout(), 90);
        }
      } finally {
        hideGraphLoading();
      }
    }, 120);
  }

  async function loadOverviewDashboard() {
    const [stats, findings] = await Promise.all([
      api("/stats"),
      api("/findings?status=open")
    ]);

    const summary = getScanSummaryForOverview();
    const categoryCounts = countBy(findings, findingCategory, ["malware", "code_quality", "root_config", "surface", "media", "other"]);
    const severityCounts = countBy(findings, f => String(f.severity || "low").toLowerCase(), ["critical", "high", "medium", "low", "info"]);

    setText("wpig-overview-total-findings", fmt(findings.length));
    setText("wpig-overview-priority-findings", fmt((severityCounts.critical || 0) + (severityCounts.high || 0)));
    setText("wpig-overview-malware-findings", fmt(categoryCounts.malware || 0));
    setText("wpig-overview-code-findings", fmt(categoryCounts.code_quality || 0));
    setText("wpig-overview-root-findings", fmt(categoryCounts.root_config || 0));
    setText("wpig-overview-exposure-findings", fmt(categoryCounts.surface || 0));

    renderOverviewDonut(categoryCounts);
    renderOverviewSeverityBars(severityCounts);
    renderOverviewPriorityFindings(findings);
    renderOverviewCoverage(stats, summary);
    renderOverviewQueues(categoryCounts);
  }

  async function loadStats() {
    const s = await api("/stats");
    setText("wpig-stat-nodes", fmt(s.nodes));
    setText("wpig-stat-edges", fmt(s.edges));
    setText("wpig-stat-findings", fmt(s.findings));
    setText("wpig-stat-high-findings", fmt(s.high_findings));
    updateFindingsBadges(s.findings);
  }

  function enabledTypes() {
    return Array.from(document.querySelectorAll(".wpig-filter:checked")).map(i => i.value);
  }

  function ensureDefaultGraphNodeFiltersChecked() {
    document.querySelectorAll(".wpig-filter").forEach(input => {
      input.checked = WPIG_DEFAULT_GRAPH_NODE_TYPES.includes(input.value);
    });
  }

  function ensureAllNodeFiltersChecked() {
    document.querySelectorAll(".wpig-filter").forEach(input => {
      input.checked = true;
    });
  }

  function applyFilters() {
    if (!state.cy) return;

    const enabled = enabledTypes();
    const q = (document.getElementById("wpig-search")?.value || "").toLowerCase();

    state.cy.nodes().forEach(node => {
      const d = node.data();
      const typeMatch = enabled.includes(d.type);
      const searchMatch = !q || String(d.label || "").toLowerCase().includes(q) || String(d.path || "").toLowerCase().includes(q);
      const visible = typeMatch && searchMatch;
      node.style("display", visible ? "element" : "none");
    });

    const visibleNodeIds = new Set();
    state.cy.nodes().forEach(node => {
      if (node.style("display") !== "none") {
        visibleNodeIds.add(node.id());
      }
    });

    state.cy.edges().forEach(edge => {
      const visible = visibleNodeIds.has(edge.source().id()) && visibleNodeIds.has(edge.target().id());
      edge.style("display", visible ? "element" : "none");
    });

    applyLargeGraphMode();
  }

  function createGraph(data) {
    const container = document.getElementById("wpig-graph");
    if (!container || typeof cytoscape === "undefined") return;

    const elements = [
      ...data.nodes.map(n => ({ data: { ...n.data, color: nodeColor(n.data.type), shape: nodeShape(n.data.type), displayLabel: trunc(n.data.label || n.data.id, 36) } })),
      ...data.edges
    ];

    if (state.cy) state.cy.destroy();

    state.cy = cytoscape({
      container,
      elements,
      minZoom: 0.18,
      maxZoom: 2.8,
      wheelSensitivity: 0.05,
      hideEdgesOnViewport: true,
      textureOnViewport: true,
      motionBlur: false,
      minZoom: 0.08,
      maxZoom: 3,
      style: [
        { selector: "node", style: {
          "background-color": "data(color)", shape: "data(shape)", label: "data(displayLabel)", color: "#111827",
          "font-size": 9, "text-valign": "bottom", "text-halign": "center", "text-margin-y": 8,
          width: 26, height: 26, "border-width": 2, "border-color": "#ffffff"
        }},
        { selector: 'node[type = "finding"], node[type = "malware_indicator"], node[type = "duplicate_group"], node[type = "refactor_opportunity"]', style: { width: 34, height: 34, "font-weight": "bold" }},
        { selector: 'node[type = "file"], node[type = "function"], node[type = "method"], node[type = "class"]', style: { width: 40, height: 24 }},
        { selector: "node.highlighted", style: { "border-width": 5, "border-color": "#22c55e", "background-blacken": -0.15 }},
        { selector: "edge", style: {
          width: 1.5, "line-color": "#cbd5e1", "target-arrow-color": "#cbd5e1", "target-arrow-shape": "triangle",
          "curve-style": "bezier", label: "data(label)", "font-size": 8, color: "#64748b",
          "text-background-color": "#ffffff", "text-background-opacity": 0.84, "text-background-padding": 2
        }},
        { selector: "edge.highlighted", style: { width: 4, "line-color": "#22c55e", "target-arrow-color": "#22c55e" }},
      ],
      layout: { name: "preset" },
    });

    state.cy.on("tap", "node", function (event) {
      const d = event.target.data();
      const props = d.properties || {};
      const path = props.path ? `\nPath: ${props.path}` : "";
      const file = props.file ? `\nFile: ${props.file}:${props.line || ""}` : "";
      const url = d.url ? `\nURL: ${d.url}` : "";
      setNotice(`${d.type}: ${d.label}${path}${file}${url}`, "info");
    });

    if (state.focusUid) {
      const focused = state.cy.getElementById(state.focusUid);
      focused.addClass("highlighted");
      focused.connectedEdges().addClass("highlighted");
      focused.connectedEdges().connectedNodes().addClass("highlighted");
      state.cy.fit(focused.connectedEdges().connectedNodes().union(focused), graphSpacingSettings().fitPadding);
      document.getElementById("wpig-graph-context").textContent = "Focused investigation view. Showing the selected finding and connected source/indicator nodes.";
    } else {
      document.getElementById("wpig-graph-context").textContent = "Showing the current site graph. Use filters or click a finding to isolate an issue.";
    }

    applyFilters();
    applyLargeGraphMode();
    if (state.cy) {
      if (data.focused || data.focusUid) {
        runGraphLayoutAndWait(getFocusedGraphLayout(), 90);
      } else {
        runGraphLayoutAndWait(getFullGraphLayout(), 105);
      }
    }
    initGraphTheme();
    initGraphSpacing();
  }

  async function loadGraph(focusUid = state.focusUid) {
    const data = await api(`/graph${focusUid ? `?focus=${encodeURIComponent(focusUid)}` : ""}`);
    createGraph(data);
    state.graphLoaded = true;
    state.graphDirty = false;
    state.graphLayoutReady = false;
    state.graphVisibleLayoutReady = false;
  }

  function findingCard(f) {
    if (f.finding_type === "media_scan" || f.evidence?.scanner === "media") {
      return mediaFindingCard(f);
    }

    const file = f.source_file || f.evidence?.path || "";
    const line = f.line_number ? `:${f.line_number}` : "";
    const owner = f.owner_name ? `${f.owner_type || "owner"}: ${f.owner_name}` : "";
    const snippet = f.matched_snippet || f.evidence?.snippet || "";
    const editorUrl = f.evidence?.editor_url || "";
    const scanner = f.evidence?.scanner ? `<span class="wpig-chip">${esc(f.evidence.scanner)}</span>` : "";
    return `
      <article class="wpig-finding wpig-severity-${esc(f.severity)}">
        <div class="wpig-finding-top"><strong>${esc(f.title)} ${scanner}</strong><span>${esc(f.severity)} · ${Number(f.score || 0)}</span></div>
        <p>${esc(f.description || "")}</p>
        ${file ? `<div class="wpig-file-path"><strong>File:</strong> <code>${esc(file)}${esc(line)}</code></div>` : ""}
        ${owner ? `<div class="wpig-file-path"><strong>Owner:</strong> <code>${esc(owner)}</code></div>` : ""}
        ${f.matched_pattern ? `<div class="wpig-file-path"><strong>Pattern:</strong> <code>${esc(f.matched_pattern)}</code></div>` : ""}
        ${snippet ? `<pre>${esc(snippet)}</pre>` : ""}
        <div class="wpig-finding-actions">
          <button class="button button-small button-primary" data-focus="${esc(f.uid)}">View in Graph</button>
          ${file ? `<button class="button button-small" data-copy="${esc(file)}">Copy Path</button>` : ""}
          ${editorUrl ? `<a class="button button-small" href="${esc(editorUrl)}" target="_blank" rel="noopener">Open in WP Editor</a>` : ""}
          <button class="button button-small" data-status="${esc(f.uid)}" data-value="reviewed">Mark Reviewed</button>
          <button class="button button-small" data-status="${esc(f.uid)}" data-value="ignored">Ignore</button>
        </div>
      </article>`;
  }

  function mediaFindingCard(f) {
    const ev = f.evidence || {};
    const issue = f.matched_pattern || "media_issue";
    const attachmentId = ev.attachment_id || "";
    const file = f.source_file || ev.path || "";
    const issueLabel = {
      missing_alt: "Alt Text",
      missing_title: "Title",
      missing_caption: "Caption",
      missing_description: "Description",
      large_file: "File Size",
      large_dimensions: "Dimensions"
    }[issue] || issue;

    const mediaEditUrl = ev.edit_link || (attachmentId ? `post.php?post=${encodeURIComponent(attachmentId)}&action=edit` : "");
    const rawImageUrl = ev.url || "";

    return `
      <article class="wpig-finding wpig-media-card wpig-severity-${esc(f.severity)}" data-media-card="${esc(f.uid)}">
        <div class="wpig-finding-top">
          <strong>${esc(f.title)} <span class="wpig-chip">media</span></strong>
          <span>${esc(f.severity)} · ${Number(f.score || 0)}</span>
        </div>
        <p>${esc(f.description || "")}</p>

        <div class="wpig-media-issue-pill">Issue: ${esc(issueLabel)}</div>

        ${file ? `<div class="wpig-file-path"><strong>File:</strong> <code>${esc(file)}</code></div>` : ""}
        ${f.matched_snippet ? `<div class="wpig-file-path"><strong>Value:</strong> <code>${esc(f.matched_snippet)}</code></div>` : ""}
        ${attachmentId ? `<div class="wpig-file-path"><strong>Attachment ID:</strong> <code>${esc(attachmentId)}</code></div>` : ""}
        ${Array.isArray(ev.used_on) && ev.used_on.length ? `
          <div class="wpig-used-on">
            <strong>Used on:</strong>
            ${ev.used_on.slice(0, 5).map(item => `<a href="${esc(item.edit_link || item.url || "#")}" target="_blank" rel="noopener">${esc(item.title || ("Post #" + item.id))}</a>`).join("")}
          </div>
        ` : `<div class="wpig-used-on"><strong>Used on:</strong><span>No usage detected in recent scanned content.</span></div>`}

        <div class="wpig-finding-actions">
          <button class="button button-small button-primary" data-focus="${esc(f.uid)}">View in Graph</button>
          ${file ? `<button class="button button-small" data-copy="${esc(file)}">Copy Path</button>` : ""}
          ${mediaEditUrl ? `<a class="button button-small" href="${esc(mediaEditUrl)}">Open Image</a>` : ""}
          ${rawImageUrl ? `<a class="button button-small" href="${esc(rawImageUrl)}" target="_blank" rel="noopener">View File</a>` : ""}
          <button class="button button-small" data-status="${esc(f.uid)}" data-value="reviewed">Mark Reviewed</button>
          <button class="button button-small" data-status="${esc(f.uid)}" data-value="ignored">Ignore</button>
        </div>
      </article>`;
  }

  async function loadFindings() {
    const findings = await api(`/findings?status=open&filter=${encodeURIComponent(state.findingFilter)}`);
    if (state.findingFilter === "all") updateFindingsBadges(findings.length);
    const box = document.getElementById("wpig-findings-list");
    if (!box) return;
    box.innerHTML = findings.length
      ? findings.map(findingCard).join("")
      : `<p>No open findings match the <strong>${esc(state.findingFilter)}</strong> filter. Try All Open or refresh findings.</p>`;
    box.querySelectorAll("[data-focus]").forEach(btn => btn.addEventListener("click", () => {
      focusFindingInGraph(btn.dataset.focus || "");
    }));
    box.querySelectorAll("[data-copy]").forEach(btn => btn.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(btn.dataset.copy || ""); setNotice("File path copied.", "success"); }
      catch (_) { setNotice(btn.dataset.copy || "", "info"); }
    }));
    box.querySelectorAll("[data-status]").forEach(btn => btn.addEventListener("click", async () => {
      await api("/finding-status", { method: "POST", body: JSON.stringify({ uid: btn.dataset.status, status: btn.dataset.value }) });
      setNotice("Finding updated.", "success");
      await hydrateScannerDashboardsFromSummary(getStoredSiteScanResults());
    refreshAll();
    }));
  }

  function renderScannerStatus(status, targetId) {
    const box = document.getElementById(targetId);
    if (!box) return;
    box.innerHTML = Object.entries(status).map(([key, item]) => `
      <div class="wpig-status-item ${item.available ? "is-ok" : "is-off"}">
        <div><strong>${esc(item.name)}</strong><p>${esc(item.description || "")}</p></div>
        <span>${item.available ? "Available" : "Not available"}</span>
      </div>
    `).join("");
  }

  async function loadScannerStatus() {
    const status = await api("/scanner-status");
    renderScannerStatus(status, "wpig-scanner-status");
    renderScannerStatus(status, "wpig-malware-status");
    renderScannerStatus(status, "wpig-malware-status-top");
  }


  function renderDependencyStatus(status) {
    const box = document.getElementById("wpig-dependency-status");
    if (!box || !status) return;

    const items = [
      ["vendor/autoload.php", status.vendor_autoload_exists, "Composer autoloader"],
      ["nikic/php-parser", status.php_parser_available, "AST Scanner dependency"],
      ["composer.json", status.composer_json_exists, "Dependency manifest"],
      ["Composer CLI", status.composer_available, status.composer_path || "composer command"],
      ["shell_exec", status.shell_exec_available, "Required for admin installer"],
      ["Admin installer", status.installer_enabled, "WPIG_ALLOW_COMPOSER_INSTALL"]
    ];

    box.innerHTML = items.map(([label, ok, help]) => `
      <div class="wpig-dependency-item ${ok ? "is-ok" : "is-off"}">
        <span>${ok ? "Available" : "Missing"}</span>
        <strong>${esc(label)}</strong>
        <small>${esc(help)}</small>
      </div>
    `).join("");

    const output = document.getElementById("wpig-composer-output");
    if (output && status.ssh_command) {
      output.dataset.sshCommand = status.ssh_command;
    }
  }

  async function loadDependencyStatus() {
    const status = await api("/dependency-status");
    renderDependencyStatus(status);
    return status;
  }

  async function runComposerInstall() {
    const output = document.getElementById("wpig-composer-output");
    const btn = document.getElementById("wpig-run-composer-install");

    if (btn) {
      btn.disabled = true;
      btn.textContent = "Installing...";
    }
    if (output) {
      output.hidden = false;
      output.innerHTML = "<strong>Running composer install...</strong><pre>Please wait. This can take a moment.</pre>";
    }

    try {
      const result = await api("/install-composer", { method: "POST", body: JSON.stringify({}) });
      renderDependencyStatus(result.status || {});
      if (output) {
        output.hidden = false;
        output.innerHTML = `
          <strong>${esc(result.message || "Composer finished.")}</strong>
          <pre>${esc(result.output || "No output returned.")}</pre>
        `;
      }
      setNotice(result.message || "Composer install finished.", result.success ? "success" : "error");
      await loadScannerStatus();
    } catch (e) {
      if (output) {
        output.hidden = false;
        output.innerHTML = `<strong>Composer install failed</strong><pre>${esc(e.message)}</pre>`;
      }
      setNotice(e.message, "error");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Run Composer Install";
      }
    }
  }

  async function loadInstallerResources() {
    const data = await api("/installer-resources");
    renderScannerStatus(data.availability || {}, "wpig-installer-status");
    renderDependencyStatus(data.dependencies || {});
    const box = document.getElementById("wpig-install-commands");
    if (box) {
      box.innerHTML = Object.values(data.commands || {}).map(group => `
        <div class="wpig-command-card">
          <h3>${esc(group.label)}</h3>
          <pre>${esc((group.commands || []).join("\n"))}</pre>
        </div>
      `).join("");
    }
  }

  function selectedValues(selector) {
    return Array.from(document.querySelectorAll(`${selector}:checked`)).map(i => i.value);
  }

  function renderMalwareResults(summary) {
    const results = document.getElementById("wpig-malware-results");
    const kpis = document.getElementById("wpig-malware-kpis");
    if (!summary) return;

    const engineCount = (summary.engines || [summary.scanner || "builtin"]).length || 1;
    const pathCount = (summary.paths || []).length;
    const files = Number(summary.files || 0);
    const findings = Number(summary.findings || 0);
    const resultEntries = summary.results ? Object.entries(summary.results) : [[summary.scanner || "builtin", summary]];

    if (kpis) {
      const cards = [
        ["Engines", engineCount, "Scanners used"],
        ["Files", files, "Files scanned"],
        ["Findings", findings, "Review items"],
        ["Paths", pathCount, (summary.paths || []).join(", ") || "Selected paths"],
      ];
      kpis.innerHTML = cards.map(([label, value, help]) => `
        <div class="wpig-kpi">
          <span>${esc(label)}</span>
          <strong>${Number(value || 0).toLocaleString()}</strong>
          <small>${esc(help)}</small>
        </div>
      `).join("");
    }

    if (results) {
      const status = findings > 0 ? "Review recommended" : "No malware findings";
      const statusClass = findings > 0 ? "is-warn" : "is-good";
      results.innerHTML = `
        <div class="wpig-quality-summary">
          <div>
            <span class="wpig-score-label">Malware Scanner Status</span>
            <strong class="${statusClass}">${esc(status)}</strong>
            <p>Use the Findings tab filtered to Malware for file-level evidence and graph isolation.</p>
          </div>
          <button class="button" id="wpig-malware-results-filter">View Malware Findings</button>
        </div>
        <div class="wpig-result-list">
          ${resultEntries.map(([engine, data]) => `
            <div class="wpig-result-row">
              <strong>${esc(engine)}</strong>
              <span>${Number(data.findings || 0).toLocaleString()}</span>
              <small>${esc(data.message || `${Number(data.files || 0).toLocaleString()} files scanned across ${(data.paths || []).join(", ") || "selected paths"}.`)}</small>
            </div>
          `).join("")}
        </div>
      `;
      document.getElementById("wpig-malware-results-filter")?.addEventListener("click", async () => {
        state.findingFilter = "malware";
        document.querySelectorAll(".wpig-finding-filter").forEach(btn => btn.classList.toggle("is-active", btn.dataset.findingFilter === "malware"));
        await loadFindings();
        activateTab("findings");
      });
    }
  }


  function renderRootConfigResults(summary) {
    const results = document.getElementById("wpig-malware-results");
    if (!results || !summary) return;

    const rows = [
      ["Files scanned", summary.files || 0, "Root/config/core files reviewed"],
      ["Root files", summary.root_files || 0, "Files in WordPress root"],
      ["Core files", summary.core_files || 0, "wp-admin/wp-includes files scanned when enabled"],
      ["Findings", summary.findings || 0, "Root/config findings created"],
    ];

    results.innerHTML = `
      <div class="wpig-quality-summary">
        <div>
          <span class="wpig-score-label">Root / Config Scan</span>
          <strong class="${Number(summary.findings || 0) ? "is-warn" : "is-good"}">${Number(summary.findings || 0) ? "Review recommended" : "Clean"}</strong>
          <p>Use the Findings tab filtered to Root / Config for file-level details.</p>
        </div>
        <button class="button" id="wpig-root-config-results-filter">View Root / Config Findings</button>
      </div>
      <div class="wpig-result-list">
        ${rows.map(([label, count, help]) => `
          <div class="wpig-result-row">
            <strong>${esc(label)}</strong>
            <span>${Number(count || 0).toLocaleString()}</span>
            <small>${esc(help)}</small>
          </div>
        `).join("")}
      </div>
    `;

    document.getElementById("wpig-root-config-results-filter")?.addEventListener("click", async () => {
      await openFindingsFilter("root_config");
    });
  }

  async function runRootConfigScan() {
    const btn = document.getElementById("wpig-run-root-config-scan");
    const results = document.getElementById("wpig-malware-results");
    const includeCore = selectedValues(".wpig-malware-path").includes("core");
    if (btn) { btn.disabled = true; btn.textContent = "Scanning..."; }
    if (results) results.innerHTML = '<div class="wpig-empty-state"><strong>Root / Config scan running...</strong><span>Reviewing wp-config.php, .htaccess, root files, and optional core files.</span></div>';

    try {
      const res = await api("/root-config-scan", { method: "POST", body: JSON.stringify({ include_core: includeCore }) });
      renderRootConfigResults(res.summary);
      state.graphDirty = true;
      state.graphLayoutReady = false;
      setNotice(`Root / Config scan complete. Files: ${res.summary.files || 0}, findings: ${res.summary.findings || 0}`, "success");
      state.findingFilter = "root_config";
      document.querySelectorAll(".wpig-finding-filter").forEach(btn => btn.classList.toggle("is-active", btn.dataset.findingFilter === "root_config"));
      await refreshAll();
    } catch (e) {
      setNotice(e.message, "error");
      if (results) results.textContent = e.message;
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = "Run Root / Config Scan"; }
    }
  }

  async function runMalwareScan() {
    const btn = document.getElementById("wpig-run-malware-scan");
    const results = document.getElementById("wpig-malware-results");
    const engines = selectedValues(".wpig-malware-engine");
    const paths = selectedValues(".wpig-malware-path");
    if (!engines.length || !paths.length) { setNotice("Select at least one scanner engine and one path.", "error"); return; }
    if (btn) { btn.disabled = true; btn.textContent = "Scanning..."; }
    if (results) results.textContent = "Malware scan running...";
    try {
      const res = await api("/malware-scan", { method: "POST", body: JSON.stringify({ engines, paths }) });
      renderMalwareResults(res.summary);
      setNotice(`Malware scan complete. Findings: ${res.summary.findings || 0}`, "success");
      state.findingFilter = "malware";
      document.querySelectorAll(".wpig-finding-filter").forEach(btn => btn.classList.toggle("is-active", btn.dataset.findingFilter === "malware"));
      await refreshAll();
      // Stay on the current scanner tab; user can click the findings button if needed;
    } catch (e) {
      setNotice(e.message, "error");
      if (results) results.textContent = e.message;
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = "Run Malware Scan"; }
    }
  }



  function renderMediaResults(summary) {
    const results = document.getElementById("wpig-media-results");
    const kpis = document.getElementById("wpig-media-kpis");
    if (!summary) return;

    const kpiItems = [
      ["Attachments", summary.attachments || 0, "Media scanned"],
      ["Findings", summary.findings || 0, "Review items"],
      ["Missing Alt", summary.missing_alt || 0, "Accessibility / SEO"],
      ["Large Files", summary.large_files || 0, "Performance review"],
    ];

    if (kpis) {
      kpis.innerHTML = kpiItems.map(([label, value, help]) => `
        <div class="wpig-kpi">
          <span>${esc(label)}</span>
          <strong>${Number(value || 0).toLocaleString()}</strong>
          <small>${esc(help)}</small>
        </div>
      `).join("");
    }

    if (results) {
      const rows = [
        ["Missing alt text", summary.missing_alt || 0, "Add descriptive alt text or empty alt for decorative images."],
        ["Missing title", summary.missing_title || 0, "Add clear titles for Media Library organization."],
        ["Missing caption", summary.missing_caption || 0, "Optional, but useful for visible context."],
        ["Missing description", summary.missing_description || 0, "Useful for documentation and asset context."],
        ["Large files", summary.large_files || 0, `Over ${summary.large_kb_threshold || 500} KB.`],
        ["Large dimensions", summary.large_dimensions || 0, `Over ${summary.large_dimension_threshold || 2000}px.`],
      ];

      results.innerHTML = `
        <div class="wpig-quality-summary">
          <div>
            <span class="wpig-score-label">Media Status</span>
            <strong class="${Number(summary.findings || 0) ? "is-warn" : "is-good"}">${Number(summary.findings || 0) ? "Review recommended" : "Clean"}</strong>
            <p>Use the Findings tab filtered to Media for each image, attachment edit link, and usage context.</p>
          </div>
          <button class="button" id="wpig-media-results-filter">View Media Findings</button>
        </div>
        <div class="wpig-result-list">
          ${rows.map(([label, count, help]) => `
            <div class="wpig-result-row">
              <strong>${esc(label)}</strong>
              <span>${Number(count || 0).toLocaleString()}</span>
              <small>${esc(help)}</small>
            </div>
          `).join("")}
        </div>
      `;

      document.getElementById("wpig-media-results-filter")?.addEventListener("click", async () => {
        state.findingFilter = "media";
        document.querySelectorAll(".wpig-finding-filter").forEach(btn => btn.classList.toggle("is-active", btn.dataset.findingFilter === "media"));
        await loadFindings();
        activateTab("findings");
      });
    }
  }

  async function runMediaScan() {
    const btn = document.getElementById("wpig-run-media-scan");
    const results = document.getElementById("wpig-media-results");
    const largeKb = document.getElementById("wpig-media-large-kb")?.value || 500;
    if (btn) { btn.disabled = true; btn.textContent = "Scanning..."; }
    if (results) results.textContent = "Media scan running...";
    try {
      const res = await api("/media-scan", { method: "POST", body: JSON.stringify({ large_kb: largeKb }) });
      renderMediaResults(res.summary);
      state.graphDirty = true;
      state.graphLayoutReady = false;
      setNotice(`Media scan complete. Attachments: ${res.summary.attachments || 0}, findings: ${res.summary.findings || 0}`, "success");
      state.findingFilter = "media";
      document.querySelectorAll(".wpig-finding-filter").forEach(btn => btn.classList.toggle("is-active", btn.dataset.findingFilter === "media"));
      await refreshAll();
      // Stay on the current scanner tab; user can click the findings button if needed;
    } catch (e) {
      setNotice(e.message, "error");
      if (results) results.textContent = e.message;
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = "Run Media Scan"; }
    }
  }

  function renderSurfaceResults(summary) {
    const results = document.getElementById("wpig-malware-results");
    const kpis = document.getElementById("wpig-malware-kpis");
    if (kpis) {
      const cards = [
        ["Checks", (summary.checks || []).length, "Exposure checks"],
        ["Cron", summary.cron_events || 0, "Cron hooks"],
        ["Findings", summary.findings || 0, "Review items"],
        ["Open Ports", summary.open_ports || 0, "Detected ports"],
      ];
      kpis.innerHTML = cards.map(([label, value, help]) => `<div class="wpig-kpi"><span>${esc(label)}</span><strong>${Number(value||0).toLocaleString()}</strong><small>${esc(help)}</small></div>`).join("");
    }
    if (results) {
      const rows = [
        ["Cron events", summary.cron_events || 0, "Scheduled WordPress/PHP cron hooks discovered."],
        ["Third-party scripts", summary.thirdparty_scripts || 0, "External scripts found in content."],
        ["REST routes", summary.rest_routes || 0, "Registered REST API routes reviewed."],
        ["Open ports", summary.open_ports || 0, "Ports reachable from server check."],
        ["Findings", summary.findings || 0, "Exposure review items created."],
      ];
      results.innerHTML = `<div class="wpig-quality-summary"><div><span class="wpig-score-label">Exposure Status</span><strong class="${Number(summary.findings||0)?"is-warn":"is-good"}">${Number(summary.findings||0)?"Review recommended":"No exposure findings"}</strong><p>Use Findings filtered to Exposure for the detailed queue.</p></div><button class="button" id="wpig-surface-results-filter">View Exposure Findings</button></div><div class="wpig-result-list">${rows.map(([label,count,help])=>`<div class="wpig-result-row"><strong>${esc(label)}</strong><span>${Number(count||0).toLocaleString()}</span><small>${esc(help)}</small></div>`).join("")}</div>`;
      document.getElementById("wpig-surface-results-filter")?.addEventListener("click", async () => {
        state.findingFilter = "surface";
        document.querySelectorAll(".wpig-finding-filter").forEach(btn => btn.classList.toggle("is-active", btn.dataset.findingFilter === "surface"));
        await loadFindings();
        activateTab("findings");
      });
    }
  }

  async function runSurfaceScan() {
    const btn = document.getElementById("wpig-run-surface-scan");
    const results = document.getElementById("wpig-malware-results");
    const checks = selectedValues(".wpig-surface-check");
    if (!checks.length) { setNotice("Select at least one exposure check.", "error"); return; }
    if (btn) { btn.disabled = true; btn.textContent = "Scanning..."; }
    if (results) results.textContent = "Exposure scan running...";
    try {
      const res = await api("/surface-scan", { method: "POST", body: JSON.stringify({ checks }) });
      renderSurfaceResults(res.summary);
      state.graphDirty = true;
      state.graphLayoutReady = false;
      setNotice(`Exposure scan complete. Findings: ${res.summary.findings || 0}`, "success");
      state.findingFilter = "surface";
      document.querySelectorAll(".wpig-finding-filter").forEach(btn => btn.classList.toggle("is-active", btn.dataset.findingFilter === "surface"));
      await refreshAll();
      // Stay on the current scanner tab; user can click the findings button if needed;
    } catch (e) {
      setNotice(e.message, "error");
      if (results) results.textContent = e.message;
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = "Run Exposure Scan"; }
    }
  }



  function storeSiteScanResults(summary) {
    try {
      localStorage.setItem("wpig_last_site_scan_summary", JSON.stringify(summary || {}));
    } catch (_) {}
  }

  function getStoredSiteScanResults() {
    try {
      return JSON.parse(localStorage.getItem("wpig_last_site_scan_summary") || "{}");
    } catch (_) {
      return {};
    }
  }

  function hydrateScannerDashboardsFromSummary(summary) {
    if (!summary || !summary.results) return;

    if (summary.results.code_quality && typeof renderQualityResults === "function") {
      renderQualityResults(summary.results.code_quality);
    }
    if (summary.results.malware && typeof renderMalwareResults === "function") {
      renderMalwareResults(summary.results.malware);
    }
    if (summary.results.root_config && typeof renderRootConfigResults === "function") {
      renderRootConfigResults(summary.results.root_config);
    }
    if (summary.results.surface && typeof renderSurfaceResults === "function") {
      renderSurfaceResults(summary.results.surface);
    }
  }

  function renderQualityResults(summary) {
    const results = document.getElementById("wpig-quality-results");
    const kpis = document.getElementById("wpig-quality-kpis");
    if (!summary) return;

    const duplicateTotal = Number(summary.duplicate_names || 0) + Number(summary.duplicate_bodies || 0);
    const items = [
      ["Files", summary.files || 0, "PHP files scanned"],
      ["Symbols", summary.symbols || 0, "Functions/classes/methods"],
      ["Findings", summary.findings || 0, "Review items created"],
      ["Duplicate Names", summary.duplicate_names || 0, "Repeated symbol names"],
      ["Duplicate Bodies", summary.duplicate_bodies || 0, "Repeated logic blocks"],
      ["Large Functions", summary.large_functions || 0, "Over line threshold"],
      ["Paths", (summary.paths || []).length, (summary.paths || []).join(", ") || "Selected paths"],
      ["Advanced Risk Files", (summary.results?.advanced?.risk_scores || []).length, "Files with risk scores"],
      ["Duplicates", duplicateTotal, "Name + body groups"]
    ];

    if (kpis) {
      kpis.innerHTML = items.slice(0, 4).map(([label, value, help]) => `
        <div class="wpig-kpi">
          <span>${esc(label)}</span>
          <strong>${Number(value || 0).toLocaleString()}</strong>
          <small>${esc(help)}</small>
        </div>
      `).join("");
    }

    if (results) {
      const findingLevel = Number(summary.findings || 0) > 20 ? "Needs review" : Number(summary.findings || 0) > 0 ? "Review recommended" : "Clean";
      const findingClass = Number(summary.findings || 0) > 20 ? "is-bad" : Number(summary.findings || 0) > 0 ? "is-warn" : "is-good";

      results.innerHTML = `
        <div class="wpig-quality-summary">
          <div>
            <span class="wpig-score-label">Code Quality Status</span>
            <strong class="${findingClass}">${esc(findingLevel)}</strong>
            <p>Use the Findings tab filtered to Code Quality for file-level details and graph isolation.</p>
          </div>
          <button class="button" id="wpig-quality-results-filter">View Code Quality Findings</button>
        </div>

        <div class="wpig-kpi-grid">
          ${items.map(([label, value, help]) => `
            <div class="wpig-kpi">
              <span>${esc(label)}</span>
              <strong>${Number(value || 0).toLocaleString()}</strong>
              <small>${esc(help)}</small>
            </div>
          `).join("")}
        </div>

        <div class="wpig-quality-bars">
          <div class="wpig-quality-bar"><span>Duplicate names</span><b style="--v:${Math.min(100, Number(summary.duplicate_names || 0) * 10)}%"></b><em>${Number(summary.duplicate_names || 0)}</em></div>
          <div class="wpig-quality-bar"><span>Duplicate bodies</span><b style="--v:${Math.min(100, Number(summary.duplicate_bodies || 0) * 10)}%"></b><em>${Number(summary.duplicate_bodies || 0)}</em></div>
          <div class="wpig-quality-bar"><span>Large functions</span><b style="--v:${Math.min(100, Number(summary.large_functions || 0) * 8)}%"></b><em>${Number(summary.large_functions || 0)}</em></div>
          <div class="wpig-quality-bar"><span>Total findings</span><b style="--v:${Math.min(100, Number(summary.findings || 0) * 3)}%"></b><em>${Number(summary.findings || 0)}</em></div>
        </div>
      `;

      document.getElementById("wpig-quality-results-filter")?.addEventListener("click", async () => {
        state.findingFilter = "code_quality";
        document.querySelectorAll(".wpig-finding-filter").forEach(btn => btn.classList.toggle("is-active", btn.dataset.findingFilter === "code_quality"));
        await loadFindings();
        // Stay on the current scanner tab; user can click the findings button if needed;
      });
    }
  }

  async function runQualityScan() {
    const btn = document.getElementById("wpig-run-quality-scan");
    const results = document.getElementById("wpig-quality-results");
    const paths = selectedValues(".wpig-quality-path");
    if (!paths.length) { setNotice("Select at least one code quality path.", "error"); return; }
    if (btn) { btn.disabled = true; btn.textContent = "Scanning..."; }
    document.querySelectorAll(".wpig-quality-tab").forEach(b => b.classList.toggle("is-active", b.dataset.qualityTab === "results"));
    document.querySelectorAll(".wpig-quality-panel").forEach(panel => panel.classList.toggle("is-active", panel.dataset.qualityPanel === "results"));
    if (results) results.innerHTML = '<div class="wpig-empty-state"><strong>Code quality scan running...</strong><span>Scanning selected PHP files and building quality metrics.</span></div>';
    try {
      const res = await api("/code-quality-scan", { method: "POST", body: JSON.stringify({ paths }) });
      renderQualityResults(res.summary);
      setNotice(`Code quality scan complete. Symbols: ${res.summary.symbols || 0}, findings: ${res.summary.findings || 0}`, "success");
      state.findingFilter = "code_quality";
      document.querySelectorAll(".wpig-finding-filter").forEach(btn => btn.classList.toggle("is-active", btn.dataset.findingFilter === "code_quality"));
      await refreshAll();
      // Stay on the current scanner tab; user can click the findings button if needed;
    } catch (e) {
      setNotice(e.message, "error");
      if (results) results.textContent = e.message;
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = "Run Code Quality Scan"; }
    }
  }

  async function refreshAll() {
    try { await Promise.all([loadStats(), loadFindings(), loadScannerStatus(), loadInstallerResources(), loadOverviewDashboard()]); await loadGraph(); await loadGraphFindingCount(); if (!document.getElementById('wpig-graph-findings-panel')?.hidden) await loadGraphFindings(); }
    catch (e) { setNotice(e.message, "error"); }
  }


  function getSiteScanButtons() {
    return Array.from(document.querySelectorAll("#wpig-run-scan, #wpig-overview-run-scan"));
  }

  function setScanButtonsLoading(isLoading) {
    getSiteScanButtons().forEach(btn => {
      btn.disabled = !!isLoading;
      btn.textContent = isLoading ? "Scanning..." : "Run Site Graph Scan";
    });
  }

  async function runSiteScan() {
    if (state.loading) return;
    state.loading = true;

    let ticker = null;

    setScanButtonsLoading(true);
    startSiteScanProgress();
    ticker = startProgressTicker();

    setNotice("Running full site scan. Tabs are hidden until scan results and graph rendering are complete.", "info");

    try {
      const result = await api("/scan", { method: "POST", body: JSON.stringify({ reset: true }) });

      if (ticker) window.clearInterval(ticker);
      setSiteScanProgress(92, "results", "Scan data saved. Preparing dashboards…");

      storeSiteScanResults(result.summary || {});
      hydrateScannerDashboardsFromSummary(result.summary || {});
      state.focusUid = "";
      state.graphDirty = true;
      state.graphLayoutReady = false;

      setSiteScanProgress(93, "results", "Refreshing stats, findings, and scanner status…");
      await Promise.all([
        loadStats(),
        loadFindings(),
        loadScannerStatus(),
        loadInstallerResources()
      ]);

      hydrateScannerDashboardsFromSummary(result.summary || {});
      await loadOverviewDashboard();
      await loadGraphAndWaitReady();

      setNotice(
        `Full site scan complete. Malware: ${result.summary.malware_findings || 0}, Code: ${result.summary.code_quality_findings || 0}, Root/Config: ${result.summary.root_config_findings || 0}, Exposure: ${result.summary.surface_findings || 0}, Total: ${result.summary.findings || 0}`,
        "success"
      );

      finishSiteScanProgress(true);
    } catch (e) {
      if (ticker) window.clearInterval(ticker);
      failSiteScanProgress(e.message);
      setNotice(e.message, "error");
    } finally {
      state.loading = false;
      setScanButtonsLoading(false);
    }
  }


  function setFilterSet(types) {
    const set = new Set(types);
    document.querySelectorAll(".wpig-filter").forEach(i => i.checked = set.has(i.value));
    applyFilters();
  }
  function securityOnly() { setFilterSet(["file","finding","malware_indicator","malware_scanner","plugin","theme","option","uploads","external_domain","thirdparty_script","api_endpoint","cron_job","open_port"]); }
  function qualityOnly() { setFilterSet(["file","function","method","class","trait","interface","duplicate_group","refactor_opportunity","finding","plugin","theme"]); }
  function mediaOnly() { setFilterSet(["media","media_issue","finding"]); }
  function showAll() { document.querySelectorAll(".wpig-filter").forEach(i => i.checked = true); applyFilters(); }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".wpig-tab").forEach(btn => btn.addEventListener("click", () => activateTab(btn.dataset.tab)));
    document.querySelectorAll(".wpig-theme-option").forEach(btn => btn.addEventListener("click", () => applyGraphTheme(btn.dataset.graphTheme || "light")));
    document.querySelectorAll(".wpig-quality-tab[data-quality-tab]").forEach(btn => btn.addEventListener("click", () => {
      const name = btn.dataset.qualityTab;
      document.querySelectorAll(".wpig-quality-tab[data-quality-tab]").forEach(b => b.classList.toggle("is-active", b === btn));
      document.querySelectorAll(".wpig-quality-panel[data-quality-panel]").forEach(panel => panel.classList.toggle("is-active", panel.dataset.qualityPanel === name));
    }));
    document.querySelectorAll(".wpig-quality-tab[data-media-tab-main]").forEach(btn => btn.addEventListener("click", () => {
      const name = btn.dataset.mediaTabMain;
      document.querySelectorAll(".wpig-quality-tab[data-media-tab-main]").forEach(b => b.classList.toggle("is-active", b === btn));
      document.querySelectorAll(".wpig-quality-panel[data-media-panel-main]").forEach(panel => panel.classList.toggle("is-active", panel.dataset.mediaPanelMain === name));
    }));
    document.querySelectorAll(".wpig-quality-tab[data-malware-tab-main]").forEach(btn => btn.addEventListener("click", () => {
      const name = btn.dataset.malwareTabMain;
      document.querySelectorAll(".wpig-quality-tab[data-malware-tab-main]").forEach(b => b.classList.toggle("is-active", b === btn));
      document.querySelectorAll(".wpig-quality-panel[data-malware-panel-main]").forEach(panel => panel.classList.toggle("is-active", panel.dataset.malwarePanelMain === name));
    }));
    document.querySelectorAll(".wpig-subtab").forEach(btn => btn.addEventListener("click", () => activateSubtab(btn.dataset.subtab)));
    document.querySelectorAll(".wpig-finding-filter").forEach(btn => btn.addEventListener("click", () => {
      openFindingsFilter(btn.dataset.findingFilter || "all");
    }));
    document.getElementById("wpig-run-scan")?.addEventListener("click", runSiteScan);
    document.getElementById("wpig-overview-run-scan")?.addEventListener("click", runSiteScan);
    document.getElementById("wpig-overview-refresh")?.addEventListener("click", loadOverviewDashboard);
    document.getElementById("wpig-overview-view-all-findings")?.addEventListener("click", async () => {
      await openFindingsFilter("all");
    });
    document.getElementById("wpig-run-malware-scan")?.addEventListener("click", runMalwareScan);
    document.getElementById("wpig-run-quality-scan")?.addEventListener("click", runQualityScan);
    document.getElementById("wpig-run-media-scan")?.addEventListener("click", runMediaScan);
    document.getElementById("wpig-run-surface-scan")?.addEventListener("click", runSurfaceScan);
    document.getElementById("wpig-quality-graph")?.addEventListener("click", () => { activateTab("graph"); qualityOnly(); });
    document.getElementById("wpig-media-graph")?.addEventListener("click", () => { activateTab("graph"); mediaOnly(); });
    document.getElementById("wpig-check-scanners")?.addEventListener("click", loadScannerStatus);
    document.getElementById("wpig-check-scanners-top")?.addEventListener("click", loadScannerStatus);
    document.getElementById("wpig-installer-refresh")?.addEventListener("click", loadInstallerResources);
    document.getElementById("wpig-dependency-refresh")?.addEventListener("click", loadDependencyStatus);
    document.getElementById("wpig-run-composer-install")?.addEventListener("click", runComposerInstall);
    document.getElementById("wpig-copy-composer-command")?.addEventListener("click", async () => {
      const output = document.getElementById("wpig-composer-output");
      const status = await loadDependencyStatus();
      const command = status.ssh_command || output?.dataset?.sshCommand || "";
      try {
        await navigator.clipboard.writeText(command);
        setNotice("Composer SSH command copied.", "success");
      } catch (_) {
        if (output) {
          output.hidden = false;
          output.innerHTML = `<strong>Composer SSH Command</strong><pre>${esc(command)}</pre>`;
        }
      }
    });
    document.getElementById("wpig-refresh-findings")?.addEventListener("click", loadFindings);
    document.getElementById("wpig-reset-focus")?.addEventListener("click", async () => {
      state.graphDirty = true;
      state.graphVisibleLayoutReady = false;
      await resetFullGraphView({ reload: true, showLoader: true, forceLayout: true });
    });
    document.getElementById("wpig-search")?.addEventListener("input", applyFilters);
    document.querySelectorAll(".wpig-filter").forEach(i => i.addEventListener("change", applyFilters));
    document.getElementById("wpig-toggle-graph-findings")?.addEventListener("click", async (event) => {
      event.preventDefault();
      await toggleGraphFindings();
    });
    document.querySelectorAll("[data-graph-finding-filter]").forEach(btn => btn.addEventListener("click", () => {
      document.querySelectorAll("[data-graph-finding-filter]").forEach(b => b.classList.toggle("is-active", b === btn));
      renderGraphFindings(window.WPIG_GRAPH_FINDINGS || [], btn.dataset.graphFindingFilter || "all");
    }));
    document.getElementById("wpig-check-all-nodes")?.addEventListener("click", () => {
      document.querySelectorAll(".wpig-filter").forEach(i => i.checked = true);
      applyFilters();
    });
    document.getElementById("wpig-uncheck-all-nodes")?.addEventListener("click", () => {
      document.querySelectorAll(".wpig-filter").forEach(i => i.checked = false);
      applyFilters();
    });
    refreshAll();
  });
})();
