/**
 * Graph viewer.
 *
 * On disk the runner writes per-seed files under results/runs/:
 *   attack_<DATETIME>_<RUNID>_seed_<SEED>_<CAMPAIGN>.json          (chain)
 *   attack_graph_<DATETIME>_<RUNID>_seed_<SEED>_<CAMPAIGN>.json    (graph)
 * runtime_server reassembles them into the legacy {variations: [...], passes: {...}}
 * shape this viewer expects, so this file just consumes the JSON payload.
 *
 * Endpoints:
 *   GET /api/graph/runs        - list available runs (one row per run_id)
 *   GET /api/graph/<run_id>    - full payload for one run (all seeds merged)
 */

import { byId, escapeHtml } from "./utils/dom.js";
import { formatDuration } from "./utils/format.js";
import { renderDag } from "./graph_dag.js";
import { fetchFragmentsFiles } from "./api/client.js";

const API_RUNS = "/api/graph/runs";
const API_RUN  = (id) => `/api/graph/${encodeURIComponent(id)}`;

let _fragmentsPath = "";

function getFragmentsParam() {
  const params = new URLSearchParams(location.search);
  return params.get("fragments") || "";
}

function setFragmentsParam(path) {
  const params = new URLSearchParams(location.search);
  if (path) params.set("fragments", path);
  else params.delete("fragments");
  const qs = params.toString();
  const url = `${location.pathname}${qs ? `?${qs}` : ""}${location.hash}`;
  history.replaceState(null, "", url);
}

function syncTabsHrefs(path) {
  document.querySelectorAll(".view-tab").forEach((a) => {
    const base = a.getAttribute("href").split("?")[0];
    a.href = path ? `${base}?fragments=${encodeURIComponent(path)}` : base;
  });
}

function passDotClass(passed) {
  if (passed === true) return "pass-dot pass-dot-ok";
  if (passed === false) return "pass-dot pass-dot-fail";
  return "pass-dot pass-dot-none";
}

function passCellClass(passed) {
  if (passed === true) return "pass-cell pass-cell-ok";
  if (passed === false) return "pass-cell pass-cell-fail";
  return "pass-cell";
}

async function fetchRuns() {
  const url = _fragmentsPath
    ? `${API_RUNS}?fragments=${encodeURIComponent(_fragmentsPath)}`
    : API_RUNS;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch ${url} failed: ${res.status}`);
  const body = await res.json();
  return body.runs || [];
}

async function fetchRun(runId) {
  const res = await fetch(API_RUN(runId));
  if (!res.ok) throw new Error(`fetch graph run ${runId} failed: ${res.status}`);
  return res.json();
}

function renderPassStrip(passes, seeds) {
  if (!Array.isArray(passes) || passes.length === 0) {
    return `<div class="muted-line">no pass vector recorded</div>`;
  }
  const cells = passes
    .map((p, i) => {
      const seed = Array.isArray(seeds) ? seeds[i] : i;
      return `<button class="${passCellClass(p)} pass-cell-button" data-seed-idx="${i}" title="seed ${seed}: ${p ? "PASS" : "FAIL"}"></button>`;
    })
    .join("");
  return `<div class="pass-strip pass-strip-large">${cells}</div>`;
}

function renderRunSummary(payload) {
  const graph = payload.graph || {};
  const passes = (payload.passes || {}).passes || [];
  const seeds = graph.variations ? graph.variations.map((v) => v.seed) : [];
  const passed = passes.filter(Boolean).length;
  const total = passes.length || (graph.variations || []).length;
  const summary = byId("graph-run-summary");
  const targetLabel = graph.llm_product
    || (graph.target_backend && graph.target_model
        ? `${graph.target_backend}:${graph.target_model}`
        : graph.target_model || null);
  summary.innerHTML = `
    <div class="sidebar-meta-row"><strong>Run:</strong> <span class="mono">${escapeHtml(payload.run_id || "n/a")}</span></div>
    <div class="sidebar-meta-row"><strong>Campaign:</strong> ${escapeHtml(graph.campaign || "n/a")}</div>
    <div class="sidebar-meta-row"><strong>Style:</strong> ${graph.style ? `<span class="chip chip-cyan">${escapeHtml(graph.style)}</span>` : "n/a"}</div>
    <div class="sidebar-meta-row"><strong>Target LLM:</strong> ${targetLabel ? `<span class="chip chip-cyan">${escapeHtml(targetLabel)}</span>` : "n/a"}</div>
    ${graph.judge_model ? `<div class="sidebar-meta-row"><strong>Judge LLM:</strong> <span class="chip">${escapeHtml(graph.judge_model)}</span></div>` : ""}
    <div class="sidebar-meta-row"><strong>Variations:</strong> ${total}</div>
    <div class="sidebar-meta-row"><strong>Pass:</strong> <span class="chip chip-green">${passed}/${total}</span></div>
    <div class="sidebar-meta-row"><strong>Started:</strong> <span class="mono">${escapeHtml(graph.started_at || "n/a")}</span></div>
    <div class="sidebar-meta-row"><strong>Ended:</strong> <span class="mono">${escapeHtml(graph.ended_at || "n/a")}</span></div>
    ${renderPassStrip(passes, seeds)}
  `;
}

function renderSidebarList(payload) {
  const graph = payload.graph || {};
  const variations = graph.variations || [];
  const list = byId("graph-sidebar-list");
  list.innerHTML = variations
    .map(
      (v) =>
        `<button class="sidebar-sub graph-side-item" data-seed="${v.seed}">
          <span class="${passDotClass(v.passed)}"></span>
          <span class="graph-side-label">seed ${escapeHtml(String(v.seed))}</span>
        </button>`
    )
    .join("");

  list.querySelectorAll(".graph-side-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      const seed = btn.dataset.seed;
      const target = document.querySelector(`.variation-card[data-seed="${seed}"]`);
      if (target) {
        target.scrollIntoView({ behavior: "smooth", block: "start" });
        list.querySelectorAll(".graph-side-item").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
      }
    });
  });
}

function renderToolsExecuted(tools) {
  if (!Array.isArray(tools) || tools.length === 0) {
    return `<div class="muted-line">(no tool calls)</div>`;
  }
  return tools
    .map((row) => {
      if (!Array.isArray(row) || row.length === 0) return "";
      const [name, ...args] = row;
      const argText = args
        .map((a) => (typeof a === "string" ? a : JSON.stringify(a)))
        .join(", ");
      const argHtml = argText.length > 200 ? `${escapeHtml(argText.slice(0, 200))}…` : escapeHtml(argText);
      return `<div class="tool-row">
        <span class="tool-name">${escapeHtml(name)}</span>
        <span class="tool-args mono">${argHtml || "<i class='muted-line'>(no args)</i>"}</span>
      </div>`;
    })
    .join("");
}

function renderFragmentCard(f) {
  const produces = (f.produces || []).join(", ") || "—";
  const consumes = (f.consumes || []).join(", ") || "—";
  const verdictWord = f.verdict || (f.passed ? "PASS" : f.passed === false ? "FAIL" : "?");
  const classifierTag = f.classifier
    ? `<span class="chip">${escapeHtml(f.classifier)}</span>`
    : "";
  const justification = f.justification || f.reason || "";
  // Failed fragments open by default so the reason is immediately visible.
  const openAttr = f.passed === false ? "open" : "";
  return `
    <details class="iter-section graph-frag-card" ${openAttr}>
      <summary class="iter-header">
        <span>
          <span class="${passDotClass(f.passed)}"></span>
          <strong>Fragment ${f.fragment_index}</strong>
          <span class="badge badge-tactic">${escapeHtml(f.phase || "unknown")}</span>
          ${f.role ? `<span class="badge">${escapeHtml(f.role)}</span>` : ""}
        </span>
        <span class="iter-meta">${f.duration_ms != null ? formatDuration(f.duration_ms) : ""} · ${(f.tools_executed || []).length} tool calls</span>
      </summary>
      <div class="iter-body">
        <div class="frag-line">
          <strong>${escapeHtml(verdictWord)}:</strong>
          ${escapeHtml(justification || "(no justification)")}
          ${classifierTag}
        </div>
        <div class="frag-line"><strong>Prompt:</strong> ${escapeHtml(f.prompt || "")}</div>
        <div class="frag-line"><strong>Produces:</strong> ${escapeHtml(produces)}</div>
        <div class="frag-line"><strong>Consumes:</strong> ${escapeHtml(consumes)}</div>
        <div class="tool-section-title" style="margin-top:0.5rem">Tools Executed (${(f.tools_executed || []).length})</div>
        <div class="tool-list-flat">${renderToolsExecuted(f.tools_executed)}</div>
        ${(f.final_response || f.final_response_preview) ? `
          <div class="tool-section-title" style="margin-top:0.5rem">Final Response</div>
          <pre class="mono response-preview">${escapeHtml(f.final_response || f.final_response_preview)}</pre>` : ""}
      </div>
    </details>`;
}

function renderVariationCard(variation) {
  const fragments = variation.fragments || [];
  const fragmentsHtml = fragments.map(renderFragmentCard).join("");
  const phasesChips = (variation.phases_in_order || [])
    .map((p) => `<span class="chip">${escapeHtml(p)}</span>`)
    .join("");
  const passLabel = variation.passed ? "PASS" : "FAIL";
  const passCls = variation.passed ? "chip-green" : "chip-red";
  const miniDag = renderDag(fragments, { showStatus: true, compact: true });
  return `
    <article class="turn-card variation-card" data-seed="${variation.seed}">
      <div class="turn-header">
        <div class="turn-header-left">
          <span class="${passDotClass(variation.passed)}"></span>
          <span class="turn-label">SEED ${variation.seed}</span>
          <span class="chip ${passCls}">${passLabel}</span>
          <span class="chip chip-cyan">user_id=${variation.user_id}</span>
          ${fragments.length} fragment${fragments.length === 1 ? "" : "s"}
        </div>
        <span class="turn-kcc">${escapeHtml(variation.campaign_id || "")}</span>
      </div>
      <div class="turn-iterations">
        <div class="chip-row">${phasesChips}</div>
        <div class="dag-mini">${miniDag}</div>
        ${fragmentsHtml}
      </div>
    </article>`;
}

function renderGraph(payload) {
  const graph = payload.graph || {};
  const view = byId("graph-view");
  const canonicalView = byId("graph-dag-canonical");
  const variations = graph.variations || [];
  if (variations.length === 0) {
    if (canonicalView) canonicalView.innerHTML = "";
    view.innerHTML = "<div class='panel'><div class='panel-body muted-line'>No variations recorded for this run.</div></div>";
    return;
  }
  // Canonical DAG: all seeds share the same fragment shape, render once at the top.
  if (canonicalView) {
    const sample = variations[0].fragments || [];
    canonicalView.innerHTML = renderDag(sample, {
      title: `Canonical attack DAG — ${graph.campaign || ""} / ${graph.style || ""}  (${sample.length} fragments)`,
      showStatus: false,
    });
  }
  view.innerHTML = variations.map(renderVariationCard).join("");
}

async function loadRunsList() {
  const runs = await fetchRuns();
  const selector = byId("graph-run-selector");
  if (runs.length === 0) {
    selector.innerHTML = `<option value="">(no graph runs for this file)</option>`;
    return [];
  }
  selector.innerHTML = runs
    .map((r) => `<option value="${r.run_id}">${escapeHtml(r.run_id)} · ${r.num_passed}/${r.num_variations} pass</option>`)
    .join("");
  return runs;
}

async function loadRun(runId) {
  if (!runId) return;
  const payload = await fetchRun(runId);
  renderRunSummary(payload);
  renderSidebarList(payload);
  renderGraph(payload);
}

async function loadFragmentsFiles() {
  const files = await fetchFragmentsFiles();
  const selector = byId("graph-fragments-selector");
  if (!selector) return files;
  if (files.length === 0) {
    selector.innerHTML = `<option value="">(no graph runs yet)</option>`;
    _fragmentsPath = "";
    return files;
  }
  const opts = [
    `<option value="">(all fragment files)</option>`,
    ...files.map(
      (f) => `<option value="${escapeHtml(f.path)}">${escapeHtml(f.basename)} · ${f.run_count} run${f.run_count === 1 ? "" : "s"}</option>`,
    ),
  ];
  selector.innerHTML = opts.join("");
  const wanted = getFragmentsParam();
  const matched = wanted && files.some((f) => f.path === wanted) ? wanted : files[0].path;
  selector.value = matched;
  _fragmentsPath = matched;
  setFragmentsParam(matched);
  syncTabsHrefs(matched);
  return files;
}

async function onFragmentsChange() {
  const selector = byId("graph-fragments-selector");
  if (!selector) return;
  _fragmentsPath = selector.value || "";
  setFragmentsParam(_fragmentsPath);
  syncTabsHrefs(_fragmentsPath);
  const runs = await loadRunsList();
  if (runs.length) {
    byId("graph-run-selector").value = runs[0].run_id;
    await loadRun(runs[0].run_id);
  } else {
    byId("graph-view").innerHTML =
      "<div class='panel'><div class='panel-body muted-line'>No graph runs for this fragments file yet.</div></div>";
    byId("graph-dag-canonical").innerHTML = "";
    byId("graph-run-summary").innerHTML = "";
    byId("graph-sidebar-list").innerHTML = "";
  }
}

async function init() {
  byId("graph-refresh-btn").addEventListener("click", async () => {
    await loadFragmentsFiles();
    const runs = await loadRunsList();
    if (runs.length) await loadRun(runs[0].run_id);
  });
  byId("graph-run-selector").addEventListener("change", () => {
    const id = byId("graph-run-selector").value;
    loadRun(id).catch((err) => console.error(err));
  });
  byId("graph-fragments-selector").addEventListener("change", onFragmentsChange);
  await loadFragmentsFiles();
  const params = new URLSearchParams(location.search);
  const runs = await loadRunsList();
  const initial = params.get("run") || (runs[0] && runs[0].run_id);
  if (initial) {
    byId("graph-run-selector").value = initial;
    await loadRun(initial);
  } else {
    byId("graph-view").innerHTML =
      "<div class='panel'><div class='panel-body muted-line'>No graph runs found yet. Run <code>make docker-attack-graph-run</code> first.</div></div>";
  }
}

init().catch((err) => {
  console.error(err);
  document.body.insertAdjacentHTML(
    "beforeend",
    `<pre class="mono" style="padding:1rem;color:var(--red)">graph viewer failed: ${escapeHtml(err.message)}</pre>`
  );
});
