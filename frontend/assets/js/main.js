import { fetchLatestRun, fetchRunById, fetchRuns } from "./api/client.js";
import { ensureRuntimeShape } from "./ingest/normalize.js";
import { normalizeFromUpload } from "./ingest/upload.js";
import { setActiveView, renderAll } from "./router.js";
import { store } from "./state/store.js";
import { byId, escapeHtml, toggleClass } from "./utils/dom.js";
import { formatDuration } from "./utils/format.js";

function updateRunSummary(data) {
  const run = data?.run || {};
  byId("run-summary").innerHTML = `
    <div><strong>Attack:</strong> ${escapeHtml(run.attack_id || "n/a")}</div>
    <div><strong>Model:</strong> ${escapeHtml(run.model || "n/a")}</div>
    ${run.session_id ? `<div><strong>Session:</strong> <span class="mono">${escapeHtml(run.session_id)}</span></div>` : ""}
    ${run.source_ip ? `<div><strong>IP:</strong> <span class="mono">${escapeHtml(run.source_ip)}</span></div>` : ""}
    <div><strong>Events:</strong> ${run.events || 0}</div>
    <div><strong>KCC:</strong> ${(run.kcc ?? 0).toFixed(2)}</div>
    <div><strong>Duration:</strong> ${formatDuration(run.total_duration_ms)}</div>
    <div><strong>Status:</strong> ${run.alerts ? "ALERT" : "Monitoring"}</div>
  `;
}

function populateSidebarItems(data) {
  const campaignsList = byId("sidebar-campaigns-list");
  const tracesList = byId("sidebar-traces-list");
  if (!campaignsList || !tracesList) return;

  const campaigns = data?.campaigns || [];
  campaignsList.innerHTML = campaigns
    .map(
      (c) =>
        `<button class="sidebar-sub" data-view="campaigns" data-id="${escapeHtml(c.id)}">${escapeHtml(c.id)}</button>`
    )
    .join("");

  const traces = data?.traces || [];
  const campaignName = campaigns.length ? campaigns[0].id : "Campaign";

  const seenStages = new Set();
  const stageButtons = traces
    .map((t) => {
      const stageIdx = t.fragment_index ?? t.step;
      if (seenStages.has(stageIdx)) return "";
      seenStages.add(stageIdx);
      const stageTraces = traces.filter((x) => (x.fragment_index ?? x.step) === stageIdx);
      const totalCalls = stageTraces.reduce((s, x) => s + (x.total_tool_calls || (x.tool_calls || []).length), 0);
      return `<button class="sidebar-stage" data-view="traces" data-stage="${stageIdx}">Stage ${stageIdx} \u2014 ${escapeHtml(t.tactic)} (${stageTraces.length} frag${stageTraces.length !== 1 ? "s" : ""}/${totalCalls}t)</button>`;
    })
    .join("");

  tracesList.innerHTML =
    `<button class="sidebar-sub" data-view="traces">${escapeHtml(campaignName)}</button>` +
    `<div class="sidebar-stage-list">${stageButtons}</div>`;

  document.querySelectorAll(".sidebar-sub").forEach((btn) => {
    btn.addEventListener("click", () => {
      const view = btn.dataset.view;
      store.set({ activeView: view });
      setActiveView(view);
      document.querySelectorAll(".sidebar-sub, .sidebar-stage").forEach((el) => el.classList.remove("active"));
      btn.classList.add("active");
    });
  });

  document.querySelectorAll(".sidebar-stage").forEach((btn) => {
    btn.addEventListener("click", () => {
      store.set({ activeView: "traces" });
      setActiveView("traces");
      document.querySelectorAll(".sidebar-sub, .sidebar-stage").forEach((el) => el.classList.remove("active"));
      btn.classList.add("active");
      const stageCard = document.querySelector(`.turn-card[data-stage-card="${btn.dataset.stage}"]`);
      if (stageCard) stageCard.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
}

function setData(data) {
  const shaped = ensureRuntimeShape(data);
  store.set({ data: shaped });
  renderAll(shaped);
  updateRunSummary(shaped);
  populateSidebarItems(shaped);
}

async function loadRuns() {
  const runs = await fetchRuns();
  store.set({ runs });
  const selector = byId("run-selector");
  const seen = new Set();
  const options = [];
  for (const r of runs) {
    if (r.run_id && seen.has(r.run_id)) continue;
    if (r.run_id) seen.add(r.run_id);
    const label = r.run_id ? `[chain] ${r.run_id} (${r.id})` : r.id;
    options.push(`<option value="${r.id}">${label}</option>`);
  }
  selector.innerHTML = options.join("");
}

async function loadLatest() {
  const data = await fetchLatestRun();
  setData(data);
}

async function loadSelectedRun() {
  const id = byId("run-selector").value;
  if (!id) return;
  const data = await fetchRunById(id);
  setData(data);
}

function bindSidebarSections() {
  document.querySelectorAll(".sidebar-header").forEach((header) => {
    header.addEventListener("click", () => {
      const group = header.closest(".sidebar-group");
      if (group) group.classList.toggle("open");
    });
  });
}

function bindNavigation() {
  document.querySelectorAll(".sidebar-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      const view = btn.dataset.view;
      store.set({ activeView: view });
      setActiveView(view);
      document.querySelectorAll(".sidebar-item, .sidebar-sub").forEach((el) => el.classList.remove("active"));
      btn.classList.add("active");
    });
  });
}

function bindUpload() {
  const panel = byId("upload-panel");
  byId("upload-mode-btn").addEventListener("click", () => {
    toggleClass(panel, "hidden", !panel.classList.contains("hidden"));
  });
  byId("upload-submit-btn").addEventListener("click", async () => {
    try {
      const data = await normalizeFromUpload();
      setData(data);
    } catch (err) {
      alert(`Upload normalization failed: ${err.message}`);
    }
  });
}

// Auto-poll every 15 s while a run is in progress, backing off to 60 s otherwise.
// A run is considered "in progress" when new session files appear between polls.
let _pollTimer = null;
let _lastRunListSnapshot = "";
let _pollInterval = 15_000;
const POLL_FAST = 15_000;
const POLL_SLOW = 60_000;

async function _poll() {
  try {
    const runs = await fetchRuns();
    const snapshot = runs.map((r) => r.id).join(",");
    const hasNewRuns = snapshot !== _lastRunListSnapshot;

    if (hasNewRuns) {
      _lastRunListSnapshot = snapshot;
      store.set({ runs });
      // Rebuild the selector without disturbing the selected item.
      const selector = byId("run-selector");
      const current = selector.value;
      const seen = new Set();
      const options = [];
      for (const r of runs) {
        if (r.run_id && seen.has(r.run_id)) continue;
        if (r.run_id) seen.add(r.run_id);
        const label = r.run_id ? `[chain] ${r.run_id} (${r.id})` : r.id;
        options.push(`<option value="${r.id}">${label}</option>`);
      }
      selector.innerHTML = options.join("");
      // Restore previous selection if still available, otherwise show latest.
      if (current && [...selector.options].some((o) => o.value === current)) {
        selector.value = current;
      } else {
        await loadLatest();
      }
      _pollInterval = POLL_FAST;
    } else {
      // No new sessions — refresh the currently displayed data to pick up
      // verdict events that may have been written after the initial load.
      const selector = byId("run-selector");
      const current = selector.value;
      if (current) {
        const data = await fetchRunById(current);
        setData(data);
      }
      _pollInterval = runs.length > 0 ? POLL_SLOW : POLL_FAST;
    }
  } catch (_) {
    // Network errors during polling are non-fatal.
  }
  _pollTimer = setTimeout(_poll, _pollInterval);
}

async function init() {
  bindSidebarSections();
  bindNavigation();
  bindUpload();
  byId("refresh-runs-btn").addEventListener("click", loadRuns);
  byId("load-latest-btn").addEventListener("click", loadLatest);
  byId("run-selector").addEventListener("change", loadSelectedRun);
  await loadRuns();
  await loadLatest();
  // Seed the snapshot so the first poll doesn't trigger a spurious reload.
  _lastRunListSnapshot = (store.state.runs || []).map((r) => r.id).join(",");
  _pollTimer = setTimeout(_poll, _pollInterval);
}

init().catch((err) => {
  console.error(err);
  alert(`Failed to initialize viewer: ${err.message}`);
});
