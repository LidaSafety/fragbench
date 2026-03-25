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
  tracesList.innerHTML = traces
    .map(
      (t, i) => {
        const iters = t.total_iterations || 1;
        const calls = t.total_tool_calls || (t.tool_calls || []).length;
        return `<button class="sidebar-sub" data-view="traces" data-idx="${i}">Turn ${
          t.step || i + 1
        } \u2014 ${escapeHtml(t.tactic)} (${iters}i/${calls}t)</button>`;
      }
    )
    .join("");

  document.querySelectorAll(".sidebar-sub").forEach((btn) => {
    btn.addEventListener("click", () => {
      const view = btn.dataset.view;
      store.set({ activeView: view });
      setActiveView(view);
      document.querySelectorAll(".sidebar-item, .sidebar-sub").forEach((el) => el.classList.remove("active"));
      btn.classList.add("active");
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

async function init() {
  bindSidebarSections();
  bindNavigation();
  bindUpload();
  byId("refresh-runs-btn").addEventListener("click", loadRuns);
  byId("load-latest-btn").addEventListener("click", loadLatest);
  byId("run-selector").addEventListener("change", loadSelectedRun);
  await loadRuns();
  await loadLatest();
}

init().catch((err) => {
  console.error(err);
  alert(`Failed to initialize viewer: ${err.message}`);
});
