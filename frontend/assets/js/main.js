import { fetchLatestRun, fetchRunById, fetchRuns } from "./api/client.js";
import { ensureRuntimeShape } from "./ingest/normalize.js";
import { normalizeFromUpload } from "./ingest/upload.js";
import { setActiveView, renderAll } from "./router.js";
import { store } from "./state/store.js";
import { byId, toggleClass } from "./utils/dom.js";

function updateRunSummary(data) {
  const run = data?.run || {};
  byId("run-summary").innerHTML = `
    <div><strong>Attack</strong>: ${run.attack_id || "n/a"}</div>
    <div><strong>Model</strong>: ${run.model || "n/a"}</div>
    <div><strong>Events</strong>: ${run.events || 0}</div>
    <div><strong>KCC</strong>: ${(run.kcc ?? 0).toFixed(2)}</div>
    <div><strong>Status</strong>: ${run.alerts ? "ALERT" : "Monitoring"}</div>
  `;
}

function setData(data) {
  const shaped = ensureRuntimeShape(data);
  store.set({ data: shaped });
  renderAll(shaped);
  updateRunSummary(shaped);
}

async function loadRuns() {
  const runs = await fetchRuns();
  store.set({ runs });
  const selector = byId("run-selector");
  selector.innerHTML = runs.map((r) => `<option value="${r.id}">${r.id}</option>`).join("");
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

function bindNavigation() {
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      const view = btn.dataset.view;
      store.set({ activeView: view });
      setActiveView(view);
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
