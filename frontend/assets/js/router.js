import { byId } from "./utils/dom.js";
import { renderCampaigns } from "./render/campaigns.js";
import { renderFragments } from "./render/fragments.js";
import { renderTraces } from "./render/traces.js";
import { renderGnn } from "./render/gnn.js";
import { renderMitre } from "./render/mitre.js";
import { renderDemo } from "./render/demo.js";

const viewIds = ["campaigns", "fragments", "traces", "gnn", "mitre", "demo"];

export function setActiveView(view) {
  viewIds.forEach((id) => {
    const el = byId(`view-${id}`);
    if (!el) return;
    if (id === view) el.classList.add("active");
    else el.classList.remove("active");
  });
  document.querySelectorAll(".sidebar-item").forEach((item) => {
    item.classList.toggle("active", item.dataset.view === view);
  });
}

export function renderAll(data) {
  renderCampaigns(byId("view-campaigns"), data);
  renderFragments(byId("view-fragments"), data);
  renderTraces(byId("view-traces"), data);
  renderGnn(byId("view-gnn"), data);
  renderMitre(byId("view-mitre"), data);
  renderDemo(byId("view-demo"), data);
}
