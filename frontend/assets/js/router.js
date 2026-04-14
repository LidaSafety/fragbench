import { byId } from "./utils/dom.js";
import { renderCampaigns } from "./render/campaigns.js";
import { renderTraces } from "./render/traces.js";

const viewIds = ["campaigns", "traces"];

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
  renderTraces(byId("view-traces"), data);
}
