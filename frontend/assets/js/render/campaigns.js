import { escapeHtml } from "../utils/dom.js";

export function renderCampaigns(container, data) {
  const campaigns = data?.campaigns || [];
  if (!campaigns.length) {
    container.innerHTML = "<div class='panel'><div class='panel-body'>No campaign data loaded.</div></div>";
    return;
  }
  container.innerHTML = campaigns
    .map(
      (c) => `
      <div class="panel">
        <div class="panel-header">
          <strong>${escapeHtml(c.id)}</strong>
          <span>${escapeHtml(c.technique || "n/a")} - ${escapeHtml(c.technique_name || "Unknown technique")}</span>
        </div>
        <div class="panel-body">
          <p>${escapeHtml(c.title || "")}</p>
          <div>${(c.tags || []).map((t) => `<span class="badge">${escapeHtml(t)}</span>`).join("")}</div>
          <p class="mono">Sessions from run: ${c.session_count ?? 0}</p>
        </div>
      </div>`
    )
    .join("");
}
