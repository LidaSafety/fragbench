import { escapeHtml } from "../utils/dom.js";

export function renderCampaigns(container, data) {
  const campaigns = data?.campaigns || [];
  if (!campaigns.length) {
    container.innerHTML = "<div class='panel'><div class='panel-body muted-line'>No campaign data loaded.</div></div>";
    return;
  }
  container.innerHTML = campaigns
    .map(
      (c) => `
      <div class="panel">
        <div class="panel-header">
          <strong>${escapeHtml(c.id)}</strong>
          <span class="badge">${escapeHtml(c.technique || "n/a")}</span>
          <span>${escapeHtml(c.technique_name || "")}</span>
        </div>
        <div class="panel-body">
          <p style="margin-bottom:0.4rem">${escapeHtml(c.title || "")}</p>
          <div style="margin-bottom:0.35rem">${(c.tags || []).map((t) => `<span class="badge">${escapeHtml(t)}</span>`).join(" ")}</div>
          <div class="mono" style="color:var(--muted);font-size:0.76rem">Sessions from run: ${c.session_count ?? 0}</div>
        </div>
      </div>`
    )
    .join("");
}
