import { escapeHtml } from "../utils/dom.js";

function renderFragmentRows(fragments) {
  if (!fragments || !fragments.length) return "";
  return `
    <div class="campaign-fragments">
      <div class="trace-subtitle" style="margin-top:0.6rem">FRAGMENT DEFINITIONS</div>
      ${fragments
        .map((f) => {
          const vars = f.variations || [];
          return `
          <div class="panel" style="margin-bottom:0.5rem">
            <div class="panel-header">
              <span>Fragment ${f.index}</span>
              <span>
                <span class="badge badge-tactic">${escapeHtml(f.mitre_tactic || "")}</span>
                ${escapeHtml(f.mitre_technique || "")}
              </span>
            </div>
            <div class="panel-body">
              <p style="margin-bottom:0.3rem"><strong>${escapeHtml(f.description || "")}</strong></p>
              ${f.baseline_prompt ? `<div class="prompt-quote" style="margin-bottom:0.45rem"><pre class="mono">${escapeHtml(f.baseline_prompt)}</pre></div>` : ""}
              <div class="kv" style="margin-bottom:0.35rem">
                <div>Variations: ${vars.length}</div>
              </div>
              ${vars.length ? `
              <ul class="variation-list">
                ${vars
                  .slice(0, 8)
                  .map((v) => `<li><span class="badge">${escapeHtml(v.style || "")}</span> <span class="mono">${escapeHtml(v.prompt || "")}</span></li>`)
                  .join("")}
                ${vars.length > 8 ? `<li class="muted-line">...and ${vars.length - 8} more</li>` : ""}
              </ul>` : ""}
            </div>
          </div>`;
        })
        .join("")}
    </div>`;
}

export function renderCampaigns(container, data) {
  const campaigns = data?.campaigns || [];
  const fragments = data?.fragments || [];
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
          ${renderFragmentRows(fragments)}
        </div>
      </div>`
    )
    .join("");
}
