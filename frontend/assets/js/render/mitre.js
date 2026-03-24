import { escapeHtml } from "../utils/dom.js";

export function renderMitre(container, data) {
  const mitre = data?.mitre;
  if (!mitre) {
    container.innerHTML = "<div class='panel'><div class='panel-body muted-line'>No MITRE data.</div></div>";
    return;
  }
  const coverage = mitre.coverage || {};
  const techniques = mitre.techniques || [];
  container.innerHTML = `
    <div class="panel">
      <div class="panel-header"><span>Tactic Coverage</span><span class="badge">${Object.keys(coverage).length} tactics</span></div>
      <div class="panel-body">
        <div class="grid-3">
        ${Object.entries(coverage)
          .map(([t, count]) => `<div class="kv"><strong>${escapeHtml(t)}</strong> <span class="mono" style="color:var(--cyan)">${count}</span></div>`)
          .join("")}
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><span>Techniques</span><span class="badge">${techniques.length}</span></div>
      <div class="panel-body">
        <ul class="variation-list">
        ${techniques
          .map(
            (t) =>
              `<li><span class="badge badge-tactic">${escapeHtml(t.technique)}</span> ${escapeHtml(t.name)} <span style="color:var(--muted)">( ${escapeHtml(t.tactic)} )</span></li>`
          )
          .join("")}
        </ul>
      </div>
    </div>
  `;
}
