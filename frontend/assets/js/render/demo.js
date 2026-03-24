import { escapeHtml } from "../utils/dom.js";

export function renderDemo(container, data) {
  const demo = data?.demo;
  if (!demo) {
    container.innerHTML = "<div class='panel'><div class='panel-body muted-line'>No demo data.</div></div>";
    return;
  }
  const queue = demo.queue || [];
  container.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <span>Runtime Queue Demo</span>
        <span class="badge">${queue.length} fragments</span>
      </div>
      <div class="panel-body">
        <div style="margin-bottom:0.35rem"><span class="mono" style="color:var(--muted)">State:</span> <strong>${escapeHtml(demo.state)}</strong></div>
        <div style="margin-bottom:0.45rem"><span class="mono" style="color:var(--muted)">KCC:</span> <strong style="color:var(--cyan)">${demo.kcc.toFixed(2)}</strong></div>
        <ul class="variation-list">
          ${queue.map((q, idx) => `<li><span class="badge">#${idx + 1}</span> ${escapeHtml(q.id)} &mdash; ${escapeHtml(q.label)} <span style="color:var(--amber)">(risk ${q.risk.toFixed(2)})</span></li>`).join("")}
        </ul>
      </div>
    </div>
  `;
}
