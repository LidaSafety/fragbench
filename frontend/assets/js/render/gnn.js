import { riskClass, percent } from "../utils/format.js";
import { escapeHtml } from "../utils/dom.js";

export function renderGnn(container, data) {
  const gnn = data?.gnn;
  if (!gnn) {
    container.innerHTML = "<div class='panel'><div class='panel-body muted-line'>No GNN data.</div></div>";
    return;
  }
  const nodes = gnn.nodes || [];
  container.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <span>Graph Classification</span>
        <strong class="${riskClass(0.5)}">${escapeHtml(gnn.classification)}</strong>
      </div>
      <div class="panel-body">
        <div class="grid-3">
          ${nodes
            .map(
              (n) => `
            <div class="kv">
              <div style="margin-bottom:0.25rem"><strong>${escapeHtml(n.id)}</strong> <span style="color:var(--muted)">${escapeHtml(n.label)}</span></div>
              <div class="${riskClass(n.risk)}" style="font-size:0.78rem;margin-bottom:0.15rem">risk=${n.risk.toFixed(2)}</div>
              <div class="progress"><div class="progress-fill" style="width:${percent(n.risk)};"></div></div>
              <div class="mono" style="font-size:0.72rem;color:var(--muted);margin-top:0.15rem">KCC ${n.kcc.toFixed(2)} | tool calls ${n.tool_count}</div>
            </div>`
            )
            .join("")}
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><span>Edges</span><span class="badge">${(gnn.edges || []).length}</span></div>
      <div class="panel-body mono" style="font-size:0.76rem">
        ${(gnn.edges || []).map((e) => `<div>${escapeHtml(e.from)} &rarr; ${escapeHtml(e.to)} <span style="color:var(--muted)">(${escapeHtml(e.type)})</span></div>`).join("")}
      </div>
    </div>
  `;
}
