import { riskClass, percent } from "../utils/format.js";

export function renderGnn(container, data) {
  const gnn = data?.gnn;
  if (!gnn) {
    container.innerHTML = "<div class='panel'><div class='panel-body'>No GNN data.</div></div>";
    return;
  }
  const nodes = gnn.nodes || [];
  container.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <span>Graph Classification</span>
        <strong>${gnn.classification}</strong>
      </div>
      <div class="panel-body">
        <div class="grid-3">
          ${nodes
            .map(
              (n) => `
            <div class="kv">
              <div><strong>${n.id}</strong> ${n.label}</div>
              <div class="${riskClass(n.risk)}">risk=${n.risk.toFixed(2)}</div>
              <div class="progress"><div class="progress-fill" style="width:${percent(n.risk)};"></div></div>
              <div>KCC ${n.kcc.toFixed(2)} | tool calls ${n.tool_count}</div>
            </div>`
            )
            .join("")}
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><span>Edges</span><span>${(gnn.edges || []).length}</span></div>
      <div class="panel-body mono">
        ${(gnn.edges || []).map((e) => `${e.from} -> ${e.to} (${e.type})`).join("<br>")}
      </div>
    </div>
  `;
}
