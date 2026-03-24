import { escapeHtml } from "../utils/dom.js";
import { riskClass, percent } from "../utils/format.js";

export function renderTraces(container, data) {
  const traces = data?.traces || [];
  if (!traces.length) {
    container.innerHTML = "<div class='panel'><div class='panel-body'>No trace data found for this run.</div></div>";
    return;
  }

  container.innerHTML = traces
    .map(
      (t) => `
      <div class="panel">
        <div class="panel-header">
          <span>Step ${t.step} - ${escapeHtml(t.tactic)}</span>
          <span class="${riskClass(t.risk)}">risk=${t.risk.toFixed(2)} kcc=${t.kcc.toFixed(2)}</span>
        </div>
        <div class="panel-body">
          <div class="trace-columns">
            <div class="trace-box"><strong>Attacker Prompt</strong><br>${escapeHtml(t.prompt)}</div>
            <div class="trace-box"><strong>Tool Calls</strong><br><pre class="mono">${escapeHtml((t.tool_calls || []).join("\n"))}</pre></div>
            <div class="trace-box"><strong>Tool Results</strong><br><pre class="mono">${escapeHtml((t.tool_results || []).join("\n"))}</pre></div>
            <div class="trace-box">
              <strong>FragBench Parse</strong><br>
              <div>KCC: ${t.kcc.toFixed(2)}</div>
              <div class="progress"><div class="progress-fill" style="width:${percent(t.kcc)};"></div></div>
              <div>Toolkits: ${(t.toolkit_set || []).join(", ") || "none"}</div>
              <div>${t.alert ? "ALERT" : "MONITORING"}</div>
            </div>
          </div>
        </div>
      </div>`
    )
    .join("");
}
