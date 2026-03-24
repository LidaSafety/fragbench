import { escapeHtml } from "../utils/dom.js";
import { riskClass, percent } from "../utils/format.js";

function parseJsonMaybe(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function renderKVRows(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return "";
  return Object.entries(obj)
    .slice(0, 30)
    .map(
      ([k, v]) =>
        `<div class="kv-row"><div class="kv-key">${escapeHtml(k)}</div><div class="kv-value">${escapeHtml(
          typeof v === "string" ? v : JSON.stringify(v)
        )}</div></div>`
    )
    .join("");
}

function truncate(text, max) {
  const s = String(text || "");
  return s.length > max ? s.slice(0, max) + "\u2026" : s;
}

function renderKccBar(kcc) {
  const segments = 6;
  const filled = Math.round(kcc * segments);
  return Array.from({ length: segments }, (_, i) => {
    let cls = "";
    if (i < filled) {
      if (kcc >= 0.75) cls = "high";
      else if (kcc >= 0.45) cls = "warn";
      else cls = "active";
    }
    return `<div class="kcc-segment ${cls}"></div>`;
  }).join("");
}

function renderToolCardWithResult(detail, result, index, open) {
  const argsParsed = parseJsonMaybe(detail.arguments_preview || "");
  const status = result ? (result.success ? "[OK]" : "[ERR]") : "";
  const resultParsed = result ? parseJsonMaybe(result.result_preview || "") : null;

  let resultHtml = "";
  if (result) {
    resultHtml = `
      <div class="tool-section-title">Result ${status}</div>
      ${resultParsed ? `<div class="kv-grid">${renderKVRows(resultParsed)}</div>` : `<pre class="mono">${escapeHtml(result.result_preview || "(empty)")}</pre>`}`;
  }

  return `
    <details class="tool-card" ${open ? "open" : ""}>
      <summary><span>${escapeHtml(detail.name || "?")}</span><span>${status} #${index}</span></summary>
      <div class="tool-card-body">
        <div class="tool-section-title">Arguments</div>
        ${argsParsed ? `<div class="kv-grid">${renderKVRows(argsParsed)}</div>` : `<pre class="mono">${escapeHtml(detail.arguments_preview || "(no args)")}</pre>`}
        ${resultHtml}
      </div>
    </details>`;
}

function renderIteration(iter, iterIdx, totalIters) {
  const thinking = iter.thinking_full || "";
  const content = iter.assistant_content || "";
  const calls = iter.tool_call_details || [];
  const results = iter.tool_results_structured || [];
  const isOpen = false;

  let thinkingHtml = "";
  if (thinking) {
    thinkingHtml = `
      <details class="tool-card">
        <summary><span>Thinking</span><span>model reasoning</span></summary>
        <div class="tool-card-body"><pre class="mono">${escapeHtml(thinking)}</pre></div>
      </details>`;
  }

  let contentHtml = "";
  if (content) {
    contentHtml = `<div class="assistant-block"><pre class="mono">${escapeHtml(content)}</pre></div>`;
  }

  let toolsHtml = "";
  if (calls.length) {
    toolsHtml = calls
      .map((c, i) => renderToolCardWithResult(c, results[i] || null, i + 1, false))
      .join("");
  } else {
    toolsHtml = `<div class="muted-line">(no tool calls)</div>`;
  }

  return `
    <details class="iter-section" ${isOpen ? "open" : ""}>
      <summary class="iter-header">
        <span>Iteration ${iter.iteration}</span>
        <span class="iter-meta">${calls.length} tool call${calls.length !== 1 ? "s" : ""}${thinking ? " \u00b7 thinking" : ""}</span>
      </summary>
      <div class="iter-body">
        <div class="iter-columns">
          <div class="iter-col">
            <div class="iter-col-label">LLM Response</div>
            ${thinkingHtml}
            ${contentHtml || (thinking ? "" : `<div class="muted-line">(no visible content)</div>`)}
          </div>
          <div class="iter-col">
            <div class="iter-col-label">Tool Calls &amp; Results</div>
            ${toolsHtml}
          </div>
        </div>
      </div>
    </details>`;
}

function renderAltPhrasings(trace) {
  const options = (trace.alt_phrasings || []).filter((x) => typeof x === "string" && x.trim());
  if (!options.length) return "";
  return `
    <details class="tool-card">
      <summary><span>ALT PHRASINGS &mdash; SAME FRAGMENT</span><span>${options.length}</span></summary>
      <div class="tool-card-body">
        <ul class="tool-list">
          ${options.map((p) => `<li class="mono">${escapeHtml(p)}</li>`).join("")}
        </ul>
      </div>
    </details>`;
}

function renderFragbenchParse(trace) {
  const firstTool = (trace.tool_calls || [])[0] || "none";
  const kcc = trace.kcc || 0;
  return `
    <div class="frag-parse">
      <div class="frag-line"><strong>KCC:</strong> ${kcc.toFixed(2)}</div>
      <div class="kcc-bar">${renderKccBar(kcc)}</div>
      <div class="frag-line"><strong>Tactic:</strong> ${escapeHtml(trace.tactic || "unknown")}</div>
      <div class="frag-line"><strong>First tool:</strong> ${escapeHtml(firstTool)}</div>
      <div class="frag-line"><strong>Toolkits:</strong> ${escapeHtml((trace.toolkit_set || []).join(", ") || "none")}</div>
      <div class="frag-line"><strong>Iterations:</strong> ${trace.total_iterations || 1}</div>
      <div class="frag-line"><strong>Tool calls:</strong> ${trace.total_tool_calls || (trace.tool_calls || []).length}</div>
      <div class="frag-line"><strong>Status:</strong> ${trace.alert ? "ALERT" : "MONITORING"}</div>
    </div>`;
}

function finalAssistant(trace) {
  const messages = trace?.assistant_messages || [];
  const finalMsg = messages.find((m) => m.is_final);
  return finalMsg?.content_full || finalMsg?.content_preview || trace.assistant_full || "";
}

export function renderTraces(container, data) {
  const traces = data?.traces || [];
  if (!traces.length) {
    container.innerHTML = "<div class='panel'><div class='panel-body muted-line'>No trace data found for this run.</div></div>";
    return;
  }

  container.innerHTML = traces
    .map((t) => {
      const iters = t.iterations_detail || [];
      const hasIters = iters.length > 0;

      const iterationsHtml = hasIters
        ? iters.map((it, i) => renderIteration(it, i, iters.length)).join("")
        : renderFallbackColumns(t);

      return `
      <div class="turn-card">
        <div class="turn-header">
          <div class="turn-header-left">
            <span class="turn-label">TURN ${t.step}</span>
            <span class="badge badge-tactic">${escapeHtml(t.tactic)}</span>
            <span class="turn-prompt-preview mono">${escapeHtml(truncate(t.prompt, 90))}</span>
          </div>
          <span class="turn-kcc">KCC ${t.kcc.toFixed(2)}</span>
        </div>
        <div class="turn-detail">
          <div class="turn-detail-top">
            <div class="turn-col col-attacker">
              <div class="turn-col-title"><span class="col-num">1</span> ATTACKER PROMPT</div>
              <div class="prompt-quote"><pre class="mono">${escapeHtml(t.prompt || "(none)")}</pre></div>
              ${renderAltPhrasings(t)}
            </div>
            <div class="turn-col col-parse">
              <div class="turn-col-title"><span class="col-num">2</span> FRAGBENCH PARSES FRAGMENT</div>
              ${renderFragbenchParse(t)}
              <div class="trace-subtitle">Final response</div>
              <div class="parse-block"><pre class="mono">${escapeHtml(truncate(finalAssistant(t), 600) || "(none)")}</pre></div>
            </div>
          </div>
          <div class="turn-iterations-header">
            <span>Agent Loop &mdash; ${hasIters ? iters.length : 1} iteration${(hasIters ? iters.length : 1) !== 1 ? "s" : ""}, ${t.total_tool_calls || (t.tool_calls || []).length} tool calls</span>
          </div>
          <div class="turn-iterations">
            ${iterationsHtml}
          </div>
        </div>
      </div>`;
    })
    .join("");
}

function renderFallbackColumns(t) {
  const calls = t.tool_call_details || [];
  const results = t.tool_results_structured || [];
  const thinking = t.thinking_full || "";
  const messages = t.assistant_messages || [];
  const content = messages.find((m) => !m.is_final)?.content_full || "";

  let thinkingHtml = "";
  if (thinking) {
    thinkingHtml = `
      <details class="tool-card" open>
        <summary><span>Thinking</span><span>model reasoning</span></summary>
        <div class="tool-card-body"><pre class="mono">${escapeHtml(thinking)}</pre></div>
      </details>`;
  }

  let toolsHtml = calls.length
    ? calls.map((c, i) => renderToolCardWithResult(c, results[i] || null, i + 1, false)).join("")
    : `<div class="muted-line">(no tool calls)</div>`;

  return `
    <details class="iter-section">
      <summary class="iter-header">
        <span>Iteration 1</span>
        <span class="iter-meta">${calls.length} tool calls</span>
      </summary>
      <div class="iter-body">
        <div class="iter-columns">
          <div class="iter-col">
            <div class="iter-col-label">LLM Response</div>
            ${thinkingHtml}
            ${content ? `<div class="assistant-block"><pre class="mono">${escapeHtml(content)}</pre></div>` : ""}
          </div>
          <div class="iter-col">
            <div class="iter-col-label">Tool Calls &amp; Results</div>
            ${toolsHtml}
          </div>
        </div>
      </div>
    </details>`;
}
