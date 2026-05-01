import { escapeHtml } from "../utils/dom.js";
import { riskClass, percent, formatDuration } from "../utils/format.js";

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

  const iterDuration = iter.duration_ms != null ? ` \u00b7 ${formatDuration(iter.duration_ms)}` : "";
  return `
    <details class="iter-section">
      <summary class="iter-header">
        <span>Iteration ${iter.iteration}</span>
        <span class="iter-meta">${calls.length} tool call${calls.length !== 1 ? "s" : ""}${thinking ? " \u00b7 thinking" : ""}${iterDuration}</span>
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

function finalAssistant(trace) {
  const messages = trace?.assistant_messages || [];
  const finalMsg = messages.find((m) => m.is_final);
  return finalMsg?.content_full || finalMsg?.content_preview || trace.assistant_full || "";
}

function allCalledToolNames(trace) {
  const details = trace.tool_call_details || [];
  const names = details.map((d) => d.name).filter(Boolean);
  return [...new Set(names)];
}

const VERDICT_BADGE_CLASS = {
  PASS:     "verdict-pass",
  FAIL:     "verdict-fail",
  ANSWERED: "verdict-answered",
  REFUSED:  "verdict-refused",
  PARTIAL:  "verdict-partial",
  UNCLEAR:  "verdict-unclear",
};

function renderVerdictBadge(verdict, justification, classifier) {
  if (!verdict) return "";
  const cls = VERDICT_BADGE_CLASS[verdict] || "verdict-unclear";
  const judgeLabel = classifier === "llm_judge" ? " <span class='verdict-classifier'>llm</span>" : "";
  const just = justification
    ? `<span class="verdict-justification"> — ${escapeHtml(justification)}</span>`
    : "";
  return `<span class="verdict-badge ${cls}">${escapeHtml(verdict)}${judgeLabel}</span>${just}`;
}

// Single source of truth: the success-judge verdict (PASS/FAIL with judge
// justification) supplied by attack_runner. We deliberately do NOT show a
// separate "Pass check" row anymore — having two pass/fail signals (one from
// the inline detector, one from the success judge) was a source of confusion
// when the two judges disagreed.
function pickVerdict(t) {
  if (t.verdict) {
    return {
      label: t.verdict,
      justification: t.verdict_justification || "",
      classifier: t.verdict_classifier || "",
    };
  }
  if (t.passed != null) {
    return {
      label: t.passed ? "PASS" : "FAIL",
      justification: t.verdict_justification || "",
      classifier: t.verdict_classifier || "",
    };
  }
  return null;
}

function renderSummarySection(t) {
  const kcc = t.kcc || 0;
  const calledTools = allCalledToolNames(t);
  const verdict = pickVerdict(t);
  const verdictHtml = verdict
    ? `<div class="frag-line"><strong>Verdict:</strong> ${renderVerdictBadge(verdict.label, verdict.justification, verdict.classifier)}</div>`
    : "";
  const seedHtml = t.seed != null
    ? `<div class="frag-line"><strong>Seed:</strong> ${escapeHtml(String(t.seed))}${t.style ? ` <span class="chip chip-cyan">${escapeHtml(t.style)}</span>` : ""}</div>`
    : "";
  const targetLabel = t.target_label || t.target_model || "";
  const mcpHtml = targetLabel
    ? `<div class="frag-line"><strong>MCP model:</strong> <span class="chip chip-cyan mono">${escapeHtml(targetLabel)}</span></div>`
    : "";
  const judgeHtml = t.judge_model
    ? `<div class="frag-line"><strong>Judge model:</strong> <span class="chip chip-cyan mono">${escapeHtml(t.judge_model)}</span></div>`
    : "";
  return `
    <div class="frag-parse">
      ${seedHtml}
      ${verdictHtml}
      ${mcpHtml}
      ${judgeHtml}
      <div class="frag-line"><strong>KCC:</strong> ${kcc.toFixed(2)}</div>
      <div class="kcc-bar">${renderKccBar(kcc)}</div>
      <div class="frag-line"><strong>Tactic:</strong> ${escapeHtml(t.tactic || "unknown")}</div>
      <div class="frag-line"><strong>Available toolkits:</strong> ${escapeHtml((t.toolkit_set || []).join(", ") || "none")}</div>
      <div class="frag-line"><strong>Tools called:</strong> ${calledTools.length ? escapeHtml(calledTools.join(", ")) : "none"}</div>
      <div class="frag-line"><strong>Iterations:</strong> ${t.total_iterations || 1}</div>
      <div class="frag-line"><strong>Total tool calls:</strong> ${t.total_tool_calls || (t.tool_calls || []).length}</div>
      <div class="frag-line"><strong>Status:</strong> ${t.alert ? "ALERT" : "MONITORING"}</div>
      ${t.duration_ms != null ? `<div class="frag-line"><strong>Duration:</strong> ${formatDuration(t.duration_ms)}</div>` : ""}
      ${t.session_id ? `<div class="frag-line"><strong>Session:</strong> <span class="mono">${escapeHtml(t.session_id)}</span></div>` : ""}
      ${t.source_ip ? `<div class="frag-line"><strong>IP:</strong> <span class="mono">${escapeHtml(t.source_ip)}</span></div>` : ""}
    </div>`;
}

function renderResultsPane(t) {
  const iters = t.iterations_detail || [];
  const hasIters = iters.length > 0;
  const iterationsHtml = hasIters
    ? iters.map((it, i) => renderIteration(it, i, iters.length)).join("")
    : renderFallbackColumns(t);
  const totalCalls = t.total_tool_calls || (t.tool_calls || []).length;
  const durationStr = t.duration_ms != null ? ` \u00b7 ${formatDuration(t.duration_ms)}` : "";

  return `
    <details class="result-section" open>
      <summary class="result-section-header">Summary</summary>
      <div class="result-section-body">
        ${renderSummarySection(t)}
      </div>
    </details>
    <details class="result-section">
      <summary class="result-section-header">Agent Loop &mdash; ${hasIters ? iters.length : 1} iteration${(hasIters ? iters.length : 1) !== 1 ? "s" : ""}, ${totalCalls} tool call${totalCalls !== 1 ? "s" : ""}${durationStr}</summary>
      <div class="result-section-body">
        ${iterationsHtml}
      </div>
    </details>
    <details class="result-section">
      <summary class="result-section-header">Final Result</summary>
      <div class="result-section-body">
        <div class="parse-block"><pre class="mono">${escapeHtml(finalAssistant(t) || "(none)")}</pre></div>
      </div>
    </details>`;
}

function groupTracesByStage(traces) {
  const groups = new Map();
  for (const t of traces) {
    const key = t.fragment_index ?? t.step;
    if (!groups.has(key)) {
      groups.set(key, {
        stageIndex: key,
        description: t.fragment_description || "",
        tactic: t.tactic || "",
        fragments: [],
      });
    }
    groups.get(key).fragments.push(t);
  }
  return [...groups.values()].sort((a, b) => a.stageIndex - b.stageIndex);
}

function fragmentLabel(t, idx) {
  const seed = t.seed != null ? t.seed : (t.variation_index != null ? t.variation_index : idx);
  const styleSuffix = t.style ? ` · ${t.style}` : "";
  return `seed ${seed}${styleSuffix}`;
}

function passDotClass(passed) {
  if (passed === true) return "pass-dot pass-dot-ok";
  if (passed === false) return "pass-dot pass-dot-fail";
  return "pass-dot pass-dot-none";
}

export function renderTraces(container, data) {
  const traces = data?.traces || [];
  if (!traces.length) {
    container.innerHTML = "<div class='panel'><div class='panel-body muted-line'>No trace data found for this run.</div></div>";
    return;
  }

  const stages = groupTracesByStage(traces);

  container.innerHTML = stages
    .map((stage) => {
      const maxKcc = Math.max(...stage.fragments.map((f) => f.kcc || 0));

      const variationItems = stage.fragments
        .map(
          (t, i) => {
            // One dot per fragment, sourced from the success-judge verdict
            // (or the per-iteration detector verdict before the chain file
            // is written). This used to show TWO dots — pass-check and
            // detector-verdict — which contradicted each other when the
            // judges disagreed.
            const dotTitle = t.verdict
              ? `${t.verdict}${t.verdict_justification ? " — " + t.verdict_justification : ""}`
              : (t.passed === true ? "variation passed" :
                 t.passed === false ? "variation failed" : "no verdict yet");
            return `<button class="variation-item${i === 0 ? " active" : ""}" data-stage="${stage.stageIndex}" data-frag="${i}">
              <div class="variation-item-header">
                <span class="variation-item-label">${escapeHtml(fragmentLabel(t, i))}</span>
                <span class="dot-row">
                  <span class="${passDotClass(t.passed)}" title="${escapeHtml(dotTitle)}"></span>
                </span>
              </div>
              <div class="variation-item-prompt">${escapeHtml(truncate(t.prompt || "(no prompt)", 120))}</div>
            </button>`;
          }
        )
        .join("");

      const resultPanels = stage.fragments
        .map(
          (t, i) =>
            `<div class="results-panel" data-stage="${stage.stageIndex}" data-frag="${i}" ${i === 0 ? "" : 'style="display:none"'}>
              ${renderResultsPane(t)}
            </div>`
        )
        .join("");

      return `
      <div class="turn-card" data-stage-card="${stage.stageIndex}">
        <div class="turn-header">
          <div class="turn-header-left">
            <span class="turn-label">STAGE ${stage.stageIndex}</span>
            <span class="badge badge-tactic">${escapeHtml(stage.tactic)}</span>
            ${stage.description ? `<span class="stage-description">${escapeHtml(stage.description)}</span>` : ""}
          </div>
          <span class="turn-kcc">KCC ${maxKcc.toFixed(2)}</span>
        </div>
        <div class="stage-splitpane">
          <div class="splitpane-left">
            <div class="splitpane-left-header">Attacker Prompt</div>
            <div class="variation-list-container">${variationItems}</div>
          </div>
          <div class="splitpane-right">
            <div class="splitpane-right-header">Results</div>
            <div class="results-container">${resultPanels}</div>
          </div>
        </div>
      </div>`;
    })
    .join("");

  bindVariationClicks(container);
}

function bindVariationClicks(container) {
  container.querySelectorAll(".variation-item").forEach((item) => {
    item.addEventListener("click", () => {
      const fragIdx = item.dataset.frag;
      const card = item.closest(".turn-card");
      if (!card) return;

      card.querySelectorAll(".variation-item").forEach((v) => v.classList.remove("active"));
      item.classList.add("active");

      card.querySelectorAll(".results-panel").forEach((panel) => {
        panel.style.display = panel.dataset.frag === fragIdx ? "" : "none";
      });
    });
  });
}
