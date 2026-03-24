import { escapeHtml } from "../utils/dom.js";

export function renderFragments(container, data) {
  const fragments = data?.fragments || [];
  if (!fragments.length) {
    container.innerHTML = "<div class='panel'><div class='panel-body muted-line'>No fragment data available.</div></div>";
    return;
  }
  container.innerHTML = fragments
    .map((f) => {
      const vars = f.variations || [];
      return `
      <div class="panel">
        <div class="panel-header">
          <span>Stage ${f.index}</span>
          <span><span class="badge badge-tactic">${escapeHtml(f.mitre_tactic)}</span> ${escapeHtml(f.mitre_technique)}</span>
        </div>
        <div class="panel-body">
          <p style="margin-bottom:0.3rem"><strong>${escapeHtml(f.description)}</strong></p>
          <div class="prompt-quote" style="margin-bottom:0.45rem"><pre class="mono">${escapeHtml(f.baseline_prompt)}</pre></div>
          <div class="kv" style="margin-bottom:0.35rem">
            <div>Variations: ${vars.length}</div>
          </div>
          <ul class="variation-list">
            ${vars
              .slice(0, 8)
              .map((v) => `<li><span class="badge">${escapeHtml(v.style)}</span> <span class="mono">${escapeHtml(v.prompt)}</span></li>`)
              .join("")}
          </ul>
        </div>
      </div>`;
    })
    .join("");
}
