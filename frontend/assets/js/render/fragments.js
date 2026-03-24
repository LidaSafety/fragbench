import { escapeHtml } from "../utils/dom.js";

export function renderFragments(container, data) {
  const fragments = data?.fragments || [];
  if (!fragments.length) {
    container.innerHTML = "<div class='panel'><div class='panel-body'>No fragment data available.</div></div>";
    return;
  }
  container.innerHTML = fragments
    .map((f) => {
      const vars = f.variations || [];
      return `
      <div class="panel">
        <div class="panel-header">
          <span>Stage ${f.index}</span>
          <span>${escapeHtml(f.mitre_tactic)} / ${escapeHtml(f.mitre_technique)}</span>
        </div>
        <div class="panel-body">
          <p><strong>${escapeHtml(f.description)}</strong></p>
          <p class="mono">${escapeHtml(f.baseline_prompt)}</p>
          <div class="kv">
            <div>Variations: ${vars.length}</div>
          </div>
          <ul class="variation-list">
            ${vars
              .slice(0, 8)
              .map((v) => `<li><span class="badge">${escapeHtml(v.style)}</span> ${escapeHtml(v.prompt)}</li>`)
              .join("")}
          </ul>
        </div>
      </div>`;
    })
    .join("");
}
