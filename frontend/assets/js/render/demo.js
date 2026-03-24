export function renderDemo(container, data) {
  const demo = data?.demo;
  if (!demo) {
    container.innerHTML = "<div class='panel'><div class='panel-body'>No demo data.</div></div>";
    return;
  }
  const queue = demo.queue || [];
  container.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <span>Runtime Queue Demo</span>
        <span>${queue.length} fragments</span>
      </div>
      <div class="panel-body">
        <div class="mono">State: ${demo.state}</div>
        <div class="mono">KCC: ${demo.kcc.toFixed(2)}</div>
        <ul class="variation-list">
          ${queue.map((q, idx) => `<li>#${idx + 1} ${q.id} - ${q.label} (risk ${q.risk.toFixed(2)})</li>`).join("")}
        </ul>
      </div>
    </div>
  `;
}
