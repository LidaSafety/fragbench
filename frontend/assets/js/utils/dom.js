export function byId(id) {
  return document.getElementById(id);
}

export function html(el, markup) {
  if (el) el.innerHTML = markup;
}

export function escapeHtml(text) {
  return String(text || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

export function toggleClass(el, className, enabled) {
  if (!el) return;
  if (enabled) el.classList.add(className);
  else el.classList.remove(className);
}
