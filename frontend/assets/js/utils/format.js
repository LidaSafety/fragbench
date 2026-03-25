export function riskClass(risk) {
  if (risk >= 0.75) return "risk-high";
  if (risk >= 0.45) return "risk-med";
  return "risk-low";
}

export function percent(num) {
  return `${Math.round((num || 0) * 100)}%`;
}

export function short(text, max = 220) {
  const value = String(text || "");
  return value.length > max ? `${value.slice(0, max)}...` : value;
}

export function formatDuration(ms) {
  if (ms == null || ms < 0) return "\u2014";
  if (ms < 1000) return `${ms}ms`;
  const secs = ms / 1000;
  if (secs < 60) return `${secs.toFixed(1)}s`;
  const mins = Math.floor(secs / 60);
  const rem = Math.round(secs % 60);
  if (mins < 60) return `${mins}m ${rem}s`;
  const hrs = Math.floor(mins / 60);
  const remMins = mins % 60;
  return `${hrs}h ${remMins}m`;
}
