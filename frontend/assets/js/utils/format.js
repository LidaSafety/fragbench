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
