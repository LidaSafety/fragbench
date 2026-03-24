/**
 * Canonical runtime model used by all renderers.
 * @typedef {Object} RuntimeData
 * @property {Object} run
 * @property {Array<Object>} campaigns
 * @property {Array<Object>} fragments
 * @property {Array<Object>} traces
 * @property {Object} mitre
 * @property {Object} gnn
 * @property {Object} demo
 * @property {Object} sources
 */

export function ensureRuntimeShape(payload) {
  const data = payload && typeof payload === "object" ? payload : {};
  return {
    run: data.run || {},
    campaigns: Array.isArray(data.campaigns) ? data.campaigns : [],
    fragments: Array.isArray(data.fragments) ? data.fragments : [],
    traces: Array.isArray(data.traces) ? data.traces : [],
    mitre: data.mitre || { coverage: {}, techniques: [] },
    gnn: data.gnn || { nodes: [], edges: [], classification: "MONITORING" },
    demo: data.demo || { queue: [], kcc: 0, state: "monitoring" },
    sources: data.sources || {},
  };
}
