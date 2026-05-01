/**
 * Vanilla-SVG fragment dependency DAG renderer.
 *
 * Inputs an array of fragment objects (`{fragment_index, role, produces[],
 * consumes[], passed?}`) and produces an SVG showing artifact flow.
 *
 * Layout: layered topological — each fragment goes into a rank equal to the
 * length of its longest dependency path from a root. Within a rank we sort
 * by fragment_index so the picture is stable across runs.
 */

import { escapeHtml } from "./utils/dom.js";

/**
 * Build {fromIdx -> toIdx[]} edges using the most-recent producer of each
 * artifact, mirroring attack_runner._build_dependencies.
 */
function buildEdges(fragments) {
  const ordered = [...fragments].sort(
    (a, b) => (a.fragment_index ?? 0) - (b.fragment_index ?? 0)
  );
  const edges = []; // {from, to, label}
  for (let i = 0; i < ordered.length; i++) {
    const f = ordered[i];
    const consumes = f.consumes || [];
    for (const art of consumes) {
      // Find latest earlier fragment that produces this artifact.
      for (let j = i - 1; j >= 0; j--) {
        const g = ordered[j];
        if ((g.produces || []).includes(art)) {
          edges.push({
            from: g.fragment_index,
            to: f.fragment_index,
            label: art,
          });
          break;
        }
      }
    }
  }
  return { ordered, edges };
}

/**
 * Compute a rank (column index) for each fragment via longest-path-from-root.
 * Returns Map<fragmentIndex, rank>.
 */
function computeRanks(ordered, edges) {
  const incomingByTo = new Map();
  for (const e of edges) {
    if (!incomingByTo.has(e.to)) incomingByTo.set(e.to, []);
    incomingByTo.get(e.to).push(e.from);
  }
  const rank = new Map();
  for (const f of ordered) {
    const incoming = incomingByTo.get(f.fragment_index) || [];
    if (incoming.length === 0) {
      rank.set(f.fragment_index, 0);
    } else {
      const maxParent = Math.max(...incoming.map((p) => rank.get(p) ?? 0));
      rank.set(f.fragment_index, maxParent + 1);
    }
  }
  return rank;
}

/**
 * Pure layout — given fragments, return {nodes, edges, width, height}
 * where each node has {fragment_index, role, x, y, w, h, rank, slot}.
 */
function layout(fragments, opts = {}) {
  const {
    nodeW = 130,
    nodeH = 56,
    colGap = 60,
    rowGap = 18,
    padX = 16,
    padY = 16,
  } = opts;
  const { ordered, edges } = buildEdges(fragments);
  const rank = computeRanks(ordered, edges);

  // Group by rank, sort within rank by fragment_index for stability.
  const byRank = new Map();
  for (const f of ordered) {
    const r = rank.get(f.fragment_index) ?? 0;
    if (!byRank.has(r)) byRank.set(r, []);
    byRank.get(r).push(f);
  }
  for (const arr of byRank.values()) {
    arr.sort((a, b) => (a.fragment_index ?? 0) - (b.fragment_index ?? 0));
  }

  const ranks = [...byRank.keys()].sort((a, b) => a - b);
  const maxSlots = Math.max(...[...byRank.values()].map((v) => v.length), 1);

  const nodes = [];
  for (const r of ranks) {
    const arr = byRank.get(r);
    const colX = padX + r * (nodeW + colGap);
    const totalH = arr.length * nodeH + (arr.length - 1) * rowGap;
    const startY = padY + (maxSlots * nodeH + (maxSlots - 1) * rowGap - totalH) / 2;
    arr.forEach((f, slot) => {
      nodes.push({
        ...f,
        rank: r,
        slot,
        x: colX,
        y: startY + slot * (nodeH + rowGap),
        w: nodeW,
        h: nodeH,
      });
    });
  }

  const width = padX + ranks.length * nodeW + (ranks.length - 1) * colGap + padX;
  const height = padY + maxSlots * nodeH + (maxSlots - 1) * rowGap + padY;
  return { nodes, edges, width, height };
}

function nodeClass(f, { showStatus }) {
  if (!showStatus) return "dag-node";
  if (f.passed === true) return "dag-node dag-node-pass";
  if (f.passed === false) return "dag-node dag-node-fail";
  return "dag-node dag-node-pending";
}

function nodeTitle(f) {
  return [
    `Fragment ${f.fragment_index}`,
    f.role ? `role: ${f.role}` : "",
    (f.produces || []).length ? `produces: ${(f.produces || []).join(", ")}` : "",
    (f.consumes || []).length ? `consumes: ${(f.consumes || []).join(", ")}` : "",
    f.passed === true ? "PASS" : f.passed === false ? "FAIL" : "",
  ]
    .filter(Boolean)
    .join("\n");
}

/**
 * Render an SVG string.
 *
 * Options:
 *   - showStatus: colour nodes by passed state (true/false/null)
 *   - title: optional headline above the DAG
 *   - compact: smaller boxes for inline use
 */
export function renderDag(fragments, options = {}) {
  if (!Array.isArray(fragments) || fragments.length === 0) {
    return `<div class="muted-line">no fragments</div>`;
  }

  const opts = options.compact
    ? { nodeW: 100, nodeH: 38, colGap: 36, rowGap: 10, padX: 10, padY: 10 }
    : { nodeW: 150, nodeH: 60, colGap: 70, rowGap: 22, padX: 18, padY: 18 };

  const { nodes, edges, width, height } = layout(fragments, opts);
  const indexToNode = new Map(nodes.map((n) => [n.fragment_index, n]));

  const edgeSvg = edges
    .map((e) => {
      const a = indexToNode.get(e.from);
      const b = indexToNode.get(e.to);
      if (!a || !b) return "";
      const x1 = a.x + a.w;
      const y1 = a.y + a.h / 2;
      const x2 = b.x;
      const y2 = b.y + b.h / 2;
      const midX = (x1 + x2) / 2;
      const path = `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;
      const labelX = midX;
      const labelY = (y1 + y2) / 2 - 4;
      return `
        <g class="dag-edge">
          <path d="${path}" />
          <text x="${labelX}" y="${labelY}" text-anchor="middle">${escapeHtml(e.label)}</text>
        </g>`;
    })
    .join("");

  const nodeSvg = nodes
    .map((n) => {
      const cls = nodeClass(n, { showStatus: !!options.showStatus });
      const labelTop = `frag ${n.fragment_index}`;
      const labelMid = n.role || "";
      const tip = nodeTitle(n);
      return `
        <g class="${cls}">
          <title>${escapeHtml(tip)}</title>
          <rect x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" rx="6" ry="6" />
          <text class="dag-node-top" x="${n.x + n.w / 2}" y="${n.y + 18}" text-anchor="middle">${escapeHtml(labelTop)}</text>
          <text class="dag-node-mid" x="${n.x + n.w / 2}" y="${n.y + 36}" text-anchor="middle">${escapeHtml(labelMid)}</text>
        </g>`;
    })
    .join("");

  const title = options.title
    ? `<div class="dag-title">${escapeHtml(options.title)}</div>`
    : "";

  return `
    ${title}
    <div class="dag-wrap">
      <svg class="dag-svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <marker id="dag-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
            <path d="M 0 0 L 10 5 L 0 10 z" />
          </marker>
        </defs>
        ${edgeSvg}
        ${nodeSvg}
      </svg>
    </div>`;
}
