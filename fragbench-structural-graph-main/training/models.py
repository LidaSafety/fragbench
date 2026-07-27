"""
FragGuard models.

Two pieces:
  1. FragGNN     — the "heavy" model run offline in batch. Produces a
                   D-dimensional embedding per node that summarizes its
                   k-hop neighborhood (data flow, temporal, shared-resource
                   edges). Embeddings get dumped to a KV store.

  2. FragScorer  — the tiny 2-layer MLP head run on the hot path. Takes a
                   cached embedding and returns P(malicious). Kept
                   deliberately small (~a few thousand params) so inference
                   is dominated by the KV lookup, not the matmul.

Design notes
------------
* The GNN uses GraphSAGE-style mean aggregation. It's cheap, scales to
  billions of nodes with neighbor sampling, and doesn't need the full
  adjacency in memory at once.
* We learn a separate edge-type embedding so "X writes file Y" is distinct
  from "X runs after Y" — fragmentation attacks lean heavily on the
  temporal + shared-resource channels, and collapsing them loses signal.
* The scorer is trained *jointly* with the GNN during offline training,
  but at serve time it's loaded standalone and fed pre-computed vectors.
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F


# Edge types observed between fragments. Order matters — it's the index
# into the edge-type embedding table.
EDGE_TYPES = ("data_flow", "temporal", "shared_resource", "shared_session")
NUM_EDGE_TYPES = len(EDGE_TYPES)


class SAGELayer(nn.Module):
    """
    One GraphSAGE layer with edge-type-aware aggregation.

    For each node v we compute:

        h_v' = ReLU( W_self · h_v  +  W_neigh · mean_{u ∈ N(v)} (h_u + e_{uv}) )

    where e_{uv} is the learned embedding of the edge type between u and v.
    Mean aggregation (vs. sum) keeps activations bounded regardless of
    degree — important because fragment graphs have very skewed degree
    distributions (shared-resource hubs like /tmp or a common PID).
    """

    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.w_self = nn.Linear(in_dim, out_dim, bias=False)
        self.w_neigh = nn.Linear(in_dim, out_dim, bias=True)

    def forward(
        self,
        h_self: torch.Tensor,          # [B, in_dim]   target node features
        h_neigh: torch.Tensor,         # [B, K, in_dim] sampled neighbor feats
        edge_type_emb: torch.Tensor,   # [B, K, in_dim] per-edge embeddings
        neigh_mask: torch.Tensor,      # [B, K] 1 = real neighbor, 0 = padding
    ) -> torch.Tensor:
        # Add edge-type signal to each neighbor, then masked mean.
        neigh = h_neigh + edge_type_emb                              # [B, K, D]
        mask = neigh_mask.unsqueeze(-1).float()                      # [B, K, 1]
        summed = (neigh * mask).sum(dim=1)                           # [B, D]
        counts = mask.sum(dim=1).clamp(min=1.0)                      # [B, 1]
        agg = summed / counts                                        # [B, D]

        out = self.w_self(h_self) + self.w_neigh(agg)
        return F.relu(out)


class FragGNN(nn.Module):
    """
    Heavy offline model. Two SAGE layers is usually enough — fragmentation
    chains we care about are short (2–5 hops). Going deeper hurts more
    than it helps because of over-smoothing on hub-heavy graphs.
    """

    def __init__(
        self,
        node_feat_dim: int = 128,
        hidden_dim: int = 256,
        embed_dim: int = 128,
    ):
        super().__init__()
        self.edge_type_table = nn.Embedding(NUM_EDGE_TYPES, node_feat_dim)

        self.layer1 = SAGELayer(node_feat_dim, hidden_dim)
        # Edge embeddings at layer 2 live in hidden_dim, so give them their
        # own projection rather than reusing the input-dim table.
        self.edge_proj_l2 = nn.Linear(node_feat_dim, hidden_dim, bias=False)
        self.layer2 = SAGELayer(hidden_dim, embed_dim)

        self.embed_dim = embed_dim

    def forward(
        self,
        x_self: torch.Tensor,          # [B, node_feat_dim]
        x_n1: torch.Tensor,            # [B, K1, node_feat_dim]   1-hop feats
        et_n1: torch.Tensor,           # [B, K1]                  edge-type ids
        mask_n1: torch.Tensor,         # [B, K1]
        x_n2: torch.Tensor,            # [B, K1, K2, node_feat_dim] 2-hop feats
        et_n2: torch.Tensor,           # [B, K1, K2]
        mask_n2: torch.Tensor,         # [B, K1, K2]
    ) -> torch.Tensor:
        B, K1 = x_n1.shape[0], x_n1.shape[1]
        K2 = x_n2.shape[2]

        # ---- Layer 1 on the 1-hop neighbors (so they each see their own 2-hop).
        # Flatten (B, K1) into a batch of B*K1 "target" nodes whose neighbors
        # are the corresponding row of x_n2.
        x_n1_flat = x_n1.reshape(B * K1, -1)
        x_n2_flat = x_n2.reshape(B * K1, K2, -1)
        et_n2_flat = et_n2.reshape(B * K1, K2)
        mask_n2_flat = mask_n2.reshape(B * K1, K2)

        edge_emb_n2 = self.edge_type_table(et_n2_flat)  # [B*K1, K2, feat]
        h_n1_flat = self.layer1(
            h_self=x_n1_flat,
            h_neigh=x_n2_flat,
            edge_type_emb=edge_emb_n2,
            neigh_mask=mask_n2_flat,
        )  # [B*K1, hidden]
        h_n1 = h_n1_flat.view(B, K1, -1)  # [B, K1, hidden]

        # ---- Layer 1 on the target node itself, using 1-hop raw features.
        edge_emb_n1 = self.edge_type_table(et_n1)  # [B, K1, feat]
        h_self_l1 = self.layer1(
            h_self=x_self,
            h_neigh=x_n1,
            edge_type_emb=edge_emb_n1,
            neigh_mask=mask_n1,
        )  # [B, hidden]

        # ---- Layer 2: target (now in hidden dim) aggregates its 1-hop
        # neighbors (also in hidden dim). Edge-type signal gets re-projected.
        edge_emb_n1_l2 = self.edge_proj_l2(edge_emb_n1)  # [B, K1, hidden]
        out = self.layer2(
            h_self=h_self_l1,
            h_neigh=h_n1,
            edge_type_emb=edge_emb_n1_l2,
            neigh_mask=mask_n1,
        )  # [B, embed_dim]

        # L2-normalize so cosine similarity is meaningful when we want to
        # cluster / nearest-neighbor suspicious embeddings later.
        return F.normalize(out, p=2, dim=-1)


# ═══════════════════════════════════════════════════════════════════════════
# ADDITIONAL GNN LAYER VARIANTS
# ═══════════════════════════════════════════════════════════════════════════


class GATLayer(nn.Module):
    """
    Graph Attention layer with edge-type-aware multi-head attention.

    Instead of uniform mean aggregation (SAGE), each neighbor gets a
    learned attention weight:

        alpha_j = softmax_j( LeakyReLU( a^T [W h_self || W (h_j + e_j)] ) )
        agg = sum_j alpha_j * W_val (h_j + e_j)
        h' = ReLU(W_self h_self + agg)

    Multi-head attention (default 4 heads) lets different heads attend
    to different edge-type / feature patterns.
    """

    def __init__(self, in_dim: int, out_dim: int, num_heads: int = 4):
        super().__init__()
        assert out_dim % num_heads == 0, "out_dim must be divisible by num_heads"
        self.num_heads = num_heads
        self.head_dim = out_dim // num_heads

        self.w_self = nn.Linear(in_dim, out_dim, bias=False)
        self.w_neigh = nn.Linear(in_dim, out_dim, bias=False)
        # Attention vector per head: scores a concatenation of [query, key]
        self.attn = nn.Parameter(torch.empty(num_heads, 2 * self.head_dim))
        nn.init.xavier_uniform_(self.attn.unsqueeze(0))
        self.leaky_relu = nn.LeakyReLU(0.2)

    def forward(
        self,
        h_self: torch.Tensor,          # [B, in_dim]
        h_neigh: torch.Tensor,         # [B, K, in_dim]
        edge_type_emb: torch.Tensor,   # [B, K, in_dim]
        neigh_mask: torch.Tensor,      # [B, K]
    ) -> torch.Tensor:
        B, K, _ = h_neigh.shape
        H, D = self.num_heads, self.head_dim

        # Project
        q = self.w_self(h_self).view(B, H, D)              # [B, H, D]
        neigh = h_neigh + edge_type_emb
        kv = self.w_neigh(neigh).view(B, K, H, D)          # [B, K, H, D]

        # Attention logits: concat query with each key
        q_exp = q.unsqueeze(1).expand(B, K, H, D)          # [B, K, H, D]
        cat = torch.cat([q_exp, kv], dim=-1)                # [B, K, H, 2D]
        logits = (cat * self.attn.unsqueeze(0).unsqueeze(0)).sum(-1)  # [B, K, H]
        logits = self.leaky_relu(logits)

        # Masked softmax
        mask = neigh_mask.unsqueeze(-1)                     # [B, K, 1]
        logits = logits.masked_fill(mask == 0, -1e9)
        attn_weights = torch.softmax(logits, dim=1)         # [B, K, H]

        # Weighted aggregation
        agg = (attn_weights.unsqueeze(-1) * kv).sum(dim=1)  # [B, H, D]
        agg = agg.reshape(B, H * D)                         # [B, out_dim]

        out = self.w_self(h_self) + agg
        return F.relu(out)


class GCNLayer(nn.Module):
    """
    GCN-style layer adapted for sampled neighborhoods.

    Approximates symmetric normalization with masked mean:

        h' = ReLU( W · (h_self + mean_{j ∈ N} (h_j + e_j)) )

    Key difference from SAGE: single shared weight matrix applied to
    the combined self + neighbor signal, rather than separate W_self
    and W_neigh. Fewer parameters, but potentially less expressive.
    """

    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.w = nn.Linear(in_dim, out_dim, bias=True)

    def forward(
        self,
        h_self: torch.Tensor,          # [B, in_dim]
        h_neigh: torch.Tensor,         # [B, K, in_dim]
        edge_type_emb: torch.Tensor,   # [B, K, in_dim]
        neigh_mask: torch.Tensor,      # [B, K]
    ) -> torch.Tensor:
        neigh = h_neigh + edge_type_emb
        mask = neigh_mask.unsqueeze(-1).float()
        summed = (neigh * mask).sum(dim=1)
        counts = mask.sum(dim=1).clamp(min=1.0)
        agg = summed / counts                               # [B, D]

        out = self.w(h_self + agg)
        return F.relu(out)


class GINLayer(nn.Module):
    """
    Graph Isomorphism Network layer — maximally expressive under the
    Weisfeiler-Leman framework.

    Uses SUM aggregation (not mean) with a learnable epsilon:

        h' = MLP( (1 + eps) * h_self + SUM_{j ∈ N} (h_j + e_j) )

    Sum aggregation is critical: it makes the update injective, giving
    GIN strictly more expressive power than GCN/SAGE in theory. The
    trade-off is sensitivity to degree distribution — the BatchNorm
    inside the MLP stabilizes this.
    """

    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.eps = nn.Parameter(torch.zeros(1))
        self.mlp = nn.Sequential(
            nn.Linear(in_dim, out_dim),
            nn.BatchNorm1d(out_dim),
            nn.ReLU(),
            nn.Linear(out_dim, out_dim),
        )

    def forward(
        self,
        h_self: torch.Tensor,          # [B, in_dim]
        h_neigh: torch.Tensor,         # [B, K, in_dim]
        edge_type_emb: torch.Tensor,   # [B, K, in_dim]
        neigh_mask: torch.Tensor,      # [B, K]
    ) -> torch.Tensor:
        neigh = h_neigh + edge_type_emb
        mask = neigh_mask.unsqueeze(-1).float()
        agg = (neigh * mask).sum(dim=1)                     # SUM, not mean

        out = self.mlp((1 + self.eps) * h_self + agg)
        return F.relu(out)


# ═══════════════════════════════════════════════════════════════════════════
# GENERIC GNN — parameterized by layer type
# ═══════════════════════════════════════════════════════════════════════════

LAYER_REGISTRY = {
    "sage": SAGELayer,
    "gat": GATLayer,
    "gcn": GCNLayer,
    "gin": GINLayer,
}


class FragGNNGeneric(nn.Module):
    """
    Same 2-hop wiring as FragGNN but parameterized by layer type.
    Accepts arch in {"sage", "gat", "gcn", "gin"}.
    """

    def __init__(
        self,
        arch: str = "sage",
        node_feat_dim: int = 128,
        hidden_dim: int = 256,
        embed_dim: int = 128,
        **layer_kwargs,
    ):
        super().__init__()
        LayerClass = LAYER_REGISTRY[arch]
        self.arch = arch
        self.edge_type_table = nn.Embedding(NUM_EDGE_TYPES, node_feat_dim)

        self.layer1 = LayerClass(node_feat_dim, hidden_dim, **layer_kwargs)
        self.edge_proj_l2 = nn.Linear(node_feat_dim, hidden_dim, bias=False)
        self.layer2 = LayerClass(hidden_dim, embed_dim, **layer_kwargs)

        self.embed_dim = embed_dim

    def forward(
        self,
        x_self: torch.Tensor,
        x_n1: torch.Tensor,
        et_n1: torch.Tensor,
        mask_n1: torch.Tensor,
        x_n2: torch.Tensor,
        et_n2: torch.Tensor,
        mask_n2: torch.Tensor,
    ) -> torch.Tensor:
        B, K1 = x_n1.shape[0], x_n1.shape[1]
        K2 = x_n2.shape[2]

        # Layer 1 on 1-hop neighbors (each sees its 2-hop)
        x_n1_flat = x_n1.reshape(B * K1, -1)
        x_n2_flat = x_n2.reshape(B * K1, K2, -1)
        et_n2_flat = et_n2.reshape(B * K1, K2)
        mask_n2_flat = mask_n2.reshape(B * K1, K2)

        edge_emb_n2 = self.edge_type_table(et_n2_flat)
        h_n1_flat = self.layer1(
            h_self=x_n1_flat,
            h_neigh=x_n2_flat,
            edge_type_emb=edge_emb_n2,
            neigh_mask=mask_n2_flat,
        )
        h_n1 = h_n1_flat.view(B, K1, -1)

        # Layer 1 on target node using 1-hop raw features
        edge_emb_n1 = self.edge_type_table(et_n1)
        h_self_l1 = self.layer1(
            h_self=x_self,
            h_neigh=x_n1,
            edge_type_emb=edge_emb_n1,
            neigh_mask=mask_n1,
        )

        # Layer 2: target aggregates updated 1-hop neighbors
        edge_emb_n1_l2 = self.edge_proj_l2(edge_emb_n1)
        out = self.layer2(
            h_self=h_self_l1,
            h_neigh=h_n1,
            edge_type_emb=edge_emb_n1_l2,
            neigh_mask=mask_n1,
        )

        return F.normalize(out, p=2, dim=-1)


class FragScorer(nn.Module):
    """
    Tiny 2-layer MLP served online. Input = cached embedding. Output =
    logit for P(malicious). Kept small on purpose: at ~1 µs/node the
    matmul itself is a few hundred nanoseconds, the rest is overhead.
    """

    def __init__(self, embed_dim: int = 128, hidden: int = 64):
        super().__init__()
        self.fc1 = nn.Linear(embed_dim, hidden)
        self.fc2 = nn.Linear(hidden, 1)

    def forward(self, z: torch.Tensor) -> torch.Tensor:
        return self.fc2(F.relu(self.fc1(z))).squeeze(-1)

    @torch.no_grad()
    def score(self, z: torch.Tensor) -> torch.Tensor:
        """Serving entry point: returns probabilities, not logits."""
        return torch.sigmoid(self.forward(z))
