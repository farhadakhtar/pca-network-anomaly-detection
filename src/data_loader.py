"""Ingest + label normalisation + reproducible synthetic flow data (ERD E1-E2).

Real CSVs are loaded with :func:`load_dataset`. When no download is available,
:func:`generate_synthetic_dataset` / :func:`generate_shift_dataset` produce
deterministic CICIDS-style flow tables so the whole pipeline runs end to end.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from src import (
    ATTACK_CATEGORIES,
    BENIGN_LABEL,
    CATEGORY_COL,
    FLOW_ID_COL,
    LABEL_COL,
    SEED,
)

# 40 numeric flow features (CICIDS-style; pipeline is n-agnostic, DRD D-05).
FEATURE_NAMES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
    "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_mean", "bwd_pkt_len_mean",
    "flow_bytes_per_s", "flow_pkts_per_s",
    "flow_iat_mean", "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean",
    "avg_pkt_size", "pkt_len_var", "pkt_len_std",
    "fwd_seg_size_avg", "bwd_seg_size_avg",
    "syn_flag_cnt", "ack_flag_cnt", "fin_flag_cnt",
    "psh_flag_cnt", "rst_flag_cnt", "urg_flag_cnt",
    "fwd_bwd_ratio", "down_up_ratio",
    "active_mean", "idle_mean", "idle_max",
    "init_win_fwd", "init_win_bwd",
    "subflow_fwd_pkts", "subflow_bwd_pkts",
    "fwd_header_len", "bwd_header_len",
    "min_pkt_len", "max_pkt_len", "pkt_len_median",
    "bytes_per_pkt", "burst_rate",
]

# Features absent from the shifted environment: exercises alignment (DRD D-08).
SHIFT_DROPPED_FEATURES = ["urg_flag_cnt", "idle_max"]

# Raw label substrings -> canonical category (DRD D-04).
_RAW_MAP = [
    ("BENIGN", BENIGN_LABEL),
    ("DDOS", "DDoS"),
    ("PORTSCAN", "PortScan"),
    ("PORT SCAN", "PortScan"),
    ("BOT", "Botnet"),
    ("BRUTE", "BruteForce"),
    ("PATATOR", "BruteForce"),
    ("INFILTRATION", "Other"),
    ("WEB ATTACK", "Other"),
    ("HEARTBLEED", "Other"),
]


def normalize_label(raw: object) -> str:
    """Map a raw dataset label onto the canonical taxonomy."""
    s = str(raw).strip().upper()
    if s == BENIGN_LABEL:
        return BENIGN_LABEL
    for needle, canon in _RAW_MAP[1:]:
        if needle in s:
            return canon
    return "Other"


def normalize_frame(df: pd.DataFrame, label_col: str = LABEL_COL,
                    dataset_id: str = "") -> pd.DataFrame:
    """Attach ``flow_id`` + ``AttackCategory``; never mutates feature values."""
    out = df.copy()
    if label_col not in out.columns:
        raise KeyError(f"label column {label_col!r} not in {list(out.columns)[:8]}...")
    out[CATEGORY_COL] = out[label_col].map(normalize_label)
    stem = dataset_id or "ds"
    out[FLOW_ID_COL] = [f"{stem}#{i}" for i in range(len(out))]
    out["dataset_id"] = stem
    return out


def load_dataset(path: str | Path, label_col: str = LABEL_COL) -> pd.DataFrame:
    """Load one raw flow CSV (ERD E1->E2)."""
    path = Path(path)
    df = pd.read_csv(path)
    return normalize_frame(df, label_col=label_col, dataset_id=path.stem)


def label_mapping_report(df: pd.DataFrame,
                         label_col: str = LABEL_COL) -> pd.DataFrame:
    """Raw-label -> canonical-category census (DRD D-04 artefact)."""
    rep = (df.assign(_canon=df[label_col].map(normalize_label))
             .groupby([label_col, "_canon"]).size()
             .reset_index(name="count")
             .rename(columns={"_canon": "canonical"}))
    return rep.sort_values("count", ascending=False).reset_index(drop=True)


# --------------------------------------------------------------------------- #
# Synthetic generator (deterministic given seed)
# --------------------------------------------------------------------------- #

def _base_benign(rng: np.random.Generator, n: int) -> dict:
    """Correlated benign flow statistics; everything derives from a few
    latent factors so PCA has real structure to learn."""
    dur = rng.lognormal(mean=6.0, sigma=1.2, size=n)            # ~ms
    fwd = np.exp(rng.normal(2.5, 1.0, n)).astype(float) + 1.0
    bwd = np.exp(rng.normal(2.2, 1.0, n)).astype(float)
    avg = rng.lognormal(mean=5.5, sigma=0.8, size=n)            # avg pkt size
    spread = rng.lognormal(mean=4.0, sigma=0.9, size=n)
    tot_f = fwd * (avg * rng.lognormal(0.0, 0.15, n))
    tot_b = bwd * (avg * rng.lognormal(0.0, 0.15, n))
    iat_m = dur / np.maximum(fwd + bwd, 1.0)
    f = {
        "flow_duration": dur,
        "tot_fwd_pkts": fwd, "tot_bwd_pkts": bwd,
        "totlen_fwd_pkts": tot_f, "totlen_bwd_pkts": tot_b,
        "fwd_pkt_len_mean": avg * rng.lognormal(0.0, 0.1, n),
        "bwd_pkt_len_mean": avg * rng.lognormal(0.0, 0.1, n),
        "flow_bytes_per_s": (tot_f + tot_b) / np.maximum(dur, 1e-3) * 1e3,
        "flow_pkts_per_s": (fwd + bwd) / np.maximum(dur, 1e-3) * 1e3,
        "flow_iat_mean": iat_m,
        "flow_iat_std": iat_m * rng.lognormal(0.0, 0.5, n),
        "fwd_iat_mean": iat_m * rng.lognormal(0.1, 0.3, n),
        "bwd_iat_mean": iat_m * rng.lognormal(0.1, 0.3, n),
        "avg_pkt_size": avg,
        "pkt_len_var": spread ** 2,
        "pkt_len_std": spread,
        "fwd_seg_size_avg": avg * rng.lognormal(0.0, 0.08, n),
        "bwd_seg_size_avg": avg * rng.lognormal(0.0, 0.08, n),
        "syn_flag_cnt": rng.poisson(1.2, n).astype(float),
        "ack_flag_cnt": np.minimum(fwd + bwd, rng.poisson(8, n)).astype(float),
        "fin_flag_cnt": rng.poisson(0.8, n).astype(float),
        "psh_flag_cnt": rng.poisson(1.5, n).astype(float),
        "rst_flag_cnt": rng.poisson(0.15, n).astype(float),
        "urg_flag_cnt": rng.poisson(0.1, n).astype(float),
        "active_mean": dur * rng.uniform(0.3, 0.7, n),
        "idle_mean": dur * rng.uniform(0.1, 0.4, n),
        "idle_max": dur * rng.uniform(0.2, 0.6, n),
        "init_win_fwd": np.clip(rng.normal(29200, 4000, n), 1024, 65535),
        "init_win_bwd": np.clip(rng.normal(64240, 6000, n), 1024, 65535),
        "fwd_header_len": np.clip(rng.normal(320, 120, n), 20, None),
        "bwd_header_len": np.clip(rng.normal(280, 110, n), 20, None),
    }
    f["subflow_fwd_pkts"] = fwd * rng.uniform(0.4, 0.9, n)
    f["subflow_bwd_pkts"] = bwd * rng.uniform(0.4, 0.9, n)
    f["fwd_bwd_ratio"] = fwd / np.maximum(bwd, 1.0)
    f["down_up_ratio"] = tot_f / np.maximum(tot_b, 1.0)
    f["min_pkt_len"] = np.maximum(avg - spread, 20.0)
    f["max_pkt_len"] = avg + spread * rng.uniform(1.0, 2.0, n)
    f["pkt_len_median"] = avg * rng.lognormal(0.0, 0.12, n)
    f["bytes_per_pkt"] = (tot_f + tot_b) / np.maximum(fwd + bwd, 1.0)
    f["burst_rate"] = (fwd + bwd) / np.maximum(f["active_mean"], 1e-3) * 1e3
    return f


def _attack_overrides(base: dict, rng: np.random.Generator, kind: str) -> dict:
    """Deform benign statistics into attack behaviour (Exp2/H2 design:
    DDoS extreme, PortScan structural, Botnet regular, BruteForce near-manifold)."""
    a = dict(base)
    n = len(next(iter(base.values())))
    if kind == "DDoS":
        a["flow_duration"] = base["flow_duration"] * 0.02
        a["tot_fwd_pkts"] = base["tot_fwd_pkts"] * 40.0
        a["tot_bwd_pkts"] = base["tot_bwd_pkts"] * 0.2 + 1.0
        a["avg_pkt_size"] = np.full(n, 60.0) * rng.lognormal(0.0, 0.1, n)
        a["syn_flag_cnt"] = a["tot_fwd_pkts"] * 0.8
        a["flow_iat_std"] = base["flow_iat_std"] * 0.05
        a["flow_bytes_per_s"] = base["flow_bytes_per_s"] * 60.0
        a["flow_pkts_per_s"] = base["flow_pkts_per_s"] * 90.0
    elif kind == "PortScan":
        a["tot_fwd_pkts"] = rng.integers(1, 3, n).astype(float)
        a["tot_bwd_pkts"] = np.zeros(n)                       # no replies: pure probe
        a["avg_pkt_size"] = np.full(n, 40.0) * rng.lognormal(0.0, 0.05, n)
        a["syn_flag_cnt"] = a["tot_fwd_pkts"]                 # SYN-only
        a["ack_flag_cnt"] = np.zeros(n)
        a["fin_flag_cnt"] = np.zeros(n)
        a["psh_flag_cnt"] = np.zeros(n)
        a["rst_flag_cnt"] = rng.integers(0, 2, n).astype(float)
        a["flow_duration"] = base["flow_duration"] * 0.01
        a["flow_iat_mean"] = a["flow_duration"] / np.maximum(a["tot_fwd_pkts"], 1.0)
        a["flow_iat_std"] = a["flow_iat_mean"] * 0.1
        a["totlen_fwd_pkts"] = a["tot_fwd_pkts"] * a["avg_pkt_size"]
        a["totlen_bwd_pkts"] = np.zeros(n)
        a["bwd_pkt_len_mean"] = np.zeros(n)
        a["down_up_ratio"] = a["totlen_fwd_pkts"]             # /max(tot_b,1) recomputed below
    elif kind == "Botnet":
        a["flow_duration"] = base["flow_duration"] * 6.0
        a["flow_iat_std"] = base["flow_iat_std"] * 0.08          # metronomic
        a["flow_iat_mean"] = np.full(n, 5000.0) * rng.lognormal(0.0, 0.05, n)
        a["tot_fwd_pkts"] = rng.lognormal(3.0, 0.25, n)
        a["psh_flag_cnt"] = rng.poisson(6, n).astype(float)
        a["idle_mean"] = np.full(n, 4000.0) * rng.lognormal(0.0, 0.05, n)
    elif kind == "BruteForce":                                   # near-benign
        a["tot_fwd_pkts"] = rng.lognormal(3.2, 0.5, n)
        a["avg_pkt_size"] = np.full(n, 120.0) * rng.lognormal(0.0, 0.15, n)
        a["ack_flag_cnt"] = a["tot_fwd_pkts"] * 0.9
        a["psh_flag_cnt"] = a["tot_fwd_pkts"] * 0.5
        a["flow_duration"] = base["flow_duration"] * 1.4
        a["totlen_fwd_pkts"] = a["tot_fwd_pkts"] * a["avg_pkt_size"]
    # Re-derive dependent quantities so rows stay internally consistent.
    fwd, bwd = a["tot_fwd_pkts"], a["tot_bwd_pkts"]
    avg = a["avg_pkt_size"]
    a["fwd_pkt_len_mean"] = avg * rng.lognormal(0.0, 0.1, n)
    a["bwd_pkt_len_mean"] = avg * rng.lognormal(0.0, 0.1, n)
    a["fwd_bwd_ratio"] = fwd / np.maximum(bwd, 1.0)
    a["bytes_per_pkt"] = (a["totlen_fwd_pkts"] + a["totlen_bwd_pkts"]) / np.maximum(fwd + bwd, 1.0)
    a["min_pkt_len"] = np.maximum(avg * 0.7, 20.0)
    a["max_pkt_len"] = avg * rng.uniform(1.2, 2.0, n)
    return a


def _frame_from_parts(parts: list[tuple[str, dict]]) -> pd.DataFrame:
    rows = []
    for label, d in parts:
        df = pd.DataFrame(d, columns=FEATURE_NAMES)
        df[LABEL_COL] = label
        rows.append(df)
    return pd.concat(rows, ignore_index=True)


def _inject_bad(df: pd.DataFrame, rng: np.random.Generator,
                rate: float = 0.01) -> pd.DataFrame:
    """Sprinkle NaN/+Inf so cleaning is exercised (counts are reported)."""
    out = df.copy()
    feats = [c for c in FEATURE_NAMES if c in out.columns]
    m = rng.random((len(out), len(feats))) < rate / 2
    out[feats] = out[feats].mask(pd.DataFrame(m, columns=feats, index=out.index))
    m2 = rng.random((len(out), len(feats))) < rate / 2
    out[feats] = out[feats].mask(
        pd.DataFrame(m2, columns=feats, index=out.index), np.inf)
    return out


def generate_synthetic_dataset(n_benign: int = 8000, n_per_attack: int = 1500,
                               seed: int = SEED) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    parts = [(BENIGN_LABEL, _base_benign(rng, n_benign))]
    for kind in ["DDoS", "PortScan", "Botnet", "BruteForce"]:
        parts.append((kind, _attack_overrides(_base_benign(rng, n_per_attack), rng, kind)))
    df = _frame_from_parts(parts)
    df = _inject_bad(df, rng)
    return normalize_frame(df, dataset_id="synthetic_A")


def generate_shift_dataset(n_benign: int = 4000, n_per_attack: int = 800,
                           seed: int = 7) -> pd.DataFrame:
    """Evening-profile benign traffic (Exp4): longer, heavier flows + noisier
    statistics, while attacks look the same -> FPR inflates, recall holds."""
    rng = np.random.default_rng(seed)
    b = _base_benign(rng, n_benign)
    # Evening-profile drift, tuned (probe) to FPR ~0.12 at frozen P99 while
    # attack recall holds: off-manifold in flags/windows + heavier volumes.
    b["flow_duration"] = b["flow_duration"] * 3.5
    b["flow_bytes_per_s"] = b["flow_bytes_per_s"] * 3.0
    b["tot_fwd_pkts"] = b["tot_fwd_pkts"] * 2.5
    b["avg_pkt_size"] = b["avg_pkt_size"] * 2.0
    b["flow_iat_mean"] = b["flow_iat_mean"] * 0.35
    b["active_mean"] = b["active_mean"] * 2.5
    b["idle_mean"] = b["idle_mean"] * 2.5
    b["syn_flag_cnt"] = b["syn_flag_cnt"] * 5.0 + 1.0
    b["ack_flag_cnt"] = b["ack_flag_cnt"] * 4.0
    b["init_win_fwd"] = np.clip(b["init_win_fwd"] * 1.4, 1024, 65535)
    b["fwd_header_len"] = b["fwd_header_len"] * 2.0
    b["burst_rate"] = b["burst_rate"] * 2.0
    for k, v in b.items():  # noisier evening network
        b[k] = v * rng.lognormal(0.0, 0.10, n_benign)
    parts = [(BENIGN_LABEL, b)]
    for kind in ["DDoS", "PortScan", "Botnet", "BruteForce"]:
        parts.append((kind, _attack_overrides(_base_benign(rng, n_per_attack), rng, kind)))
    df = _frame_from_parts(parts)
    df = _inject_bad(df, rng)
    df = df.drop(columns=SHIFT_DROPPED_FEATURES)  # cross-dataset mismatch
    return normalize_frame(df, dataset_id="synthetic_B")
