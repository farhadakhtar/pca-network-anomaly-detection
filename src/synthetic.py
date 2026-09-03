"""Deterministic synthetic flow-like data for tests and smoke runs.

Synthetic data is not real cybersecurity evidence; it exists only for CI and
pipeline validation when large public datasets are absent.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Flow Bytes/s",
    "Flow Packets/s", "Flow IAT Mean", "Average Packet Size",
    "Packet Length Variance", "SYN Flag Count", "ACK Flag Count",
    "Fwd/Bwd Packet Ratio",
]


def _benign(rng: np.random.Generator, n: int, shift: bool = False) -> pd.DataFrame:
    mult = 1.35 if shift else 1.0
    fwd = rng.poisson(18 * mult, n) + 1
    bwd = rng.poisson(14 * mult, n) + 1
    duration = rng.lognormal(mean=7.4 + (0.18 if shift else 0), sigma=0.45, size=n)
    avg = rng.normal(520 * mult, 80, n).clip(60)
    fwd_len = fwd * avg * rng.normal(1.0, 0.08, n)
    bwd_len = bwd * avg * rng.normal(0.85, 0.10, n)
    packets = fwd + bwd
    bytes_total = fwd_len + bwd_len
    df = pd.DataFrame({
        "Flow Duration": duration,
        "Total Fwd Packets": fwd,
        "Total Backward Packets": bwd,
        "Total Length of Fwd Packets": fwd_len,
        "Total Length of Bwd Packets": bwd_len,
        "Fwd Packet Length Mean": fwd_len / fwd,
        "Bwd Packet Length Mean": bwd_len / bwd,
        "Flow Bytes/s": bytes_total / np.maximum(duration, 1),
        "Flow Packets/s": packets / np.maximum(duration, 1),
        "Flow IAT Mean": duration / packets,
        "Average Packet Size": bytes_total / packets,
        "Packet Length Variance": rng.gamma(2.0, 120.0 * mult, n),
        "SYN Flag Count": rng.binomial(2, 0.08, n),
        "ACK Flag Count": rng.binomial(5, 0.75, n),
        "Fwd/Bwd Packet Ratio": fwd / bwd,
    })
    df["Label"] = "BENIGN_SHIFT" if shift else "BENIGN"
    df["environment"] = "B" if shift else "A"
    df["timestamp"] = pd.date_range("2024-01-01", periods=n, freq="min")
    return df


def _attack(rng: np.random.Generator, n: int, label: str) -> pd.DataFrame:
    df = _benign(rng, n, False)
    if label == "DDoS":
        df["Flow Duration"] *= 0.08; df["Flow Packets/s"] *= 35; df["Flow Bytes/s"] *= 25; df["SYN Flag Count"] += rng.poisson(8, n)
    elif label == "PortScan":
        df["Flow Duration"] *= 0.15; df["Total Fwd Packets"] = rng.poisson(2, n) + 1; df["Total Backward Packets"] = rng.poisson(1, n) + 1; df["SYN Flag Count"] += rng.poisson(4, n)
    elif label == "Botnet":
        df["Flow IAT Mean"] *= 4; df["Average Packet Size"] *= 0.55; df["ACK Flag Count"] = rng.binomial(2, 0.25, n)
    elif label == "BruteForce":
        df["Total Fwd Packets"] *= 2; df["Flow Duration"] *= 0.45; df["Fwd/Bwd Packet Ratio"] *= 3
    df["Label"] = label
    df["environment"] = "attack"
    return df


def generate_synthetic_flows(n_benign: int = 1000, n_attack_per_type: int = 150, n_shift: int = 250, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    parts = [_benign(rng, n_benign), _benign(rng, n_shift, shift=True)]
    for label in ["DDoS", "PortScan", "Botnet", "BruteForce"]:
        parts.append(_attack(rng, n_attack_per_type, label))
    data = pd.concat(parts, ignore_index=True)
    return data.sample(frac=1.0, random_state=seed).reset_index(drop=True)
