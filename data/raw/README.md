# `data/raw/` — Immutable ingest layer (DRD D-02)

## What lives here

- **Real datasets (preferred for final runs):** place flow-based NIDS CSVs here, e.g.
  `CICIDS2017-Friday.csv`, `UNSW-NB15_1.csv`. Then point
  `src/data_loader.load_dataset()` at the file. Label column defaults to
  `Label`; attack names are normalised to
  `BENIGN + {DDoS, PortScan, Botnet, BruteForce, Other}`
  (mapping table is written to `results/tables/label_map.csv`).
- **Synthetic fallback (default, reproducible):** `run_all.py` and notebook 01
  generate `synthetic_A.csv` (train/eval environment) and `synthetic_B.csv`
  (shifted environment) via `src/data_loader.generate_synthetic_dataset()`.
  40 numeric flow features mimic CICIDS-style statistics (durations, packet
  counts, bytes/s, IAT, flag counts, ratios). The generator injects ~1%
  `NaN`/`Inf` so the cleaning path is genuinely exercised.

## Provenance

| File | Source | Rows | Note |
|------|--------|-----:|------|
| `synthetic_A.csv` | `generate_synthetic_dataset(seed=42)` | ~14 000 | 8 000 benign + 4 × 1 500 attacks |
| `synthetic_B.csv` | `generate_shift_dataset(seed=7)` | ~7 200 | 4 000 shifted benign + 4 × 800 attacks; drops 2 features to exercise alignment (DRD D-08) |

Real CICIDS/UNSW-NB15 downloads (multi-GB) are intentionally **not** vendored.
To use them: download from the official sources, record URL + sha256 below,
and re-run notebooks 01→06 unchanged — the pipeline is `n`-agnostic.

## Checksums (regenerate with `sha256sum data/raw/*.csv`)

- synthetic files are deterministic given the seeds above; no download needed.
