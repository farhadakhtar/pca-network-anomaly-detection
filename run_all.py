"""Headless end-to-end runner: data -> EDA -> features -> PCA -> Exp1-5 -> artefacts.

Mirrors notebooks/01-06 cell-for-cell (same ``src`` APIs). Notebooks are the
interactive interface; this script is the one-command reproducible rerun
(DRD N-02, EDR §2.4 artefact contract).
"""
from __future__ import annotations

import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor
from sklearn.svm import OneClassSVM

from src import (ATTACK_CATEGORIES, BENIGN_LABEL, CATEGORY_COL, FLOW_ID_COL,
                 LABEL_COL, SEED)
from src.data_loader import (FEATURE_NAMES, SHIFT_DROPPED_FEATURES,
                             generate_shift_dataset, generate_synthetic_dataset,
                             label_mapping_report, load_dataset)
from src.evaluation import (evaluate, evaluate_per_attack, save_metrics_csv,
                            write_experiment_summary)
from src.feature_selection import align_features, select_features
from src.pca_detector import PCADetector
from src.preprocessing import (Preprocessor, clean_frame, save_processed,
                               split_one_class)
from src.thresholding import Threshold, fit_threshold, predict, save_thresholds
from src.visualization import (plot_frontier, plot_recall_bars,
                               plot_roc_pr, plot_runtime_bars,
                               plot_score_hist, plot_shift_overlay,
                               plot_variance_elbow)

ROOT = Path(__file__).resolve().parent
RAW, PROC = ROOT / "data" / "raw", ROOT / "data" / "processed"
TAB, FIG, REP = ROOT / "results" / "tables", ROOT / "results" / "figures", ROOT / "results" / "reports"
for _d in (RAW, PROC, TAB, FIG, REP):
    _d.mkdir(parents=True, exist_ok=True)

SWEEP = ["p95", "p99", "p99.5", "mean+2std", "mean+3std", "mad"]
LEAK = ("scaler + PCA + threshold fit on benign-train only; "
        "labels used solely for scoring/slicing (EDR V-01)")


def _scores_frame(det, pp, frames: dict[str, pd.DataFrame],
                  thr: Threshold) -> pd.DataFrame:
    """Score named frames -> per-flow table (ERD E8-E11)."""
    parts = []
    for role, fr in frames.items():
        spe, mse = det.score(pp.transform(fr))
        parts.append(pd.DataFrame({
            FLOW_ID_COL: fr[FLOW_ID_COL].values, "y_true": (fr[CATEGORY_COL] != BENIGN_LABEL).astype(int).values,
            CATEGORY_COL: fr[CATEGORY_COL].values, "split_role": role,
            "score": spe, "mse": mse}))
    out = pd.concat(parts, ignore_index=True)
    out["y_pred"] = predict(out["score"].to_numpy(), thr)
    return out


def stage_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    t = time.time()
    dA = generate_synthetic_dataset()
    dB = generate_shift_dataset()
    dA.to_csv(RAW / "synthetic_A.csv", index=False)
    dB.to_csv(RAW / "synthetic_B.csv", index=False)
    A, B = load_dataset(RAW / "synthetic_A.csv"), load_dataset(RAW / "synthetic_B.csv")
    prof = []
    for name, d in (("synthetic_A", A), ("synthetic_B", B)):
        feats = [c for c in d.columns if c in FEATURE_NAMES]
        prof.append({"dataset": name, "rows": len(d), "features": len(feats),
                     "benign": int((d[CATEGORY_COL] == BENIGN_LABEL).sum()),
                     "attacks": int((d[CATEGORY_COL] != BENIGN_LABEL).sum()),
                     "missing_rate": round(float(d[feats].isna().mean().mean()), 4),
                     "inf_rate": round(float(np.isinf(d[feats].to_numpy(dtype=float, na_value=np.nan)).mean()), 4)})
    pd.DataFrame(prof).to_csv(TAB / "dataset_profile.csv", index=False)
    label_mapping_report(A).to_csv(TAB / "label_map.csv", index=False)
    print(f"[data] A={A.shape} B={B.shape} ({time.time()-t:.1f}s)")
    return A, B


def stage_features(A: pd.DataFrame, B: pd.DataFrame):
    t = time.time()
    keptA, repA = select_features(A)
    keptB, _ = select_features(B)
    repA.to_csv(TAB / "feature_report.csv", index=False)
    common, align = align_features(keptA, keptB)
    align.to_csv(TAB / "feature_alignment.csv", index=False)
    print(f"[features] keptA={len(keptA)} keptB={len(keptB)} common={len(common)} ({time.time()-t:.1f}s)")
    return keptA, common


def stage_preprocess(A: pd.DataFrame, keptA: list[str], common: list[str]):
    t = time.time()
    Ac, info = clean_frame(A, keptA)
    sp = split_one_class(Ac)
    n_tr = len(sp["train_benign"])
    pp40 = Preprocessor(keptA).fit(sp["train_benign"])
    pp40.save(PROC / "scaler.pkl")
    pp38 = Preprocessor(common).fit(sp["train_benign"])
    pp38.save(PROC / "scaler_common.pkl")
    Xtr = pp40.transform(sp["train_benign"])
    Xb = pp40.transform(sp["test_benign"])
    Xa = pp40.transform(sp["test_attack"])
    yte = np.array([0] * len(Xb) + [1] * len(Xa))
    cats = np.array([BENIGN_LABEL] * len(Xb) + sp["test_attack"][CATEGORY_COL].tolist())
    save_processed(PROC / "processed_A.npz", X_train=Xtr, X_test_benign=Xb,
                   X_test_attack=Xa, y_test=yte, test_cats=cats,
                   meta={"seed": SEED, "n_train_benign": n_tr, "features": len(keptA),
                         "dropped_rows": info["rows_dropped"]})
    print(f"[preprocess] train={n_tr} test_b={len(Xb)} test_a={len(Xa)} ({time.time()-t:.1f}s)")
    return sp, pp40, pp38, (Xtr, Xb, Xa, yte, cats)


def stage_pca_exp1(sp, pp40, mats):
    t = time.time()
    Xtr, Xb, Xa, yte, cats = mats
    det = PCADetector().fit(Xtr)
    det.save(PROC / "pca_model.pkl")
    train_spe, _ = det.score(Xtr)
    thr_map = {s: fit_threshold(train_spe, s) for s in SWEEP}
    save_thresholds(PROC / "thresholds.json", thr_map)
    base = thr_map["p99"]
    sdf = _scores_frame(det, pp40, {"test_benign": sp["test_benign"], "test_attack": sp["test_attack"]}, base)
    sdf.to_csv(TAB / "scores_exp1.csv", index=False)
    rows = []
    for s, th in thr_map.items():
        m = evaluate(sdf["y_true"].to_numpy(), sdf["score"].to_numpy(), predict(sdf["score"].to_numpy(), th))
        rows.append({"k": det.k_, "strategy": s, "threshold": th.value, **m})
    m1 = pd.DataFrame(rows)
    save_metrics_csv(TAB / "metrics_exp1.csv", m1)
    ben_s = sdf[sdf.y_true == 0]["score"].to_numpy()
    att_s = sdf[sdf.y_true == 1]["score"].to_numpy()
    figs = [str(plot_score_hist(ben_s, att_s, base.value, FIG / "score_hist_exp1.png")),
            *map(str, plot_roc_pr(sdf["y_true"].to_numpy(), sdf["score"].to_numpy(), FIG / "exp1")),
            str(plot_variance_elbow(det.variance_table(), det.k_, FIG / "variance_elbow.png")),
            str(plot_frontier(m1.rename(columns={"strategy": "strategy"})[["strategy", "fpr", "recall"]], FIG / "threshold_frontier_exp1.png"))]
    r99 = m1[m1.strategy == "p99"].iloc[0]
    write_experiment_summary(
        REP / "exp1_summary.md", exp_id="Exp1", title="Basic anomaly detection",
        train_desc=f"synthetic_A benign-train (n={len(Xtr)}, seed={SEED})",
        test_desc=f"benign-test + mixed attacks (n={len(yte)})",
        model_desc=f"PCA k={det.k_}, variance={det.variance_retained_:.3f}",
        threshold_desc=f"P99 = {base.value:.2f}",
        metrics=m1.round(4), figures=figs,
        worked=[f"AUROC={r99.auroc:.3f}, AUPRC={r99.auprc:.3f}: scores separate",
                f"median attack SPE >> benign (see score_hist_exp1.png)"],
        failed=[f"recall@P99={r99.recall:.2f}: near-manifold attacks leak (see Exp2)"]
        if r99.recall < 0.8 else ["none material"],
        leakage_note=f"{LEAK} (train_benign n={len(Xtr)})", notebook="notebooks/03_pca_baseline.ipynb")
    print(f"[exp1] k={det.k_} AUROC={r99.auroc:.3f} recall@P99={r99.recall:.3f} ({time.time()-t:.1f}s)")
    return det, base, sdf, train_spe


def stage_attacks(sdf: pd.DataFrame):
    t = time.time()
    per = evaluate_per_attack(sdf)
    save_metrics_csv(TAB / "metrics_exp2_per_attack.csv", per)
    fig = str(plot_recall_bars(per, FIG / "recall_by_attack.png", title="Exp2 recall@P99 by attack"))
    hold = per[["attack", "detection_rate", "auroc"]].rename(
        columns={"attack": "held_out_attack", "detection_rate": "recall_at_P99"})
    hold.to_csv(TAB / "metrics_exp3_holdout.csv", index=False)
    rec = per["detection_rate"]
    for exp_id, title, nb in (("exp2", "Per-attack evaluation", "notebooks/04_unseen_attack_evaluation.ipynb"),
                              ("exp3", "Unseen-attack (leave-one-out) framing", "notebooks/04_unseen_attack_evaluation.ipynb")):
        extra = ([f"worst-case held-out recall={rec.min():.2f} bounds the open-world claim"]
                 if exp_id == "exp3" else
                 [f"easiest: {per.iloc[0]['attack']} (recall={per.iloc[0]['detection_rate']:.2f})",
                  f"hardest: {per.iloc[-1]['attack']} (recall={per.iloc[-1]['detection_rate']:.2f})"])
        write_experiment_summary(
            REP / f"{exp_id}_summary.md", exp_id=f"Exp{exp_id[-1]}", title=title,
            train_desc="frozen Exp1 PCA (benign-train only)", test_desc="benign-test vs each attack separately",
            model_desc="frozen PCA", threshold_desc="frozen P99",
            metrics=(hold if exp_id == "exp3" else per).round(4), figures=[fig],
            worked=[f"median recall={rec.median():.2f} across categories"] + extra,
            failed=[f"{per.iloc[-1]['attack']} overlaps benign scores: linear-subspace blind spot"]
            if rec.min() < 0.6 else ["none material"],
            leakage_note=LEAK, notebook=nb)
    print(f"[exp2/3] worst={per.iloc[-1]['attack']}@{rec.min():.2f} ({time.time()-t:.1f}s)")
    return per


def _temporal_t1(test_benign: pd.DataFrame, seed: int = 11) -> pd.DataFrame:
    """Evening drift on the frozen test-benign set (Exp4a)."""
    rng = np.random.default_rng(seed)
    t1 = test_benign.copy()
    for c, f in (("flow_duration", 1.3), ("flow_bytes_per_s", 1.2),
                 ("tot_fwd_pkts", 1.15), ("avg_pkt_size", 1.1)):
        if c in t1:
            t1[c] = t1[c] * f * rng.lognormal(0.0, 0.05, len(t1))
    return t1


def stage_shift(det, base, pp40, pp38, sp, B: pd.DataFrame, common: list[str]):
    t = time.time()
    t1 = _temporal_t1(sp["test_benign"])
    tr_spe = det.score(pp40.transform(sp["train_benign"]))[0]
    fpr_src = float((det.score(pp40.transform(sp["test_benign"]))[0] > base.value).mean())
    s_t1 = det.score(pp40.transform(t1))[0]
    s_att = det.score(pp40.transform(sp["test_attack"]))[0]
    yt = np.array([0] * len(s_t1) + [1] * len(s_att))
    m4a = evaluate(yt, np.concatenate([s_t1, s_att]), predict(np.concatenate([s_t1, s_att]), base))
    # cross-env model on common features, frozen; tested on B (Exp4b/c)
    det38 = PCADetector().fit(pp38.transform(sp["train_benign"]))
    base38 = fit_threshold(det38.score(pp38.transform(sp["train_benign"]))[0], "p99")
    Bb = B[B[CATEGORY_COL] == BENIGN_LABEL].reset_index(drop=True)
    Ba = B[B[CATEGORY_COL] != BENIGN_LABEL].reset_index(drop=True)
    sb38 = det38.score(pp38.transform(Bb))[0]
    sa38 = det38.score(pp38.transform(Ba))[0]
    yb = np.array([0] * len(sb38) + [1] * len(sa38))
    m4bc = evaluate(yb, np.concatenate([sb38, sa38]), predict(np.concatenate([sb38, sa38]), base38))
    fpr_src38 = float((det38.score(pp38.transform(sp["test_benign"]))[0] > base38.value).mean())
    rows = [
        {"shift": "temporal (t0->t1 drift)", "model": "M40", "FPR_source": round(fpr_src, 4),
         "FPR_target": round(m4a["fpr"], 4), "dFPR": round(m4a["fpr"] - fpr_src, 4),
         "recall_src": "", "recall_tgt": round(m4a["recall"], 4),
         "AUROC_tgt": round(m4a["auroc"], 4), "AUPRC_tgt": round(m4a["auprc"], 4)},
        {"shift": "environment (A->B)", "model": "M38-common", "FPR_source": round(fpr_src38, 4),
         "FPR_target": round(m4bc["fpr"], 4), "dFPR": round(m4bc["fpr"] - fpr_src38, 4),
         "recall_src": "", "recall_tgt": round(m4bc["recall"], 4),
         "AUROC_tgt": round(m4bc["auroc"], 4), "AUPRC_tgt": round(m4bc["auprc"], 4)},
        {"shift": "cross-dataset (A->B, aligned 38)", "model": "M38-common", "FPR_source": round(fpr_src38, 4),
         "FPR_target": round(m4bc["fpr"], 4), "dFPR": round(m4bc["fpr"] - fpr_src38, 4),
         "recall_src": "", "recall_tgt": round(m4bc["recall"], 4),
         "AUROC_tgt": round(m4bc["auroc"], 4), "AUPRC_tgt": round(m4bc["auprc"], 4)},
    ]
    m4 = pd.DataFrame(rows)
    save_metrics_csv(TAB / "metrics_exp4.csv", m4)
    figs = [str(plot_shift_overlay(tr_spe, s_t1, s_att, base.value, FIG / "shift_overlay_temporal.png")),
            str(plot_shift_overlay(det38.score(pp38.transform(sp["test_benign"]))[0], sb38, sa38,
                                   base38.value, FIG / "shift_overlay_env.png"))]
    mode = ("threshold/adaptation problem (AUROC retained)" if m4a["auroc"] > 0.8
            else "representation problem (AUROC collapsed)")
    write_experiment_summary(
        REP / "exp4_summary.md", exp_id="Exp4", title="Distribution-shift robustness",
        train_desc="frozen M40 (Exp1) + frozen M38-common", test_desc="drifted t1 benign; env-B benign + B attacks",
        model_desc="frozen PCA, frozen P99 thresholds", threshold_desc=f"M40 P99={base.value:.2f}; M38 P99={base38.value:.2f}",
        metrics=m4, figures=figs,
        worked=[f"temporal dFPR={rows[0]['dFPR']:+.3f}, env dFPR={rows[1]['dFPR']:+.3f}",
                f"attack recall retained at {m4bc['recall']:.2f}: geometry holds"],
        failed=[f"fixed P99 inflates FPR under shift -> {mode} (EDR §7)"] if rows[1]["dFPR"] > 0.02 else ["shift had little effect"],
        leakage_note=f"{LEAK}; thresholds never fit on target (EDR V-02)",
        notebook="notebooks/05_distribution_shift.ipynb")
    print(f"[exp4] dFPR temp={rows[0]['dFPR']:+.3f} env={rows[1]['dFPR']:+.3f} ({time.time()-t:.1f}s)")
    return m4


def stage_baselines(mats, sdf: pd.DataFrame):
    t = time.time()
    Xtr, Xb, Xa, yte, cats = mats
    Xte = np.vstack([Xb, Xa])
    rng = np.random.default_rng(SEED)
    sub = rng.choice(len(Xtr), min(3000, len(Xtr)), replace=False)
    cands = {
        "PCA": None,  # filled from frozen scores
        "IsolationForest": IsolationForest(n_estimators=200, random_state=SEED),
        "OneClassSVM": OneClassSVM(kernel="rbf", gamma="scale", nu=0.05),
        "AutoencoderMLP": MLPRegressor(hidden_layer_sizes=(24, 8, 24), max_iter=200,
                                       early_stopping=True, n_iter_no_change=10, random_state=SEED),
    }
    train_sc, test_sc, times = {}, {}, {}
    # PCA: frozen Exp1 test scores; refit on identical data for honest timing
    # (same seed -> identical model) + benign-train scores for the P99 rule.
    t0 = time.time()
    _p = PCADetector().fit(Xtr)
    t1 = time.time()
    train_sc["PCA"] = _p.score(Xtr)[0]
    test_sc["PCA"] = sdf["score"].to_numpy()  # test_benign then test_attack == Xte order
    _p.score(Xte)
    t2 = time.time()
    times["PCA"] = (t1 - t0, t2 - t1)
    for name, mdl in cands.items():
        if name == "PCA":
            continue
        t0 = time.time()
        fitX = Xtr[sub] if name == "OneClassSVM" else Xtr
        mdl.fit(fitX if name != "AutoencoderMLP" else Xtr, Xtr if name == "AutoencoderMLP" else None)
        t1 = time.time()
        if name == "IsolationForest":
            train_sc[name], test_sc[name] = -mdl.score_samples(Xtr), -mdl.score_samples(Xte)
        elif name == "OneClassSVM":
            train_sc[name], test_sc[name] = -mdl.decision_function(Xtr), -mdl.decision_function(Xte)
        else:
            train_sc[name] = ((Xtr - mdl.predict(Xtr)) ** 2).mean(axis=1)
            test_sc[name] = ((Xte - mdl.predict(Xte)) ** 2).mean(axis=1)
        t2 = time.time()
        times[name] = (t1 - t0, t2 - t1)
    # PCA timing measured on refit (same data, same seed -> identical model)
    rows, per_rows = [], []
    for name in cands:
        th = fit_threshold(train_sc[name], "p99")
        yp = predict(test_sc[name], th)
        m = evaluate(yte, test_sc[name], yp)
        rows.append({"model": name, **{k: round(v, 4) if isinstance(v, float) else v for k, v in m.items()},
                     "train_s": round(times[name][0], 2), "infer_s": round(times[name][1], 3)})
        df_tmp = pd.DataFrame({"y_true": yte, "score": test_sc[name], "y_pred": yp,
                               CATEGORY_COL: [BENIGN_LABEL] * len(Xb) + list(cats[len(Xb):])})
        for _, r in evaluate_per_attack(df_tmp).iterrows():
            per_rows.append({"model": name, "attack": r["attack"], "recall": round(r["detection_rate"], 4)})
    comp = pd.DataFrame(rows)
    save_metrics_csv(TAB / "metrics_exp5.csv", comp)
    pd.DataFrame(per_rows).to_csv(TAB / "metrics_exp5_per_attack.csv", index=False)
    figs = [str(plot_runtime_bars(comp, FIG / "runtime_exp5.png"))]
    best = comp.sort_values("f1", ascending=False).iloc[0]
    pca = comp[comp.model == "PCA"].iloc[0]
    write_experiment_summary(
        REP / "exp5_summary.md", exp_id="Exp5", title="Baseline comparison (identical splits)",
        train_desc=f"same benign-train (n={len(Xtr)}); OCSVM subsampled to {len(sub)}",
        test_desc=f"same test (n={len(yte)})", model_desc="PCA / IF / OCSVM / MLP-AE",
        threshold_desc="each model's own P99-of-train rule (same protocol)",
        metrics=comp, figures=figs,
        worked=[f"best F1: {best['model']} ({best['f1']:.3f})",
                f"PCA: F1={pca['f1']:.3f}, train={pca['train_s']}s (cheapest linear option)"],
        failed=["nonlinear models win only if they beat PCA on hard slices; see per_attack CSV"]
        if best["model"] == "PCA" else [f"{best['model']} beats PCA on F1 by {best['f1']-pca['f1']:.3f}; check cost gap"],
        leakage_note=f"{LEAK}; identical X_train/X_test for all models (EDR §3 Exp5)",
        notebook="notebooks/06_baseline_comparison.ipynb")
    print(f"[exp5] best={best['model']} F1={best['f1']:.3f} ({time.time()-t:.1f}s)")
    return comp


def main():
    t0 = time.time()
    A, B = stage_data()
    keptA, common = stage_features(A, B)
    sp, pp40, pp38, mats = stage_preprocess(A, keptA, common)
    det, base, sdf, _ = stage_pca_exp1(sp, pp40, mats)
    stage_attacks(sdf)
    stage_shift(det, base, pp40, pp38, sp, B, common)
    stage_baselines(mats, sdf)
    print(f"DONE in {time.time()-t0:.1f}s -> results/tables, results/figures, results/reports")


if __name__ == "__main__":
    main()
