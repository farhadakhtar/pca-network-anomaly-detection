"""Contract tests: one-class discipline, determinism, metrics (DRD B7, EDR §6)."""
import numpy as np
import pandas as pd

from src import BENIGN_LABEL, CATEGORY_COL, SEED
from src.data_loader import (FEATURE_NAMES, generate_synthetic_dataset,
                             normalize_label)
from src.evaluation import evaluate
from src.feature_selection import align_features, select_features
from src.pca_detector import PCADetector
from src.preprocessing import Preprocessor, clean_frame, split_one_class
from src.thresholding import fit_threshold, predict


def test_taxonomy_mapping():
    assert normalize_label("BENIGN") == "BENIGN"
    assert normalize_label("DDoS") == "DDoS"
    assert normalize_label(" Port Scan ") == "PortScan"
    assert normalize_label("FTP-Patator") == "BruteForce"
    assert normalize_label("Bot") == "Botnet"
    assert normalize_label("Something-New") == "Other"


def test_flow_ids_unique_and_label_kept_out_of_features():
    df = generate_synthetic_dataset(n_benign=500, n_per_attack=50)
    assert df["flow_id"].is_unique
    kept, _ = select_features(df)
    assert "Label" not in kept and CATEGORY_COL not in kept
    assert "flow_id" not in kept and "dataset_id" not in kept


def test_selection_drops_constant_and_reports_reason():
    df = generate_synthetic_dataset(n_benign=300, n_per_attack=30)
    df["dead_col"] = 1.0
    kept, rep = select_features(df)
    assert "dead_col" not in kept
    row = rep[rep.feature == "dead_col"].iloc[0]
    assert row["action"] == "drop" and "constant" in row["reason"]


def test_scaler_fit_only_on_benign_train():
    df = generate_synthetic_dataset(n_benign=600, n_per_attack=100)
    dfc, _ = clean_frame(df, FEATURE_NAMES)
    sp = split_one_class(dfc)
    pp = Preprocessor(FEATURE_NAMES).fit(sp["train_benign"])
    # scaler statistics must equal benign-train statistics (ERD C1)
    ref = sp["train_benign"][FEATURE_NAMES].replace([np.inf, -np.inf], np.nan)
    ref = ref.fillna(ref.median()).to_numpy()
    np.testing.assert_allclose(pp.scaler_.mean_, ref.mean(axis=0), rtol=1e-9)
    # and scaled train-benign is ~zero-mean/unit-var (DRD Q-04)
    Xt = pp.transform(sp["train_benign"])
    np.testing.assert_allclose(Xt.mean(axis=0), 0.0, atol=1e-9)


def test_detector_deterministic_and_wellformed():
    df = generate_synthetic_dataset(n_benign=600, n_per_attack=100)
    dfc, _ = clean_frame(df, FEATURE_NAMES)
    sp = split_one_class(dfc)
    pp = Preprocessor(FEATURE_NAMES).fit(sp["train_benign"])
    Xtr = pp.transform(sp["train_benign"])
    a = PCADetector().fit(Xtr)
    b = PCADetector().fit(Xtr)
    assert a.k_ == b.k_ and 1 <= a.k_ < Xtr.shape[1]          # ERD C4
    sa, ma = a.score(pp.transform(sp["test_attack"]))
    assert (sa >= 0).all() and (ma >= 0).all()
    np.testing.assert_allclose(sa, b.score(pp.transform(sp["test_attack"]))[0])


def test_threshold_p99_and_prediction_rule():
    s = np.arange(1000, dtype=float)
    t = fit_threshold(s, "p99")
    assert t.value == np.percentile(s, 99)
    p = predict(np.array([t.value - 1, t.value + 1]), t)
    assert p.tolist() == [0, 1]


def test_evaluate_toy_and_single_class_safe():
    m = evaluate(np.array([0, 0, 1, 1]), np.array([0.1, 0.2, 0.8, 0.9]),
                 np.array([0, 0, 1, 1]))
    assert (m["precision"], m["recall"], m["f1"], m["fpr"]) == (1.0, 1.0, 1.0, 0.0)
    m1 = evaluate(np.array([0, 0, 0]), np.array([0.1, 0.2, 0.3]),
                  np.array([0, 0, 0]))
    assert np.isnan(m1["auroc"]) and m1["fpr"] == 0.0  # must not crash (DRD N-03)


def test_alignment_is_ordered_intersection():
    common, rep = align_features(["a", "b", "c"], ["b", "c", "d"])
    assert common == ["b", "c"]
    assert set(rep[rep.status == "only_A"].feature) == {"a"}


def test_end_to_end_small_recall_and_separation():
    df = generate_synthetic_dataset(n_benign=1500, n_per_attack=250, seed=SEED)
    dfc, _ = clean_frame(df, FEATURE_NAMES)
    sp = split_one_class(dfc)
    pp = Preprocessor(FEATURE_NAMES).fit(sp["train_benign"])
    det = PCADetector().fit(pp.transform(sp["train_benign"]))
    sb, _ = det.score(pp.transform(sp["test_benign"]))
    sa, _ = det.score(pp.transform(sp["test_attack"]))
    assert np.median(sa) > np.percentile(sb, 90)              # DRD Q-05
    t = fit_threshold(det.score(pp.transform(sp["train_benign"]))[0])
    yt = np.array([0] * len(sb) + [1] * len(sa))
    m = evaluate(yt, np.concatenate([sb, sa]), predict(np.concatenate([sb, sa]), t))
    assert m["auroc"] > 0.75 and m["recall"] > 0.3
