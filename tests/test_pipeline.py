from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from src.config import ExperimentConfig
from src.data_loader import infer_label_column, load_dataset, make_splits
from src.evaluation import binary_metrics
from src.experiments import run_experiment
from src.pca_detector import PCAReconstructionDetector
from src.preprocessing import FlowPreprocessor
from src.synthetic import generate_synthetic_flows
from src.thresholding import fit_threshold, predict_from_scores


def test_data_loading_synthetic_and_missing_file():
    ds = load_dataset({"synthetic": True, "n_benign": 20, "n_attack_per_type": 3}, seed=1)
    assert ds.label_column == "Label"
    assert ds.stats()["rows"] > 20
    with pytest.raises(FileNotFoundError):
        load_dataset({"path": "data/raw/does-not-exist.csv"}, seed=1)


def test_missing_label_detection():
    with pytest.raises(ValueError):
        infer_label_column(pd.DataFrame({"a": [1, 2]}))


def test_preprocessing_nan_inf_constant_and_leakage():
    df = pd.DataFrame({
        "Label": ["BENIGN"] * 6,
        "a": [1, 2, np.nan, 4, 5, 6],
        "b": [1, 1, 1, 1, 1, 1],
        "c": [1, 2, 3, np.inf, 5, 6],
        "attack_score": [9, 9, 9, 9, 9, 9],
    })
    pre = FlowPreprocessor("Label", correlation_threshold=None).fit(df)
    assert "b" not in pre.features_
    assert "attack_score" not in pre.features_
    x = pre.transform(df)
    assert np.isfinite(x).all()


def test_pca_reconstruction_scoring():
    rng = np.random.default_rng(0)
    x = rng.normal(size=(50, 5))
    det = PCAReconstructionDetector(n_components=0.9).fit(x)
    rec = det.reconstruct(x)
    scores = det.score_samples(x)
    assert rec.shape == x.shape
    assert scores.shape == (50,)
    assert (scores >= -1e-12).all()


def test_thresholding_methods():
    scores = np.arange(100, dtype=float)
    assert fit_threshold(scores, "percentile", percentile=95).threshold > 90
    assert fit_threshold(scores, "mean_std", k=1).threshold > scores.mean()
    assert fit_threshold(scores, "robust", k=1).threshold > np.median(scores)
    pred = predict_from_scores(np.array([0, 10]), 5)
    assert pred.tolist() == [0, 1]


def test_evaluation_metrics():
    m = binary_metrics(np.array([0, 0, 1, 1]), np.array([0, 1, 1, 0]), np.array([0.1, 0.8, 0.9, 0.2]))
    assert m.tp == 1 and m.fp == 1 and m.fn == 1 and m.tn == 1
    assert m.fpr == 0.5
    assert m.auroc is not None


def test_leakage_fit_indices_are_training_only():
    ds = load_dataset({"synthetic": True, "n_benign": 60, "n_attack_per_type": 5}, seed=2)
    splits = make_splits(ds, ExperimentConfig().split, seed=2)
    pre = FlowPreprocessor(ds.label_column).fit(splits.train_benign)
    assert len(pre.fit_index_) == len(splits.train_benign)
    assert set(splits.train_benign[ds.label_column].unique()) == {"BENIGN"}


def test_end_to_end_synthetic_run(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    out = tmp_path / "runs"
    cfg.write_text(f"""
experiment_name: pytest_smoke
random_seed: 7
output_dir: {out.as_posix()}
dataset:
  synthetic: true
  n_benign: 120
  n_attack_per_type: 10
  n_shift: 20
threshold:
  method: percentile
  percentile: 98
pca:
  n_components: 0.95
  score: mse
baselines:
  enabled: [pca]
""", encoding="utf-8")
    result = run_experiment(cfg)
    run_dir = Path(result["run_dir"])
    assert (run_dir / "metrics.json").exists()
    assert (run_dir / "tables" / "predictions.csv").exists()
    assert (run_dir / "figures" / "score_histogram.png").exists()
