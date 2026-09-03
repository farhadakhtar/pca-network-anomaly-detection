"""Reproducible command-line experiment runner.

Example:
    python -m src.experiments --config configs/synthetic_baseline.yaml
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import shutil
import time
import numpy as np
import pandas as pd

from .baseline_models import make_baseline
from .config import ExperimentConfig, load_config, resolve_path, save_json
from .data_loader import load_dataset, make_splits
from .evaluation import binary_metrics, labels_to_binary, per_attack_summary
from .failure_analysis import threshold_sensitivity
from .pca_detector import PCAReconstructionDetector
from .preprocessing import FlowPreprocessor
from .thresholding import fit_threshold, predict_from_scores
from .visualization import plot_confusion, plot_explained_variance, plot_per_attack, plot_roc_pr, plot_score_histogram


def _run_dir(base: str, name: str) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = resolve_path(base) / f"{ts}_{name}"
    path.mkdir(parents=True, exist_ok=True)
    (path / "figures").mkdir(exist_ok=True); (path / "tables").mkdir(exist_ok=True); (path / "reports").mkdir(exist_ok=True)
    return path


def _label_binary_for_test(labels: pd.Series, benign_label: str) -> np.ndarray:
    return labels_to_binary(labels, benign_label)


def run_experiment(config_path: str | Path) -> dict[str, object]:
    raw_cfg = load_config(config_path)
    cfg = ExperimentConfig.from_dict(raw_cfg)
    np.random.seed(cfg.random_seed)
    run_dir = _run_dir(cfg.output_dir, cfg.experiment_name)
    shutil.copy2(resolve_path(config_path), run_dir / "config.yaml")

    dataset = load_dataset(cfg.dataset, cfg.random_seed)
    splits = make_splits(dataset, cfg.split, cfg.random_seed)
    requested_features = cfg.preprocessing.get("features")
    pre = FlowPreprocessor(
        label_column=dataset.label_column,
        requested_features=requested_features,
        max_missing_fraction=float(cfg.preprocessing.get("max_missing_fraction", 0.5)),
        correlation_threshold=cfg.preprocessing.get("correlation_threshold", 0.995),
    )

    x_train = pre.fit_transform(splits.train_benign)
    x_cal = pre.transform(splits.calibration_benign)
    test_frame = pd.concat([splits.test_benign, splits.test_attack], ignore_index=True)
    x_test = pre.transform(test_frame)
    y_test = _label_binary_for_test(test_frame[dataset.label_column], dataset.benign_label)

    pca_cfg = cfg.pca
    detector = PCAReconstructionDetector(n_components=pca_cfg.get("n_components", 0.95), score_method=pca_cfg.get("score", "mse"), random_state=cfg.random_seed, whiten=bool(pca_cfg.get("whiten", False)))
    t0 = time.perf_counter(); detector.fit(x_train); train_seconds = time.perf_counter() - t0
    cal_scores = detector.score_samples(x_cal)
    thr_cfg = cfg.threshold.copy(); method = thr_cfg.pop("method", "percentile")
    threshold = fit_threshold(cal_scores, method=method, **thr_cfg)
    t1 = time.perf_counter(); test_scores = detector.score_samples(x_test); inference_seconds = time.perf_counter() - t1
    y_pred = predict_from_scores(test_scores, threshold.threshold)
    metrics = binary_metrics(y_test, y_pred, test_scores)
    attack_summary = per_attack_summary(test_frame[dataset.label_column], y_pred, test_scores, dataset.benign_label)

    meta = {
        "experiment_name": cfg.experiment_name,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": dataset.metadata,
        "dataset_stats": dataset.stats(),
        "split": splits.metadata,
        "preprocessing": pre.report().as_dict(),
        "pca": detector.metadata().as_dict(),
        "threshold": threshold.as_dict(),
        "random_seed": cfg.random_seed,
        "train_seconds": train_seconds,
        "inference_seconds": inference_seconds,
        "synthetic_warning": dataset.metadata.get("warning"),
    }

    predictions = test_frame[[dataset.label_column]].copy()
    predictions["ground_truth_binary"] = y_test; predictions["prediction_binary"] = y_pred; predictions["anomaly_score"] = test_scores; predictions["threshold"] = threshold.threshold
    predictions.to_csv(run_dir / "tables" / "predictions.csv", index=False)
    attack_summary.to_csv(run_dir / "tables" / "per_attack_summary.csv", index=False)
    sens = threshold_sensitivity(test_scores, y_test, [90, 95, 97.5, 99, 99.5]) if (y_test == 0).any() else pd.DataFrame()
    sens.to_csv(run_dir / "tables" / "threshold_sensitivity.csv", index=False)

    metrics_dict = metrics.as_dict()
    pd.DataFrame([metrics_dict]).to_csv(run_dir / "tables" / "metrics.csv", index=False)
    save_json({"metadata": meta, "metrics": metrics_dict}, run_dir / "metrics.json")

    plot_explained_variance(meta["pca"]["cumulative_explained_variance"], run_dir / "figures" / "explained_variance.png")
    plot_score_histogram(test_scores, y_test, threshold.threshold, run_dir / "figures" / "score_histogram.png")
    plot_confusion(y_test, y_pred, run_dir / "figures" / "confusion_matrix.png")
    plot_roc_pr(y_test, test_scores, run_dir / "figures" / "roc_curve.png", run_dir / "figures" / "precision_recall_curve.png")
    plot_per_attack(attack_summary, run_dir / "figures" / "per_attack_detection.png")

    # Distribution-shift smoke evaluation: only if shifted benign rows exist or real metadata produced them.
    shift_metrics = None
    if not splits.shifted_benign.empty:
        x_shift = pre.transform(splits.shifted_benign)
        shift_scores = detector.score_samples(x_shift)
        shift_pred = predict_from_scores(shift_scores, threshold.threshold)
        y_shift = np.zeros(len(shift_pred), dtype=int)
        shift_metrics = binary_metrics(y_shift, shift_pred, shift_scores).as_dict()
        pd.DataFrame({"anomaly_score": shift_scores, "prediction_binary": shift_pred, "threshold": threshold.threshold}).to_csv(run_dir / "tables" / "distribution_shift_benign.csv", index=False)
        save_json({"note": "Benign distribution-shift false-positive evaluation; only valid if rows are genuinely benign shift.", "metrics": shift_metrics}, run_dir / "reports" / "distribution_shift.json")

    baseline_rows = []
    for name in cfg.baselines.get("enabled", []):
        if str(name).lower() == "pca":
            baseline_rows.append({"model": "pca", "train_seconds": train_seconds, "inference_seconds": inference_seconds, **metrics_dict})
            continue
        model = make_baseline(str(name), cfg.random_seed)
        run = model.fit_score(x_train, x_test)
        model_threshold = fit_threshold(model.fit_score(x_train, x_cal).scores, method=method, **thr_cfg)
        pred = predict_from_scores(run.scores, model_threshold.threshold)
        m = binary_metrics(y_test, pred, run.scores).as_dict()
        baseline_rows.append({"model": run.name, "threshold": model_threshold.threshold, "train_seconds": run.train_seconds, "inference_seconds": run.inference_seconds, **m})
    if baseline_rows:
        pd.DataFrame(baseline_rows).to_csv(run_dir / "tables" / "baseline_comparison.csv", index=False)

    report = [
        f"# Experiment report: {cfg.experiment_name}", "",
        "This run is synthetic smoke-test evidence only." if dataset.metadata.get("source") == "synthetic" else "This run used a configured external dataset.", "",
        f"Run directory: `{run_dir}`", f"Features used: {len(pre.features_)}", f"PCA components: {meta['pca']['n_components_selected']}", f"Threshold: {threshold.threshold:.6g} ({threshold.method})", "",
        "## Metrics", "```", pd.DataFrame([metrics_dict]).to_string(index=False), "```", "",
        "## Per-traffic summary", "```", attack_summary.to_string(index=False), "```", "",
    ]
    if shift_metrics:
        report += ["## Benign distribution shift", "```", pd.DataFrame([shift_metrics]).to_string(index=False), "```", ""]
    (run_dir / "reports" / "report.md").write_text("\n".join(report), encoding="utf-8")

    return {"run_dir": str(run_dir), "metrics": metrics_dict, "metadata": meta}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run PCA network anomaly experiments.")
    parser.add_argument("--config", required=True, help="YAML/JSON experiment configuration path")
    args = parser.parse_args()
    result = run_experiment(args.config)
    print(f"Experiment complete: {result['run_dir']}")
    print(result["metrics"])


if __name__ == "__main__":
    main()
