"""Comparable benign-only anomaly model wrappers."""
from __future__ import annotations

import time
from dataclasses import dataclass
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neural_network import MLPRegressor


@dataclass
class ModelRun:
    name: str
    scores: np.ndarray
    train_seconds: float
    inference_seconds: float
    metadata: dict[str, object]


class SklearnAnomalyWrapper:
    def __init__(self, name: str, model):
        self.name = name; self.model = model

    def fit_score(self, x_train: np.ndarray, x_test: np.ndarray) -> ModelRun:
        t0 = time.perf_counter(); self.model.fit(x_train); train_t = time.perf_counter() - t0
        t1 = time.perf_counter()
        # sklearn novelty models: larger negative decision function means more anomalous.
        scores = -self.model.decision_function(x_test)
        infer_t = time.perf_counter() - t1
        return ModelRun(self.name, np.asarray(scores), train_t, infer_t, {"params": self.model.get_params()})


class AutoencoderWrapper:
    """Small MLPRegressor reconstruction baseline; no deep learning dependency."""
    def __init__(self, random_state: int = 42, hidden_layer_sizes: tuple[int, ...] = (16, 8, 16), max_iter: int = 250):
        self.name = "autoencoder"
        self.model = MLPRegressor(hidden_layer_sizes=hidden_layer_sizes, activation="relu", solver="adam", random_state=random_state, max_iter=max_iter, early_stopping=True)

    def fit_score(self, x_train: np.ndarray, x_test: np.ndarray) -> ModelRun:
        t0 = time.perf_counter(); self.model.fit(x_train, x_train); train_t = time.perf_counter() - t0
        t1 = time.perf_counter(); rec = self.model.predict(x_test); scores = np.mean((x_test - rec) ** 2, axis=1); infer_t = time.perf_counter() - t1
        return ModelRun(self.name, scores, train_t, infer_t, {"params": self.model.get_params()})


def make_baseline(name: str, seed: int = 42):
    name = name.lower()
    if name == "isolation_forest":
        return SklearnAnomalyWrapper("isolation_forest", IsolationForest(n_estimators=100, contamination="auto", random_state=seed, n_jobs=1))
    if name == "one_class_svm":
        return SklearnAnomalyWrapper("one_class_svm", OneClassSVM(kernel="rbf", gamma="scale", nu=0.05))
    if name == "autoencoder":
        return AutoencoderWrapper(random_state=seed)
    raise ValueError(f"Unknown baseline model '{name}'.")
