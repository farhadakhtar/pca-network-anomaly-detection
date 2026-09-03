"""Configuration loading for reproducible experiments."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def resolve_path(path: str | Path | None, base: Path = PROJECT_ROOT) -> Path | None:
    if path is None:
        return None
    p = Path(path)
    return p if p.is_absolute() else (base / p).resolve()


def load_config(path: str | Path) -> dict[str, Any]:
    """Load YAML or JSON config from a repository-relative or absolute path."""
    config_path = resolve_path(path)
    if config_path is None or not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    text = config_path.read_text(encoding="utf-8")
    if config_path.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(text) or {}
    return json.loads(text)


def save_json(data: dict[str, Any], path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


@dataclass(frozen=True)
class SplitConfig:
    train_size: float = 0.60
    calibration_size: float = 0.20
    benign_test_size: float = 0.20
    shuffle: bool = True
    temporal_column: str | None = None
    environment_column: str | None = None


@dataclass(frozen=True)
class ExperimentConfig:
    experiment_name: str = "synthetic_pca_baseline"
    random_seed: int = 42
    output_dir: str = "results/runs"
    dataset: dict[str, Any] = field(default_factory=lambda: {"synthetic": True})
    preprocessing: dict[str, Any] = field(default_factory=dict)
    pca: dict[str, Any] = field(default_factory=lambda: {"n_components": 0.95, "score": "mse"})
    threshold: dict[str, Any] = field(default_factory=lambda: {"method": "percentile", "percentile": 99.0})
    split: SplitConfig = field(default_factory=SplitConfig)
    baselines: dict[str, Any] = field(default_factory=lambda: {"enabled": ["pca"]})

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ExperimentConfig":
        split = SplitConfig(**raw.get("split", {}))
        return cls(
            experiment_name=raw.get("experiment_name", cls.experiment_name),
            random_seed=int(raw.get("random_seed", 42)),
            output_dir=raw.get("output_dir", "results/runs"),
            dataset=raw.get("dataset", {"synthetic": True}),
            preprocessing=raw.get("preprocessing", {}),
            pca=raw.get("pca", {"n_components": 0.95, "score": "mse"}),
            threshold=raw.get("threshold", {"method": "percentile", "percentile": 99.0}),
            split=split,
            baselines=raw.get("baselines", {"enabled": ["pca"]}),
        )
