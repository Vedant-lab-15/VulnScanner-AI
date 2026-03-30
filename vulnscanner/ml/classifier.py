"""
ML vulnerability classifier.

Uses an XGBoost (or scikit-learn GradientBoosting fallback) model trained on
extracted code features. Provides:
  - predict(snippet, language) -> (label, confidence)
  - explain(snippet, language) -> SHAP feature importances
  - save / load model
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from vulnscanner.utils.logging import get_logger
from .features import FeatureExtractor, FeatureVector

logger = get_logger(__name__)

def _resolve_models_dir() -> Path:
    for p in [Path(__file__).parents[3], Path(__file__).parents[2], Path.cwd()]:
        candidate = p / "models"
        if candidate.exists():
            return candidate
    return Path.cwd() / "models"

_DEFAULT_MODEL_PATH = _resolve_models_dir() / "vuln_classifier.joblib"
_DEFAULT_META_PATH = _resolve_models_dir() / "model_meta.json"

# Labels
LABEL_VULNERABLE = 1
LABEL_SAFE = 0


class VulnClassifier:
    """
    Wraps a trained sklearn-compatible classifier for vulnerability prediction.

    If no trained model exists, falls back to a heuristic rule-based scorer
    so the scanner still works out-of-the-box before training.
    """

    def __init__(self, model_path: Path | None = None) -> None:
        self.model_path = model_path or _DEFAULT_MODEL_PATH
        self.extractor = FeatureExtractor()
        self._model: Any = None
        self._meta: dict[str, Any] = {}
        self._shap_explainer: Any = None
        self._load()

    # ------------------------------------------------------------------
    # Load / save
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if self.model_path.exists():
            try:
                self._model = joblib.load(self.model_path)
                if _DEFAULT_META_PATH.exists():
                    self._meta = json.loads(_DEFAULT_META_PATH.read_text())
                logger.info(f"ML model loaded from {self.model_path}")
                self._init_shap()
            except Exception as exc:
                logger.warning(f"Could not load ML model: {exc}. Using heuristic fallback.")
                self._model = None
        else:
            logger.info("No trained model found — using heuristic scorer.")

    def _init_shap(self) -> None:
        try:
            import shap
            self._shap_explainer = shap.TreeExplainer(self._model)
        except Exception:
            self._shap_explainer = None

    def save(self, model: Any, meta: dict[str, Any] | None = None) -> None:
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, self.model_path)
        self._model = model
        if meta:
            # Write alongside the model file, not to a global path
            meta_path = self.model_path.parent / "model_meta.json"
            meta_path.write_text(json.dumps(meta, indent=2))
            self._meta = meta
        self._init_shap()
        logger.info(f"Model saved to {self.model_path}")

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(self, code: str, language: str = "python") -> tuple[int, float]:
        """
        Returns (label, confidence) where label is 1=vulnerable, 0=safe.
        confidence is in [0, 1].
        """
        fv = self.extractor.extract(code, language)
        X = fv.to_array().reshape(1, -1)

        if self._model is not None:
            try:
                proba = self._model.predict_proba(X)[0]
                label = int(np.argmax(proba))
                confidence = float(proba[label])
                return label, confidence
            except Exception as exc:
                logger.debug(f"Model prediction failed: {exc}")

        # Heuristic fallback
        return self._heuristic_score(fv)

    def _heuristic_score(self, fv: FeatureVector) -> tuple[int, float]:
        """Simple rule-based scorer used when no model is trained."""
        score = 0.0
        if fv.has_user_input:
            score += 0.3
        if fv.concat_pattern_count > 0:
            score += 0.2
        if fv.sink_keyword_count > 0:
            score += 0.15 * min(fv.sink_keyword_count, 3)
        if fv.dangerous_func_count > 0:
            score += 0.2
        if fv.has_hardcoded_string:
            score += 0.25
        score = min(score, 0.95)
        label = LABEL_VULNERABLE if score >= 0.4 else LABEL_SAFE
        return label, round(score, 3)

    # ------------------------------------------------------------------
    # Explainability
    # ------------------------------------------------------------------

    def explain(self, code: str, language: str = "python") -> dict[str, float]:
        """Return feature importance dict for a single prediction."""
        fv = self.extractor.extract(code, language)
        X = fv.to_array().reshape(1, -1)
        feature_names = FeatureVector.feature_names()

        if self._shap_explainer is not None:
            try:
                shap_vals = self._shap_explainer.shap_values(X)
                # For binary classification, shap_values returns list[array]
                vals = shap_vals[1][0] if isinstance(shap_vals, list) else shap_vals[0]
                return {name: float(val) for name, val in zip(feature_names, vals)}
            except Exception:
                pass

        # Fallback: return raw feature values as "importance"
        return {name: float(val) for name, val in zip(feature_names, fv.to_array())}

    def top_features(self, code: str, language: str = "python", n: int = 5) -> list[tuple[str, float]]:
        """Return top-n most influential features."""
        importance = self.explain(code, language)
        sorted_feats = sorted(importance.items(), key=lambda x: abs(x[1]), reverse=True)
        return sorted_feats[:n]

    @property
    def model_version(self) -> str:
        return self._meta.get("version", "heuristic-v1")
