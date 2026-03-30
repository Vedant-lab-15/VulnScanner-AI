"""
ML model training pipeline.

Trains an XGBoost classifier on synthetic + public vulnerable code samples.
Run via: vulnscanner train

Dataset format expected in datasets/training_data.csv:
  columns: code_snippet, language, label (0=safe, 1=vulnerable)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import LabelEncoder

from vulnscanner.utils.logging import get_logger
from .features import FeatureExtractor
from .classifier import VulnClassifier

logger = get_logger(__name__)

def _resolve_dir(name: str) -> Path:
    for p in [Path(__file__).parents[3], Path(__file__).parents[2], Path.cwd()]:
        candidate = p / name
        if candidate.exists():
            return candidate
    d = Path.cwd() / name
    d.mkdir(parents=True, exist_ok=True)
    return d

_DATASETS_DIR = _resolve_dir("datasets")
_MODELS_DIR = _resolve_dir("models")


def _load_xgboost() -> Any:
    try:
        from xgboost import XGBClassifier
        return XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )
    except ImportError:
        logger.warning("XGBoost not available, falling back to GradientBoosting")
        from sklearn.ensemble import GradientBoostingClassifier
        return GradientBoostingClassifier(
            n_estimators=200, max_depth=5, learning_rate=0.1, random_state=42
        )


def generate_synthetic_dataset(output_path: Path | None = None) -> pd.DataFrame:
    """
    Generate a synthetic training dataset from the rule patterns.
    Each rule contributes positive (vulnerable) and negative (safe) examples.
    """
    from vulnscanner.patterns.engine import PatternEngine

    records: list[dict[str, Any]] = []

    # Vulnerable examples (label=1)
    vuln_snippets = [
        # SQL injection
        ('cursor.execute("SELECT * FROM users WHERE id = " + user_id)', "python", 1),
        ('cursor.execute(f"SELECT * FROM users WHERE name = {name}")', "python", 1),
        ('db.query("SELECT * FROM orders WHERE id = " + req.query.id)', "javascript", 1),
        ('$pdo->query("SELECT * FROM users WHERE id = " . $_GET["id"])', "php", 1),
        # XSS
        ('return render_template_string("<h1>" + request.args["name"] + "</h1>")', "python", 1),
        ('document.getElementById("out").innerHTML = userInput;', "javascript", 1),
        ('echo $_GET["name"];', "php", 1),
        # Command injection
        ('os.system("ping " + user_input)', "python", 1),
        ('subprocess.run(f"ls {path}", shell=True)', "python", 1),
        ('exec("ls " + req.query.dir)', "javascript", 1),
        # Hardcoded secrets
        ('SECRET_KEY = "supersecretkey123"', "python", 1),
        ('const apiKey = "sk-abc123verysecret";', "javascript", 1),
        ('$password = "admin123";', "php", 1),
        # Weak crypto
        ('import hashlib; hashlib.md5(password.encode()).hexdigest()', "python", 1),
        ('MessageDigest.getInstance("MD5")', "java", 1),
        # SSRF
        ('requests.get(request.args["url"])', "python", 1),
        ('fetch(req.query.url)', "javascript", 1),
        # Insecure TLS
        ('requests.get(url, verify=False)', "python", 1),
        ('rejectUnauthorized: false', "javascript", 1),
        # JWT issues
        ('jwt.decode(token, options={"verify_signature": False})', "python", 1),
        ('jwt.sign(payload, "secret")', "javascript", 1),
        # Path traversal
        ('open(f"/uploads/{request.args[\'file\']}")', "python", 1),
        ('fs.readFile(req.query.filename)', "javascript", 1),
        # Debug mode
        ('app.run(debug=True)', "python", 1),
        ('DEBUG = True', "python", 1),
    ]

    # Safe examples (label=0)
    safe_snippets = [
        # Parameterised queries
        ('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))', "python", 0),
        ('db.query("SELECT * FROM orders WHERE id = ?", [req.query.id])', "javascript", 0),
        # Safe rendering
        ('return render_template("hello.html", name=name)', "python", 0),
        ('element.textContent = userInput;', "javascript", 0),
        # Safe subprocess
        ('subprocess.run(["ping", "-c", "1", host], check=True)', "python", 0),
        # Env-based secrets
        ('SECRET_KEY = os.environ["SECRET_KEY"]', "python", 0),
        ('const apiKey = process.env.API_KEY;', "javascript", 0),
        # Strong crypto
        ('import bcrypt; bcrypt.hashpw(password.encode(), bcrypt.gensalt())', "python", 0),
        ('MessageDigest.getInstance("SHA-256")', "java", 0),
        # Safe HTTP
        ('requests.get(url, verify=True, timeout=5)', "python", 0),
        # JWT with verification
        ('jwt.decode(token, public_key, algorithms=["RS256"])', "python", 0),
        # Safe file access
        ('target = (base / filename).resolve(); assert str(target).startswith(str(base))', "python", 0),
        # Production config
        ('DEBUG = False', "python", 0),
        ('app.run(debug=False)', "python", 0),
        # Generic safe code
        ('def calculate_total(items): return sum(item.price for item in items)', "python", 0),
        ('const result = arr.map(x => x * 2);', "javascript", 0),
        ('public int add(int a, int b) { return a + b; }', "java", 0),
    ]

    all_samples = vuln_snippets + safe_snippets
    extractor = FeatureExtractor()

    for code, lang, label in all_samples:
        fv = extractor.extract(code, lang)
        row = {name: val for name, val in zip(fv.feature_names(), fv.to_array())}
        row["code_snippet"] = code
        row["language"] = lang
        row["label"] = label
        records.append(row)

    df = pd.DataFrame(records)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
        logger.info(f"Synthetic dataset saved to {output_path} ({len(df)} samples)")

    return df


def train(data_path: Path | None = None, output_dir: Path | None = None) -> dict[str, Any]:
    """
    Full training pipeline. Returns metrics dict.
    """
    output_dir = output_dir or _MODELS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load or generate dataset
    if data_path and data_path.exists():
        logger.info(f"Loading dataset from {data_path}")
        df = pd.read_csv(data_path)
    else:
        logger.info("No dataset found — generating synthetic training data")
        synth_path = _DATASETS_DIR / "synthetic_training.csv"
        df = generate_synthetic_dataset(synth_path)

    extractor = FeatureExtractor()
    feature_names = FeatureVector_names = extractor.extract("x", "python").feature_names()

    # Build feature matrix
    if all(col in df.columns for col in feature_names):
        X = df[feature_names].values.astype(np.float32)
    else:
        # Re-extract features from code_snippet column
        pairs = list(zip(df["code_snippet"].tolist(), df["language"].tolist()))
        X = extractor.extract_batch(pairs)

    y = df["label"].values.astype(int)

    logger.info(f"Training on {len(X)} samples, {X.shape[1]} features")
    logger.info(f"Class distribution: {dict(zip(*np.unique(y, return_counts=True)))}")

    model = _load_xgboost()

    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring="roc_auc")
    logger.info(f"CV ROC-AUC: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

    # Final fit on all data
    model.fit(X, y)

    # Metrics on training set (for reporting)
    y_pred = model.predict(X)
    report = classification_report(y, y_pred, output_dict=True)
    auc = roc_auc_score(y, model.predict_proba(X)[:, 1])

    metrics = {
        "cv_roc_auc_mean": float(cv_scores.mean()),
        "cv_roc_auc_std": float(cv_scores.std()),
        "train_roc_auc": float(auc),
        "classification_report": report,
        "n_samples": len(X),
        "n_features": X.shape[1],
    }

    # Save model
    classifier = VulnClassifier.__new__(VulnClassifier)
    classifier.model_path = output_dir / "vuln_classifier.joblib"
    classifier.extractor = extractor
    classifier._model = None
    classifier._meta = {}
    classifier._shap_explainer = None

    meta = {
        "version": "xgb-v1.0",
        "n_samples": len(X),
        "cv_auc": float(cv_scores.mean()),
        "feature_names": feature_names,
    }
    classifier.save(model, meta)

    # Save metrics
    metrics_path = output_dir / "training_metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2))
    logger.info(f"Training complete. Metrics saved to {metrics_path}")

    return metrics
