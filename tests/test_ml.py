"""
Tests for ML feature extraction, classification, and training pipeline.
"""

from __future__ import annotations

import numpy as np
import pytest

from vulnscanner.ml.features import FeatureExtractor, FeatureVector
from vulnscanner.ml.classifier import VulnClassifier, LABEL_VULNERABLE, LABEL_SAFE


class TestFeatureExtractor:
    def setup_method(self):
        self.extractor = FeatureExtractor()

    def test_returns_feature_vector(self):
        fv = self.extractor.extract("x = 1", "python")
        assert isinstance(fv, FeatureVector)

    def test_to_array_correct_length(self):
        fv = self.extractor.extract("x = 1", "python")
        arr = fv.to_array()
        assert arr.shape == (len(FeatureVector.feature_names()),)

    def test_feature_names_match_array_length(self):
        names = FeatureVector.feature_names()
        fv = self.extractor.extract("x = 1", "python")
        assert len(names) == len(fv.to_array())

    def test_detects_sql_keyword(self):
        fv = self.extractor.extract('cursor.execute("SELECT * FROM users")', "python")
        assert fv.has_sql_keyword == 1

    def test_detects_user_input(self):
        fv = self.extractor.extract('name = request.args["name"]', "python")
        assert fv.has_user_input == 1

    def test_detects_concat_pattern(self):
        fv = self.extractor.extract('"SELECT * FROM users WHERE id = " + user_id', "python")
        assert fv.concat_pattern_count >= 1

    def test_detects_hardcoded_string(self):
        fv = self.extractor.extract('SECRET_KEY = "supersecretkey123"', "python")
        assert fv.has_hardcoded_string == 1

    def test_detects_shell_keyword(self):
        fv = self.extractor.extract('os.system("ping " + host)', "python")
        assert fv.has_shell_keyword == 1

    def test_detects_crypto_keyword(self):
        fv = self.extractor.extract('hashlib.md5(password.encode())', "python")
        assert fv.has_crypto_keyword == 1

    def test_detects_network_keyword(self):
        fv = self.extractor.extract('requests.get(url)', "python")
        assert fv.has_network_keyword == 1

    def test_safe_code_low_score(self):
        fv = self.extractor.extract('def add(a, b): return a + b', "python")
        assert fv.has_user_input == 0
        assert fv.has_sql_keyword == 0
        assert fv.concat_pattern_count == 0
        assert fv.dangerous_func_count == 0

    def test_extract_batch(self):
        snippets = [
            ('cursor.execute("SELECT * FROM users WHERE id = " + uid)', "python"),
            ('def add(a, b): return a + b', "python"),
        ]
        X = self.extractor.extract_batch(snippets)
        assert X.shape == (2, len(FeatureVector.feature_names()))
        assert X.dtype == np.float32

    def test_line_count_correct(self):
        code = "line1\nline2\nline3"
        fv = self.extractor.extract(code, "python")
        assert fv.line_count == 3

    def test_string_density(self):
        fv = self.extractor.extract('"hello" "world" "test"', "python")
        assert fv.string_literal_count >= 2
        assert fv.string_density > 0


class TestVulnClassifier:
    def setup_method(self):
        self.clf = VulnClassifier()

    def test_predict_returns_label_and_confidence(self):
        label, conf = self.clf.predict("x = 1", "python")
        assert label in (0, 1)
        assert 0.0 <= conf <= 1.0

    def test_sqli_classified_vulnerable(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        label, conf = self.clf.predict(code, "python")
        assert label == LABEL_VULNERABLE
        assert conf >= 0.4

    def test_safe_code_classified_safe(self):
        code = 'def calculate_total(items): return sum(item.price for item in items)'
        label, conf = self.clf.predict(code, "python")
        assert label == LABEL_SAFE

    def test_hardcoded_secret_vulnerable(self):
        code = 'SECRET_KEY = "supersecretkey123abc"'
        label, conf = self.clf.predict(code, "python")
        assert label == LABEL_VULNERABLE

    def test_command_injection_vulnerable(self):
        code = 'os.system(f"ping {host}")'
        label, conf = self.clf.predict(code, "python")
        assert label == LABEL_VULNERABLE

    def test_top_features_returns_list(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        feats = self.clf.top_features(code, "python")
        assert isinstance(feats, list)
        assert len(feats) <= 5
        assert all(isinstance(name, str) and isinstance(val, float) for name, val in feats)

    def test_explain_returns_dict(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        importance = self.clf.explain(code, "python")
        assert isinstance(importance, dict)
        assert len(importance) == len(FeatureVector.feature_names())

    def test_model_version_string(self):
        assert isinstance(self.clf.model_version, str)
        assert len(self.clf.model_version) > 0

    def test_confidence_in_range(self):
        snippets = [
            ('cursor.execute("SELECT * FROM users WHERE id = " + uid)', "python"),
            ('requests.get(request.args["url"])', "python"),
            ('SECRET_KEY = "hardcodedsecret"', "python"),
            ('def add(a, b): return a + b', "python"),
        ]
        for code, lang in snippets:
            _, conf = self.clf.predict(code, lang)
            assert 0.0 <= conf <= 1.0, f"Confidence out of range for: {code[:40]}"


class TestTrainingPipeline:
    def test_generate_synthetic_dataset(self, tmp_path):
        from vulnscanner.ml.trainer import generate_synthetic_dataset
        df = generate_synthetic_dataset(tmp_path / "test_data.csv")
        assert len(df) >= 30
        assert "code_snippet" in df.columns
        assert "label" in df.columns
        assert "language" in df.columns
        assert set(df["label"].unique()).issubset({0, 1})

    def test_dataset_has_both_classes(self, tmp_path):
        from vulnscanner.ml.trainer import generate_synthetic_dataset
        df = generate_synthetic_dataset()
        assert 0 in df["label"].values
        assert 1 in df["label"].values

    def test_train_returns_metrics(self, tmp_path):
        from vulnscanner.ml.trainer import train
        metrics = train(output_dir=tmp_path)
        assert "cv_roc_auc_mean" in metrics
        assert "train_roc_auc" in metrics
        assert "n_samples" in metrics
        assert 0.0 <= metrics["cv_roc_auc_mean"] <= 1.0
        assert metrics["n_samples"] >= 30

    def test_trained_model_saved(self, tmp_path):
        from vulnscanner.ml.trainer import train
        train(output_dir=tmp_path)
        assert (tmp_path / "vuln_classifier.joblib").exists()
        assert (tmp_path / "model_meta.json").exists()

    def test_trained_model_loadable(self, tmp_path):
        from vulnscanner.ml.trainer import train
        train(output_dir=tmp_path)
        clf = VulnClassifier(model_path=tmp_path / "vuln_classifier.joblib")
        label, conf = clf.predict('cursor.execute("SELECT * FROM users WHERE id = " + uid)', "python")
        assert label in (0, 1)
        assert 0.0 <= conf <= 1.0
