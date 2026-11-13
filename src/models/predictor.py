"""Load a platform model and classify command strings without executing them."""
import joblib
import hashlib
import json
from io import BytesIO

from src.config import feature_version, paths
from src.models.integrity import verified_artifact_bytes
from src.preprocessing.normalizer import windows_analysis_views
from src.features.pipeline import (
    LABEL_LOOKS_LIKE_KNOWN_LOL, MIN_LABELS_FOR_TRAINING,
    LinuxFeaturePipeline, WindowsFeaturePipeline,
)


def make_pipeline(platform):
    corpus = str(paths(platform)["corpus"])
    pipeline = WindowsFeaturePipeline if platform == "windows" else LinuxFeaturePipeline
    return pipeline(corpus)


def determine_verdict(labels, probability, threshold):
    if len(labels) < MIN_LABELS_FOR_TRAINING and LABEL_LOOKS_LIKE_KNOWN_LOL not in labels:
        return "NEUTRAL"
    if LABEL_LOOKS_LIKE_KNOWN_LOL in labels or probability >= threshold:
        return "BAD"
    return "GOOD"


class LotLPredictor:
    def __init__(self, platform="windows"):
        model_dir = paths(platform)["models"]
        metadata = json.loads((model_dir / "feature_config.json").read_text(encoding="utf-8"))
        if metadata.get("feature_version") != feature_version(platform):
            raise ValueError(f"Feature rules changed. Run python scripts/train.py --platform {platform} before scanning.")
        if hashlib.sha256(paths(platform)["corpus"].read_bytes()).hexdigest() != metadata["corpus_sha256"]:
            raise ValueError("BLEU corpus changed. Retrain before scanning.")
        # Verify BOTH files before any deserialization; load the verified snapshots
        # so replacing a file after validation cannot bypass the checks.
        classifier_bytes = verified_artifact_bytes(
            model_dir / "rf_classifier.joblib", metadata.get("classifier_sha256"),
        )
        vectorizer_bytes = verified_artifact_bytes(
            model_dir / "vectorizer.joblib", metadata.get("vectorizer_sha256"),
        )
        self.platform = platform
        self.threshold = metadata["threshold"]
        self._classifier = joblib.load(BytesIO(classifier_bytes))
        self._classifier.verbose = 0
        self._vectorizer = joblib.load(BytesIO(vectorizer_bytes))
        self._bad_index = list(self._classifier.classes_).index(1)
        self._pipeline = make_pipeline(platform)

    def predict(self, command):
        return self.predict_batch([command])[0]

    def predict_batch(self, commands):
        commands = list(commands)
        results = []
        for start in range(0, len(commands), 1000):
            batch = [str(command).strip() for command in commands[start:start + 1000]]
            labels_list = [self._pipeline(command) for command in batch]
            matrix = self._vectorizer.transform([" ".join(labels) for labels in labels_list])
            scores = self._classifier.predict_proba(matrix)[:, self._bad_index]
            for command, labels, score in zip(batch, labels_list, scores):
                results.append({
                    "command": command,
                    "verdict": determine_verdict(labels, score, self.threshold),
                    "probability": round(float(score), 4),
                    "labels": labels,
                    "normalized_commands": list(windows_analysis_views(command)[1:]) if self.platform == "windows" else [],
                })
        return results
