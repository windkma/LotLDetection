"""Fit the model on the stratified 90% training split."""
import hashlib
import json

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from tqdm import tqdm

from src.config import FEATURE_VERSION, N_ESTIMATORS, SEED, THRESHOLDS, paths
from src.data import load_train_test, save_training_dataset
from src.features.pipeline import MIN_LABELS_FOR_TRAINING
from src.models.predictor import make_pipeline


def train(platform="windows"):
    files = paths(platform)
    training, test = load_train_test(platform)
    pipeline = make_pipeline(platform)
    print(f"{platform}: train={len(training)} test={len(test)}")

    features, targets, source_rows, commands = [], [], [], []
    skipped = 0
    for source_index, command, target in tqdm(
        zip(training.index, training["commands"], training["label"]),
        total=len(training), desc="Features",
    ):
        labels = pipeline(str(command).strip(), training=True)
        if target == 1 and len(labels) < MIN_LABELS_FOR_TRAINING:
            skipped += 1
            continue
        features.append(" ".join(labels))
        targets.append(int(target))
        source_rows.append(int(source_index))
        commands.append(command)
    if set(targets) != {0, 1}:
        raise ValueError("Training features must retain samples of both classes.")
    print(f"Training samples: {len(targets)}; skipped BAD without features: {skipped}")
    vectorizer = CountVectorizer()
    matrix = vectorizer.fit_transform(features)
    save_training_dataset(
        files["training_dataset"], source_rows, commands, targets, matrix,
        vectorizer.get_feature_names_out(),
    )
    print(f"Saved training dataset: {files['training_dataset']} ({matrix.shape[0]} rows, {matrix.shape[1]} features)")
    classifier = RandomForestClassifier(
        n_estimators=N_ESTIMATORS, class_weight="balanced", random_state=SEED, n_jobs=-1,
    )
    classifier.fit(matrix, targets)

    files["models"].mkdir(parents=True, exist_ok=True)
    joblib.dump(classifier, files["models"] / "rf_classifier.joblib")
    joblib.dump(vectorizer, files["models"] / "vectorizer.joblib")
    config = {
        "platform": platform, "n_estimators": N_ESTIMATORS, "class_weight": "balanced",
        "feature_version": FEATURE_VERSION,
        "minimum_labels": MIN_LABELS_FOR_TRAINING,
        "random_state": SEED, "threshold": THRESHOLDS[platform],
        "split": {"train": 0.9, "test": 0.1, "method": "stratified_shuffle"},
        "dataset_sha256": hashlib.sha256(files["dataset"].read_bytes()).hexdigest(),
        "training_dataset_sha256": hashlib.sha256(files["training_dataset"].read_bytes()).hexdigest(),
        "corpus_sha256": hashlib.sha256(files["corpus"].read_bytes()).hexdigest(),
        "classifier_sha256": hashlib.sha256((files["models"] / "rf_classifier.joblib").read_bytes()).hexdigest(),
        "vectorizer_sha256": hashlib.sha256((files["models"] / "vectorizer.joblib").read_bytes()).hexdigest(),
        "total_features": len(vectorizer.vocabulary_), "training_samples": len(targets), "skipped_bad": skipped,
    }
    (files["models"] / "feature_config.json").write_text(
        json.dumps(config, indent=2), encoding="utf-8",
    )
    print(f"Saved model: {files['models']}")
    print(f"Run scripts/evaluate.py --platform {platform} to evaluate the held-out test.")
    return config
