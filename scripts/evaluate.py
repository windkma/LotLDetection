"""Evaluate the fixed held-out test split using the same predictor as scan."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.data import load_train_test
from src.evaluation import report
from src.models.predictor import LotLPredictor


def main():
    parser = argparse.ArgumentParser(description="Evaluate LotlDetection on test data")
    parser.add_argument("--platform", choices=["windows", "linux"], default="windows")
    args = parser.parse_args()
    _, test = load_train_test(args.platform)
    predictor = LotLPredictor(args.platform)
    print(f"Test [{args.platform}]: {len(test)} samples")
    report(test["label"], predictor.predict_batch(test["commands"]))


if __name__ == "__main__":
    main()
