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
    parser.add_argument("--split", choices=["train", "test"], default="test")
    args = parser.parse_args()
    train_df, test_df = load_train_test(args.platform)
    dataset = train_df if args.split == "train" else test_df
    predictor = LotLPredictor(args.platform)
    print(f"{args.split.capitalize()} [{args.platform}]: {len(dataset)} samples")
    report(dataset["label"], predictor.predict_batch(dataset["commands"]))


if __name__ == "__main__":
    main()
