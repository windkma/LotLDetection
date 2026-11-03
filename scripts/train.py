"""Train a Windows or Linux model."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.models.trainer import train


def main():
    parser = argparse.ArgumentParser(description="Train LotlDetection")
    parser.add_argument("--platform", choices=["windows", "linux"], default="windows")
    args = parser.parse_args()
    train(args.platform)


if __name__ == "__main__":
    main()
