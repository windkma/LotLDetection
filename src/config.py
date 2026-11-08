"""Fixed experiment settings; CLI users only select the platform."""
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SEED = 42
# PHẦN BỔ SUNG 2026-11-08: chuẩn hóa toàn bộ nhãn, gộp ADDED_* và BIN_* thành COMMAND_* và regex ngữ nghĩa.
FEATURE_VERSION = "lotldetection-symbolic-unified-v13"
N_ESTIMATORS = 100
THRESHOLDS = {"windows": 0.35, "linux": 0.60}


def paths(platform):
    if platform not in THRESHOLDS:
        raise ValueError("Platform must be 'windows' or 'linux'.")
    corpus = "cmd_known.corpus" if platform == "windows" else "bash_known.corpus"
    return {
        "dataset": PROJECT_ROOT / "data" / "raw" / f"{platform}.csv",
        "training_dataset": PROJECT_ROOT / "data" / "features" / platform / "train.csv",
        "corpus": PROJECT_ROOT / "data" / "external" / corpus,
        "models": PROJECT_ROOT / "models" / platform,
    }
