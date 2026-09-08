# Supervised Machine Learning Pipeline

## Overview
This module implements a supervised **Random Forest Classifier** designed to distinguish malicious APT41 activity from benign system operations using real Linux `auditd` telemetry.

---

## Behavioral Feature Engineering
Features are engineered strictly from runtime process behavior to prevent any source or file-based data leakage:

* **`cmd_length`**: Total character length of the executed command string.
* **`entropy`**: Shannon Entropy of the command line to capture payload obfuscation and Base64-encoded strings.
* **`special_char_count`**: Count of shell chaining and redirection operators (`;`, `|`, `&`, `>`, `<`, `` ` ``, `$`).
* **`is_sensitive_path`**: Boolean flag indicating interactions with sensitive targets (e.g., `/etc/shadow`, `/tmp`, `LinEnum`).
* **`is_attack_tool`**: Boolean flag indicating high-risk utility execution (e.g., `curl`, `openssl`, `xxd`, `crontab`, `nc`).
* **`argc`**: Argument count associated with the execution.
* **`a0_freq`**: Normalized execution frequency of the primary binary (`a0`), fit strictly on training splits.

---

## Validation Strategy: Class-Wise Temporal Split
To guarantee robust evaluation without temporal leakage:
* Attack logs and Benign `auditd` telemetry are independently sorted chronologically via `@timestamp`.
* A **70/30 Out-Of-Time (OOT)** split is applied class-wise (`Train: 42`, `Test: 19`).
* Frequency encoding is isolated strictly within the training set to prevent look-ahead bias.

---

## Evaluation Metrics (Test Set)
* **Attack Precision**: 0.93
* **Attack Recall**: 1.00 (Zero false negatives on prospective attack activity)
* **F1-Score**: 0.97
* **ROC-AUC Score**: 0.9857

---

## Pipeline & Artifact Integration
* Generates canonical inference outputs at `data/processed/ml_predictions.csv`.
* Retains canonical integer `event_id` mapping for end-to-end alignment with the Correlation Engine and SOC Alerting pipeline.