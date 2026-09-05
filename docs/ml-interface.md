# ML Integration Contract

This document defines the interface between the Machine Learning component and the Cyber Defense Digital Twin security pipeline.

The goal is to allow the ML model to evolve without breaking detection, correlation, risk scoring, or the SOC dashboard.

---

## ML Input

The ML module consumes cleaned cybersecurity events produced by the preprocessing stage.

The processed input follows the configured dataset slug:

```text
data/processed/{DATASET_SLUG}_clean.csv
```

Default:

```text
data/processed/apt41_clean.csv
```

The dataset slug can be changed using:

```bash
export CYBER_DATASET_SLUG=my_campaign
```

The ML module must not modify the cleaned source dataset.

---

## Required ML Output

The ML module must produce one prediction record per input event.

Required fields:

```text
event_id
@timestamp
host
ml_score
ml_label
model_name
```

### event_id

Must preserve the canonical `event_id` generated during preprocessing.

This field is used to join ML predictions with:

- Detection Engine
- Event Correlation
- SOC Alerts
- SOC Dashboard

The ML module must not generate independent event IDs when canonical IDs are available.

### ml_score

Numeric anomaly or model score.

For the current pipeline:

```text
0.0 <= ml_score <= 1.0
```

The current score represents relative anomaly context and must not be treated as a calibrated probability of malicious activity.

### ml_label

Human-readable model classification.

Current baseline examples:

```text
Anomaly
Inlier / Normal-like
```

### model_name

Identifies the model that produced the prediction.

Example:

```text
IsolationForest
```

---

## Expected Output File

ML predictions must be written to:

```text
data/processed/ml_predictions.csv
```

The rest of the security pipeline expects this output contract to remain stable whenever possible.

---

## Important ML Rules

The ML model must not use ground-truth security labels as predictive features.

The following fields must not be used as model input features:

```text
technique
tactic
```

These fields may be used for:

- Evaluation
- Analysis
- Visualization
- Ground-truth comparison

They must not create feature leakage into the model.

Other fields that directly reveal attack ground truth should also be excluded from predictive features.

---

## Current Baseline

The current implementation uses:

```text
Isolation Forest
```

It is currently used as a relative anomaly baseline.

The current development dataset contains simulated attack activity and does not include a proper benign / normal traffic baseline.

Therefore:

> The current ML component is not an Attack-vs-Benign classifier.

An anomalous event is only unusual relative to the other events observed in the current dataset.

---

## Integration Flow

```text
Clean Cybersecurity Events
          |
          v
      ML Model
          |
          v
   ml_predictions.csv
          |
          | canonical event_id
          v
   Detection Context
          |
          v
   Event Correlation
          |
          v
     SOC Risk Score
          |
          v
      SOC Alert
          |
          v
    SOC Dashboard
```

ML is used as additional security context.

It is not the sole source of an alert or risk decision.

---

## Risk Integration

The SOC risk engine combines:

```text
Rule-Based Detection Evidence
            +
Multi-Stage Attack Context
            +
Limited ML Anomaly Context
            =
Final SOC Risk Score
```

The ML contribution is intentionally limited so anomalous model output cannot dominate stronger cybersecurity evidence.

---

## Pipeline Validation

The validation stage verifies ML integration integrity.

Current ML-related checks include:

- ML output exists
- Required ML columns exist
- ML event IDs are unique
- ML event IDs match canonical events
- ML coverage is complete
- Every detection has a corresponding ML prediction
- ML scores remain within the expected range

A critical validation failure causes the pipeline to fail.

---

## Next ML Phase

Future ML development should focus on:

1. Adding benign / normal cybersecurity telemetry
2. Improving security-specific feature engineering
3. Preventing feature leakage
4. Comparing multiple anomaly detection approaches
5. Evaluating supervised models when appropriate labeled data is available
6. Using time-aware train / validation / test splits when appropriate
7. Measuring SOC-oriented performance
8. Reducing operational false positives
9. Preserving the existing ML output interface

Recommended evaluation metrics include:

```text
Precision
Recall
F1 Score
PR-AUC
False Positives per Hour / Day
```

Accuracy alone should not be the primary evaluation metric for imbalanced cybersecurity datasets.

---

## Handoff Requirement

Future ML implementations should continue producing:

```text
event_id
@timestamp
host
ml_score
ml_label
model_name
```

If the ML output contract needs to change, the change should be coordinated with the cybersecurity pipeline because correlation, validation, risk scoring, and the dashboard depend on these fields.