# Cyber Defense Digital Twin

AI-assisted cybersecurity platform for threat detection, event correlation, attack analysis, anomaly detection, and SOC decision support.

The project combines cybersecurity detection engineering with machine learning to transform raw security telemetry into correlated, explainable, and prioritized SOC alerts.

---

## Project Goal

The goal of the Cyber Defense Digital Twin is to build a prototype SOC platform capable of analyzing cybersecurity telemetry and reconstructing suspicious activity across multiple stages of an attack.

Instead of showing isolated alerts only, the system attempts to provide an analyst with enough context to understand:

- What happened
- Which events are related
- Which host is affected
- Which MITRE ATT&CK stages were observed
- How anomalous the activity appears
- Why the alert received its risk score
- What the analyst should investigate next

The platform is designed as analyst decision support.

It does not automatically isolate hosts, block traffic, rotate credentials, or perform containment actions.

---

## MVP Capabilities

The current MVP supports:

- Cybersecurity telemetry preprocessing
- Canonical event ID generation
- Attack timeline generation
- Rule-based threat detection
- MITRE ATT&CK mapping
- Event correlation
- Multi-stage attack-chain construction
- Machine learning anomaly scoring
- Attack graph generation
- SOC risk scoring
- Explainable risk reasons
- Recommended analyst actions
- Alert prioritization
- Automated pipeline integrity validation
- Interactive Streamlit SOC dashboard

---

## Architecture

```text
                 Raw Cybersecurity Events
                           |
                           v
                  Data Preprocessing
                           |
              +------------+------------+
              |                         |
              v                         v
       Attack Timeline             ML Baseline
              |                         |
              v                         |
       MITRE ATT&CK Summary             |
              |                         |
              v                         |
         Attack Graph                   |
                                        |
                 Detection Engine <-----+
                        |
                        v
                Event Correlation
                        |
                        v
              Correlated Attack Chain
                        |
                        v
                  SOC Risk Scoring
                        |
                        v
                    SOC Alert
                        |
                        v
                  SOC Dashboard

                        +
                        |
                        v
              Pipeline Validation
```

---

## Project Structure

```text
Cyber-Defense-Digital-Twin/
│
├── dashboard/
│   ├── app.py
│   └── README.md
│
├── data/
│   ├── raw/
│   └── processed/
│
├── docs/
│   ├── architecture.md
│   ├── ml-interface.md
│   ├── mvp.md
│   └── team-roles.md
│
├── notebooks/
│
├── src/
│   ├── attack_graph/
│   │   ├── build_attack_graph.py
│   │   └── visualize_attack_graph.py
│   │
│   ├── correlation/
│   │   ├── build_timeline.py
│   │   └── context_correlator.py
│   │
│   ├── detection/
│   │   ├── detection_engine.py
│   │   ├── evaluate_detections.py
│   │   └── generate_soc_alert.py
│   │
│   ├── mitre/
│   │   └── build_mitre_summary.py
│   │
│   ├── ml/
│   │   └── baseline_model.py
│   │
│   ├── preprocessing/
│   │   ├── clean_events.py
│   │   └── inspect_dataset.py
│   │
│   └── validation/
│       └── validate_pipeline.py
│
├── requirements.txt
├── run_pipeline.py
└── README.md
```

---

## Quick Start

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Run the complete security pipeline:

```bash
python run_pipeline.py
```

A successful execution should finish with:

```text
PIPELINE VALIDATION PASSED
PIPELINE COMPLETED SUCCESSFULLY
```

Launch the SOC dashboard:

```bash
streamlit run dashboard/app.py
```

---

## Pipeline Stages

`run_pipeline.py` executes the security workflow in the following order:

```text
1. Data Cleaning
2. ML Baseline
3. Attack Timeline
4. MITRE Summary
5. Detection Engine
6. Context Correlation
7. Attack Graph Builder
8. Attack Graph Visualization
9. SOC Alert Generation
10. Pipeline Validation
```

If one of the pipeline stages fails, execution stops and reports the failed stage.

---

## Dataset Configuration

The pipeline is designed so processed file paths are not permanently tied to one campaign.

The default dataset slug is:

```text
apt41
```

The default raw dataset is:

```text
data/raw/cyber/APT41-Campaign-1-logs.csv
```

APT41 is kept as the default for backward compatibility.

The dataset can be changed through environment variables.

Example:

```bash
export CYBER_DATASET_SLUG=my_campaign
export CYBER_RAW_FILE=data/raw/cyber/my_campaign.csv

python run_pipeline.py
```

`CYBER_DATASET_SLUG` controls the generated processed filenames.

For example:

```text
my_campaign_clean.csv
my_campaign_timeline.csv
my_campaign_detections.csv
my_campaign_correlated_chains.csv
my_campaign_soc_alert.csv
```

`CYBER_RAW_FILE` controls the source telemetry file used by preprocessing.

This allows compatible cybersecurity datasets to use the same pipeline without modifying internal file paths.

---

## Current Development Dataset

The initial development and validation scenario uses an APT41 campaign dataset.

The current sample contains simulated attack activity and is used to validate the complete end-to-end security architecture.

The current dataset does not contain a proper benign or normal traffic baseline.

This limitation is especially important when interpreting the machine learning output.

---

## Main Pipeline Outputs

Processed artifacts are stored under:

```text
data/processed/
```

Using the default `apt41` dataset slug, the pipeline generates:

```text
apt41_clean.csv
apt41_timeline.csv
apt41_mitre_summary.csv
apt41_detections.csv
apt41_correlated_chains.csv
apt41_graph_nodes.csv
apt41_graph_edges.csv
apt41_soc_alert.csv
ml_predictions.csv
```

The attack graph visualization is stored under:

```text
docs/apt41_attack_graph.png
```

The attack graph filename follows the configured dataset slug.

---

## Canonical Event IDs

A canonical `event_id` is assigned during preprocessing.

The same event ID is preserved across:

```text
Clean Dataset
      |
      v
Attack Timeline
      |
      +------> Detection Engine
      |
      +------> ML Predictions
                     |
                     v
               Correlation
                     |
                     v
                 SOC Alert
                     |
                     v
                 Dashboard
```

This allows the same security event to be traced consistently through the complete pipeline.

Pipeline validation checks that event IDs remain consistent between pipeline components.

---

## Detection Engine

The detection engine applies rule-based security logic to cleaned telemetry.

Current detections include behavior such as:

- Remote file downloads
- Persistence activity
- Sensitive account or credential file access
- Masquerading behavior
- Network configuration discovery
- File encryption activity

Each detection contains security context including fields such as:

```text
event_id
timestamp
host
rule name
severity
command
detected technique
```

Detection results are later enriched with machine learning and correlation context.

---

## MITRE ATT&CK

Telemetry is mapped to MITRE ATT&CK tactics and techniques.

The system uses ATT&CK context to help reconstruct the attack path and identify multi-stage activity.

Examples of observed stages in the current scenario include:

```text
Initial Access
Execution
Persistence
Privilege Escalation
Defense Evasion
Credential Access
Discovery
Lateral Movement
Collection
Impact
```

MITRE context is used for analysis and visualization.

Ground-truth MITRE labels are not intended to be used as ML prediction features.

---

## Event Correlation

Individual detections are correlated into attack chains.

Correlation uses contextual information such as:

- Host
- Event timing
- Detection rules
- MITRE stages
- Canonical event IDs
- ML anomaly scores

A correlated chain contains information including:

```text
chain_id
host
event_count
event_ids
rules
context
stage_sequence
unique_attack_stages
average ML score
anomaly count
anomaly ratio
```

This allows the system to move from isolated alerts toward multi-stage attack analysis.

---

## Attack Graph

The attack graph reconstructs ATT&CK activity as connected stages.

Graph nodes represent tactic and technique combinations.

Graph edges represent chronological transitions between observed attack stages.

The generated visualization provides a high-level view of the attack path and is displayed inside the SOC dashboard.

---

## Machine Learning Baseline

The current ML component uses:

```text
Isolation Forest
```

The model currently acts as a relative anomaly baseline.

The ML output interface includes:

```text
event_id
@timestamp
host
ml_score
ml_label
model_name
```

Predictions are stored in:

```text
data/processed/ml_predictions.csv
```

ML predictions are joined with security detections using the canonical `event_id`.

---

## Important ML Limitation

The current dataset contains attack activity without a proper benign or normal traffic baseline.

Therefore:

> The current ML model is a relative anomaly baseline, not an Attack-vs-Benign classifier.

An anomaly score means that an event appears unusual relative to other events in the current dataset.

It must not be interpreted as a calibrated probability that an event is malicious.

For this reason, the ML contribution to SOC risk scoring is intentionally limited.

Rule-based security evidence and multi-stage attack context remain the primary risk factors.

---

## SOC Risk Scoring

SOC alerts combine several signals.

```text
Detection Severity
        +
Multi-Stage Attack Context
        +
Limited ML Anomaly Context
        =
Final SOC Risk Score
```

The current scoring model considers:

- Detection severity
- Number of attack stages
- Attack-chain context
- Average ML anomaly score
- Anomaly concentration
- Persistence activity
- Credential-access activity
- Impact or encryption activity

Risk scores are bounded between:

```text
0 - 100
```

---

## Explainable Risk

The platform does not output only a numeric score.

Each SOC alert also includes reason codes and human-readable explanations describing why the alert received its risk level.

Example reason codes include:

```text
ELEVATED_DETECTION_SEVERITY
MULTI_STAGE_ATTACK
HIGH_ANOMALY_RATIO
PERSISTENCE_ACTIVITY
CREDENTIAL_ACCESS
IMPACT_ACTIVITY
```

This makes the risk score easier for an analyst to understand and investigate.

---

## Recommended Analyst Actions

SOC alerts can provide recommended investigation actions.

Examples include:

- Prioritize analyst investigation
- Review the affected host
- Preserve relevant evidence
- Investigate encryption or destructive activity
- Review credential access
- Identify potentially exposed accounts
- Inspect persistence mechanisms
- Expand threat hunting around related hosts, users, IP addresses, and timestamps
- Review high-scoring anomalous events

These recommendations are advisory only.

The system does not automatically execute containment actions.

---

## SOC Dashboard

The Streamlit dashboard provides an analyst-focused interface for pipeline results.

Current dashboard capabilities include:

- Prioritized Alert Queue
- Active alert selection
- Risk Score
- Alert severity
- Host information
- Correlated event count
- MITRE ATT&CK stage count
- ML anomaly ratio
- Risk summary
- Risk reason codes
- Recommended analyst actions
- Risk components
- Correlated attack-chain information
- Detection severity distribution
- Detection event table
- ML prediction analysis
- MITRE tactic distribution
- Attack timeline
- Attack graph visualization
- Pipeline data-source health indicators

When multiple alerts exist, the dashboard can select an active alert and filter detection and ML information using the correlated event IDs belonging to that chain.

---

## Alert Queue

The dashboard contains a prioritized SOC Alert Queue.

Alerts are ordered by risk score so analysts can investigate higher-risk activity first.

Queue information includes:

```text
Priority
Chain ID
Severity
Risk Score
Host
Event Count
MITRE Stage Count
Anomaly Ratio
```

---

## Pipeline Validation

The final stage of the workflow runs automated integrity checks.

Validation verifies:

- Required pipeline output files exist
- Required columns are present
- Clean event IDs are valid
- Event IDs are unique
- Timeline IDs match canonical event IDs
- ML event IDs are unique
- ML coverage is complete
- Every detection has an ML prediction
- Detections reference valid canonical events
- ML scores remain within the expected range
- Correlated chain event counts are correct
- Chains contain no duplicate event IDs
- Chain events reference valid detections
- SOC alerts reference existing attack chains
- Risk scores remain between 0 and 100
- SOC alert event counts match correlated chains

Successful validation ends with:

```text
PIPELINE VALIDATION PASSED
```

The full pipeline then finishes with:

```text
PIPELINE COMPLETED SUCCESSFULLY
```

---

## Team Responsibilities

### Cybersecurity / SOC

Primary responsibilities include:

- Cybersecurity data exploration
- Data preprocessing and cleaning
- Detection engineering
- Event correlation
- MITRE ATT&CK integration
- Attack graph design
- SOC risk scoring
- Risk explanations
- Analyst recommendations
- Pipeline integration
- Pipeline validation
- SOC dashboard integration

### Machine Learning

Primary responsibilities include:

- Dataset analysis
- Feature engineering
- ML model development
- Anomaly detection
- Model evaluation
- Model comparison
- Model improvement

---

## ML Integration Contract

The cybersecurity pipeline expects ML predictions to preserve the existing interface.

Expected fields include:

```text
event_id
@timestamp
host
ml_score
ml_label
model_name
```

The complete interface is documented in:

```text
docs/ml-interface.md
```

Future ML changes should preserve this output contract whenever possible so the detection, correlation, risk, and dashboard layers do not require unnecessary changes.

---

## ML Handoff / Next Phase

The cybersecurity MVP architecture and the ML integration layer are now ready for continued model development.

The next ML phase should focus on:

1. Adding benign and normal cybersecurity telemetry
2. Building stronger security-specific features
3. Preventing feature leakage from MITRE labels or other ground-truth information
4. Testing additional anomaly detection approaches
5. Evaluating supervised classification when appropriate labeled data becomes available
6. Using time-aware train, validation, and test splits when appropriate
7. Comparing models using SOC-oriented metrics
8. Measuring operational false-positive rates
9. Preserving the existing ML output interface

Recommended evaluation metrics include:

```text
Precision
Recall
F1 Score
PR-AUC
False Positives per Hour / Day
```

Accuracy alone should not be treated as the primary metric for imbalanced cybersecurity data.

---

## Current MVP Status

The cybersecurity MVP is operational end-to-end.

```text
Raw Telemetry
      |
      v
Preprocessing
      |
      +----------+
      |          |
      v          v
 Detection      ML
      |          |
      +-----+----+
            |
            v
       Correlation
            |
            v
      Attack Context
            |
            v
       Risk Scoring
            |
            v
         SOC Alert
            |
            v
      SOC Dashboard
            |
            v
        Validation
```

The current platform successfully connects cybersecurity detection, MITRE ATT&CK context, event correlation, anomaly analysis, attack visualization, SOC risk scoring, and analyst-facing alert presentation.

The next major development phase is improving the machine learning component using datasets containing both malicious and benign activity.