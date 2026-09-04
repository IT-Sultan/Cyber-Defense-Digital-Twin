import pandas as pd
from pathlib import Path

DETECTIONS_FILE = Path("data/processed/apt41_detections.csv")
ML_FILE = Path("data/processed/ml_predictions.csv")
OUTPUT_FILE = Path("data/processed/apt41_soc_alert.csv")

print("[+] Loading detections...")

df = pd.read_csv(
    DETECTIONS_FILE,
    parse_dates=["@timestamp"]
)

df = df.sort_values("@timestamp").reset_index(drop=True)

# Load ML predictions and join using canonical event_id
ml_df = pd.read_csv(ML_FILE)

df = df.merge(
    ml_df[["event_id", "ml_score", "ml_label"]],
    on="event_id",
    how="left"
)

# Ensure every detection matched an ML event
missing_ml = df["ml_score"].isna().sum()

if missing_ml > 0:
    print(f"[!] Warning: {missing_ml} detections have no ML prediction")

# Severity weights
severity_weights = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

df["severity_weight"] = (
    df["severity"]
    .str.lower()
    .map(severity_weights)
    .fillna(1)
)

# Build attack stage sequence using DETECTED tactics only
stage_sequence = []

for tactic in df["detected_tactic"].dropna():

    tactic = str(tactic)

    if not stage_sequence or stage_sequence[-1] != tactic:
        stage_sequence.append(tactic)

# Base detection risk score
raw_score = df["severity_weight"].sum()

max_score = len(df) * 4

base_risk_score = round(
    (raw_score / max_score) * 100
)

# Multi-stage attack bonus
unique_stages = df["detected_tactic"].nunique()

stage_bonus = 15 if unique_stages >= 4 else 0

# ML contribution
# ml_score is a Relative Anomaly Score, not an attack probability.
ml_avg_score = df["ml_score"].dropna().mean()

if pd.isna(ml_avg_score):
    ml_avg_score = 0.0

# Keep ML influence limited to max 10 points
ml_bonus = round(ml_avg_score * 10)

# Final risk score
risk_score = min(
    100,
    base_risk_score + stage_bonus + ml_bonus
)

# Final severity
if risk_score >= 75:
    final_severity = "CRITICAL"
elif risk_score >= 50:
    final_severity = "HIGH"
elif risk_score >= 25:
    final_severity = "MEDIUM"
else:
    final_severity = "LOW"

host = (
    df["host"].dropna().iloc[0]
    if df["host"].notna().any()
    else "unknown"
)

alert = pd.DataFrame([
    {
        "alert_name": "APT41 Multi-Stage Attack Chain",
        "host": host,
        "start_time": df["@timestamp"].min(),
        "end_time": df["@timestamp"].max(),
        "correlated_events": len(df),
        "unique_attack_stages": unique_stages,
        "stage_sequence": " -> ".join(stage_sequence),
        "base_risk_score": base_risk_score,
        "stage_bonus": stage_bonus,
        "ml_avg_score": round(ml_avg_score, 4),
        "ml_bonus": ml_bonus,
        "risk_score": risk_score,
        "severity": final_severity
    }
])

alert.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\n=== SOC ALERT ===")

print(alert.to_string(index=False))

print(f"\n[+] Alert saved to: {OUTPUT_FILE}")