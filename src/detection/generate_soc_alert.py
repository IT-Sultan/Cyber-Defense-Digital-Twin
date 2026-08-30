import pandas as pd
from pathlib import Path

DETECTIONS_FILE = Path("data/processed/apt41_detections.csv")
OUTPUT_FILE = Path("data/processed/apt41_soc_alert.csv")

print("[+] Loading detections...")

df = pd.read_csv(
    DETECTIONS_FILE,
    parse_dates=["@timestamp"]
)

df = df.sort_values("@timestamp").reset_index(drop=True)

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

# Calculate risk score
raw_score = df["severity_weight"].sum()

max_score = len(df) * 4

risk_score = round(
    (raw_score / max_score) * 100
)

# Multi-stage attack bonus
unique_stages = df["detected_tactic"].nunique()

if unique_stages >= 4:
    risk_score = min(100, risk_score + 15)

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