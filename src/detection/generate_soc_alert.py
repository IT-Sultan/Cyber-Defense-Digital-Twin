import pandas as pd
from pathlib import Path

CHAINS_FILE = Path("data/processed/apt41_correlated_chains.csv")
OUTPUT_FILE = Path("data/processed/apt41_soc_alert.csv")

print("[+] Loading correlated attack chains...")

chains_df = pd.read_csv(
    CHAINS_FILE,
    parse_dates=["start_time", "end_time"]
)

severity_weights = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

alerts = []

for _, chain in chains_df.iterrows():

    # Severity data passed from correlation
    severities_value = chain.get("severities", "")

    if pd.isna(severities_value):
        severities = []
    else:
        severities = [
            severity.strip().lower()
            for severity in str(severities_value).split(" -> ")
            if severity.strip()
        ]

    severity_score = sum(
        severity_weights.get(severity, 1)
        for severity in severities
    )

    max_score = len(severities) * 4

    base_risk_score = (
        round((severity_score / max_score) * 100)
        if max_score > 0
        else 0
    )

    # Multi-stage bonus
    unique_stages = int(chain.get("unique_attack_stages", 0))
    stage_bonus = 15 if unique_stages >= 4 else 0

    # ML contribution
    # Relative anomaly signal only, not attack probability
    ml_avg_score = float(chain.get("avg_ml_score", 0.0))
    ml_bonus = round(ml_avg_score * 10)

    risk_score = min(
        100,
        base_risk_score + stage_bonus + ml_bonus
    )

    if risk_score >= 75:
        final_severity = "CRITICAL"
    elif risk_score >= 50:
        final_severity = "HIGH"
    elif risk_score >= 25:
        final_severity = "MEDIUM"
    else:
        final_severity = "LOW"

    alerts.append({
        "alert_name": "Correlated Multi-Stage Attack Chain",
        "chain_id": chain["chain_id"],
        "host": chain["host"],
        "start_time": chain["start_time"],
        "end_time": chain["end_time"],
        "correlated_events": chain["event_count"],
        "unique_attack_stages": unique_stages,
        "stage_sequence": chain["stage_sequence"],
        "context": chain["context"],
        "base_risk_score": base_risk_score,
        "stage_bonus": stage_bonus,
        "ml_avg_score": round(ml_avg_score, 4),
        "anomaly_count": int(chain.get("anomaly_count", 0)),
        "anomaly_ratio": round(float(chain.get("anomaly_ratio", 0.0)), 4),
        "ml_bonus": ml_bonus,
        "risk_score": risk_score,
        "severity": final_severity
    })

alert_df = pd.DataFrame(alerts)

alert_df.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\n=== SOC ALERTS ===")
print(alert_df.to_string(index=False))

print(f"\n[+] Alerts generated: {len(alert_df)}")
print(f"[+] Alert saved to: {OUTPUT_FILE}")