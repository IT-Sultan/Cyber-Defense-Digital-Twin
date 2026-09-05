import pandas as pd
from pathlib import Path
import os
DATASET_SLUG = os.getenv("CYBER_DATASET_SLUG", "apt41")

CHAINS_FILE = Path(f"data/processed/{DATASET_SLUG}_correlated_chains.csv")
OUTPUT_FILE = Path(f"data/processed/{DATASET_SLUG}_soc_alert.csv")

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

    # ML context
    ml_avg_score = chain.get("avg_ml_score", 0.0)

    if pd.isna(ml_avg_score):
        ml_avg_score = 0.0

    ml_avg_score = float(ml_avg_score)

    anomaly_count = chain.get("anomaly_count", 0)

    if pd.isna(anomaly_count):
        anomaly_count = 0

    anomaly_count = int(anomaly_count)

    anomaly_ratio = chain.get("anomaly_ratio", 0.0)

    if pd.isna(anomaly_ratio):
        anomaly_ratio = 0.0

    anomaly_ratio = float(anomaly_ratio)

    # Relative anomaly signal only, not attack probability
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

    # Risk explanation
    reason_codes = []
    risk_reasons = []

    if base_risk_score >= 65:
        reason_codes.append("ELEVATED_DETECTION_SEVERITY")
        risk_reasons.append(
            f"Elevated detection severity profile ({base_risk_score}/100)"
        )

    if unique_stages >= 4:
        reason_codes.append("MULTI_STAGE_ATTACK")
        risk_reasons.append(
            f"Multi-stage attack observed across {unique_stages} tactics"
        )

    if anomaly_ratio >= 0.75:
        reason_codes.append("HIGH_ANOMALY_RATIO")
        risk_reasons.append(
            f"High anomaly concentration ({anomaly_ratio:.1%} of correlated detections)"
        )

    context = str(chain.get("context", ""))

    if "Possible persistence chain" in context:
        reason_codes.append("PERSISTENCE_ACTIVITY")
        risk_reasons.append("Persistence activity observed")

    if "Credential access activity" in context:
        reason_codes.append("CREDENTIAL_ACCESS")
        risk_reasons.append("Credential access activity observed")

    if "Impact / encryption activity" in context:
        reason_codes.append("IMPACT_ACTIVITY")
        risk_reasons.append("Impact or encryption activity observed")

    if not risk_reasons:
        reason_codes.append("SUSPICIOUS_CORRELATED_ACTIVITY")
        risk_reasons.append("Suspicious correlated activity observed")

    risk_summary = (
        f"{final_severity} risk ({risk_score}/100): "
        + "; ".join(risk_reasons)
    )

    # Recommended analyst actions
    recommended_actions = []

    if final_severity == "CRITICAL":
        recommended_actions.append(
            "Prioritize immediate analyst investigation of this host"
        )

    if "IMPACT_ACTIVITY" in reason_codes:
        recommended_actions.append(
            "Consider isolating the affected host after preserving relevant evidence"
        )
        recommended_actions.append(
            "Determine the scope of encryption or destructive activity"
        )

    if "CREDENTIAL_ACCESS" in reason_codes:
        recommended_actions.append(
            "Review credential access activity and identify potentially exposed accounts"
        )
        recommended_actions.append(
            "Consider credential rotation after validating exposure"
        )

    if "PERSISTENCE_ACTIVITY" in reason_codes:
        recommended_actions.append(
            "Inspect persistence mechanisms such as cron jobs and startup configuration"
        )

    if "MULTI_STAGE_ATTACK" in reason_codes:
        recommended_actions.append(
            "Expand threat hunting around the host, user, IP addresses, and attack time window"
        )

    if "HIGH_ANOMALY_RATIO" in reason_codes:
        recommended_actions.append(
            "Review the highest-scoring anomalous events for additional context"
        )

    if not recommended_actions:
        recommended_actions.append(
            "Review correlated events and validate whether escalation is required"
        )

    alerts.append({
        "alert_name": "Correlated Multi-Stage Attack Chain",
        "chain_id": chain["chain_id"],
        "host": chain["host"],
        "start_time": chain["start_time"],
        "end_time": chain["end_time"],
        "correlated_events": chain["event_count"],
        "unique_attack_stages": unique_stages,
        "stage_sequence": chain["stage_sequence"],
        "context": context,
        "base_risk_score": base_risk_score,
        "stage_bonus": stage_bonus,
        "ml_avg_score": round(ml_avg_score, 4),
        "anomaly_count": anomaly_count,
        "anomaly_ratio": round(anomaly_ratio, 4),
        "ml_bonus": ml_bonus,
        "risk_score": risk_score,
        "severity": final_severity,
        "reason_codes": " | ".join(reason_codes),
        "risk_reasons": " | ".join(risk_reasons),
        "risk_summary": risk_summary,
        "recommended_actions": " | ".join(recommended_actions)
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