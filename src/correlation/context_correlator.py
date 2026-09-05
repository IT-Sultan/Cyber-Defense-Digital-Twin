import pandas as pd
from pathlib import Path

INPUT_FILE = Path("data/processed/apt41_detections.csv")
ML_FILE = Path("data/processed/ml_predictions.csv")
OUTPUT_FILE = Path("data/processed/apt41_correlated_chains.csv")

WINDOW_SECONDS = 180

print("[+] Loading detections...")

df = pd.read_csv(
    INPUT_FILE,
    parse_dates=["@timestamp"]
)

# Load ML predictions
ml_df = pd.read_csv(ML_FILE)

# Attach ML context to detections using canonical event_id
df = df.merge(
    ml_df[["event_id", "ml_score", "ml_label"]],
    on="event_id",
    how="left"
)

missing_ml = df["ml_score"].isna().sum()

if missing_ml > 0:
    print(f"[!] Warning: {missing_ml} detections have no ML prediction")

df = df.sort_values("@timestamp").reset_index(drop=True)

# Use a fallback when host is missing
df["host"] = df["host"].fillna("unknown")

chain_ids = []
current_chain = 1

for i in range(len(df)):

    if i == 0:
        chain_ids.append(current_chain)
        continue

    current = df.iloc[i]
    previous = df.iloc[i - 1]

    time_gap = (
        current["@timestamp"] - previous["@timestamp"]
    ).total_seconds()

    same_host = current["host"] == previous["host"]

    if same_host and time_gap <= WINDOW_SECONDS:
        chain_ids.append(current_chain)
    else:
        current_chain += 1
        chain_ids.append(current_chain)

df["chain_id"] = chain_ids

chains = []

for chain_id, group in df.groupby("chain_id"):

    rules = group["rule_name"].dropna().tolist()
    severities = group["severity"].dropna().tolist()

    stage_sequence = []

    for tactic in group["detected_tactic"].dropna():
        tactic = str(tactic)

        if not stage_sequence or stage_sequence[-1] != tactic:
            stage_sequence.append(tactic)

    unique_attack_stages = group["detected_tactic"].nunique()

    context = []

    if (
        "Remote File Download" in rules
        and "SSH Remote Service" in rules
    ):
        context.append("Possible lateral movement preparation")

    if (
        "Remote File Download" in rules
        and "Cron Persistence" in rules
    ):
        context.append("Possible persistence chain")

    if "Shadow File Access" in rules:
        context.append("Credential access activity")

    if "File Encryption Activity" in rules:
        context.append("Impact / encryption activity")

    if not context:
        context.append("Suspicious activity chain")

    # ML context for this attack chain
    avg_ml_score = group["ml_score"].dropna().mean()

    if pd.isna(avg_ml_score):
        avg_ml_score = 0.0

    anomaly_count = (
        group["ml_label"] == "Anomaly"
    ).sum()

    anomaly_ratio = (
        anomaly_count / len(group)
        if len(group) > 0
        else 0.0
    )

    chains.append({
        "chain_id": chain_id,
        "host": group["host"].iloc[0],
        "start_time": group["@timestamp"].min(),
        "end_time": group["@timestamp"].max(),
        "event_count": len(group),
        "unique_attack_stages": unique_attack_stages,
"stage_sequence": " -> ".join(stage_sequence),
"severities": " -> ".join(severities),
        "avg_ml_score": round(avg_ml_score, 4),
        "anomaly_count": int(anomaly_count),
        "anomaly_ratio": round(anomaly_ratio, 4),
        "rules": " -> ".join(rules),
        "context": " | ".join(context),
        "commands": " || ".join(
            group["command"].dropna().astype(str)
        )
    })

chains_df = pd.DataFrame(chains)

chains_df.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\n=== CORRELATED ATTACK CHAINS ===")

print(
    chains_df[
        [
            "chain_id",
            "host",
            "event_count",
            "avg_ml_score",
            "anomaly_count",
            "anomaly_ratio",
            "context",
            "rules"
        ]
    ].to_string(index=False)
)

print(f"\n[+] Chains created: {len(chains_df)}")
print(f"[+] Saved to: {OUTPUT_FILE}")