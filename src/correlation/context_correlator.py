import pandas as pd
from pathlib import Path

INPUT_FILE = Path("data/processed/apt41_detections.csv")
OUTPUT_FILE = Path("data/processed/apt41_correlated_chains.csv")

WINDOW_SECONDS = 180

print("[+] Loading detections...")

df = pd.read_csv(
    INPUT_FILE,
    parse_dates=["@timestamp"]
)

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

    chains.append({
        "chain_id": chain_id,
        "host": group["host"].iloc[0],
        "start_time": group["@timestamp"].min(),
        "end_time": group["@timestamp"].max(),
        "event_count": len(group),
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
            "context",
            "rules"
        ]
    ].to_string(index=False)
)

print(f"\n[+] Chains created: {len(chains_df)}")
print(f"[+] Saved to: {OUTPUT_FILE}")