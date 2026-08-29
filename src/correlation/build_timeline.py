import pandas as pd
from pathlib import Path

INPUT_FILE = Path("data/processed/apt41_clean.csv")
OUTPUT_FILE = Path("data/processed/apt41_timeline.csv")

print("[+] Loading cleaned APT41 data...")

df = pd.read_csv(INPUT_FILE, parse_dates=["@timestamp"])

# Sort all events chronologically
df = df.sort_values("@timestamp").reset_index(drop=True)

# Create a simple event ID
df["event_id"] = range(1, len(df) + 1)

# Columns useful for the first attack timeline
timeline_columns = [
    "event_id",
    "@timestamp",
    "tactic",
    "technique",
    "host.name",
    "fields.ip",
    "command_executed",
    "a0"
]

timeline_columns = [
    column for column in timeline_columns
    if column in df.columns
]

timeline = df[timeline_columns].copy()

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

timeline.to_csv(
    OUTPUT_FILE,
    index=False
)

print(f"[+] Timeline events: {len(timeline)}")
print(f"[+] Timeline saved to: {OUTPUT_FILE}")

print("\n=== ATTACK TIMELINE ===")

print(
    timeline[
        ["event_id", "@timestamp", "tactic", "technique", "command_executed"]
    ].to_string(index=False)
)