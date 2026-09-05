import pandas as pd
from pathlib import Path
import os
DATASET_SLUG = os.getenv("CYBER_DATASET_SLUG", "apt41")

INPUT_FILE = Path(f"data/processed/{DATASET_SLUG}_clean.csv")
OUTPUT_FILE = Path(f"data/processed/{DATASET_SLUG}_timeline.csv")

print("[+] Loading cleaned dataset...")

df = pd.read_csv(INPUT_FILE, parse_dates=["@timestamp"])

# Sort all events chronologically
df = df.sort_values("@timestamp").reset_index(drop=True)

# event_id must come from preprocessing
if "event_id" not in df.columns:
    raise KeyError("event_id missing from cleaned dataset")

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