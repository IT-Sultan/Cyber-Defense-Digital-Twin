import pandas as pd
from pathlib import Path

INPUT_FILE = Path("data/processed/apt41_timeline.csv")
OUTPUT_FILE = Path("data/processed/apt41_mitre_summary.csv")

print("[+] Loading attack timeline...")

df = pd.read_csv(
    INPUT_FILE,
    parse_dates=["@timestamp"]
)

summary = (
    df.dropna(subset=["tactic", "technique"])
      .groupby(["tactic", "technique"])
      .agg(
          event_count=("event_id", "count"),
          first_seen=("@timestamp", "min"),
          last_seen=("@timestamp", "max")
      )
      .reset_index()
      .sort_values("first_seen")
)

summary.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\n=== MITRE ATT&CK SUMMARY ===")
print(summary.to_string(index=False))

print(f"\n[+] Summary saved to: {OUTPUT_FILE}")