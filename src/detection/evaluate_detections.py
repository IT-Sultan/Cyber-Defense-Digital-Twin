import pandas as pd
from pathlib import Path
import os
DATASET_SLUG = os.getenv("CYBER_DATASET_SLUG", "apt41")

INPUT_FILE = Path(f"data/processed/{DATASET_SLUG}_detections.csv")

print("[+] Loading detections...")

df = pd.read_csv(INPUT_FILE)

def normalize(value):
    if pd.isna(value):
        return ""

    return (
        str(value)
        .strip()
        .lower()
        .replace("_", "-")
        .replace(" ", "-")
    )

df["tactic_match"] = (
    df["detected_tactic"].apply(normalize)
    ==
    df["ground_truth_tactic"].apply(normalize)
)

df["technique_match"] = (
    df["detected_technique"].apply(normalize)
    ==
    df["ground_truth_technique"].apply(normalize)
)

total = len(df)

tactic_matches = df["tactic_match"].sum()
technique_matches = df["technique_match"].sum()

print("\n=== DETECTION EVALUATION ===")

print(f"Total detections: {total}")

print(
    f"Tactic matches: {tactic_matches}/{total} "
    f"({tactic_matches / total * 100:.1f}%)"
)

print(
    f"Technique matches: {technique_matches}/{total} "
    f"({technique_matches / total * 100:.1f}%)"
)

print("\n=== MISMATCHES ===")

mismatches = df[
    (~df["tactic_match"])
    |
    (~df["technique_match"])
]

if mismatches.empty:
    print("No mismatches found.")
else:
    print(
        mismatches[
            [
                "command",
                "detected_tactic",
                "ground_truth_tactic",
                "detected_technique",
                "ground_truth_technique"
            ]
        ].to_string(index=False)
    )