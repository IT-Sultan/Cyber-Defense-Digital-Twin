import pandas as pd
import re
from pathlib import Path

INPUT_FILE = Path("data/processed/apt41_clean.csv")
OUTPUT_FILE = Path("data/processed/apt41_detections.csv")

print("[+] Loading cleaned APT41 events...")

df = pd.read_csv(
    INPUT_FILE,
    parse_dates=["@timestamp"]
)

# Detection rules
rules = [
    {
        "rule_id": "DET001",
        "name": "Remote File Download",
        "pattern": r"\b(curl|wget)\b",
        "severity": "medium",
        "tactic": "command-and-control",
        "technique_id": "T1105",
        "technique": "Ingress Tool Transfer"
    },
    {
        "rule_id": "DET002",
        "name": "Cron Persistence",
        "pattern": r"\b(crontab|cron)\b",
        "severity": "high",
        "tactic": "persistence",
        "technique_id": "T1053.003",
        "technique": "Scheduled Task/Job: Cron"
    },
    {
        "rule_id": "DET003",
        "name": "SSH Remote Service",
        "pattern": r"\bssh\b",
        "severity": "high",
        "tactic": "lateral-movement",
        "technique_id": "T1021.004",
        "technique": "Remote Services: SSH"
    },
    {
        "rule_id": "DET004",
        "name": "Shadow File Access",
        "pattern": r"/etc/(shadow|passwd)",
        "severity": "critical",
        "tactic": "credential-access",
        "technique_id": "T1003.008",
        "technique": "/etc/passwd and /etc/shadow"
    },
    {
        "rule_id": "DET005",
        "name": "File Encryption Activity",
        "pattern": r"\bopenssl\s+enc\b",
        "severity": "critical",
        "tactic": "impact",
        "technique_id": "T1486",
        "technique": "Data Encrypted for Impact"
    },
    {
        "rule_id": "DET006",
        "name": "Possible Masquerading",
        "pattern": r"\bcp\s+/bin/\S+\s+/tmp/\S+",
        "severity": "medium",
        "tactic": "defense-evasion",
        "technique_id": "T1036",
        "technique": "Masquerading"
    },
    {
        "rule_id": "DET007",
        "name": "Network Configuration Discovery",
        "pattern": r"\b(ifconfig|ip\s+(a|addr|route))\b",
        "severity": "low",
        "tactic": "discovery",
        "technique_id": "T1016",
        "technique": "System Network Configuration Discovery"
    },
    {
        "rule_id": "DET008",
        "name": "System Information Discovery",
        "pattern": r"\b(uname|hostname)\b",
        "severity": "low",
        "tactic": "discovery",
        "technique_id": "T1082",
        "technique": "System Information Discovery"
    }
]

detections = []

for index, row in df.iterrows():

    command = str(row.get("command_executed", ""))

    if command == "nan" or not command.strip():
        command = str(row.get("a0", ""))

    if command == "nan":
        command = ""

    for rule in rules:

        if re.search(
            rule["pattern"],
            command,
            flags=re.IGNORECASE
        ):
            detections.append({
                "event_id": row["event_id"],
                "@timestamp": row.get("@timestamp"),
                "host": row.get("host.name"),
                "command": command,
                "rule_id": rule["rule_id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "detected_tactic": rule["tactic"],
                "detected_technique_id": rule["technique_id"],
                "detected_technique": rule["technique"],
                "ground_truth_tactic": row.get("tactic"),
                "ground_truth_technique": row.get("technique")
            })

detections_df = pd.DataFrame(detections)

OUTPUT_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)

detections_df.to_csv(
    OUTPUT_FILE,
    index=False
)

print(f"[+] Total detections: {len(detections_df)}")

if not detections_df.empty:
    print("\n=== DETECTION SUMMARY ===")

    print(
        detections_df[
            [
                "rule_name",
                "severity",
                "detected_technique"
            ]
        ].value_counts()
    )

    print("\n=== DETECTIONS ===")

    print(
        detections_df[
            [
                "@timestamp",
                "rule_name",
                "severity",
                "command"
            ]
        ].to_string(index=False)
    )

print(f"\n[+] Detections saved to: {OUTPUT_FILE}")