import sys
from pathlib import Path
import os
import pandas as pd


DATA_DIR = Path("data/processed")
DATASET_SLUG = os.getenv("CYBER_DATASET_SLUG", "apt41")
FILES = {
    "clean": DATA_DIR / f"{DATASET_SLUG}_clean.csv",
    "ml": DATA_DIR / "ml_predictions.csv",
    "timeline": DATA_DIR / f"{DATASET_SLUG}_timeline.csv",
    "detections": DATA_DIR / f"{DATASET_SLUG}_detections.csv",
    "chains": DATA_DIR / f"{DATASET_SLUG}_correlated_chains.csv",
    "alerts": DATA_DIR / f"{DATASET_SLUG}_soc_alert.csv",
}

failures = []


def passed(message):
    print(f"[PASS] {message}")


def failed(message):
    print(f"[FAIL] {message}")
    failures.append(message)


def require_columns(df, name, columns):
    missing = [
        column
        for column in columns
        if column not in df.columns
    ]

    if missing:
        failed(
            f"{name}: missing columns: {', '.join(missing)}"
        )
        return False

    passed(f"{name}: required columns present")
    return True


print("\n====================================")
print(" CYBER DEFENSE PIPELINE VALIDATION")
print("====================================\n")


# --------------------------------------------------
# 1. Required output files
# --------------------------------------------------

for name, path in FILES.items():

    if path.exists():
        passed(f"{name} output exists")
    else:
        failed(f"{name} output missing: {path}")


if failures:
    print("\nPipeline outputs are incomplete.")
    sys.exit(1)


# --------------------------------------------------
# 2. Load outputs
# --------------------------------------------------

clean_df = pd.read_csv(FILES["clean"])
ml_df = pd.read_csv(FILES["ml"])
timeline_df = pd.read_csv(FILES["timeline"])
detections_df = pd.read_csv(FILES["detections"])
chains_df = pd.read_csv(FILES["chains"])
alerts_df = pd.read_csv(FILES["alerts"])


# --------------------------------------------------
# 3. Required columns
# --------------------------------------------------

schemas_ok = True

schemas_ok &= require_columns(
    clean_df,
    "Clean dataset",
    ["event_id", "@timestamp"]
)

schemas_ok &= require_columns(
    ml_df,
    "ML predictions",
    ["event_id", "ml_score", "ml_label"]
)

schemas_ok &= require_columns(
    timeline_df,
    "Timeline",
    ["event_id", "@timestamp"]
)

schemas_ok &= require_columns(
    detections_df,
    "Detections",
    [
        "event_id",
        "@timestamp",
        "rule_name",
        "severity"
    ]
)

schemas_ok &= require_columns(
    chains_df,
    "Correlated chains",
    [
        "chain_id",
        "event_count",
        "event_ids",
        "risk_score"
    ]
    if "risk_score" in chains_df.columns
    else [
        "chain_id",
        "event_count",
        "event_ids"
    ]
)

schemas_ok &= require_columns(
    alerts_df,
    "SOC alerts",
    [
        "chain_id",
        "correlated_events",
        "risk_score",
        "severity"
    ]
)

if not schemas_ok:
    print("\nSchema validation failed.")
    sys.exit(1)


# --------------------------------------------------
# 4. Canonical event ID integrity
# --------------------------------------------------

clean_ids = set(
    pd.to_numeric(
        clean_df["event_id"],
        errors="coerce"
    ).dropna().astype(int)
)

timeline_ids = set(
    pd.to_numeric(
        timeline_df["event_id"],
        errors="coerce"
    ).dropna().astype(int)
)

ml_ids = set(
    pd.to_numeric(
        ml_df["event_id"],
        errors="coerce"
    ).dropna().astype(int)
)

detection_ids = set(
    pd.to_numeric(
        detections_df["event_id"],
        errors="coerce"
    ).dropna().astype(int)
)


if clean_df["event_id"].isna().any():
    failed("Clean dataset contains missing event_id values")
else:
    passed("Clean dataset has no missing event_id values")


if clean_df["event_id"].duplicated().any():
    failed("Clean dataset contains duplicate event_id values")
else:
    passed("Clean event IDs are unique")


if ml_df["event_id"].duplicated().any():
    failed("ML predictions contain duplicate event_id values")
else:
    passed("ML event IDs are unique")


if clean_ids == timeline_ids:
    passed("Timeline event IDs match canonical clean dataset")
else:
    failed("Timeline event IDs do not match clean dataset")


if clean_ids == ml_ids:
    passed(
        f"ML coverage complete: {len(ml_ids)}/{len(clean_ids)} events"
    )
else:
    missing_ml = clean_ids - ml_ids
    extra_ml = ml_ids - clean_ids

    failed(
        f"ML event coverage mismatch "
        f"(missing={len(missing_ml)}, extra={len(extra_ml)})"
    )


missing_detection_ml = detection_ids - ml_ids

if not missing_detection_ml:
    passed(
        f"All detections have ML predictions "
        f"({len(detection_ids)}/{len(detection_ids)})"
    )
else:
    failed(
        f"{len(missing_detection_ml)} detection event IDs "
        "have no ML prediction"
    )


invalid_detection_ids = detection_ids - clean_ids

if not invalid_detection_ids:
    passed("All detections reference canonical event IDs")
else:
    failed(
        f"{len(invalid_detection_ids)} detections reference "
        "unknown event IDs"
    )


# --------------------------------------------------
# 5. ML score validation
# --------------------------------------------------

ml_scores = pd.to_numeric(
    ml_df["ml_score"],
    errors="coerce"
)

if ml_scores.isna().any():
    failed("ML predictions contain invalid ml_score values")
elif ((ml_scores < 0) | (ml_scores > 1)).any():
    failed("ML scores exist outside expected 0-1 range")
else:
    passed("ML scores are within 0-1 range")


# --------------------------------------------------
# 6. Correlated chain integrity
# --------------------------------------------------

chain_ids_seen = set()

for _, chain in chains_df.iterrows():

    chain_id = int(chain["chain_id"])
    chain_ids_seen.add(chain_id)

    raw_event_ids = chain["event_ids"]

    try:
        event_ids = [
            int(value.strip())
            for value in str(raw_event_ids).split("|")
            if value.strip()
        ]
    except ValueError:
        failed(
            f"Chain {chain_id}: invalid event_ids format"
        )
        continue

    expected_count = int(chain["event_count"])

    if len(event_ids) == expected_count:
        passed(
            f"Chain {chain_id}: event_count matches event_ids "
            f"({expected_count})"
        )
    else:
        failed(
            f"Chain {chain_id}: event_count={expected_count}, "
            f"but event_ids contains {len(event_ids)} events"
        )

    if len(event_ids) == len(set(event_ids)):
        passed(
            f"Chain {chain_id}: no duplicate event IDs"
        )
    else:
        failed(
            f"Chain {chain_id}: duplicate event IDs detected"
        )

    unknown_ids = set(event_ids) - detection_ids

    if not unknown_ids:
        passed(
            f"Chain {chain_id}: all events reference detections"
        )
    else:
        failed(
            f"Chain {chain_id}: contains "
            f"{len(unknown_ids)} unknown detection event IDs"
        )


# --------------------------------------------------
# 7. SOC alert integrity
# --------------------------------------------------

for _, alert in alerts_df.iterrows():

    chain_id = int(alert["chain_id"])

    if chain_id in chain_ids_seen:
        passed(
            f"Alert chain {chain_id} references an existing chain"
        )
    else:
        failed(
            f"Alert references missing chain {chain_id}"
        )
        continue

    risk_score = pd.to_numeric(
        alert["risk_score"],
        errors="coerce"
    )

    if pd.isna(risk_score):
        failed(
            f"Alert chain {chain_id}: invalid risk score"
        )
    elif 0 <= risk_score <= 100:
        passed(
            f"Alert chain {chain_id}: risk score valid "
            f"({int(risk_score)}/100)"
        )
    else:
        failed(
            f"Alert chain {chain_id}: risk score outside 0-100"
        )

    matching_chain = chains_df[
        chains_df["chain_id"] == chain_id
    ]

    if not matching_chain.empty:

        chain_event_count = int(
            matching_chain.iloc[0]["event_count"]
        )

        alert_event_count = int(
            alert["correlated_events"]
        )

        if chain_event_count == alert_event_count:
            passed(
                f"Alert chain {chain_id}: correlated event "
                "count matches chain"
            )
        else:
            failed(
                f"Alert chain {chain_id}: event count mismatch"
            )


# --------------------------------------------------
# Final result
# --------------------------------------------------

print("\n====================================")

if failures:

    print(
        f" PIPELINE VALIDATION FAILED "
        f"({len(failures)} issue(s))"
    )

    print("====================================")

    for number, failure in enumerate(
        failures,
        start=1
    ):
        print(f"{number}. {failure}")

    sys.exit(1)

else:

    print(" PIPELINE VALIDATION PASSED")
    print("====================================")
    sys.exit(0)