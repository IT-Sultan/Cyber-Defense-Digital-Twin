import argparse
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score

from src.ml.supervised_classifier import extract_features


FEATURE_COLS = [
    "argc",
    "cmd_length",
    "entropy",
    "special_char_count",
    "is_sensitive_path",
    "is_attack_tool",
    "a0_freq",
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--holdout",
        required=True,
        help="Path to a labeled holdout CSV"
    )
    args = parser.parse_args()

    attack = pd.read_csv("data/processed/apt41_clean.csv")
    benign = pd.read_csv("data/processed/linux_auditd_benign.csv")
    holdout = pd.read_csv(args.holdout)

    attack["is_attack"] = 1
    benign["is_attack"] = 0

    if "is_attack" not in holdout.columns:
        raise ValueError("Holdout CSV must contain is_attack column")

    attack["dt_temp"] = pd.to_datetime(
        attack["@timestamp"], errors="coerce"
    )
    benign["dt_temp"] = pd.to_datetime(
        benign["@timestamp"], errors="coerce"
    )

    attack = attack.sort_values("dt_temp").reset_index(drop=True)
    benign = benign.sort_values("dt_temp").reset_index(drop=True)

    split_att = int(len(attack) * 0.70)
    split_ben = int(len(benign) * 0.70)

    train_df = pd.concat([
        attack.iloc[:split_att],
        benign.iloc[:split_ben]
    ], ignore_index=True)

    train_df = extract_features(train_df)
    holdout = extract_features(holdout)

    a0_freq_map = (
        train_df["a0"]
        .value_counts(normalize=True)
        .to_dict()
    )

    train_df["a0_freq"] = (
        train_df["a0"].map(a0_freq_map).fillna(0)
    )

    holdout["a0_freq"] = (
        holdout["a0"].map(a0_freq_map).fillna(0)
    )

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=4,
        random_state=42,
        class_weight="balanced"
    )

    clf.fit(
        train_df[FEATURE_COLS],
        train_df["is_attack"]
    )

    scores = clf.predict_proba(
        holdout[FEATURE_COLS]
    )[:, 1]

    preds = (scores >= 0.5).astype(int)

    results = holdout.copy()
    results["ml_score"] = scores
    results["predicted"] = preds

    print("=" * 60)
    print("FRESH HOLDOUT EVALUATION")
    print("=" * 60)

    print(f"Events: {len(results)}")
    print(f"Average ML score: {scores.mean():.4f}")
    print(f"Max ML score: {scores.max():.4f}")

    # Benign-only holdout
    if results["is_attack"].nunique() == 1 and results["is_attack"].iloc[0] == 0:
        fp = results[results["predicted"] == 1]

        print(f"False positives: {len(fp)}")
        print(
            f"False positive rate: "
            f"{len(fp) / len(results) * 100:.2f}%"
        )

        if len(fp):
            print("\nTop False Positives:")
            print(
                fp.sort_values(
                    "ml_score",
                    ascending=False
                )[
                    [
                        "command_executed",
                        "a0",
                        "ml_score",
                        "is_sensitive_path",
                        "is_attack_tool",
                    ]
                ].head(20).to_string(index=False)
            )

    # Mixed benign + attack holdout
    else:
        y_true = results["is_attack"]

        print(
            f"Attack Precision: "
            f"{precision_score(y_true, preds, zero_division=0):.3f}"
        )
        print(
            f"Attack Recall: "
            f"{recall_score(y_true, preds, zero_division=0):.3f}"
        )
        print(
            f"Attack F1: "
            f"{f1_score(y_true, preds, zero_division=0):.3f}"
        )

        if y_true.nunique() > 1:
            print(
                f"ROC-AUC: "
                f"{roc_auc_score(y_true, scores):.4f}"
            )


if __name__ == "__main__":
    main()