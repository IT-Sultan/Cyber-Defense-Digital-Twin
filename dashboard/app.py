from pathlib import Path
import subprocess
import sys
import os
import pandas as pd
import streamlit as st


# --------------------------------------------------
# Paths
# --------------------------------------------------

ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = ROOT / "data" / "processed"
DATASET_SLUG = os.getenv("CYBER_DATASET_SLUG", "apt41")
ALERT_FILE = DATA_DIR / f"{DATASET_SLUG}_soc_alert.csv"
CHAINS_FILE = DATA_DIR / f"{DATASET_SLUG}_correlated_chains.csv"
DETECTIONS_FILE = DATA_DIR / f"{DATASET_SLUG}_detections.csv"
TIMELINE_FILE = DATA_DIR / f"{DATASET_SLUG}_timeline.csv"
ML_FILE = DATA_DIR / "ml_predictions.csv"

ATTACK_GRAPH_FILE = ROOT / "docs" / f"{DATASET_SLUG}_attack_graph.png"


# --------------------------------------------------
# Streamlit config
# --------------------------------------------------

st.set_page_config(
    page_title="Cyber Defense Digital Twin",
    page_icon="🛡️",
    layout="wide"
)
st.markdown("""
<style>

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
}

[data-testid="stMetric"] {
    background: #161b22;
    border: 1px solid #30363d;
    padding: 18px;
    border-radius: 12px;
}

[data-testid="stMetricLabel"] {
    font-size: 14px;
}

[data-testid="stMetricValue"] {
    font-weight: 700;
}

div[data-testid="stAlert"] {
    border-radius: 12px;
}

.stTabs [data-baseweb="tab-list"] {
    gap: 12px;
}

.stTabs [data-baseweb="tab"] {
    padding-left: 12px;
    padding-right: 12px;
}

</style>
""", unsafe_allow_html=True)

# --------------------------------------------------
# Helpers
# --------------------------------------------------

def load_csv(path):
    if not path.exists():
        return pd.DataFrame()

    try:
        return pd.read_csv(path)
    except Exception as exc:
        st.error(f"Failed to load {path.name}: {exc}")
        return pd.DataFrame()


def split_values(value):
    if pd.isna(value):
        return []

    return [
        item.strip()
        for item in str(value).split("|")
        if item.strip()
    ]


def safe_text(value, default="Unknown"):
    if pd.isna(value):
        return default

    return str(value)


# --------------------------------------------------
# Sidebar
# --------------------------------------------------

st.sidebar.title("🛡️ Cyber Defense")

st.sidebar.caption(
    "Cyber Defense Digital Twin"
)

st.sidebar.divider()

if st.sidebar.button(
    "▶ Run Security Pipeline",
    width="stretch"
):

    with st.spinner("Running security pipeline..."):

        result = subprocess.run(
            [sys.executable, str(ROOT / "run_pipeline.py")],
            cwd=ROOT,
            capture_output=True,
            text=True
        )

    if result.returncode == 0:
        st.sidebar.success("Pipeline completed successfully")
        st.rerun()

    else:
        st.sidebar.error("Pipeline failed")

        with st.sidebar.expander("Pipeline error"):
            st.code(result.stderr)


if st.sidebar.button(
    "🔄 Refresh Dashboard",
    width="stretch"
):
    st.rerun()


st.sidebar.divider()

st.sidebar.markdown("### Data Sources")

files_status = {
    "SOC Alerts": ALERT_FILE.exists(),
    "Correlation": CHAINS_FILE.exists(),
    "Detections": DETECTIONS_FILE.exists(),
    "Timeline": TIMELINE_FILE.exists(),
    "ML Predictions": ML_FILE.exists()
}

for name, exists in files_status.items():

    if exists:
        st.sidebar.write(f"✅ {name}")
    else:
        st.sidebar.write(f"❌ {name}")


# --------------------------------------------------
# Load data
# --------------------------------------------------

alerts_df = load_csv(ALERT_FILE)
chains_df = load_csv(CHAINS_FILE)
detections_df = load_csv(DETECTIONS_FILE)
timeline_df = load_csv(TIMELINE_FILE)
ml_df = load_csv(ML_FILE)


# --------------------------------------------------
# Header
# --------------------------------------------------

st.title("🛡️ Cyber Defense Digital Twin")

st.caption(
    "AI-assisted SOC detection, correlation, anomaly analysis and risk prioritization"
)

st.divider()


# --------------------------------------------------
# Check alert data
# --------------------------------------------------

if alerts_df.empty:

    st.warning(
        "No SOC alert data found. Run the security pipeline first."
    )

    st.stop()


# --------------------------------------------------
# Alert selection
# --------------------------------------------------

alerts_df = alerts_df.sort_values(
    by="risk_score",
    ascending=False
).reset_index(drop=True)


def build_alert_label(index):
    row = alerts_df.iloc[index]

    chain_id = row.get("chain_id", index + 1)
    severity = safe_text(row.get("severity"))
    host = safe_text(row.get("host"))
    risk = int(row.get("risk_score", 0))

    if pd.notna(chain_id):
        try:
            chain_id = int(chain_id)
        except (TypeError, ValueError):
            pass

    return (
        f"Chain {chain_id} • "
        f"{severity} • "
        f"{risk}/100 • "
        f"{host}"
    )

# --------------------------------------------------
# Alert Queue / Prioritization
# --------------------------------------------------

st.subheader("🚨 Alert Queue")

queue_columns = [
    "chain_id",
    "severity",
    "risk_score",
    "host",
    "correlated_events",
    "unique_attack_stages",
    "anomaly_ratio"
]

available_queue_columns = [
    column
    for column in queue_columns
    if column in alerts_df.columns
]

queue_df = alerts_df[available_queue_columns].copy()

queue_df.insert(
    0,
    "priority",
    range(1, len(queue_df) + 1)
)

queue_df = queue_df.rename(columns={
    "priority": "Priority",
    "chain_id": "Chain",
    "severity": "Severity",
    "risk_score": "Risk Score",
    "host": "Host",
    "correlated_events": "Events",
    "unique_attack_stages": "MITRE Stages",
    "anomaly_ratio": "Anomaly Ratio"
})

if "Anomaly Ratio" in queue_df.columns:
    queue_df["Anomaly Ratio"] = (
        queue_df["Anomaly Ratio"] * 100
    ).round(1).astype(str) + "%"

st.dataframe(
    queue_df,
    width="stretch",
    hide_index=True
)

st.caption(
    "Alerts are prioritized by risk score from highest to lowest."
)

st.divider()
st.sidebar.markdown("### Alert Selection")

selected_alert_index = st.sidebar.selectbox(
    "Active Alert",
    options=range(len(alerts_df)),
    format_func=build_alert_label
)

st.sidebar.metric(
    "Total Alerts",
    len(alerts_df)
)

alert = alerts_df.iloc[selected_alert_index]
# --------------------------------------------------
# Filter data for selected alert
# --------------------------------------------------

selected_chain_id = alert.get("chain_id")

selected_event_ids = []

if not chains_df.empty and "chain_id" in chains_df.columns:

    chain_ids_numeric = pd.to_numeric(
        chains_df["chain_id"],
        errors="coerce"
    )

    selected_chain_numeric = pd.to_numeric(
        pd.Series([selected_chain_id]),
        errors="coerce"
    ).iloc[0]

    selected_chain_rows = chains_df[
        chain_ids_numeric == selected_chain_numeric
    ]

    if not selected_chain_rows.empty:

        event_ids_value = selected_chain_rows.iloc[0].get(
            "event_ids",
            ""
        )

        if pd.notna(event_ids_value):

            for event_id in str(event_ids_value).split("|"):

                event_id = event_id.strip()

                try:
                    selected_event_ids.append(
                        int(float(event_id))
                    )
                except ValueError:
                    pass


# Filter detections to selected alert
if selected_event_ids and "event_id" in detections_df.columns:

    detections_df = detections_df[
        detections_df["event_id"].isin(selected_event_ids)
    ].copy()


# Filter ML predictions to selected alert
if selected_event_ids and "event_id" in ml_df.columns:

    ml_df = ml_df[
        ml_df["event_id"].isin(selected_event_ids)
    ].copy()

# --------------------------------------------------
# Main metrics
# --------------------------------------------------

risk_score = int(alert.get("risk_score", 0))
severity = safe_text(alert.get("severity"))
host = safe_text(alert.get("host"))

correlated_events = int(
    alert.get("correlated_events", 0)
)

unique_stages = int(
    alert.get("unique_attack_stages", 0)
)

ml_avg_score = float(
    alert.get("ml_avg_score", 0.0)
)

anomaly_ratio = float(
    alert.get("anomaly_ratio", 0.0)
)


top_cols = st.columns(3)

top_cols[0].metric(
    "Risk Score",
    f"{risk_score}/100"
)

top_cols[1].metric(
    "Severity",
    severity
)

top_cols[2].metric(
    "Host",
    host
)

bottom_cols = st.columns(3)

bottom_cols[0].metric(
    "Correlated Events",
    correlated_events
)

bottom_cols[1].metric(
    "MITRE Stages",
    unique_stages
)

bottom_cols[2].metric(
    "Anomaly Ratio",
    f"{anomaly_ratio:.1%}"
)


st.progress(
    min(max(risk_score, 0), 100) / 100
)


# --------------------------------------------------
# Tabs
# --------------------------------------------------

overview_tab, chain_tab, detection_tab, ml_tab, mitre_tab = st.tabs(
    [
        "🚨 SOC Alert",
        "🔗 Attack Chain",
        "🔎 Detections",
        "🤖 ML Analysis",
        "🗺️ MITRE ATT&CK"
    ]
)


# --------------------------------------------------
# SOC ALERT TAB
# --------------------------------------------------

with overview_tab:

    st.subheader("Risk Summary")

    risk_summary = safe_text(
        alert.get("risk_summary"),
        "No risk summary available."
    )

    st.info(risk_summary)

    col1, col2 = st.columns(2)

    with col1:

        st.subheader("Why This Alert Is High Risk")

        reason_codes = split_values(
            alert.get("reason_codes")
        )

        risk_reasons = split_values(
            alert.get("risk_reasons")
        )

        if risk_reasons:

            for reason in risk_reasons:
                st.write(f"• {reason}")

        else:
            st.write("No risk explanation available.")

        if reason_codes:

            with st.expander("Reason Codes"):

                for code in reason_codes:
                    st.code(code)


    with col2:

        st.subheader("Recommended Analyst Actions")

        actions = split_values(
            alert.get("recommended_actions")
        )

        if actions:

            for number, action in enumerate(
                actions,
                start=1
            ):
                st.write(f"{number}. {action}")

        else:

            st.write(
                "No recommended actions available."
            )


    st.divider()

    st.subheader("Risk Components")

    risk_cols = st.columns(3)

    risk_cols[0].metric(
        "Detection Risk",
        int(alert.get("base_risk_score", 0))
    )

    risk_cols[1].metric(
        "Multi-stage Bonus",
        f"+{int(alert.get('stage_bonus', 0))}"
    )

    risk_cols[2].metric(
        "ML Bonus",
        f"+{int(alert.get('ml_bonus', 0))}"
    )

    st.caption(
        "ML score represents relative anomaly within the current dataset and is not an attack probability."
    )


# --------------------------------------------------
# ATTACK CHAIN TAB
# --------------------------------------------------

with chain_tab:

    st.subheader("Correlated Attack Chain")

    stage_sequence = safe_text(
        alert.get("stage_sequence"),
        "No stage sequence available"
    )

    st.markdown("### Attack Stage Sequence")

    st.code(
        stage_sequence,
        language=None
    )

    st.markdown("### Correlation Context")

    st.write(
        safe_text(
            alert.get("context"),
            "No correlation context available."
        )
    )

    if not chains_df.empty:

        st.markdown("### Correlated Chains")

        preferred_columns = [
            "chain_id",
            "host",
            "event_count",
            "unique_attack_stages",
            "avg_ml_score",
            "anomaly_count",
            "anomaly_ratio",
            "context"
        ]

        available_columns = [
            column
            for column in preferred_columns
            if column in chains_df.columns
        ]

        st.dataframe(
            chains_df[available_columns],
            width="stretch",
            hide_index=True
        )


# --------------------------------------------------
# DETECTIONS TAB
# --------------------------------------------------

with detection_tab:

    st.subheader("Detection Engine")

    if detections_df.empty:

        st.warning(
            "No detection data available."
        )

    else:

        st.metric(
            "Total Detections",
            len(detections_df)
        )

        if "severity" in detections_df.columns:

            st.markdown(
                "### Detection Severity Distribution"
            )

            severity_counts = (
                detections_df["severity"]
                .fillna("unknown")
                .value_counts()
            )

            st.bar_chart(
                severity_counts
            )

        preferred_columns = [
            "event_id",
            "@timestamp",
            "host",
            "rule_name",
            "severity",
            "detected_tactic",
            "detected_technique",
            "command"
        ]

        available_columns = [
            column
            for column in preferred_columns
            if column in detections_df.columns
        ]

        st.markdown(
            "### Detection Events"
        )

        st.dataframe(
            detections_df[available_columns],
            width="stretch",
            hide_index=True
        )


# --------------------------------------------------
# ML TAB
# --------------------------------------------------

with ml_tab:

    st.subheader("Machine Learning Anomaly Analysis")

    ml_cols = st.columns(3)

    ml_cols[0].metric(
        "Average ML Score",
        f"{ml_avg_score:.4f}"
    )

    ml_cols[1].metric(
        "Anomaly Ratio",
        f"{anomaly_ratio:.1%}"
    )

    ml_cols[2].metric(
        "Anomaly Count",
        int(alert.get("anomaly_count", 0))
    )

    st.caption(
        "Isolation Forest is currently used as a relative anomaly baseline."
    )

    if not ml_df.empty:

        if "ml_label" in ml_df.columns:

            st.markdown(
                "### ML Classification Distribution"
            )

            label_counts = (
                ml_df["ml_label"]
                .fillna("Unknown")
                .value_counts()
            )

            st.bar_chart(
                label_counts
            )

        preferred_columns = [
            "event_id",
            "@timestamp",
            "host",
            "ml_score",
            "ml_label",
            "model_name"
        ]

        available_columns = [
            column
            for column in preferred_columns
            if column in ml_df.columns
        ]

        st.markdown(
            "### ML Predictions"
        )

        st.dataframe(
            ml_df[available_columns],
            width="stretch",
            hide_index=True
        )


# --------------------------------------------------
# MITRE TAB
# --------------------------------------------------

with mitre_tab:

    st.subheader("MITRE ATT&CK View")

    if not timeline_df.empty:

        if "tactic" in timeline_df.columns:

            tactic_counts = (
                timeline_df["tactic"]
                .fillna("unknown")
                .value_counts()
            )

            st.markdown(
                "### Tactic Distribution"
            )

            st.bar_chart(
                tactic_counts
            )

        preferred_columns = [
            "event_id",
            "@timestamp",
            "tactic",
            "technique",
            "host.name",
            "command_executed"
        ]

        available_columns = [
            column
            for column in preferred_columns
            if column in timeline_df.columns
        ]

        st.markdown(
            "### Attack Timeline"
        )

        st.dataframe(
            timeline_df[available_columns],
            width="stretch",
            hide_index=True
        )


    if ATTACK_GRAPH_FILE.exists():

        st.markdown(
            "### Attack Graph"
        )

        st.image(
            str(ATTACK_GRAPH_FILE),
            width="stretch"
        )


# --------------------------------------------------
# Footer
# --------------------------------------------------

st.divider()

st.caption(
    "Cyber Defense Digital Twin • Detection + Correlation + MITRE ATT&CK + ML-assisted Risk Analysis"
)