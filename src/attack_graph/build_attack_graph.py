import pandas as pd
from pathlib import Path
import os
DATASET_SLUG = os.getenv("CYBER_DATASET_SLUG", "apt41")

INPUT_FILE = Path(f"data/processed/{DATASET_SLUG}_timeline.csv")
NODES_FILE = Path(f"data/processed/{DATASET_SLUG}_graph_nodes.csv")
EDGES_FILE = Path(f"data/processed/{DATASET_SLUG}_graph_edges.csv")

print("[+] Loading attack timeline...")

df = pd.read_csv(
    INPUT_FILE,
    parse_dates=["@timestamp"]
)

events = (
    df.dropna(subset=["tactic", "technique"])
      .sort_values("@timestamp")
      .reset_index(drop=True)
)

events["node"] = (
    events["tactic"].astype(str)
    + " | "
    + events["technique"].astype(str)
)

nodes = (
    events.groupby(
        ["node", "tactic", "technique"],
        as_index=False
    )
    .agg(
        event_count=("event_id", "count"),
        first_seen=("@timestamp", "min"),
        last_seen=("@timestamp", "max")
    )
)

sequence = events["node"].tolist()

collapsed_sequence = []

for node in sequence:
    if not collapsed_sequence or collapsed_sequence[-1] != node:
        collapsed_sequence.append(node)

edges = []

for i in range(len(collapsed_sequence) - 1):
    edges.append({
        "source": collapsed_sequence[i],
        "target": collapsed_sequence[i + 1]
    })

edges = pd.DataFrame(edges)

if not edges.empty:
    edges = (
        edges.groupby(["source", "target"])
        .size()
        .reset_index(name="transition_count")
    )

NODES_FILE.parent.mkdir(parents=True, exist_ok=True)

nodes.to_csv(NODES_FILE, index=False)
edges.to_csv(EDGES_FILE, index=False)

print("\n=== ATTACK GRAPH NODES ===")
print(nodes.to_string(index=False))

print("\n=== ATTACK GRAPH EDGES ===")
print(edges.to_string(index=False))

print(f"\n[+] Nodes saved to: {NODES_FILE}")
print(f"[+] Edges saved to: {EDGES_FILE}")