import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import textwrap
from pathlib import Path
import os
DATASET_SLUG = os.getenv("CYBER_DATASET_SLUG", "apt41")

NODES_FILE = Path(f"data/processed/{DATASET_SLUG}_graph_nodes.csv")
EDGES_FILE = Path(f"data/processed/{DATASET_SLUG}_graph_edges.csv")
OUTPUT_FILE = Path(f"docs/{DATASET_SLUG}_attack_graph.png")

print("[+] Loading attack graph data...")

nodes = pd.read_csv(
    NODES_FILE,
    parse_dates=["first_seen", "last_seen"]
)

edges = pd.read_csv(EDGES_FILE)

graph = nx.DiGraph()

# Sort nodes by the first time each technique appeared
nodes = nodes.sort_values("first_seen").reset_index(drop=True)

for _, row in nodes.iterrows():
    graph.add_node(
        row["node"],
        tactic=row["tactic"],
        technique=row["technique"],
        event_count=row["event_count"]
    )

for _, row in edges.iterrows():
    graph.add_edge(
        row["source"],
        row["target"],
        weight=row["transition_count"]
    )

print(f"[+] Nodes: {graph.number_of_nodes()}")
print(f"[+] Edges: {graph.number_of_edges()}")

# Put tactics on different horizontal levels
tactics = nodes["tactic"].drop_duplicates().tolist()

tactic_levels = {
    tactic: index
    for index, tactic in enumerate(tactics)
}

# X = chronological order
# Y = MITRE tactic
pos = {}

for index, row in nodes.iterrows():
    pos[row["node"]] = (
        index * 2.5,
        tactic_levels[row["tactic"]] * 2.2
    )

plt.figure(figsize=(24, 12))

nx.draw_networkx_nodes(
    graph,
    pos,
    node_size=5000
)

nx.draw_networkx_edges(
    graph,
    pos,
    arrows=True,
    arrowsize=25,
    width=1.5,
    connectionstyle="arc3,rad=0.08"
)

# Show technique name instead of the full node string
labels = {}

for _, row in nodes.iterrows():

    technique = "\n".join(
        textwrap.wrap(
            str(row["technique"]),
            width=22
        )
    )

    labels[row["node"]] = (
        f"{technique}\n"
        f"[{row['tactic']}]"
    )

nx.draw_networkx_labels(
    graph,
    pos,
    labels=labels,
    font_size=8
)

plt.title(
    f"{DATASET_SLUG.upper()} Attack Path — MITRE ATT&CK Timeline",
    fontsize=18
)

plt.axis("off")
plt.tight_layout()

OUTPUT_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)

plt.savefig(
    OUTPUT_FILE,
    dpi=220,
    bbox_inches="tight"
)

print(f"[+] Attack graph saved to: {OUTPUT_FILE}")