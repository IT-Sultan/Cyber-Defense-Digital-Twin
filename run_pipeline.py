import subprocess
import sys

STEPS = [
    ("Data Cleaning", "src/preprocessing/clean_events.py"),
    ("ML Supervised Classifier", "src/ml/supervised_classifier.py"),
    ("Attack Timeline", "src/correlation/build_timeline.py"),
    ("MITRE Summary", "src/mitre/build_mitre_summary.py"),
    ("Detection Engine", "src/detection/detection_engine.py"),
    ("Context Correlation", "src/correlation/context_correlator.py"),
    ("Attack Graph Builder", "src/attack_graph/build_attack_graph.py"),
    ("Attack Graph Visualization", "src/attack_graph/visualize_attack_graph.py"),
    ("SOC Alert Generation", "src/detection/generate_soc_alert.py"),
    ("Pipeline Validation", "src/validation/validate_pipeline.py"),
]

print("\n====================================")
print("  CYBER DEFENSE DIGITAL TWIN")
print("  Starting Security Pipeline")
print("====================================\n")

for name, script in STEPS:
    print(f"\n[+] Running: {name}")
    print("-" * 50)

    try:
        subprocess.run(
            [sys.executable, script],
            check=True
        )
        print(f"[✓] Completed: {name}")

    except subprocess.CalledProcessError:
        print(f"[!] Pipeline failed at: {name}")
        sys.exit(1)

print("\n====================================")
print("  PIPELINE COMPLETED SUCCESSFULLY")
print("====================================")