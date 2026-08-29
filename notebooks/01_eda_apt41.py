import pandas as pd

FILE = "data/processed/apt41_clean.csv"

df = pd.read_csv(
    FILE,
    parse_dates=["@timestamp"]
)

print("\n=== DATASET SHAPE ===")
print(df.shape)

print("\n=== COLUMNS ===")
for column in df.columns:
    print(column)

print("\n=== DATA TYPES ===")
print(df.dtypes)

print("\n=== MISSING VALUES % ===")
missing = (df.isna().mean() * 100).sort_values(ascending=False)
print(missing[missing > 0])

print("\n=== TIME RANGE ===")
print("Start:", df["@timestamp"].min())
print("End:", df["@timestamp"].max())

if "tactic" in df.columns:
    print("\n=== MITRE TACTICS ===")
    print(df["tactic"].value_counts())

if "technique" in df.columns:
    print("\n=== MITRE TECHNIQUES ===")
    print(df["technique"].value_counts())

if "command_executed" in df.columns:
    print("\n=== COMMAND SAMPLES ===")
    print(df["command_executed"].dropna().head(10))