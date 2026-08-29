import pandas as pd
from pathlib import Path

RAW_FILE = Path("data/raw/cyber/APT41-Campaign-1-logs.csv")
OUTPUT_FILE = Path("data/processed/apt41_clean.csv")

print("[+] Loading dataset...")

df = pd.read_csv(RAW_FILE)

print(f"[+] Original shape: {df.shape}")

# 1. Replace '-' placeholders with real missing values
df = df.replace("-", pd.NA)

# 2. Remove Elasticsearch .keyword duplicate columns
keyword_columns = [
    column for column in df.columns
    if column.endswith(".keyword")
]

df = df.drop(columns=keyword_columns)

print(f"[+] Removed {len(keyword_columns)} .keyword columns")

# 3. Remove columns that contain no useful values
empty_columns = [
    column for column in df.columns
    if df[column].isna().all()
]

df = df.drop(columns=empty_columns)

# 4. Convert timestamp to datetime
df["@timestamp"] = pd.to_datetime(
    df["@timestamp"].str.replace(" @ ", " ", regex=False),
    format="%b %d, %Y %H:%M:%S.%f",
    errors="coerce"
)

# 5. Convert numeric fields
numeric_columns = [
    "epoch",
    "argc",
    "sequence"
]

for column in numeric_columns:
    if column in df.columns:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )

# log.offset contains commas such as 1,730,355
if "log.offset" in df.columns:
    df["log.offset"] = pd.to_numeric(
        df["log.offset"].astype(str).str.replace(",", ""),
        errors="coerce"
    )

# 6. Remove exact duplicate rows
before_duplicates = len(df)

df = df.drop_duplicates()

removed_duplicates = before_duplicates - len(df)

# 7. Sort events chronologically
df = df.sort_values("@timestamp").reset_index(drop=True)

# 8. Save cleaned dataset
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

df.to_csv(
    OUTPUT_FILE,
    index=False
)

print(f"[+] Final shape: {df.shape}")
print(f"[+] Removed duplicates: {removed_duplicates}")
print(f"[+] Clean dataset saved to: {OUTPUT_FILE}")