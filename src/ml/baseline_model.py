import os
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

def run_ml_pipeline():
    # المسارات متوافقة مع الـ Contract
    input_path = "data/processed/apt41_clean.csv"
    
    # بدائل في حال كان الملف في المسار الرئيسي لـ data
    if not os.path.exists(input_path):
        if os.path.exists("data/apt41_clean_sample.csv"):
            input_path = "data/apt41_clean_sample.csv"
        elif os.path.exists("data/APT41-Campaign-1-logs.csv"):
            input_path = "data/APT41-Campaign-1-logs.csv"
        else:
            raise FileNotFoundError("لم يتم العثور على ملف البيانات!")

    print(f"[*] قراءة البيانات من: {input_path}")
    df = pd.read_csv(input_path, low_memory=False)

    # 1. استخراج الـ Features (مع استبعاد tactic و technique لتفادي الـ Data Leakage)
    df['command_executed'] = df['command_executed'].fillna('-').astype(str) if 'command_executed' in df.columns else '-'
    df['a0'] = df['a0'].fillna('unknown').astype(str) if 'a0' in df.columns else 'unknown'
    df['argc'] = pd.to_numeric(df.get('argc', 1), errors='coerce').fillna(1)
    
    df['cmd_length'] = df['command_executed'].apply(len)
    
    sensitive_patterns = ['/tmp', '/etc/passwd', '/etc/shadow', 'encrypted', 'LinEnum', 'grab_keys']
    df['is_sensitive_path'] = df['command_executed'].apply(lambda x: 1 if any(p in x for p in sensitive_patterns) else 0)
    
    attack_tools = ['curl', 'openssl', 'tar', 'chmod', 'xxd', 'crontab', 'sudo', 'bash']
    df['is_attack_tool'] = df['a0'].apply(lambda x: 1 if x in attack_tools else 0)
    
    le = LabelEncoder()
    df['a0_encoded'] = le.fit_transform(df['a0'])
    
    np.random.seed(42)
    df['time_delta'] = np.random.uniform(0.5, 10.0, size=len(df))

    features = ['argc', 'cmd_length', 'is_sensitive_path', 'is_attack_tool', 'a0_encoded', 'time_delta']
    X = df[features]

    # 2. تدريب Baseline Model
    print("[*] تدريب مودل الـ Baseline...")
    iso_forest = IsolationForest(contamination=0.2, random_state=42)
    iso_forest.fit(X)
    
    raw_scores = iso_forest.decision_function(X)
    df['ml_score'] = (1 / (1 + np.exp(raw_scores))).round(4)
    
    df['ml_label'] = df['ml_score'].apply(lambda s: 'High Risk' if s >= 0.6 else ('Medium Risk' if s >= 0.4 else 'Low Risk'))
    df['model_name'] = 'IsolationForest_Baseline_v1'

    # 3. إعداد المخرجات حسب الـ Contract
    df['event_id'] = df['_id'] if '_id' in df.columns else [f"event_{i}" for i in range(len(df))]
    df['host'] = df['host.name'] if 'host.name' in df.columns else 'unknown'
    if '@timestamp' not in df.columns:
        df['@timestamp'] = pd.Timestamp.now().isoformat()

    required_cols = ['event_id', '@timestamp', 'host', 'ml_score', 'ml_label', 'model_name']
    ml_predictions = df[required_cols]

    # 4. حفظ المخرجات في المسار المحدد بالـ Contract
    os.makedirs("data/processed", exist_ok=True)
    output_path = "data/processed/ml_predictions.csv"
    ml_predictions.to_csv(output_path, index=False)
    
    print(f"[+] تم إنتاج ملف التنبؤات بنجاح في: {output_path}")

if __name__ == "__main__":
    run_ml_pipeline()