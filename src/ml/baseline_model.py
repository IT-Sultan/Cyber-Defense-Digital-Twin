import os
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

def run_ml_pipeline():
    # 1. تحديد مسار الإدخال
    input_path = "data/processed/apt41_clean.csv"
    if not os.path.exists(input_path):
        if os.path.exists("data/apt41_clean_sample.csv"):
            input_path = "data/apt41_clean_sample.csv"
        elif os.path.exists("data/APT41-Campaign-1-logs.csv"):
            input_path = "data/APT41-Campaign-1-logs.csv"
        else:
            raise FileNotFoundError("لم يتم العثور على ملف البيانات المدخل!")

    print(f"[*] قراءة البيانات من: {input_path}")
    df = pd.read_csv(input_path, low_memory=False)

    # 2. حساب time_delta الفعلي من @timestamp لكل host
    if '@timestamp' in df.columns:
        df['datetime_temp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
        host_col = 'host.name' if 'host.name' in df.columns else 'host'
        df['host_temp'] = df[host_col] if host_col in df.columns else 'default_host'
        
        df = df.sort_values(by=['host_temp', 'datetime_temp']).reset_index(drop=True)
        df['time_delta'] = df.groupby('host_temp')['datetime_temp'].diff().dt.total_seconds().fillna(0)
    else:
        df['time_delta'] = 0.0

    # 3. هندسة الميزات السلوكية (بدون tactic أو technique)
    df['command_executed'] = df['command_executed'].fillna('-').astype(str) if 'command_executed' in df.columns else '-'
    df['a0'] = df['a0'].fillna('unknown').astype(str) if 'a0' in df.columns else 'unknown'
    df['argc'] = pd.to_numeric(df.get('argc', 1), errors='coerce').fillna(1)
    
    df['cmd_length'] = df['command_executed'].apply(len)
    
    sensitive_patterns = ['/tmp', '/etc/passwd', '/etc/shadow', 'encrypted', 'LinEnum', 'grab_keys']
    df['is_sensitive_path'] = df['command_executed'].apply(lambda x: 1 if any(p in x for p in sensitive_patterns) else 0)
    
    attack_tools = ['curl', 'openssl', 'tar', 'chmod', 'xxd', 'crontab', 'sudo', 'bash']
    df['is_attack_tool'] = df['a0'].apply(lambda x: 1 if x in attack_tools else 0)
    
    a0_freq = df['a0'].value_counts(normalize=True).to_dict()
    df['a0_freq_encoded'] = df['a0'].map(a0_freq).fillna(0)

    feature_cols = ['argc', 'cmd_length', 'is_sensitive_path', 'is_attack_tool', 'a0_freq_encoded', 'time_delta']
    X = df[feature_cols]

    # 4. تدريب Isolation Forest
    print("[*] تدريب Isolation Forest (Relative Anomaly Baseline)...")
    iso_forest = IsolationForest(contamination='auto', random_state=42)
    iso_forest.fit(X)
    
    # حساب Relative Anomaly Score: كل ما زادت القيمة زادت نسبة الشذوذ (محصورة بين 0 و 1)
    # score_samples ترجع قيم سالبة؛ كل ما كانت أكثر سلبية دلت على شذوذ أكبر
    raw_anomaly_scores = -iso_forest.score_samples(X)
    min_s, max_s = raw_anomaly_scores.min(), raw_anomaly_scores.max()
    if max_s > min_s:
        df['ml_score'] = ((raw_anomaly_scores - min_s) / (max_s - min_s)).round(4)
    else:
        df['ml_score'] = 0.5

    # استخراج الـ label مباشرة من الـ predict (-1 = Anomaly, 1 = Inlier / Normal-like)
    preds = iso_forest.predict(X)
    df['ml_label'] = np.where(preds == -1, 'Anomaly', 'Inlier / Normal-like')
    df['model_name'] = 'IsolationForest_Baseline_v2'

    # 5. تصدير المخرجات المتوافقة مع ml-interface.md
    if 'event_id' not in df.columns:
        if '_id' in df.columns:
            df['event_id'] = df['_id']
        else:
            df['event_id'] = [f"event_{i}" for i in range(len(df))]

    df['host'] = df['host.name'] if 'host.name' in df.columns else 'unknown'

    if '@timestamp' not in df.columns:
        df['@timestamp'] = pd.Timestamp.now().isoformat()

    required_cols = ['event_id', '@timestamp', 'host', 'ml_score', 'ml_label', 'model_name']
    output_df = df[required_cols]

    os.makedirs("data/processed", exist_ok=True)
    output_path = "data/processed/ml_predictions.csv"
    output_df.to_csv(output_path, index=False)

    print(f"[+] تم توليد المخرجات بنجاح في: {output_path}")

if __name__ == "__main__":
    run_ml_pipeline()