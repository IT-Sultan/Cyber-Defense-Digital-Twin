import os
import math
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

def calculate_entropy(text):
    if not text or text == '-':
        return 0.0
    text_str = str(text)
    text_len = len(text_str)
    freq = {}
    for c in text_str:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_features(df):
    df = df.copy()
    df['command_executed'] = df['command_executed'].fillna('-').astype(str)
    df['a0'] = df['a0'].fillna('unknown').astype(str)
    df['argc'] = pd.to_numeric(df.get('argc', 1), errors='coerce').fillna(1)
    df['cmd_length'] = df['command_executed'].apply(len)
    df['entropy'] = df['command_executed'].apply(calculate_entropy)
    
    special_chars = [';', '|', '&', '>', '<', '`', '$']
    df['special_char_count'] = df['command_executed'].apply(lambda cmd: sum(cmd.count(ch) for ch in special_chars))
    
    # استخدام has_sensitive_path المعتمد فقط مع تفادي إيجابيات tmp العامة
    sensitive_targets = ['/etc/passwd', '/etc/shadow', 'linenum', 'grab_keys', 'authorized_keys', '/tmp/malicious', '/tmp/reports.xlsm']
    df['has_sensitive_path'] = df['command_executed'].apply(
        lambda x: 1 if any(p in x.lower() for p in sensitive_targets) else 0
    )
    
    attack_tools = ['curl', 'openssl', 'tar', 'chmod', 'xxd', 'crontab', 'sudo', 'bash', 'sh', 'nc', 'ncat']
    df['is_attack_tool'] = df['a0'].apply(lambda x: 1 if x in attack_tools else 0)
    return df

def main():
    print("[+] Training Production ML Classifier on Full Auditd Telemetry...")
    
    attack_raw = pd.read_csv("data/processed/linux_auditd_attack.csv")
    benign_raw = pd.read_csv("data/processed/linux_auditd_benign.csv")
    
    attack_raw['is_attack'] = 1
    benign_raw['is_attack'] = 0

    full_telemetry = pd.concat([attack_raw, benign_raw], ignore_index=True)
    full_telemetry = extract_features(full_telemetry)

    # حساب a0_map أثناء التدريب
    a0_map = full_telemetry['a0'].value_counts(normalize=True).to_dict()
    full_telemetry['a0_freq'] = full_telemetry['a0'].map(a0_map).fillna(0)

    feature_cols = ['argc', 'cmd_length', 'entropy', 'special_char_count', 'has_sensitive_path', 'is_attack_tool', 'a0_freq']
    
    clf = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42, class_weight='balanced')
    clf.fit(full_telemetry[feature_cols], full_telemetry['is_attack'])
    
    THRESHOLD = 0.60
    
    # حفظ النموذج مع ملحقاته كـ Bundle كامل
    os.makedirs("models", exist_ok=True)
    artifact = {
        'model': clf,
        'threshold': THRESHOLD,
        'a0_map': a0_map,
        'feature_cols': feature_cols
    }
    joblib.dump(artifact, "models/production_random_forest.pkl")
    print(f"[+] Complete model artifact saved to: models/production_random_forest.pkl")

    # Ingestion على APT41 للتوافق مع البايبلاين
    clean_apt_file = "data/processed/apt41_clean.csv"
    df_apt = pd.read_csv(clean_apt_file, low_memory=False)

    df_apt_feat = extract_features(df_apt)
    df_apt_feat['a0_freq'] = df_apt_feat['a0'].map(a0_map).fillna(0)

    probs = clf.predict_proba(df_apt_feat[feature_cols])[:, 1]
    
    df_apt['ml_score'] = np.round(probs, 4)
    df_apt['ml_label'] = df_apt['ml_score'].apply(
        lambda s: 'High Risk' if s >= THRESHOLD else ('Medium Risk' if s >= 0.40 else 'Low Risk')
    )
    df_apt['model_name'] = 'RandomForest_Retrained_Auditd_v2'

    if 'event_id' in df_apt.columns:
        df_apt['event_id'] = df_apt['event_id'].astype('int64')
    else:
        df_apt['event_id'] = range(1, len(df_apt) + 1)

    host_val = df_apt['host.name'] if 'host.name' in df_apt.columns else df_apt.get('host', '4fa5a8bb3a60')
    df_apt['host'] = host_val

    out_df = df_apt[['event_id', '@timestamp', 'host', 'ml_score', 'ml_label', 'model_name']].copy()
    out_csv = "data/processed/ml_predictions.csv"
    out_df.to_csv(out_csv, index=False)
    print(f"[+] Production predictions updated in: {out_csv}")

if __name__ == "__main__":
    main()