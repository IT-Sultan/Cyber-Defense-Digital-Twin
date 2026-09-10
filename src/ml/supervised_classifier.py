import os
import math
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score

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
    df['special_char_count'] = df['command_executed'].apply(
        lambda cmd: sum(cmd.count(ch) for ch in special_chars)
    )

    def has_sensitive_path(cmd):
        cmd = str(cmd)
        tokens = cmd.replace('"', ' ').replace("'", ' ').split()

        path_hit = any(
            token == "/tmp"
            or token.startswith("/tmp/")
            or token == "/etc/passwd"
            or token == "/etc/shadow"
            or "authorized_keys" in token
            for token in tokens
        )

        marker_hit = any(
            marker.lower() in cmd.lower()
            for marker in ["LinEnum", "grab_keys"]
        )

        return int(path_hit or marker_hit)

    df['is_sensitive_path'] = df['command_executed'].apply(has_sensitive_path)

    attack_tools = [
        'curl', 'openssl', 'tar', 'chmod', 'xxd',
        'crontab', 'sudo', 'bash', 'sh', 'nc', 'ncat'
    ]

    df['is_attack_tool'] = df['a0'].apply(
        lambda x: 1 if x in attack_tools else 0
    )

    return df

def main():
    # 1. تحميل سجلات APT41 النظيفة حصراً لضمان تطابق الـ event_id العددي
    clean_file = "data/processed/apt41_clean.csv"
    if not os.path.exists(clean_file):
        raise FileNotFoundError(f"لم يتم العثور على {clean_file}")
    
    raw_attack = pd.read_csv(clean_file, low_memory=False)

    # استخراج event_id المتطابق رقمياً مع الـ Timeline والـ Detections
    if 'event_id' in raw_attack.columns:
        attack_ids = raw_attack['event_id'].astype('int64')
    else:
        attack_ids = pd.Series(range(1, len(raw_attack) + 1), dtype='int64')

    host_val = raw_attack['host.name'] if 'host.name' in raw_attack.columns else raw_attack.get('host', '4fa5a8bb3a60')

    df_attack = pd.DataFrame({
        'event_id': attack_ids,
        '@timestamp': raw_attack['@timestamp'],
        'host': host_val,
        'command_executed': raw_attack['command_executed'],
        'a0': raw_attack['a0'],
        'argc': raw_attack.get('argc', 1),
        'is_attack': 1
    })

    # 2. تحميل الـ Linux Auditd Benign الفعلي
    benign_file = "data/processed/linux_auditd_benign.csv"
    raw_benign = pd.read_csv(benign_file)
    
    # ترقيم الـ Benign بأرقام مفصولة لتفادي أي تضارب
    benign_ids = pd.Series(range(10001, 10001 + len(raw_benign)), dtype='int64')
    host_benign = raw_benign['host.name'] if 'host.name' in raw_benign.columns else raw_benign.get('host', 'auditd-host-01')

    df_benign = pd.DataFrame({
        'event_id': benign_ids,
        '@timestamp': raw_benign['@timestamp'],
        'host': host_benign,
        'command_executed': raw_benign['command_executed'],
        'a0': raw_benign['a0'],
        'argc': raw_benign.get('argc', 1),
        'is_attack': 0
    })

    # 3. Class-wise Temporal Split (تقسيم زمني مستقل لكل فئة)
    df_attack['dt_temp'] = pd.to_datetime(df_attack['@timestamp'], errors='coerce')
    df_attack = df_attack.sort_values('dt_temp').reset_index(drop=True)

    df_benign['dt_temp'] = pd.to_datetime(df_benign['@timestamp'], errors='coerce')
    df_benign = df_benign.sort_values('dt_temp').reset_index(drop=True)

    split_att = int(len(df_attack) * 0.70)
    split_ben = int(len(df_benign) * 0.70)

    train_df = pd.concat([df_attack.iloc[:split_att], df_benign.iloc[:split_ben]], ignore_index=True)
    test_df = pd.concat([df_attack.iloc[split_att:], df_benign.iloc[split_ben:]], ignore_index=True)

    # استخراج الـ Features
    train_df = extract_features(train_df)
    test_df = extract_features(test_df)

    # حساب a0_freq داخل الـ Train فقط لتفادي Data Leakage
    a0_freq_map = train_df['a0'].value_counts(normalize=True).to_dict()
    train_df['a0_freq'] = train_df['a0'].map(a0_freq_map).fillna(0)
    test_df['a0_freq'] = test_df['a0'].map(a0_freq_map).fillna(0)

    feature_cols = ['argc', 'cmd_length', 'entropy', 'special_char_count', 'is_sensitive_path', 'is_attack_tool', 'a0_freq']

    X_train, y_train = train_df[feature_cols], train_df['is_attack']
    X_test, y_test = test_df[feature_cols], test_df['is_attack']

    print(f"[*] Temporal Train: {len(train_df)} (Attacks={y_train.sum()}, Benign={len(train_df)-y_train.sum()})")
    print(f"[*] Temporal Test: {len(test_df)} (Attacks={y_test.sum()}, Benign={len(test_df)-y_test.sum()})")

    # 4. تدريب المودل
    clf = RandomForestClassifier(n_estimators=100, max_depth=4, random_state=42, class_weight='balanced')
    clf.fit(X_train, y_train)

    # 5. التقييم على عينة الاختبار
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    
    print("\n" + "="*50)
    print("نتائج التقييم الزمني (Class-wise Temporal Evaluation):")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Attack'], zero_division=0))
    if len(np.unique(y_test)) > 1:
        print(f"Test ROC-AUC Score: {roc_auc_score(y_test, y_prob):.4f}")
    print("="*50)

    # 6. توليد التوقعات لبيانات الهجوم بالكامل (الـ 46 حدث بالـ event_id العددي الأصلي)
    df_attack_features = extract_features(df_attack.copy())
    df_attack_features['a0_freq'] = df_attack_features['a0'].map(a0_freq_map).fillna(0)

    attack_probs = clf.predict_proba(df_attack_features[feature_cols])[:, 1]

    df_attack['ml_score'] = np.round(attack_probs, 4)
    df_attack['ml_label'] = df_attack['ml_score'].apply(
        lambda s: 'High Risk' if s >= 0.75 else ('Medium Risk' if s >= 0.40 else 'Low Risk')
    )
    df_attack['model_name'] = 'RandomForest_TemporalSplit_v1'

    required_cols = ['event_id', '@timestamp', 'host', 'ml_score', 'ml_label', 'model_name']
    out_df = df_attack[required_cols].copy()
    out_df['event_id'] = out_df['event_id'].astype('int64')

    out_csv = "data/processed/ml_predictions.csv"
    out_df.to_csv(out_csv, index=False)
    print(f"\n[+] تم تحديث التوقعات لـ {len(out_df)} حدث بالـ IDs المطابقة في: {out_csv}")

if __name__ == "__main__":
    main()