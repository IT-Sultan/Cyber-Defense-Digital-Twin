import os
import math
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

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
    df['command_executed'] = df['command_executed'].fillna('-').astype(str)
    df['a0'] = df['a0'].fillna('unknown').astype(str)
    df['argc'] = pd.to_numeric(df.get('argc', 1), errors='coerce').fillna(1)
    
    df['cmd_length'] = df['command_executed'].apply(len)
    df['entropy'] = df['command_executed'].apply(calculate_entropy)
    
    special_chars = [';', '|', '&', '>', '<', '`', '$']
    df['special_char_count'] = df['command_executed'].apply(lambda cmd: sum(cmd.count(ch) for ch in special_chars))
    
    sensitive_paths = ['/tmp', '/etc/passwd', '/etc/shadow', 'LinEnum', 'grab_keys', 'authorized_keys', 'shadow']
    df['is_sensitive_path'] = df['command_executed'].apply(lambda x: 1 if any(p in x for p in sensitive_paths) else 0)
    
    attack_tools = ['curl', 'openssl', 'tar', 'chmod', 'xxd', 'crontab', 'sudo', 'bash', 'sh', 'nc', 'ncat']
    df['is_attack_tool'] = df['a0'].apply(lambda x: 1 if x in attack_tools else 0)
    
    return df

def main():
    # 1. تحميل داتا الـ Auditd الكاملة (274 Benign و 159 Attack)
    benign_path = "data/processed/linux_auditd_benign.csv"
    attack_path = "data/processed/linux_auditd_attack.csv"

    df_benign = pd.read_csv(benign_path)
    df_attack = pd.read_csv(attack_path)

    df_benign['is_attack'] = 0
    df_attack['is_attack'] = 1

    # توحيد واستخراج session_id
    # إذا ما كان فيه عمود session_id صريح، نستخرجه من الملفات أو المصدر
    if 'session_id' not in df_benign.columns:
        df_benign['session_id'] = 'benign_session_01'
    if 'session_id' not in df_attack.columns:
        df_attack['session_id'] = 'attack_session_01'

    df_all = pd.concat([df_benign, df_attack], ignore_index=True)
    print(f"[*] Total Events: {len(df_all)} (Benign={len(df_benign)}, Attack={len(df_attack)})")
    print(f"[*] Total Sessions: {df_all['session_id'].nunique()} unique sessions")

    # 2. استخراج الميزات
    df_all = extract_features(df_all)

    # 3. Group Split حسب session_id عشان نمنع تسريب الجلسات تماماً
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    train_idx, test_idx = next(gss.split(df_all, groups=df_all['session_id']))

    train_df = df_all.iloc[train_idx].copy()
    test_df = df_all.iloc[test_idx].copy()

    # حساب a0_freq داخل الـ Train فقط
    a0_freq_map = train_df['a0'].value_counts(normalize=True).to_dict()
    train_df['a0_freq'] = train_df['a0'].map(a0_freq_map).fillna(0)
    test_df['a0_freq'] = test_df['a0'].map(a0_freq_map).fillna(0)

    feature_cols = ['argc', 'cmd_length', 'entropy', 'special_char_count', 'is_sensitive_path', 'is_attack_tool', 'a0_freq']

    X_train, y_train = train_df[feature_cols], train_df['is_attack']
    X_test, y_test = test_df[feature_cols], test_df['is_attack']

    print(f"[*] Train Events: {len(train_df)} | Test Events: {len(test_df)}")

    # 4. تدريب المودل الجديد
    clf = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42, class_weight='balanced')
    clf.fit(X_train, y_train)

    # 5. التقييم
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print("\n" + "="*50)
    print("نتائج تدريب المودل الجديد (Session-based Group Split):")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Attack'], digits=4))
    if len(np.unique(y_test)) > 1:
        print(f"ROC-AUC Score: {roc_auc_score(y_test, y_prob):.4f}")
    print("-" * 50)
    print(f"False Positives (FP) [إنذارات كاذبة]: {fp}")
    print(f"False Negatives (FN) [هجمات لم تُكتشف]: {fn}")
    print(f"True Positives  (TP) [هجمات مكتشفة]: {tp}")
    print(f"True Negatives  (TN) [سلوك طبيعي سليم]: {tn}")
    print("="*50)

if __name__ == "__main__":
    main()