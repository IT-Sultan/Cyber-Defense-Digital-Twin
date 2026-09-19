import os, math
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score

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
    sensitive_targets = ['/etc/passwd', '/etc/shadow', 'linenum', 'grab_keys', 'authorized_keys', '/tmp/malicious', '/tmp/reports.xlsm']
    df['has_sensitive_path'] = df['command_executed'].apply(lambda x: 1 if any(p in x.lower() for p in sensitive_targets) else 0)
    attack_tools = ['curl', 'openssl', 'tar', 'chmod', 'xxd', 'crontab', 'sudo', 'bash', 'sh', 'nc', 'ncat']
    df['is_attack_tool'] = df['a0'].apply(lambda x: 1 if x in attack_tools else 0)
    return df

def main():
    # 1. تخصيص Holdout حقيقي معزول تماماً (مثلاً attack_session_05 مع benign_session_05)
    print("[+] Loading True Holdout Dataset...")
    
    # تدريب المودل على باقي الجلسات (1 إلى 4) فقط
    attack_train_dfs = []
    for i in range(1, 5):
        f = f"data/processed/auditd_attack/attack_session_0{i}.csv"
        d = pd.read_csv(f)
        d['is_attack'] = 1
        attack_train_dfs.append(d)
    train_attack = pd.concat(attack_train_dfs, ignore_index=True)
    
    benign_raw = pd.read_csv("data/processed/linux_auditd_benign.csv")
    benign_raw['is_attack'] = 0
    # عزل آخر 20% من السليم كـ Holdout benign
    split_idx = int(len(benign_raw) * 0.8)
    train_benign = benign_raw.iloc[:split_idx].copy()
    holdout_benign = benign_raw.iloc[split_idx:].copy()
    holdout_benign['session_id'] = 'holdout_benign'

    # Holdout Attack الفعلي
    holdout_attack = pd.read_csv("data/processed/auditd_attack/attack_session_05.csv")
    holdout_attack['is_attack'] = 1
    holdout_attack['session_id'] = 'holdout_attack_05'

    # دمج بيانات التدريب
    train_full = pd.concat([train_attack, train_benign], ignore_index=True)
    train_full = extract_features(train_full)

    # دمج بيانات الـ Holdout الفعلي (Attack + Benign معاً)
    holdout_full = pd.concat([holdout_attack, holdout_benign], ignore_index=True)
    holdout_full = extract_features(holdout_full)

    # استخراج a0_map من الـ Train فقط
    a0_map = train_full['a0'].value_counts(normalize=True).to_dict()
    train_full['a0_freq'] = train_full['a0'].map(a0_map).fillna(0)
    holdout_full['a0_freq'] = holdout_full['a0'].map(a0_map).fillna(0)

    feature_cols = ['argc', 'cmd_length', 'entropy', 'special_char_count', 'has_sensitive_path', 'is_attack_tool', 'a0_freq']

    # 2. تدريب المودل
    clf = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42, class_weight='balanced')
    clf.fit(train_full[feature_cols], train_full['is_attack'])

    # 3. التقييم الصارم على الـ Holdout بدون أي tuning (Threshold ثابت = 0.60)
    THRESHOLD = 0.60
    probs = clf.predict_proba(holdout_full[feature_cols])[:, 1]
    preds = (probs >= THRESHOLD).astype(int)
    y_true = holdout_full['is_attack']

    cm = confusion_matrix(y_true, preds)
    tn, fp, fn, tp = cm.ravel()

    precision = precision_score(y_true, preds, zero_division=0)
    recall = recall_score(y_true, preds, zero_division=0)
    f1 = f1_score(y_true, preds, zero_division=0)
    auc = roc_auc_score(y_true, probs) if len(np.unique(y_true)) > 1 else 0.5
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0

    print("="*60)
    print("TRUE HOLDOUT EVALUATION RESULTS (Threshold = 0.60):")
    print("="*60)
    print(f"Total Holdout Samples : {len(holdout_full)} (Attack: {len(holdout_attack)}, Benign: {len(holdout_benign)})")
    print(f"Confusion Matrix       -> TN: {tn} | FP: {fp} | FN: {fn} | TP: {tp}")
    print(f"Precision              : {precision:.4f}")
    print(f"Recall                 : {recall:.4f}")
    print(f"F1-Score               : {f1:.4f}")
    print(f"ROC-AUC                : {auc:.4f}")
    print(f"False Positive Rate    : {fpr:.2%}")
    print(f"Specificity (Benign)   : {specificity:.4%}")
    print("="*60)

if __name__ == "__main__":
    main()