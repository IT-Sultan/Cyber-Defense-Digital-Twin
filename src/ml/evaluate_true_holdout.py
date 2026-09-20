import os, math
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score

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
    print("[+] Loading True Holdout Dataset with True Session IDs...")
    
    # 1. تجميع جلسات الهجوم والسليم بالـ session_id الحقيقي
    attack_dfs = []
    for i in range(1, 6):
        f = f"data/processed/auditd_attack/attack_session_0{i}.csv"
        d = pd.read_csv(f)
        d['session_id'] = f"attack_session_0{i}"
        d['is_attack'] = 1
        attack_dfs.append(d)
    attack_all = pd.concat(attack_dfs, ignore_index=True)

    benign_raw = pd.read_csv("data/processed/linux_auditd_benign.csv")
    benign_raw['is_attack'] = 0
    if 'session_id' not in benign_raw.columns:
        benign_raw['session_id'] = [f"benign_session_0{(i % 5) + 1}" for i in range(len(benign_raw))]
    else:
        benign_raw['session_id'] = benign_raw['session_id'].astype(str).apply(
            lambda x: f"benign_session_{''.join(filter(str.isdigit, x)):0>2}"
        )

    full_auditd = pd.concat([attack_all, benign_raw], ignore_index=True)

    # 2. عزل جلسة 05 بالكامل (هجوم وسليم) كـ True Holdout حقيقي
    holdout_sessions = ['attack_session_05', 'benign_session_05']
    
    holdout_full = full_auditd[full_auditd['session_id'].isin(holdout_sessions)].copy()
    train_full = full_auditd[~full_auditd['session_id'].isin(holdout_sessions)].copy()

    # 3. Assert صارم للتأكد من عدم وجود أي تداخل (Leakage Prevention)
    train_sess_set = set(train_full['session_id'].unique())
    holdout_sess_set = set(holdout_full['session_id'].unique())
    assert len(train_sess_set.intersection(holdout_sess_set)) == 0, "[!] ERROR: Leakage detected! Holdout sessions exist in train set."

    # استخراج الفيتشرز
    train_full = extract_features(train_full)
    holdout_full = extract_features(holdout_full)

    # حساب a0_map من الـ Train فقط
    a0_map = train_full['a0'].value_counts(normalize=True).to_dict()
    train_full['a0_freq'] = train_full['a0'].map(a0_map).fillna(0)
    holdout_full['a0_freq'] = holdout_full['a0'].map(a0_map).fillna(0)

    feature_cols = ['argc', 'cmd_length', 'entropy', 'special_char_count', 'has_sensitive_path', 'is_attack_tool', 'a0_freq']

    # 4. التدريب والتقييم بـ Threshold ثابت = 0.60
    clf = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42, class_weight='balanced')
    clf.fit(train_full[feature_cols], train_full['is_attack'])

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
    print("TRUE HOLDOUT EVALUATION (True Session Isolation - Session 05):")
    print("="*60)
    print(f"Train Sessions         : {sorted(list(train_sess_set))}")
    print(f"Holdout Sessions       : {sorted(list(holdout_sess_set))}")
    print(f"Total Holdout Samples  : {len(holdout_full)} (Attack: {len(holdout_full[holdout_full['is_attack']==1])}, Benign: {len(holdout_full[holdout_full['is_attack']==0])})")
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