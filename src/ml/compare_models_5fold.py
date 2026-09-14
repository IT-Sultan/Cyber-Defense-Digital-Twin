import os, math
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

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
    
    sensitive_paths = ['/tmp', '/etc/passwd', '/etc/shadow', 'LinEnum', 'grab_keys', 'authorized_keys', 'shadow']
    df['is_sensitive_path'] = df['command_executed'].apply(lambda x: 1 if any(p in x for p in sensitive_paths) else 0)
    
    attack_tools = ['curl', 'openssl', 'tar', 'chmod', 'xxd', 'crontab', 'sudo', 'bash', 'sh', 'nc', 'ncat']
    df['is_attack_tool'] = df['a0'].apply(lambda x: 1 if x in attack_tools else 0)
    return df

def find_best_threshold_on_train(X_train, y_train, clf):
    """تحديد الـ threshold الأمثل من بيانات التدريب فقط لمنع أي تسريب"""
    train_probs = clf.predict_proba(X_train)[:, 1]
    best_th = 0.50
    best_f1 = -1.0
    for th in np.arange(0.40, 0.85, 0.05):
        preds = (train_probs >= th).astype(int)
        score = f1_score(y_train, preds, zero_division=0)
        if score > best_f1:
            best_f1 = score
            best_th = th
    return round(best_th, 2)

def main():
    # 1. تجهيز بيانات الاختبار الـ 5 جلسات (Auditd)
    attack_dfs = []
    for i in range(1, 6):
        f = f"data/processed/auditd_attack/attack_session_0{i}.csv"
        df = pd.read_csv(f)
        df['session_id'] = f"session_0{i}"
        df['is_attack'] = 1
        attack_dfs.append(df)
    attack_all = pd.concat(attack_dfs, ignore_index=True)

    benign_raw = pd.read_csv("data/processed/linux_auditd_benign.csv")
    benign_raw['is_attack'] = 0
    chunk_size = math.ceil(len(benign_raw) / 5)
    sessions = []
    for i in range(5):
        sessions.extend([f"session_0{i+1}"] * chunk_size)
    benign_raw['session_id'] = sessions[:len(benign_raw)]

    full_auditd = pd.concat([attack_all, benign_raw], ignore_index=True)
    full_auditd = extract_features(full_auditd)

    # 2. تجهيز وتدريب المودل القديم (Legacy Model) على بيانات APT41 الأصلية
    legacy_file = "data/processed/apt41_clean.csv"
    raw_legacy = pd.read_csv(legacy_file)
    raw_legacy['is_attack'] = 1
    # عينة سليم قديمة (أول 15 حدث auditd قديمة)
    benign_old = benign_raw.iloc[:15].copy()
    benign_old['is_attack'] = 0
    
    df_legacy = pd.concat([raw_legacy, benign_old], ignore_index=True)
    df_legacy = extract_features(df_legacy)
    legacy_a0_map = df_legacy['a0'].value_counts(normalize=True).to_dict()
    df_legacy['a0_freq'] = df_legacy['a0'].map(legacy_a0_map).fillna(0)

    feature_cols = ['argc', 'cmd_length', 'entropy', 'special_char_count', 'is_sensitive_path', 'is_attack_tool', 'a0_freq']
    
    clf_legacy = RandomForestClassifier(n_estimators=100, max_depth=4, random_state=42, class_weight='balanced')
    clf_legacy.fit(df_legacy[feature_cols], df_legacy['is_attack'])

    # 3. تشغيل الـ 5 Folds للمقارنة 1:1
    folds = [f"session_0{i}" for i in range(1, 6)]
    
    res_old = []
    res_new = []
    chosen_thresholds = []

    total_fp_old, total_fn_old = 0, 0
    total_fp_new, total_fn_new = 0, 0

    for sess in folds:
        test_df = full_auditd[full_auditd['session_id'] == sess].copy()
        train_df = full_auditd[full_auditd['session_id'] != sess].copy()

        # أ) معالجة المودل الجديد (حساب a0_freq من Train فقط)
        a0_map = train_df['a0'].value_counts(normalize=True).to_dict()
        train_df['a0_freq'] = train_df['a0'].map(a0_map).fillna(0)
        test_df['a0_freq'] = test_df['a0'].map(a0_map).fillna(0)

        X_train, y_train = train_df[feature_cols], train_df['is_attack']
        X_test, y_test = test_df[feature_cols], test_df['is_attack']

        clf_new = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42, class_weight='balanced')
        clf_new.fit(X_train, y_train)

        # اختيار الـ threshold من الـ Train فقط!
        th = find_best_threshold_on_train(X_train, y_train, clf_new)
        chosen_thresholds.append(th)

        probs_new = clf_new.predict_proba(X_test)[:, 1]
        preds_new = (probs_new >= th).astype(int)

        cm_n = confusion_matrix(y_test, preds_new)
        total_fp_new += cm_n[0,1]
        total_fn_new += cm_n[1,0]
        res_new.append({
            'prec': precision_score(y_test, preds_new, zero_division=0),
            'rec': recall_score(y_test, preds_new, zero_division=0),
            'f1': f1_score(y_test, preds_new, zero_division=0),
            'auc': roc_auc_score(y_test, probs_new) if len(np.unique(y_test)) > 1 else 0.5
        })

        # ب) اختبار المودل القديم على نفس بيانات الـ Test بالضبط
        test_legacy = test_df.copy()
        test_legacy['a0_freq'] = test_legacy['a0'].map(legacy_a0_map).fillna(0)
        probs_old = clf_legacy.predict_proba(test_legacy[feature_cols])[:, 1]
        preds_old = (probs_old >= 0.50).astype(int)

        cm_o = confusion_matrix(y_test, preds_old)
        total_fp_old += cm_o[0,1]
        total_fn_old += cm_o[1,0]
        res_old.append({
            'prec': precision_score(y_test, preds_old, zero_division=0),
            'rec': recall_score(y_test, preds_old, zero_division=0),
            'f1': f1_score(y_test, preds_old, zero_division=0),
            'auc': roc_auc_score(y_test, probs_old) if len(np.unique(y_test)) > 1 else 0.5
        })

    df_old = pd.DataFrame(res_old)
    df_new = pd.DataFrame(res_new)

    print("="*65)
    print("1:1 COMPARISON: LEGACY MODEL VS RETRAINED MODEL (5-FOLD CV)")
    print("="*65)
    print(f"Optimal Thresholds tuned strictly on Train sets: {chosen_thresholds} (Mean: {np.mean(chosen_thresholds):.2f})\n")

    print(f"--- 1. LEGACY MODEL (Trained on APT41 Baseline) ---")
    print(f"Precision : {df_old['prec'].mean():.4f} ± {df_old['prec'].std():.4f}")
    print(f"Recall    : {df_old['rec'].mean():.4f} ± {df_old['rec'].std():.4f}")
    print(f"F1-Score  : {df_old['f1'].mean():.4f} ± {df_old['f1'].std():.4f}")
    print(f"ROC-AUC   : {df_old['auc'].mean():.4f} ± {df_old['auc'].std():.4f}")
    print(f"Total FP  : {total_fp_old} | Total FN: {total_fn_old}\n")

    print(f"--- 2. RETRAINED MODEL (Trained on Auditd Telemetry with Train-Tuned Thresholds) ---")
    print(f"Precision : {df_new['prec'].mean():.4f} ± {df_new['prec'].std():.4f}")
    print(f"Recall    : {df_new['rec'].mean():.4f} ± {df_new['rec'].std():.4f}")
    print(f"F1-Score  : {df_new['f1'].mean():.4f} ± {df_new['f1'].std():.4f}")
    print(f"ROC-AUC   : {df_new['auc'].mean():.4f} ± {df_new['auc'].std():.4f}")
    print(f"Total FP  : {total_fp_new} | Total FN: {total_fn_new}")
    print("="*65)

if __name__ == "__main__":
    main()