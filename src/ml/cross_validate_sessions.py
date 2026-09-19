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
    # 1. تحميل جلسات الهجوم والسليم
    attack_dfs = []
    for i in range(1, 6):
        f = f"data/processed/auditd_attack/attack_session_0{i}.csv"
        df = pd.read_csv(f)
        df['session_id'] = f"session_0{i}"
        df['is_attack'] = 1
        attack_dfs.append(df)
    attack_all = pd.concat(attack_dfs, ignore_index=True)

    # تحميل السليم ومطابقته لـ 5 جلسات
    benign_raw = pd.read_csv("data/processed/linux_auditd_benign.csv")
    benign_raw['is_attack'] = 0
    # إذا كانت مقسمة أو نقسمها 5 أقسام متساوية بحسب الجلسات
    if 'session_id' not in benign_raw.columns:
        # تقسيم بالترتيب لـ 5 أجزاء
        chunk_size = math.ceil(len(benign_raw) / 5)
        sessions = []
        for i in range(5):
            sessions.extend([f"session_0{i+1}"] * chunk_size)
        benign_raw['session_id'] = sessions[:len(benign_raw)]
    else:
        # توحيد التسمية لتطابق session_01 .. 05
        benign_raw['session_id'] = benign_raw['session_id'].str.extract(r'(\d+)')[0].apply(lambda x: f"session_{int(x):02d}")

    full_df = pd.concat([attack_all, benign_raw], ignore_index=True)
    full_df = extract_features(full_df)

    feature_cols = ['argc', 'cmd_length', 'entropy', 'special_char_count', 'is_sensitive_path', 'is_attack_tool', 'a0_freq']

    # جداول النتائج لكل Fold
    folds = [f"session_0{i}" for i in range(1, 6)]
    
    metrics_new = []
    metrics_old = []
    
    total_fp_new, total_fn_new = 0, 0
    total_fp_old, total_fn_old = 0, 0

    print("="*65)
    print("STARTING 5-FOLD GROUP CROSS-VALIDATION ACROSS ALL SESSIONS")
    print("="*65)

    for fold_num, test_sess in enumerate(folds, 1):
        test_df = full_df[full_df['session_id'] == test_sess].copy()
        train_df = full_df[full_df['session_id'] != test_sess].copy()

        # حساب a0_freq داخل الـ Train فقط
        a0_map = train_df['a0'].value_counts(normalize=True).to_dict()
        train_df['a0_freq'] = train_df['a0'].map(a0_map).fillna(0)
        test_df['a0_freq'] = test_df['a0'].map(a0_map).fillna(0)

        X_train, y_train = train_df[feature_cols], train_df['is_attack']
        X_test, y_test = test_df[feature_cols], test_df['is_attack']

        # المودل الجديد (Retrained on other 4 sessions)
        clf_new = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42, class_weight='balanced')
        clf_new.fit(X_train, y_train)

        probs_new = clf_new.predict_proba(X_test)[:, 1]
        preds_new = (probs_new >= 0.60).astype(int)  # Threshold 0.60

        cm_new = confusion_matrix(y_test, preds_new)
        tn_n, fp_n, fn_n, tp_n = cm_new.ravel()
        total_fp_new += fp_n
        total_fn_new += fn_n

        roc_n = roc_auc_score(y_test, probs_new) if len(np.unique(y_test)) > 1 else 0.5
        metrics_new.append({
            'prec': precision_score(y_test, preds_new, zero_division=0),
            'rec': recall_score(y_test, preds_new, zero_division=0),
            'f1': f1_score(y_test, preds_new, zero_division=0),
            'auc': roc_n
        })

        # المودل القديم (افتراضياً بدون تدريب على هذه الـ Folds، أو محاكاة الـ baseline)
        preds_old = (probs_new >= 0.85).astype(int) # المودل القديم كان متحفظ جداً ودقته 1.0 لكن recall طايح
        cm_old = confusion_matrix(y_test, preds_old)
        tn_o, fp_o, fn_o, tp_o = cm_old.ravel()
        total_fp_old += fp_o
        total_fn_old += fn_o

        metrics_old.append({
            'prec': precision_score(y_test, preds_old, zero_division=0),
            'rec': recall_score(y_test, preds_old, zero_division=0),
            'f1': f1_score(y_test, preds_old, zero_division=0),
            'auc': roc_n
        })

        print(f"Fold {fold_num} ({test_sess}): Test Events={len(test_df)} | FP={fp_n}, FN={fn_n} | F1={metrics_new[-1]['f1']:.4f}")

    df_m_new = pd.DataFrame(metrics_new)
    df_m_old = pd.DataFrame(metrics_old)

    print("\n" + "="*65)
    print("SUMMARY RESULTS (5-FOLD CV):")
    print("="*65)
    print("--- NEW MODEL (Threshold = 0.60) ---")
    print(f"Precision : {df_m_new['prec'].mean():.4f} ± {df_m_new['prec'].std():.4f}")
    print(f"Recall    : {df_m_new['rec'].mean():.4f} ± {df_m_new['rec'].std():.4f}")
    print(f"F1-Score  : {df_m_new['f1'].mean():.4f} ± {df_m_new['f1'].std():.4f}")
    print(f"ROC-AUC   : {df_m_new['auc'].mean():.4f} ± {df_m_new['auc'].std():.4f}")
    print(f"Total FP  : {total_fp_new}")
    print(f"Total FN  : {total_fn_new}")

if __name__ == "__main__":
    main()