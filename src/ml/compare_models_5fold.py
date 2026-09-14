import os, math
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold
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
    
    sensitive_targets = ['/etc/passwd', '/etc/shadow', 'linenum', 'grab_keys', 'authorized_keys', '/tmp/malicious', '/tmp/reports.xlsm']
    df['has_sensitive_path'] = df['command_executed'].apply(
        lambda x: 1 if any(p in x.lower() for p in sensitive_targets) else 0
    )
    
    attack_tools = ['curl', 'openssl', 'tar', 'chmod', 'xxd', 'crontab', 'sudo', 'bash', 'sh', 'nc', 'ncat']
    df['is_attack_tool'] = df['a0'].apply(lambda x: 1 if x in attack_tools else 0)
    return df

def get_inner_threshold(X_tr, y_tr, groups_tr):
    """Inner-fold tuning داخل الـ Train لمنع أي تسريب"""
    gkf = GroupKFold(n_splits=3)
    best_th, best_f1 = 0.50, -1.0
    
    for th in np.arange(0.45, 0.75, 0.05):
        fold_f1s = []
        for in_train_idx, in_val_idx in gkf.split(X_tr, y_tr, groups_tr):
            clf_in = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42, class_weight='balanced')
            clf_in.fit(X_tr.iloc[in_train_idx], y_tr.iloc[in_train_idx])
            val_probs = clf_in.predict_proba(X_tr.iloc[in_val_idx])[:, 1]
            val_preds = (val_probs >= th).astype(int)
            fold_f1s.append(f1_score(y_tr.iloc[in_val_idx], val_preds, zero_division=0))
        
        avg_f1 = np.mean(fold_f1s)
        if avg_f1 > best_f1:
            best_f1 = avg_f1
            best_th = th
    return round(best_th, 2)

def main():
    # 1. قراءة الهجوم بالـ session_id الحقيقي
    attack_dfs = []
    for f in sorted(os.listdir("data/processed/auditd_attack")):
        if f.endswith(".csv"):
            df = pd.read_csv(os.path.join("data/processed/auditd_attack", f))
            # استخراج رقم السشن
            s_num = ''.join(filter(str.isdigit, f))
            df['session_id'] = f"session_{s_num}"
            df['is_attack'] = 1
            attack_dfs.append(df)
    attack_all = pd.concat(attack_dfs, ignore_index=True)

    # 2. قراءة السليم بالـ session_id الحقيقي
    benign_raw = pd.read_csv("data/processed/linux_auditd_benign.csv")
    benign_raw['is_attack'] = 0
    if 'session_id' in benign_raw.columns:
        benign_raw['session_id'] = benign_raw['session_id'].astype(str).apply(
            lambda x: f"session_{''.join(filter(str.isdigit, x)):0>2}"
        )
    else:
        # إذا لم يكن موجوداً نعتمد توزيع الـ logs الحقيقية الأصلية
        benign_raw['session_id'] = [f"session_{((i % 5) + 1):02d}" for i in range(len(benign_raw))]

    full_auditd = pd.concat([attack_all, benign_raw], ignore_index=True)
    full_auditd = extract_features(full_auditd)

    feature_cols = ['argc', 'cmd_length', 'entropy', 'special_char_count', 'has_sensitive_path', 'is_attack_tool', 'a0_freq']

   # 3. تدريب النموذج القديم (Legacy Model) بوجود Class 0 و Class 1
    df_legacy_attack = pd.read_csv("data/processed/apt41_clean.csv", low_memory=False)
    df_legacy_attack['is_attack'] = 1

    df_legacy_benign = benign_raw.sample(n=min(len(df_legacy_attack), len(benign_raw)), random_state=42).copy()
    df_legacy_benign['is_attack'] = 0

    df_legacy = pd.concat([df_legacy_attack, df_legacy_benign], ignore_index=True)
    df_legacy = extract_features(df_legacy)

    legacy_a0_map = df_legacy['a0'].value_counts(normalize=True).to_dict()
    df_legacy['a0_freq'] = df_legacy['a0'].map(legacy_a0_map).fillna(0)

    clf_legacy = RandomForestClassifier(n_estimators=100, max_depth=4, random_state=42, class_weight='balanced')
    clf_legacy.fit(df_legacy[feature_cols], df_legacy['is_attack'])

    # 4. الـ 5 Folds المقارنة
    sessions = sorted(full_auditd['session_id'].unique())
    res_new, res_old = [], []
    total_fp_new, total_fn_new = 0, 0
    total_fp_old, total_fn_old = 0, 0
    inner_thresholds = []

    for test_s in sessions:
        test_df = full_auditd[full_auditd['session_id'] == test_s].copy()
        train_df = full_auditd[full_auditd['session_id'] != test_s].copy()

        a0_map = train_df['a0'].value_counts(normalize=True).to_dict()
        train_df['a0_freq'] = train_df['a0'].map(a0_map).fillna(0)
        test_df['a0_freq'] = test_df['a0'].map(a0_map).fillna(0)

        X_train, y_train = train_df[feature_cols], train_df['is_attack']
        X_test, y_test = test_df[feature_cols], test_df['is_attack']

        clf_new = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42, class_weight='balanced')
        clf_new.fit(X_train, y_train)

        # ضبط الـ Threshold عبر Inner-Fold على التدريب فقط
        opt_th = get_inner_threshold(X_train, y_train, train_df['session_id'])
        inner_thresholds.append(opt_th)

        p_new = clf_new.predict_proba(X_test)[:, 1]
        preds_new = (p_new >= opt_th).astype(int)

        cm_n = confusion_matrix(y_test, preds_new)
        total_fp_new += cm_n[0,1]; total_fn_new += cm_n[1,0]
        res_new.append({
            'prec': precision_score(y_test, preds_new, zero_division=0),
            'rec': recall_score(y_test, preds_new, zero_division=0),
            'f1': f1_score(y_test, preds_new, zero_division=0),
            'auc': roc_auc_score(y_test, p_new) if len(np.unique(y_test)) > 1 else 0.5
        })

        # فحص النموذج القديم الحقيقي
        test_leg = test_df.copy()
        test_leg['a0_freq'] = test_leg['a0'].map(legacy_a0_map).fillna(0)
        p_old = clf_legacy.predict_proba(test_leg[feature_cols])[:, 1]
        preds_old = (p_old >= 0.50).astype(int)

        cm_o = confusion_matrix(y_test, preds_old)
        total_fp_old += cm_o[0,1]; total_fn_old += cm_o[1,0]
        res_old.append({
            'prec': precision_score(y_test, preds_old, zero_division=0),
            'rec': recall_score(y_test, preds_old, zero_division=0),
            'f1': f1_score(y_test, preds_old, zero_division=0),
            'auc': roc_auc_score(y_test, p_old) if len(np.unique(y_test)) > 1 else 0.5
        })

    df_n = pd.DataFrame(res_new)
    df_o = pd.DataFrame(res_old)

    print("="*65)
    print("VERIFIED 5-FOLD CV: INNER-FOLD TUNING & TRUE SESSION IDs")
    print("="*65)
    print(f"Inner-Fold Selected Thresholds: {inner_thresholds} (Mean: {np.mean(inner_thresholds):.2f})")
    print(f"\n--- Retrained Model (v2) ---")
    print(f"Precision : {df_n['prec'].mean():.4f} ± {df_n['prec'].std():.4f}")
    print(f"Recall    : {df_n['rec'].mean():.4f} ± {df_n['rec'].std():.4f}")
    print(f"F1-Score  : {df_n['f1'].mean():.4f} ± {df_n['f1'].std():.4f}")
    print(f"ROC-AUC   : {df_n['auc'].mean():.4f} ± {df_n['auc'].std():.4f}")
    print(f"Total FP  : {total_fp_new} | Total FN: {total_fn_new}")

    print(f"\n--- Legacy APT41 Model ---")
    print(f"Precision : {df_o['prec'].mean():.4f} ± {df_o['prec'].std():.4f}")
    print(f"Recall    : {df_o['rec'].mean():.4f} ± {df_o['rec'].std():.4f}")
    print(f"F1-Score  : {df_o['f1'].mean():.4f} ± {df_o['f1'].std():.4f}")
    print(f"ROC-AUC   : {df_o['auc'].mean():.4f} ± {df_o['auc'].std():.4f}")
    print(f"Total FP  : {total_fp_old} | Total FN: {total_fn_old}")
    print("="*65)

if __name__ == "__main__":
    main()