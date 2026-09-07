import os
import sys
import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import classification_report, roc_auc_score

ROOT = Path(__file__).resolve().parents[2]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

def calculate_entropy(text):
    """حساب شانون انتروبي للأمر لاكتشاف التشفير والتشويش (Obfuscation / Base64)"""
    if not text or text == '-':
        return 0.0
    text_len = len(text)
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_advanced_features(df):
    """هندسة ميزات سلوكية متقدمة مع تجنب تسريب البيانات (No ground truth)"""
    df['command_executed'] = df['command_executed'].fillna('-').astype(str)
    df['a0'] = df['a0'].fillna('unknown').astype(str)
    df['argc'] = pd.to_numeric(df.get('argc', 1), errors='coerce').fillna(1)

    # 1. الميزات النصية
    df['cmd_length'] = df['command_executed'].apply(len)
    df['entropy'] = df['command_executed'].apply(calculate_entropy)

    # 2. فحص الرموز الخاصة المستخدمة في الهجمات (Pipes, Redirection, Chaining)
    special_chars = [';', '|', '&', '>', '<', '`', '$']
    df['special_char_count'] = df['command_executed'].apply(lambda cmd: sum(cmd.count(ch) for ch in special_chars))

    # 3. مسارات حساسة وأدوات شائعة في الهجمات
    sensitive_paths = ['/tmp', '/etc/passwd', '/etc/shadow', 'LinEnum', 'grab_keys', 'authorized_keys', 'shadow']
    df['is_sensitive_path'] = df['command_executed'].apply(lambda x: 1 if any(p in x for p in sensitive_paths) else 0)

    attack_tools = ['curl', 'openssl', 'tar', 'chmod', 'xxd', 'crontab', 'sudo', 'bash', 'sh', 'nc', 'ncat']
    df['is_attack_tool'] = df['a0'].apply(lambda x: 1 if x in attack_tools else 0)



    # 5. حساب الفارق الزمني لكل host
    if '@timestamp' in df.columns:
        df['datetime_temp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
        host_col = 'host.name' if 'host.name' in df.columns else ('host' if 'host' in df.columns else None)
        df['host_clean'] = df[host_col] if host_col else 'unknown'
        df = df.sort_values(by=['host_clean', 'datetime_temp']).reset_index(drop=True)
        df['time_delta'] = df.groupby('host_clean')['datetime_temp'].diff().dt.total_seconds().fillna(0)
    else:
        df['time_delta'] = 0.0

    features = [
    'argc',
    'cmd_length',
    'entropy',
    'special_char_count',
    'is_sensitive_path',
    'is_attack_tool',
    'time_delta'
]
    return df, features

def main():
    # 1. تحميل سجلات الهجوم
    DATASET_SLUG = os.getenv("CYBER_DATASET_SLUG", "apt41")

    attack_file = f"data/processed/{DATASET_SLUG}_clean.csv"

    if not os.path.exists(attack_file):
        raise FileNotFoundError(
            f"Clean dataset not found: {attack_file}. Run preprocessing first."
        )

    print(f"[*] قراءة بيانات الهجوم من: {attack_file}")
    df_attack = pd.read_csv(attack_file, low_memory=False)
    df_attack['is_attack'] = 1

    # 2. تحميل أو توليد السجلات الطبيعية
    benign_file = "data/processed/benign_synthetic_logs.csv"
    if not os.path.exists(benign_file):
        from src.preprocessing.generate_benign_logs import generate_benign_events
        df_benign = generate_benign_events(num_samples=len(df_attack) * 3)
    else:
        df_benign = pd.read_csv(benign_file)

    # 3. توحيد ودمج البيانات
    common_cols = ['_id', '@timestamp', 'command_executed', 'a0', 'argc', 'is_attack']
    host_src = 'host.name' if 'host.name' in df_attack.columns else 'host'
    df_attack['host_canonical'] = df_attack[host_src] if host_src in df_attack.columns else '4fa5a8bb3a60'
    df_benign['host_canonical'] = df_benign['host.name'] if 'host.name' in df_benign.columns else 'srv-app-prod-01'

    df_attack = df_attack.rename(columns={'host_canonical': 'host'})
    df_benign = df_benign.rename(columns={'host_canonical': 'host'})

    df_combined = pd.concat([df_attack, df_benign], ignore_index=True)

    # 4. استخراج الـ Features
    df_combined, feature_cols = extract_advanced_features(df_combined)
    X = df_combined[feature_cols]
    y = df_combined['is_attack']

    print(f"[*] إجمالي العينات: {len(X)} | عينات الهجوم: {y.sum()} | عينات طبيعية: {len(y) - y.sum()}")

    # 5. تدريب النموذج مع Cross Validation لتقييم واقعي
    clf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42, class_weight='balanced')
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

    # الحصول على احتمالية التنبؤ لكل حدث
    probabilities = cross_val_predict(clf, X, y, cv=cv, method='predict_proba')[:, 1]
    clf.fit(X, y)

    # 6. المقاييس التشخيصية
    predictions = (probabilities >= 0.5).astype(int)
    print("\n" + "="*50)
    print("نتائج تقييم النموذج (Cross-Validated Metrics):")
    print(classification_report(y, predictions, target_names=['Benign', 'Attack']))
    print(f"ROC-AUC Score: {roc_auc_score(y, probabilities):.4f}")
    print("="*50)

    # 7. التصدير المطابق للمواصفات القياسية (docs/ml-interface.md)
    df_combined['ml_score'] = np.round(probabilities, 4)
    df_combined['ml_label'] = df_combined['ml_score'].apply(lambda s: 'High Risk' if s >= 0.75 else ('Medium Risk' if s >= 0.40 else 'Low Risk'))
    df_combined['model_name'] = 'RandomForest_Supervised_v1'

    # الحفاظ على canonical event_id
    if 'event_id' not in df_combined.columns:
        if '_id' in df_combined.columns:
            df_combined['event_id'] = df_combined['_id']
        else:
            df_combined['event_id'] = [f"event_{i}" for i in range(len(df_combined))]

    # الاقتصار فقط على الأحداث المرتبطة بسجلات المشروع الأساسية للحفاظ على سلامة الداشبورد
    final_output = df_combined[df_combined['is_attack'] == 1].copy()

    required_cols = ['event_id', '@timestamp', 'host', 'ml_score', 'ml_label', 'model_name']
    out_df = final_output[required_cols]

    out_csv = "data/processed/ml_predictions.csv"
    out_df.to_csv(out_csv, index=False)
    print(f"\n[+] تم تحديث ملف المخرجات النهائي المتوافق مع الداشبورد: {out_csv}")

if __name__ == "__main__":
    main()