import os
import glob
import pandas as pd

# قراءة البيانات الخام فقط من data واستثناء المخرجات و processed
csv_files = glob.glob('data/*.csv')
raw_files = [f for f in csv_files if 'output' not in f and 'predictions' not in f]

print(f"الملفات الخام المفحوصة: {raw_files}")

dataframes = []
for file in raw_files:
    try:
        temp = pd.read_csv(file, low_memory=False)
        dataframes.append(temp)
        print(f"الملف {file}: {len(temp)} صف, {temp.shape[1]} عمود")
    except Exception as e:
        print(f"خطأ في قراءة {file}: {e}")

if dataframes:
    df = pd.concat(dataframes, ignore_index=True)
    print("\n" + "="*40)
    print(f"إجمالي صفوف الداتا الخام: {len(df)}")
    print(f"إجمالي الأعمدة: {df.shape[1]}")
    if 'tactic' in df.columns:
        print("\nتوزيع الـ Tactics:")
        print(df['tactic'].value_counts(dropna=False))
    print("="*40)