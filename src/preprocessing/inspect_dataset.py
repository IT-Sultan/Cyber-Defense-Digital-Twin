import os
import glob
import pandas as pd

# 1. فحص ملفات الحملات المتوفرة
csv_files = glob.glob('**/*.csv', recursive=True)
print(f"الملفات الموجودة بالمشروع: {csv_files}")

# قراءة البيانات
dataframes = []
for file in csv_files:
    if 'output' not in file: # استبعاد ملفات المخرجات
        try:
            temp = pd.read_csv(file, low_memory=False)
            dataframes.append(temp)
            print(f"الملف {file}: {len(temp)} صف, {temp.shape[1]} عمود")
        except Exception as e:
            print(f"خطأ في قراءة {file}: {e}")

if dataframes:
    df = pd.concat(dataframes, ignore_index=True)
    print("\n" + "="*40)
    print(f"إجمالي عدد الصفوف (Rows): {len(df)}")
    print(f"إجمالي عدد الأعمدة (Columns): {df.shape[1]}")
    
    # فحص توزيع التكتيكات والـ Labels
    if 'tactic' in df.columns:
        print("\nتوزيع الـ Tactics:")
        print(df['tactic'].value_counts(dropna=False))
        
    if 'technique' in df.columns:
        print(f"\nعدد الـ Unique Techniques: {df['technique'].nunique()}")
        
    print("="*40)