import os
import re
import pandas as pd
from datetime import datetime

def parse_auditd_log(log_path="data/raw/linux_audit.log", output_path="data/processed/linux_auditd_benign.csv"):
    """
    تحويل سجلات Linux Auditd الخام (SYSCALL + EXECVE) إلى جدول منظم 
    متوافق تماماً مع Schema بيانات المشروع
    """
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"لم يتم العثور على ملف السجلات: {log_path}")

    events = {}
    event_order = []

    with open(log_path, 'r', encoding='utf-8') as f:
        for line in f:
            # استخراج معرف الحدث والوقت: audit(timestamp.millisec:event_seq)
            match = re.search(r'msg=audit\((\d+\.\d+):(\d+)\)', line)
            if not match:
                continue
            
            ts_epoch, seq = match.groups()
            event_key = f"{ts_epoch}:{seq}"
            
            if event_key not in events:
                events[event_key] = {
                    'timestamp_epoch': float(ts_epoch),
                    'seq': seq,
                    'exe': None,
                    'argc': 1,
                    'args': []
                }
                event_order.append(event_key)

            if "type=SYSCALL" in line:
                exe_match = re.search(r'exe="([^"]+)"', line)
                if exe_match:
                    events[event_key]['exe'] = exe_match.group(1)

            elif "type=EXECVE" in line:
                argc_match = re.search(r'argc=(\d+)', line)
                if argc_match:
                    events[event_key]['argc'] = int(argc_match.group(1))
                
                # استخراج جميع المعاملات a0, a1, a2...
                args = re.findall(r'a\d+="?([^" \n]+)"?', line)
                events[event_key]['args'] = args

    # تجميع الأحداث وتحويلها لصيغة المشروع
    parsed_records = []
    for k in event_order:
        data = events[k]
        dt = datetime.utcfromtimestamp(data['timestamp_epoch'])
        iso_timestamp = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        args = data['args']
        a0 = args[0] if args else (os.path.basename(data['exe']) if data['exe'] else 'unknown')
        command_str = " ".join(args) if args else (data['exe'] or 'unknown')

        parsed_records.append({
            '_id': f"auditd_real_{data['seq']}",
            '@timestamp': iso_timestamp,
            'host.name': '4fa5a8bb3a60', # الهوست المشترك في المشروع
            'command_executed': command_str,
            'a0': a0,
            'argc': data['argc'],
            'is_attack': 0
        })

    df = pd.DataFrame(parsed_records)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[+] نجح استخراج {len(df)} حدث Auditd حقيقي وحفظها في: {output_path}")
    return df

if __name__ == "__main__":
    parse_auditd_log()