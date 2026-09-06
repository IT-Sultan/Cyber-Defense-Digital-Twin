import os
import random
import pandas as pd
from datetime import datetime, timedelta

def generate_benign_events(num_samples=150, start_time="2024-06-18T10:00:00Z"):
    hosts = ['4fa5a8bb3a60'] # نفس الهوست عشان ما يفرق المودل بالاسم
    
    # أوامر طبيعية واقعية فيها أوامر طويلة ومعقدة تشبه شغل الـ SysAdmins
    benign_commands = [
        ("ls -la /var/log", "ls", 3),
        ("cat /etc/hosts", "cat", 2),
        ("df -h", "df", 2),
        ("uptime", "uptime", 1),
        ("tar -czf /tmp/backup_config.tar.gz /etc/nginx/", "tar", 4), # أمر طبيعي بس فيه tar و tmp
        ("chmod 644 /var/www/html/index.nginx-debian.html", "chmod", 3), # chmod طبيعي
        ("curl -s http://localhost:80/healthz", "curl", 3), # curl طبيعي لفحص السيرفر
        ("python3 -m pip list --outdated", "python3", 4),
        ("find /var/log -type f -name '*.log' -mtime +30", "find", 6),
        ("systemctl restart systemd-journald.service", "systemctl", 3),
        ("grep -rn 'ERROR' /var/log/syslog | tail -n 20", "grep", 7),
        ("sudo -u www-data php /var/www/artisan schedule:run", "sudo", 5),
        ("bash /opt/scripts/daily_cleanup.sh", "bash", 3),
        ("crontab -l", "crontab", 2)
    ]

    base_dt = pd.to_datetime(start_time)
    records = []

    for i in range(num_samples):
        cmd, a0, argc = random.choice(benign_commands)
        time_offset = random.randint(5, 300)
        base_dt += timedelta(seconds=time_offset)
        
        record = {
            '_id': f"benign_evt_{i+1:04d}",
            '@timestamp': base_dt.isoformat(),
            'host.name': random.choice(hosts),
            'command_executed': cmd,
            'a0': a0,
            'argc': argc,
            'is_attack': 0
        }
        records.append(record)

    os.makedirs("data/processed", exist_ok=True)
    out_path = "data/processed/benign_synthetic_logs.csv"
    df = pd.DataFrame(records)
    df.to_csv(out_path, index=False)
    print(f"[+] تم توليد {num_samples} حدث طبيعي واقعي في: {out_path}")
    return df

if __name__ == "__main__":
    generate_benign_events()