import os
import re
import glob
import pandas as pd
from datetime import datetime, timezone


def decode_audit_value(value):
    value = value.strip('"')

    # auditd أحيانًا يحول بعض القيم إلى Hex
    if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) % 2 == 0:
        try:
            return bytes.fromhex(value).decode("utf-8", errors="replace")
        except ValueError:
            pass

    return value


def parse_auditd_log(
    log_pattern="data/raw/auditd/benign/*.log",
    output_path="data/processed/linux_auditd_benign.csv"
):
    """
    Parse multiple raw Linux auditd sessions (SYSCALL + EXECVE)
    into the clean benign schema used by the project.
    """

    log_files = sorted(glob.glob(log_pattern))

    if not log_files:
        raise FileNotFoundError(
            f"No auditd log files found: {log_pattern}"
        )

    events = {}
    event_order = []

    print(f"[+] Found {len(log_files)} auditd session files")

    for log_path in log_files:
        source_name = os.path.basename(log_path)

        print(f"    Parsing: {source_name}")

        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:

                match = re.search(
                    r"msg=audit\((\d+\.\d+):(\d+)\)",
                    line
                )

                if not match:
                    continue

                ts_epoch, seq = match.groups()

                # Include source file to guarantee uniqueness
                event_key = f"{source_name}:{ts_epoch}:{seq}"

                if event_key not in events:
                    events[event_key] = {
                        "timestamp_epoch": float(ts_epoch),
                        "seq": seq,
                        "source": source_name,
                        "exe": None,
                        "argc": 1,
                        "args": [],
                        "has_execve": False
                    }
                    event_order.append(event_key)

                if "type=SYSCALL" in line:
                    exe_match = re.search(r'exe="([^"]+)"', line)

                    if exe_match:
                        events[event_key]["exe"] = exe_match.group(1)

                elif "type=EXECVE" in line:
                    events[event_key]["has_execve"] = True

                    argc_match = re.search(r"argc=(\d+)", line)

                    if argc_match:
                        events[event_key]["argc"] = int(
                            argc_match.group(1)
                        )

                    raw_args = re.findall(
                        r'\ba\d+=(".*?"|\S+)',
                        line
                    )

                    events[event_key]["args"] = [
                        decode_audit_value(arg)
                        for arg in raw_args
                    ]

    parsed_records = []

    for event_key in event_order:
        data = events[event_key]

        # نبي EXECVE telemetry فقط
        if not data["has_execve"]:
            continue

        dt = datetime.fromtimestamp(
            data["timestamp_epoch"],
            tz=timezone.utc
        )

        iso_timestamp = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        args = data["args"]

        if args:
            a0 = args[0]
            command_str = " ".join(args)
        else:
            exe = data["exe"] or "unknown"
            a0 = os.path.basename(exe)
            command_str = exe

        parsed_records.append({
            "_id": f"auditd_real_{len(parsed_records) + 10001}",
            "@timestamp": iso_timestamp,
            "host.name": "cyber-lab-ubuntu",
            "host": "cyber-lab-ubuntu",
            "command_executed": command_str,
            "a0": a0,
            "argc": data["argc"],
            "is_attack": 0
        })

    df = pd.DataFrame(parsed_records)

    os.makedirs(
        os.path.dirname(output_path),
        exist_ok=True
    )

    df.to_csv(output_path, index=False)

    print()
    print(f"[+] Sessions processed: {len(log_files)}")
    print(f"[+] EXECVE events extracted: {len(df)}")
    print(f"[+] Unique IDs: {df['_id'].nunique()}")
    print(f"[+] Output: {output_path}")

    return df


if __name__ == "__main__":
    parse_auditd_log()