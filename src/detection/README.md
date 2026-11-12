# Detection Engineering

Rule-based detection for the Cyber Defense Digital Twin pipeline. `detection_engine.py` applies regular-expression rules to the command text of every cleaned event (it falls back to the `a0` field when the command is empty) and writes one detection row for each matching rule and event.

## Rules

| ID | Name | Matches | Severity | MITRE tactic | Technique |
|---|---|---|---|---|---|
| DET001 | Remote File Download | `curl` or `wget` | medium | command-and-control | T1105 Ingress Tool Transfer |
| DET002 | Cron Persistence | `crontab` or `cron` | high | persistence | T1053.003 Scheduled Task/Job: Cron |
| DET003 | SSH Remote Service | an `ssh` client command (`ssh` followed by whitespace, at the start of the command or after a space or `/`) | high | lateral-movement | T1021.004 Remote Services: SSH |
| DET004 | Shadow File Access | `/etc/shadow` | critical | credential-access | T1003.008 /etc/passwd and /etc/shadow |
| DET005 | File Encryption Activity | `openssl enc` | critical | impact | T1486 Data Encrypted for Impact |
| DET006 | Possible Masquerading | `cp /bin/<x> /tmp/<y>` | medium | defense-evasion | T1036 Masquerading |
| DET007 | Network Configuration Discovery | `ifconfig`, `ip a`, `ip addr`, `ip route` | low | discovery | T1016 System Network Configuration Discovery |
| DET008 | System Information Discovery | `uname` or `hostname` | low | discovery | T1082 System Information Discovery |
| DET009 | Passwd File Read | `/etc/passwd` | medium | discovery | T1087.001 Account Discovery: Local Account |

## Tuning notes (2026-11)

- DET003 used to match `\bssh\b`, which also matched `ssh-agent`, `.ssh` paths and `SSH_AUTH_SOCK` in desktop background commands: 14 false high-severity alerts in 1006 benign events (sessions 06 and 07).
- DET004 used to match `/etc/passwd` as well as `/etc/shadow` and raised critical alerts for a file every user can read. `/etc/passwd` is now handled by DET009 (medium, discovery).
- Effect on same-environment data: critical or high alerts on the 1006 benign events went from 18 to 0; critical or high events among the 159 attack events went from 7 to 5 (the two `/etc/passwd` events are still detected, now as medium).
- Effect on the APT41 demo alert: base risk 69 to 62 and total risk 92 to 85 (still CRITICAL).
- Coverage with the original rule set on same-environment data: 27 of 159 attack events (17%) matched at least one rule, versus 9 of 274 (3.3%) and 29 of 1006 (2.9%) benign events.

## Limitations

- Rules match command text only (no user, parent process, working directory or exit status), so the same command can be benign or malicious (for example `cat /etc/passwd`).
- Rules were written around the APT41 dataset. There are no rules yet for archive creation with `tar`, credential hunting with `grep`, or staging with `cp`.
- Events with no command text and no `a0` value are never matched (21 of 46 APT41 events).
- Low-severity discovery rules are noisy by nature: about half of their hits in same-environment data are benign.
- The correlator (`src/correlation/context_correlator.py`) builds chain context text from rule names, so rename a rule only together with that file.
- `detection_engine.py` runs as a script at import time (it reads and writes files), so it cannot be unit tested without running it.

## Usage

```bash
python src/detection/detection_engine.py
```

Input: `data/processed/<slug>_clean.csv`. Output: `data/processed/<slug>_detections.csv`. The slug comes from `CYBER_DATASET_SLUG` (default `apt41`).

To add a rule, add a dict with `rule_id`, `name`, `pattern`, `severity`, `tactic`, `technique_id` and `technique` to `rules`, and test it on both benign and attack data before merging.
