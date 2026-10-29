# ShopLite incident response

A small internal web host that ran **ShopLite** — a Python/Flask e-commerce app behind
nginx — was breached and pulled offline. You are the incident responder. You have been
given a frozen forensic snapshot of the host. Reconstruct what happened, write a
structured incident report, and clean a restorable copy of the host.

This is a **frozen snapshot**: no services are running and nothing on it is live. Everything
you need is static files on disk — application source, configuration, nginx and auth logs, a SQLite database,
users' home directories and shell history, cron and sudo configuration. You read the
evidence; you do not run the app.

## Where things are

- **`/evidence/host`** — read-only snapshot of the breached host exactly as captured.
  Paths inside it mirror the real host: the app is at `/evidence/host/srv/shoplite`,
  nginx logs at `/evidence/host/var/log/nginx/`, app logs at
  `/evidence/host/var/log/shoplite/`, auth log at `/evidence/host/var/log/auth.log`,
  system files under `/evidence/host/etc/`, home directories under `/evidence/host/home/`.
- **`/app/host`** — a writable copy of the same snapshot. This is the host you will
  clean in Part 2.
- **`/app/report`** — your workspace for the two report files below.

Your working directory is `/app`. When you cite a path in your report, write it as a
host path starting with `/` (for example `/srv/shoplite/app.py`); a leading
`/evidence/host` or `/app/host` is accepted too.

## Part 1 — Investigate and report

Reconstruct the single attack chain and write **`/app/report/findings.json`**, a JSON
object with exactly these keys:

```json
{
  "initial_access": {
    "endpoint": "/path/the/attacker/abused",
    "method": "POST",
    "source_ip": "203.0.113.x",
    "first_seen_utc": "2026-10-29T00:00:00Z"
  },
  "webshell": {
    "path": "/srv/shoplite/.../file",
    "first_access_utc": "2026-10-29T00:00:00Z"
  },
  "persistence": [
    { "type": "ssh_authorized_key", "path_or_name": "/home/ubuntu/.ssh/authorized_keys" },
    { "type": "rogue_account", "path_or_name": "username" },
    { "type": "cron", "path_or_name": "/etc/cron.d/..." }
  ],
  "backdoor_account": { "username": "..." },
  "privesc": { "mechanism": "...", "path": "/usr/local/bin/..." },
  "exfil": { "dest_ip": "198.51.100.x", "approx_bytes": 1234567 },
  "stolen_secret_name": "NAME_OF_THE_ENV_VARIABLE",
  "iocs": { "ips": ["..."], "usernames": ["..."], "files": ["..."] },
  "timeline": [
    { "time_utc": "2026-10-29T00:00:00Z", "event": "short description" }
  ]
}
```

Field notes:

- `initial_access` — the endpoint, HTTP method, and source IP of the **first successful
  malicious request**, with its timestamp. Background internet scanners are noise; name
  the IP that actually carried out the intrusion.
- `webshell.path` — the backdoor the attacker planted; `first_access_utc` is when it was
  first requested.
- `persistence` — one entry per mechanism. The `type` must be one of exactly:
  `ssh_authorized_key`, `rogue_account`, `cron`. `path_or_name` is the file path for a
  file-based mechanism, or the account name for `rogue_account`.
- `privesc.mechanism` — a short label for how the attacker went from the web account to
  root (for example mentioning sudo and a writable script); `privesc.path` is the file
  central to it.
- `exfil.approx_bytes` — your best estimate of how much data left the host. Scored within
  ±25% of the true figure.
- `stolen_secret_name` — the **name** of the secret (e.g. the environment variable name)
  the attacker read, not its value.
- `iocs` — deduplicated indicators: the malicious IPs, the attacker-controlled
  usernames, and the attacker-controlled files. Listing clearly-benign items lowers the
  score.
- `timeline` — at least five entries, ordered earliest first, covering the chain from
  initial access through exfiltration.

## Part 2 — Remediate

### Report the plan

Write **`/app/report/remediation.md`** describing, in prose, the actions you took to
contain and eradicate the intrusion and to prevent recurrence. Cover removing the
webshell, removing the rogue account, removing the attacker's SSH access, removing the
malicious scheduled job, fixing the privilege-escalation path, patching the vulnerable
endpoint, and rotating the leaked secret.

### Apply the fixes to `/app/host`

Actually perform these on the writable copy at `/app/host`:

1. **Remove the rogue account** from both `/app/host/etc/passwd` and
   `/app/host/etc/shadow`. Remove only the attacker's account; every legitimate account
   must remain.
2. **Delete the webshell** file. Leave the legitimate uploaded files in place.
3. **Remove the attacker's SSH key** from the authorized_keys file, leaving the
   legitimate administrator key intact.
4. **Remove the malicious scheduled job**, leaving legitimate cron files intact.
5. **Fix the privilege-escalation path**: the root-run helper script must no longer be
   world-writable, or the sudo rule that abused it must be removed.
6. **Patch the vulnerable endpoint** in `/app/host/srv/shoplite/app.py` so the dangerous
   file-handling is neutralized (validate the upload — for example restrict the filename
   or the allowed extensions — or otherwise stop saving attacker-controlled paths).
7. **Rotate the leaked secret**: the hard-coded/stored synthetic secret value must no
   longer appear in the application source or config under `/app/host/srv/shoplite`.

Be surgical. Over-cleaning that removes legitimate accounts, keys, cron jobs, or files,
or that breaks the application, loses credit.

## Scoring

Total reward is in [0, 1], the sum of:

- **Investigation — 0.45.** `/app/report/findings.json` is graded field by field against
  ground truth. IPs, usernames, endpoints and paths are matched after normalizing case
  and trailing slashes. Set-valued fields are scored on precision and recall. Timestamps
  are accepted within a few minutes. `approx_bytes` is full credit within ±25% and falls
  off linearly. The timeline is scored by how many required events appear in the correct
  order.
- **Eradication — 0.45.** Your `/app/host` is re-scanned. Each attacker artifact removed
  earns credit **only when** the matching legitimate artifact is still intact, so both
  leaving attacker artifacts and destroying legitimate ones cost you.
- **Remediation write-up — 0.10.** `/app/report/remediation.md` is checked for mention of
  each required action.

A snapshot left untouched, with no report written, scores 0.

All data in this exercise is synthetic.
