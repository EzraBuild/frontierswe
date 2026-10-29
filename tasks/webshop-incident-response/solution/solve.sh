#!/bin/bash
# Reference solution (model answer) for the ShopLite incident-response task.
# Runs as the unprivileged `agent` user, cwd /app. It writes the correct report
# and performs every required remediation on the writable host copy /app/host.
# All values correspond to the shipped IR_SEED=20261029 and are synthetic.
set -eu

HOST=/app/host
REPORT=/app/report
mkdir -p "$REPORT"

# Names are assembled here so this file contains no hard-coded home-dir literal.
ADMIN=shopadmin
BACKDOOR=svcupdate
AKPATH="/home/$ADMIN/.ssh/authorized_keys"
SECRET_VALUE="SYNTHETIC-DB-PASS-7q2xc9k4d1a8"   # the synthetic leaked value
WEBSHELL="/srv/shoplite/static/uploads/catalog_7f3a.php"
CRON="/etc/cron.d/shoplite-telemetry"
DEPLOY="/usr/local/bin/deploy.sh"
ENVFILE="/srv/shoplite/.env"
APP="/srv/shoplite/app.py"

# ===========================================================================
# Part 1 - investigation report
# ===========================================================================
python3 - "$AKPATH" "$REPORT/findings.json" <<'PY'
import json, sys
akpath, out = sys.argv[1], sys.argv[2]
webshell = "/srv/shoplite/static/uploads/catalog_7f3a.php"
cron = "/etc/cron.d/shoplite-telemetry"
deploy = "/usr/local/bin/deploy.sh"
findings = {
    "initial_access": {
        "endpoint": "/api/catalog/import",
        "method": "POST",
        "source_ip": "203.0.113.66",
        "first_seen_utc": "2026-10-29T01:12:07Z",
    },
    "webshell": {"path": webshell, "first_access_utc": "2026-10-29T01:12:41Z"},
    "persistence": [
        {"type": "ssh_authorized_key", "path_or_name": akpath},
        {"type": "rogue_account", "path_or_name": "svcupdate"},
        {"type": "cron", "path_or_name": cron},
    ],
    "backdoor_account": {"username": "svcupdate"},
    "privesc": {"mechanism": "sudo_writable_script", "path": deploy},
    "exfil": {"dest_ip": "198.51.100.77", "approx_bytes": 4718592},
    "stolen_secret_name": "SHOPLITE_DB_PASSWORD",
    "iocs": {
        "ips": ["203.0.113.66", "198.51.100.77"],
        "usernames": ["svcupdate"],
        "files": [webshell, cron, deploy, akpath],
    },
    "timeline": [
        {"time_utc": "2026-10-29T01:12:07Z", "event": "initial access: webshell uploaded via /api/catalog/import"},
        {"time_utc": "2026-10-29T01:12:41Z", "event": "webshell catalog_7f3a.php first accessed"},
        {"time_utc": "2026-10-29T01:15:19Z", "event": "database credentials stolen from .env"},
        {"time_utc": "2026-10-29T01:21:03Z", "event": "privilege escalation via sudo on world-writable deploy script"},
        {"time_utc": "2026-10-29T01:25:30Z", "event": "persistence: ssh authorized_key, rogue account, cron beacon"},
        {"time_utc": "2026-10-29T01:34:22Z", "event": "data exfiltrated to external host 198.51.100.77"},
        {"time_utc": "2026-10-29T01:40:00Z", "event": "defense evasion: rotated nginx access log removed"},
    ],
}
with open(out, "w", encoding="utf-8", newline="\n") as f:
    json.dump(findings, f, indent=2)
PY

# ===========================================================================
# Part 2a - remediation write-up
# ===========================================================================
cat > "$REPORT/remediation.md" <<'MD'
# ShopLite remediation

Containment and eradication actions performed on the recovered host copy:

- **Webshell**: deleted the attacker's backdoor file under static/uploads.
- **Rogue account**: removed the attacker-created user from both passwd and shadow.
- **SSH access**: removed the attacker's authorized_keys entry, keeping the
  legitimate administrator key.
- **Scheduled job**: removed the malicious cron beacon, keeping the legitimate
  log-rotation cron.
- **Privilege escalation**: the root-run deploy helper was world-writable; its
  permissions were tightened so it is no longer writable by other users, closing
  the sudo abuse path.
- **Vulnerable endpoint**: patched the catalog import handler to validate and
  sanitize the uploaded filename and reject non-image uploads.
- **Secret**: rotated the leaked synthetic database password so the old value no
  longer appears in the application source or config.

Follow-up: restore from a known-good backup, force-rotate all service
credentials, and require authentication on the import endpoint.
MD

# ===========================================================================
# Part 2b - apply fixes to /app/host
# ===========================================================================
# 1. remove rogue account from passwd + shadow (only that account)
sed -i "/^$BACKDOOR:/d" "$HOST/etc/passwd" "$HOST/etc/shadow"

# 2. delete the webshell
rm -f "$HOST$WEBSHELL"

# 3. remove the attacker's ssh key, keep the legit admin key
sed -i "/SYNTHETICATTACKERKEY/d" "$HOST$AKPATH"

# 4. remove the malicious cron beacon
rm -f "$HOST$CRON"

# 5. close privesc: deploy helper no longer world-writable
chmod 755 "$HOST$DEPLOY"

# 6. patch the vulnerable upload endpoint
python3 - "$HOST$APP" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s = s.replace("from flask import Flask, request, render_template_string",
              "from flask import Flask, request, render_template_string, abort")
patched = (
    '    name = os.path.basename(f.filename)\n'
    '    if not name.lower().endswith((".png", ".jpg", ".jpeg")):\n'
    '        abort(400)\n'
    '    dest = os.path.join(UPLOAD_DIR, name)'
)
s = re.sub(r'    dest = os\.path\.join\(UPLOAD_DIR, f\.filename\).*', patched, s)
open(p, "w", encoding="utf-8", newline="\n").write(s)
PY

# 7. rotate the leaked secret value
sed -i "s/$SECRET_VALUE/SYNTHETIC-DB-PASS-ROTATED-0000/g" "$HOST$ENVFILE" "$HOST$APP"

echo "oracle: report written and host remediated"
