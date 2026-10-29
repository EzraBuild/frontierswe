#!/usr/bin/env python3
# SYNTHETIC EVIDENCE GENERATOR - deterministic spec for a forensics exercise.
# This module is the single source of truth for the ShopLite incident scene.
# It is byte-identical in environment/setup/ (used at image build time to RENDER
# the scene) and in tests/ (used by the verifier to RE-DERIVE ground truth).
# It is NEVER shipped inside the task image.
#
# Everything here is synthetic. External IPs are from the TEST-NET ranges
# (RFC 5737): 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24. Domains are
# .example / .test / .invalid. Secrets are obviously fake.
"""Deterministic specification of the ShopLite breach scene.

All facts are a function of IR_SEED (an 8-digit YYYYMMDD string). Timestamps are
the seed date (00:00:00Z) plus fixed second-offsets, so the renderer and the
verifier agree exactly without storing a plaintext answer key in the image.
"""

from datetime import datetime, timedelta, timezone

# --- actors / identifiers (fixed, synthetic) --------------------------------
ATTACKER_IP = "203.0.113.66"       # carried out the intrusion
EXFIL_IP = "198.51.100.77"         # data exfiltration destination
SCANNER_IP = "192.0.2.45"          # background scanner, NOT the intruder (noise)

ADMIN_USER = "shopadmin"           # legitimate human admin (UID 1001)
APP_USER = "shopapp"               # legitimate service account the app runs as (1002)
BACKUP_USER = "shopbackup"         # legitimate backup account (1003)
BACKDOOR_USER = "svcupdate"        # attacker-created account (UID 1337)

ADMIN_UID = 1001
APP_UID = 1002
BACKUP_UID = 1003
BACKDOOR_UID = 1337

# synthetic password behind the backdoor account's shadow hash (hash made at
# build time with `openssl passwd -6`; the value itself never needs to match).
BACKDOOR_PASSWORD = "SYNTHETIC-pw-Rotate4Me"

# --- app / host paths (host-logical, without an evidence-root prefix) --------
APP_DIR = "/srv/shoplite"
APP_SOURCE = APP_DIR + "/app.py"
ENV_FILE = APP_DIR + "/.env"
UPLOAD_DIR = APP_DIR + "/static/uploads"
WEBSHELL = UPLOAD_DIR + "/catalog_7f3a.php"
LEGIT_UPLOAD = UPLOAD_DIR + "/logo.png"
DB_FILE = APP_DIR + "/instance/shoplite.db"

CRON_MALICIOUS = "/etc/cron.d/shoplite-telemetry"
CRON_LEGIT = "/etc/cron.d/shoplite-logrotate"
SUDOERS_FILE = "/etc/sudoers.d/shoplite"
PRIVESC_SCRIPT = "/usr/local/bin/deploy.sh"

# the leaked secret is identified by NAME, not value
STOLEN_SECRET_NAME = "SHOPLITE_DB_PASSWORD"
STOLEN_SECRET_VALUE = "SYNTHETIC-DB-PASS-7q2xc9k4d1a8"  # synthetic, not a real format

# initial access
INITIAL_ENDPOINT = "/api/catalog/import"
INITIAL_METHOD = "POST"

# exfiltration volume (bytes); graded within +/-25%
EXFIL_BYTES = 4718592  # ~4.5 MiB, the DB archive pulled through the webshell

# ssh key comments (public keys only; synthetic)
ADMIN_KEY_COMMENT = ADMIN_USER + "@laptop.example"
ATTACKER_KEY_COMMENT = BACKDOOR_USER + "@ops.invalid"


def home(user):
    """Host-logical home directory for a user (built dynamically on purpose)."""
    return "/home/" + user


def authorized_keys_path(user):
    return home(user) + "/.ssh/authorized_keys"


def base_time(seed):
    d = datetime.strptime(str(seed), "%Y%m%d")
    return d.replace(tzinfo=timezone.utc)


# event offsets from base_time, in seconds (ordered)
OFFSETS = {
    "scan": 3521,            # 00:58:41  background scanner noise
    "initial_access": 4327,  # 01:12:07  successful upload of the webshell
    "webshell": 4361,        # 01:12:41  webshell first requested
    "cred_theft": 4519,      # 01:15:19  read DB credentials from .env
    "privesc": 4863,         # 01:21:03  sudo deploy.sh -> root
    "persistence": 5130,     # 01:25:30  ssh key + rogue account + cron
    "exfil": 5662,           # 01:34:22  archive pushed to EXFIL_IP
    "log_tamper": 6000,      # 01:40:00  rotated access log removed (gap)
}


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def nginx_time(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def event_times(seed):
    bt = base_time(seed)
    return {k: bt + timedelta(seconds=v) for k, v in OFFSETS.items()}


def ground_truth(seed):
    """Return the full ground-truth fact set for the given seed."""
    t = event_times(seed)
    return {
        "initial_access": {
            "endpoint": INITIAL_ENDPOINT,
            "method": INITIAL_METHOD,
            "source_ip": ATTACKER_IP,
            "first_seen_utc": iso(t["initial_access"]),
        },
        "webshell": {
            "path": WEBSHELL,
            "first_access_utc": iso(t["webshell"]),
        },
        "persistence": [
            {"type": "ssh_authorized_key", "path_or_name": authorized_keys_path(ADMIN_USER)},
            {"type": "rogue_account", "path_or_name": BACKDOOR_USER},
            {"type": "cron", "path_or_name": CRON_MALICIOUS},
        ],
        "backdoor_account": {"username": BACKDOOR_USER},
        "privesc": {"mechanism": "sudo_writable_script", "path": PRIVESC_SCRIPT},
        "exfil": {"dest_ip": EXFIL_IP, "approx_bytes": EXFIL_BYTES},
        "stolen_secret_name": STOLEN_SECRET_NAME,
        "iocs": {
            "ips": [ATTACKER_IP, EXFIL_IP],
            "usernames": [BACKDOOR_USER],
            "files": [WEBSHELL, CRON_MALICIOUS, PRIVESC_SCRIPT, authorized_keys_path(ADMIN_USER)],
        },
        "timeline": [
            {"time_utc": iso(t["initial_access"]), "event": "initial access: webshell uploaded via catalog import endpoint"},
            {"time_utc": iso(t["webshell"]), "event": "webshell first accessed"},
            {"time_utc": iso(t["cred_theft"]), "event": "database credentials stolen from .env"},
            {"time_utc": iso(t["privesc"]), "event": "privilege escalation via sudo writable deploy script"},
            {"time_utc": iso(t["persistence"]), "event": "persistence established: ssh key, rogue account, cron"},
            {"time_utc": iso(t["exfil"]), "event": "data exfiltrated to external host"},
            {"time_utc": iso(t["log_tamper"]), "event": "defense evasion: rotated access log removed"},
        ],
    }


# the ordered timeline stages the verifier requires, each with keyword cues an
# agent's free-text event may contain to count as that stage.
REQUIRED_TIMELINE = [
    ("initial_access", ["initial access", "upload", "import", "catalog"]),
    ("webshell", ["webshell", "web shell", "backdoor", "shell"]),
    ("cred_theft", ["credential", ".env", "secret", "password", "db pass"]),
    ("privesc", ["privilege", "privesc", "sudo", "root", "escalat"]),
    ("persistence", ["persistence", "ssh key", "authorized_keys", "cron", "account"]),
    ("exfil", ["exfil", "exfiltrat", "data theft", "transfer out", "upload to"]),
]


if __name__ == "__main__":
    import json
    import os
    print(json.dumps(ground_truth(os.environ.get("IR_SEED", "20261029")), indent=2))
