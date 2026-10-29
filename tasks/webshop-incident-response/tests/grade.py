#!/usr/bin/env python3
"""Verifier for the ShopLite incident-response task.

Recomputes ground truth from IR_SEED (via scene_spec, which lives only here and
in the build context, never in the task image), grades the agent's report, and
re-scans the cleaned host copy at /app/host. Writes reward files under
/logs/verifier. stdlib only, no network. Any catastrophic failure leaves the
fallback reward of 0.0 that test.sh wrote.
"""

import json
import os
import re
import signal
import sys
import traceback
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scene_spec as S

VDIR = "/logs/verifier"
REPORT = "/app/report"
HOST = "/app/host"
SEED = os.environ.get("IR_SEED", "20261029")
DEADLINE_SEC = 600


# ---------------------------------------------------------------- helpers ---
def norm(s):
    return str(s).strip().casefold()


def norm_path(p):
    p = str(p).strip()
    for pre in ("/evidence/host", "/app/host"):
        if p.startswith(pre):
            p = p[len(pre):]
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1]
    return p.casefold()


def parse_ts(s):
    s = str(s).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def ts_score(agent_val, truth_iso, tol_sec=300):
    a = parse_ts(agent_val)
    t = parse_ts(truth_iso)
    if a is None or t is None:
        return 0.0
    return 1.0 if abs((a - t).total_seconds()) <= tol_sec else 0.0


def f1(got, want):
    got = {norm(x) for x in got}
    want = {norm(x) for x in want}
    if not want:
        return 1.0 if not got else 0.0
    if not got:
        return 0.0
    tp = len(got & want)
    if tp == 0:
        return 0.0
    prec = tp / len(got)
    rec = tp / len(want)
    return 2 * prec * rec / (prec + rec)


def read_json(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def exists(path):
    return os.path.exists(HOST + path)


def host_text(path):
    return read_text(HOST + path)


# ----------------------------------------------------- investigation (.45) ---
def grade_findings(gt, ev):
    try:
        f = read_json(os.path.join(REPORT, "findings.json"))
    except Exception as e:
        ev["findings_error"] = f"could not read findings.json: {e}"
        return 0.0
    if not isinstance(f, dict):
        ev["findings_error"] = "findings.json is not a JSON object"
        return 0.0

    score = 0.0

    def g(d, *keys):
        cur = d
        for k in keys:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(k)
        return cur

    # initial_access (0.10)
    ia = f.get("initial_access", {}) or {}
    gia = gt["initial_access"]
    s = 0.0
    if norm_path(ia.get("endpoint", "")) == norm_path(gia["endpoint"]):
        s += 0.03
    if norm(ia.get("method", "")) == norm(gia["method"]):
        s += 0.01
    if norm(ia.get("source_ip", "")) == norm(gia["source_ip"]):
        s += 0.03
    s += 0.03 * ts_score(ia.get("first_seen_utc", ""), gia["first_seen_utc"])
    ev["initial_access"] = round(s, 4)
    score += s

    # webshell (0.06)
    ws = f.get("webshell", {}) or {}
    s = 0.0
    if norm_path(ws.get("path", "")) == norm_path(gt["webshell"]["path"]):
        s += 0.04
    s += 0.02 * ts_score(ws.get("first_access_utc", ""), gt["webshell"]["first_access_utc"])
    ev["webshell"] = round(s, 4)
    score += s

    # persistence (0.06): F1 over (type, path_or_name) pairs
    gp = {(norm(x["type"]), norm_path(x["path_or_name"])) for x in gt["persistence"]}
    ap = set()
    for x in (f.get("persistence") or []):
        if isinstance(x, dict):
            ap.add((norm(x.get("type", "")), norm_path(x.get("path_or_name", ""))))
    s = 0.06 * f1(ap, gp)
    ev["persistence"] = round(s, 4)
    score += s

    # backdoor_account (0.04)
    s = 0.04 if norm(g(f, "backdoor_account", "username") or "") == norm(gt["backdoor_account"]["username"]) else 0.0
    ev["backdoor_account"] = round(s, 4)
    score += s

    # privesc (0.05): mechanism keyword (0.02) + path (0.03)
    pv = f.get("privesc", {}) or {}
    s = 0.0
    mech = norm(pv.get("mechanism", ""))
    if "sudo" in mech and any(w in mech for w in ("writ", "world", "script")):
        s += 0.02
    elif mech == norm(gt["privesc"]["mechanism"]):
        s += 0.02
    if norm_path(pv.get("path", "")) == norm_path(gt["privesc"]["path"]):
        s += 0.03
    ev["privesc"] = round(s, 4)
    score += s

    # exfil (0.06): dest_ip (0.03) + approx_bytes (0.03, +/-25% full)
    ex = f.get("exfil", {}) or {}
    s = 0.0
    if norm(ex.get("dest_ip", "")) == norm(gt["exfil"]["dest_ip"]):
        s += 0.03
    try:
        ab = float(ex.get("approx_bytes", 0))
        truth = float(gt["exfil"]["approx_bytes"])
        rel = abs(ab - truth) / truth
        if rel <= 0.25:
            s += 0.03
        elif rel < 0.50:
            s += 0.03 * (0.50 - rel) / 0.25
    except Exception:
        pass
    ev["exfil"] = round(s, 4)
    score += s

    # stolen_secret_name (0.03)
    ssn = norm(f.get("stolen_secret_name", ""))
    s = 0.03 if norm(gt["stolen_secret_name"]) in ssn and ssn else 0.0
    ev["stolen_secret_name"] = round(s, 4)
    score += s

    # iocs (0.03): mean F1 of ips / usernames / files
    iocs = f.get("iocs", {}) or {}
    sub = [
        f1(iocs.get("ips") or [], [norm(x) for x in gt["iocs"]["ips"]]),
        f1(iocs.get("usernames") or [], [norm(x) for x in gt["iocs"]["usernames"]]),
        f1([norm_path(x) for x in (iocs.get("files") or [])], [norm_path(x) for x in gt["iocs"]["files"]]),
    ]
    s = 0.03 * (sum(sub) / 3.0)
    ev["iocs"] = round(s, 4)
    score += s

    # timeline (0.02): required stages in correct order
    tl = f.get("timeline") or []
    events = []
    for e in tl:
        if isinstance(e, dict):
            events.append((parse_ts(e.get("time_utc", "")), norm(e.get("event", ""))))
    matched = 0
    idx = 0
    last_t = None
    for _, (stage, cues) in enumerate(S.REQUIRED_TIMELINE):
        for j in range(idx, len(events)):
            t, text = events[j]
            if any(c in text for c in cues):
                if last_t is None or t is None or t >= last_t:
                    matched += 1
                    idx = j + 1
                    last_t = t if t is not None else last_t
                    break
    s = 0.02 * (matched / len(S.REQUIRED_TIMELINE))
    ev["timeline"] = round(s, 4)
    score += s

    ev["findings_total"] = round(score, 4)
    return score


# -------------------------------------------------------- eradication (.45) ---
def grade_eradication(gt, ev):
    score = 0.0

    # account_clean (0.08)
    passwd = host_text("/etc/passwd")
    shadow = host_text("/etc/shadow")
    bad = S.BACKDOOR_USER
    bad_gone = (not re.search(rf"(?m)^{re.escape(bad)}:", passwd)
                and not re.search(rf"(?m)^{re.escape(bad)}:", shadow))
    good_users = [S.ADMIN_USER, S.APP_USER, S.BACKUP_USER, "root"]
    good_ok = all(re.search(rf"(?m)^{re.escape(u)}:", passwd) for u in good_users)
    s = 0.08 if (bad_gone and good_ok) else 0.0
    ev["account_clean"] = {"score": s, "bad_removed": bad_gone, "legit_intact": good_ok}
    score += s

    # webshell_removed (0.08)
    ws_gone = not exists(S.WEBSHELL)
    updir = HOST + S.UPLOAD_DIR
    no_shell_residue = True
    if os.path.isdir(updir):
        for root, _, files in os.walk(updir):
            for fn in files:
                t = read_text(os.path.join(root, fn))
                if "@eval(" in t or "inert sample for a forensics exercise" in t:
                    no_shell_residue = False
    legit_upload_ok = exists(S.LEGIT_UPLOAD)
    s = 0.08 if (ws_gone and no_shell_residue and legit_upload_ok) else 0.0
    ev["webshell_removed"] = {"score": s, "webshell_gone": ws_gone,
                              "no_residue": no_shell_residue, "legit_upload_intact": legit_upload_ok}
    score += s

    # ssh_key_removed (0.07)
    ak = host_text(S.authorized_keys_path(S.ADMIN_USER))
    atk_gone = (S.ATTACKER_KEY_COMMENT not in ak) and ("SYNTHETICATTACKERKEY" not in ak)
    legit_present = (S.ADMIN_KEY_COMMENT in ak) or ("SYNTHETICLEGITADMINKEY" in ak)
    s = 0.07 if (atk_gone and legit_present) else 0.0
    ev["ssh_key_removed"] = {"score": s, "attacker_key_gone": atk_gone, "legit_key_intact": legit_present}
    score += s

    # cron_removed (0.07)
    cron_bad_gone = not exists(S.CRON_MALICIOUS)
    cron_legit_ok = exists(S.CRON_LEGIT)
    s = 0.07 if (cron_bad_gone and cron_legit_ok) else 0.0
    ev["cron_removed"] = {"score": s, "malicious_gone": cron_bad_gone, "legit_intact": cron_legit_ok}
    score += s

    # privesc_fixed (0.05): script no longer world-writable OR sudo rule gone;
    # the helper itself must still exist (surgical fix, not nuking the deploy)
    deploy_full = HOST + S.PRIVESC_SCRIPT
    deploy_exists = os.path.exists(deploy_full)
    not_ww = False
    if deploy_exists:
        not_ww = (os.stat(deploy_full).st_mode & 0o002) == 0
    sudoers_gone = not exists(S.SUDOERS_FILE)
    fixed = deploy_exists and (not_ww or sudoers_gone)
    s = 0.05 if fixed else 0.0
    ev["privesc_fixed"] = {"score": s, "deploy_exists": deploy_exists,
                           "not_world_writable": not_ww, "sudo_rule_removed": sudoers_gone}
    score += s

    # vuln_patched (0.05): dangerous upload sink neutralized, app still present
    app = host_text(S.APP_SOURCE)
    app_present = bool(app) and "@app.route" in app
    tokens = ("secure_filename", "allowed", "splitext", "endswith", "abort(", "400", "415", "basename")
    raw_sink = ("f.filename" in app) and ("os.path.join" in app or ".save(" in app)
    neutralized = app_present and ((not raw_sink) or any(tok in app for tok in tokens))
    s = 0.05 if neutralized else 0.0
    ev["vuln_patched"] = {"score": s, "app_present": app_present,
                          "raw_sink_present": raw_sink, "neutralized": neutralized}
    score += s

    # secret_rotated (0.05): synthetic secret value gone from app source + .env,
    # but the config files still exist (rotated, not deleted)
    app_src = host_text(S.APP_SOURCE)
    envf = host_text(S.ENV_FILE)
    value_gone = (S.STOLEN_SECRET_VALUE not in app_src) and (S.STOLEN_SECRET_VALUE not in envf)
    cfg_intact = exists(S.ENV_FILE) and exists(S.APP_SOURCE)
    s = 0.05 if (value_gone and cfg_intact) else 0.0
    ev["secret_rotated"] = {"score": s, "value_gone": value_gone, "config_intact": cfg_intact}
    score += s

    ev["eradication_total"] = round(score, 4)
    return score


# --------------------------------------------------- remediation notes (.10) ---
def grade_remediation_md(ev):
    txt = norm(read_text(os.path.join(REPORT, "remediation.md")))
    if not txt:
        ev["remediation_md"] = 0.0
        return 0.0
    anchors = [
        ("webshell", ["webshell", "web shell", "backdoor file"]),
        ("account", ["account", "user", "passwd"]),
        ("ssh", ["ssh", "authorized_keys", "key"]),
        ("cron", ["cron", "scheduled"]),
        ("privesc", ["sudo", "privilege", "world-writable", "world writable"]),
        ("patch", ["patch", "validate", "upload", "sanitiz"]),
        ("secret", ["rotate", "secret", "password", "credential"]),
    ]
    hit = sum(1 for _, cues in anchors if any(c in txt for c in cues))
    s = 0.10 * (hit / len(anchors))
    ev["remediation_md"] = round(s, 4)
    return s


def main():
    os.makedirs(VDIR, exist_ok=True)
    ev = {"seed": SEED}
    gt = S.ground_truth(SEED)
    total = 0.0
    total += grade_findings(gt, ev)
    total += grade_eradication(gt, ev)
    total += grade_remediation_md(ev)
    total = max(0.0, min(1.0, total))

    with open(os.path.join(VDIR, "reward.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"{total:.4f}")
    with open(os.path.join(VDIR, "reward.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump({"reward": round(total, 4),
                   "investigation": ev.get("findings_total", 0.0),
                   "eradication": ev.get("eradication_total", 0.0),
                   "remediation_md": ev.get("remediation_md", 0.0)}, f, indent=2)
    with open(os.path.join(VDIR, "evidence.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(ev, f, indent=2)
    print(f"reward={total:.4f}")


if __name__ == "__main__":
    def _timeout(signum, frame):
        raise TimeoutError("verifier soft deadline exceeded")
    try:
        signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(DEADLINE_SEC)
    except Exception:
        pass
    try:
        main()
    except Exception:
        traceback.print_exc()
        try:
            os.makedirs(VDIR, exist_ok=True)
            with open(os.path.join(VDIR, "reward.txt"), "w", encoding="utf-8", newline="\n") as f:
                f.write("0.0")
        except Exception:
            pass
        sys.exit(1)
