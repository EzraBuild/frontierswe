# webshop-incident-response (author notes)

A blue-team DFIR task. The agent is an incident responder handed a frozen, offline
snapshot of a compromised Linux host that ran "ShopLite", a small Flask storefront.
It must reconstruct the intrusion into a structured report and surgically clean a
writable copy of the host. **Everything in the scene is synthetic and inert** — no
service runs, the "webshell" is a disk artifact that is never executed, external IPs
are TEST-NET (RFC 5737), domains are `.example`/`.test`/`.invalid`, and every secret is
obviously fake.

## The attack chain (ground truth)

An external host (`203.0.113.66`) posts to an unauthenticated image-import endpoint
(`/api/catalog/import`) whose Flask handler saves the uploaded file to an
attacker-controlled path, planting a PHP webshell at
`/srv/shoplite/static/uploads/catalog_7f3a.php`. Through it the attacker reads the
service `.env` (stealing `SHOPLITE_DB_PASSWORD`), escalates to root via a world-writable
root-run helper (`/usr/local/bin/deploy.sh`) that the app's service account may `sudo`,
then establishes persistence three ways (an `authorized_keys` entry for the admin user, a
rogue UID-1337 account `svcupdate`, and a cron beacon `/etc/cron.d/shoplite-telemetry`).
It archives the customer SQLite DB (~4.5 MiB) and exfiltrates it to `198.51.100.77`, then
removes the rotated nginx access log, leaving a visible gap. Timestamps line up across
the nginx log, app log, auth log, cron, shell history and file mtimes; all are derived
from `IR_SEED` so the scene is deterministic and regenerable.

## How scoring works

- **Investigation (0.45)** — `/app/report/findings.json` graded field by field
  (endpoints/IPs/paths normalized, timestamps within ±5 min, set fields by F1, exfil
  bytes within ±25%, timeline by ordered-stage matching).
- **Eradication (0.45)** — `/app/host` re-scanned. Seven checks (rogue account removed
  from passwd+shadow, webshell deleted, attacker SSH key removed, malicious cron removed,
  privesc closed, upload sink patched, secret rotated). Each pays out **only when the
  matching legitimate artifact is still intact**, so over-deletion (nuking the admin key,
  a legit account, the app, the config) earns nothing for that item.
- **Remediation write-up (0.10)** — `/app/report/remediation.md` checked for mention of
  each required action.

A do-nothing agent scores exactly 0.0: no report (0 investigation, 0 write-up) and an
untouched host fails every eradication check because each requires a removal.

## Ground-truth integrity

`scene_spec.py` is the single source of truth. A byte-identical copy lives in
`environment/setup/` (used at build time to render the scene) and in `tests/` (used by
the verifier to re-derive ground truth). The generator is **not** shipped in the image:
the Dockerfile renders the scene and then deletes `/opt/setup` in the same layer, so the
agent sees only the rendered evidence, never the answer key.

## Running it

From the repo root (Docker lives inside WSL on this machine):

```
harbor run -p tasks/webshop-incident-response -a oracle
harbor run -p tasks/webshop-incident-response -a nop
```

Oracle scores `1.0000`; nop scores `0.0000`.
