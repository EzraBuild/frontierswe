# Task-folder conventions (Harbor 0.22 / FrontierSWE style)

Repo root: C:\Users\user\Desktop\frontierSWE  (WSL: /mnt/c/Users/user/Desktop/frontierSWE)

tasks/<task-name>/
  instruction.md            # what the agent sees. Plain prose + a few headings. States the exact scoring formula.
  task.toml                 # see template below
  README.md                 # short author notes: what is tested, why it is hard, how to run oracle/nop
  environment/Dockerfile    # agent image. MUST preinstall everything the verifier needs (python3 etc.)
  environment/...           # setup scripts, workspace files copied into the image
  tests/test.sh             # verifier entry. Harbor uploads tests/ -> /tests AFTER the agent phase, runs /tests/test.sh as root
  tests/...                 # verifier code + any hidden data. NEVER referenced by the Dockerfile. NEVER copied into the image.
  solution/solve.sh         # Harbor uploads solution/ -> /solution and runs /solution/solve.sh (oracle). Must reach reward 1.0.

Rules
- Reward: test.sh writes a float in [0,1] to /logs/verifier/reward.txt (mkdir -p /logs/verifier first). Also write
  /logs/verifier/reward.json  {"reward": x, ...breakdown...} and a human-readable /logs/verifier/evidence.json.
  test.sh must ALWAYS write reward.txt, even on crash (trap / fallback 0.0). A do-nothing agent must get exactly 0.0.
- Network: [environment] network_mode = "no-network". So test.sh cannot apt-get/pip install; preinstall in Dockerfile.
- Verifier runs in the agent's container after the agent is done (shared mode). Rebuild/recompute from sources; do not
  trust agent-produced binaries or caches. Use absolute paths (/usr/bin/python3). Set PATH explicitly in test.sh.
- Agent runs as non-root user `agent` ([agent] user = "agent"). Dockerfile: useradd -m agent; chown -R agent /app.
  Verifier runs as root. Working dir /app.
- No Windows paths, no author machine paths, no secrets/keys/tokens that look real (anything that must look like a key
  in a security scenario is clearly synthetic, e.g. prefixed "SYNTHETIC-" or generated from a seed, and never a real
  provider's prefix like AKIA/ghp_/sk-).
- All text files LF line endings, UTF-8, no BOM. Scripts start with #!/bin/bash or #!/usr/bin/env python3.
  Dockerfile must `chmod +x` any script it copies. Harbor chmods test.sh / solve.sh itself.
- Docker base images by pinned tag (rust:1.91-slim-bookworm, ubuntu:24.04, python:3.12-slim-bookworm already pulled).
- instruction.md must not mention /tests, /solution, hidden file names or the oracle.
- [agent] timeout_sec = 72000.0 (20h). [verifier] timeout_sec sized to the real verifier runtime x3, with a comment.

task.toml template
----------------
schema_version = "1.4"

[task]
name = "ezra-samples/<task-name>"
description = "<one sentence>"
keywords = ["..."]

[metadata]
difficulty = "hard"          # or "very_hard"
category = "<category>"
oracle_reward_threshold = 1.0

[agent]
timeout_sec = 72000.0
user = "agent"

[verifier]
# <comment explaining the budget>
timeout_sec = 3600.0

[verifier.env]
<SEED vars etc.>

[environment]
network_mode = "no-network"
build_timeout_sec = 1800.0
cpus = 4
memory_mb = 8192
storage_mb = 20480
os = "linux"
mcp_servers = []

[environment.env]

[solution.env]

Building / testing from Windows (Docker only exists inside WSL Ubuntu)
---------------------------------------------------------------------
wsl -d Ubuntu -- bash -lc 'cd /mnt/c/Users/user/Desktop/frontierSWE/tasks/<name>/environment && docker build -t <name>:dev .'
Manual end-to-end (before harbor):
wsl -d Ubuntu -- bash -lc 'T=/mnt/c/Users/user/Desktop/frontierSWE/tasks/<name>; docker run --rm --network none -v $T/tests:/tests:ro -v $T/solution:/solution:ro <name>:dev bash -c "mkdir -p /logs/verifier && su agent -c \"bash /solution/solve.sh\" && bash /tests/test.sh; cat /logs/verifier/reward.txt"'
(Fix CRLF first if needed: files written from Windows must be LF. Use `sed -i "s/\r$//"` or write with LF.)
nop check: same but skip solve.sh; reward must print 0.0.
Harbor itself (installed in WSL at ~/.local/bin/harbor): run from the repo root in WSL:
  harbor run -p tasks/<name> -a oracle -o /home/user/fswe-jobs
  harbor run -p tasks/<name> -a nop    -o /home/user/fswe-jobs
