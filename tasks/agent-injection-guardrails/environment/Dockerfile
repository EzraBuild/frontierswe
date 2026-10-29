FROM python:3.12-slim-bookworm

# The assistant and the grader use only the Python standard library. `su` (from
# util-linux, already present) is used by the grader to run the agent's decision
# module as the unprivileged `agent` user, isolated from the hidden scenarios.
RUN useradd -m -s /bin/bash agent

COPY workspace/ /app/
WORKDIR /app

RUN chown -R agent:agent /app
