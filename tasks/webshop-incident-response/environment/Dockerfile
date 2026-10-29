FROM ubuntu:24.04

# Build-time only: python3 to render the scene, openssl to make a real-but-
# harmless shadow hash. No network is needed at agent or verifier runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged responder account. The agent works entirely under /app.
RUN useradd -m -s /bin/bash agent

# Render the compromised-host snapshot from the seed. The generator lives only
# under /opt/setup and is deleted in this same layer, so it is not present in
# the final image the agent sees.
ARG IR_SEED=20261029
ENV IR_SEED=${IR_SEED}
COPY setup/ /opt/setup/
RUN cd /opt/setup \
    && python3 render_scene.py /evidence/host \
    && mkdir -p /app \
    && cp -a /evidence/host /app/host \
    && mkdir -p /app/report \
    && rm -rf /opt/setup

# Evidence is read-only; the writable copy under /app/host is what gets cleaned.
RUN chmod -R a-w /evidence \
    && chown -R agent:agent /app

WORKDIR /app
USER agent
