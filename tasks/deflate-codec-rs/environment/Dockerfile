FROM rust:1.91-slim-bookworm

# python3 is what the grader uses as the reference zlib/gzip implementation;
# it is installed here because the container has no network at grading time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash agent

COPY workspace/ /app/
WORKDIR /app

# Warm the toolchain with the skeleton so an offline build is known to work,
# then drop the build output and hand the workspace to the agent user.
RUN cd /app/dz \
    && cargo build --release --offline \
    && ./target/release/dz zlib < /dev/null; rm -rf /app/dz/target \
    && chown -R agent:agent /app
