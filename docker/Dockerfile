# ─────────────────────────────────────────────────────────────────────────────
#  eventlog_ops – containerised EVTX analysis
#
#  Build args you can override:
#    HAYABUSA_VERSION   (default 3.8.0)
#    CHAINSAW_VERSION   (default 2.14.1)
#
#  Runtime env vars (all optional):
#    LLM_ENDPOINT     – override the LLM endpoint at startup
#    LLM_MODEL        – override the LLM model name
#    EVENTLOG_*       – override individual tool paths (see auto_configure())
# ─────────────────────────────────────────────────────────────────────────────

ARG HAYABUSA_VERSION=3.8.0
ARG CHAINSAW_VERSION=2.14.1

FROM python:3.12-slim

ARG HAYABUSA_VERSION
ARG CHAINSAW_VERSION
# TARGETARCH is a built-in BuildKit arg (amd64 / arm64)
ARG TARGETARCH=amd64

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    # Skip all interactive prompts; the script reads the pre-written ini instead.
    EVENTLOG_AUTO_CONFIG=1

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        unzip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Hayabusa ──────────────────────────────────────────────────────────────────
# The release zip bundles the binary + rules/ + config/ – no git clone needed.
RUN set -ex; \
    case "${TARGETARCH}" in \
      amd64) arch="x64-musl" ;; \
      arm64) arch="aarch64-gnu" ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL \
      "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-${arch}.zip" \
      -o /tmp/hayabusa.zip; \
    mkdir -p /opt/hayabusa; \
    unzip -o /tmp/hayabusa.zip -d /opt/hayabusa/; \
    # Rename the versioned binary to a stable 'hayabusa' name
    mv "/opt/hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-${arch}" /opt/hayabusa/hayabusa; \
    chmod +x /opt/hayabusa/hayabusa; \
    rm -f /tmp/hayabusa.zip

# ── Chainsaw ──────────────────────────────────────────────────────────────────
# The release tar bundles the binary + mappings/ under a top-level chainsaw/ dir.
# Rules are not in the release tar – fetch them via a sparse git clone.
RUN set -ex; \
    case "${TARGETARCH}" in \
      amd64) arch="x86_64-unknown-linux-gnu" ;; \
      arm64) arch="aarch64-unknown-linux-gnu" ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    mkdir -p /opt/chainsaw; \
    curl -fsSL \
      "https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VERSION}/chainsaw_${arch}.tar.gz" \
      -o /tmp/chainsaw.tar.gz; \
    # The tar has a top-level chainsaw/ dir; strip it so files land in /opt/chainsaw/
    tar -xzf /tmp/chainsaw.tar.gz --strip-components=1 -C /opt/chainsaw/; \
    chmod +x /opt/chainsaw/chainsaw; \
    rm -f /tmp/chainsaw.tar.gz

# Fetch chainsaw detection rules (not included in the release tar).
RUN git clone --depth 1 --filter=blob:none --no-checkout \
        https://github.com/WithSecureLabs/chainsaw.git /tmp/chainsaw-git \
    && cd /tmp/chainsaw-git \
    && git sparse-checkout init --no-cone \
    && git sparse-checkout set 'rules/' \
    && git checkout HEAD \
    && mv /tmp/chainsaw-git/rules /opt/chainsaw/rules \
    && rm -rf /tmp/chainsaw-git

# ── APT-Hunter ────────────────────────────────────────────────────────────────
RUN git clone --depth 1 \
        https://github.com/ahmedkhlief/APT-Hunter.git /opt/apt-hunter

RUN python3 -m venv /opt/apt-hunter/.venv \
    && /opt/apt-hunter/.venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/apt-hunter/.venv/bin/pip install --no-cache-dir \
         -r /opt/apt-hunter/requirements.txt

# ── Sigma rules ───────────────────────────────────────────────────────────────
# Sparse-checkout only the rules/ subtree to keep the layer small.
RUN git clone --depth 1 --filter=blob:none --no-checkout \
        https://github.com/SigmaHQ/sigma.git /opt/sigma \
    && cd /opt/sigma \
    && git sparse-checkout init --no-cone \
    && git sparse-checkout set 'rules/' \
    && git checkout HEAD

# ── Application ───────────────────────────────────────────────────────────────
WORKDIR /app

# Install optional Python dependencies used by the script.
RUN pip install --no-cache-dir requests openpyxl

COPY eventlog_operations_v4.py .

# Pre-write the ini so the script never prompts for paths.
# Values mirror CONTAINER_TOOL_DEFAULTS in the script.
RUN printf '%s\n' \
      '[tools]' \
      'hayabusa          = /opt/hayabusa/hayabusa' \
      'hayabusa_rules    = /opt/hayabusa/rules' \
      'apt_hunter        = /opt/apt-hunter/APT-Hunter.py' \
      'apt_hunter_python = /opt/apt-hunter/.venv/bin/python' \
      'chainsaw          = /opt/chainsaw/chainsaw' \
      'sigma             = /opt/sigma/rules' \
      'mapping           = /opt/chainsaw/mappings/sigma-event-logs-all.yml' \
      'chainsaw_rules    = /opt/chainsaw/rules' \
      '' \
      '[llm]' \
      'enabled         = false' \
      'endpoint        = http://host.docker.internal:1234/v1/chat/completions' \
      'model           = openai/gpt-oss-120b' \
      'system_prompt   = You are an incident-response assistant. Summarize findings with a concise markdown table (columns: Tool, Key Finding, Supporting Evidence) followed by a short narrative summary.' \
      'temperature     = 0.2' \
      'max_tokens      = -1' \
      'timeout_seconds = 180' \
    > /app/eventlog_tools.ini

# /data is the default mount point for EVTX files.
VOLUME ["/data"]

COPY docker/entrypoint.sh /usr/local/bin/eventlog-ops
RUN chmod +x /usr/local/bin/eventlog-ops

ENTRYPOINT ["eventlog-ops"]
# Pass /data as the default target so bare `docker run` works.
CMD ["/data"]
