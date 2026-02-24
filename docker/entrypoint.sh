#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  eventlog-ops container entrypoint
#
#  Usage (passed straight through to eventlog_operations_v4.py):
#    docker run --rm -v /path/to/evtx:/data eventlog-ops [options]
#
#  If no positional TARGET is given, /data is used as the default.
#
#  Useful environment variables:
#    LLM_ENDPOINT      – LLM API base URL (updates the ini on first run)
#    LLM_MODEL         – LLM model identifier
#    EVENTLOG_AUTO_CONFIG=1  – rebuild ini from env vars (already set in image)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT="/app/eventlog_operations_v4.py"
INI="/app/eventlog_tools.ini"

# ── Honour LLM_ENDPOINT/LLM_MODEL at runtime without re-baking the image ─────
# If the caller passes LLM_ENDPOINT we patch the ini in-place so that a bare
# `--llm-summary` flag picks it up without any interactive prompts.
# We use awk to scope changes to the [llm] section only, avoiding accidental
# rewrites of identically-named keys in other sections (e.g. [tools]).
_patch_ini_key() {
    local file="$1" section="$2" key="$3" value="$4"
    awk -v section="${section}" -v key="${key}" -v value="${value}" '
        /^\[/ { in_section = ($0 == "[" section "]") }
        in_section && $0 ~ "^" key "[[:space:]]*=" { $0 = key " = " value; found=1 }
        { print }
    ' "${file}" > "${file}.tmp" && mv "${file}.tmp" "${file}"
}

if [[ -n "${LLM_ENDPOINT:-}" && -f "${INI}" ]]; then
    _patch_ini_key "${INI}" "llm" "endpoint" "${LLM_ENDPOINT}"
    _patch_ini_key "${INI}" "llm" "enabled"  "true"
fi
if [[ -n "${LLM_MODEL:-}" && -f "${INI}" ]]; then
    _patch_ini_key "${INI}" "llm" "model" "${LLM_MODEL}"
fi

# ── Default positional arg to /data when none is supplied ─────────────────────
# Detect whether the first non-flag argument looks like a path; if the user
# only supplied flags (e.g. --llm-summary), prepend /data automatically.
args=("$@")
has_target=false
for arg in "${args[@]}"; do
    case "${arg}" in
        --*)  ;;          # flag – skip
        -*)   ;;          # short flag – skip
        *)    has_target=true; break ;;
    esac
done

if [[ "${has_target}" == "false" ]]; then
    args=("/data" "${args[@]}")
fi

exec python3 "${SCRIPT}" "${args[@]}"
