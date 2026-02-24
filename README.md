# Event Log Operations (v4)

Python orchestration script that runs **Hayabusa**, **APT-Hunter**, and **Chainsaw** over a Windows event log collection, aggregates the results, and (optionally) summarises the findings with a local LLM.

Available as a standalone script or as a self-contained Docker image (`eventlog-ops`).

---

## Features

- Automatic detection of tool locations with persisted configuration (`eventlog_tools.ini`).
- Progress updates, failure detection, and retry support for each tool.
- Consolidated report/log directory: `<target>/eventlog_operations_output/`.
- Cached artifact metadata (CSV/XLSX previews, directory contents) reused for progress, summaries, and LLM prompts.
- Optional pre-run update step for Git-based tools (`--update-tools`).
- Optional LLM summarisation (`--llm-summary`) with configurable endpoint, prompt, temperature, token limit, and timeout. Output is saved and printed with colored confidence levels (traffic-light scheme).
- Archive creation on demand (`--archive`).
- Rerun detection: if an output set already exists you can rerun everything, regenerate only the LLM summary, archive, or exit.
- Per-tool skip flags (`--skip-hayabusa`, `--skip-apt-hunter`, `--skip-chainsaw`) to run a subset of tools.

---

## Docker (recommended)

### Build

```bash
docker build -f docker/Dockerfile -t eventlog-ops:latest .
```

The image bundles Hayabusa, Chainsaw, APT-Hunter (with its Python virtualenv), and Sigma rules. No local tool installation is needed.

Build args you can override:

| Arg | Default |
|-----|---------|
| `HAYABUSA_VERSION` | `3.8.0` |
| `CHAINSAW_VERSION` | `2.14.1` |

The image is built for the host architecture automatically via BuildKit (`TARGETARCH`). Hayabusa and APT-Hunter support both `amd64` and `arm64`. **Chainsaw** ships an `x86_64` binary only; on Apple Silicon (arm64) it will fail at runtime — use `--skip-chainsaw` (see below).

### Run

```bash
docker run --rm \
  -v "/path/to/evtx/files:/data" \
  eventlog-ops:latest [options]
```

`/data` is the default target directory. Pass a different path as the first positional argument if needed.

#### Skip broken/unsupported tools

```bash
# ARM Mac — Chainsaw binary is x86_64-only, skip it
docker run --rm -v "/path/to/evtx:/data" eventlog-ops:latest --skip-chainsaw

# Run Hayabusa only
docker run --rm -v "/path/to/evtx:/data" eventlog-ops:latest \
  --skip-apt-hunter --skip-chainsaw
```

#### Enable LLM summarisation at runtime

```bash
docker run --rm \
  -v "/path/to/evtx:/data" \
  -e LLM_ENDPOINT="http://host.docker.internal:1234/v1/chat/completions" \
  -e LLM_MODEL="openai/gpt-oss-120b" \
  eventlog-ops:latest --llm-summary
```

`LLM_ENDPOINT` and `LLM_MODEL` are patched into the bundled `eventlog_tools.ini` at startup; no image rebuild is needed.

#### Iterate on the script without rebuilding

Bind-mount the script over the copy baked into the image:

```bash
docker run --rm \
  -v "/path/to/evtx:/data" \
  -v "/path/to/eventlog_operations_v4.py:/app/eventlog_operations_v4.py:ro" \
  eventlog-ops:latest [options]
```

> **Note:** `/data` must **not** be mounted read-only — the pipeline writes output into the target directory.

---

## Standalone (no Docker)

### Requirements

- Python 3.9+ (tested on macOS, Linux).
- External tools cloned/installed at paths accessible to the script (default: `~/git/`):
  - [Hayabusa](https://github.com/Yamato-Security/hayabusa)
  - [Chainsaw](https://github.com/WithSecureLabs/chainsaw)
  - [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter)
- Python packages:
  - `requests` (for LLM integration, optional)
  - `openpyxl` (for XLSX previews in LLM context, optional)

```bash
python3 -m pip install --user requests openpyxl
```

### Initial setup

Run the script once to trigger the configuration wizard:

```bash
python3 eventlog_operations_v4.py
```

You will be prompted for:

1. Paths to the Hayabusa, APT-Hunter, Chainsaw binaries and related directories.
2. Python interpreter for APT-Hunter (ideally a project-specific virtualenv).
3. Optional LLM configuration (endpoint, model, prompt, temperature, max tokens, timeout).

Answers are stored in `eventlog_tools.ini`. Delete the file to rerun the wizard.

---

## Usage

```bash
python3 eventlog_operations_v4.py [TARGET] [options]
# or, inside the container:
docker run --rm -v "/path/to/evtx:/data" eventlog-ops:latest [options]
```

**TARGET** (optional positional): path to the directory containing EVTX files. Defaults to the current directory (standalone) or `/data` (Docker).

### Flags

| Flag | Description |
|------|-------------|
| `--skip-hayabusa` | Skip the Hayabusa scan. |
| `--skip-apt-hunter` | Skip the APT-Hunter scan. |
| `--skip-chainsaw` | Skip the Chainsaw scan. |
| `--update-tools` | Runs `git pull` (and cargo build / pip install) before processing. |
| `--retry-failed` | Automatically reruns any tool that exits non-zero once. |
| `--llm-summary` | Sends collected artifacts to the configured LLM endpoint and stores/prints a generated summary. |
| `--archive` | Creates a timestamped ZIP archive of `eventlog_operations_output` and logs. |
| `--debug` | Enables verbose logging to stdout. |
| `--debug-log <path>` | Writes detailed logs to the supplied file. |

When existing outputs are detected for the given target, the script offers options to rerun, regenerate the LLM summary, archive, or exit.

---

## Output layout

```
<target>/eventlog_operations_output/
  ├─ <case>_hayabusa_output.csv
  ├─ <case>_apt_hunter_output/
  │    ├─ out_Report.xlsx
  │    ├─ out_TimeSketch.csv
  │    └─ out_Collected_SIDs.csv
  ├─ <case>_chainsaw_output/
  │    └─ ...
  ├─ <case>_llm_summary.txt          (when --llm-summary used)
  └─ eventlog_operations_log/
       ├─ <case>_hayabusa.log
       ├─ <case>_apt_hunter.log
       └─ <case>_chainsaw.log
```

All progress updates and summaries are color-coded (requires a TTY). Cached artifact metadata avoids redundant parsing for large CSV/XLSX outputs.

---

## Known limitations

### Chainsaw on Apple Silicon (arm64)

The Chainsaw release binary is `x86_64`-only. On an ARM Mac (even under Rosetta) the binary will fail inside a Linux Docker container. Use `--skip-chainsaw` until an `aarch64` build is available or the image is rebuilt from source for ARM.

### APT-Hunter coverage

APT-Hunter does not include Sysmon (Microsoft-Windows-Sysmon/Operational) detection rules. If your EVTX collection is Sysmon-only, APT-Hunter will complete successfully but produce zero detections. This is expected behaviour, not a pipeline failure.

### APT-Hunter multiprocessing in Docker on macOS

APT-Hunter's directory-mode (`-p <directory>`) uses `multiprocessing.Process` with `fork`, which deadlocks inside a Docker container on macOS. The pipeline works around this by running APT-Hunter once per file instead of passing the whole directory.

---

## Tips

- Ensure Hayabusa is built with the latest parser (`cargo build --release`) to avoid Sigma rule parsing warnings.
- APT-Hunter performs best from a dedicated virtualenv (`python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`).
- For heavy LLM responses, adjust `timeout_seconds` in the `[llm]` section of `eventlog_tools.ini`.
- Use `--debug-log` when running unattended so you have a persistent execution trail.

---

## License

This project inherits the licensing terms supplied in `LICENSE`.
