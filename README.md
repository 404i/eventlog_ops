# Event Log Operations (v4)

Python orchestration script that runs **Hayabusa**, **APT-Hunter**, and **Chainsaw** over a Windows event log collection, aggregates the results, and (optionally) summarises the findings with a local LLM.

---

## Features

- Automatic detection of tool locations with persisted configuration (`eventlog_tools.ini`).
- Progress updates, failure detection, and retry support for each tool.
- Consolidated report/log directory: `eventlog_operations_output/<case>`.
- Cached artifact metadata (CSV/XLSX previews, directory contents) reused for progress, summaries, and LLM prompts.
- Optional pre-run update step for Git-based tools (`--update-tools`).
- Optional LLM summarisation (`--llm-summary`) with configurable endpoint, prompt, temperature, token limit, and timeout. Output is saved and printed with colored confidence levels (traffic-light scheme).
- Archive creation on demand (`--archive`).
- Rerun detection: if an output set already exists you can rerun everything, regenerate only the LLM summary, archive, or exit.

---

## Requirements

- Python 3.9+ (tested on macOS, Linux).
- External tools cloned under a location accessible to the script (default assumption is `~/git/`):
  - [Hayabusa](https://github.com/Yamato-Security/hayabusa)
  - [Chainsaw](https://github.com/WithSecureLabs/chainsaw)
  - [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter)
- Python packages:
  - `requests` (for LLM integration, optional)
  - `openpyxl` (for XLSX previews in LLM context, optional)
  - `tqdm` is no longer required by the script.

*Tip:* install optional packages with `python3 -m pip install --user requests openpyxl`.

---

## Initial Setup

Run the script once from the directory containing your EVTX files:

```bash
python3 eventlog_operations_v4.py
```

You will be prompted for:

1. Paths to the Hayabusa, APT-Hunter, Chainsaw binaries and related directories.
2. Python interpreter for APT-Hunter (ideally a project-specific virtualenv).
3. Optional LLM configuration (endpoint, model, prompt, temperature, max tokens, timeout).

The answers are stored in `eventlog_tools.ini`. Delete the file to rerun the wizard.

---

## Usage

```bash
python3 eventlog_operations_v4.py [TARGET] [options]
```

- **TARGET** (optional positional): path to the directory containing EVTX files. If omitted, you will be prompted.

### Common Flags

| Flag | Description |
|------|-------------|
| `--update-tools` | Runs `git pull` (and a cargo build for Hayabusa, pip install for APT-Hunter venv) before processing. |
| `--retry-failed` | Automatically reruns any tool that exits non-zero once. |
| `--llm-summary` | Sends collected artifacts to the configured LLM endpoint and stores/prints a generated summary. |
| `--archive` | Creates a timestamped ZIP archive of `eventlog_operations_output` and logs. |
| `--debug` | Enables verbose logging to stdout. |
| `--debug-log <path>` | Writes detailed logs to the supplied file. |

When existing outputs are detected for the given target, the script offers options to rerun, regenerate the LLM summary, archive, or exit.

---

## Output Layout

```
<case>/eventlog_operations_output/
  ├─ <case>_hayabusa_output.csv
  ├─ <case>_apt_hunter_output_Report.xlsx
  ├─ <case>_apt_hunter_output_TimeSketch.csv
  ├─ <case>_chainsaw_output/...
  ├─ <case>_llm_summary.txt (when --llm-summary used)
  └─ eventlog_operations_log/
       ├─ <case>_hayabusa.log
       ├─ <case>_apt_hunter.log
       └─ <case>_chainsaw.log
```

All progress updates and summaries are color-coded (requires a TTY). Cached artifact metadata avoids redundant parsing for large CSV/XLSX outputs.

---

## Tips

- Ensure Hayabusa is built with the latest parser (`cargo build --release`) to avoid Sigma rule parsing warnings.
- APT-Hunter performs best from a dedicated virtualenv (`python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`).
- For heavy LLM responses, adjust `timeout_seconds` in the `[llm]` section of `eventlog_tools.ini`.
- Use `--debug-log` when running unattended so you have a persistent execution trail.

---

## License

This project inherits the licensing terms supplied in `LICENSE`.
