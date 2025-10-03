# Requirements:

# Install tqdm via pip
# Install chainsaw, apt-hunter and hayabusa via git in $USER/git/
# Depending on your Hayabusa version you might need to change the path/binary name in the hayabusa executions snippet.


import argparse
import configparser
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
#from tqdm import tqdm


# Locate configuration alongside script or executable
try:
    CONFIG_ROOT = Path(__file__).resolve().parent
except NameError:
    CONFIG_ROOT = Path(sys.argv[0]).resolve().parent

CONFIG_FILE = CONFIG_ROOT / "eventlog_tools.ini"


def prompt_for_path(prompt_text, default_path):
    """Interactively prompt user for a filesystem path, with validation."""

    while True:
        user_input = input(f"{prompt_text} [{default_path}]: ").strip()
        candidate = Path(user_input or default_path).expanduser()

        if candidate.exists():
            return candidate

        retry = input(
            f"Path '{candidate}' does not exist. Press Enter to retry or type 'yes' to accept anyway: "
        ).strip().lower()
        if retry in {"y", "yes"}:
            return candidate


def collect_tool_paths():
    """Guide the user through initial configuration of external tool locations."""

    print("Initial setup: specify where each tool is installed (absolute paths recommended).")
    defaults = {
        "hayabusa": Path.home() / "git" / "hayabusa" / "hayabusa",
        "apt_hunter": Path.home() / "git" / "APT-Hunter" / "APT-Hunter.py",
        "chainsaw": Path.home() / "git" / "chainsaw" / "target" / "release" / "chainsaw",
        "sigma": Path.home() / "git" / "sigma",
        "mapping": Path.home() / "git" / "chainsaw" / "mappings" / "sigma-event-logs-all.yml",
        "chainsaw_rules": Path.home() / "git" / "chainsaw" / "rules",
    }

    paths = {}
    paths["hayabusa"] = prompt_for_path("Path to hayabusa binary", defaults["hayabusa"])
    paths["apt_hunter"] = prompt_for_path("Path to APT-Hunter.py", defaults["apt_hunter"])
    paths["chainsaw"] = prompt_for_path("Path to chainsaw binary", defaults["chainsaw"])
    paths["sigma"] = prompt_for_path("Path to Sigma rules directory", defaults["sigma"])
    paths["mapping"] = prompt_for_path(
        "Path to chainsaw Sigma mapping file", defaults["mapping"]
    )
    paths["chainsaw_rules"] = prompt_for_path(
        "Path to chainsaw rules directory", defaults["chainsaw_rules"]
    )

    config = configparser.ConfigParser()
    config["tools"] = {key: str(value) for key, value in paths.items()}
    with CONFIG_FILE.open("w", encoding="utf-8") as config_file:
        config.write(config_file)

    print(f"Configuration saved to {CONFIG_FILE}. Delete this file to re-run setup.")
    return {key: Path(value) for key, value in paths.items()}


def load_tool_paths():
    """Load tool paths from configuration or trigger setup if missing."""

    config = configparser.ConfigParser()
    if not CONFIG_FILE.exists():
        return collect_tool_paths()

    config.read(CONFIG_FILE, encoding="utf-8")

    if "tools" not in config:
        return collect_tool_paths()

    tools_section = config["tools"]
    required_keys = {
        "hayabusa",
        "apt_hunter",
        "chainsaw",
        "sigma",
        "mapping",
        "chainsaw_rules",
    }

    missing = required_keys - set(tools_section.keys())
    if missing:
        print(f"Configuration missing keys: {', '.join(sorted(missing))}. Re-running setup.")
        return collect_tool_paths()

    return {key: Path(tools_section[key]).expanduser() for key in required_keys}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run Hayabusa, APT-Hunter, and Chainsaw against a log directory."
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Path to the directory containing event logs (defaults to an interactive prompt)",
    )
    return parser.parse_args()


def resolve_target_directory(args):
    if args.target:
        candidate = Path(args.target).expanduser()
    else:
        while True:
            user_input = input("Path to event log directory: ").strip()
            candidate = Path(user_input).expanduser()
            if candidate.exists():
                break
            print(f"Provided path '{candidate}' does not exist. Please try again.")
    if not candidate.exists():
        raise FileNotFoundError(f"Target directory '{candidate}' does not exist.")
    if not candidate.is_dir():
        raise NotADirectoryError(f"Target path '{candidate}' is not a directory.")
    return candidate.resolve()


args = parse_args()
target_dir = resolve_target_directory(args)
folder_name = target_dir.name
tool_paths = load_tool_paths()
hayabusa_path = tool_paths["hayabusa"]
apt_hunter_path = tool_paths["apt_hunter"]
chainsaw_path = tool_paths["chainsaw"]
chainsaw_sigma = tool_paths["sigma"]
chainsaw_mapping = tool_paths["mapping"]
chainsaw_rules = tool_paths["chainsaw_rules"]

# Report folder path
report_folder = target_dir / "report"

# Create the report folder if it doesn't exist
os.makedirs(report_folder, exist_ok=True)

# Report file paths
hayabusa_report = str(report_folder / f"{folder_name}_hayabusa_output.csv")
apt_hunter_report = str(report_folder / f"{folder_name}_apt_hunter_output")
chainsaw_report = str(report_folder / f"{folder_name}_chainsaw.csv")

# Log folder path
log_folder = target_dir / "eventlog_operations_log"

# Create the log folder if it doesn't exist
os.makedirs(log_folder, exist_ok=True)

hayabusa_log = str(log_folder / f"{folder_name}_hayabusa.log")
apt_hunter_log = str(log_folder / f"{folder_name}_apt_hunter.log")
chainsaw_log = str(log_folder / f"{folder_name}_chainsaw.log")

# Execute hayabusa in the background and redirect stdout to log file and report file
hayabusa_cmd = (
    f"{shlex.quote(str(hayabusa_path))} csv-timeline --ISO-8601 -t 20 --UTC -q --no-wizard "
    f"-d {shlex.quote(str(target_dir))} -o {shlex.quote(hayabusa_report)} > {shlex.quote(hayabusa_log)} 2>&1"
)
hayabusa_process = subprocess.Popen(hayabusa_cmd, shell=True)

# Execute apt-hunter in the background and redirect stdout to log file and report file
apt_hunter_cmd = (
    f"python3 {shlex.quote(str(apt_hunter_path))} -p {shlex.quote(str(target_dir))} "
    f"-cores 20 -tz UTC -allreport -o {shlex.quote(apt_hunter_report)} > {shlex.quote(apt_hunter_log)} 2>&1"
)
apt_hunter_process = subprocess.Popen(apt_hunter_cmd, shell=True)

# Execute chainsaw and redirect stdout to log file and report file
chainsaw_cmd = (
    f"{shlex.quote(str(chainsaw_path))} hunt {shlex.quote(str(target_dir))} "
    f"-s {shlex.quote(str(chainsaw_sigma))} --mapping {shlex.quote(str(chainsaw_mapping))} "
    f"-r {shlex.quote(str(chainsaw_rules))} --timezone UTC --full --csv "
    f"-o {shlex.quote(chainsaw_report)} > {shlex.quote(chainsaw_log)} 2>&1"
)
chainsaw_process = subprocess.Popen(chainsaw_cmd, shell=True)

# Display running and finished tools with elapsed time
running_tools = []
finished_tools = []
start_time = time.time()

while hayabusa_process.poll() is None or apt_hunter_process.poll() is None or chainsaw_process.poll() is None:
    current_time = time.time()
    elapsed_time = current_time - start_time

    if hayabusa_process.poll() is None and "hayabusa" not in running_tools:
        running_tools.append("hayabusa")
        print(f"Running tools: {', '.join(running_tools)} ({elapsed_time:.2f} seconds)")

    if apt_hunter_process.poll() is None and "apt-hunter" not in running_tools:
        running_tools.append("apt-hunter")
        print(f"Running tools: {', '.join(running_tools)} ({elapsed_time:.2f} seconds)")

    if chainsaw_process.poll() is None and "chainsaw" not in running_tools:
        running_tools.append("chainsaw")
        print(f"Running tools: {', '.join(running_tools)} ({elapsed_time:.2f} seconds)")

    if hayabusa_process.poll() is not None and "hayabusa" in running_tools and "hayabusa" not in finished_tools:
        finished_tools.append("hayabusa")
        running_tools.remove("hayabusa")
        print(f"Finished tools: {', '.join(finished_tools)} ({elapsed_time:.2f} seconds)")

    if apt_hunter_process.poll() is not None and "apt-hunter" in running_tools and "apt-hunter" not in finished_tools:
        finished_tools.append("apt-hunter")
        running_tools.remove("apt-hunter")
        print(f"Finished tools: {', '.join(finished_tools)} ({elapsed_time:.2f} seconds)")

    if chainsaw_process.poll() is not None and "chainsaw" in running_tools and "chainsaw" not in finished_tools:
        finished_tools.append("chainsaw")
        running_tools.remove("chainsaw")
        print(f"Finished tools: {', '.join(finished_tools)} ({elapsed_time:.2f} seconds)")

    time.sleep(0.5)


print("eventlog_operations.py has finished.")
input("Please press any key to continue...")
