#Please ensure that you have the `tqdm` library installed. You can install it using `pip install tqdm`.

import os
import subprocess
from datetime import datetime
from tqdm import tqdm

# Get the current folder name
folder_name = os.path.basename(os.getcwd())

# Report folder path
report_folder = "report"

# Create the report folder if it doesn't exist
os.makedirs(report_folder, exist_ok=True)

# Report file paths
hayabusa_report = f"{report_folder}/{folder_name}_hayabusa_output.csv"
apt_hunter_report = f"{report_folder}/{folder_name}_apt_hunter_output"
chainsaw_report = f"{report_folder}/{folder_name}_chainsaw.csv"

# Log folder path
log_folder = "eventlog_operations_log"

# Create the log folder if it doesn't exist
os.makedirs(log_folder, exist_ok=True)

# Log file paths
hayabusa_log = f"{log_folder}/{folder_name}_hayabusa.log"
apt_hunter_log = f"{log_folder}/{folder_name}_apt_hunter.log"
chainsaw_log = f"{log_folder}/{folder_name}_chainsaw.log"

# Execute hayabusa and redirect stdout to log file and report file
hayabusa_cmd = f"/home/{os.environ['USER']}/git/hayabusa/./hayabusa-2.5.1-lin-gnu csv-timeline --ISO-8601 -t 20 --UTC -q -d \"{os.getcwd()}\" -o \"{hayabusa_report}\""
hayabusa_process = subprocess.Popen(hayabusa_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)

# Execute apt-hunter and redirect stdout to log file and report file
apt_hunter_cmd = f"python3 /home/{os.environ['USER']}/git/APT-Hunter-main/APT-Hunter.py -p \"{os.getcwd()}\" -cores 20 -tz UTC -allreport -o \"{apt_hunter_report}\""
apt_hunter_process = subprocess.Popen(apt_hunter_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)

# Execute chainsaw and redirect stdout to log file and report file
chainsaw_cmd = f"/home/{os.environ['USER']}/git/chainsaw/target/release/./chainsaw hunt \"{os.getcwd()}\" -s /home/{os.environ['USER']}/git/sigma --mapping /home/{os.environ['USER']}/git/chainsaw/mappings/sigma-event-logs-all.yml -r /home/{os.environ['USER']}/git/chainsaw/rules --timezone UTC --full --csv -o \"{chainsaw_report}\""
chainsaw_process = subprocess.Popen(chainsaw_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)

# Function to display tool completion status
def display_completion_status(tool_name, tool_process):
    # Wait for the tool to complete and get its output and error
    output, error = tool_process.communicate()

    if tool_process.returncode == 0:
        print(f"[{tool_name}] Tool has finished.")
    else:
        print(f"[{tool_name}] Tool has failed with the following error:\n{error}")

    # Write stdout and stderr to log files
    with open(f"{log_folder}/{folder_name}_{tool_name}.log", "w") as log_file:
        log_file.write(output)
        log_file.write(error)

# Display progress bar for each tool
with tqdm(total=3, desc="Running tools") as pbar:
    pbar.update(1)

    # Display hayabusa progress bar
    hayabusa_pbar = tqdm(desc="hayabusa", unit="s", leave=False)
while hayabusa_process.poll() is None:
    hayabusa_pbar.update(1)
hayabusa_pbar.close()
pbar.update(1)

# Display apt-hunter progress bar
apt_hunter_pbar = tqdm(desc="apt-hunter", unit="s", leave=False)
while apt_hunter_process.poll() is None:
    apt_hunter_pbar.update(1)
apt_hunter_pbar.close()
pbar.update(1)

# Display chainsaw progress bar
chainsaw_pbar = tqdm(desc="chainsaw", unit="s", leave=False)
while chainsaw_process.poll() is None:
    chainsaw_pbar.update(1)
chainsaw_pbar.close()
pbar.update(1)

print("eventlog_operations.py has finished.")
input("Please press any key to continue...")