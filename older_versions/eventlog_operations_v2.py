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

# Function to display tool completion status
def display_completion_status(tool_name, returncode):
    if returncode == 0:
        print(f"[{tool_name}] Tool has finished.")
    else:
        print(f"[{tool_name}] Tool has failed with return code: {returncode}")

# Execute hayabusa in the background and redirect stdout to log file and report file
hayabusa_cmd = f"/home/{os.environ['USER']}/git/hayabusa/./hayabusa-2.5.1-lin-gnu csv-timeline --ISO-8601 -t 20 --UTC -q -d \"{os.getcwd()}\" -o \"{hayabusa_report}\" > \"{hayabusa_log}\" 2>&1"
hayabusa_process = subprocess.Popen(hayabusa_cmd, shell=True)

# Execute apt-hunter in the background and redirect stdout to log file and report file
apt_hunter_cmd = f"python3 /home/{os.environ['USER']}/git/APT-Hunter-main/APT-Hunter.py -p \"{os.getcwd()}\" -cores 20 -tz UTC -allreport -o \"{apt_hunter_report}\" > \"{apt_hunter_log}\" 2>&1"
apt_hunter_process = subprocess.Popen(apt_hunter_cmd, shell=True)

# Execute chainsaw and redirect stdout to log file and report file
chainsaw_cmd = f"/home/{os.environ['USER']}/git/chainsaw/target/release/./chainsaw hunt \"{os.getcwd()}\" -s /home/{os.environ['USER']}/git/sigma --mapping /home/{os.environ['USER']}/git/chainsaw/mappings/sigma-event-logs-all.yml -r /home/{os.environ['USER']}/git/chainsaw/rules --timezone UTC --full --csv -o \"{chainsaw_report}\" > \"{chainsaw_log}\" 2>&1"
chainsaw_process = subprocess.Popen(chainsaw_cmd, shell=True)

# Display progress bars for each tool
with tqdm(total=3, desc="Running tools") as pbar:
    # Create individual progress bars for each tool
    hayabusa_pbar = tqdm(desc="hayabusa", unit="s", leave=False)
    apt_hunter_pbar = tqdm(desc="apt-hunter", unit="s", leave=False)
    chainsaw_pbar = tqdm(desc="chainsaw", unit="s", leave=False)

while hayabusa_process.poll() is None or apt_hunter_process.poll() is None or chainsaw_process.poll() is None:
    if hayabusa_process.poll() is None:
        hayabusa_pbar.update(1)
    if apt_hunter_process.poll() is None:
        apt_hunter_pbar.update(1)
    if chainsaw_process.poll() is None:
        chainsaw_pbar.update(1)

# Close the progress bars after the processes have finished
hayabusa_pbar.close()
apt_hunter_pbar.close()
chainsaw_pbar.close()

# Display completion status for each tool
display_completion_status("hayabusa", hayabusa_process.returncode)
display_completion_status("apt-hunter", apt_hunter_process.returncode)
display_completion_status("chainsaw", chainsaw_process.returncode)

pbar.update(3)

print("eventlog_operations.py has finished.")
input("Please press any key to continue...")

