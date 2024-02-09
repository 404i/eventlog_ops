# Requirements:

# Install tqdm via pip
# Install chainsaw, apt-hunter and hayabusa via git in $USER/git/
# Depending on your Hayabusa version you might need to change the path/binary name in the hayabusa executions snippet.


import os
import subprocess
from datetime import datetime
import time
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


print("eventlog_operations.py has finished.")
input("Please press any key to continue...")
