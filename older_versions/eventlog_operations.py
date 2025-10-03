import os
import subprocess

# Get the current folder name
folder_name = os.path.basename(os.getcwd())

# Report folder path
report_folder = "report"

# Create the report folder if it doesn't exist
os.makedirs(report_folder, exist_ok=True)

# Report file paths
hayabusa_report = os.path.join(report_folder, f"{folder_name}_hayabusa_output.csv")
apt_hunter_report = os.path.join(report_folder, f"{folder_name}_apt_hunter_output")
chainsaw_report = os.path.join(report_folder, f"{folder_name}_chainsaw.csv")

# Log folder path
log_folder = "eventlog_operations_log"

# Create the log folder if it doesn't exist
os.makedirs(log_folder, exist_ok=True)

# Log file paths
hayabusa_log = os.path.join(log_folder, f"{folder_name}_hayabusa.log")
apt_hunter_log = os.path.join(log_folder, f"{folder_name}_apt_hunter.log")
chainsaw_log = os.path.join(log_folder, f"{folder_name}_chainsaw.log")

# Execute hayabusa in the background and redirect stdout to log file and report file
hayabusa_cmd = ["/home/{}/git/hayabusa/hayabusa-2.5.1-lin-gnu".format(os.getlogin()), "csv-timeline", "--ISO-8601", "-t", "20", "--UTC", "-q", "-d", os.getcwd(), "-o", hayabusa_report]
hayabusa_process = subprocess.Popen(hayabusa_cmd, stdout=open(hayabusa_log, 'w'), stderr=subprocess.STDOUT)

# Execute apt-hunter in the background and redirect stdout to log file and report file
apt_hunter_cmd = ["python3", "/home/{}/git/APT-Hunter-main/APT-Hunter.py".format(os.getlogin()), "-p", os.getcwd(), "-cores", "20", "-tz", "UTC", "-allreport", "-o", apt_hunter_report]
apt_hunter_process = subprocess.Popen(apt_hunter_cmd, stdout=open(apt_hunter_log, 'w'), stderr=subprocess.STDOUT)

# Execute chainsaw and redirect stdout to log file and report file
chainsaw_cmd = ["/home/{}/git/chainsaw/target/release/chainsaw".format(os.getlogin()), "hunt", os.getcwd(), "-s", "/home/{}/git/sigma".format(os.getlogin()), "--mapping", "/home/{}/git/chainsaw/mappings/sigma-event-logs-all.yml".format(os.getlogin()), "-r", "/home/{}/git/chainsaw/rules".format(os.getlogin()), "--timezone", "UTC", "--full", "--csv", chainsaw_report]
chainsaw_process = subprocess.Popen(chainsaw_cmd, stdout=open(chainsaw_log, 'w'), stderr=subprocess.STDOUT)

# Wait for each tool to finish
hayabusa_process.wait()
apt_hunter_process.wait()
chainsaw_process.wait()

# Function to display tool completion status
def display_completion_status(tool_name, process):
    if process.returncode == 0:
        print(f"[{tool_name}] Tool has finished.")
    else:
        print(f"[{tool_name}] Tool is pending to finish.")

# Display completion status for each tool
display_completion_status("hayabusa", hayabusa_process)
display_completion_status("apt-hunter", apt_hunter_process)
display_completion_status("chainsaw", chainsaw_process)

# Display script completion message
print("Script execution completed.")
