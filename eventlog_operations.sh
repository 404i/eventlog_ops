#!/bin/bash

# Get the current folder name
folder_name=$(basename "$(pwd)")

# Report folder path
report_folder="report"

# Create the report folder if it doesn't exist
mkdir -p "$report_folder"

# Report file paths
hayabusa_report="$report_folder/${folder_name}_hayabusa_output.csv"
apt_hunter_report="$report_folder/${folder_name}_apt_hunter_output"
chainsaw_report="$report_folder/${folder_name}_chainsaw.csv"

# Log folder path
log_folder="eventlog_operations_log"

# Create the log folder if it doesn't exist
mkdir -p "$log_folder"

# Log file paths
hayabusa_log="$log_folder/${folder_name}_hayabusa.log"
apt_hunter_log="$log_folder/${folder_name}_apt_hunter.log"
chainsaw_log="$log_folder/${folder_name}_chainsaw.log"

# Execute hayabusa in the background and redirect stdout to log file and report file
/home/<USER>/git/hayabusa/./hayabusa-2.5.1-lin-gnu csv-timeline --ISO-8601 -t 20 --UTC -q -d "$PWD" -o "$hayabusa_report" > "$hayabusa_log" 2>&1 &
hayabusa_pid=$!  #CHANGE <USER> with your username!

# Execute apt-hunter in the background and redirect stdout to log file and report file
python3 /home/<USER>/git/APT-Hunter-main/APT-Hunter.py -p "$PWD" -cores 20 -tz UTC -allreport -o "$apt_hunter_report" > "$apt_hunter_log" 2>&1 &
apt_hunter_pid=$! #CHANGE <USER> with your username!

# Execute chainsaw and redirect stdout to log file and report file
/home/<USER>/git/chainsaw/target/release/./chainsaw hunt "$PWD" -s /home/tsochkata/git/sigma --mapping /home/tsochkata/git/chainsaw/mappings/sigma-event-logs-all.yml -r /home/tsochkata/git/chainsaw/rules --timezone UTC --full --csv "$chainsaw_report" > "$chainsaw_log" 2>&1 &
chainsaw_pid=$! #CHANGE <USER> with your username!

# Function to display tool completion status
display_completion_status() {
    local tool_name=$1
    local tool_pid=$2

    if wait "$tool_pid"; then
        echo "[$tool_name] Tool has finished."
    else
        echo "[$tool_name] Tool is pending to finish."
    fi
}

# Display completion status for each tool
display_completion_status "hayabusa" "$hayabusa_pid"
display_completion_status "apt-hunter" "$apt_hunter_pid"
display_completion_status "chainsaw" "$chainsaw_pid"

# Display script completion message
echo "Script execution completed."
