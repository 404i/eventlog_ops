# eventlog_ops
eventlog operations script using chainsaw, hayabusa and APT-Hunter for rapid triage and forensics on windows event logs.
Assuming you are running the tools from `$USER/git/` and you have installed tqdm via `pip install tqdm`

Links to tools:

https://github.com/Yamato-Security/hayabusa

https://github.com/WithSecureLabs/chainsaw

https://github.com/ahmedkhlief/APT-Hunter/releases/tag/V3.0

You may need to ammend the path to the tools in the script as their versions change.

The tool runs in current directory, so you need to copy it in the same directory with the event logs. 

Run with `python3 eventlog_operations_v3.py`

The tool logs stdout from the three tools in ./event_log_operations and logs output from the tools in ./report
