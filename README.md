# eventlog_ops
eventlog operations script using chainsaw, hayabusa and APT-Hunter for rapid triage and forensics on windows event logs.
Assuming you are running the tools from `$USER/git/` and you have installed tqdm via `pip install tqdm`

Links to tools:

https://github.com/Yamato-Security/hayabusa

https://github.com/WithSecureLabs/chainsaw

https://github.com/ahmedkhlief/APT-Hunter/releases/tag/V3.0

You may need to ammend the path to the tools in the script as their versions change.

![image](https://github.com/404i/eventlog_ops/assets/116623836/48773096-b7b2-4b18-a7ea-70fd3702175b)

The tool runs in current directory, so you need to copy it in the same directory with the event logs. 

Run with `python3 eventlog_operations_v3.py`

![image](https://github.com/404i/eventlog_ops/assets/116623836/7bea041f-efe6-4cc9-9e9b-a3f9bfef2fc8)


The tool logs stdout from the three tools in ./event_log_operations and logs output from the tools in ./report


![image](https://github.com/404i/eventlog_ops/assets/116623836/21638b8b-20c1-499b-8400-7dd43ceb90f9)
