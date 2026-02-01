# Moltbot/OpenClaw Scanner Suite

A collection of Python scripts to detect, track, and analyze installations of clawbot, moltbot, and openclaw.

## Scripts

### 1. `installation_tracker.py` - File-based Scanner
Scans the filesystem for installations, configs, logs, and integrations.

### 2. `openclaw_cli_scanner.py` - CLI-based Scanner
Uses the OpenClaw CLI to fetch live data from a running installation.

## Features

### Installation Tracker (`installation_tracker.py`)
- **Installation Detection**: Checks for binaries, npm packages, and workspace directories
- **Active Status Monitoring**: Detects running processes and listening ports
- **Configuration Parsing**: Reads and parses JSON configuration files
- **Log Analysis**: Extracts connection information from log files
- **API Key Detection**: Finds API keys in config files (displayed masked)
- **User Information**: Collects detailed user info from local machine settings
- **TOOLS.md Parsing**: Extracts user-defined integrations
- **Available Skills**: Scans moltbot source for 50+ available skills

### OpenClaw CLI Scanner (`openclaw_cli_scanner.py`)
- **Skills**: List available skills with readiness status
- **Channels**: Show configured channels and their health
- **Agents**: List isolated agents with workspace details
- **Models**: Display available models and aliases
- **Plugins**: Show installed plugins
- **Status**: Gateway health and connectivity
- **Doctor**: Run health diagnostics

## Requirements

- Python 3.6+
- No external dependencies (uses standard library only)

## Installation

```bash
git clone <repository-url>
cd moltbolt_scanner_v2
chmod +x installation_tracker.py
```

## Usage

### Basic Scan (Text Report)

```bash
python3 installation_tracker.py
```

### JSON Output

```bash
python3 installation_tracker.py --json
```

### Save to File

```bash
python3 installation_tracker.py -o report.txt
python3 installation_tracker.py --json -o report.json
```

### Scan Specific Tool

```bash
python3 installation_tracker.py --tool openclaw
python3 installation_tracker.py --tool moltbot
python3 installation_tracker.py --tool clawbot
```

### Provide API Key

```bash
python3 installation_tracker.py --api-key "your-api-key-here"
```

---

## OpenClaw CLI Scanner Usage

### Basic Scan (requires openclaw/moltbot CLI)

```bash
python3 openclaw_cli_scanner.py
```

### JSON Output

```bash
python3 openclaw_cli_scanner.py --json
```

### Specific Data

```bash
python3 openclaw_cli_scanner.py --skills      # Only skills
python3 openclaw_cli_scanner.py --channels    # Only channels
python3 openclaw_cli_scanner.py --models      # Only models
python3 openclaw_cli_scanner.py --agents      # Only agents
python3 openclaw_cli_scanner.py --plugins     # Only plugins
python3 openclaw_cli_scanner.py --status      # Only status
python3 openclaw_cli_scanner.py --doctor      # Run diagnostics
```

### Specify CLI Command

```bash
python3 openclaw_cli_scanner.py --cli moltbot
python3 openclaw_cli_scanner.py --cli clawdbot
```

### Save to File

```bash
python3 openclaw_cli_scanner.py --json -o report.json
```

---

## Output

### Machine Information

| Field | Description |
|-------|-------------|
| hostname | System hostname |
| computer_name | macOS computer name |
| local_hostname | macOS local hostname |
| api_key_provided | Masked API key |

### User Information

| Field | Description |
|-------|-------------|
| username | Login username |
| full_name | Full name from system settings |
| user_id | Numeric user ID |
| group_id | Numeric group ID |
| home_directory | User's home path |
| shell | Default shell |
| groups | All groups user belongs to |
| system_info | Full uname output |

### Tool Information (per tool)

| Field | Description |
|-------|-------------|
| installed | Whether the tool is installed |
| active | Whether the tool is currently running |
| installation_details | Binary path, npm info, workspace location |
| processes | Running process details (PID, CPU, memory) |
| port_listening | Whether default port is listening |
| config_files | Found configuration files and their contents |
| log_files | Found log files |
| connections | Extracted connection targets from logs |
| api_keys_found | API keys found in configs (masked) |

## Checked Locations

### openclaw

- Config: `~/.openclaw/openclaw.json`, `~/.config/openclaw/config.json`
- Logs: `~/.openclaw/logs/*.log`, `~/.openclaw/workspace/logs/*.log`
- Workspace: `~/.openclaw/workspace`
- Port: 18789

### moltbot

- Config: `~/.moltbot/config.json`, `~/.config/moltbot/settings.json`
- Logs: `~/.moltbot/logs/*.log`, `~/.moltbot/*.log`
- Workspace: `~/.moltbot/workspace`
- Port: 18800

### clawbot

- Config: `~/.clawbot/config.json`, `~/.config/clawbot/settings.json`
- Logs: `~/.clawbot/logs/*.log`, `~/.clawbot/*.log`
- Workspace: `~/.clawbot/workspace`
- Port: 18801

## Example Output

### Text Report

```
============================================================
INSTALLATION TRACKER REPORT
Scan Time: 2026-02-01T13:02:42.286726
============================================================

MACHINE INFORMATION:
  Hostname: DJ4DX6WYL4
  Computer Name: DJ4DX6WYL4
  Local Hostname: DJ4DX6WYL4-5
  API Key (masked): YOUR****

USER INFORMATION:
  Username: john.doe
  Full Name: John Doe
  User ID: 501
  Group ID: 20
  Home Directory: /Users/john.doe
  Shell: /bin/zsh
  Groups: staff, everyone, admin

----------------------------------------
TOOL: OPENCLAW
----------------------------------------
  Installed: YES
  Active: YES
  Installation Details:
    binary_path: /usr/local/bin/openclaw
  Running Processes (1):
    PID 12345: openclaw-gateway --port 18789...
  Port 18789: LISTENING
  Config Files (1):
    - /Users/john.doe/.openclaw/openclaw.json
  Connections Found (2):
    - api.anthropic.com
    - ws://127.0.0.1:18789
```

### JSON Output

```json
{
  "scan_timestamp": "2026-02-01T13:02:42.286726",
  "machine_info": {
    "hostname": "DJ4DX6WYL4",
    "api_key_provided": "YOUR****",
    "user": {
      "username": "john.doe",
      "full_name": "John Doe",
      "user_id": "501",
      "group_id": "20",
      "home_directory": "/Users/john.doe",
      "shell": "/bin/zsh",
      "groups": ["staff", "everyone", "admin"]
    }
  },
  "tools": {
    "openclaw": {
      "installed": true,
      "active": true,
      "processes": [...],
      "connections": [...]
    }
  }
}
```

## Extending

To add support for additional tools, edit the `TOOL_CONFIGS` dictionary in `installation_tracker.py`:

```python
TOOL_CONFIGS = {
    "newtool": {
        "config_paths": ["~/.newtool/config.json"],
        "log_paths": ["~/.newtool/logs/*.log"],
        "workspace_path": "~/.newtool/workspace",
        "process_names": ["newtool", "newtool-daemon"],
        "default_port": 19000,
        "binary_names": ["newtool"],
    },
}
```

## License

MIT
