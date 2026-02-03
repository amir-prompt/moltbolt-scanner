# OpenClaw Usage Scanner

A Python script to scan OpenClaw usage data, including active skills, session logs, and app/tool usage analytics.

## Features

- **User Details**: Collects local machine user information (username, hostname, OS)
- **Active Skills**: Filters and lists only active/eligible skills from CLI
- **Session Log Analysis**: Scans session `.jsonl` files for tool calls
- **App Detection**: Extracts app names from commands (open -a, AppleScript, killall, etc.)
- **Tools Summary**: Aggregates tool usage statistics across sessions
- **Apps Summary**: Tracks which macOS apps were invoked via commands

## Requirements

- Python 3.6+
- No external dependencies (uses standard library only)

## Installation

```bash
git clone <repository-url>
cd moltbolt_scanner_v2
chmod +x openclaw_usage.py
```

## Usage

### Basic Scan (JSON output)

```bash
python3 openclaw_usage.py
```

### Full Output (includes all tool calls and details)

```bash
python3 openclaw_usage.py --full
```

### Compact JSON (no indentation)

```bash
python3 openclaw_usage.py --compact
```

### Specify CLI Command

```bash
python3 openclaw_usage.py --cli moltbot
python3 openclaw_usage.py --cli clawdbot
```

### Limit Tool Calls in Output

```bash
python3 openclaw_usage.py --full --limit 100
```

## Output

### Default Output

By default, the script outputs a summary with user details and aggregated statistics:

```json
{
  "scan_timestamp": "2026-02-02T10:30:00.000000",
  "user": {
    "username": "john.doe",
    "home_dir": "/Users/john.doe",
    "current_dir": "/Users/john.doe/projects",
    "hostname": "MacBook-Pro.local",
    "os": {
      "system": "Darwin",
      "release": "25.2.0",
      "version": "Darwin Kernel Version 25.2.0",
      "machine": "arm64"
    },
    "shell": "/bin/zsh",
    "lang": "en_US.UTF-8"
  },
  "summary": {
    "active_skills": [...],
    "active_skills_count": 5,
    "apps_detected": ["Safari", "Slack", "VS Code"],
    "apps_detected_count": 3,
    "tools_used": ["Bash", "Read", "Write", "Edit"],
    "tools_used_count": 4,
    "total_tool_calls": 150,
    "sessions_scanned": 10
  }
}
```

### Full Output (with `--full` flag)

Includes additional details:

| Field | Description |
|-------|-------------|
| `openclaw_path` | Path to the `.openclaw` folder |
| `active_skills` | Full skill objects with metadata |
| `session_analysis.tool_calls` | Recent tool calls with arguments |
| `session_analysis.tools_summary` | Tool usage counts |
| `session_analysis.apps_summary` | App usage counts |

## Scanned Locations

- **OpenClaw folder**: `~/.openclaw`
- **Session logs**: `~/.openclaw/agents/main/sessions/*.jsonl`

## App Detection

The scanner detects apps from commands using these patterns:

- `open -a AppName` or `open -a "App Name"`
- `osascript -e 'tell application "AppName"'`
- `killall AppName`
- `/Applications/AppName.app`
- CLI tools mapped to apps (e.g., `code` -> VS Code, `slack` -> Slack)

## License

MIT
