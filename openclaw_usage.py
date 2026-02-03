#!/usr/bin/env python3
"""
OpenClaw Usage Scanner
Scans .openclaw folder, active skills, and session logs for tools/apps usage.
Outputs JSON with all collected data.
"""

import json
import os
import platform
import re
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

API_ENDPOINT = "https://openclawmang.vercel.app/api/reports"


def find_openclaw_folder() -> Optional[Path]:
    """Find the .openclaw folder in the user's home directory.

    Returns:
        Path to .openclaw folder or None if not found
    """
    openclaw_path = Path.home() / ".openclaw"

    if openclaw_path.exists() and openclaw_path.is_dir():
        return openclaw_path

    return None


def get_user_details() -> Dict[str, Any]:
    """Get local machine user details.

    Returns:
        Dict with user and machine information
    """
    return {
        "username": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
        "home_dir": str(Path.home()),
        "current_dir": os.getcwd(),
        "hostname": platform.node(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "shell": os.getenv("SHELL", "unknown"),
        "lang": os.getenv("LANG", "unknown"),
    }


def get_active_skills(cli_command: str = "openclaw") -> Dict[str, Any]:
    """Run openclaw skills list and filter only active skills.

    Args:
        cli_command: The CLI command to use (openclaw, moltbot, or clawdbot)

    Returns:
        Dict with active skills list and counts
    """
    cmd = [cli_command, "skills", "list", "--json"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return {
                "error": f"Command failed: {result.stderr}",
                "active_skills": [],
                "count": 0
            }

        data = json.loads(result.stdout)
        all_skills = data.get("skills", [])

        # Filter for active/eligible skills (not disabled)
        active_skills = [
            skill for skill in all_skills
            if skill.get("eligible", False) and not skill.get("disabled", False)
        ]

        return {
            "active_skills": active_skills,
            "count": len(active_skills),
            "total": len(all_skills)
        }

    except subprocess.TimeoutExpired:
        return {"error": "Command timed out", "active_skills": [], "count": 0}
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}", "active_skills": [], "count": 0}
    except FileNotFoundError:
        return {"error": f"CLI not found: {cli_command}", "active_skills": [], "count": 0}
    except Exception as e:
        return {"error": str(e), "active_skills": [], "count": 0}


def get_cron_jobs(cli_command: str = "openclaw") -> Dict[str, Any]:
    """Run openclaw cron list to get scheduled cron jobs.

    Args:
        cli_command: The CLI command to use (openclaw, moltbot, or clawdbot)

    Returns:
        Dict with cron jobs list and count
    """
    cmd = [cli_command, "cron", "list"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return {
                "error": f"Command failed: {result.stderr}",
                "cron_jobs": [],
                "count": 0
            }

        # Try to parse as JSON first
        try:
            data = json.loads(result.stdout)
            cron_jobs = data if isinstance(data, list) else data.get("cron_jobs", data.get("jobs", []))
            return {
                "cron_jobs": cron_jobs,
                "count": len(cron_jobs) if isinstance(cron_jobs, list) else 0
            }
        except json.JSONDecodeError:
            # If not JSON, parse the text output
            lines = result.stdout.strip().split("\n")
            cron_jobs = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith(("#", "No cron", "CRON")):
                    cron_jobs.append({"raw": line})

            return {
                "cron_jobs": cron_jobs,
                "count": len(cron_jobs),
                "raw_output": result.stdout.strip()
            }

    except subprocess.TimeoutExpired:
        return {"error": "Command timed out", "cron_jobs": [], "count": 0}
    except FileNotFoundError:
        return {"error": f"CLI not found: {cli_command}", "cron_jobs": [], "count": 0}
    except Exception as e:
        return {"error": str(e), "cron_jobs": [], "count": 0}


def get_security_audit(cli_command: str = "openclaw") -> Dict[str, Any]:
    """Run openclaw security audit to check for security issues.

    Args:
        cli_command: The CLI command to use (openclaw, moltbot, or clawdbot)

    Returns:
        Dict with security audit results
    """
    cmd = [cli_command, "security", "audit"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        output = result.stdout.strip()
        stderr = result.stderr.strip()

        # Try to parse as JSON first
        try:
            data = json.loads(output)
            return {
                "audit_results": data,
                "issues_found": len(data) if isinstance(data, list) else data.get("issues", []),
                "passed": result.returncode == 0
            }
        except json.JSONDecodeError:
            # Parse text output
            return {
                "raw_output": output,
                "stderr": stderr if stderr else None,
                "passed": result.returncode == 0
            }

    except subprocess.TimeoutExpired:
        return {"error": "Command timed out"}
    except FileNotFoundError:
        return {"error": f"CLI not found: {cli_command}"}
    except Exception as e:
        return {"error": str(e)}


def get_plugins_list(cli_command: str = "openclaw") -> Dict[str, Any]:
    """Run openclaw plugins list to get active plugins only.

    Args:
        cli_command: The CLI command to use (openclaw, moltbot, or clawdbot)

    Returns:
        Dict with active plugins list and count
    """
    cmd = [cli_command, "plugins", "list", "--json"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return {
                "error": f"Command failed: {result.stderr}",
                "active_plugins": [],
                "count": 0
            }

        try:
            data = json.loads(result.stdout)
            all_plugins = data if isinstance(data, list) else data.get("plugins", [])

            # Filter for active plugins only - exclude disabled ones
            active_plugins = []
            for plugin in all_plugins:
                if not isinstance(plugin, dict):
                    continue
                # Skip if explicitly disabled
                if plugin.get("enabled") == False:
                    continue
                if plugin.get("status") == "disabled":
                    continue
                if plugin.get("disabled") == True:
                    continue
                if plugin.get("active") == False:
                    continue
                active_plugins.append(plugin)

            return {
                "active_plugins": active_plugins,
                "count": len(active_plugins),
                "total": len(all_plugins)
            }
        except json.JSONDecodeError:
            lines = result.stdout.strip().split("\n")
            plugins = [{"raw": line.strip()} for line in lines if line.strip()]
            return {
                "active_plugins": plugins,
                "count": len(plugins),
                "raw_output": result.stdout.strip()
            }

    except subprocess.TimeoutExpired:
        return {"error": "Command timed out", "active_plugins": [], "count": 0}
    except FileNotFoundError:
        return {"error": f"CLI not found: {cli_command}", "active_plugins": [], "count": 0}
    except Exception as e:
        return {"error": str(e), "active_plugins": [], "count": 0}


def get_channels_list(cli_command: str = "openclaw") -> Dict[str, Any]:
    """Run openclaw channels list to get configured channels/integrations.

    Args:
        cli_command: The CLI command to use (openclaw, moltbot, or clawdbot)

    Returns:
        Dict with channels list and count
    """
    cmd = [cli_command, "channels", "list"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return {
                "error": f"Command failed: {result.stderr}",
                "channels": [],
                "count": 0
            }

        try:
            data = json.loads(result.stdout)
            channels = data if isinstance(data, list) else data.get("channels", [])
            return {
                "channels": channels,
                "count": len(channels) if isinstance(channels, list) else 0
            }
        except json.JSONDecodeError:
            lines = result.stdout.strip().split("\n")
            channels = [{"raw": line.strip()} for line in lines if line.strip()]
            return {
                "channels": channels,
                "count": len(channels),
                "raw_output": result.stdout.strip()
            }

    except subprocess.TimeoutExpired:
        return {"error": "Command timed out", "channels": [], "count": 0}
    except FileNotFoundError:
        return {"error": f"CLI not found: {cli_command}", "channels": [], "count": 0}
    except Exception as e:
        return {"error": str(e), "channels": [], "count": 0}


def get_nodes_list(cli_command: str = "openclaw") -> Dict[str, Any]:
    """Run openclaw nodes list to get connected/paired nodes.

    Args:
        cli_command: The CLI command to use (openclaw, moltbot, or clawdbot)

    Returns:
        Dict with nodes list and count
    """
    cmd = [cli_command, "nodes", "list"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return {
                "error": f"Command failed: {result.stderr}",
                "nodes": [],
                "count": 0
            }

        try:
            data = json.loads(result.stdout)
            nodes = data if isinstance(data, list) else data.get("nodes", [])
            return {
                "nodes": nodes,
                "count": len(nodes) if isinstance(nodes, list) else 0
            }
        except json.JSONDecodeError:
            lines = result.stdout.strip().split("\n")
            nodes = [{"raw": line.strip()} for line in lines if line.strip()]
            return {
                "nodes": nodes,
                "count": len(nodes),
                "raw_output": result.stdout.strip()
            }

    except subprocess.TimeoutExpired:
        return {"error": "Command timed out", "nodes": [], "count": 0}
    except FileNotFoundError:
        return {"error": f"CLI not found: {cli_command}", "nodes": [], "count": 0}
    except Exception as e:
        return {"error": str(e), "nodes": [], "count": 0}


def get_models_status(cli_command: str = "openclaw") -> Dict[str, Any]:
    """Run openclaw models status to get authentication and model status.

    Args:
        cli_command: The CLI command to use (openclaw, moltbot, or clawdbot)

    Returns:
        Dict with models status including auth info
    """
    cmd = [cli_command, "models", "status"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        output = result.stdout.strip()

        try:
            data = json.loads(output)
            return {
                "models_status": data,
                "has_auth": True
            }
        except json.JSONDecodeError:
            return {
                "raw_output": output,
                "passed": result.returncode == 0
            }

    except subprocess.TimeoutExpired:
        return {"error": "Command timed out"}
    except FileNotFoundError:
        return {"error": f"CLI not found: {cli_command}"}
    except Exception as e:
        return {"error": str(e)}


def extract_app_names(command: str) -> List[str]:
    """Extract app names from a command string.

    Args:
        command: The command string to parse

    Returns:
        List of app names found in the command
    """
    apps = []

    # Pattern: osascript -e 'tell application "AppName"'
    osascript_pattern = r'tell application ["\']([^"\']+)["\']'
    apps.extend(re.findall(osascript_pattern, command, re.IGNORECASE))

    # Pattern: open -a AppName or open -a "App Name"
    open_pattern = r'open\s+-a\s+["\']?([^"\';\s]+(?:\s+[^"\';\s]+)*)["\']?'
    apps.extend(re.findall(open_pattern, command, re.IGNORECASE))

    # Pattern: killall "AppName" or killall AppName
    killall_pattern = r'killall\s+["\']?([^"\';\s]+)["\']?'
    apps.extend(re.findall(killall_pattern, command, re.IGNORECASE))

    # Pattern: /Applications/AppName.app
    app_path_pattern = r'/Applications/([^/]+)\.app'
    apps.extend(re.findall(app_path_pattern, command))

    # # CLI tools that map to apps
    # cli_to_app = {
    #     "memo": "Apple Notes",
    #     "icalbuddy": "Calendar",
    #     "remindctl": "Reminders",
    #     "grizzly": "Bear Notes",
    #     "chrome": "Google Chrome",
    #     "brave": "Brave Browser",
    #     "firefox": "Firefox",
    #     "safari": "Safari",
    #     "edge": "Microsoft Edge",
    #     "code": "VS Code",
    #     "cursor": "Cursor",
    #     "slack": "Slack",
    #     "discord": "Discord",
    #     "spotify": "Spotify",
    #     "telegram": "Telegram",
    #     "whatsapp": "WhatsApp",
    #     "obsidian": "Obsidian",
    #     "notion": "Notion",
    #     "figma": "Figma",
    #     "zoom": "Zoom",
    #     "teams": "Microsoft Teams",
    # }

    # command_lower = command.lower()
    # for cli, app in cli_to_app.items():
    #     if re.search(rf'\b{cli}\b', command_lower):
    #         apps.append(app)

    # Remove duplicates while preserving order
    seen = set()
    unique_apps = []
    for app in apps:
        app_lower = app.lower()
        if app_lower not in seen:
            seen.add(app_lower)
            unique_apps.append(app)

    return unique_apps


def scan_session_logs(openclaw_path: Path) -> Dict[str, Any]:
    """Scan session logs and extract tools and apps used.

    Args:
        openclaw_path: Path to the .openclaw folder

    Returns:
        Dict with tool calls, usage summary, and apps used
    """
    sessions_dir = openclaw_path / "agents" / "main" / "sessions"

    if not sessions_dir.exists():
        return {
            "error": f"Sessions directory not found: {sessions_dir}",
            "tool_calls": [],
            "tools_summary": {},
            "apps_summary": {}
        }

    tool_calls = []

    # Find all session .jsonl files
    session_files = [f for f in sessions_dir.glob("*.jsonl") if f.name != "sessions.json"]

    for session_file in session_files:
        try:
            with open(session_file, "r") as f:
                for line in f:
                    # Quick check before parsing JSON
                    if "toolCall" not in line:
                        continue
                    try:
                        data = json.loads(line.strip())
                        if data.get("type") != "message":
                            continue
                        message = data.get("message", {})
                        content = message.get("content", [])

                        for item in content:
                            if isinstance(item, dict) and item.get("type") == "toolCall":
                                arguments = item.get("arguments", {})
                                command = arguments.get("command", "")
                                apps = extract_app_names(command) if command else []

                                tool_calls.append({
                                    "tool_name": item.get("name"),
                                    "tool_id": item.get("id"),
                                    "timestamp": data.get("timestamp"),
                                    "session": session_file.name,
                                    "arguments": arguments,
                                    "apps_detected": apps
                                })
                    except json.JSONDecodeError:
                        continue
        except Exception:
            continue

    # Sort by timestamp (most recent first)
    tool_calls.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    # Build tools usage summary
    tools_summary = {}
    for tc in tool_calls:
        name = tc.get("tool_name", "unknown")
        tools_summary[name] = tools_summary.get(name, 0) + 1

    # Sort by count (descending)
    tools_summary = dict(sorted(tools_summary.items(), key=lambda x: x[1], reverse=True))

    # Build apps usage summary
    apps_summary = {}
    for tc in tool_calls:
        for app in tc.get("apps_detected", []):
            apps_summary[app] = apps_summary.get(app, 0) + 1

    apps_summary = dict(sorted(apps_summary.items(), key=lambda x: x[1], reverse=True))

    return {
        "tool_calls": tool_calls,
        "tools_summary": tools_summary,
        "apps_summary": apps_summary,
        "total_tool_calls": len(tool_calls),
        "unique_tools": len(tools_summary),
        "unique_apps": len(apps_summary),
        "sessions_scanned": len([f for f in session_files if f.name != "sessions.json"])
    }


def send_report(report_data: Dict[str, Any], api_key: str) -> Dict[str, Any]:
    """Send scan report to the API endpoint.

    Args:
        report_data: The scan report to send
        api_key: API key for authorization

    Returns:
        Dict with success status and response or error message
    """
    # Remove api_key from the payload (it's used in header, not body)
    payload = {k: v for k, v in report_data.items() if k != "api_key"}

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            API_ENDPOINT,
            data=data,
            headers=headers,
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=30) as response:
            response_body = response.read().decode("utf-8")
            return {
                "success": True,
                "status_code": response.status,
                "response": json.loads(response_body) if response_body else {}
            }

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else ""
        return {
            "success": False,
            "status_code": e.code,
            "error": f"HTTP {e.code}: {e.reason}",
            "response": error_body
        }
    except urllib.error.URLError as e:
        return {
            "success": False,
            "error": f"Connection error: {e.reason}"
        }
    except json.JSONDecodeError:
        return {
            "success": True,
            "status_code": response.status,
            "response": response_body
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Scan OpenClaw usage: active skills, tools, and apps. Outputs JSON."
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="API key for sending report to the server"
    )
    parser.add_argument(
        "--cli",
        type=str,
        default="openclaw",
        help="CLI command to use (openclaw, moltbot, clawdbot)"
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Compact JSON output (no indentation)"
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Include full response with all details (default: only user and summary)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Limit number of recent tool calls to include in full output (default: 50)"
    )

    args = parser.parse_args()

    # Step 1: Find .openclaw folder
    openclaw_path = find_openclaw_folder()

    if openclaw_path is None:
        result = {
            "error": ".openclaw folder not found",
            "expected_path": str(Path.home() / ".openclaw"),
            "openclaw_path": None,
            "active_skills": None,
            "session_analysis": None
        }
        print(json.dumps(result, indent=None if args.compact else 2))
        sys.exit(1)

    # Step 2: Get active skills
    skills_result = get_active_skills(args.cli)

    # Step 3: Scan session logs
    logs_result = scan_session_logs(openclaw_path)

    # Step 4: Get user details
    user_details = get_user_details()

    # Step 5: Get cron jobs
    cron_result = get_cron_jobs(args.cli)

    # Step 6: Get security audit (CISO critical)
    security_result = get_security_audit(args.cli)

    # Step 7: Get plugins list (attack surface)
    plugins_result = get_plugins_list(args.cli)

    # Step 8: Get channels list (external integrations)
    channels_result = get_channels_list(args.cli)

    # Step 9: Get nodes list (remote connections)
    nodes_result = get_nodes_list(args.cli)

    # Step 10: Get models status (auth posture)
    models_result = get_models_status(args.cli)

    # Limit tool calls in output
    logs_result["tool_calls"] = logs_result["tool_calls"][:args.limit]

    # Build summary
    active_skills_list = skills_result.get("active_skills", [])
    app_names = list(logs_result.get("apps_summary", {}).keys())
    tool_names = list(logs_result.get("tools_summary", {}).keys())

    summary = {
        "active_skills": active_skills_list,
        "active_skills_count": len(active_skills_list),
        "apps_detected": app_names,
        "apps_detected_count": len(app_names),
        "tools_used": tool_names,
        "tools_used_count": len(tool_names),
        "total_tool_calls": logs_result.get("total_tool_calls", 0),
        "sessions_scanned": logs_result.get("sessions_scanned", 0),
        "cron_jobs": cron_result.get("cron_jobs", []),
        "cron_jobs_count": cron_result.get("count", 0),
        # CISO-relevant data
        "security_audit": security_result,
        "active_plugins": plugins_result.get("active_plugins", []),
        "active_plugins_count": plugins_result.get("count", 0),
        "channels": channels_result.get("channels", []),
        "channels_count": channels_result.get("count", 0),
        "nodes": nodes_result.get("nodes", []),
        "nodes_count": nodes_result.get("count", 0),
        "models_status": models_result
    }

    # Build output based on --full flag
    if args.full:
        result = {
            "scan_timestamp": datetime.now().isoformat(),
            "user": user_details,
            "openclaw_path": str(openclaw_path),
            "summary": summary,
            "active_skills": skills_result,
            "session_analysis": logs_result,
            "cron_jobs": cron_result,
            # CISO-relevant detailed data
            "security_audit": security_result,
            "active_plugins": plugins_result,
            "channels": channels_result,
            "nodes": nodes_result,
            "models_status": models_result
        }
    else:
        result = {
            "scan_timestamp": datetime.now().isoformat(),
            "user": user_details,
            "summary": summary
        }

    # Send report to API if api-key is provided
    if args.api_key:
        api_result = send_report(result, args.api_key)
        result["api_report"] = api_result

    # Output JSON
    if args.compact:
        print(json.dumps(result))
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
