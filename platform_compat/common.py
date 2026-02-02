"""Common utilities shared across platform implementations."""

import os
import subprocess
from typing import List, Optional

from structures import ProcessInfo, ToolPaths


def run_cmd(cmd: List[str], timeout: int = 5) -> Optional[str]:
    """Run command, return stripped stdout or None on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def get_user_id() -> Optional[str]:
    """Get current user ID (works on macOS and Linux)."""
    return run_cmd(["id", "-u"])


def get_group_id() -> Optional[str]:
    """Get current group ID (works on macOS and Linux)."""
    return run_cmd(["id", "-g"])


def get_groups() -> List[str]:
    """Get user's groups (works on macOS and Linux)."""
    output = run_cmd(["groups"])
    return output.split() if output else []


def get_system_info() -> Optional[str]:
    """Get system info via uname -a (works on macOS and Linux)."""
    return run_cmd(["uname", "-a"])


def find_processes(process_names: List[str]) -> List[ProcessInfo]:
    """Find processes matching any of the given names.
    
    Works identically on macOS and Linux (ps aux format).
    """
    processes: List[ProcessInfo] = []
    exclude_patterns = ["installation_tracker", "grep", "ps aux"]

    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                line_lower = line.lower()

                if any(excl in line_lower for excl in exclude_patterns):
                    continue

                for proc_name in process_names:
                    if proc_name.lower() in line_lower:
                        parts = line.split()
                        if len(parts) >= 11:
                            processes.append({
                                "user": parts[0],
                                "pid": parts[1],
                                "cpu": parts[2],
                                "mem": parts[3],
                                "command": " ".join(parts[10:]),
                                "process_name": proc_name,
                            })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return processes


def get_base_tool_paths(tool_name: str) -> ToolPaths:
    """Get tool paths common to all platforms."""
    home = os.path.expanduser("~")
    return {
        "config": [
            os.path.join(home, f".{tool_name}", f"{tool_name}.json"),
            os.path.join(home, f".{tool_name}", "config.json"),
            os.path.join(home, ".config", tool_name, "config.json"),
        ],
        "logs": [
            os.path.join(home, f".{tool_name}", "logs", "*.log"),
            os.path.join(home, f".{tool_name}", "*.log"),
            f"/tmp/{tool_name}/*.log",
            f"/tmp/{tool_name}*.log",
            f"/tmp/{tool_name}-gateway.log",
        ]
    }
