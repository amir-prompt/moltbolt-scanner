"""macOS (Darwin) implementation."""

import os
import subprocess
from typing import List, Optional

from .base import PlatformCompat, ProcessInfo, ToolPaths, UserInfo
from .common import (
    run_cmd, get_user_id, get_group_id,
    get_groups, get_system_info, find_processes as _find_processes,
    get_base_tool_paths,
)


class DarwinCompat(PlatformCompat):
    """macOS-specific implementation."""

    def get_user_info(self, username: Optional[str] = None) -> UserInfo:
        if username is None:
            username = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"

        # macOS: id -F for full name
        full_name = run_cmd(["id", "-F"])

        # macOS: fallback to dscl for real name
        if not full_name:
            output = run_cmd(["dscl", ".", "-read", f"/Users/{username}", "RealName"])
            if output:
                lines = output.split("\n")
                if len(lines) > 1:
                    full_name = lines[1].strip()
                elif lines:
                    full_name = lines[0].replace("RealName:", "").strip()

        return {
            "username": username,
            "home_directory": os.path.expanduser("~"),
            "user_id": get_user_id(),
            "group_id": get_group_id(),
            "full_name": full_name,
            "shell": os.environ.get("SHELL", "unknown"),
            "groups": get_groups(),
            "system_info": get_system_info(),
            "computer_name": run_cmd(["scutil", "--get", "ComputerName"]),
            "local_hostname": run_cmd(["scutil", "--get", "LocalHostName"]),
        }

    def find_processes(self, process_names: List[str]) -> List[ProcessInfo]:
        return _find_processes(process_names)

    def get_tool_paths(self, tool_name: str) -> ToolPaths:
        return get_base_tool_paths(tool_name)

    def read_system_log(self, subsystem: str, time_range: str,
                        max_lines: int = 500) -> List[str]:
        """Read macOS unified log."""
        try:
            result = subprocess.run([
                "log", "show",
                "--predicate", f'subsystem == "{subsystem}"',
                "--last", time_range, "--info"
            ], capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                lines = [l for l in result.stdout.strip().split('\n')
                         if l.strip() and not l.startswith('Filtering')]
                return lines[-max_lines:]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return []
