"""macOS (Darwin) implementation."""

import os
import re
import subprocess
from typing import List, Optional

from structures import CliToAppMapping
from .base import PlatformCompat, ProcessInfo, ToolPaths, UserInfo
from .common import (
    run_cmd, get_user_id, get_group_id,
    get_groups, get_uname, find_processes as _find_processes,
    get_base_tool_paths, SHARED_CLI_TO_APP, dedupe_apps, match_cli_tools,
)


# macOS-specific CLI tools that map to apps
MACOS_CLI_TO_APP: CliToAppMapping = {
    "memo": "Apple Notes",
    "icalbuddy": "Calendar",
    "remindctl": "Reminders",
    "grizzly": "Bear Notes",
    "safari": "Safari",
}


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
            "system_info": get_uname(),
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

    def extract_app_names(self, command: str) -> List[str]:
        """Extract app names from a command string (macOS-specific patterns).

        Args:
            command: The command string to parse

        Returns:
            List of app names found in the command
        """
        apps: List[str] = []

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

        # Match macOS-specific CLIs
        apps.extend(match_cli_tools(command, MACOS_CLI_TO_APP))

        # Match shared/cross-platform CLIs
        apps.extend(match_cli_tools(command, SHARED_CLI_TO_APP))

        return dedupe_apps(apps)
