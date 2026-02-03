"""Linux implementation."""

import os
import re
import subprocess
from typing import List, Optional

from .base import PlatformCompat, ProcessInfo, ToolPaths, UserInfo
from .common import (
    run_cmd, get_user_id, get_group_id,
    get_groups, get_uname, find_processes as _find_processes,
    get_base_tool_paths,
)


class LinuxCompat(PlatformCompat):
    """Linux-specific implementation."""

    def get_user_info(self, username: Optional[str] = None) -> UserInfo:
        if username is None:
            username = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"

        # Linux: getent passwd for full name (GECOS field)
        full_name: Optional[str] = None
        output = run_cmd(["getent", "passwd", username])
        if output:
            parts = output.split(":")
            if len(parts) >= 5 and parts[4]:
                full_name = parts[4].split(",")[0]

        return {
            "username": username,
            "home_directory": os.path.expanduser("~"),
            "user_id": get_user_id(),
            "group_id": get_group_id(),
            "full_name": full_name,
            "shell": os.environ.get("SHELL", "unknown"),
            "groups": get_groups(),
            "system_info": get_uname(),
            "computer_name": run_cmd(["hostname"]),
            "local_hostname": None,
        }

    def find_processes(self, process_names: List[str]) -> List[ProcessInfo]:
        return _find_processes(process_names)

    def get_tool_paths(self, tool_name: str) -> ToolPaths:
        paths = get_base_tool_paths(tool_name)
        # Linux-specific: add /var/log
        paths["logs"].append(f"/var/log/{tool_name}/*.log")
        return paths

    def read_system_log(self, subsystem: str, time_range: str,
                        max_lines: int = 500) -> List[str]:
        """Read Linux systemd journal. subsystem = systemd unit name."""
        # Convert time_range (e.g., "24h", "1h", "30m") to journalctl --since format
        since = self._convert_time_range(time_range)
        try:
            cmd = [
                "journalctl", "-u", subsystem,
                "-n", str(max_lines),
                "--no-pager", "-q"
            ]
            if since:
                cmd.extend(["--since", since])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                return [l for l in result.stdout.strip().split('\n') if l.strip()]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return []

    @staticmethod
    def _convert_time_range(time_range: str) -> Optional[str]:
        """Convert '24h', '1h', '30m', '1d' to journalctl --since format."""
        match = re.match(r'^(\d+)([hmd])$', time_range.lower())
        if not match:
            return None
        value, unit = match.groups()
        unit_map = {'h': 'hours', 'm': 'minutes', 'd': 'days'}
        return f"{value} {unit_map.get(unit, 'hours')} ago"
