#!/usr/bin/env python3
"""
Installation Tracker for clawbot/moltbot/openclaw
Detects installations, active status, and connection resources.
"""

import json
import os
import re
import socket
import subprocess
import glob
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any

# Configuration - Add your API key here
API_KEY = "YOUR_API_KEY_HERE"

# Known installation paths and configurations
TOOL_CONFIGS = {
    "openclaw": {
        "config_paths": [
            "~/.openclaw/openclaw.json",
            "~/.config/openclaw/config.json",
        ],
        "log_paths": [
            "~/.openclaw/logs/*.log",
            "~/.openclaw/workspace/logs/*.log",
            "/var/log/openclaw/*.log",
        ],
        "workspace_path": "~/.openclaw/workspace",
        "process_names": ["openclaw", "openclaw-gateway", "openclaw-daemon"],
        "default_port": 18789,
        "binary_names": ["openclaw"],
    },
    "moltbot": {
        "config_paths": [
            "~/.moltbot/config.json",
            "~/.config/moltbot/settings.json",
            "~/.moltbot/moltbot.json",
        ],
        "log_paths": [
            "~/.moltbot/logs/*.log",
            "~/.moltbot/*.log",
            "/var/log/moltbot/*.log",
        ],
        "workspace_path": "~/.moltbot/workspace",
        "process_names": ["moltbot", "moltbot-agent", "moltbot-daemon"],
        "default_port": 18800,
        "binary_names": ["moltbot"],
    },
    "clawbot": {
        "config_paths": [
            "~/.clawbot/config.json",
            "~/.config/clawbot/settings.json",
            "~/.clawbot/clawbot.json",
        ],
        "log_paths": [
            "~/.clawbot/logs/*.log",
            "~/.clawbot/*.log",
            "/var/log/clawbot/*.log",
        ],
        "workspace_path": "~/.clawbot/workspace",
        "process_names": ["clawbot", "clawbot-agent", "clawbot-daemon"],
        "default_port": 18801,
        "binary_names": ["clawbot"],
    },
}


class InstallationTracker:
    def __init__(self, api_key: str = API_KEY):
        self.api_key = api_key
        self.username = self._get_current_username()
        self.hostname = socket.gethostname()
        self.results: Dict[str, Any] = {}

    def _get_current_username(self) -> str:
        """Get the current system username."""
        return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"

    def _get_machine_user_info(self) -> Dict[str, Any]:
        """Get detailed user information from local machine settings."""
        user_info = {
            "username": self.username,
            "home_directory": os.path.expanduser("~"),
            "user_id": None,
            "group_id": None,
            "full_name": None,
            "shell": os.environ.get("SHELL", "unknown"),
            "groups": [],
        }

        # Get user ID
        try:
            result = subprocess.run(["id", "-u"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                user_info["user_id"] = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Get group ID
        try:
            result = subprocess.run(["id", "-g"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                user_info["group_id"] = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Get full name (macOS specific with id -F)
        try:
            result = subprocess.run(["id", "-F"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                user_info["full_name"] = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Fallback: Try dscl for macOS to get real name
        if not user_info["full_name"]:
            try:
                result = subprocess.run(
                    ["dscl", ".", "-read", f"/Users/{self.username}", "RealName"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split("\n")
                    if len(lines) > 1:
                        user_info["full_name"] = lines[1].strip()
                    elif lines:
                        user_info["full_name"] = lines[0].replace("RealName:", "").strip()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # Fallback for Linux: Try getent
        if not user_info["full_name"]:
            try:
                result = subprocess.run(
                    ["getent", "passwd", self.username],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    parts = result.stdout.strip().split(":")
                    if len(parts) >= 5:
                        user_info["full_name"] = parts[4].split(",")[0]
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # Get user groups
        try:
            result = subprocess.run(["groups"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                user_info["groups"] = result.stdout.strip().split()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Get additional system info
        try:
            result = subprocess.run(["uname", "-a"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                user_info["system_info"] = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Get computer name (macOS)
        try:
            result = subprocess.run(
                ["scutil", "--get", "ComputerName"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                user_info["computer_name"] = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Get local hostname (macOS)
        try:
            result = subprocess.run(
                ["scutil", "--get", "LocalHostName"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                user_info["local_hostname"] = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return user_info

    def _expand_path(self, path: str) -> str:
        """Expand ~ and environment variables in path."""
        return os.path.expanduser(os.path.expandvars(path))

    def _check_binary_installed(self, binary_name: str) -> Optional[str]:
        """Check if a binary is installed and return its path."""
        try:
            result = subprocess.run(
                ["which", binary_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    def _check_npm_package(self, package_name: str) -> Optional[Dict[str, str]]:
        """Check if an npm package is installed globally."""
        try:
            result = subprocess.run(
                ["npm", "list", "-g", package_name, "--json"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                if "dependencies" in data and package_name in data["dependencies"]:
                    return {
                        "version": data["dependencies"][package_name].get("version", "unknown"),
                        "path": data.get("path", "unknown")
                    }
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        return None

    def _check_process_running(self, process_names: List[str]) -> List[Dict[str, Any]]:
        """Check if any of the specified processes are running."""
        running_processes = []
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    for proc_name in process_names:
                        if proc_name in line.lower() and "grep" not in line.lower():
                            parts = line.split()
                            if len(parts) >= 11:
                                running_processes.append({
                                    "user": parts[0],
                                    "pid": parts[1],
                                    "cpu": parts[2],
                                    "mem": parts[3],
                                    "command": " ".join(parts[10:]),
                                    "process_name": proc_name
                                })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return running_processes

    def _check_port_listening(self, port: int) -> bool:
        """Check if a port is listening."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(("127.0.0.1", port))
                return result == 0
        except socket.error:
            return False

    def _read_config_file(self, config_path: str) -> Optional[Dict[str, Any]]:
        """Read and parse a JSON configuration file."""
        expanded_path = self._expand_path(config_path)
        if os.path.exists(expanded_path):
            try:
                with open(expanded_path, "r") as f:
                    content = f.read()
                    # Handle JSON with comments or trailing commas
                    content = re.sub(r'//.*?\n', '\n', content)
                    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
                    content = re.sub(r',(\s*[}\]])', r'\1', content)
                    return json.loads(content)
            except (json.JSONDecodeError, IOError) as e:
                return {"_error": str(e), "_path": expanded_path}
        return None

    def _find_log_files(self, log_patterns: List[str]) -> List[str]:
        """Find all log files matching the patterns."""
        log_files = []
        for pattern in log_patterns:
            expanded_pattern = self._expand_path(pattern)
            log_files.extend(glob.glob(expanded_pattern))
        return sorted(log_files, key=os.path.getmtime, reverse=True) if log_files else []

    def _parse_log_connections(self, log_file: str, max_lines: int = 1000) -> List[Dict[str, Any]]:
        """Parse log file for connection information."""
        connections = []
        connection_patterns = [
            r'connect(?:ed|ing)?\s+(?:to\s+)?["\']?([a-zA-Z0-9\-._]+(?::\d+)?)["\']?',
            r'(?:api|server|host|endpoint|url)["\s:=]+["\']?(https?://[^\s"\']+)["\']?',
            r'(?:websocket|ws|wss)://([^\s"\']+)',
            r'(?:authenticated|login|auth)\s+(?:to|with|as)\s+["\']?([^\s"\']+)["\']?',
            r'model["\s:=]+["\']?([^\s"\']+)["\']?',
        ]

        try:
            with open(log_file, "r", errors="ignore") as f:
                lines = f.readlines()[-max_lines:]
                for line in lines:
                    for pattern in connection_patterns:
                        matches = re.findall(pattern, line, re.IGNORECASE)
                        for match in matches:
                            connections.append({
                                "resource": match,
                                "log_file": log_file,
                                "pattern": pattern[:30] + "...",
                                "line_sample": line.strip()[:100]
                            })
        except IOError:
            pass

        # Deduplicate by resource
        seen = set()
        unique_connections = []
        for conn in connections:
            if conn["resource"] not in seen:
                seen.add(conn["resource"])
                unique_connections.append(conn)

        return unique_connections

    def _extract_api_keys_from_config(self, config: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract potential API keys from configuration."""
        api_keys = []
        key_patterns = ["api_key", "apikey", "api-key", "token", "secret", "auth_token"]

        def search_dict(d: Dict, path: str = ""):
            for k, v in d.items():
                current_path = f"{path}.{k}" if path else k
                if isinstance(v, dict):
                    search_dict(v, current_path)
                elif isinstance(v, str):
                    k_lower = k.lower()
                    if any(pattern in k_lower for pattern in key_patterns):
                        # Mask the key for security
                        masked_value = v[:4] + "****" + v[-4:] if len(v) > 8 else "****"
                        api_keys.append({
                            "path": current_path,
                            "value_masked": masked_value,
                            "length": len(v)
                        })

        if isinstance(config, dict):
            search_dict(config)
        return api_keys

    def scan_tool(self, tool_name: str) -> Dict[str, Any]:
        """Scan for a specific tool installation and status."""
        config = TOOL_CONFIGS.get(tool_name, {})
        result = {
            "tool_name": tool_name,
            "installed": False,
            "installation_details": {},
            "active": False,
            "processes": [],
            "port_listening": False,
            "config_files": [],
            "log_files": [],
            "connections": [],
            "api_keys_found": [],
        }

        # Check binary installation
        for binary in config.get("binary_names", []):
            binary_path = self._check_binary_installed(binary)
            if binary_path:
                result["installed"] = True
                result["installation_details"]["binary_path"] = binary_path

        # Check npm installation
        npm_info = self._check_npm_package(tool_name)
        if npm_info:
            result["installed"] = True
            result["installation_details"]["npm"] = npm_info

        # Check workspace directory
        workspace_path = self._expand_path(config.get("workspace_path", ""))
        if os.path.exists(workspace_path):
            result["installed"] = True
            result["installation_details"]["workspace_exists"] = True
            result["installation_details"]["workspace_path"] = workspace_path

        # Check running processes
        processes = self._check_process_running(config.get("process_names", []))
        if processes:
            result["active"] = True
            result["processes"] = processes

        # Check default port
        default_port = config.get("default_port")
        if default_port:
            port_listening = self._check_port_listening(default_port)
            result["port_listening"] = port_listening
            result["default_port"] = default_port
            if port_listening:
                result["active"] = True

        # Read configuration files
        for config_path in config.get("config_paths", []):
            config_data = self._read_config_file(config_path)
            if config_data:
                result["config_files"].append({
                    "path": self._expand_path(config_path),
                    "data": config_data
                })
                # Extract API keys from config
                api_keys = self._extract_api_keys_from_config(config_data)
                result["api_keys_found"].extend(api_keys)

        # Find and parse log files
        log_files = self._find_log_files(config.get("log_paths", []))
        result["log_files"] = log_files[:10]  # Limit to 10 most recent

        # Parse connections from logs
        for log_file in log_files[:5]:  # Parse top 5 most recent logs
            connections = self._parse_log_connections(log_file)
            result["connections"].extend(connections)

        return result

    def scan_all(self) -> Dict[str, Any]:
        """Scan for all known tools."""
        user_info = self._get_machine_user_info()
        self.results = {
            "scan_timestamp": datetime.now().isoformat(),
            "machine_info": {
                "hostname": self.hostname,
                "api_key_provided": self.api_key[:4] + "****" if len(self.api_key) > 4 else "****",
                "user": user_info,
            },
            "tools": {}
        }

        for tool_name in TOOL_CONFIGS:
            self.results["tools"][tool_name] = self.scan_tool(tool_name)

        return self.results

    def generate_report(self) -> str:
        """Generate a human-readable report."""
        if not self.results:
            self.scan_all()

        user_info = self.results['machine_info'].get('user', {})
        lines = [
            "=" * 60,
            "INSTALLATION TRACKER REPORT",
            f"Scan Time: {self.results['scan_timestamp']}",
            "=" * 60,
            "",
            "MACHINE INFORMATION:",
            f"  Hostname: {self.results['machine_info']['hostname']}",
            f"  Computer Name: {user_info.get('computer_name', 'N/A')}",
            f"  Local Hostname: {user_info.get('local_hostname', 'N/A')}",
            f"  API Key (masked): {self.results['machine_info']['api_key_provided']}",
            "",
            "USER INFORMATION:",
            f"  Username: {user_info.get('username', 'N/A')}",
            f"  Full Name: {user_info.get('full_name', 'N/A')}",
            f"  User ID: {user_info.get('user_id', 'N/A')}",
            f"  Group ID: {user_info.get('group_id', 'N/A')}",
            f"  Home Directory: {user_info.get('home_directory', 'N/A')}",
            f"  Shell: {user_info.get('shell', 'N/A')}",
            f"  Groups: {', '.join(user_info.get('groups', [])) or 'N/A'}",
            "",
        ]

        for tool_name, tool_data in self.results["tools"].items():
            lines.append("-" * 40)
            lines.append(f"TOOL: {tool_name.upper()}")
            lines.append("-" * 40)
            lines.append(f"  Installed: {'YES' if tool_data['installed'] else 'NO'}")
            lines.append(f"  Active: {'YES' if tool_data['active'] else 'NO'}")

            if tool_data["installation_details"]:
                lines.append("  Installation Details:")
                for k, v in tool_data["installation_details"].items():
                    lines.append(f"    {k}: {v}")

            if tool_data["processes"]:
                lines.append(f"  Running Processes ({len(tool_data['processes'])}):")
                for proc in tool_data["processes"][:5]:
                    lines.append(f"    PID {proc['pid']}: {proc['command'][:50]}...")

            if tool_data["port_listening"]:
                lines.append(f"  Port {tool_data['default_port']}: LISTENING")

            if tool_data["config_files"]:
                lines.append(f"  Config Files ({len(tool_data['config_files'])}):")
                for cf in tool_data["config_files"]:
                    lines.append(f"    - {cf['path']}")

            if tool_data["api_keys_found"]:
                lines.append(f"  API Keys Found ({len(tool_data['api_keys_found'])}):")
                for ak in tool_data["api_keys_found"]:
                    lines.append(f"    - {ak['path']}: {ak['value_masked']}")

            if tool_data["log_files"]:
                lines.append(f"  Log Files ({len(tool_data['log_files'])}):")
                for lf in tool_data["log_files"][:3]:
                    lines.append(f"    - {lf}")

            if tool_data["connections"]:
                lines.append(f"  Connections Found ({len(tool_data['connections'])}):")
                for conn in tool_data["connections"][:10]:
                    lines.append(f"    - {conn['resource']}")

            lines.append("")

        return "\n".join(lines)

    def export_json(self, filepath: str = None) -> str:
        """Export results as JSON."""
        if not self.results:
            self.scan_all()

        output = json.dumps(self.results, indent=2, default=str)

        if filepath:
            with open(filepath, "w") as f:
                f.write(output)

        return output


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Track clawbot/moltbot/openclaw installations"
    )
    parser.add_argument(
        "--api-key",
        default=API_KEY,
        help="API key to include in report"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of text report"
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path"
    )
    parser.add_argument(
        "--tool",
        choices=["openclaw", "moltbot", "clawbot"],
        help="Scan only a specific tool"
    )

    args = parser.parse_args()

    tracker = InstallationTracker(api_key=args.api_key)

    if args.tool:
        result = tracker.scan_tool(args.tool)
        output = json.dumps(result, indent=2, default=str)
    elif args.json:
        output = tracker.export_json()
    else:
        output = tracker.generate_report()

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Report saved to: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
