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

# Try to import yaml, fallback to basic parsing if not available
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Configuration - Add your API key here
API_KEY = "YOUR_API_KEY_HERE"

# Known services/apps for categorization
KNOWN_SERVICES = {
    # AI/ML Services
    "anthropic": {"name": "Anthropic Claude", "category": "AI/ML"},
    "openai": {"name": "OpenAI", "category": "AI/ML"},
    "api.openai.com": {"name": "OpenAI API", "category": "AI/ML"},
    "api.anthropic.com": {"name": "Anthropic API", "category": "AI/ML"},
    "huggingface": {"name": "Hugging Face", "category": "AI/ML"},
    "cohere": {"name": "Cohere", "category": "AI/ML"},
    "replicate": {"name": "Replicate", "category": "AI/ML"},
    "palm": {"name": "Google PaLM", "category": "AI/ML"},
    "gemini": {"name": "Google Gemini", "category": "AI/ML"},
    "vertex": {"name": "Google Vertex AI", "category": "AI/ML"},
    "bedrock": {"name": "AWS Bedrock", "category": "AI/ML"},
    "azure.openai": {"name": "Azure OpenAI", "category": "AI/ML"},

    # Cloud Providers
    "amazonaws.com": {"name": "AWS", "category": "Cloud"},
    "aws": {"name": "AWS", "category": "Cloud"},
    "s3.": {"name": "AWS S3", "category": "Cloud Storage"},
    "ec2.": {"name": "AWS EC2", "category": "Cloud Compute"},
    "lambda.": {"name": "AWS Lambda", "category": "Cloud Compute"},
    "azure": {"name": "Microsoft Azure", "category": "Cloud"},
    "blob.core.windows": {"name": "Azure Blob Storage", "category": "Cloud Storage"},
    "googleapis.com": {"name": "Google Cloud", "category": "Cloud"},
    "storage.googleapis": {"name": "Google Cloud Storage", "category": "Cloud Storage"},
    "digitalocean": {"name": "DigitalOcean", "category": "Cloud"},

    # Version Control
    "github.com": {"name": "GitHub", "category": "Version Control"},
    "api.github.com": {"name": "GitHub API", "category": "Version Control"},
    "gitlab": {"name": "GitLab", "category": "Version Control"},
    "bitbucket": {"name": "Bitbucket", "category": "Version Control"},

    # Databases
    "mongodb": {"name": "MongoDB", "category": "Database"},
    "postgres": {"name": "PostgreSQL", "category": "Database"},
    "mysql": {"name": "MySQL", "category": "Database"},
    "redis": {"name": "Redis", "category": "Database"},
    "elasticsearch": {"name": "Elasticsearch", "category": "Database"},
    "dynamodb": {"name": "AWS DynamoDB", "category": "Database"},
    "firestore": {"name": "Google Firestore", "category": "Database"},
    "supabase": {"name": "Supabase", "category": "Database"},

    # Communication
    "slack": {"name": "Slack", "category": "Communication"},
    "discord": {"name": "Discord", "category": "Communication"},
    "telegram": {"name": "Telegram", "category": "Communication"},
    "twilio": {"name": "Twilio", "category": "Communication"},
    "sendgrid": {"name": "SendGrid", "category": "Communication"},
    "mailgun": {"name": "Mailgun", "category": "Communication"},

    # Authentication
    "auth0": {"name": "Auth0", "category": "Authentication"},
    "okta": {"name": "Okta", "category": "Authentication"},
    "oauth": {"name": "OAuth Provider", "category": "Authentication"},
    "cognito": {"name": "AWS Cognito", "category": "Authentication"},

    # Monitoring/Logging
    "datadog": {"name": "Datadog", "category": "Monitoring"},
    "sentry": {"name": "Sentry", "category": "Monitoring"},
    "newrelic": {"name": "New Relic", "category": "Monitoring"},
    "splunk": {"name": "Splunk", "category": "Monitoring"},
    "grafana": {"name": "Grafana", "category": "Monitoring"},
    "prometheus": {"name": "Prometheus", "category": "Monitoring"},

    # CI/CD
    "jenkins": {"name": "Jenkins", "category": "CI/CD"},
    "circleci": {"name": "CircleCI", "category": "CI/CD"},
    "travis": {"name": "Travis CI", "category": "CI/CD"},
    "actions.github": {"name": "GitHub Actions", "category": "CI/CD"},

    # Container/Orchestration
    "docker": {"name": "Docker", "category": "Container"},
    "kubernetes": {"name": "Kubernetes", "category": "Orchestration"},
    "k8s": {"name": "Kubernetes", "category": "Orchestration"},

    # Local Services
    "localhost": {"name": "Localhost", "category": "Local"},
    "127.0.0.1": {"name": "Localhost", "category": "Local"},
    "0.0.0.0": {"name": "All Interfaces", "category": "Local"},
}

# Known installation paths and configurations
TOOL_CONFIGS = {
    "openclaw": {
        "config_paths": [
            "~/.openclaw/openclaw.json",
            "~/.openclaw/config.json",
            "~/.openclaw/config.yaml",
            "~/.openclaw/config.yml",
            "~/.openclaw/openclaw.yaml",
            "~/.openclaw/openclaw.yml",
            "~/.config/openclaw/config.json",
            "~/.config/openclaw/config.yaml",
            "~/.config/openclaw/config.yml",
            "/etc/openclaw/config.yaml",
            "/etc/openclaw/config.yml",
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
            "~/.moltbot/config.yaml",
            "~/.moltbot/config.yml",
            "~/.moltbot/moltbot.json",
            "~/.moltbot/moltbot.yaml",
            "~/.moltbot/moltbot.yml",
            "~/.config/moltbot/config.json",
            "~/.config/moltbot/config.yaml",
            "~/.config/moltbot/config.yml",
            "~/.config/moltbot/settings.json",
            "~/.config/moltbot/settings.yaml",
            "~/.config/moltbot/settings.yml",
            "/etc/moltbot/config.yaml",
            "/etc/moltbot/config.yml",
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
            "~/.clawbot/config.yaml",
            "~/.clawbot/config.yml",
            "~/.clawbot/clawbot.json",
            "~/.clawbot/clawbot.yaml",
            "~/.clawbot/clawbot.yml",
            "~/.config/clawbot/config.json",
            "~/.config/clawbot/config.yaml",
            "~/.config/clawbot/config.yml",
            "~/.config/clawbot/settings.json",
            "~/.config/clawbot/settings.yaml",
            "~/.config/clawbot/settings.yml",
            "/etc/clawbot/config.yaml",
            "/etc/clawbot/config.yml",
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
        """Read and parse a JSON or YAML configuration file."""
        expanded_path = self._expand_path(config_path)
        if os.path.exists(expanded_path):
            try:
                with open(expanded_path, "r") as f:
                    content = f.read()

                # Determine file type by extension
                is_yaml = expanded_path.lower().endswith(('.yaml', '.yml'))

                if is_yaml:
                    return self._parse_yaml(content, expanded_path)
                else:
                    # Handle JSON with comments or trailing commas
                    content = re.sub(r'//.*?\n', '\n', content)
                    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
                    content = re.sub(r',(\s*[}\]])', r'\1', content)
                    return json.loads(content)
            except (json.JSONDecodeError, IOError) as e:
                return {"_error": str(e), "_path": expanded_path}
        return None

    def _parse_yaml(self, content: str, filepath: str) -> Optional[Dict[str, Any]]:
        """Parse YAML content, with fallback if PyYAML not installed."""
        if YAML_AVAILABLE:
            try:
                # Use safe_load to prevent arbitrary code execution
                data = yaml.safe_load(content)
                if isinstance(data, dict):
                    return data
                return {"_data": data, "_type": type(data).__name__}
            except yaml.YAMLError as e:
                return {"_error": str(e), "_path": filepath}
        else:
            # Basic YAML parsing fallback (handles simple key: value pairs)
            return self._basic_yaml_parse(content, filepath)

    def _basic_yaml_parse(self, content: str, filepath: str) -> Dict[str, Any]:
        """Basic YAML parser for simple configs when PyYAML is not available."""
        result = {"_warning": "PyYAML not installed, using basic parser", "_path": filepath}
        current_dict = result
        indent_stack = [(0, result)]

        for line in content.split('\n'):
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            # Calculate indent level
            indent = len(line) - len(line.lstrip())

            # Find the key-value pair
            if ':' in stripped:
                key, _, value = stripped.partition(':')
                key = key.strip()
                value = value.strip()

                # Remove quotes from value
                if value and value[0] in '"\'':
                    value = value[1:-1] if len(value) > 1 and value[-1] == value[0] else value[1:]

                # Handle nested structures
                while indent_stack and indent <= indent_stack[-1][0]:
                    if len(indent_stack) > 1:
                        indent_stack.pop()
                    else:
                        break

                current_dict = indent_stack[-1][1]

                if value:
                    # Convert common types
                    if value.lower() == 'true':
                        value = True
                    elif value.lower() == 'false':
                        value = False
                    elif value.lower() in ('null', 'none', '~'):
                        value = None
                    elif value.isdigit():
                        value = int(value)
                    elif re.match(r'^-?\d+\.\d+$', value):
                        value = float(value)

                    current_dict[key] = value
                else:
                    # Nested dict
                    new_dict = {}
                    current_dict[key] = new_dict
                    indent_stack.append((indent + 1, new_dict))

        return result

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

    def _parse_log_for_accessed_apps(self, log_file: str, max_lines: int = 2000) -> List[Dict[str, Any]]:
        """Parse log file to identify apps/services accessed or attempted to access."""
        accessed_apps = []

        # Patterns for identifying access attempts and their status
        access_patterns = [
            # HTTP/API requests
            (r'(?:GET|POST|PUT|DELETE|PATCH)\s+["\']?(https?://[^\s"\']+)["\']?', "http_request"),
            (r'(?:request|fetch|call)(?:ing|ed)?\s+(?:to\s+)?["\']?(https?://[^\s"\']+)["\']?', "api_call"),
            (r'(?:api|endpoint)["\s:=]+["\']?(https?://[^\s"\'<>]+)["\']?', "api_endpoint"),

            # URLs and hosts
            (r'(?:url|host|server|endpoint)["\s:=]+["\']?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?::\d+)?)["\']?', "host"),
            (r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)(?:[:/]|$)', "url_host"),

            # Connection events
            (r'connect(?:ed|ing|ion)?\s+(?:to\s+)?["\']?([a-zA-Z0-9][-a-zA-Z0-9.]+(?::\d+)?)["\']?', "connection"),
            (r'(?:establish|open)(?:ed|ing)?\s+(?:connection\s+)?(?:to\s+)?["\']?([^\s"\']+)["\']?', "connection"),

            # Authentication
            (r'(?:auth|login|signin|authenticate)(?:ed|ing|ation)?\s+(?:to|with|for|at)\s+["\']?([^\s"\']+)["\']?', "auth"),
            (r'(?:oauth|sso|saml)\s+(?:to|with|for)\s+["\']?([^\s"\']+)["\']?', "oauth"),
            (r'(?:token|credential|key)\s+(?:for|from)\s+["\']?([^\s"\']+)["\']?', "credential"),

            # WebSocket
            (r'(?:websocket|ws|wss)://([^\s"\']+)', "websocket"),

            # Database connections
            (r'(?:mongodb|postgres|mysql|redis|elasticsearch)(?:://)?([^\s"\']+)', "database"),
            (r'(?:database|db)\s+(?:connection|host)["\s:=]+["\']?([^\s"\']+)["\']?', "database"),

            # Service-specific
            (r'(?:github|gitlab|bitbucket)\.com/([^\s"\']+)', "vcs"),
            (r'(?:slack|discord|telegram)(?:\.com)?(?:/|:)([^\s"\']+)', "messaging"),
            (r's3://([^\s"\']+)', "s3"),
            (r'(?:bucket|container)["\s:=]+["\']?([^\s"\']+)["\']?', "storage"),

            # File system access
            (r'(?:read|write|access|open)(?:ing|ed)?\s+(?:file\s+)?["\']?(/[^\s"\']+)["\']?', "file"),
            (r'(?:path|file|directory)["\s:=]+["\']?(/[^\s"\']+)["\']?', "file"),

            # Model/AI service
            (r'(?:model|llm)["\s:=]+["\']?([^\s"\']+)["\']?', "model"),
            (r'(?:claude|gpt|gemini|llama|mistral)[-\s]?[\d.]*', "ai_model"),
        ]

        # Status indicators
        success_indicators = ['success', 'ok', '200', '201', '204', 'connected', 'authenticated', 'completed', 'done']
        failure_indicators = ['fail', 'error', 'denied', 'refused', 'timeout', '401', '403', '404', '500', '502', '503', 'rejected', 'unauthorized']
        attempt_indicators = ['attempt', 'trying', 'connecting', 'requesting', 'fetching']

        try:
            with open(log_file, "r", errors="ignore") as f:
                lines = f.readlines()[-max_lines:]

                for line_num, line in enumerate(lines):
                    line_lower = line.lower()

                    # Determine access status from line context
                    status = "unknown"
                    if any(ind in line_lower for ind in success_indicators):
                        status = "success"
                    elif any(ind in line_lower for ind in failure_indicators):
                        status = "failed"
                    elif any(ind in line_lower for ind in attempt_indicators):
                        status = "attempted"

                    # Try to extract timestamp
                    timestamp = None
                    timestamp_patterns = [
                        r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})',
                        r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',
                        r'\[(\d+)\]',  # Unix timestamp
                    ]
                    for ts_pattern in timestamp_patterns:
                        ts_match = re.search(ts_pattern, line)
                        if ts_match:
                            timestamp = ts_match.group(1)
                            break

                    # Find all access patterns
                    for pattern, access_type in access_patterns:
                        matches = re.findall(pattern, line, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0]

                            # Skip empty or too short matches
                            if not match or len(match) < 3:
                                continue

                            # Categorize the service
                            service_info = self._categorize_service(match)

                            accessed_apps.append({
                                "resource": match,
                                "access_type": access_type,
                                "status": status,
                                "timestamp": timestamp,
                                "service_name": service_info.get("name"),
                                "service_category": service_info.get("category"),
                                "log_file": log_file,
                                "line_number": line_num + 1,
                                "line_sample": line.strip()[:150]
                            })

        except IOError:
            pass

        return accessed_apps

    def _categorize_service(self, resource: str) -> Dict[str, str]:
        """Categorize a resource/service based on known patterns."""
        resource_lower = resource.lower()

        for pattern, info in KNOWN_SERVICES.items():
            if pattern.lower() in resource_lower:
                return info

        # Try to identify by domain patterns
        if re.search(r'\.gov$', resource_lower):
            return {"name": "Government Service", "category": "Government"}
        if re.search(r'\.edu$', resource_lower):
            return {"name": "Educational Institution", "category": "Education"}
        if re.search(r'\.internal$|\.local$|\.corp$', resource_lower):
            return {"name": "Internal Service", "category": "Internal"}
        if re.search(r'api\.', resource_lower):
            return {"name": "API Service", "category": "API"}

        return {"name": "Unknown", "category": "Unknown"}

    def _aggregate_accessed_apps(self, apps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate accessed apps into a summary with statistics."""
        summary = {
            "total_access_events": len(apps),
            "by_category": {},
            "by_status": {"success": 0, "failed": 0, "attempted": 0, "unknown": 0},
            "unique_services": [],
            "access_timeline": [],
        }

        seen_services = {}

        for app in apps:
            # Count by status
            status = app.get("status", "unknown")
            if status in summary["by_status"]:
                summary["by_status"][status] += 1

            # Group by category
            category = app.get("service_category", "Unknown")
            if category not in summary["by_category"]:
                summary["by_category"][category] = []

            # Track unique services per category
            resource = app.get("resource", "")
            service_key = f"{category}:{resource}"

            if service_key not in seen_services:
                seen_services[service_key] = {
                    "resource": resource,
                    "service_name": app.get("service_name"),
                    "category": category,
                    "access_count": 0,
                    "success_count": 0,
                    "failure_count": 0,
                    "first_seen": app.get("timestamp"),
                    "last_seen": app.get("timestamp"),
                    "access_types": set(),
                }
                summary["by_category"][category].append(seen_services[service_key])

            # Update service stats
            seen_services[service_key]["access_count"] += 1
            seen_services[service_key]["access_types"].add(app.get("access_type", "unknown"))
            if status == "success":
                seen_services[service_key]["success_count"] += 1
            elif status == "failed":
                seen_services[service_key]["failure_count"] += 1
            if app.get("timestamp"):
                seen_services[service_key]["last_seen"] = app.get("timestamp")

        # Convert sets to lists for JSON serialization
        for service in seen_services.values():
            service["access_types"] = list(service["access_types"])
            summary["unique_services"].append(service)

        # Sort unique services by access count
        summary["unique_services"].sort(key=lambda x: x["access_count"], reverse=True)

        return summary

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
            "accessed_apps": [],
            "accessed_apps_summary": {},
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

        # Parse logs for accessed apps/services
        all_accessed_apps = []
        for log_file in log_files[:5]:  # Parse top 5 most recent logs
            accessed = self._parse_log_for_accessed_apps(log_file)
            all_accessed_apps.extend(accessed)

        result["accessed_apps"] = all_accessed_apps
        result["accessed_apps_summary"] = self._aggregate_accessed_apps(all_accessed_apps)

        return result

    def scan_all(self, tools: List[str] = None) -> Dict[str, Any]:
        """Scan for specified tools or all known tools if none specified."""
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

        # Use provided tools list or default to all configured tools
        tools_to_scan = tools if tools else list(TOOL_CONFIGS.keys())

        for tool_name in tools_to_scan:
            if tool_name in TOOL_CONFIGS:
                self.results["tools"][tool_name] = self.scan_tool(tool_name)
            else:
                # For custom tools not in TOOL_CONFIGS, create a generic config
                self.results["tools"][tool_name] = self.scan_custom_tool(tool_name)

        return self.results

    def scan_custom_tool(self, tool_name: str) -> Dict[str, Any]:
        """Scan for a custom tool using generic paths based on tool name."""
        # Generate generic config paths based on tool name
        generic_config = {
            "config_paths": [
                f"~/.{tool_name}/config.json",
                f"~/.{tool_name}/config.yaml",
                f"~/.{tool_name}/config.yml",
                f"~/.{tool_name}/{tool_name}.json",
                f"~/.{tool_name}/{tool_name}.yaml",
                f"~/.{tool_name}/{tool_name}.yml",
                f"~/.config/{tool_name}/config.json",
                f"~/.config/{tool_name}/config.yaml",
                f"~/.config/{tool_name}/config.yml",
                f"/etc/{tool_name}/config.yaml",
                f"/etc/{tool_name}/config.yml",
            ],
            "log_paths": [
                f"~/.{tool_name}/logs/*.log",
                f"~/.{tool_name}/*.log",
                f"/var/log/{tool_name}/*.log",
            ],
            "workspace_path": f"~/.{tool_name}/workspace",
            "process_names": [tool_name, f"{tool_name}-agent", f"{tool_name}-daemon", f"{tool_name}-server"],
            "default_port": None,
            "binary_names": [tool_name],
        }

        # Temporarily add to TOOL_CONFIGS
        TOOL_CONFIGS[tool_name] = generic_config
        result = self.scan_tool(tool_name)
        # Remove after scanning
        del TOOL_CONFIGS[tool_name]

        return result

    def add_custom_tool(self, tool_name: str, config: Dict[str, Any] = None):
        """Add a custom tool configuration."""
        if config:
            TOOL_CONFIGS[tool_name] = config
        else:
            # Use generic config
            TOOL_CONFIGS[tool_name] = {
                "config_paths": [
                    f"~/.{tool_name}/config.json",
                    f"~/.{tool_name}/config.yaml",
                    f"~/.{tool_name}/config.yml",
                    f"~/.config/{tool_name}/config.json",
                    f"~/.config/{tool_name}/config.yaml",
                ],
                "log_paths": [
                    f"~/.{tool_name}/logs/*.log",
                    f"~/.{tool_name}/*.log",
                    f"/var/log/{tool_name}/*.log",
                ],
                "workspace_path": f"~/.{tool_name}/workspace",
                "process_names": [tool_name, f"{tool_name}-agent", f"{tool_name}-daemon"],
                "default_port": None,
                "binary_names": [tool_name],
            }

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

            # Accessed Apps Summary
            summary = tool_data.get("accessed_apps_summary", {})
            if summary.get("total_access_events", 0) > 0:
                lines.append("")
                lines.append("  ACCESSED APPS/SERVICES:")
                lines.append(f"    Total Access Events: {summary['total_access_events']}")
                lines.append(f"    Unique Services: {len(summary.get('unique_services', []))}")

                by_status = summary.get("by_status", {})
                lines.append(f"    Status: {by_status.get('success', 0)} success, "
                           f"{by_status.get('failed', 0)} failed, "
                           f"{by_status.get('attempted', 0)} attempted")

                # Show by category
                by_category = summary.get("by_category", {})
                if by_category:
                    lines.append("")
                    lines.append("    By Category:")
                    for category, services in sorted(by_category.items()):
                        if services:
                            lines.append(f"      [{category}]")
                            for svc in services[:5]:  # Limit to 5 per category
                                status_str = ""
                                if svc.get("success_count", 0) > 0:
                                    status_str += f" ({svc['success_count']} ok"
                                if svc.get("failure_count", 0) > 0:
                                    status_str += f", {svc['failure_count']} fail"
                                if status_str:
                                    status_str += ")"
                                lines.append(f"        - {svc['resource'][:50]}{status_str}")
                            if len(services) > 5:
                                lines.append(f"        ... and {len(services) - 5} more")

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

    def generate_access_report(self, as_json: bool = False) -> str:
        """Generate a focused report on accessed apps and servers based on events."""
        if not self.results:
            self.scan_all()

        # Collect all accessed apps across all tools
        all_apps = []
        all_events = []

        for tool_name, tool_data in self.results.get("tools", {}).items():
            for app in tool_data.get("accessed_apps", []):
                app["source_tool"] = tool_name
                all_events.append(app)

            for svc in tool_data.get("accessed_apps_summary", {}).get("unique_services", []):
                svc["source_tool"] = tool_name
                all_apps.append(svc)

        # Aggregate by resource across all tools
        aggregated = {}
        for app in all_apps:
            resource = app.get("resource", "")
            if resource not in aggregated:
                aggregated[resource] = {
                    "resource": resource,
                    "service_name": app.get("service_name"),
                    "category": app.get("category", "Unknown"),
                    "total_access_count": 0,
                    "success_count": 0,
                    "failure_count": 0,
                    "access_types": set(),
                    "source_tools": set(),
                    "first_seen": app.get("first_seen"),
                    "last_seen": app.get("last_seen"),
                }
            aggregated[resource]["total_access_count"] += app.get("access_count", 0)
            aggregated[resource]["success_count"] += app.get("success_count", 0)
            aggregated[resource]["failure_count"] += app.get("failure_count", 0)
            aggregated[resource]["access_types"].update(app.get("access_types", []))
            aggregated[resource]["source_tools"].add(app.get("source_tool", ""))

        # Convert sets to lists for JSON
        for item in aggregated.values():
            item["access_types"] = list(item["access_types"])
            item["source_tools"] = list(item["source_tools"])

        # Sort by access count
        sorted_apps = sorted(aggregated.values(), key=lambda x: x["total_access_count"], reverse=True)

        # Group by category
        by_category = {}
        for app in sorted_apps:
            cat = app.get("category", "Unknown")
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(app)

        # Calculate stats
        stats = {
            "total_unique_resources": len(sorted_apps),
            "total_events": len(all_events),
            "successful_accesses": sum(a.get("success_count", 0) for a in sorted_apps),
            "failed_accesses": sum(a.get("failure_count", 0) for a in sorted_apps),
            "categories": list(by_category.keys()),
        }

        report_data = {
            "report_type": "accessed_apps_and_servers",
            "generated_at": datetime.now().isoformat(),
            "statistics": stats,
            "by_category": by_category,
            "all_resources": sorted_apps,
            "recent_events": all_events[-100:],  # Last 100 events
        }

        if as_json:
            return json.dumps(report_data, indent=2, default=str)

        # Generate text report
        lines = [
            "=" * 70,
            "ACCESSED APPS AND SERVERS REPORT",
            f"Generated: {report_data['generated_at']}",
            "=" * 70,
            "",
            "SUMMARY:",
            f"  Total Unique Resources: {stats['total_unique_resources']}",
            f"  Total Access Events: {stats['total_events']}",
            f"  Successful Accesses: {stats['successful_accesses']}",
            f"  Failed Accesses: {stats['failed_accesses']}",
            f"  Categories: {', '.join(stats['categories'])}",
            "",
        ]

        # List by category
        for category in sorted(by_category.keys()):
            apps = by_category[category]
            lines.append("=" * 70)
            lines.append(f"[{category.upper()}] - {len(apps)} resource(s)")
            lines.append("=" * 70)

            for app in apps:
                resource = app.get("resource", "N/A")
                service_name = app.get("service_name", "")
                access_count = app.get("total_access_count", 0)
                success = app.get("success_count", 0)
                failure = app.get("failure_count", 0)
                access_types = ", ".join(app.get("access_types", []))
                tools = ", ".join(app.get("source_tools", []))

                lines.append("")
                lines.append(f"  Resource: {resource}")
                if service_name and service_name != "Unknown":
                    lines.append(f"  Service:  {service_name}")
                lines.append(f"  Access Count: {access_count} (success: {success}, failed: {failure})")
                if access_types:
                    lines.append(f"  Access Types: {access_types}")
                if tools:
                    lines.append(f"  Source Tools: {tools}")
                lines.append("  " + "-" * 40)

            lines.append("")

        # Recent events section
        if all_events:
            lines.append("=" * 70)
            lines.append("RECENT ACCESS EVENTS (last 20)")
            lines.append("=" * 70)

            for event in all_events[-20:]:
                resource = event.get("resource", "N/A")
                status = event.get("status", "unknown")
                access_type = event.get("access_type", "N/A")
                timestamp = event.get("timestamp", "N/A")
                tool = event.get("source_tool", "N/A")

                status_icon = "✓" if status == "success" else "✗" if status == "failed" else "?"
                lines.append(f"  [{status_icon}] {resource[:50]}")
                lines.append(f"      Type: {access_type} | Status: {status} | Tool: {tool}")
                if timestamp:
                    lines.append(f"      Time: {timestamp}")
                lines.append("")

        return "\n".join(lines)

    def get_accessed_apps_list(self) -> List[Dict[str, Any]]:
        """Get a simple list of all accessed apps/servers."""
        if not self.results:
            self.scan_all()

        apps_list = []
        seen = set()

        for tool_name, tool_data in self.results.get("tools", {}).items():
            for svc in tool_data.get("accessed_apps_summary", {}).get("unique_services", []):
                resource = svc.get("resource", "")
                if resource and resource not in seen:
                    seen.add(resource)
                    apps_list.append({
                        "resource": resource,
                        "service_name": svc.get("service_name"),
                        "category": svc.get("category"),
                        "access_count": svc.get("access_count", 0),
                        "success_count": svc.get("success_count", 0),
                        "failure_count": svc.get("failure_count", 0),
                        "source_tool": tool_name,
                    })

        return sorted(apps_list, key=lambda x: x["access_count"], reverse=True)


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Track tool installations (clawbot/moltbot/openclaw and custom tools)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan default tools (openclaw, moltbot, clawbot)
  python installation_tracker.py

  # Scan specific tools from the default list
  python installation_tracker.py --tools openclaw moltbot

  # Scan custom tools (will use generic paths based on tool name)
  python installation_tracker.py --tools mytool anothertool

  # Mix default and custom tools
  python installation_tracker.py --tools openclaw mytool custombot

  # Output as JSON
  python installation_tracker.py --tools openclaw --json

  # Save to file
  python installation_tracker.py --tools openclaw moltbot -o report.json --json

  # List accessed apps and servers (focused report)
  python installation_tracker.py --access-report
  python installation_tracker.py --access-report --json

  # Simple list of accessed resources
  python installation_tracker.py --list-accessed
  python installation_tracker.py --list-accessed --json
        """
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
        help="Scan only a specific tool (deprecated, use --tools instead)"
    )
    parser.add_argument(
        "--tools",
        "-t",
        nargs="+",
        help="List of tools to scan (e.g., --tools openclaw moltbot mytool)"
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List all predefined tools and exit"
    )
    parser.add_argument(
        "--access-report",
        action="store_true",
        help="Generate a focused report on accessed apps and servers"
    )
    parser.add_argument(
        "--list-accessed",
        action="store_true",
        help="Output a simple list of accessed apps/servers"
    )

    args = parser.parse_args()

    # Handle --list-tools
    if args.list_tools:
        print("Predefined tools:")
        for tool_name, config in TOOL_CONFIGS.items():
            print(f"  {tool_name}:")
            print(f"    Port: {config.get('default_port', 'N/A')}")
            print(f"    Processes: {', '.join(config.get('process_names', []))}")
        print("\nYou can also specify custom tool names with --tools")
        return

    tracker = InstallationTracker(api_key=args.api_key)

    # Determine which tools to scan
    tools_to_scan = None
    if args.tools:
        tools_to_scan = args.tools
    elif args.tool:
        tools_to_scan = [args.tool]

    # Perform scan first
    tracker.scan_all(tools=tools_to_scan)

    # Generate appropriate output
    if args.access_report:
        # Focused report on accessed apps/servers
        output = tracker.generate_access_report(as_json=args.json)
    elif args.list_accessed:
        # Simple list of accessed apps/servers
        apps_list = tracker.get_accessed_apps_list()
        if args.json:
            output = json.dumps(apps_list, indent=2, default=str)
        else:
            lines = [
                "ACCESSED APPS AND SERVERS LIST",
                "=" * 50,
                ""
            ]
            if apps_list:
                for app in apps_list:
                    status = f"✓{app['success_count']}" if app['success_count'] else ""
                    if app['failure_count']:
                        status += f" ✗{app['failure_count']}"
                    category = f"[{app['category']}]" if app['category'] else ""
                    lines.append(f"  {app['resource']}")
                    lines.append(f"    {category} Count: {app['access_count']} {status}")
                    lines.append("")
            else:
                lines.append("  No accessed apps/servers found in logs.")
            output = "\n".join(lines)
    elif tools_to_scan and len(tools_to_scan) == 1:
        # Single tool scan - output just that tool's data
        tool_name = tools_to_scan[0]
        result = tracker.results.get("tools", {}).get(tool_name, {})
        output = json.dumps(result, indent=2, default=str)
    else:
        # Full report
        if args.json:
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
