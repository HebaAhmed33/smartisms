"""
Linux Configuration Parser
Parses Linux config files: sshd_config, sysctl.conf, login.defs, etc.
Key=Value and Key Value formats.
"""

import re
from core.models import ParsedConfig


class LinuxParser:
    """Parser for Linux configuration files (sshd_config, sysctl, login.defs)."""

    def parse(self, content: str) -> ParsedConfig:
        """Parse Linux config into structured format."""
        config = ParsedConfig(vendor="linux")
        lines = content.split('\n')

        # Detect config type from content
        config_type = self._detect_config_type(content)

        for line in lines:
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Handle Match blocks in sshd_config
            match_block = re.match(r'^Match\s+(.*)', line, re.IGNORECASE)
            if match_block:
                block_name = f"Match {match_block.group(1)}"
                config.blocks.append(block_name)
                if block_name not in config.sections:
                    config.sections[block_name] = {}
                continue

            # Parse key-value: supports key=value, key value, key\tvalue
            kv_match = re.match(r'^(\S+)\s*[=\s]\s*(.*)', line)
            if kv_match:
                key = kv_match.group(1).strip()
                value = kv_match.group(2).strip()

                # Remove surrounding quotes
                value = value.strip('"').strip("'")

                # Remove inline comments
                if ' #' in value:
                    value = value[:value.index(' #')].strip()

                config.flat_keys[key] = value

                # Store in sections by config type
                if config_type not in config.sections:
                    config.sections[config_type] = {}
                config.sections[config_type][key] = value

        config.blocks.append(config_type)
        return config

    def _detect_config_type(self, content: str) -> str:
        """Detect which Linux config file type this is."""
        content_lower = content.lower()

        if 'permitrootlogin' in content_lower or 'sshd' in content_lower:
            return "sshd_config"
        elif 'net.ipv4' in content_lower or 'sysctl' in content_lower:
            return "sysctl"
        elif 'pass_max_days' in content_lower or 'login.defs' in content_lower:
            return "login_defs"
        elif 'umask' in content_lower and 'pass_' in content_lower:
            return "login_defs"
        elif 'auditd' in content_lower or 'log_file' in content_lower:
            return "auditd"
        else:
            return "linux_generic"
