"""
Cisco IOS Configuration Parser
Parses Cisco IOS/IOS-XE style configuration files into structured format.
"""

import re
from core.models import ParsedConfig


class CiscoParser:
    """Parser for Cisco IOS configuration files."""

    # Lines that are comments or should be skipped
    SKIP_PATTERNS = [
        r"^\s*!",           # Cisco comment
        r"^\s*$",           # Empty line
        r"^Building\s+configuration",
        r"^Current\s+configuration",
        r"^end\s*$",
    ]

    def parse(self, content: str) -> ParsedConfig:
        """Parse Cisco IOS config into structured format."""
        config = ParsedConfig(vendor="cisco")
        lines = content.split('\n')

        current_section = None
        current_block = {}
        section_stack = []

        for line_num, raw_line in enumerate(lines):
            line = raw_line.rstrip()

            # Skip comments and empty lines
            if self._should_skip(line):
                continue

            # Detect section start (interface, router, line, etc.)
            section_match = re.match(
                r'^(interface|router|line|ip access-list|crypto|class-map|'
                r'policy-map|route-map|vlan|spanning-tree|aaa|key chain)\s+(.*)',
                line, re.IGNORECASE
            )

            if section_match:
                # Save previous section
                if current_section:
                    self._save_section(config, current_section, current_block)

                section_type = section_match.group(1).lower()
                section_name = section_match.group(2).strip()
                current_section = f"{section_type} {section_name}"
                current_block = {}
                config.blocks.append(current_section)
                continue

            # Detect end of section (line starting without whitespace)
            if not line.startswith(' ') and not line.startswith('\t') and current_section:
                self._save_section(config, current_section, current_block)
                current_section = None
                current_block = {}

            # Parse key-value within section
            if current_section:
                stripped = line.strip()
                if stripped:
                    key, value = self._parse_kv(stripped)
                    current_block[key] = value

                    # Also store as section.key in flat_keys
                    flat_key = f"{current_section}::{key}"
                    config.flat_keys[flat_key] = value
            else:
                # Global config line
                stripped = line.strip()
                if stripped:
                    key, value = self._parse_kv(stripped)
                    config.flat_keys[key] = value

        # Save last section
        if current_section:
            self._save_section(config, current_section, current_block)

        return config

    def _should_skip(self, line: str) -> bool:
        """Check if line should be skipped."""
        for pattern in self.SKIP_PATTERNS:
            if re.match(pattern, line):
                return True
        return False

    def _parse_kv(self, line: str) -> tuple:
        """
        Parse a config line into key-value pair.
        Examples:
            'hostname R1' -> ('hostname', 'R1')
            'no ip http server' -> ('no ip http server', 'true')
            'ip ssh version 2' -> ('ip ssh version', '2')
        """
        # Handle 'no' commands
        if line.startswith('no '):
            return (line, 'true')

        # Try to split into key + value
        parts = line.split()
        if len(parts) == 1:
            return (line, 'true')
        elif len(parts) == 2:
            return (parts[0], parts[1])
        else:
            # Last element is typically the value
            key = ' '.join(parts[:-1])
            value = parts[-1]
            return (key, value)

    def _save_section(self, config: ParsedConfig, section_name: str, block: dict):
        """Save a parsed section to the config object."""
        config.sections[section_name] = block.copy()

        # If it's an interface, also store in interfaces
        if section_name.startswith('interface '):
            iface_name = section_name.replace('interface ', '')
            config.interfaces[iface_name] = block.copy()
