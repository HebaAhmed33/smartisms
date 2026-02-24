"""
JunOS Configuration Parser
Parses Juniper JunOS configuration files (set-style and hierarchical).
"""

import re
from core.models import ParsedConfig


class JunOSParser:
    """Parser for Juniper JunOS configuration files."""

    def parse(self, content: str) -> ParsedConfig:
        """Parse JunOS config into structured format."""
        config = ParsedConfig(vendor="junos")
        lines = content.split('\n')

        # Detect format: set-style vs hierarchical
        set_count = sum(1 for l in lines if l.strip().startswith('set '))
        brace_count = sum(1 for l in lines if '{' in l or '}' in l)

        if set_count > brace_count:
            self._parse_set_style(lines, config)
        else:
            self._parse_hierarchical(lines, config)

        return config

    def _parse_set_style(self, lines: list, config: ParsedConfig):
        """Parse JunOS 'set' command style configuration."""
        for line in lines:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith('/*'):
                continue

            # Remove 'set ' prefix
            if line.startswith('set '):
                path = line[4:]  # Remove 'set '
            elif line.startswith('deactivate '):
                path = line[11:]
                config.flat_keys[f"deactivate::{path}"] = "true"
                continue
            else:
                continue

            # Split the path into components
            parts = path.split()
            if len(parts) < 2:
                config.flat_keys[path] = "true"
                continue

            # Build hierarchical key
            full_key = ' '.join(parts[:-1])
            value = parts[-1]
            config.flat_keys[full_key] = value

            # Build section hierarchy
            section = parts[0]
            if section not in config.sections:
                config.sections[section] = {}
                config.blocks.append(section)

            # Nested sections
            current = config.sections[section]
            for part in parts[1:-1]:
                if part not in current:
                    current[part] = {}
                if isinstance(current[part], dict):
                    current = current[part]
                else:
                    break
            if isinstance(current, dict) and len(parts) >= 2:
                current[parts[-2] if len(parts) > 2 else parts[-1]] = value

    def _parse_hierarchical(self, lines: list, config: ParsedConfig):
        """Parse JunOS hierarchical (curly-brace) style configuration."""
        path_stack = []
        current_dict = config.sections

        for line in lines:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith('/*') or line.startswith('*/'):
                continue

            # Opening brace — push section
            if line.endswith('{'):
                section_name = line[:-1].strip()
                path_stack.append(section_name)

                # Navigate/create nested structure
                current = config.sections
                for segment in path_stack:
                    if segment not in current:
                        current[segment] = {}
                    current = current[segment]

                config.blocks.append(' '.join(path_stack))
                continue

            # Closing brace — pop section
            if line == '}':
                if path_stack:
                    path_stack.pop()
                continue

            # Key-value pair within current section
            # Remove trailing semicolons
            line = line.rstrip(';').strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) >= 2:
                key = parts[0]
                value = ' '.join(parts[1:])
            else:
                key = line
                value = "true"

            # Store in flat_keys with full path
            flat_key = ' '.join(path_stack + [key]) if path_stack else key
            config.flat_keys[flat_key] = value

            # Store in hierarchical sections
            current = config.sections
            for segment in path_stack:
                if segment not in current:
                    current[segment] = {}
                if isinstance(current[segment], dict):
                    current = current[segment]
            if isinstance(current, dict):
                current[key] = value
