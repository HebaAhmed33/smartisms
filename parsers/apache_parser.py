"""
Apache Configuration Parser
Parses Apache httpd configuration files with XML-style directives.
"""

import re
from core.models import ParsedConfig


class ApacheParser:
    """Parser for Apache httpd configuration files."""

    def parse(self, content: str) -> ParsedConfig:
        """Parse Apache config into structured format."""
        config = ParsedConfig(vendor="apache")
        lines = content.split('\n')

        block_stack = []   # Track nested <Directory>, <VirtualHost>, etc.

        for line in lines:
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Opening XML-style block: <VirtualHost *:80>
            open_match = re.match(r'^<(\w+)\s*(.*?)>', line)
            close_match = re.match(r'^</(\w+)>', line)

            if close_match:
                # Closing block tag
                if block_stack:
                    block_stack.pop()
                continue

            if open_match:
                tag_name = open_match.group(1)
                tag_args = open_match.group(2).strip()
                block_name = f"{tag_name} {tag_args}".strip() if tag_args else tag_name
                block_stack.append(block_name)

                full_block = '::'.join(block_stack)
                config.blocks.append(full_block)
                if full_block not in config.sections:
                    config.sections[full_block] = {}
                continue

            # Parse directive: Key Value
            parts = line.split(None, 1)
            key = parts[0]
            value = parts[1] if len(parts) > 1 else "On"

            # Remove surrounding quotes from value
            value = value.strip('"').strip("'")

            # Build flat key with block context
            if block_stack:
                current_block = '::'.join(block_stack)
                flat_key = f"{current_block}::{key}"
            else:
                flat_key = key

            config.flat_keys[flat_key] = value

            # Store in sections
            current_section = '::'.join(block_stack) if block_stack else "global"
            if current_section not in config.sections:
                config.sections[current_section] = {}
            config.sections[current_section][key] = value

        return config
