"""
Nginx Configuration Parser
Parses Nginx configuration files with block-style directives.
"""

import re
from core.models import ParsedConfig


class NginxParser:
    """Parser for Nginx configuration files."""

    def parse(self, content: str) -> ParsedConfig:
        """Parse Nginx config into structured format."""
        config = ParsedConfig(vendor="nginx")
        lines = content.split('\n')

        block_stack = []        # Track nested block context
        current_block_name = "global"

        for line in lines:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Handle opening block: "http {", "server {", "location /path {"
            brace_open = re.match(r'^(\S+(?:\s+\S+)*)\s*\{', line)
            if brace_open:
                block_name = brace_open.group(1).strip()
                block_stack.append(block_name)
                current_block_name = '::'.join(block_stack)
                config.blocks.append(current_block_name)

                if current_block_name not in config.sections:
                    config.sections[current_block_name] = {}
                continue

            # Handle closing block
            if line == '}' or line == '};':
                if block_stack:
                    block_stack.pop()
                current_block_name = '::'.join(block_stack) if block_stack else "global"
                continue

            # Handle inline block: "events { worker_connections 512; }"
            inline_match = re.match(r'^(\S+)\s*\{(.*)\}', line)
            if inline_match:
                block_name = inline_match.group(1)
                inner = inline_match.group(2).strip().rstrip(';')
                full_block = '::'.join(block_stack + [block_name])
                config.blocks.append(full_block)
                if inner:
                    key, _, value = inner.partition(' ')
                    config.flat_keys[f"{full_block}::{key}"] = value.strip()
                    if full_block not in config.sections:
                        config.sections[full_block] = {}
                    config.sections[full_block][key] = value.strip()
                continue

            # Parse directive: key value;
            line_clean = line.rstrip(';').strip()
            if not line_clean:
                continue

            parts = line_clean.split(None, 1)
            key = parts[0]
            value = parts[1] if len(parts) > 1 else "on"

            # Store with block context
            if block_stack:
                flat_key = f"{current_block_name}::{key}"
            else:
                flat_key = key

            config.flat_keys[flat_key] = value

            # Store in sections dict
            if current_block_name not in config.sections:
                config.sections[current_block_name] = {}
            config.sections[current_block_name][key] = value

        return config
