"""
Firewall Configuration Parser
Parses iptables, nftables, and generic firewall rule configurations.
"""

import re
from core.models import ParsedConfig


class FirewallParser:
    """Parser for firewall configurations (iptables, nftables, generic)."""

    def parse(self, content: str) -> ParsedConfig:
        """Parse firewall config into structured format."""
        config = ParsedConfig(vendor="firewall")
        lines = content.split('\n')

        # Detect firewall type
        fw_type = self._detect_firewall_type(content)
        config.sections["type"] = {"firewall_type": fw_type}

        if fw_type == "iptables":
            self._parse_iptables(lines, config)
        elif fw_type == "nftables":
            self._parse_nftables(lines, config)
        else:
            self._parse_generic(lines, config)

        config.blocks.append(fw_type)
        return config

    def _detect_firewall_type(self, content: str) -> str:
        """Detect the firewall technology."""
        if '*filter' in content or content.strip().startswith(':INPUT') or 'iptables' in content:
            return "iptables"
        elif 'nft ' in content or 'table ' in content:
            return "nftables"
        elif 'config firewall' in content:
            return "fortigate"
        else:
            return "generic"

    def _parse_iptables(self, lines: list, config: ParsedConfig):
        """Parse iptables-save/restore format."""
        current_table = "filter"
        rule_count = 0

        for line in lines:
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            # Table declaration: *filter, *nat, *mangle
            if line.startswith('*'):
                current_table = line[1:]
                config.blocks.append(f"table:{current_table}")
                config.sections[f"table:{current_table}"] = {}
                continue

            # Chain policy: :INPUT ACCEPT [0:0]
            policy_match = re.match(r'^:(\w+)\s+(ACCEPT|DROP|REJECT)\s*', line)
            if policy_match:
                chain = policy_match.group(1)
                policy = policy_match.group(2)
                key = f"default_policy_{chain.lower()}"
                config.flat_keys[key] = policy
                if f"table:{current_table}" in config.sections:
                    config.sections[f"table:{current_table}"][key] = policy
                continue

            # Rule: -A INPUT -p tcp --dport 22 -j ACCEPT
            rule_match = re.match(r'^-A\s+(\w+)\s+(.*)', line)
            if rule_match:
                chain = rule_match.group(1)
                rule_body = rule_match.group(2)
                rule_count += 1

                rule_key = f"rule_{chain.lower()}_{rule_count}"
                config.flat_keys[rule_key] = rule_body

                # Extract specific rule attributes
                if '--dport' in rule_body:
                    port_match = re.search(r'--dport\s+(\S+)', rule_body)
                    if port_match:
                        config.flat_keys[f"{rule_key}_dport"] = port_match.group(1)

                if '-j' in rule_body:
                    target_match = re.search(r'-j\s+(\w+)', rule_body)
                    if target_match:
                        config.flat_keys[f"{rule_key}_target"] = target_match.group(1)

                continue

            # COMMIT
            if line == 'COMMIT':
                config.flat_keys[f"table_{current_table}_committed"] = "true"
                continue

            # Policy flags: -P INPUT DROP
            pflag_match = re.match(r'^-P\s+(\w+)\s+(ACCEPT|DROP|REJECT)', line)
            if pflag_match:
                chain = pflag_match.group(1)
                policy = pflag_match.group(2)
                config.flat_keys[f"default_policy_{chain.lower()}"] = policy

    def _parse_nftables(self, lines: list, config: ParsedConfig):
        """Parse nftables configuration."""
        block_stack = []

        for line in lines:
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            # Block opening
            if line.endswith('{'):
                block_name = line[:-1].strip()
                block_stack.append(block_name)
                full_block = '::'.join(block_stack)
                config.blocks.append(full_block)
                config.sections[full_block] = {}
                continue

            # Block closing
            if line == '}':
                if block_stack:
                    block_stack.pop()
                continue

            # Directives inside blocks
            line_clean = line.rstrip(';').strip()
            if line_clean:
                current_block = '::'.join(block_stack) if block_stack else "global"
                parts = line_clean.split(None, 1)
                key = parts[0]
                value = parts[1] if len(parts) > 1 else "true"

                config.flat_keys[f"{current_block}::{key}"] = value
                if current_block in config.sections:
                    config.sections[current_block][key] = value

    def _parse_generic(self, lines: list, config: ParsedConfig):
        """Parse generic firewall config as key-value pairs."""
        for line in lines:
            line = line.strip()

            if not line or line.startswith('#') or line.startswith('//'):
                continue

            parts = line.split(None, 1)
            key = parts[0]
            value = parts[1] if len(parts) > 1 else "true"

            config.flat_keys[key] = value
