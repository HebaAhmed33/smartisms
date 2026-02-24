"""
Module 2 — Vendor Detection
Analyzes file content and filename to determine the vendor/platform
of a configuration file using signature pattern matching.
"""

import re
import os
from typing import Any, Dict, List, Tuple
from core.models import ConfigInput, VendorInfo  # pyre-ignore


class VendorDetector:
    """Detects the vendor/platform of a configuration file."""

    # File extension to vendor mapping
    EXTENSION_MAP: Dict[str, str] = {
        '.junos': 'junos',
        '.htaccess': 'apache',
    }

    # Vendor signature patterns (checked against file content)
    VENDOR_SIGNATURES: Dict[str, Any] = {
        "cisco": {
            "patterns": [
                r"^hostname\s+\S+",
                r"^enable\s+(secret|password)\s+",
                r"^interface\s+(Ethernet|GigabitEthernet|FastEthernet|Loopback|Vlan|Serial)",
                r"^ip\s+route\s+",
                r"^ip\s+ssh\s+version",
                r"^line\s+(con|vty|aux)\s+",
                r"^router\s+(ospf|eigrp|bgp|rip)\s+",
                r"^access-list\s+\d+",
                r"^snmp-server\s+",
                r"^banner\s+(motd|login|exec)\s+",
                r"^service\s+(timestamps|password-encryption)",
                r"^no\s+ip\s+http\s+server",
                r"^crypto\s+(key|isakmp|ipsec)\s+",
                r"^ntp\s+server\s+",
            ],
            "weight": 1.0,
        },
        "junos": {
            "patterns": [
                r"^set\s+system\s+",
                r"^set\s+interfaces\s+",
                r"^set\s+firewall\s+",
                r"^set\s+protocols\s+",
                r"^set\s+security\s+",
                r"^set\s+routing-options\s+",
                r"^system\s*\{",
                r"^interfaces\s*\{",
                r"^protocols\s*\{",
                r"^security\s*\{",
            ],
            "weight": 1.0,
        },
        "nginx": {
            "patterns": [
                r"^\s*server\s*\{",
                r"^\s*http\s*\{",
                r"^\s*location\s+[/~]",
                r"^\s*upstream\s+\w+",
                r"^\s*listen\s+\d+",
                r"^\s*server_name\s+",
                r"^\s*ssl_certificate\s+",
                r"^\s*proxy_pass\s+",
                r"^\s*worker_processes\s+",
                r"^\s*error_log\s+",
                r"^\s*access_log\s+",
                r"^\s*add_header\s+",
                r"^\s*ssl_protocols\s+",
            ],
            "weight": 1.0,
        },
        "apache": {
            "patterns": [
                r"<VirtualHost\s+",
                r"ServerName\s+",
                r"DocumentRoot\s+",
                r"<Directory\s+",
                r"ServerRoot\s+",
                r"LoadModule\s+",
                r"ErrorLog\s+",
                r"CustomLog\s+",
                r"SSLEngine\s+",
                r"SSLCertificateFile\s+",
                r"ServerTokens\s+",
                r"ServerSignature\s+",
                r"TraceEnable\s+",
                r"Header\s+(set|append|unset)\s+",
            ],
            "weight": 1.0,
        },
        "linux": {
            "patterns": [
                r"^PermitRootLogin\s+",
                r"^PasswordAuthentication\s+",
                r"^Protocol\s+\d",
                r"^LogLevel\s+",
                r"^MaxAuthTries\s+",
                r"^X11Forwarding\s+",
                r"^AllowTcpForwarding\s+",
                r"^ClientAliveInterval\s+",
                r"^#.*sshd_config",
                r"^#.*sysctl\.conf",
                r"^net\.ipv4\.",
                r"^net\.ipv6\.",
                r"^kernel\.",
                r"^fs\.suid_dumpable",
                r"^PASS_MAX_DAYS\s+",
                r"^PASS_MIN_DAYS\s+",
                r"^PASS_MIN_LEN\s+",
                r"^UMASK\s+",
                r"^Ciphers\s+",
                r"^MACs\s+",
                r"^KexAlgorithms\s+",
            ],
            "weight": 1.0,
        },
        "firewall": {
            "patterns": [
                r"^config\s+firewall\s+policy",
                r"^iptables\s+-[A-Z]",
                r"^-A\s+(INPUT|OUTPUT|FORWARD)\s+",
                r"^nft\s+(add|list|delete)\s+",
                r"^set\s+policy\s+",
                r"^:INPUT\s+(ACCEPT|DROP)",
                r"^:OUTPUT\s+(ACCEPT|DROP)",
                r"^:FORWARD\s+(ACCEPT|DROP)",
                r"^\*filter",
                r"^COMMIT",
                r"^-P\s+(INPUT|OUTPUT|FORWARD)\s+",
            ],
            "weight": 1.0,
        },
    }

    # Filename hint patterns
    FILENAME_HINTS: Dict[str, List[str]] = {
        "cisco": [r"cisco", r"ios", r"router", r"switch"],
        "junos": [r"junos", r"juniper", r"srx", r"mx\d"],
        "nginx": [r"nginx"],
        "apache": [r"apache", r"httpd", r"htaccess"],
        "linux": [r"sshd", r"sysctl", r"passwd", r"login\.defs", r"audit"],
        "firewall": [r"firewall", r"iptables", r"nftables", r"pf\.conf"],
    }

    def detect(self, config_input: ConfigInput) -> VendorInfo:
        """
        Detect the vendor/platform of a configuration file.

        Uses a multi-pass approach:
        1. File extension check
        2. Filename hint matching
        3. Content signature pattern matching

        Args:
            config_input: The loaded configuration file.

        Returns:
            VendorInfo with detected vendor and confidence score.
        """
        scores: Dict[str, float] = {vendor: 0.0 for vendor in self.VENDOR_SIGNATURES}
        matched_patterns: List[str] = []
        detection_method: str = "signature"

        # Pass 1: Extension check
        _, ext = os.path.splitext(config_input.filename)
        if ext.lower() in self.EXTENSION_MAP:
            vendor = self.EXTENSION_MAP[ext.lower()]
            return VendorInfo(
                vendor_name=vendor,
                confidence=0.95,
                detection_method="extension",
                matched_patterns=[f"extension:{ext}"]
            )

        # Pass 2: Filename hints
        filename_lower = config_input.filename.lower()
        for vendor, hint_patterns in self.FILENAME_HINTS.items():
            for pattern in hint_patterns:
                if re.search(pattern, filename_lower, re.IGNORECASE):
                    scores[vendor] += 2.0
                    matched_patterns.append(f"filename:{pattern}")
                    detection_method = "filename+signature"

        # Pass 3: Content signature matching (first 200 lines)
        lines = config_input.content.split('\n')[:200]
        for vendor, sig_config in self.VENDOR_SIGNATURES.items():
            vendor_patterns = sig_config["patterns"]
            vendor_weight = sig_config["weight"]
            for pattern in vendor_patterns:
                for line in lines:
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue
                    if re.match(pattern, line_stripped, re.IGNORECASE | re.MULTILINE):
                        scores[vendor] += vendor_weight
                        matched_patterns.append(f"content:{pattern}")
                        break  # One match per pattern is enough

        # Find the best match
        best_vendor: str = max(scores, key=lambda k: scores[k])
        best_score: float = scores[best_vendor]
        best_patterns: Any = self.VENDOR_SIGNATURES[best_vendor]["patterns"]
        total_patterns: int = len(best_patterns)

        if best_score == 0:
            return VendorInfo(
                vendor_name="unknown",
                confidence=0.0,
                detection_method="none",
                matched_patterns=[]
            )

        # Normalize confidence (0.0-1.0)
        confidence: float = min(best_score / (total_patterns * 0.5), 1.0)

        # Filter matched patterns for the winning vendor
        filtered_patterns: List[str] = [
            p for p in matched_patterns
            if any(vp in p for vp in best_patterns)
            or "filename:" in p
        ]

        truncated: List[str] = [filtered_patterns[i] for i in range(min(10, len(filtered_patterns)))]
        return VendorInfo(
            vendor_name=best_vendor,
            confidence=float(int(confidence * 100)) / 100.0,
            detection_method=detection_method,
            matched_patterns=truncated
        )
