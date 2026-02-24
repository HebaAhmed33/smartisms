"""
Module 3 — Parser Engine
Routes configuration files to the appropriate vendor parser
and returns a structured ParsedConfig object.
"""

from core.models import ConfigInput, VendorInfo, ParsedConfig  # pyre-ignore
from parsers.cisco_parser import CiscoParser  # pyre-ignore
from parsers.junos_parser import JunOSParser  # pyre-ignore
from parsers.nginx_parser import NginxParser  # pyre-ignore
from parsers.apache_parser import ApacheParser  # pyre-ignore
from parsers.linux_parser import LinuxParser  # pyre-ignore
from parsers.firewall_parser import FirewallParser  # pyre-ignore


class ParserEngine:
    """Routes config files to the correct vendor parser."""

    def __init__(self):
        self._parsers = {
            "cisco": CiscoParser(),
            "junos": JunOSParser(),
            "nginx": NginxParser(),
            "apache": ApacheParser(),
            "linux": LinuxParser(),
            "firewall": FirewallParser(),
        }

    def parse(self, config_input: ConfigInput, vendor_info: VendorInfo) -> ParsedConfig:
        """
        Parse a configuration file using the detected vendor parser.

        Args:
            config_input: The loaded configuration file.
            vendor_info: Detected vendor information.

        Returns:
            ParsedConfig with structured representation.

        Raises:
            ValueError: If vendor is unsupported or unknown.
        """
        vendor = vendor_info.vendor_name.lower()

        if vendor == "unknown":
            raise ValueError(
                f"Cannot parse file '{config_input.filename}': unknown vendor. "
                f"Vendor detection confidence was {vendor_info.confidence}"
            )

        if vendor not in self._parsers:
            raise ValueError(
                f"No parser available for vendor '{vendor}'. "
                f"Supported vendors: {list(self._parsers.keys())}"
            )

        parser = self._parsers[vendor]
        parsed = parser.parse(config_input.content)
        parsed.vendor = vendor
        parsed.raw_lines = config_input.content.split('\n')

        return parsed

    @property
    def supported_vendors(self) -> list:
        return list(self._parsers.keys())
