"""
Module 4 — Normalizer
Transforms vendor-specific parsed configs into a canonical schema
for vendor-agnostic rule evaluation.
"""

from core.models import ParsedConfig, NormalizedConfig  # pyre-ignore


class Normalizer:
    """Normalizes parsed configs into canonical form for rule evaluation."""

    def normalize(self, parsed: ParsedConfig) -> NormalizedConfig:
        """
        Transform a vendor-specific ParsedConfig into a NormalizedConfig.

        Normalization steps:
        1. Lowercase all keys
        2. Strip extra whitespace
        3. Resolve common abbreviations
        4. Flatten hierarchical blocks into dot-separated keys
        5. Build block lookup dict

        Args:
            parsed: Vendor-specific parsed configuration.

        Returns:
            NormalizedConfig with canonical entries and blocks.
        """
        normalized = NormalizedConfig(
            vendor=parsed.vendor,
            metadata={"raw_line_count": len(parsed.raw_lines)}
        )

        # Normalize flat keys
        for key, value in parsed.flat_keys.items():
            norm_key = self._normalize_key(key)
            norm_value = self._normalize_value(value)
            normalized.entries[norm_key] = norm_value

        # Normalize sections into blocks
        for section_name, section_data in parsed.sections.items():
            norm_block_name = self._normalize_key(section_name)
            if isinstance(section_data, dict):
                norm_block = {}
                for k, v in section_data.items():
                    norm_k = self._normalize_key(k)
                    norm_v = self._normalize_value(v)
                    norm_block[norm_k] = norm_v

                    # Also add flattened block.key entry
                    flat_key = f"{norm_block_name}::{norm_k}"
                    normalized.entries[flat_key] = norm_v

                normalized.blocks[norm_block_name] = norm_block

        # Normalize interface configs
        if parsed.interfaces:
            for iface_name, iface_data in parsed.interfaces.items():
                norm_iface = self._normalize_key(f"interface {iface_name}")
                norm_block = {}
                for k, v in iface_data.items():
                    norm_k = self._normalize_key(k)
                    norm_v = self._normalize_value(v)
                    norm_block[norm_k] = norm_v
                    normalized.entries[f"{norm_iface}::{norm_k}"] = norm_v
                normalized.blocks[norm_iface] = norm_block

        return normalized

    def _normalize_key(self, key: str) -> str:
        """Normalize a configuration key."""
        if not key:
            return key

        # Lowercase
        key = key.lower().strip()

        # Compact multiple spaces
        key = ' '.join(key.split())

        # Apply common abbreviations
        key = self._resolve_abbreviations(key)

        return key

    def _normalize_value(self, value) -> str:
        """Normalize a configuration value."""
        if value is None:
            return ""
        if isinstance(value, dict):
            return str(value)
        if isinstance(value, bool):
            return "yes" if value else "no"

        value = str(value).strip()

        # Normalize boolean-like values
        value_lower = value.lower()
        bool_true = {"yes", "on", "true", "enable", "enabled", "1"}
        bool_false = {"no", "off", "false", "disable", "disabled", "0"}

        if value_lower in bool_true:
            return "yes"
        elif value_lower in bool_false:
            return "no"

        # Remove surrounding quotes
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            value = str(value)[1:-1]  # pyre-ignore

        return value

    def _resolve_abbreviations(self, key: str) -> str:
        """Resolve common vendor abbreviations to canonical forms."""
        abbreviations = {
            "gig": "gigabitethernet",
            "fa": "fastethernet",
            "eth": "ethernet",
            "lo": "loopback",
            "po": "port-channel",
            "gi": "gigabitethernet",
            "te": "tengigeethernet",
        }

        for abbr, full in abbreviations.items():
            # Only replace at word boundaries within interface names
            if f"interface {abbr}" in key:
                key = key.replace(f"interface {abbr}", f"interface {full}", 1)

        return key
