"""
SmartISMS Data Models
Core data structures used throughout the compliance engine.
"""

from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime


@dataclass
class ConfigInput:
    """Represents a loaded configuration file."""
    path: str
    content: str
    file_hash: str  # SHA-256
    file_size: int
    timestamp: str
    filename: str


@dataclass
class VendorInfo:
    """Result of vendor detection."""
    vendor_name: str        # cisco | junos | nginx | apache | linux | firewall
    confidence: float       # 0.0 - 1.0
    detection_method: str   # "extension" | "signature" | "heuristic"
    matched_patterns: list = field(default_factory=list)


@dataclass
class ParsedConfig:
    """Structured representation of a parsed config file."""
    vendor: str
    sections: dict = field(default_factory=dict)    # Hierarchical structure
    flat_keys: dict = field(default_factory=dict)   # Flattened key-value pairs
    blocks: list = field(default_factory=list)       # Named blocks found
    raw_lines: list = field(default_factory=list)    # Original lines for reference
    interfaces: dict = field(default_factory=dict)   # Interface-specific configs


@dataclass
class NormalizedConfig:
    """Vendor-agnostic canonical representation for rule evaluation."""
    vendor: str
    entries: dict = field(default_factory=dict)      # Canonical key -> value
    blocks: dict = field(default_factory=dict)       # Block name -> block content dict
    metadata: dict = field(default_factory=dict)     # File metadata

    def get(self, key: str, default=None):
        """Get a normalized config value by key (case-insensitive)."""
        key_lower = key.lower().strip()
        # Direct match
        if key_lower in self.entries:
            return self.entries[key_lower]
        # Try without extra spaces
        key_compact = " ".join(key_lower.split())
        if key_compact in self.entries:
            return self.entries[key_compact]
        return default

    def has_key(self, key: str) -> bool:
        """Check if a key exists in normalized config."""
        return self.get(key) is not None

    def has_block(self, block_name: str) -> bool:
        """Check if a named block exists."""
        block_lower = block_name.lower().strip()
        return block_lower in self.blocks

    def get_block(self, block_name: str) -> dict:
        """Get contents of a named block."""
        return self.blocks.get(block_name.lower().strip(), {})


@dataclass
class RuleCondition:
    """Defines the condition logic for a rule."""
    type: str               # key_value_match | block_exists | regex_match | negation | compound
    scope: str = "global"   # global | interface | block:<name>
    key: str = ""
    operator: str = "equals"  # equals | not_equals | contains | regex | gte | lte | exists | not_exists
    expected_value: Any = None
    sub_conditions: list = field(default_factory=list)   # For compound type
    logical_operator: str = "AND"                        # AND | OR for compound


@dataclass
class Rule:
    """Complete rule definition for compliance evaluation."""
    rule_id: str
    standard: str           # ISO27001 | PCI-DSS | HIPAA | CIS
    control_id: str
    title: str
    description: str
    vendor: str             # cisco | junos | nginx | apache | linux | firewall
    category: str           # access_control | encryption | logging | network | authentication | ...
    severity: str           # high | medium | low
    weight: int             # 1-5
    condition: RuleCondition
    remediation_text: str
    remediation_command: str
    cross_standard_refs: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class RuleResult:
    """Result of evaluating a single rule."""
    rule: Rule
    status: str             # PASS | FAIL | WARNING | ERROR | SKIPPED
    found_value: Any = None
    expected_value: Any = None
    reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ClassifiedResult:
    """Rule result with penalty classification applied."""
    rule_result: RuleResult
    penalty: int = 0
    weighted_penalty: float = 0.0
    severity_label: str = ""
    status_label: str = ""


@dataclass
class StandardScore:
    """Compliance score for a single standard."""
    standard: str
    raw_score: float
    max_score: float
    percentage: float
    risk_level: str
    risk_color: str
    total_rules: int
    passed: int
    warned: int
    failed: int
    errored: int


@dataclass
class ComplianceScore:
    """Overall compliance scoring result."""
    raw_score: float
    max_score: float
    percentage: float
    risk_level: str
    risk_color: str
    total_rules: int
    passed: int
    warned: int
    failed: int
    errored: int
    per_standard: dict = field(default_factory=dict)  # standard -> StandardScore
    per_category: dict = field(default_factory=dict)   # category -> percentage
    severity_distribution: dict = field(default_factory=dict)  # severity -> count


@dataclass
class CrossStandardMapping:
    """Maps equivalent controls across different standards."""
    mapping_id: str
    canonical_control: str
    description: str
    mappings: list = field(default_factory=list)  # list of {standard, control_id, section}


@dataclass
class EvaluationReport:
    """Complete evaluation report data."""
    config_input: ConfigInput
    vendor_info: VendorInfo
    compliance_score: ComplianceScore
    classified_results: list       # list[ClassifiedResult]
    cross_mappings: list           # list[CrossStandardMapping]
    standards_evaluated: list
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    engine_version: str = "1.0.0"
