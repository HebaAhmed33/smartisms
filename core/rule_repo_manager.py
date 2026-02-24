"""
Module 9 — Rule Repository Manager
Loads, validates, indexes, and manages rule definition JSON files.
"""

import os
import json
import logging
from typing import List, Optional
from core.models import Rule, RuleCondition  # pyre-ignore


logger = logging.getLogger("smartisms.rule_repo")


class RuleRepoManager:
    """Manages the rule repository: loading, validation, filtering, indexing."""

    def __init__(self, rules_dir: str):
        """
        Initialize the rule repository.

        Args:
            rules_dir: Path to the root rules directory.
        """
        self.rules_dir = os.path.abspath(rules_dir)
        self._rules: List[Rule] = []
        self._index_by_id: dict = {}
        self._index_by_vendor: dict = {}
        self._index_by_standard: dict = {}
        self._cross_standard_map: list = []

    def load_all(self) -> List[Rule]:
        """
        Load all rules from the rules directory.

        Returns:
            List of validated Rule objects.
        """
        self._rules = []
        self._index_by_id = {}
        self._index_by_vendor = {}
        self._index_by_standard = {}

        if not os.path.isdir(self.rules_dir):
            logger.warning(f"Rules directory not found: {self.rules_dir}")
            return []

        # Walk through all JSON files
        for root, dirs, files in os.walk(self.rules_dir):
            for filename in sorted(files):
                if not filename.endswith('.json'):
                    continue
                if filename == 'cross_standard_map.json':
                    self._load_cross_standard_map(os.path.join(root, filename))
                    continue

                filepath = os.path.join(root, filename)
                self._load_rule_file(filepath)

        logger.info(f"Loaded {len(self._rules)} rules from {self.rules_dir}")
        return self._rules

    def _load_rule_file(self, filepath: str):
        """Load and validate a single rule JSON file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # File can contain a single rule (dict) or list of rules
            if isinstance(data, list):
                for rule_data in data:
                    self._parse_and_register(rule_data, filepath)
            elif isinstance(data, dict):
                self._parse_and_register(data, filepath)
            else:
                logger.error(f"Invalid rule file format: {filepath}")

        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error in {filepath}: {e}")
        except Exception as e:
            logger.error(f"Error loading {filepath}: {e}")

    def _parse_and_register(self, data: dict, filepath: str):
        """Parse a rule dictionary and register it."""
        try:
            rule = self._dict_to_rule(data)
            if self._validate_rule(rule, filepath):
                self._rules.append(rule)
                self._index_rule(rule)
        except (KeyError, TypeError) as e:
            logger.error(f"Invalid rule data in {filepath}: {e}")

    def _dict_to_rule(self, data: dict) -> Rule:
        """Convert a dictionary to a Rule object."""
        # Parse condition
        cond_data = data.get("condition", {})
        sub_conditions = []
        for sc in cond_data.get("sub_conditions", []):
            sub_conditions.append(sc)  # Keep as dict for lazy parsing

        condition = RuleCondition(
            type=cond_data.get("type", "key_value_match"),
            scope=cond_data.get("scope", "global"),
            key=cond_data.get("key", ""),
            operator=cond_data.get("operator", "equals"),
            expected_value=cond_data.get("expected_value", ""),
            sub_conditions=sub_conditions,
            logical_operator=cond_data.get("logical_operator", "AND"),
        )

        return Rule(
            rule_id=data["rule_id"],
            standard=data["standard"],
            control_id=data["control_id"],
            title=data.get("title", ""),
            description=data.get("description", ""),
            vendor=data["vendor"],
            category=data.get("category", "general"),
            severity=data.get("severity", "medium"),
            weight=int(data.get("weight", 3)),
            condition=condition,
            remediation_text=data.get("remediation_text", ""),
            remediation_command=data.get("remediation_command", ""),
            cross_standard_refs=data.get("cross_standard_refs", []),
            metadata=data.get("metadata", {}),
        )

    def _validate_rule(self, rule: Rule, filepath: str) -> bool:
        """Validate a rule has all required fields and valid values."""
        errors = []

        if not rule.rule_id:
            errors.append("Missing rule_id")
        if rule.rule_id in self._index_by_id:
            errors.append(f"Duplicate rule_id: {rule.rule_id}")
        if not rule.standard:
            errors.append("Missing standard")
        if not rule.vendor:
            errors.append("Missing vendor")
        if rule.severity not in ("high", "medium", "low"):
            errors.append(f"Invalid severity: {rule.severity}")
        if not (1 <= rule.weight <= 5):
            errors.append(f"Invalid weight: {rule.weight} (must be 1-5)")
        if rule.condition.type not in (
            "key_value_match", "block_exists", "regex_match", "negation", "compound"
        ):
            errors.append(f"Invalid condition type: {rule.condition.type}")

        if errors:
            logger.warning(f"Rule validation errors in {filepath}: {', '.join(errors)}")
            return False
        return True

    def _index_rule(self, rule: Rule):
        """Index a rule for fast lookup by ID, vendor, and standard."""
        self._index_by_id[rule.rule_id] = rule

        vendor = rule.vendor.lower()
        if vendor not in self._index_by_vendor:
            self._index_by_vendor[vendor] = []
        self._index_by_vendor[vendor].append(rule)

        standard = rule.standard.upper()
        if standard not in self._index_by_standard:
            self._index_by_standard[standard] = []
        self._index_by_standard[standard].append(rule)

    def _load_cross_standard_map(self, filepath: str):
        """Load the cross-standard mapping file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list):
                self._cross_standard_map = data
            elif isinstance(data, dict) and "mappings" in data:
                self._cross_standard_map = data["mappings"]
            logger.info(f"Loaded {len(self._cross_standard_map)} cross-standard mappings")
        except Exception as e:
            logger.error(f"Error loading cross-standard map: {e}")

    # --- Query methods ---

    def get_by_id(self, rule_id: str) -> Optional[Rule]:
        return self._index_by_id.get(rule_id)

    def get_by_vendor(self, vendor: str) -> List[Rule]:
        return self._index_by_vendor.get(vendor.lower(), [])

    def get_by_standard(self, standard: str) -> List[Rule]:
        return self._index_by_standard.get(standard.upper(), [])

    def get_all(self) -> List[Rule]:
        return self._rules.copy()

    def get_cross_standard_map(self) -> list:
        return self._cross_standard_map.copy()

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def vendor_count(self) -> int:
        return len(self._index_by_vendor)

    @property
    def standard_count(self) -> int:
        return len(self._index_by_standard)

    def get_stats(self) -> dict:
        """Return statistics about the loaded rules."""
        return {
            "total_rules": self.rule_count,
            "vendors": list(self._index_by_vendor.keys()),
            "standards": list(self._index_by_standard.keys()),
            "rules_per_vendor": {v: len(r) for v, r in self._index_by_vendor.items()},
            "rules_per_standard": {s: len(r) for s, r in self._index_by_standard.items()},
            "cross_standard_mappings": len(self._cross_standard_map),
        }
