"""
Module 5 — Rule Engine Core
Loads rules, matches them against normalized config,
produces deterministic evaluation results.
"""

import re
import logging
from typing import List, Optional
from core.models import Rule, RuleCondition, RuleResult, NormalizedConfig  # pyre-ignore


logger = logging.getLogger("smartisms.rule_engine")


class RuleEngine:
    """
    Core rule evaluation engine.
    Deterministic: same input + same rules = identical output.
    """

    def evaluate(
        self,
        config: NormalizedConfig,
        rules: List[Rule],
        standards: Optional[List[str]] = None
    ) -> List[RuleResult]:
        """
        Evaluate all applicable rules against a normalized config.

        Args:
            config: Normalized configuration to evaluate.
            rules: List of all loaded rules.
            standards: Optional filter — only evaluate rules for these standards.

        Returns:
            Sorted list of RuleResult objects (sorted by rule_id for determinism).
        """
        # Filter rules by vendor and optionally by standard
        applicable_rules = self._filter_rules(rules, config.vendor, standards)

        # Sort by rule_id for deterministic ordering
        applicable_rules.sort(key=lambda r: r.rule_id)

        results = []
        for rule in applicable_rules:
            result = self._evaluate_single_rule(rule, config)
            results.append(result)

        return results

    def _filter_rules(
        self,
        rules: List[Rule],
        vendor: str,
        standards: Optional[List[str]]
    ) -> List[Rule]:
        """Filter rules by vendor and optional standard list."""
        std_filter: List[str] = []
        if standards is not None:
            std_filter = [s.upper() for s in standards]
        filtered: List[Rule] = []
        for rule in rules:
            # Vendor must match
            if rule.vendor.lower() != vendor.lower():
                continue
            # Standard filter (if provided)
            if len(std_filter) > 0:
                if rule.standard.upper() not in std_filter:
                    continue
            filtered.append(rule)
        return filtered

    def _evaluate_single_rule(self, rule: Rule, config: NormalizedConfig) -> RuleResult:
        """
        Evaluate a single rule against the normalized config.

        Returns:
            RuleResult with PASS, FAIL, WARNING, or ERROR status.
        """
        try:
            return self._evaluate_condition(rule, rule.condition, config)
        except Exception as e:
            logger.error(f"Error evaluating rule {rule.rule_id}: {e}")
            return RuleResult(
                rule=rule,
                status="ERROR",
                reason=f"Evaluation error: {str(e)}"
            )

    def _evaluate_condition(
        self,
        rule: Rule,
        condition: RuleCondition,
        config: NormalizedConfig
    ) -> RuleResult:
        """Evaluate a single condition against the config."""

        if condition.type == "key_value_match":
            return self._eval_key_value(rule, condition, config)
        elif condition.type == "block_exists":
            return self._eval_block_exists(rule, condition, config)
        elif condition.type == "regex_match":
            return self._eval_regex(rule, condition, config)
        elif condition.type == "negation":
            return self._eval_negation(rule, condition, config)
        elif condition.type == "compound":
            return self._eval_compound(rule, condition, config)
        else:
            return RuleResult(
                rule=rule,
                status="ERROR",
                reason=f"Unknown condition type: {condition.type}"
            )

    def _eval_key_value(
        self, rule: Rule, cond: RuleCondition, config: NormalizedConfig
    ) -> RuleResult:
        """Evaluate key_value_match condition."""
        key = cond.key.lower().strip()
        actual = config.get(key)

        if actual is None:
            return RuleResult(
                rule=rule,
                status="FAIL",
                found_value=None,
                expected_value=cond.expected_value,
                reason=f"Key '{cond.key}' not found in configuration"
            )

        expected = str(cond.expected_value).lower().strip()
        actual_str = str(actual).lower().strip()

        match = self._compare(actual_str, cond.operator, expected)

        return RuleResult(
            rule=rule,
            status="PASS" if match else "FAIL",
            found_value=actual,
            expected_value=cond.expected_value,
            reason="" if match else f"Expected {cond.operator} '{cond.expected_value}', found '{actual}'"
        )

    def _eval_block_exists(
        self, rule: Rule, cond: RuleCondition, config: NormalizedConfig
    ) -> RuleResult:
        """Evaluate block_exists condition."""
        block_name = cond.key.lower().strip()
        exists = config.has_block(block_name)

        if cond.operator == "exists":
            passed = exists
        elif cond.operator == "not_exists":
            passed = not exists
        else:
            passed = exists  # Default: check existence

        return RuleResult(
            rule=rule,
            status="PASS" if passed else "FAIL",
            found_value="exists" if exists else "not found",
            expected_value=cond.operator,
            reason="" if passed else f"Block '{cond.key}' {'not found' if cond.operator == 'exists' else 'should not exist'}"
        )

    def _eval_regex(
        self, rule: Rule, cond: RuleCondition, config: NormalizedConfig
    ) -> RuleResult:
        """Evaluate regex_match condition."""
        actual = config.get(cond.key.lower())

        if actual is None:
            return RuleResult(
                rule=rule,
                status="FAIL",
                found_value=None,
                expected_value=f"regex:{cond.expected_value}",
                reason=f"Key '{cond.key}' not found in configuration"
            )

        try:
            pattern = re.compile(str(cond.expected_value), re.IGNORECASE)
            match = pattern.search(str(actual))
        except re.error as e:
            return RuleResult(
                rule=rule,
                status="ERROR",
                reason=f"Invalid regex pattern: {e}"
            )

        return RuleResult(
            rule=rule,
            status="PASS" if match else "FAIL",
            found_value=actual,
            expected_value=f"regex:{cond.expected_value}",
            reason="" if match else f"Value '{actual}' does not match pattern '{cond.expected_value}'"
        )

    def _eval_negation(
        self, rule: Rule, cond: RuleCondition, config: NormalizedConfig
    ) -> RuleResult:
        """Evaluate negation condition (key must NOT exist or must have negated form)."""
        key = cond.key.lower().strip()

        # Check if the 'no <key>' form exists
        negated_key = f"no {key}"
        negated_exists = config.has_key(negated_key)

        # Check if the positive key exists
        positive_exists = config.has_key(key)

        # The negation rule passes if:
        #  - The negated form "no <key>" exists, OR
        #  - The positive key does NOT exist
        if cond.operator == "not_exists":
            passed = not positive_exists
        else:
            passed = negated_exists or not positive_exists

        return RuleResult(
            rule=rule,
            status="PASS" if passed else "FAIL",
            found_value="negated" if negated_exists else ("present" if positive_exists else "absent"),
            expected_value="negated/absent",
            reason="" if passed else f"Key '{key}' should be negated or absent"
        )

    def _eval_compound(
        self, rule: Rule, cond: RuleCondition, config: NormalizedConfig
    ) -> RuleResult:
        """Evaluate compound condition (AND/OR of sub-conditions)."""
        if not cond.sub_conditions:
            return RuleResult(
                rule=rule,
                status="ERROR",
                reason="Compound condition has no sub-conditions"
            )

        sub_results = []
        for sub_cond_data in cond.sub_conditions:
            if isinstance(sub_cond_data, RuleCondition):
                sub_cond = sub_cond_data
            else:
                sub_cond = RuleCondition(**sub_cond_data)
            sub_result = self._evaluate_condition(rule, sub_cond, config)
            sub_results.append(sub_result)

        statuses = [r.status for r in sub_results]

        if cond.logical_operator.upper() == "AND":
            if all(s == "PASS" for s in statuses):
                status = "PASS"
            elif any(s == "FAIL" for s in statuses):
                status = "FAIL"
            else:
                status = "WARNING"
        else:  # OR
            if any(s == "PASS" for s in statuses):
                status = "PASS"
            elif all(s == "FAIL" for s in statuses):
                status = "FAIL"
            else:
                status = "WARNING"

        # Collect sub-result details
        details = [
            f"[{r.status}] {r.rule.condition.key if hasattr(r, 'rule') else 'sub'}: {r.reason}"
            for r in sub_results
        ]

        return RuleResult(
            rule=rule,
            status=status,
            reason=f"Compound ({cond.logical_operator}): " + "; ".join(details)
        )

    def _compare(self, actual: str, operator: str, expected: str) -> bool:
        """
        Compare actual vs expected value using the given operator.
        All comparisons are case-insensitive.
        """
        if operator == "equals":
            return actual == expected
        elif operator == "not_equals":
            return actual != expected
        elif operator == "contains":
            return expected in actual
        elif operator == "not_contains":
            return expected not in actual
        elif operator == "gte":
            try:
                return float(actual) >= float(expected)
            except ValueError:
                return False
        elif operator == "lte":
            try:
                return float(actual) <= float(expected)
            except ValueError:
                return False
        elif operator == "gt":
            try:
                return float(actual) > float(expected)
            except ValueError:
                return False
        elif operator == "lt":
            try:
                return float(actual) < float(expected)
            except ValueError:
                return False
        elif operator == "exists":
            return actual is not None
        elif operator == "not_exists":
            return actual is None
        elif operator == "regex":
            try:
                return bool(re.search(expected, actual, re.IGNORECASE))
            except re.error:
                return False
        else:
            logger.warning(f"Unknown operator '{operator}', defaulting to equals")
            return actual == expected
