"""
Module 6 — Severity Classifier
Assigns penalty values to rule results based on the penalty matrix
(result status × rule severity).
"""

from typing import List
from core.models import RuleResult, ClassifiedResult  # pyre-ignore


class SeverityClassifier:
    """Classifies rule results and assigns weighted penalties."""

    # Penalty matrix: (status, severity) -> penalty points
    PENALTY_MATRIX = {
        ("FAIL", "high"):      -5,
        ("FAIL", "medium"):    -3,
        ("FAIL", "low"):       -1,
        ("WARNING", "high"):   -3,
        ("WARNING", "medium"): -2,
        ("WARNING", "low"):    -1,
        ("PASS", "high"):       0,
        ("PASS", "medium"):     0,
        ("PASS", "low"):        0,
        ("ERROR", "high"):     -5,   # Errors treated as worst-case
        ("ERROR", "medium"):   -3,
        ("ERROR", "low"):      -1,
        ("SKIPPED", "high"):    0,   # Skipped rules don't penalize
        ("SKIPPED", "medium"):  0,
        ("SKIPPED", "low"):     0,
    }

    def classify(self, results: List[RuleResult]) -> List[ClassifiedResult]:
        """
        Apply penalty classification to all rule results.

        Args:
            results: List of raw rule evaluation results.

        Returns:
            List of ClassifiedResult with penalties applied.
        """
        classified = []

        for result in results:
            severity = result.rule.severity.lower()
            status = result.status.upper()
            weight = result.rule.weight

            # Look up penalty from matrix
            penalty = self.PENALTY_MATRIX.get(
                (status, severity),
                -3  # Default penalty for unknown combinations
            )

            # Apply weight multiplier
            weighted_penalty = abs(penalty) * weight

            classified.append(ClassifiedResult(
                rule_result=result,
                penalty=penalty,
                weighted_penalty=weighted_penalty,
                severity_label=severity,
                status_label=status
            ))

        return classified

    def get_penalty(self, status: str, severity: str) -> int:
        """Get the raw penalty for a status-severity combination."""
        return self.PENALTY_MATRIX.get(
            (status.upper(), severity.lower()),
            -3
        )
