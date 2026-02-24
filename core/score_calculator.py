"""
Module 7 — Compliance Score Calculator
Computes weighted compliance scores, risk levels,
and per-standard breakdowns.
"""

from typing import List, Tuple
from core.models import ClassifiedResult, ComplianceScore, StandardScore  # pyre-ignore


class ScoreCalculator:
    """Calculates compliance scores using weighted penalty formula."""

    # Risk level thresholds: (min_score, max_score, label, color)
    RISK_LEVELS: List[Tuple[int, int, str, str]] = [
        (90, 100, "Low Risk",      "#28a745"),
        (70,  89, "Medium Risk",   "#ffc107"),
        (50,  69, "High Risk",     "#fd7e14"),
        ( 0,  49, "Critical Risk", "#dc3545"),
    ]

    def calculate(self, classified_results: List[ClassifiedResult]) -> ComplianceScore:
        """
        Calculate overall and per-standard compliance scores.

        Formula:
            max_score = Σ(rule_weight × 5) for all rules
            actual_penalty = Σ(rule_weight × |penalty|) for all rules
            raw_score = max_score - actual_penalty
            percentage = (raw_score / max_score) × 100

        Args:
            classified_results: List of classified evaluation results.

        Returns:
            ComplianceScore with overall and per-standard breakdowns.
        """
        if not classified_results:
            return ComplianceScore(
                raw_score=0, max_score=0, percentage=100.0,
                risk_level="Low Risk", risk_color="#28a745",
                total_rules=0, passed=0, warned=0, failed=0, errored=0
            )

        # Overall calculation
        max_score = sum(cr.rule_result.rule.weight * 5 for cr in classified_results)
        actual_penalty = sum(cr.weighted_penalty for cr in classified_results)
        raw_score = max_score - actual_penalty

        if max_score == 0:
            percentage = 100.0
        else:
            percentage = float(int((raw_score / max_score) * 10000)) / 100.0

        # Clamp percentage
        percentage = max(0.0, min(100.0, percentage))

        # Count statuses
        passed = sum(1 for cr in classified_results if cr.status_label == "PASS")
        warned = sum(1 for cr in classified_results if cr.status_label == "WARNING")
        failed = sum(1 for cr in classified_results if cr.status_label == "FAIL")
        errored = sum(1 for cr in classified_results if cr.status_label in ("ERROR", "SKIPPED"))

        # Risk level
        risk_level, risk_color = self._get_risk_level(percentage)

        # Severity distribution
        severity_dist = {"high": 0, "medium": 0, "low": 0}
        for cr in classified_results:
            if cr.status_label in ("FAIL", "WARNING"):
                sev = cr.severity_label.lower()
                if sev in severity_dist:
                    severity_dist[sev] += 1

        # Per-standard breakdown
        per_standard = self._calculate_per_standard(classified_results)

        # Per-category breakdown
        per_category = self._calculate_per_category(classified_results)

        return ComplianceScore(
            raw_score=raw_score,
            max_score=max_score,
            percentage=percentage,
            risk_level=risk_level,
            risk_color=risk_color,
            total_rules=len(classified_results),
            passed=passed,
            warned=warned,
            failed=failed,
            errored=errored,
            per_standard=per_standard,
            per_category=per_category,
            severity_distribution=severity_dist
        )

    def _calculate_per_standard(self, results: List[ClassifiedResult]) -> dict:
        """Calculate compliance scores per standard."""
        # Group by standard
        by_standard = {}
        for cr in results:
            std = cr.rule_result.rule.standard
            if std not in by_standard:
                by_standard[std] = []
            by_standard[std].append(cr)

        per_standard = {}
        for standard, std_results in sorted(by_standard.items()):
            max_s = sum(cr.rule_result.rule.weight * 5 for cr in std_results)
            penalty_s = sum(cr.weighted_penalty for cr in std_results)
            raw_s = max_s - penalty_s
            pct_s = float(int((raw_s / max_s) * 10000)) / 100.0 if max_s > 0 else 100.0
            pct_s = max(0.0, min(100.0, pct_s))

            risk_level, risk_color = self._get_risk_level(pct_s)

            per_standard[standard] = StandardScore(
                standard=standard,
                raw_score=raw_s,
                max_score=max_s,
                percentage=pct_s,
                risk_level=risk_level,
                risk_color=risk_color,
                total_rules=len(std_results),
                passed=sum(1 for cr in std_results if cr.status_label == "PASS"),
                warned=sum(1 for cr in std_results if cr.status_label == "WARNING"),
                failed=sum(1 for cr in std_results if cr.status_label == "FAIL"),
                errored=sum(1 for cr in std_results if cr.status_label in ("ERROR", "SKIPPED")),
            )

        return per_standard

    def _calculate_per_category(self, results: List[ClassifiedResult]) -> dict:
        """Calculate compliance percentages per category."""
        by_category = {}
        for cr in results:
            cat = cr.rule_result.rule.category
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(cr)

        per_category = {}
        for category, cat_results in sorted(by_category.items()):
            max_c = sum(cr.rule_result.rule.weight * 5 for cr in cat_results)
            penalty_c = sum(cr.weighted_penalty for cr in cat_results)
            raw_c = max_c - penalty_c
            pct_c = float(int((raw_c / max_c) * 10000)) / 100.0 if max_c > 0 else 100.0
            per_category[category] = max(0.0, min(100.0, pct_c))

        return per_category

    def _get_risk_level(self, percentage: float) -> Tuple[str, str]:
        """Determine risk level and color from percentage."""
        for min_val, max_val, label, color in self.RISK_LEVELS:
            if min_val <= percentage <= max_val:
                return label, color
        return "Critical Risk", "#dc3545"
