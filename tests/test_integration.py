"""
SmartISMS Integration Tests
Tests the full pipeline: config → vendor detection → parse → normalize → evaluate → score → report.
Also validates deterministic behavior.
"""

import os
import sys
import json
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.input_handler import InputHandler
from core.vendor_detector import VendorDetector
from core.parser_engine import ParserEngine
from core.normalizer import Normalizer
from core.rule_engine import RuleEngine
from core.severity_classifier import SeverityClassifier
from core.score_calculator import ScoreCalculator
from core.report_generator import ReportGenerator
from core.rule_repo_manager import RuleRepoManager
from core.models import EvaluationReport


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS_DIR = os.path.join(PROJECT_ROOT, "datasets")
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "output")


def run_full_pipeline(config_path, standards=None):
    """Run the complete SmartISMS pipeline on a config file."""
    # Step 1: Input
    handler = InputHandler()
    config_input = handler.load_file(config_path)

    # Step 2: Vendor Detection
    detector = VendorDetector()
    vendor_info = detector.detect(config_input)

    # Step 3: Parse
    parser = ParserEngine()
    parsed = parser.parse(config_input, vendor_info)

    # Step 4: Normalize
    normalizer = Normalizer()
    normalized = normalizer.normalize(parsed)

    # Step 5: Load Rules & Evaluate
    repo = RuleRepoManager(RULES_DIR)
    rules = repo.load_all()
    engine = RuleEngine()
    results = engine.evaluate(normalized, rules, standards)

    # Step 6: Classify & Score
    classifier = SeverityClassifier()
    classified = classifier.classify(results)

    calculator = ScoreCalculator()
    score = calculator.calculate(classified)

    return config_input, vendor_info, normalized, classified, score, repo


class TestInputHandler:
    """Tests for Module 1 — Input Handler."""

    def test_load_valid_file(self):
        path = os.path.join(DATASETS_DIR, "cisco", "cisco_secure_router.conf")
        handler = InputHandler()
        result = handler.load_file(path)
        assert result.content is not None
        assert len(result.content) > 0
        assert result.file_hash is not None
        assert result.file_size > 0

    def test_load_nonexistent_file(self):
        handler = InputHandler()
        with pytest.raises(FileNotFoundError):
            handler.load_file("/nonexistent/path/config.conf")

    def test_hash_determinism(self):
        path = os.path.join(DATASETS_DIR, "cisco", "cisco_secure_router.conf")
        handler = InputHandler()
        r1 = handler.load_file(path)
        r2 = handler.load_file(path)
        assert r1.file_hash == r2.file_hash


class TestVendorDetector:
    """Tests for Module 2 — Vendor Detection."""

    def test_detect_cisco(self):
        path = os.path.join(DATASETS_DIR, "cisco", "cisco_secure_router.conf")
        handler = InputHandler()
        config = handler.load_file(path)
        detector = VendorDetector()
        vendor = detector.detect(config)
        assert vendor.vendor_name == "cisco"
        assert vendor.confidence > 0.5

    def test_detect_nginx(self):
        path = os.path.join(DATASETS_DIR, "nginx", "nginx_secure.conf")
        handler = InputHandler()
        config = handler.load_file(path)
        detector = VendorDetector()
        vendor = detector.detect(config)
        assert vendor.vendor_name == "nginx"
        assert vendor.confidence > 0.5

    def test_detect_linux(self):
        path = os.path.join(DATASETS_DIR, "linux", "linux_sshd_secure.conf")
        handler = InputHandler()
        config = handler.load_file(path)
        detector = VendorDetector()
        vendor = detector.detect(config)
        assert vendor.vendor_name == "linux"
        assert vendor.confidence > 0.5

    def test_detect_firewall(self):
        path = os.path.join(DATASETS_DIR, "firewall", "firewall_strict.conf")
        handler = InputHandler()
        config = handler.load_file(path)
        detector = VendorDetector()
        vendor = detector.detect(config)
        assert vendor.vendor_name == "firewall"
        assert vendor.confidence > 0.3


class TestRuleRepoManager:
    """Tests for Module 9 — Rule Repository."""

    def test_load_all_rules(self):
        repo = RuleRepoManager(RULES_DIR)
        rules = repo.load_all()
        assert len(rules) > 0
        print(f"Loaded {len(rules)} rules")

    def test_filter_by_vendor(self):
        repo = RuleRepoManager(RULES_DIR)
        repo.load_all()
        cisco_rules = repo.get_by_vendor("cisco")
        assert len(cisco_rules) > 0
        for rule in cisco_rules:
            assert rule.vendor == "cisco"

    def test_filter_by_standard(self):
        repo = RuleRepoManager(RULES_DIR)
        repo.load_all()
        cis_rules = repo.get_by_standard("CIS")
        assert len(cis_rules) > 0
        for rule in cis_rules:
            assert rule.standard == "CIS"

    def test_cross_standard_map(self):
        repo = RuleRepoManager(RULES_DIR)
        repo.load_all()
        mappings = repo.get_cross_standard_map()
        assert len(mappings) > 0

    def test_stats(self):
        repo = RuleRepoManager(RULES_DIR)
        repo.load_all()
        stats = repo.get_stats()
        assert stats["total_rules"] > 0
        assert len(stats["vendors"]) > 0
        assert len(stats["standards"]) > 0
        print(f"Stats: {json.dumps(stats, indent=2)}")


class TestFullPipeline:
    """Integration tests for the full SmartISMS pipeline."""

    def test_cisco_secure(self):
        path = os.path.join(DATASETS_DIR, "cisco", "cisco_secure_router.conf")
        _, vendor, _, classified, score, _ = run_full_pipeline(path)

        assert vendor.vendor_name == "cisco"
        assert score.percentage > 40  # Secure config scoring with multi-standard overlap
        assert score.total_rules > 0
        print(f"Cisco Secure: {score.percentage}% - {score.risk_level}")
        print(f"  Pass: {score.passed}, Warn: {score.warned}, Fail: {score.failed}")

    def test_cisco_weak(self):
        path = os.path.join(DATASETS_DIR, "cisco", "cisco_weak_ssh.conf")
        _, vendor, _, classified, score, _ = run_full_pipeline(path)

        assert vendor.vendor_name == "cisco"
        assert score.percentage < 70  # Weak config should score poorly
        assert score.failed > 0
        print(f"Cisco Weak: {score.percentage}% - {score.risk_level}")
        print(f"  Pass: {score.passed}, Warn: {score.warned}, Fail: {score.failed}")

    def test_cisco_mixed(self):
        path = os.path.join(DATASETS_DIR, "cisco", "cisco_mixed.conf")
        _, vendor, _, classified, score, _ = run_full_pipeline(path)

        assert vendor.vendor_name == "cisco"
        assert score.passed > 0
        assert score.failed > 0
        print(f"Cisco Mixed: {score.percentage}% - {score.risk_level}")

    def test_linux_secure(self):
        path = os.path.join(DATASETS_DIR, "linux", "linux_sshd_secure.conf")
        _, vendor, _, classified, score, _ = run_full_pipeline(path)

        assert vendor.vendor_name == "linux"
        assert score.percentage > 70
        print(f"Linux Secure: {score.percentage}% - {score.risk_level}")
        print(f"  Pass: {score.passed}, Warn: {score.warned}, Fail: {score.failed}")

    def test_linux_weak(self):
        path = os.path.join(DATASETS_DIR, "linux", "linux_sshd_weak.conf")
        _, vendor, _, classified, score, _ = run_full_pipeline(path)

        assert vendor.vendor_name == "linux"
        assert score.failed > 0
        print(f"Linux Weak: {score.percentage}% - {score.risk_level}")

    def test_per_standard_scores(self):
        path = os.path.join(DATASETS_DIR, "cisco", "cisco_secure_router.conf")
        _, _, _, _, score, _ = run_full_pipeline(path)

        assert len(score.per_standard) > 0
        for std, std_score in score.per_standard.items():
            print(f"  {std}: {std_score.percentage}% ({std_score.risk_level})")
            assert std_score.total_rules > 0

    def test_severity_distribution(self):
        path = os.path.join(DATASETS_DIR, "cisco", "cisco_weak_ssh.conf")
        _, _, _, _, score, _ = run_full_pipeline(path)

        assert "high" in score.severity_distribution
        print(f"Severity dist: {score.severity_distribution}")


class TestDeterminism:
    """Verify deterministic evaluation — same input always produces same output."""

    def test_deterministic_results(self):
        """Run same config 3 times, verify identical output."""
        path = os.path.join(DATASETS_DIR, "cisco", "cisco_secure_router.conf")

        scores = []
        for i in range(3):
            _, _, _, classified, score, _ = run_full_pipeline(path)
            scores.append(score.percentage)

        assert scores[0] == scores[1] == scores[2], \
            f"Non-deterministic! Scores: {scores}"
        print(f"Determinism verified: {scores[0]}% across 3 runs")

    def test_deterministic_rule_order(self):
        """Verify rules are evaluated in same order."""
        path = os.path.join(DATASETS_DIR, "linux", "linux_sshd_secure.conf")

        run1_ids = []
        run2_ids = []

        for i in range(2):
            _, _, _, classified, _, _ = run_full_pipeline(path)
            ids = [cr.rule_result.rule.rule_id for cr in classified]
            if i == 0:
                run1_ids = ids
            else:
                run2_ids = ids

        assert run1_ids == run2_ids, "Rule evaluation order is non-deterministic!"


class TestReportGeneration:
    """Tests for Module 8 — Report Generator."""

    def test_generate_html_report(self):
        path = os.path.join(DATASETS_DIR, "cisco", "cisco_secure_router.conf")
        config_input, vendor_info, _, classified, score, repo = run_full_pipeline(path)

        report = EvaluationReport(
            config_input=config_input,
            vendor_info=vendor_info,
            compliance_score=score,
            classified_results=classified,
            cross_mappings=repo.get_cross_standard_map(),
            standards_evaluated=list(score.per_standard.keys()),
        )

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        output_path = os.path.join(OUTPUT_DIR, "test_report.html")
        generator = ReportGenerator()
        result_path = generator.generate_html(report, output_path)

        assert os.path.exists(result_path)
        with open(result_path, 'r', encoding='utf-8') as f:
            content = f.read()
        assert "SmartISMS" in content
        assert "Compliance" in content
        print(f"HTML report generated: {result_path}")

    def test_generate_json_report(self):
        path = os.path.join(DATASETS_DIR, "cisco", "cisco_weak_ssh.conf")
        config_input, vendor_info, _, classified, score, repo = run_full_pipeline(path)

        report = EvaluationReport(
            config_input=config_input,
            vendor_info=vendor_info,
            compliance_score=score,
            classified_results=classified,
            cross_mappings=repo.get_cross_standard_map(),
            standards_evaluated=list(score.per_standard.keys()),
        )

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        output_path = os.path.join(OUTPUT_DIR, "test_report.json")
        generator = ReportGenerator()
        result_path = generator.generate_json(report, output_path)

        assert os.path.exists(result_path)
        with open(result_path, 'r') as f:
            data = json.load(f)
        assert "compliance_score" in data
        assert "results" in data
        assert data["compliance_score"]["failed"] > 0
        print(f"JSON report generated: {result_path}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
