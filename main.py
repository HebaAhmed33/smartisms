#!/usr/bin/env python3
"""
SmartISMS — Intelligent Information Security Management System
CLI Entry Point

A rule-based expert system that evaluates configuration files against
security standards: ISO 27001, PCI-DSS, HIPAA, CIS Benchmarks.

Usage:
    python main.py --config <file> [--standards ISO27001,PCI-DSS] [--output report.html]
    python main.py --config-dir <directory> [--standards CIS] [--format html|json]
"""

import argparse
import os
import sys
import json
import logging
from datetime import datetime

from core.input_handler import InputHandler  # pyre-ignore
from core.vendor_detector import VendorDetector  # pyre-ignore
from core.parser_engine import ParserEngine  # pyre-ignore
from core.normalizer import Normalizer  # pyre-ignore
from core.rule_engine import RuleEngine  # pyre-ignore
from core.severity_classifier import SeverityClassifier  # pyre-ignore
from core.score_calculator import ScoreCalculator  # pyre-ignore
from core.report_generator import ReportGenerator  # pyre-ignore
from core.rule_repo_manager import RuleRepoManager  # pyre-ignore
from core.models import EvaluationReport  # pyre-ignore


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S"
    )


def get_project_root() -> str:
    """Get the project root directory."""
    return os.path.dirname(os.path.abspath(__file__))


def run_evaluation(
    config_path: str,
    standards: list = None,  # pyre-ignore
    output_path: str = None,  # pyre-ignore
    output_format: str = "html",
    rules_dir: str = None,  # pyre-ignore
    verbose: bool = False
) -> EvaluationReport:
    """
    Run the full SmartISMS evaluation pipeline.

    Pipeline: Input → Detect → Parse → Normalize → Evaluate → Classify → Score → Report

    Args:
        config_path: Path to the configuration file.
        standards: List of standards to evaluate (None = all).
        output_path: Path for the output report.
        output_format: "html" or "json".
        rules_dir: Path to rules directory.
        verbose: Enable verbose logging.
    """
    logger = logging.getLogger("smartisms")
    project_root = get_project_root()

    # Defaults
    if not rules_dir:
        rules_dir = os.path.join(project_root, "rules")
    if not output_path:
        os.makedirs(os.path.join(project_root, "output"), exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.splitext(os.path.basename(config_path))[0]
        output_path = os.path.join(
            project_root, "output",
            f"report_{filename}_{timestamp}.{output_format}"
        )

    print(f"\n{'='*60}")
    print(f"  [*] SmartISMS -- Compliance Evaluation Engine")
    print(f"{'='*60}\n")

    # -- Step 1: Input Handler --
    logger.info("Step 1/7: Loading configuration file...")
    input_handler = InputHandler()
    config_input = input_handler.load_file(config_path)
    print(f"  [FILE] {config_input.filename}")
    print(f"  [SIZE] {config_input.file_size} bytes")
    print(f"  [HASH] SHA-256: {config_input.file_hash[:32]}...")

    # -- Step 2: Vendor Detection --
    logger.info("Step 2/7: Detecting vendor...")
    vendor_detector = VendorDetector()
    vendor_info = vendor_detector.detect(config_input)
    print(f"  [VENDOR] {vendor_info.vendor_name.upper()} (confidence: {vendor_info.confidence})")

    if vendor_info.vendor_name == "unknown":
        print("  [ERROR] Could not detect vendor. Aborting.")
        sys.exit(1)

    # -- Step 3: Parse --
    logger.info("Step 3/7: Parsing configuration...")
    parser_engine = ParserEngine()
    parsed_config = parser_engine.parse(config_input, vendor_info)
    print(f"  [PARSE] {len(parsed_config.flat_keys)} keys, {len(parsed_config.blocks)} blocks")

    # -- Step 4: Normalize --
    logger.info("Step 4/7: Normalizing configuration...")
    normalizer = Normalizer()
    normalized = normalizer.normalize(parsed_config)
    print(f"  [NORM]  {len(normalized.entries)} entries, {len(normalized.blocks)} blocks")

    # -- Step 5: Load Rules & Evaluate --
    logger.info("Step 5/7: Loading rules and evaluating...")
    rule_repo = RuleRepoManager(rules_dir)
    all_rules = rule_repo.load_all()
    stats = rule_repo.get_stats()
    print(f"  [RULES] {stats['total_rules']} rules loaded")
    for std, count in stats.get('rules_per_standard', {}).items():
        print(f"          {std}: {count} rules")

    rule_engine = RuleEngine()
    results = rule_engine.evaluate(normalized, all_rules, standards)
    print(f"  [EVAL]  {len(results)} rules applied")

    # -- Step 6: Classify & Score --
    logger.info("Step 6/7: Classifying and scoring...")
    classifier = SeverityClassifier()
    classified = classifier.classify(results)

    calculator = ScoreCalculator()
    compliance_score = calculator.calculate(classified)

    print(f"\n  {'-'*40}")
    print(f"  COMPLIANCE SCORE: {compliance_score.percentage}%")
    print(f"  RISK LEVEL:       {compliance_score.risk_level}")
    print(f"  Passed: {compliance_score.passed} | Warnings: {compliance_score.warned} | Failed: {compliance_score.failed}")
    print(f"  {'-'*40}\n")

    # -- Step 7: Generate Report --
    logger.info("Step 7/7: Generating report...")

    # Build report object
    cross_mappings = rule_repo.get_cross_standard_map()
    evaluated_standards = standards if standards else list(stats.get('rules_per_standard', {}).keys())

    report = EvaluationReport(
        config_input=config_input,
        vendor_info=vendor_info,
        compliance_score=compliance_score,
        classified_results=classified,
        cross_mappings=cross_mappings,
        standards_evaluated=evaluated_standards,
    )

    # Generate output
    report_gen = ReportGenerator()
    if output_format == "json":
        report_gen.generate_json(report, output_path)
    else:
        report_gen.generate_html(report, output_path)

    print(f"  [REPORT] {output_path}")
    print(f"\n{'='*60}")
    print(f"  [OK] Evaluation complete!")
    print(f"{'='*60}\n")

    return report


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="smartisms",
        description="SmartISMS — Intelligent Information Security Management System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --config datasets/cisco/cisco_secure_router.conf
  python main.py --config myconfig.conf --standards ISO27001,PCI-DSS
  python main.py --config myconfig.conf --output report.html --format html
  python main.py --config myconfig.conf --format json --verbose
        """
    )

    parser.add_argument(
        "--config", "-c",
        required=True,
        help="Path to the configuration file to evaluate"
    )
    parser.add_argument(
        "--standards", "-s",
        default=None,
        help="Comma-separated list of standards to evaluate (default: all). "
             "Options: ISO27001, PCI-DSS, HIPAA, CIS"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output file path (default: output/report_<name>_<timestamp>.<format>)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["html", "json"],
        default="html",
        help="Output format (default: html)"
    )
    parser.add_argument(
        "--rules-dir",
        default=None,
        help="Path to rules directory (default: rules/)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging"
    )

    args = parser.parse_args()

    setup_logging(args.verbose)

    # Parse standards list
    standards = None
    if args.standards:
        standards = [s.strip() for s in args.standards.split(",")]

    try:
        run_evaluation(
            config_path=args.config,
            standards=standards,  # pyre-ignore
            output_path=args.output,
            output_format=args.format,
            rules_dir=args.rules_dir,
            verbose=args.verbose,
        )
    except FileNotFoundError as e:
        print(f"\n  [ERROR] File Error: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"\n  [ERROR] Validation Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n  [ERROR] Unexpected Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
