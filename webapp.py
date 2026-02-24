"""
SmartISMS Web Interface
Flask-based web UI for compliance evaluation.
Run with: python webapp.py
Open: http://localhost:5000
"""

import os
import sys
import json
import tempfile
from flask import Flask, request, jsonify, send_from_directory

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.input_handler import InputHandler
from core.vendor_detector import VendorDetector
from core.parser_engine import ParserEngine
from core.normalizer import Normalizer
from core.rule_engine import RuleEngine
from core.severity_classifier import SeverityClassifier
from core.score_calculator import ScoreCalculator
from core.rule_repo_manager import RuleRepoManager

app = Flask(__name__, static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max upload


@app.route('/')
def index():
    """Serve the main page."""
    return send_from_directory('static', 'index.html')


@app.route('/api/standards', methods=['GET'])
def get_standards():
    """Return available standards."""
    rules_dir = os.path.join(os.path.dirname(__file__), 'rules')
    repo = RuleRepoManager(rules_dir)
    rules = repo.load_all()
    standards = sorted(set(r.standard for r in rules))
    return jsonify({"standards": standards})


@app.route('/api/evaluate', methods=['POST'])
def evaluate():
    """Evaluate an uploaded config file."""
    try:
        # Get uploaded file
        if 'config_file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files['config_file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        # Get selected standards
        standards_str = request.form.get('standards', '')
        standards = [s.strip() for s in standards_str.split(',') if s.strip()] or None

        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False, encoding='utf-8') as tmp:
            content = file.read().decode('utf-8', errors='replace')
            tmp.write(content)
            tmp_path = tmp.name

        try:
            # Run the SmartISMS pipeline
            result = run_pipeline(tmp_path, file.filename, standards)
            return jsonify(result)
        finally:
            # Cleanup temp file
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def run_pipeline(file_path, original_filename, standards=None):
    """Run the full SmartISMS evaluation pipeline and return JSON results."""

    # Step 1: Load file
    handler = InputHandler()
    config_input = handler.load_file(file_path)
    config_input.filename = original_filename  # Use original filename for detection

    # Step 2: Detect vendor
    detector = VendorDetector()
    vendor_info = detector.detect(config_input)

    # Step 3: Parse
    parser = ParserEngine()
    parsed = parser.parse(config_input, vendor_info)

    # Step 4: Normalize
    normalizer = Normalizer()
    normalized = normalizer.normalize(parsed)

    # Step 5: Load rules and evaluate
    rules_dir = os.path.join(os.path.dirname(__file__), 'rules')
    repo = RuleRepoManager(rules_dir)
    all_rules = repo.load_all()

    engine = RuleEngine()
    rule_results = engine.evaluate(normalized, all_rules, standards)

    # Step 6: Classify and score
    classifier = SeverityClassifier()
    classified = classifier.classify(rule_results)

    calculator = ScoreCalculator()
    score = calculator.calculate(classified)

    # Step 7: Build response
    rules_detail = []
    for cr in classified:
        rules_detail.append({
            "rule_id": cr.rule_result.rule.rule_id,
            "title": cr.rule_result.rule.title,
            "standard": cr.rule_result.rule.standard,
            "category": cr.rule_result.rule.category,
            "severity": cr.severity_label,
            "status": cr.status_label,
            "expected": cr.rule_result.expected_value,
            "found": cr.rule_result.found_value,
            "reason": cr.rule_result.reason,
            "weight": cr.rule_result.rule.weight,
        })

    # Per-standard breakdown
    per_standard = {}
    for std_name, std_score in score.per_standard.items():
        per_standard[std_name] = {
            "percentage": std_score.percentage,
            "risk_level": std_score.risk_level,
            "risk_color": std_score.risk_color,
            "passed": std_score.passed,
            "warned": std_score.warned,
            "failed": std_score.failed,
            "total": std_score.total_rules,
        }

    return {
        "filename": original_filename,
        "file_size": config_input.file_size,
        "file_hash": config_input.file_hash[:16] + "...",
        "vendor": vendor_info.vendor_name.upper(),
        "vendor_confidence": vendor_info.confidence,
        "total_rules_evaluated": len(classified),
        "score": {
            "percentage": score.percentage,
            "risk_level": score.risk_level,
            "risk_color": score.risk_color,
            "passed": score.passed,
            "warned": score.warned,
            "failed": score.failed,
            "errored": score.errored,
        },
        "severity_distribution": score.severity_distribution,
        "per_standard": per_standard,
        "per_category": score.per_category,
        "rules": rules_detail,
    }


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("  SmartISMS Web Interface")
    print("  Open: http://localhost:5000")
    print("=" * 60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
