"""
Module 8 — Report Generator
Renders professional HTML/PDF compliance reports using Jinja2 templates.
"""

import os
import json
from datetime import datetime
from typing import List, Optional
from core.models import (  # pyre-ignore
    ConfigInput, VendorInfo, ComplianceScore,
    ClassifiedResult, EvaluationReport
)

try:
    from jinja2 import Environment, FileSystemLoader  # pyre-ignore
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False


class ReportGenerator:
    """Generates professional compliance reports in HTML and PDF formats."""

    def __init__(self, templates_dir: Optional[str] = None):
        self.templates_dir = templates_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "templates"
        )

    def generate_html(
        self,
        report: EvaluationReport,
        output_path: str
    ) -> str:
        """
        Generate an HTML compliance report.

        Args:
            report: Complete evaluation report data.
            output_path: Path to write the HTML file.

        Returns:
            Path to the generated HTML file.
        """
        html_content = self._render_html(report)

        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return output_path

    def generate_json(
        self,
        report: EvaluationReport,
        output_path: str
    ) -> str:
        """Generate a JSON results file for programmatic use."""
        data = self._report_to_dict(report)

        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)

        return output_path

    def _render_html(self, report: EvaluationReport) -> str:
        """Render the HTML report using Jinja2 or built-in template."""
        if JINJA2_AVAILABLE and os.path.exists(os.path.join(self.templates_dir, 'report.html')):
            env = Environment(loader=FileSystemLoader(self.templates_dir))
            template = env.get_template('report.html')
            return template.render(report=report, **self._template_context(report))
        else:
            return self._render_builtin_html(report)

    def _template_context(self, report: EvaluationReport) -> dict:
        """Build template context from report data."""
        # Group failed controls by severity
        failed_high = [cr for cr in report.classified_results
                      if cr.status_label == "FAIL" and cr.severity_label == "high"]
        failed_medium = [cr for cr in report.classified_results
                        if cr.status_label == "FAIL" and cr.severity_label == "medium"]
        failed_low = [cr for cr in report.classified_results
                     if cr.status_label == "FAIL" and cr.severity_label == "low"]
        warnings = [cr for cr in report.classified_results
                   if cr.status_label == "WARNING"]
        passed = [cr for cr in report.classified_results
                 if cr.status_label == "PASS"]

        return {
            "config": report.config_input,
            "vendor": report.vendor_info,
            "score": report.compliance_score,
            "failed_high": failed_high,
            "failed_medium": failed_medium,
            "failed_low": failed_low,
            "warnings": warnings,
            "passed": passed,
            "all_results": report.classified_results,
            "cross_mappings": report.cross_mappings,
            "standards": report.standards_evaluated,
            "timestamp": report.timestamp,
            "version": report.engine_version,
        }

    def _render_builtin_html(self, report: EvaluationReport) -> str:
        """Built-in HTML template (no Jinja2 dependency required)."""
        ctx = self._template_context(report)
        score = report.compliance_score

        # Build per-standard rows
        standard_rows = ""
        for std_name, std_score in score.per_standard.items():
            standard_rows += f"""
            <tr>
                <td>{std_name}</td>
                <td>{std_score.total_rules}</td>
                <td class="pass">{std_score.passed}</td>
                <td class="warn">{std_score.warned}</td>
                <td class="fail">{std_score.failed}</td>
                <td><span class="badge" style="background:{std_score.risk_color}">{std_score.percentage}%</span></td>
                <td><span class="risk-badge" style="background:{std_score.risk_color}">{std_score.risk_level}</span></td>
            </tr>"""

        # Build failed controls rows
        failed_rows = ""
        for cr in report.classified_results:
            if cr.status_label not in ("FAIL", "WARNING"):
                continue
            r = cr.rule_result
            severity_class = f"severity-{cr.severity_label}"
            status_class = "fail" if cr.status_label == "FAIL" else "warn"
            failed_rows += f"""
            <tr class="{severity_class}">
                <td><code>{r.rule.rule_id}</code></td>
                <td>{r.rule.title}</td>
                <td><span class="badge {status_class}">{cr.status_label}</span></td>
                <td><span class="badge {severity_class}">{cr.severity_label.upper()}</span></td>
                <td>{r.rule.standard}</td>
                <td><code>{r.found_value if r.found_value else 'N/A'}</code></td>
                <td><code>{r.expected_value if r.expected_value else 'N/A'}</code></td>
            </tr>"""

        # Build remediation rows
        remediation_rows = ""
        for cr in report.classified_results:
            if cr.status_label not in ("FAIL", "WARNING"):
                continue
            r = cr.rule_result
            cmd = r.rule.remediation_command if r.rule.remediation_command else "N/A"
            remediation_rows += f"""
            <tr>
                <td><code>{r.rule.rule_id}</code></td>
                <td><span class="badge severity-{cr.severity_label}">{cr.severity_label.upper()}</span></td>
                <td>{r.rule.remediation_text}</td>
                <td><pre><code>{cmd}</code></pre></td>
            </tr>"""

        # Build appendix rows (all rules)
        appendix_rows = ""
        for cr in report.classified_results:
            r = cr.rule_result
            status_class = "pass" if cr.status_label == "PASS" else ("fail" if cr.status_label == "FAIL" else "warn")
            appendix_rows += f"""
            <tr>
                <td><code>{r.rule.rule_id}</code></td>
                <td>{r.rule.title}</td>
                <td>{r.rule.standard}</td>
                <td><span class="badge {status_class}">{cr.status_label}</span></td>
                <td>{cr.severity_label.upper()}</td>
                <td>{cr.penalty}</td>
            </tr>"""

        # Cross-standard mapping rows
        cross_rows: str = ""
        for mapping in report.cross_mappings:
            if isinstance(mapping, dict):
                for m in mapping.get("mappings", []):
                    cross_rows += f"""  # pyre-ignore
                    <tr>
                        <td>{mapping.get('canonical_control', '')}</td>
                        <td>{mapping.get('description', '')}</td>
                        <td>{m.get('standard', '')}</td>
                        <td>{m.get('control_id', '')}</td>
                        <td>{m.get('section', '')}</td>
                    </tr>"""

        # Severity bar chart (CSS-based)
        sev = score.severity_distribution
        max_sev = max(sev.values()) if sev.values() else 1
        sev_bars = ""
        for level, count in [("high", sev.get("high", 0)), ("medium", sev.get("medium", 0)), ("low", sev.get("low", 0))]:
            width = (count / max_sev * 100) if max_sev > 0 else 0
            sev_bars += f"""
            <div class="bar-row">
                <span class="bar-label">{level.upper()}</span>
                <div class="bar-container">
                    <div class="bar severity-{level}-bg" style="width:{width}%"></div>
                </div>
                <span class="bar-value">{count}</span>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmartISMS Compliance Report</title>
    <style>
        :root {{
            --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
            --text: #e2e8f0; --text-muted: #94a3b8; --border: #475569;
            --pass: #22c55e; --warn: #eab308; --fail: #ef4444;
            --high: #ef4444; --medium: #f59e0b; --low: #3b82f6;
            --accent: #6366f1;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ font-size: 2rem; margin-bottom: 0.5rem; background: linear-gradient(135deg, var(--accent), #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        h2 {{ font-size: 1.4rem; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--accent); color: var(--accent); }}
        h3 {{ font-size: 1.1rem; margin: 1.5rem 0 0.5rem; color: var(--text); }}
        .header {{ background: var(--surface); border-radius: 12px; padding: 2rem; margin-bottom: 2rem; border: 1px solid var(--border); }}
        .header-meta {{ display: flex; gap: 2rem; margin-top: 1rem; color: var(--text-muted); font-size: 0.9rem; flex-wrap: wrap; }}
        .score-hero {{ display: flex; align-items: center; gap: 2rem; margin-top: 1.5rem; }}
        .score-circle {{ width: 120px; height: 120px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2rem; font-weight: 700; border: 4px solid; }}
        .risk-label {{ font-size: 1.2rem; font-weight: 600; padding: 0.4rem 1rem; border-radius: 8px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-top: 1rem; }}
        .stat-card {{ background: var(--surface2); border-radius: 8px; padding: 1rem; text-align: center; }}
        .stat-card .value {{ font-size: 1.8rem; font-weight: 700; }}
        .stat-card .label {{ color: var(--text-muted); font-size: 0.85rem; }}
        .card {{ background: var(--surface); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid var(--border); overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
        th {{ background: var(--surface2); padding: 0.75rem; text-align: left; font-weight: 600; white-space: nowrap; }}
        td {{ padding: 0.75rem; border-top: 1px solid var(--border); }}
        tr:hover {{ background: rgba(99, 102, 241, 0.05); }}
        .badge {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: 600; display: inline-block; }}
        .pass {{ color: var(--pass); }} .warn {{ color: var(--warn); }} .fail {{ color: var(--fail); }}
        .badge.pass {{ background: rgba(34,197,94,0.15); }} .badge.warn {{ background: rgba(234,179,8,0.15); }} .badge.fail {{ background: rgba(239,68,68,0.15); }}
        .severity-high {{ color: var(--high); }} .severity-medium {{ color: var(--medium); }} .severity-low {{ color: var(--low); }}
        .badge.severity-high {{ background: rgba(239,68,68,0.15); }} .badge.severity-medium {{ background: rgba(245,158,11,0.15); }} .badge.severity-low {{ background: rgba(59,130,246,0.15); }}
        .risk-badge {{ padding: 0.25rem 0.8rem; border-radius: 6px; font-size: 0.8rem; font-weight: 600; color: #fff; }}
        code {{ background: var(--surface2); padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.85rem; }}
        pre {{ background: var(--surface2); padding: 0.75rem; border-radius: 6px; overflow-x: auto; margin: 0; }}
        pre code {{ background: none; padding: 0; }}
        .bar-row {{ display: flex; align-items: center; gap: 0.75rem; margin: 0.5rem 0; }}
        .bar-label {{ width: 70px; font-weight: 600; font-size: 0.85rem; }}
        .bar-container {{ flex: 1; height: 24px; background: var(--surface2); border-radius: 4px; overflow: hidden; }}
        .bar {{ height: 100%; border-radius: 4px; transition: width 0.5s ease; }}
        .severity-high-bg {{ background: var(--high); }} .severity-medium-bg {{ background: var(--medium); }} .severity-low-bg {{ background: var(--low); }}
        .bar-value {{ width: 30px; text-align: right; font-weight: 600; font-size: 0.9rem; }}
        .footer {{ text-align: center; color: var(--text-muted); font-size: 0.8rem; margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); }}
        @media print {{ body {{ background: #fff; color: #000; }} .card,.header {{ border: 1px solid #ddd; }} th {{ background: #f3f4f6; }} }}
    </style>
</head>
<body>
<div class="container">

    <!-- 1. Header & Executive Summary -->
    <div class="header">
        <h1>🛡️ SmartISMS Compliance Report</h1>
        <div class="header-meta">
            <span>📄 <strong>{report.config_input.filename}</strong></span>
            <span>🏷️ Vendor: <strong>{report.vendor_info.vendor_name.upper()}</strong></span>
            <span>📅 {report.timestamp[:10]}</span>
            <span>🔒 SHA-256: <code>{report.config_input.file_hash[:16]}...</code></span>
            <span>📏 Standards: <strong>{', '.join(report.standards_evaluated)}</strong></span>
        </div>

        <div class="score-hero">
            <div class="score-circle" style="border-color:{score.risk_color}; color:{score.risk_color}">
                {score.percentage}%
            </div>
            <div>
                <div class="risk-label" style="background:{score.risk_color}; color:#fff">{score.risk_level}</div>
                <p style="margin-top:0.5rem; color:var(--text-muted)">{score.total_rules} rules evaluated • Score: {score.raw_score}/{score.max_score}</p>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card"><div class="value" style="color:var(--pass)">{score.passed}</div><div class="label">Passed</div></div>
            <div class="stat-card"><div class="value" style="color:var(--warn)">{score.warned}</div><div class="label">Warnings</div></div>
            <div class="stat-card"><div class="value" style="color:var(--fail)">{score.failed}</div><div class="label">Failed</div></div>
            <div class="stat-card"><div class="value" style="color:var(--text-muted)">{score.errored}</div><div class="label">Errors</div></div>
        </div>
    </div>

    <!-- 2. Compliance Overview -->
    <h2>📊 Compliance Overview by Standard</h2>
    <div class="card">
        <table>
            <thead><tr><th>Standard</th><th>Rules</th><th>Pass</th><th>Warn</th><th>Fail</th><th>Score</th><th>Risk</th></tr></thead>
            <tbody>{standard_rows}</tbody>
        </table>
    </div>

    <!-- 3. Severity Distribution -->
    <h2>📈 Severity Distribution (Failures & Warnings)</h2>
    <div class="card">
        {sev_bars}
    </div>

    <!-- 4. Failed Controls -->
    <h2>❌ Failed & Warning Controls</h2>
    <div class="card">
        <table>
            <thead><tr><th>Rule ID</th><th>Title</th><th>Status</th><th>Severity</th><th>Standard</th><th>Found</th><th>Expected</th></tr></thead>
            <tbody>{failed_rows if failed_rows else '<tr><td colspan="7" style="text-align:center;color:var(--pass)">✅ No failed controls!</td></tr>'}</tbody>
        </table>
    </div>

    <!-- 5. Remediation Actions -->
    <h2>🔧 Remediation Actions</h2>
    <div class="card">
        <table>
            <thead><tr><th>Rule ID</th><th>Severity</th><th>Remediation</th><th>Command</th></tr></thead>
            <tbody>{remediation_rows if remediation_rows else '<tr><td colspan="4" style="text-align:center;color:var(--pass)">✅ No remediation needed!</td></tr>'}</tbody>
        </table>
    </div>

    <!-- 6. Cross-Standard Mapping -->
    <h2>🔗 Cross-Standard Mapping</h2>
    <div class="card">
        <table>
            <thead><tr><th>Canonical Control</th><th>Description</th><th>Standard</th><th>Control ID</th><th>Section</th></tr></thead>
            <tbody>{cross_rows if cross_rows else '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No cross-standard mappings loaded.</td></tr>'}</tbody>
        </table>
    </div>

    <!-- 7. Appendix -->
    <h2>📋 Appendix: Full Rule Evaluation Log</h2>
    <div class="card">
        <table>
            <thead><tr><th>Rule ID</th><th>Title</th><th>Standard</th><th>Status</th><th>Severity</th><th>Penalty</th></tr></thead>
            <tbody>{appendix_rows}</tbody>
        </table>
    </div>

    <div class="footer">
        <p>Generated by SmartISMS v{report.engine_version} • {report.timestamp} • Deterministic Rule-Based Evaluation Engine</p>
    </div>

</div>
</body>
</html>"""

        return html

    def _report_to_dict(self, report: EvaluationReport) -> dict:
        """Convert an EvaluationReport to a JSON-serializable dictionary."""
        results_list = []
        for cr in report.classified_results:
            r = cr.rule_result
            results_list.append({
                "rule_id": r.rule.rule_id,
                "standard": r.rule.standard,
                "control_id": r.rule.control_id,
                "title": r.rule.title,
                "vendor": r.rule.vendor,
                "category": r.rule.category,
                "severity": cr.severity_label,
                "weight": r.rule.weight,
                "status": cr.status_label,
                "penalty": cr.penalty,
                "weighted_penalty": cr.weighted_penalty,
                "found_value": str(r.found_value) if r.found_value else None,
                "expected_value": str(r.expected_value) if r.expected_value else None,
                "reason": r.reason,
                "remediation_text": r.rule.remediation_text,
                "remediation_command": r.rule.remediation_command,
                "cross_standard_refs": r.rule.cross_standard_refs,
            })

        per_standard = {}
        for std, ss in report.compliance_score.per_standard.items():
            per_standard[std] = {
                "percentage": ss.percentage,
                "risk_level": ss.risk_level,
                "total": ss.total_rules,
                "passed": ss.passed,
                "warned": ss.warned,
                "failed": ss.failed,
            }

        return {
            "smartisms_version": report.engine_version,
            "timestamp": report.timestamp,
            "config_file": report.config_input.filename,
            "config_hash": report.config_input.file_hash,
            "vendor": report.vendor_info.vendor_name,
            "vendor_confidence": report.vendor_info.confidence,
            "standards_evaluated": report.standards_evaluated,
            "compliance_score": {
                "percentage": report.compliance_score.percentage,
                "raw_score": report.compliance_score.raw_score,
                "max_score": report.compliance_score.max_score,
                "risk_level": report.compliance_score.risk_level,
                "total_rules": report.compliance_score.total_rules,
                "passed": report.compliance_score.passed,
                "warned": report.compliance_score.warned,
                "failed": report.compliance_score.failed,
                "errored": report.compliance_score.errored,
            },
            "per_standard": per_standard,
            "severity_distribution": report.compliance_score.severity_distribution,
            "results": results_list,
        }
