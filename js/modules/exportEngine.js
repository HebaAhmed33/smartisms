/**
 * SmartISMS - Export Engine Module
 * HTML export and browser print-to-PDF
 */

import { Helpers } from '../utils/helpers.js';

export class ExportEngine {
    /**
     * Export report as self-contained HTML
     */
    exportHTML(report) {
        const html = this._buildHTML(report);
        const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `SmartISMS_Report_${report.meta.generatedDate}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    /**
     * Export via browser print dialog (PDF)
     */
    exportPDF(report) {
        const html = this._buildHTML(report);
        const printWindow = window.open('', '_blank');
        printWindow.document.write(html);
        printWindow.document.close();
        setTimeout(() => { printWindow.print(); }, 500);
    }

    _buildHTML(r) {
        const esc = Helpers.escapeHtml;
        const failedRows = (r.ruleResults.failed || []).map(f =>
            `<tr><td>${esc(f.rule_id)}</td><td>${esc(f.control_id)}</td><td>${esc(f.standard)}</td><td>${esc(f.description)}</td><td class="sev-${f.severity.toLowerCase()}">${f.severity}</td><td>${esc(f.remediation_text)}</td></tr>`
        ).join('');

        const riskRows = (r.riskRegister.items || []).map(ri =>
            `<tr><td>${esc(ri.risk_id)}</td><td>${esc(ri.control_id)}</td><td>${esc(ri.standard)}</td><td>${esc(ri.description)}</td><td>${ri.impact}</td><td>${ri.likelihood}</td><td>${ri.riskScore}</td><td class="risk-${ri.riskLevel.toLowerCase()}">${ri.riskLevel}</td><td>${ri.status}</td></tr>`
        ).join('');

        const treatRows = (r.treatmentPlan.treatmentPlan || []).map(t =>
            `<tr><td>${esc(t.risk_id)}</td><td>${esc(t.description)}</td><td>${t.treatmentStrategy}</td><td>${t.priority}</td><td>${t.targetTimeframe}</td><td>${t.responsibleRole}</td><td>${t.status}</td></tr>`
        ).join('');

        const recItems = (r.recommendations || []).map(rec =>
            `<li>${rec.icon} <strong>[${rec.priority}]</strong> ${esc(rec.text)}</li>`
        ).join('');

        const stdBreakdown = Object.entries(r.compliance.byStandard || {}).map(([name, d]) =>
            `<tr><td>${esc(name)}</td><td>${d.total}</td><td>${d.passed}</td><td>${d.failed}</td><td>${d.percentage}%</td></tr>`
        ).join('');

        return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>SmartISMS Report - ${esc(r.organization.assessmentName)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:#fff;color:#1a1a2e;padding:40px;line-height:1.6}
h1{color:#0f3460;border-bottom:3px solid #0f3460;padding-bottom:10px;margin-bottom:20px}
h2{color:#16213e;margin:30px 0 15px;border-left:4px solid #e94560;padding-left:12px}
table{width:100%;border-collapse:collapse;margin:15px 0;font-size:13px}
th{background:#0f3460;color:#fff;padding:10px 8px;text-align:left}
td{padding:8px;border-bottom:1px solid #ddd}
tr:nth-child(even){background:#f8f9fa}
.sev-high{color:#e94560;font-weight:bold}.sev-medium{color:#e89a2d;font-weight:bold}.sev-low{color:#2ecc71;font-weight:bold}
.risk-high{color:#e94560;font-weight:bold}.risk-medium{color:#e89a2d;font-weight:bold}.risk-low{color:#2ecc71;font-weight:bold}
.metric{display:inline-block;background:#f0f4ff;border:1px solid #d0d8ff;border-radius:8px;padding:15px 25px;margin:8px;text-align:center}
.metric .value{font-size:28px;font-weight:bold;color:#0f3460}.metric .label{font-size:12px;color:#666}
.summary{background:#f8f9fa;padding:20px;border-radius:8px;margin:15px 0;border-left:4px solid #0f3460}
ul{padding-left:20px}li{margin:8px 0}
@media print{body{padding:20px}h1{font-size:20px}table{font-size:11px}}
</style></head><body>
<h1>🛡️ SmartISMS Security Assessment Report</h1>
<div class="summary"><strong>Report ID:</strong> ${esc(r.meta.reportId)} | <strong>Date:</strong> ${esc(r.meta.generatedAt)}</div>

<h2>Executive Summary</h2><p>${esc(r.executiveSummary)}</p>

<h2>Organization</h2>
<p><strong>Name:</strong> ${esc(r.organization.assessmentName)}<br><strong>Type:</strong> ${esc(r.organization.orgType)}<br><strong>Risk Appetite:</strong> ${esc(r.organization.riskAppetite)}</p>

<h2>Compliance Overview</h2>
<div class="metric"><div class="value">${r.compliance.percentage}%</div><div class="label">Compliance</div></div>
<div class="metric"><div class="value">${r.compliance.riskLevel}</div><div class="label">Risk Level</div></div>
<div class="metric"><div class="value">${r.ruleResults.summary.total}</div><div class="label">Rules Evaluated</div></div>
<div class="metric"><div class="value">${r.ruleResults.summary.failed}</div><div class="label">Failed</div></div>

<h2>Compliance by Standard</h2>
<table><tr><th>Standard</th><th>Total</th><th>Passed</th><th>Failed</th><th>Compliance</th></tr>${stdBreakdown}</table>

<h2>Failed Controls</h2>
<table><tr><th>Rule ID</th><th>Control</th><th>Standard</th><th>Description</th><th>Severity</th><th>Remediation</th></tr>${failedRows}</table>

<h2>Risk Register</h2>
<table><tr><th>Risk ID</th><th>Control</th><th>Standard</th><th>Description</th><th>Impact</th><th>Likelihood</th><th>Score</th><th>Level</th><th>Status</th></tr>${riskRows}</table>

<h2>Risk Treatment Plan</h2>
<table><tr><th>Risk ID</th><th>Description</th><th>Strategy</th><th>Priority</th><th>Timeframe</th><th>Responsible</th><th>Status</th></tr>${treatRows}</table>

<h2>Recommendations</h2><ul>${recItems}</ul>

<div style="margin-top:40px;text-align:center;color:#999;font-size:12px">Generated by SmartISMS v1.0 — Rule-Based Expert System</div>
</body></html>`;
    }
}
