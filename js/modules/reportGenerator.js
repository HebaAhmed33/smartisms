/**
 * SmartISMS - Report Generator Module
 * Assembles all data into a structured report object
 */

import { Helpers } from '../utils/helpers.js';

export class ReportGenerator {
    generate({ organization, selectedStandards, files, platformDetections, ruleResults, compliance, riskItems, riskSummary, treatmentData }) {
        return {
            meta: { reportId: Helpers.generateId('RPT'), generatedAt: Helpers.formatDateTime(), generatedDate: Helpers.formatDate(), version: '1.0' },
            executiveSummary: this._genSummary(compliance, riskSummary, treatmentData),
            organization,
            assessment: {
                name: organization.assessmentName,
                standards: selectedStandards,
                filesAnalyzed: files.map(f => ({ name: f.name, size: f.size, platform: platformDetections.find(p => p.fileName === f.name)?.label || 'Unknown' })),
                platforms: platformDetections
            },
            compliance,
            ruleResults: { all: ruleResults.results, summary: ruleResults.summary, failed: ruleResults.results.filter(r => r.status === 'FAIL'), warnings: ruleResults.results.filter(r => r.status === 'WARNING'), passed: ruleResults.results.filter(r => r.status === 'PASS') },
            riskRegister: { items: riskItems, summary: riskSummary },
            treatmentPlan: treatmentData,
            recommendations: this._genRecs(ruleResults.results, compliance, riskSummary)
        };
    }

    _genSummary(c, rs, td) {
        let s = `This assessment evaluated security posture against selected standards. Overall compliance: ${c.percentage}% ("${c.riskLevel}").`;
        if (rs.total > 0) s += ` ${rs.total} risk items: ${rs.high} High, ${rs.medium} Medium, ${rs.low} Low.`;
        else s += ' No risk items identified.';
        if (td.summary.accepted > 0) s += ` ${td.summary.accepted} risk(s) accepted (appetite: ${td.summary.appetite}).`;
        if (td.summary.requiresTreatment > 0) s += ` ${td.summary.requiresTreatment} risk(s) require treatment.`;
        return s;
    }

    _genRecs(results, compliance, riskSummary) {
        const recs = [];
        if (compliance.percentage < 50) recs.push({ priority: 'Critical', category: 'Overall Posture', text: 'Compliance critically low. Immediate comprehensive review required.', icon: '🔴' });
        else if (compliance.percentage < 70) recs.push({ priority: 'High', category: 'Overall Posture', text: 'Below acceptable thresholds. Prioritize high-severity findings.', icon: '🟠' });
        else if (compliance.percentage < 90) recs.push({ priority: 'Medium', category: 'Overall Posture', text: 'Moderate compliance. Address remaining findings.', icon: '🟡' });
        else recs.push({ priority: 'Low', category: 'Overall Posture', text: 'Strong compliance. Maintain controls.', icon: '🟢' });

        const hf = results.filter(r => r.status === 'FAIL' && r.severity === 'High');
        if (hf.length > 0) recs.push({ priority: 'Critical', category: 'High Severity', text: `${hf.length} high-severity control(s) failed. Remediate immediately.`, icon: '🔴' });

        const ef = results.filter(r => r.status === 'FAIL' && (r.description.toLowerCase().includes('ssl') || r.description.toLowerCase().includes('encrypt')));
        if (ef.length > 0) recs.push({ priority: 'High', category: 'Encryption', text: 'Encryption configs missing. Implement TLS/SSL.', icon: '🔐' });

        const af = results.filter(r => r.status === 'FAIL' && (r.description.toLowerCase().includes('authentication') || r.description.toLowerCase().includes('login')));
        if (af.length > 0) recs.push({ priority: 'High', category: 'Authentication', text: 'Authentication gaps detected. Strengthen access controls.', icon: '🔑' });

        const lf = results.filter(r => r.status === 'FAIL' && r.description.toLowerCase().includes('logging'));
        if (lf.length > 0) recs.push({ priority: 'Medium', category: 'Logging', text: 'Logging incomplete. Enable comprehensive audit logging.', icon: '📋' });

        return recs;
    }
}
