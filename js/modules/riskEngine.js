/**
 * SmartISMS - Risk Engine Module
 * Risk assessment: Impact × Likelihood for each failed rule
 */

import { Helpers } from '../utils/helpers.js';

export class RiskEngine {
    /**
     * Generate risk items from failed rule evaluations
     * @param {Array} failedResults - Failed rule results from RuleEngine
     * @returns {Array} Risk items with scores and classifications
     */
    generateRiskItems(failedResults) {
        return failedResults.map((result, index) => {
            const likelihood = Helpers.severityToNumber(result.severity);
            const impact = result.impact || Helpers.severityToNumber(result.severity);
            const riskScore = impact * likelihood;
            const riskLevel = Helpers.classifyRisk(riskScore);

            return {
                risk_id: `RISK-${String(index + 1).padStart(3, '0')}`,
                rule_id: result.rule_id,
                control_id: result.control_id,
                standard: result.standard,
                platform: result.platform,
                description: result.description,
                severity: result.severity,
                impact,
                likelihood,
                riskScore,
                riskLevel,
                status: 'Open',
                remediation_text: result.remediation_text,
                remediation_command_example: result.remediation_command_example
            };
        });
    }

    /**
     * Generate risk summary statistics
     * @param {Array} riskItems
     * @returns {Object} Summary statistics
     */
    summarize(riskItems) {
        const high = riskItems.filter(r => r.riskLevel === 'High').length;
        const medium = riskItems.filter(r => r.riskLevel === 'Medium').length;
        const low = riskItems.filter(r => r.riskLevel === 'Low').length;

        const avgScore = riskItems.length > 0
            ? (riskItems.reduce((sum, r) => sum + r.riskScore, 0) / riskItems.length).toFixed(1)
            : 0;

        const maxScore = riskItems.length > 0
            ? Math.max(...riskItems.map(r => r.riskScore))
            : 0;

        return {
            total: riskItems.length,
            high,
            medium,
            low,
            averageScore: parseFloat(avgScore),
            maxScore,
            overallLevel: high > 0 ? 'High' : (medium > 0 ? 'Medium' : 'Low')
        };
    }
}
