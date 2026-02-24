/**
 * SmartISMS - Compliance Calculator Module
 * Weighted compliance scoring per specification
 */

export class ComplianceCalculator {
    /**
     * Calculate compliance percentage from rule results
     * @param {Array} results - Array of rule evaluation results
     * @returns {{percentage, riskLevel, totalPossible, deductions, byStandard, bySeverity}}
     */
    calculate(results) {
        if (!results || results.length === 0) {
            return {
                percentage: 0,
                riskLevel: 'Critical Risk',
                totalPossible: 0,
                deductions: 0,
                byStandard: {},
                bySeverity: { High: { total: 0, failed: 0 }, Medium: { total: 0, failed: 0 }, Low: { total: 0, failed: 0 } }
            };
        }

        // Total possible = sum of all rule weights
        const totalPossible = results.reduce((sum, r) => sum + r.weight, 0);

        // Deductions = sum of failed rule weights (FAIL only, not WARNING)
        const deductions = results
            .filter(r => r.status === 'FAIL')
            .reduce((sum, r) => sum + r.weight, 0);

        // Warning deductions (partial - 50% of weight)
        const warningDeductions = results
            .filter(r => r.status === 'WARNING')
            .reduce((sum, r) => sum + (r.weight * 0.5), 0);

        // Compliance percentage
        const percentage = totalPossible > 0
            ? Math.round(((totalPossible - deductions - warningDeductions) / totalPossible) * 100)
            : 0;

        // Risk level
        const riskLevel = this._classifyRiskLevel(percentage);

        // Breakdown by standard
        const byStandard = this._breakdownByStandard(results);

        // Breakdown by severity
        const bySeverity = this._breakdownBySeverity(results);

        return {
            percentage: Math.max(0, Math.min(100, percentage)),
            riskLevel,
            totalPossible,
            deductions,
            warningDeductions,
            byStandard,
            bySeverity
        };
    }

    /**
     * Classify overall risk level from compliance percentage
     * @private
     */
    _classifyRiskLevel(percentage) {
        if (percentage >= 90) return 'Low Risk';
        if (percentage >= 70) return 'Medium Risk';
        if (percentage >= 50) return 'High Risk';
        return 'Critical Risk';
    }

    /**
     * Break down compliance by standard
     * @private
     */
    _breakdownByStandard(results) {
        const standards = {};

        for (const result of results) {
            if (!standards[result.standard]) {
                standards[result.standard] = { total: 0, passed: 0, failed: 0, warnings: 0, totalWeight: 0, failedWeight: 0 };
            }
            const s = standards[result.standard];
            s.total++;
            s.totalWeight += result.weight;
            if (result.status === 'PASS') s.passed++;
            else if (result.status === 'FAIL') { s.failed++; s.failedWeight += result.weight; }
            else if (result.status === 'WARNING') s.warnings++;
        }

        // Calculate percentage per standard
        for (const std of Object.values(standards)) {
            std.percentage = std.totalWeight > 0
                ? Math.round(((std.totalWeight - std.failedWeight) / std.totalWeight) * 100)
                : 0;
        }

        return standards;
    }

    /**
     * Break down compliance by severity
     * @private
     */
    _breakdownBySeverity(results) {
        const severities = { High: { total: 0, failed: 0 }, Medium: { total: 0, failed: 0 }, Low: { total: 0, failed: 0 } };

        for (const result of results) {
            if (severities[result.severity]) {
                severities[result.severity].total++;
                if (result.status === 'FAIL') {
                    severities[result.severity].failed++;
                }
            }
        }

        return severities;
    }
}
