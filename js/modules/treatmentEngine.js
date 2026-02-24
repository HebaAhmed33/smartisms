/**
 * SmartISMS - Treatment Engine Module
 * Risk treatment plans, acceptable risk determination, strategy assignment
 */

import { Helpers } from '../utils/helpers.js';

export class TreatmentEngine {
    /**
     * Generate treatment plan from risk items
     * @param {Array} riskItems - From RiskEngine
     * @param {string} riskAppetite - 'Low', 'Medium', or 'High'
     * @returns {{treatmentPlan: Array, acceptedRisks: Array, requiresTreatment: Array}}
     */
    generatePlan(riskItems, riskAppetite) {
        const threshold = Helpers.appetiteToThreshold(riskAppetite);

        const treatmentPlan = riskItems.map(risk => {
            const isAcceptable = risk.riskScore <= threshold;

            if (isAcceptable) {
                return {
                    ...risk,
                    status: 'Accepted',
                    treatmentStrategy: 'Accept',
                    priority: 'None',
                    targetTimeframe: 'N/A',
                    responsibleRole: 'Risk Owner',
                    rationale: `Risk score (${risk.riskScore}) is within organizational risk appetite threshold (${threshold})`
                };
            }

            return {
                ...risk,
                status: 'Open',
                ...this._determineTreatment(risk)
            };
        });

        const acceptedRisks = treatmentPlan.filter(r => r.status === 'Accepted');
        const requiresTreatment = treatmentPlan.filter(r => r.status !== 'Accepted');

        return {
            treatmentPlan,
            acceptedRisks,
            requiresTreatment,
            summary: {
                total: treatmentPlan.length,
                accepted: acceptedRisks.length,
                requiresTreatment: requiresTreatment.length,
                appetiteThreshold: threshold,
                appetite: riskAppetite
            }
        };
    }

    /**
     * Determine treatment strategy based on risk level
     * @private
     */
    _determineTreatment(risk) {
        switch (risk.riskLevel) {
            case 'High':
                return {
                    treatmentStrategy: 'Mitigate',
                    priority: 'Critical',
                    targetTimeframe: 'Immediate (0–30 days)',
                    responsibleRole: this._getResponsibleRole(risk),
                    rationale: `High risk (score: ${risk.riskScore}) requires immediate mitigation`
                };

            case 'Medium':
                return {
                    treatmentStrategy: this._getMediumStrategy(risk),
                    priority: 'High',
                    targetTimeframe: 'Short-term (30–90 days)',
                    responsibleRole: this._getResponsibleRole(risk),
                    rationale: `Medium risk (score: ${risk.riskScore}) should be addressed in the short term`
                };

            case 'Low':
                return {
                    treatmentStrategy: 'Accept',
                    priority: 'Medium',
                    targetTimeframe: 'Planned (90–180 days)',
                    responsibleRole: this._getResponsibleRole(risk),
                    rationale: `Low risk (score: ${risk.riskScore}) can be monitored and addressed in planned maintenance`
                };

            default:
                return {
                    treatmentStrategy: 'Mitigate',
                    priority: 'High',
                    targetTimeframe: 'Short-term (30–90 days)',
                    responsibleRole: 'IT Security Team',
                    rationale: 'Default treatment strategy applied'
                };
        }
    }

    /**
     * Determine medium-risk strategy
     * @private
     */
    _getMediumStrategy(risk) {
        // If it's a network/infrastructure issue, suggest transfer (outsource security)
        if (['cisco', 'junos', 'firewall'].includes(risk.platform)) {
            return 'Mitigate';
        }
        // For application-layer issues, mitigate directly
        return 'Mitigate';
    }

    /**
     * Get responsible role based on platform and severity
     * @private
     */
    _getResponsibleRole(risk) {
        const roleMap = {
            cisco: 'Network Security Engineer',
            junos: 'Network Security Engineer',
            firewall: 'Network Security Engineer',
            linux: 'System Administrator',
            nginx: 'Web Application Security Engineer',
            apache: 'Web Application Security Engineer'
        };
        return roleMap[risk.platform] || 'IT Security Team';
    }
}
