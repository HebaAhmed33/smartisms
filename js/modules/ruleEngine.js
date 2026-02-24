/**
 * SmartISMS - Rule Engine Module
 * Core deterministic evaluation engine
 */

export class RuleEngine {
    constructor() {
        this.rules = [];
        this.results = [];
    }

    /**
     * Load rules from JSON data
     * @param {Array} rulesData - Array of rule objects from JSON files
     */
    loadRules(rulesData) {
        this.rules = [...this.rules, ...rulesData];
    }

    /**
     * Clear loaded rules
     */
    clearRules() {
        this.rules = [];
        this.results = [];
    }

    /**
     * Filter rules by selected standards and detected platform
     * @param {string[]} selectedStandards - e.g. ['ISO 27001', 'PCI-DSS']
     * @param {string} platform - detected platform e.g. 'cisco'
     * @returns {Array} filtered rules
     */
    filterRules(selectedStandards, platform) {
        return this.rules.filter(rule => {
            const standardMatch = selectedStandards.includes(rule.standard);
            const platformMatch = rule.platform === platform || rule.platform === 'generic' || platform === 'unknown';
            return standardMatch && platformMatch;
        });
    }

    /**
     * Evaluate a single rule against config content
     * @param {Object} rule - Rule object
     * @param {string} configText - Raw config text (not normalized, for accurate matching)
     * @returns {{rule_id, status, severity, weight, description, control_id, standard, remediation_text, remediation_command_example}}
     */
    evaluateRule(rule, configText) {
        let passed = false;

        try {
            switch (rule.check_type) {
                case 'contains':
                    passed = configText.includes(rule.expected_value);
                    break;

                case 'not_contains':
                    passed = !configText.includes(rule.expected_value);
                    break;

                case 'equals':
                    passed = configText.split(/\r?\n/).some(
                        line => line.trim() === rule.expected_value
                    );
                    break;

                case 'regex':
                    try {
                        const regex = new RegExp(rule.expected_value, 'im');
                        passed = regex.test(configText);
                    } catch (e) {
                        // Invalid regex - treat as fail with warning
                        console.warn(`Invalid regex in rule ${rule.rule_id}: ${rule.expected_value}`);
                        passed = false;
                    }
                    break;

                default:
                    console.warn(`Unknown check_type "${rule.check_type}" in rule ${rule.rule_id}`);
                    passed = false;
            }
        } catch (error) {
            console.error(`Error evaluating rule ${rule.rule_id}:`, error);
            passed = false;
        }

        // Determine status
        let status;
        if (passed) {
            status = 'PASS';
        } else if (rule.severity === 'Low') {
            status = 'WARNING';
        } else {
            status = 'FAIL';
        }

        return {
            rule_id: rule.rule_id,
            standard: rule.standard,
            control_id: rule.control_id,
            platform: rule.platform,
            description: rule.description,
            check_type: rule.check_type,
            expected_value: rule.expected_value,
            severity: rule.severity,
            weight: rule.weight,
            impact: rule.impact,
            likelihood_base: rule.likelihood_base,
            status,
            remediation_text: rule.remediation_text,
            remediation_command_example: rule.remediation_command_example
        };
    }

    /**
     * Execute all applicable rules against config content
     * @param {string[]} selectedStandards
     * @param {string} platform
     * @param {string} configText
     * @returns {{results: Array, summary: Object}}
     */
    execute(selectedStandards, platform, configText) {
        const applicableRules = this.filterRules(selectedStandards, platform);
        this.results = applicableRules.map(rule => this.evaluateRule(rule, configText));

        const passCount = this.results.filter(r => r.status === 'PASS').length;
        const failCount = this.results.filter(r => r.status === 'FAIL').length;
        const warningCount = this.results.filter(r => r.status === 'WARNING').length;

        return {
            results: this.results,
            summary: {
                total: this.results.length,
                passed: passCount,
                failed: failCount,
                warnings: warningCount
            }
        };
    }

    /**
     * Get failed results only
     */
    getFailedResults() {
        return this.results.filter(r => r.status === 'FAIL');
    }

    /**
     * Get warning results only
     */
    getWarningResults() {
        return this.results.filter(r => r.status === 'WARNING');
    }

    /**
     * Get passed results only
     */
    getPassedResults() {
        return this.results.filter(r => r.status === 'PASS');
    }
}
