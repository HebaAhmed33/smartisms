/**
 * SmartISMS - Utility Helpers
 * Shared utility functions used across all modules
 */

export const Helpers = {
    /**
     * Generate a unique ID with prefix
     */
    generateId(prefix = 'ID') {
        return `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
    },

    /**
     * Format date for reports
     */
    formatDate(date = new Date()) {
        return date.toISOString().split('T')[0];
    },

    /**
     * Format datetime for reports
     */
    formatDateTime(date = new Date()) {
        return date.toLocaleString('en-US', {
            year: 'numeric', month: 'long', day: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });
    },

    /**
     * Severity to numeric value
     */
    severityToNumber(severity) {
        const map = { 'High': 3, 'Medium': 2, 'Low': 1 };
        return map[severity] || 1;
    },

    /**
     * Risk score to classification
     */
    classifyRisk(score) {
        if (score >= 7) return 'High';
        if (score >= 4) return 'Medium';
        return 'Low';
    },

    /**
     * Compliance percentage to risk level
     */
    complianceToRiskLevel(percentage) {
        if (percentage >= 90) return 'Low Risk';
        if (percentage >= 70) return 'Medium Risk';
        if (percentage >= 50) return 'High Risk';
        return 'Critical Risk';
    },

    /**
     * Risk level CSS class
     */
    riskLevelClass(level) {
        const map = {
            'Low': 'risk-low', 'Low Risk': 'risk-low',
            'Medium': 'risk-medium', 'Medium Risk': 'risk-medium',
            'High': 'risk-high', 'High Risk': 'risk-high',
            'Critical Risk': 'risk-critical'
        };
        return map[level] || 'risk-medium';
    },

    /**
     * Severity badge CSS class
     */
    severityClass(severity) {
        const map = { 'High': 'severity-high', 'Medium': 'severity-medium', 'Low': 'severity-low' };
        return map[severity] || 'severity-low';
    },

    /**
     * Appetite label to threshold value
     */
    appetiteToThreshold(appetite) {
        const map = { 'Low': 1, 'Medium': 3, 'High': 6 };
        return map[appetite] || 3;
    },

    /**
     * Escape HTML for safe display
     */
    escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },

    /**
     * Delay execution (for animation purposes)
     */
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
};
