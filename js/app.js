/**
 * SmartISMS - Main Application Controller
 * 7-step wizard orchestrator
 */

import { InputHandler } from './modules/inputHandler.js';
import { ValidationEngine } from './modules/validationEngine.js';
import { PlatformDetector } from './modules/platformDetector.js';
import { Parser } from './modules/parser.js';
import { RuleEngine } from './modules/ruleEngine.js';
import { ComplianceCalculator } from './modules/complianceCalc.js';
import { RiskEngine } from './modules/riskEngine.js';
import { TreatmentEngine } from './modules/treatmentEngine.js';
import { ReportGenerator } from './modules/reportGenerator.js';
import { ExportEngine } from './modules/exportEngine.js';
import { Helpers } from './utils/helpers.js';

class SmartISMS {
    constructor() {
        this.currentStep = 1;
        this.maxStep = 1;
        this.state = { organization: {}, selectedStandards: [], files: [], platformDetections: [], ruleResults: null, compliance: null, riskItems: [], riskSummary: null, treatmentData: null, report: null };
        this.inputHandler = new InputHandler();
        this.validationEngine = new ValidationEngine();
        this.platformDetector = new PlatformDetector();
        this.parser = new Parser();
        this.ruleEngine = new RuleEngine();
        this.complianceCalc = new ComplianceCalculator();
        this.riskEngine = new RiskEngine();
        this.treatmentEngine = new TreatmentEngine();
        this.reportGenerator = new ReportGenerator();
        this.exportEngine = new ExportEngine();
        this.ruleFiles = { 'ISO 27001': 'rules_repository/iso27001.json', 'PCI-DSS': 'rules_repository/pci_dss.json', 'HIPAA': 'rules_repository/hipaa.json', 'CIS': 'rules_repository/cis.json' };
        this._init();
    }

    _init() {
        this._bindNavigation();
        this._bindStep1();
        this._bindStep2();
        this._bindStep3();
        this._bindExport();
        this._showStep(1);
    }

    // ── Navigation ──
    _bindNavigation() {
        document.querySelectorAll('[data-next]').forEach(btn => btn.addEventListener('click', () => this._nextStep()));
        document.querySelectorAll('[data-prev]').forEach(btn => btn.addEventListener('click', () => this._prevStep()));
        document.querySelectorAll('.step-indicator').forEach(ind => {
            ind.addEventListener('click', () => {
                const step = parseInt(ind.dataset.step);
                if (step <= this.maxStep) this._showStep(step);
            });
        });
    }

    _showStep(step) {
        this.currentStep = step;
        document.querySelectorAll('.step-panel').forEach(p => { p.classList.remove('active'); });
        const panel = document.getElementById(`step-${step}`);
        if (panel) panel.classList.add('active');
        document.querySelectorAll('.step-indicator').forEach(ind => {
            const s = parseInt(ind.dataset.step);
            ind.classList.toggle('active', s === step);
            ind.classList.toggle('completed', s < step);
            ind.classList.toggle('disabled', s > this.maxStep);
        });
        this._updateProgressBar();
    }

    _updateProgressBar() {
        const bar = document.getElementById('progress-fill');
        if (bar) bar.style.width = `${((this.currentStep - 1) / 6) * 100}%`;
    }

    _nextStep() {
        if (this.currentStep === 1 && !this._validateStep1()) return;
        if (this.currentStep === 2 && !this._validateStep2()) return;
        if (this.currentStep === 3 && !this._validateStep3()) return;
        const next = this.currentStep + 1;
        if (next > 7) return;
        this.maxStep = Math.max(this.maxStep, next);
        if (next === 4) { this._showStep(4); this._runProcessing(); return; }
        this._showStep(next);
    }

    _prevStep() {
        if (this.currentStep > 1) this._showStep(this.currentStep - 1);
    }

    // ── Step 1: Organization Setup ──
    _bindStep1() {
        const form = document.getElementById('org-form');
        if (form) form.addEventListener('submit', e => { e.preventDefault(); this._nextStep(); });
    }

    _validateStep1() {
        const name = document.getElementById('assessment-name')?.value.trim();
        const type = document.getElementById('org-type')?.value;
        const appetite = document.getElementById('risk-appetite')?.value;
        if (!name || !type || !appetite) { this._showError('step1-error', 'Please fill in all fields.'); return false; }
        this.state.organization = { assessmentName: name, orgType: type, riskAppetite: appetite };
        this._hideError('step1-error');
        return true;
    }

    // ── Step 2: Standard Selection ──
    _bindStep2() {
        document.querySelectorAll('.standard-checkbox').forEach(cb => {
            cb.addEventListener('change', () => {
                cb.closest('.standard-option').classList.toggle('selected', cb.checked);
                this._updateStandardSelection();
            });
        });
    }

    _validateStep2() {
        this._updateStandardSelection();
        if (this.state.selectedStandards.length === 0) { this._showError('step2-error', 'Select at least one standard.'); return false; }
        this._hideError('step2-error');
        return true;
    }

    _updateStandardSelection() {
        this.state.selectedStandards = [];
        document.querySelectorAll('.standard-checkbox:checked').forEach(cb => this.state.selectedStandards.push(cb.value));
    }

    // ── Step 3: File Upload ──
    _bindStep3() {
        const input = document.getElementById('file-input');
        const dropzone = document.getElementById('dropzone');
        if (input) input.addEventListener('change', e => this._handleFiles(e.target.files));
        if (dropzone) {
            dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('dragover'); });
            dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
            dropzone.addEventListener('drop', e => { e.preventDefault(); dropzone.classList.remove('dragover'); this._handleFiles(e.dataTransfer.files); });
            dropzone.addEventListener('click', () => input?.click());
        }
    }

    async _handleFiles(fileList) {
        if (!fileList || fileList.length === 0) return;
        try {
            this.state.files = await this.inputHandler.readFiles(fileList);
            const validation = this.validationEngine.validateAll(this.state.files);
            const fileListEl = document.getElementById('file-list');
            if (fileListEl) {
                fileListEl.innerHTML = '';
                validation.results.forEach(r => {
                    const platform = this.platformDetector.detect(this.state.files.find(f => f.name === r.fileName)?.content || '');
                    const div = document.createElement('div');
                    div.className = `file-item ${r.valid ? 'valid' : 'invalid'}`;
                    div.innerHTML = `<div class="file-info"><span class="file-icon">${r.valid ? '✅' : '❌'}</span><span class="file-name">${Helpers.escapeHtml(r.fileName)}</span><span class="file-platform badge">${platform.label}</span></div>${r.errors.length ? `<div class="file-errors">${r.errors.map(e => `<div class="error-msg">⚠️ ${Helpers.escapeHtml(e)}</div>`).join('')}</div>` : ''}`;
                    fileListEl.appendChild(div);
                });
            }
            // Run platform detection
            this.state.platformDetections = this.platformDetector.detectAll(this.state.files);
            if (!validation.allValid) this._showError('step3-error', 'Some files failed validation. Fix or remove them.');
            else this._hideError('step3-error');
        } catch (err) { this._showError('step3-error', `Error reading files: ${err.message}`); }
    }

    _validateStep3() {
        if (this.state.files.length === 0) { this._showError('step3-error', 'Please upload at least one file.'); return false; }
        const validation = this.validationEngine.validateAll(this.state.files);
        if (!validation.allValid) { this._showError('step3-error', 'Fix validation errors before proceeding.'); return false; }
        this._hideError('step3-error');
        return true;
    }

    // ── Step 4: Processing Pipeline ──
    async _runProcessing() {
        const statusEl = document.getElementById('processing-status');
        const progressEl = document.getElementById('processing-progress');
        const steps = [
            'Loading rule files...', 'Parsing configurations...', 'Normalizing syntax...', 'Mapping rules to configs...',
            'Executing rule engine...', 'Classifying results...', 'Applying severity weights...',
            'Calculating compliance...', 'Generating risk items...', 'Performing risk assessment...',
            'Building risk register...', 'Creating treatment plan...', 'Determining acceptable risks...', 'Generating report...'
        ];
        try {
            // Step 1: Load rules
            this.ruleEngine.clearRules();
            for (const std of this.state.selectedStandards) {
                this._updateProcessing(statusEl, progressEl, steps[0], 1, steps.length);
                const url = this.ruleFiles[std];
                if (url) { const resp = await fetch(url); const rules = await resp.json(); this.ruleEngine.loadRules(rules); }
                await Helpers.delay(200);
            }
            // Steps 2-4
            for (let i = 1; i <= 3; i++) { this._updateProcessing(statusEl, progressEl, steps[i], i + 1, steps.length); await Helpers.delay(300); }

            // Step 5-7: Execute rule engine per file
            this._updateProcessing(statusEl, progressEl, steps[4], 5, steps.length);
            let allResults = [];
            for (const file of this.state.files) {
                const det = this.state.platformDetections.find(p => p.fileName === file.name);
                const platform = det?.platform || 'unknown';
                const parsed = this.parser.parse(file.content, platform);
                const res = this.ruleEngine.execute(this.state.selectedStandards, platform, file.content);
                allResults = allResults.concat(res.results);
            }
            this.state.ruleResults = {
                results: allResults,
                summary: { total: allResults.length, passed: allResults.filter(r => r.status === 'PASS').length, failed: allResults.filter(r => r.status === 'FAIL').length, warnings: allResults.filter(r => r.status === 'WARNING').length }
            };
            await Helpers.delay(300);

            // Step 8: Compliance
            this._updateProcessing(statusEl, progressEl, steps[7], 8, steps.length);
            this.state.compliance = this.complianceCalc.calculate(allResults);
            await Helpers.delay(300);

            // Step 9-10: Risk
            this._updateProcessing(statusEl, progressEl, steps[8], 9, steps.length);
            const failed = allResults.filter(r => r.status === 'FAIL');
            this.state.riskItems = this.riskEngine.generateRiskItems(failed);
            this.state.riskSummary = this.riskEngine.summarize(this.state.riskItems);
            await Helpers.delay(300);

            // Step 11-13: Treatment
            this._updateProcessing(statusEl, progressEl, steps[11], 12, steps.length);
            this.state.treatmentData = this.treatmentEngine.generatePlan(this.state.riskItems, this.state.organization.riskAppetite);
            await Helpers.delay(300);

            // Step 14: Report
            this._updateProcessing(statusEl, progressEl, steps[13], 14, steps.length);
            this.state.report = this.reportGenerator.generate(this.state);
            await Helpers.delay(400);

            // Done → go to results
            this.maxStep = 7;
            this._showStep(5);
            this._renderDashboard();
        } catch (err) {
            if (statusEl) statusEl.textContent = `Error: ${err.message}`;
            console.error('Processing error:', err);
        }
    }

    _updateProcessing(statusEl, progressEl, text, current, total) {
        if (statusEl) statusEl.textContent = text;
        if (progressEl) progressEl.style.width = `${(current / total) * 100}%`;
    }

    // ── Step 5: Results Dashboard ──
    _renderDashboard() {
        const r = this.state.report;
        if (!r) return;
        // Compliance score
        const scoreEl = document.getElementById('compliance-score');
        if (scoreEl) { scoreEl.textContent = `${r.compliance.percentage}%`; scoreEl.className = `score-value ${Helpers.riskLevelClass(r.compliance.riskLevel)}`; }
        const levelEl = document.getElementById('risk-level-label');
        if (levelEl) { levelEl.textContent = r.compliance.riskLevel; levelEl.className = `risk-label ${Helpers.riskLevelClass(r.compliance.riskLevel)}`; }
        // Summary cards
        this._setText('total-rules', r.ruleResults.summary.total);
        this._setText('passed-rules', r.ruleResults.summary.passed);
        this._setText('failed-rules', r.ruleResults.summary.failed);
        this._setText('warning-rules', r.ruleResults.summary.warnings);
        this._setText('total-risks', r.riskRegister.summary.total);
        this._setText('high-risks', r.riskRegister.summary.high);
        this._setText('medium-risks', r.riskRegister.summary.medium);
        this._setText('low-risks', r.riskRegister.summary.low);
        // Executive summary
        this._setText('exec-summary', r.executiveSummary);
        // Standards breakdown
        this._renderStandardsBreakdown(r.compliance.byStandard);
        // Severity chart
        this._renderSeverityChart(r.compliance.bySeverity);
        // Failed controls
        this._renderFailedControls(r.ruleResults.failed);
        // Risk register (step 6)
        this._renderRiskRegister(r.riskRegister.items);
        // Treatment plan (step 6)
        this._renderTreatmentPlan(r.treatmentPlan);
        // Recommendations
        this._renderRecommendations(r.recommendations);
    }

    _renderStandardsBreakdown(byStandard) {
        const el = document.getElementById('standards-breakdown');
        if (!el) return;
        el.innerHTML = Object.entries(byStandard).map(([name, d]) =>
            `<div class="standard-card"><div class="standard-name">${Helpers.escapeHtml(name)}</div><div class="standard-score">${d.percentage}%</div><div class="standard-bar"><div class="standard-bar-fill" style="width:${d.percentage}%"></div></div><div class="standard-detail">${d.passed} passed · ${d.failed} failed · ${d.warnings} warnings</div></div>`
        ).join('');
    }

    _renderSeverityChart(bySeverity) {
        const el = document.getElementById('severity-chart');
        if (!el) return;
        const total = (bySeverity.High?.total || 0) + (bySeverity.Medium?.total || 0) + (bySeverity.Low?.total || 0);
        if (total === 0) { el.innerHTML = '<div class="no-data">No rules evaluated</div>'; return; }
        el.innerHTML = ['High', 'Medium', 'Low'].map(sev => {
            const d = bySeverity[sev] || { total: 0, failed: 0 };
            const pct = total > 0 ? Math.round((d.total / total) * 100) : 0;
            return `<div class="sev-row"><span class="sev-label badge ${Helpers.severityClass(sev)}">${sev}</span><div class="sev-bar-track"><div class="sev-bar-fill ${Helpers.severityClass(sev)}" style="width:${pct}%"></div></div><span class="sev-count">${d.failed}/${d.total} failed</span></div>`;
        }).join('');
    }

    _renderFailedControls(failed) {
        const el = document.getElementById('failed-controls-table');
        if (!el) return;
        if (failed.length === 0) { el.innerHTML = '<tr><td colspan="6" class="no-data">🎉 No failed controls!</td></tr>'; return; }
        el.innerHTML = failed.map(f =>
            `<tr><td>${Helpers.escapeHtml(f.rule_id)}</td><td>${Helpers.escapeHtml(f.control_id)}</td><td>${Helpers.escapeHtml(f.standard)}</td><td>${Helpers.escapeHtml(f.description)}</td><td><span class="badge ${Helpers.severityClass(f.severity)}">${f.severity}</span></td><td class="remediation-cell"><div class="remediation-text">${Helpers.escapeHtml(f.remediation_text)}</div>${f.remediation_command_example ? `<code class="remediation-cmd">${Helpers.escapeHtml(f.remediation_command_example)}</code>` : ''}</td></tr>`
        ).join('');
    }

    _renderRiskRegister(items) {
        const el = document.getElementById('risk-register-table');
        if (!el) return;
        if (items.length === 0) { el.innerHTML = '<tr><td colspan="10" class="no-data">No risk items</td></tr>'; return; }
        el.innerHTML = items.map(ri =>
            `<tr><td>${ri.risk_id}</td><td>${ri.control_id}</td><td>${ri.standard}</td><td>${Helpers.escapeHtml(ri.description)}</td><td><span class="badge ${Helpers.severityClass(ri.severity)}">${ri.severity}</span></td><td>${ri.impact}</td><td>${ri.likelihood}</td><td><strong>${ri.riskScore}</strong></td><td><span class="badge ${Helpers.riskLevelClass(ri.riskLevel)}">${ri.riskLevel}</span></td><td>${ri.status}</td></tr>`
        ).join('');
    }

    _renderTreatmentPlan(td) {
        const el = document.getElementById('treatment-table');
        if (!el) return;
        el.innerHTML = td.treatmentPlan.map(t =>
            `<tr><td>${t.risk_id}</td><td>${Helpers.escapeHtml(t.description)}</td><td><span class="badge">${t.treatmentStrategy}</span></td><td>${t.priority}</td><td>${t.targetTimeframe}</td><td>${t.responsibleRole}</td><td><span class="badge ${t.status === 'Accepted' ? 'status-accepted' : 'status-open'}">${t.status}</span></td></tr>`
        ).join('');
        // Accepted risks count
        this._setText('accepted-count', td.summary.accepted);
        this._setText('treatment-count', td.summary.requiresTreatment);
    }

    _renderRecommendations(recs) {
        const el = document.getElementById('recommendations-list');
        if (!el) return;
        el.innerHTML = recs.map(r =>
            `<div class="rec-item rec-${r.priority.toLowerCase()}"><span class="rec-icon">${r.icon}</span><div class="rec-content"><div class="rec-header"><span class="badge">${r.priority}</span> <span class="rec-category">${r.category}</span></div><p>${Helpers.escapeHtml(r.text)}</p></div></div>`
        ).join('');
    }

    // ── Step 7: Export ──
    _bindExport() {
        document.getElementById('export-html')?.addEventListener('click', () => { if (this.state.report) this.exportEngine.exportHTML(this.state.report); });
        document.getElementById('export-pdf')?.addEventListener('click', () => { if (this.state.report) this.exportEngine.exportPDF(this.state.report); });
    }

    // ── Utility ──
    _setText(id, text) { const el = document.getElementById(id); if (el) el.textContent = text; }
    _showError(id, msg) { const el = document.getElementById(id); if (el) { el.textContent = msg; el.style.display = 'block'; } }
    _hideError(id) { const el = document.getElementById(id); if (el) el.style.display = 'none'; }
}

// Boot
document.addEventListener('DOMContentLoaded', () => { window.smartISMS = new SmartISMS(); });
