/* ========================================
   SmartISMS — Frontend Logic
   ======================================== */

// DOM Elements
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const fileInfo = document.getElementById('file-info');
const fileName = document.getElementById('file-name');
const fileSize = document.getElementById('file-size');
const removeFileBtn = document.getElementById('remove-file');
const evaluateBtn = document.getElementById('evaluate-btn');
const uploadSection = document.getElementById('upload-section');
const loadingSection = document.getElementById('loading-section');
const resultsSection = document.getElementById('results-section');
const errorSection = document.getElementById('error-section');

let selectedFile = null;

// ===== File Upload =====
dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
        handleFile(e.dataTransfer.files[0]);
    }
});

fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
        handleFile(fileInput.files[0]);
    }
});

removeFileBtn.addEventListener('click', () => {
    selectedFile = null;
    fileInput.value = '';
    fileInfo.classList.add('hidden');
    dropZone.classList.remove('hidden');
    evaluateBtn.disabled = true;
});

function handleFile(file) {
    selectedFile = file;
    fileName.textContent = file.name;
    fileSize.textContent = formatFileSize(file.size);
    fileInfo.classList.remove('hidden');
    dropZone.classList.add('hidden');
    evaluateBtn.disabled = false;
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' bytes';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// ===== Evaluate =====
evaluateBtn.addEventListener('click', async () => {
    if (!selectedFile) return;

    // Get selected standards
    const checkboxes = document.querySelectorAll('#standards-grid input[type="checkbox"]:checked');
    const standards = Array.from(checkboxes).map(cb => cb.value);

    if (standards.length === 0) {
        alert('Please select at least one compliance standard.');
        return;
    }

    // Show loading
    uploadSection.classList.add('hidden');
    loadingSection.classList.remove('hidden');
    resultsSection.classList.add('hidden');
    errorSection.classList.add('hidden');

    // Animate loading steps
    const loadingSteps = document.getElementById('loading-steps');
    const steps = [
        'Detecting vendor and platform...',
        'Parsing configuration file...',
        'Normalizing entries...',
        'Evaluating compliance rules...',
        'Calculating scores...',
        'Building results...'
    ];
    let stepIdx = 0;
    const stepInterval = setInterval(() => {
        stepIdx = (stepIdx + 1) % steps.length;
        loadingSteps.textContent = steps[stepIdx];
    }, 800);

    try {
        // Build form data
        const formData = new FormData();
        formData.append('config_file', selectedFile);
        formData.append('standards', standards.join(','));

        // Send request
        const response = await fetch('/api/evaluate', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        clearInterval(stepInterval);

        if (!response.ok) {
            throw new Error(data.error || 'Evaluation failed');
        }

        // Show results
        loadingSection.classList.add('hidden');
        renderResults(data);

    } catch (error) {
        clearInterval(stepInterval);
        loadingSection.classList.add('hidden');
        errorSection.classList.remove('hidden');
        document.getElementById('error-message').textContent = error.message;
    }
});

// ===== Render Results =====
function renderResults(data) {
    resultsSection.classList.remove('hidden');
    resultsSection.classList.add('fade-in');

    const score = data.score;
    const pct = score.percentage;

    // Animate score gauge
    const gaugeFill = document.getElementById('gauge-fill');
    const circumference = 2 * Math.PI * 85; // r=85
    const offset = circumference - (pct / 100) * circumference;
    gaugeFill.style.stroke = score.risk_color;
    setTimeout(() => {
        gaugeFill.style.strokeDashoffset = offset;
    }, 100);

    // Animate score number
    animateNumber('score-value', 0, pct, 1500, '%');

    // Risk level
    const riskEl = document.getElementById('risk-level');
    riskEl.textContent = score.risk_level;
    riskEl.style.color = score.risk_color;

    // Vendor info
    document.getElementById('vendor-info').textContent =
        `${data.vendor} • ${data.filename} • ${data.total_rules_evaluated} rules`;

    // Stats
    animateNumber('stat-passed', 0, score.passed, 1000);
    animateNumber('stat-warned', 0, score.warned, 1000);
    animateNumber('stat-failed', 0, score.failed, 1000);
    animateNumber('stat-total', 0, data.total_rules_evaluated, 1000);

    // Per-standard breakdown
    renderStandardsBreakdown(data.per_standard);

    // Severity distribution
    renderSeverityBars(data.severity_distribution);

    // Rules table
    renderRulesTable(data.rules);

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function animateNumber(elementId, start, end, duration, suffix = '') {
    const el = document.getElementById(elementId);
    const range = end - start;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        // Ease out cubic
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = start + range * eased;

        if (suffix === '%') {
            el.textContent = current.toFixed(1) + suffix;
        } else {
            el.textContent = Math.round(current) + suffix;
        }

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    requestAnimationFrame(update);
}

// ===== Per-Standard Breakdown =====
function renderStandardsBreakdown(perStandard) {
    const container = document.getElementById('standards-results');
    container.innerHTML = '';

    for (const [name, data] of Object.entries(perStandard)) {
        const card = document.createElement('div');
        card.className = 'std-result-card fade-in';
        card.innerHTML = `
            <div class="std-result-header">
                <span class="std-result-name">${name}</span>
                <span class="std-result-pct" style="color: ${data.risk_color}">${data.percentage}%</span>
            </div>
            <div class="std-progress-bar">
                <div class="std-progress-fill" style="width: 0%; background: ${data.risk_color}"></div>
            </div>
            <div class="std-result-stats">
                <span>✅ ${data.passed} pass</span>
                <span>❌ ${data.failed} fail</span>
                <span>📊 ${data.total} total</span>
            </div>
        `;
        container.appendChild(card);

        // Animate progress bar
        setTimeout(() => {
            card.querySelector('.std-progress-fill').style.width = data.percentage + '%';
        }, 200);
    }
}

// ===== Severity Bars =====
function renderSeverityBars(distribution) {
    const container = document.getElementById('severity-bars');
    container.innerHTML = '';

    const maxVal = Math.max(distribution.high || 0, distribution.medium || 0, distribution.low || 0, 1);
    const severities = [
        { key: 'high', label: 'High', color: '#ef4444' },
        { key: 'medium', label: 'Medium', color: '#eab308' },
        { key: 'low', label: 'Low', color: '#3b82f6' },
    ];

    for (const sev of severities) {
        const count = distribution[sev.key] || 0;
        const pct = (count / maxVal) * 100;
        const item = document.createElement('div');
        item.className = 'severity-bar-item fade-in';
        item.innerHTML = `
            <div class="severity-bar-label">${sev.label}</div>
            <div class="severity-bar-track">
                <div class="severity-bar-fill" style="height: 0%; background: ${sev.color}20; border: 2px solid ${sev.color}"></div>
            </div>
            <div class="severity-bar-count" style="color: ${sev.color}">${count}</div>
        `;
        container.appendChild(item);

        setTimeout(() => {
            item.querySelector('.severity-bar-fill').style.height = Math.max(pct, 5) + '%';
        }, 300);
    }
}

// ===== Rules Table =====
let allRules = [];

function renderRulesTable(rules) {
    allRules = rules;
    filterRules('all');

    // Setup filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterRules(btn.dataset.filter);
        });
    });
}

function filterRules(filter) {
    const tbody = document.getElementById('rules-tbody');
    tbody.innerHTML = '';

    const filtered = filter === 'all' ? allRules : allRules.filter(r => r.status === filter);

    for (const rule of filtered) {
        const statusIcon = {
            'PASS': '✅', 'FAIL': '❌', 'WARNING': '⚠️', 'ERROR': '🔴'
        }[rule.status] || '❓';

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="status-badge status-${rule.status}">${statusIcon} ${rule.status}</span></td>
            <td style="font-family: monospace; font-size: 0.82rem; color: var(--text-muted)">${rule.rule_id}</td>
            <td style="font-weight: 500; color: var(--text-primary)">${rule.title}</td>
            <td>${rule.standard}</td>
            <td><span class="severity-badge sev-${rule.severity}">${rule.severity}</span></td>
            <td class="rule-detail">${rule.reason || '—'}</td>
        `;
        tbody.appendChild(tr);
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr><td colspan="6" style="text-align: center; padding: 2rem; color: var(--text-muted)">
                No rules found for this filter.
            </td></tr>
        `;
    }
}

// ===== Reset UI =====
function resetUI() {
    selectedFile = null;
    fileInput.value = '';
    fileInfo.classList.add('hidden');
    dropZone.classList.remove('hidden');
    evaluateBtn.disabled = true;
    uploadSection.classList.remove('hidden');
    loadingSection.classList.add('hidden');
    resultsSection.classList.add('hidden');
    errorSection.classList.add('hidden');

    // Reset gauge
    document.getElementById('gauge-fill').style.strokeDashoffset = 534;
    document.getElementById('score-value').textContent = '0%';

    window.scrollTo({ top: 0, behavior: 'smooth' });
}
