/* =========================================================
   PhishingGuard frontend logic
   Talks to the Spring Boot backend at /api/emails/*
   No frameworks. No AI/ML calls anywhere in this file.
   ========================================================= */

const API_BASE = '/api/emails';

// ---------- Sample test emails (Section 24 of the spec) ----------
const SAMPLE_EMAILS = {
    safe: {
        senderEmail: 'newsletter@company.com',
        subject: 'Monthly Newsletter',
        emailBody: 'Hello,\nHere is your monthly newsletter.\nThank you for subscribing.'
    },
    suspicious: {
        senderEmail: 'support@example.com',
        subject: 'Important Security Notice',
        emailBody: 'Please review your account information.\nYou may need to verify your account.'
    },
    phishing: {
        senderEmail: 'security@paypa1-alert.com',
        subject: 'URGENT! Your Account Will Be Suspended',
        emailBody: 'Your account will be blocked immediately.\nClick the link below and verify your password, OTP and credit card information.\nhttp://192.168.10.5/verify'
    }
};

// ---------- Utility helpers ----------

function qs(id) { return document.getElementById(id); }

function showToast(message, type = '') {
    const toast = qs('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.className = 'toast show' + (type ? ' ' + type : '');
    setTimeout(() => { toast.className = 'toast'; }, 3500);
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return str
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
}

async function apiRequest(url, options = {}) {
    const response = await fetch(url, {
        headers: { 'Content-Type': 'application/json' },
        ...options
    });

    let body = null;
    try { body = await response.json(); } catch (e) { /* no body */ }

    if (!response.ok) {
        const message = body && (body.error || Object.values(body)[0]);
        throw new Error(message || 'Request failed (' + response.status + ')');
    }
    return body;
}

// ---------- Dashboard statistics (index.html) ----------

async function loadStatistics() {
    try {
        const stats = await apiRequest(API_BASE + '/statistics');
        qs('statTotal').textContent = stats.totalAnalyzed;
        qs('statSafe').textContent = stats.safe;
        qs('statSuspicious').textContent = stats.suspicious;
        qs('statPhishing').textContent = stats.phishing;
    } catch (err) {
        console.error('Failed to load statistics:', err);
    }
}

// ---------- Email Analysis Form (index.html) ----------

function clearFieldErrors() {
    ['senderEmail', 'subject', 'emailBody'].forEach(id => {
        const el = qs('err-' + id);
        if (el) el.textContent = '';
    });
}

function validateForm(data) {
    const errors = {};
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!data.senderEmail || !data.senderEmail.trim()) {
        errors.senderEmail = 'Please enter a sender email.';
    } else if (!emailPattern.test(data.senderEmail.trim())) {
        errors.senderEmail = 'Please enter a valid sender email.';
    }

    if (!data.subject || !data.subject.trim()) {
        errors.subject = 'Please enter an email subject.';
    }

    if (!data.emailBody || !data.emailBody.trim()) {
        errors.emailBody = 'Please enter the email body.';
    }

    return errors;
}

function displayResult(result) {
    const panel = qs('resultPanel');
    panel.classList.remove('hidden');

    const badge = qs('resultBadge');
    badge.textContent = result.classification;
    badge.className = 'result-badge ' + result.classification.toLowerCase();

    qs('scoreValue').textContent = result.riskScore;
    qs('explanationText').textContent = result.explanation;

    // Animate gauge: circumference = 2 * PI * 52 ≈ 326.7
    const circumference = 326.7;
    const offset = circumference - (result.riskScore / 100) * circumference;
    const gaugeFill = qs('gaugeFill');
    gaugeFill.style.strokeDashoffset = circumference;

    let gaugeColor = 'var(--safe)';
    if (result.classification === 'SUSPICIOUS') gaugeColor = 'var(--suspicious)';
    if (result.classification === 'PHISHING') gaugeColor = 'var(--phishing)';
    gaugeFill.style.stroke = gaugeColor;

    requestAnimationFrame(() => {
        setTimeout(() => { gaugeFill.style.strokeDashoffset = offset; }, 50);
    });

    const list = qs('indicatorsList');
    list.innerHTML = '';
    if (result.detectedIndicators && result.detectedIndicators.length > 0) {
        result.detectedIndicators.forEach(indicator => {
            const li = document.createElement('li');
            li.textContent = indicator;
            list.appendChild(li);
        });
    } else {
        const li = document.createElement('li');
        li.textContent = 'No phishing indicators detected';
        li.className = 'none';
        list.appendChild(li);
    }

    const recommendation = qs('recommendationText');
    if (result.classification === 'PHISHING') {
        recommendation.textContent = 'Recommendation: Do not click links or provide passwords, OTPs or financial information.';
    } else if (result.classification === 'SUSPICIOUS') {
        recommendation.textContent = 'Recommendation: Review the email carefully before responding or clicking any links.';
    } else {
        recommendation.textContent = 'Recommendation: No action needed, but always stay cautious with unexpected emails.';
    }

    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function initAnalyzeForm() {
    const form = qs('analyzeForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearFieldErrors();

        const data = {
            senderEmail: qs('senderEmail').value,
            subject: qs('subject').value,
            emailBody: qs('emailBody').value
        };

        const errors = validateForm(data);
        if (Object.keys(errors).length > 0) {
            Object.entries(errors).forEach(([field, message]) => {
                const el = qs('err-' + field);
                if (el) el.textContent = message;
            });
            return;
        }

        const btn = qs('analyzeBtn');
        btn.disabled = true;
        btn.textContent = 'Analyzing...';

        try {
            const result = await apiRequest(API_BASE + '/analyze', {
                method: 'POST',
                body: JSON.stringify(data)
            });
            displayResult(result);
            loadStatistics();
            showToast('Email analyzed successfully.', 'success');
        } catch (err) {
            showToast(err.message || 'Failed to analyze email.', 'error');
        } finally {
            btn.disabled = false;
            btn.textContent = 'Analyze Email';
        }
    });

    qs('clearBtn').addEventListener('click', () => {
        form.reset();
        clearFieldErrors();
        qs('resultPanel').classList.add('hidden');
    });

    document.querySelectorAll('[data-sample]').forEach(btn => {
        btn.addEventListener('click', () => {
            const sample = SAMPLE_EMAILS[btn.dataset.sample];
            if (!sample) return;
            qs('senderEmail').value = sample.senderEmail;
            qs('subject').value = sample.subject;
            qs('emailBody').value = sample.emailBody;
            clearFieldErrors();
        });
    });
}

// ---------- History Page (history.html) ----------

function classificationBadge(classification) {
    const cls = (classification || '').toLowerCase();
    return `<span class="badge ${cls}">${escapeHtml(classification)}</span>`;
}

async function loadHistory() {
    const tbody = qs('historyBody');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="7" class="empty-row">Loading history...</td></tr>';

    try {
        const history = await apiRequest(API_BASE);

        if (!history || history.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-row">No emails analyzed yet. Go to the Analyze Email page to get started.</td></tr>';
            return;
        }

        tbody.innerHTML = '';
        history.forEach(item => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="mono">#${item.id}</td>
                <td>${escapeHtml(item.senderEmail)}</td>
                <td>${escapeHtml(item.subject)}</td>
                <td class="mono">${item.riskScore} / 100</td>
                <td>${classificationBadge(item.classification)}</td>
                <td class="mono">${escapeHtml(item.analyzedAt)}</td>
                <td>
                    <div class="row-actions">
                        <button class="icon-btn" data-view="${item.id}">View</button>
                        <button class="icon-btn danger" data-delete="${item.id}">Delete</button>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });

        tbody.querySelectorAll('[data-view]').forEach(btn => {
            btn.addEventListener('click', () => viewDetails(btn.dataset.view));
        });
        tbody.querySelectorAll('[data-delete]').forEach(btn => {
            btn.addEventListener('click', () => deleteEntry(btn.dataset.delete));
        });

    } catch (err) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-row">Failed to load history.</td></tr>';
        showToast(err.message || 'Failed to load history.', 'error');
    }
}

async function viewDetails(id) {
    try {
        const item = await apiRequest(API_BASE + '/' + id);
        const modalBody = qs('modalBody');

        const indicatorsHtml = (item.detectedIndicators && item.detectedIndicators.length > 0)
            ? item.detectedIndicators.map(i => `&bull; ${escapeHtml(i)}`).join('<br>')
            : 'No phishing indicators detected';

        modalBody.innerHTML = `
            <div class="modal-row">
                <span class="label">Sender Email</span>
                <span class="value mono">${escapeHtml(item.senderEmail)}</span>
            </div>
            <div class="modal-row">
                <span class="label">Subject</span>
                <span class="value">${escapeHtml(item.subject)}</span>
            </div>
            <div class="modal-row">
                <span class="label">Risk Score</span>
                <span class="value mono">${item.riskScore} / 100</span>
            </div>
            <div class="modal-row">
                <span class="label">Classification</span>
                <span class="value">${classificationBadge(item.classification)}</span>
            </div>
            <div class="modal-row">
                <span class="label">Detected Indicators</span>
                <div class="value mono-block">${indicatorsHtml}</div>
            </div>
            <div class="modal-row">
                <span class="label">Explanation</span>
                <span class="value">${escapeHtml(item.explanation)}</span>
            </div>
            <div class="modal-row">
                <span class="label">Analyzed At</span>
                <span class="value mono">${escapeHtml(item.analyzedAt)}</span>
            </div>
        `;

        qs('modalOverlay').classList.remove('hidden');
    } catch (err) {
        showToast(err.message || 'Failed to load details.', 'error');
    }
}

async function deleteEntry(id) {
    if (!confirm('Delete this analysis record? This cannot be undone.')) return;

    try {
        await apiRequest(API_BASE + '/' + id, { method: 'DELETE' });
        showToast('Entry deleted.', 'success');
        loadHistory();
    } catch (err) {
        showToast(err.message || 'Failed to delete entry.', 'error');
    }
}

function initHistoryPage() {
    const refreshBtn = qs('refreshBtn');
    if (refreshBtn) refreshBtn.addEventListener('click', loadHistory);

    const modalClose = qs('modalClose');
    const modalOverlay = qs('modalOverlay');
    if (modalClose && modalOverlay) {
        modalClose.addEventListener('click', () => modalOverlay.classList.add('hidden'));
        modalOverlay.addEventListener('click', (e) => {
            if (e.target === modalOverlay) modalOverlay.classList.add('hidden');
        });
    }

    loadHistory();
}

// ---------- Page bootstrap ----------

document.addEventListener('DOMContentLoaded', () => {
    if (qs('statsGrid')) loadStatistics();
    if (qs('analyzeForm')) initAnalyzeForm();
    if (qs('historyBody')) initHistoryPage();
});
