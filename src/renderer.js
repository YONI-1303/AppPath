import './index.css';
import { marked } from 'marked';
import DOMPurify from 'dompurify';

const iconPaths = {
  overview: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  scan: '<path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3"/><path d="M4 12h16"/>',
  graph: '<circle cx="5" cy="6" r="2"/><circle cx="18" cy="5" r="2"/><circle cx="12" cy="18" r="2"/><path d="m7 6 9-1M6 8l5 8m6-9-4 9"/>',
  paths: '<circle cx="6" cy="18" r="2"/><circle cx="18" cy="6" r="2"/><path d="M8 18h3a3 3 0 0 0 3-3v-3a3 3 0 0 1 3-3h1"/>',
  reports: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M8 13h8M8 17h6"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="m19 15 2 1-2 3-2-1-2 1v2h-4v-2l-2-1-2 1-2-3 2-1v-2l-2-1 2-3 2 1 2-1V7h4v2l2 1 2-1 2 3-2 1Z"/>',
  shield: '<path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/><path d="m9 12 2 2 4-4"/>',
  upload: '<path d="M12 16V4m-4 4 4-4 4 4"/><path d="M4 16v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M8 13h8M8 17h6"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3"/>',
  alert: '<path d="m10 4-8 14a2 2 0 0 0 2 3h16a2 2 0 0 0 2-3L14 4a2 2 0 0 0-4 0Z"/><path d="M12 9v4m0 4h.01"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
  download: '<path d="M12 3v12m-5-5 5 5 5-5"/><path d="M5 17v4h14v-4"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  ai: '<path d="M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1m0-12.8-2.1 2.1m-8.6 8.6-2.1 2.1"/><circle cx="12" cy="12" r="5"/><path d="m10 12 1.4 1.4L14.5 10"/>',
  code: '<path d="m8 6-5 6 5 6m8-12 5 6-5 6m-2-16-4 20"/>',
  standards: '<path d="M12 3 4 7v5c0 5 3.5 8 8 9 4.5-1 8-4 8-9V7l-8-4Z"/><path d="m8 12 2.5 2.5L16 9"/>',
  validate: '<path d="m4 12 5 5L20 6"/><path d="M21 12a9 9 0 1 1-3-6.7"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M5.5 9A7 7 0 0 1 18 6l2 6M4 12l2 6a7 7 0 0 0 12.5-3"/>',
};

function icon(name) {
  return `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${iconPaths[name] || iconPaths.shield}</svg>`;
}
function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
function renderAiMarkdown(text) {
  // AI output is untrusted text. Convert Markdown to HTML, then sanitize it
  // before inserting it into the renderer.
  const markdownHtml = marked.parse(String(text ?? ''), {
    gfm: true,
    breaks: false,
  });
  return DOMPurify.sanitize(markdownHtml);
}

function formatSize(bytes = 0) {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
function formatDate(value = new Date()) {
  return new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
}

const navPages = [
  { id: 'overview', label: 'Overview' },
  { id: 'analyze', label: 'Analyze APK', tag: 'CORE' },
  { id: 'triage', label: 'Review desk', tag: 'NEW' },
  { id: 'graph', label: 'Security graph' },
  { id: 'paths', label: 'Attack paths' },
  { id: 'code', label: 'Code mapping' },
  { id: 'ai', label: 'AI Fix', tag: 'LOCAL' },
  { id: 'validate', label: 'Validation' },
  { id: 'standards', label: 'MASVS checklist' },
  { id: 'reports', label: 'Reports' },
];
let currentPage = 'overview';
let selectedFile = null;
let latestReport = null;
let scanHistory = [];
let busy = false;
let selectedFindingId = null;
let selectedFindingReportSha = '';
let findingSearchQuery = '';
let findingSeverityFilter = 'all';
let findingCategoryFilter = 'all';
let findingReviewFilter = 'all';
let notice = '';
let noticeType = 'warning';
let ollamaStatus = { checked: false, available: false, models: [], error: '' };
let aiTargetFindingId = '';
let aiSelectedModel = '';
let aiCodeSnippet = '';
let aiResult = '';
let aiBusy = false;
let codeMapStatus = '';
let codeMapResult = null;
let codeMapBusy = false;
let selectedJadxName = '';
let validationBaselineSha = '';
let validationResult = null;

function showNotice(message, type = 'warning') {
  notice = message;
  noticeType = type;
}
function noticeHTML() {
  if (!notice) return '';
  return `<div class="notice ${noticeType}">${icon(noticeType === 'success' ? 'check' : 'alert')}<span>${escapeHTML(notice)}</span></div>`;
}
function heading(title, subtitle, action = '') {
  return `<div class="page-heading"><div><div class="eyebrow">APP SECURITY WORKSPACE</div><h1>${title}</h1><p>${subtitle}</p></div>${action}</div>`;
}
function sevClass(severity) {
  return ['critical', 'high', 'medium', 'low', 'info'].includes(String(severity).toLowerCase()) ? String(severity).toLowerCase() : 'info';
}
const REVIEW_STATES = [
  ['unreviewed', 'Needs review'],
  ['confirmed', 'Confirmed issue'],
  ['false_positive', 'False positive'],
  ['accepted_risk', 'Accepted risk'],
  ['fix_pending_retest', 'Fix applied · retest needed'],
  ['resolved_verified', 'Resolved · manually verified'],
];
function reviewStatus(finding) {
  const status = String(finding?.review_status || 'unreviewed');
  return REVIEW_STATES.some(([value]) => value === status) ? status : 'unreviewed';
}
function reviewLabel(findingOrStatus) {
  const status = typeof findingOrStatus === 'string' ? findingOrStatus : reviewStatus(findingOrStatus);
  return REVIEW_STATES.find(([value]) => value === status)?.[1] || 'Needs review';
}
function reviewBadge(finding) {
  const status = reviewStatus(finding);
  return `<span class="review-badge review-${status}">${escapeHTML(reviewLabel(status))}</span>`;
}
function summaryCount(key) {
  return latestReport?.summary?.[key] ?? 0;
}
function uploadArea() {
  return `<div class="upload-zone ${selectedFile ? 'has-file' : ''}" id="dropzone">
    ${selectedFile ? `<div class="selected-file"><div class="file-badge">${icon('file')}</div><div class="file-info"><strong>${escapeHTML(selectedFile.name)}</strong><span>${formatSize(selectedFile.size)} · Selected locally</span></div><button class="text-button" data-action="remove-file">Remove</button></div>` : `<div class="upload-icon">${icon('upload')}</div><h3>Choose an Android APK</h3><p>Browse for a local .apk package to inspect.</p><button class="button secondary" data-action="browse">Browse APK files</button><div class="upload-meta">${icon('lock')} Local static analysis · APK is not executed</div>`}
  </div>`;
}
function metrics() {
  const total = latestReport?.summary?.total ?? 0;
  const scannedCount = scanHistory.length;
  return `<div class="metrics">
    <article class="metric"><div class="metric-label">Apps analyzed ${icon('file')}</div><div class="metric-value">${scannedCount}</div><div class="metric-foot">Completed local scans</div></article>
    <article class="metric"><div class="metric-label">Security findings ${icon('alert')}</div><div class="metric-value">${total}</div><div class="metric-foot">${latestReport ? 'Latest scan results' : 'No findings recorded'}</div></article>
    <article class="metric"><div class="metric-label">Candidate paths ${icon('paths')}</div><div class="metric-value">${latestReport?.candidate_paths?.length ?? 0}</div><div class="metric-foot">Rule-based review hypotheses</div></article>
    <article class="metric"><div class="metric-label">Analysis mode ${icon('lock')}</div><div class="metric-value small-value">Local</div><div class="metric-foot green">APK is never launched</div></article>
  </div>`;
}
function findingsTable(findings, limit = 8) {
  if (!findings?.length) return `<div class="empty-state compact"><div class="empty-icon">${icon('check')}</div><strong>No heuristic findings in this scan</strong><p>This does not prove the app is secure. Review the full analysis notes and test the app appropriately.</p></div>`;
  const rows = findings.slice(0, limit).map(f => `<tr><td><span class="severity ${sevClass(f.severity)}">${escapeHTML(String(f.severity).toUpperCase())}</span></td><td><button class="finding-title-button" data-finding-id="${escapeHTML(f.id)}">${escapeHTML(f.title)}</button><small>${escapeHTML(f.category)} · ${escapeHTML(f.id)} · View details</small></td><td class="evidence-cell">${escapeHTML(f.evidence)}</td><td>${reviewBadge(f)}${f.review_note ? `<small class="review-note-preview">${escapeHTML(f.review_note.slice(0, 110))}${f.review_note.length > 110 ? '…' : ''}</small>` : ''}</td></tr>`).join('');
  return `<div class="table-wrap"><table class="findings-table"><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Review status</th></tr></thead><tbody>${rows}</tbody></table></div>${findings.length > limit ? `<div class="table-foot">Showing ${limit} of ${findings.length} findings. Open the Analyze view for full results.</div>` : ''}`;
}

function filterFindings(findings = []) {
  const query = findingSearchQuery.trim().toLowerCase();
  return findings.filter(f => {
    if (findingSeverityFilter !== 'all' && String(f.severity).toLowerCase() !== findingSeverityFilter) return false;
    if (findingCategoryFilter !== 'all' && String(f.category) !== findingCategoryFilter) return false;
    if (findingReviewFilter !== 'all' && reviewStatus(f) !== findingReviewFilter) return false;
    if (!query) return true;
    return [f.id, f.rule_id, f.title, f.description, f.evidence, f.recommendation, f.category, f.severity, reviewLabel(f), f.review_note]
      .some(value => String(value || '').toLowerCase().includes(query));
  });
}
function findingsFilterPanel(report) {
  const categories = [...new Set((report.findings || []).map(f => String(f.category || 'Other')))].sort();
  const visible = filterFindings(report.findings || []);
  return `<div class="finding-filters">
    <label class="filter-search-label" for="finding-search">Search findings<input id="finding-search" class="field-control" type="search" placeholder="Search title, evidence, ID, recommendation…" value="${escapeHTML(findingSearchQuery)}" /></label>
    <label class="filter-select-label" for="finding-severity">Severity<select id="finding-severity" class="field-control">${[['all','All severities'],['critical','Critical'],['high','High'],['medium','Medium'],['low','Low'],['info','Info']].map(([value,label]) => `<option value="${value}" ${findingSeverityFilter === value ? 'selected' : ''}>${label}</option>`).join('')}</select></label>
    <label class="filter-select-label" for="finding-category">Category<select id="finding-category" class="field-control"><option value="all">All categories</option>${categories.map(category => `<option value="${escapeHTML(category)}" ${findingCategoryFilter === category ? 'selected' : ''}>${escapeHTML(category)}</option>`).join('')}</select></label>
    <label class="filter-select-label" for="finding-review">Review status<select id="finding-review" class="field-control"><option value="all" ${findingReviewFilter === 'all' ? 'selected' : ''}>All review states</option>${REVIEW_STATES.map(([value,label]) => `<option value="${value}" ${findingReviewFilter === value ? 'selected' : ''}>${escapeHTML(label)}</option>`).join('')}</select></label>
  </div><div id="filtered-findings"><div class="table-foot">Showing ${visible.length} of ${(report.findings || []).length} findings in this scan.</div>${findingsTable(visible, 500)}</div>`;
}
function updateFilteredFindings() {
  const wrapper = document.querySelector('#filtered-findings');
  if (!wrapper || !latestReport) return;
  const all = latestReport.findings || [];
  const visible = filterFindings(all);
  const table = visible.length
    ? findingsTable(visible, 500)
    : all.length
      ? `<div class="empty-state compact"><div class="empty-icon">${icon('search')}</div><strong>No findings match those filters</strong><p>Try a different search term, severity, category, or review state.</p></div>`
      : findingsTable([], 500);
  wrapper.innerHTML = `<div class="table-foot">Showing ${visible.length} of ${all.length} findings in this scan.</div>${table}`;
}
function severityBars() {
  if (!latestReport) return `<div class="severity-content"><div class="donut empty-donut"><div><strong>0</strong><span>findings</span></div></div><div class="legend"><div><i class="critical"></i>Critical <b>0</b></div><div><i class="high"></i>High <b>0</b></div><div><i class="medium"></i>Medium <b>0</b></div><div><i class="low"></i>Low <b>0</b></div></div></div>`;
  const total = Math.max(1, latestReport.summary.total || 0);
  const critical = summaryCount('critical'), high = summaryCount('high'), medium = summaryCount('medium'), low = summaryCount('low');
  const parts = [critical, high, medium, low];
  const colors = ['#fa687b', '#f4a25b', '#e8d06b', '#4ed4a8'];
  let angle = 0;
  const stops = parts.map((v, i) => { const start = angle; angle += v / total * 360; return `${colors[i]} ${start}deg ${angle}deg`; });
  const conic = latestReport.summary.total ? `conic-gradient(${stops.join(',')})` : 'conic-gradient(#29364e 0deg 360deg)';
  return `<div class="severity-content"><div class="donut" style="background:${conic}"><div><strong>${latestReport.summary.total}</strong><span>findings</span></div></div><div class="legend"><div><i class="critical"></i>Critical <b>${critical}</b></div><div><i class="high"></i>High <b>${high}</b></div><div><i class="medium"></i>Medium <b>${medium}</b></div><div><i class="low"></i>Low <b>${low}</b></div></div></div>`;
}
function overviewPage() {
  const status = latestReport ? `${escapeHTML(latestReport.app.file_name)} scanned successfully` : 'Static analysis engine is ready';
  const description = latestReport ? `${escapeHTML(latestReport.app.package_name)} · SHA-256 recorded · Review results below.` : 'Select an APK and run local static triage. No Android application is installed or executed.';
  return `${heading('Security overview', 'Inspect Android APKs, review evidence, and prioritize security findings.', `<button class="button primary" data-action="go-analyze">${icon('scan')} New analysis</button>`)}
    <div class="status-banner"><div class="status-icon">${icon('shield')}</div><div class="status-copy"><strong>${status}</strong><p>${description}</p></div><span class="status-pill"><span class="dot ${latestReport ? '' : 'pending'}"></span>${latestReport ? 'Scan complete' : 'Local engine'}</span></div>
    ${metrics()}
    <div class="content-grid"><section class="panel"><div class="panel-heading"><div><h2>Start an analysis</h2><p>Choose a package to inspect with local static analysis.</p></div><span class="step-label">APK TRIAGE</span></div>${uploadArea()}<div class="scan-actions"><span class="hint">${icon('lock')} Stays on this computer</span><button class="button primary" data-action="scan" ${busy ? 'disabled' : ''}>${busy ? 'Analyzing…' : 'Analyze APK →'}</button></div>${noticeHTML()}</section>
    <section class="panel severity-panel"><div class="panel-heading"><div><h2>Severity breakdown</h2><p>Based on the latest scan</p></div><span class="step-label">${latestReport ? 'LATEST SCAN' : 'NO SCANS'}</span></div>${severityBars()}<p class="panel-note">Permission and string matches are indicators, not proof of malicious behavior.</p></section></div>
    <section class="panel recent-panel"><div class="panel-heading"><div><h2>${latestReport ? 'Latest findings' : 'Recent analyses'}</h2><p>${latestReport ? `${escapeHTML(latestReport.app.file_name)} · ${formatDate(latestReport.scannedAt)}` : 'Your latest security assessments will appear here.'}</p></div>${latestReport ? '<button class="text-button" data-page="analyze">View full results →</button>' : ''}</div>${latestReport ? findingsTable(latestReport.findings, 5) : `<div class="empty-state"><div class="empty-icon">${icon('file')}</div><strong>No analyses yet</strong><p>Run the first scan to create your first report.</p><button class="button secondary" data-action="go-analyze">Analyze an APK</button></div>`}</section>`;
}
function analyzePage() {
  const report = latestReport;
  return `${heading('Analyze an APK', 'Inspect package metadata, permissions, exposed components, endpoint strings, and potential security indicators.', report ? '<button class="button secondary" data-action="export">'+icon('download')+' Export JSON report</button>' : '')}
    <div class="analysis-layout"><section class="panel analyze-panel"><div class="panel-heading"><div><h2>Select an Android package</h2><p>Static analysis only; selected APKs are not installed or run.</p></div><span class="step-label">LOCAL SCAN</span></div>${uploadArea()}<div class="scan-actions"><span class="hint">${icon('lock')} Maximum APK size: 100 MB</span><button class="button primary" data-action="scan" ${busy ? 'disabled' : ''}>${busy ? 'Analyzing…' : 'Run analysis →'}</button></div>${noticeHTML()}<div class="steps"><div class="step ${selectedFile ? 'active' : ''}"><b>1</b><span><strong>Select APK</strong><small>Choose a file</small></span></div><div class="step ${busy ? 'active' : ''}"><b>2</b><span><strong>Static scan</strong><small>Androguard</small></span></div><div class="step ${report ? 'active' : ''}"><b>3</b><span><strong>Review results</strong><small>Evidence and notes</small></span></div></div></section>
    <aside class="panel requirements"><div class="large-shield">${icon('shield')}</div><h2>What this scanner checks</h2><p>AppPath runs local static triage against the APK structure. It is an early screening tool, not a complete penetration test.</p><div class="requirement"><b>01</b><div><strong>Manifest and permissions</strong><small>Package details, SDK versions, requested permissions, and explicitly exported components.</small></div></div><div class="requirement"><b>02</b><div><strong>Code-string and crypto indicators</strong><small>HTTP URLs, possible secret patterns, and limited cipher/digest class or string references.</small></div></div><div class="privacy-note">${icon('lock')} Never install an unknown APK just to analyze it.</div></aside></div>
    ${report ? `<section class="panel results-panel"><div class="panel-heading"><div><h2>Scan results</h2><p>${escapeHTML(report.app.file_name)} · ${formatDate(report.scannedAt)}</p></div><span class="status-pill"><span class="dot"></span> Analysis complete</span></div><div class="result-meta-grid"><div><span>PACKAGE</span><strong>${escapeHTML(report.app.package_name)}</strong></div><div><span>VERSION</span><strong>${escapeHTML(report.app.version_name)} (${escapeHTML(report.app.version_code)})</strong></div><div><span>TARGET SDK</span><strong>${escapeHTML(report.app.target_sdk)}</strong></div><div><span>SHA-256</span><strong class="hash-value" title="${escapeHTML(report.app.sha256)}">${escapeHTML(report.app.sha256)}</strong></div></div><div class="result-summary"><div class="result-summary-count"><strong>${report.summary.total}</strong><span>Total indicators</span></div>${['critical','high','medium','low'].map(s => `<div><span class="severity ${s}">${s.toUpperCase()}</span><strong>${report.summary[s] || 0}</strong></div>`).join('')}</div><div class="result-section-title"><div><h3>Security findings</h3><p>Each item includes its supporting evidence and a suggested review action.</p></div></div>${findingsFilterPanel(report)}<div class="details-grid"><section><div class="result-section-title"><div><h3>Requested permissions (${report.permissions.length})</h3><p>As declared in the manifest.</p></div></div>${report.permissions.length ? `<div class="tag-list">${report.permissions.map(p => `<span class="data-tag">${escapeHTML(p)}</span>`).join('')}</div>` : '<p class="muted">No permissions extracted.</p>'}</section><section><div class="result-section-title"><div><h3>Components (${report.components.length})</h3><p>Activities, services, receivers, and providers.</p></div></div>${report.components.length ? `<div class="table-wrap"><table class="findings-table"><thead><tr><th>Type</th><th>Component</th><th>Exported</th></tr></thead><tbody>${report.components.slice(0,150).map(c => `<tr><td>${escapeHTML(c.type)}</td><td><strong>${escapeHTML(c.name)}</strong><small>Permission: ${escapeHTML(c.permission)}</small></td><td>${c.exported === true ? '<span class="severity medium">TRUE</span>' : c.exported === false ? 'False' : 'Default'}</td></tr>`).join('')}</tbody></table></div>` : '<p class="muted">No components extracted.</p>'}</section></div><div class="result-section-title"><div><h3>Endpoint strings (${report.urls.length})</h3><p>Extracted URL strings, with query parameters omitted.</p></div></div>${report.urls.length ? `<div class="endpoint-list">${report.urls.map(url => `<code>${escapeHTML(url)}</code>`).join('')}</div>` : '<p class="muted">No URL strings were extracted from DEX files.</p>'}<div class="analysis-notes"><h3>Scope and limitations</h3><ul>${report.analysis_notes.map(n => `<li>${escapeHTML(n)}</li>`).join('')}</ul></div></section>` : ''}`;
}
function candidatePathCards(paths = []) {
  if (!paths.length) return `<div class="empty-state compact"><div class="empty-icon">${icon('paths')}</div><strong>No candidate paths from current rules</strong><p>The scanner did not find one of its supported combinations. This is not proof that no attack path exists.</p></div>`;
  return `<div class="candidate-path-list">${paths.map(path => `<article class="candidate-path-card"><div class="candidate-path-head"><div><span class="placeholder-tag">${escapeHTML(path.confidence_label || 'Review candidate')}</span><h3>${escapeHTML(path.title)}</h3></div><span class="severity ${sevClass(path.severity)}">${escapeHTML(String(path.severity || 'info').toUpperCase())}</span></div><p>${escapeHTML(path.explanation)}</p><div class="candidate-steps">${(path.steps || []).map((step, index) => `<div class="candidate-step"><span class="candidate-step-number">${String(index + 1).padStart(2, '0')}</span><div><button class="finding-title-button" data-finding-id="${escapeHTML(step.finding_id)}">${escapeHTML(step.title)}</button><small>${escapeHTML(step.finding_id)} · ${escapeHTML(step.evidence)}</small></div></div>`).join('<div class="candidate-link">Possible relationship — validate manually</div>')}</div><div class="analysis-notes"><strong>Limitations</strong><p>${escapeHTML(path.limitations)}</p><strong>Recommended review</strong><p>${escapeHTML(path.recommendation)}</p></div></article>`).join('')}</div>`;
}
function findingDetailsModal() {
  if (!selectedFindingId || !latestReport) return '';
  const sourceReport = scanHistory.find(report => report.app?.sha256 === selectedFindingReportSha) || latestReport;
  const finding = sourceReport.findings?.find(item => item.id === selectedFindingId);
  if (!finding) return '';
  const relatedPaths = (sourceReport.candidate_paths || []).filter(item => (item.steps || []).some(step => step.finding_id === finding.id));
  const status = reviewStatus(finding);
  const statusOptions = REVIEW_STATES.map(([value, label]) => `<option value="${value}" ${status === value ? 'selected' : ''}>${escapeHTML(label)}</option>`).join('');
  const lastReviewed = finding.reviewed_at ? `Last saved ${formatDate(finding.reviewed_at)}` : 'Not reviewed yet';
  return `<div class="modal-backdrop" data-action="close-finding"><section class="finding-modal" role="dialog" aria-modal="true" aria-labelledby="finding-modal-title" data-modal-panel><div class="modal-head"><div><span class="eyebrow">FINDING DETAILS · ${escapeHTML(finding.id)}${sourceReport.app?.sha256 !== latestReport.app?.sha256 ? ' · HISTORICAL REPORT' : ''}</span><h2 id="finding-modal-title">${escapeHTML(finding.title)}</h2></div><button class="modal-close" aria-label="Close finding details" data-action="close-finding">×</button></div><div class="modal-meta"><span class="severity ${sevClass(finding.severity)}">${escapeHTML(String(finding.severity).toUpperCase())}</span><span class="step-label">${escapeHTML(finding.category)}</span>${reviewBadge(finding)}</div><div class="finding-detail-section"><h3>What the scanner observed</h3><p>${escapeHTML(finding.description)}</p></div><div class="finding-detail-section"><h3>Evidence</h3><pre>${escapeHTML(finding.evidence)}</pre></div><div class="finding-detail-section"><h3>Recommended action</h3><p>${escapeHTML(finding.recommendation)}</p></div><div class="finding-detail-section"><h3>OWASP MASVS topic mapping</h3><div class="tag-list">${(finding.masvs_groups || ['MASVS-CODE']).map(group => `<span class="data-tag">${escapeHTML(group)}</span>`).join('')}</div><p class="muted">Topic mapping only; this is not a verified MASVS control result.</p></div>${relatedPaths.length ? `<div class="finding-detail-section"><h3>Related candidate paths</h3>${relatedPaths.map(path => `<div class="related-path"><strong>${escapeHTML(path.title)}</strong><p>${escapeHTML(path.explanation)}</p><small>Review candidate only — not a confirmed exploit chain.</small></div>`).join('')}</div>` : ''}<section class="review-editor"><div class="review-editor-heading"><div><h3>Analyst review</h3><p>Record a human decision. This status is not assigned automatically by the scanner.</p></div><span class="review-saved-at">${escapeHTML(lastReviewed)}</span></div><label class="field-label" for="finding-review-status">Review outcome</label><select id="finding-review-status" class="field-control">${statusOptions}</select><label class="field-label" for="finding-review-note">Review note</label><textarea id="finding-review-note" class="field-control review-note-input" maxlength="3000" placeholder="Record why this is confirmed, a false positive, accepted risk, or what retest is needed…">${escapeHTML(finding.review_note || '')}</textarea><div class="review-editor-footer"><span>Saved with local scan history and included in exports.</span><button class="button primary" data-action="save-review" data-finding-id="${escapeHTML(finding.id)}">Save review</button></div></section><div class="modal-footer"><span>Static-analysis indicator · validate before concluding</span><div class="modal-actions"><button class="button secondary" data-action="map-code" data-finding-id="${escapeHTML(finding.id)}">Map source</button><button class="button primary" data-action="ai-fix" data-finding-id="${escapeHTML(finding.id)}">AI review</button><button class="button secondary" data-action="close-finding">Close</button></div></div></section></div>`;
}
function evidenceNetworkSvg(report) {
  const groups = new Map();
  (report.findings || []).forEach(f => {
    if (!groups.has(f.category)) groups.set(f.category, []);
    groups.get(f.category).push(f);
  });
  const entries = [...groups.entries()].slice(0, 6);
  if (!entries.length) return `<div class="empty-state compact"><strong>No nodes to display</strong><p>The scanner did not return findings for this APK.</p></div>`;
  const width = 1000;
  const laneStep = entries.length === 1 ? 0 : 900 / (entries.length - 1);
  const centers = entries.map((_, i) => entries.length === 1 ? width / 2 : 50 + i * laneStep);
  const maxRows = Math.max(1, ...entries.map(([, findings]) => Math.min(6, findings.length)));
  const height = 205 + maxRows * 61;
  const lines = [];
  const nodes = [];
  // APK root node.
  nodes.push(`<g class="network-root"><rect x="407" y="18" width="186" height="43" rx="10"/><text x="500" y="36" text-anchor="middle" class="network-root-title">ANDROID APK</text><text x="500" y="49" text-anchor="middle" class="network-root-sub">${escapeHTML(String(report.app.package_name || 'Unknown package').slice(0, 27))}</text></g>`);
  entries.forEach(([category, findings], col) => {
    const x = centers[col];
    lines.push(`<line class="network-edge" x1="500" y1="61" x2="${x}" y2="112"/>`);
    nodes.push(`<g class="network-category"><rect x="${x - 70}" y="112" width="140" height="35" rx="8"/><text x="${x}" y="133" text-anchor="middle">${escapeHTML(String(category).slice(0, 22))}</text><title>${escapeHTML(category)} · ${findings.length} finding(s)</title></g>`);
    findings.slice(0, 6).forEach((finding, row) => {
      const top = 178 + row * 61;
      lines.push(`<line class="network-edge faint" x1="${x}" y1="147" x2="${x}" y2="${top}"/>`);
      const label = String(finding.title || 'Finding');
      const shortLabel = label.length > 22 ? `${label.slice(0, 20)}…` : label;
      nodes.push(`<g class="network-finding" data-finding-id="${escapeHTML(finding.id)}" role="button" tabindex="0" aria-label="Open ${escapeHTML(label)} details"><rect x="${x - 70}" y="${top}" width="140" height="47" rx="7" class="network-card ${sevClass(finding.severity)}"/><circle cx="${x - 57}" cy="${top + 15}" r="3.4" class="network-dot ${sevClass(finding.severity)}"/><text x="${x - 48}" y="${top + 18}" class="network-severity">${escapeHTML(String(finding.severity).toUpperCase())}</text><text x="${x - 61}" y="${top + 33}" class="network-title">${escapeHTML(shortLabel)}</text><title>${escapeHTML(label)} · ${escapeHTML(finding.id)}. Click for evidence.</title></g>`);
    });
    if (findings.length > 6) nodes.push(`<text x="${x}" y="${height - 12}" text-anchor="middle" class="network-more">+${findings.length - 6} more in results</text>`);
  });
  const omitted = Math.max(0, groups.size - entries.length);
  return `<div class="network-graph-wrap"><svg class="network-graph" viewBox="0 0 ${width} ${height}" role="img" aria-label="Interactive graph connecting the APK to finding categories and findings"><g>${lines.join('')}</g><g>${nodes.join('')}</g></svg></div><div class="graph-key"><span><i class="critical"></i> Critical</span><span><i class="high"></i> High</span><span><i class="medium"></i> Medium</span><span><i class="low"></i> Low</span><span>Click a finding node to inspect its evidence.</span></div>${omitted ? `<p class="muted">Only the first six categories are drawn. Full findings remain in the Analyze view.</p>` : ''}`;
}
function graphPage() {
  if (!latestReport) return `${heading('Security graph', 'Explore the APK → category → finding evidence map.')}${emptyWorkspace('No scan data yet', 'Run a real APK analysis first. The graph will render nodes from findings returned by the scanner.', 'analyze')}`;
  return `${heading('Security graph', 'Explore an interactive map built from the latest scan’s evidence.', '<button class="button secondary" data-page="paths">Review candidate paths →</button>')}
    <section class="panel"><div class="panel-heading"><div><h2>Evidence relationship graph</h2><p>Lines represent a hierarchy of evidence grouping, not a verified attack path or runtime flow.</p></div><span class="step-label">${latestReport.findings.length} FINDINGS</span></div>${evidenceNetworkSvg(latestReport)}
      <div class="analysis-notes"><p>Finding nodes open their exact evidence and recommendations. Candidate attack-path hypotheses are shown separately and require manual validation.</p></div></section>
    <section class="panel paths-panel"><div class="panel-heading"><div><h2>Candidate relationships</h2><p>Conservative rule-based combinations with linked evidence.</p></div><span class="step-label">${(latestReport.candidate_paths || []).length} CANDIDATES</span></div>${candidatePathCards(latestReport.candidate_paths || [])}</section>`;
}
function pathsPage() {
  const paths = latestReport?.candidate_paths || [];
  return `${heading('Attack paths', 'Evidence-linked candidate relationships for manual security review.')}
    ${latestReport ? `<section class="panel paths-panel"><div class="panel-heading"><div><h2>Candidate paths</h2><p>Generated only when specific static indicators co-occur. They are hypotheses, not verified exploit chains.</p></div><span class="step-label">${paths.length} CANDIDATES</span></div>${candidatePathCards(paths)}<div class="analysis-notes"><h3>How to interpret these results</h3><ul><li>Each step links to an actual finding ID and its extracted evidence.</li><li>The scanner does not establish runtime reachability or prove that an attacker can exploit a chain.</li><li>Absence of a candidate path does not prove the app is safe.</li></ul></div></section>` : `<section class="panel placeholder"><div class="placeholder-icon">${icon('paths')}</div><span class="placeholder-tag">SCAN REQUIRED</span><h2>Run a scan before evaluating candidate paths</h2><p>The rule engine will correlate a small set of supported indicator combinations and show their evidence. It will not fabricate paths to fill the page.</p><div class="placeholder-steps"><div><span>01</span>Collect static findings</div><div><span>02</span>Apply conservative correlation rules</div><div><span>03</span>Review evidence and validate manually</div></div><button class="button primary" data-action="go-analyze">Go to APK analysis →</button></section>`}`;
}
function reviewDeskPage() {
  if (!latestReport) return `${heading('Review desk', 'Track manual decisions and notes for each static-analysis finding.')}${emptyWorkspace('Run a scan before triage', 'The Review Desk gives every finding a recorded human review state, with notes saved locally.', 'analyze')}`;
  const findings = latestReport.findings || [];
  const countFor = status => findings.filter(f => reviewStatus(f) === status).length;
  const reviewed = findings.length - countFor('unreviewed');
  const filtered = filterFindings(findings);
  const ordered = [...filtered].sort((a, b) => {
    const sev = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const bySeverity = (sev[String(a.severity).toLowerCase()] ?? 5) - (sev[String(b.severity).toLowerCase()] ?? 5);
    if (bySeverity) return bySeverity;
    return (REVIEW_STATES.findIndex(([v]) => v === reviewStatus(a))) - (REVIEW_STATES.findIndex(([v]) => v === reviewStatus(b)));
  });
  return `${heading('Review desk', 'Turn automated indicators into a documented human-reviewed assessment.', '<button class="button secondary" data-page="reports">Reports & exports →</button>')}
    <div class="status-banner"><div class="status-icon">${icon('review')}</div><div class="status-copy"><strong>${reviewed} of ${findings.length} findings reviewed</strong><p>These states are analyst decisions, not scanner verdicts. “Resolved” is an explicit manual attestation.</p></div><span class="status-pill"><span class="dot ${reviewed === findings.length ? '' : 'pending'}"></span>${findings.length ? Math.round(reviewed / findings.length * 100) : 0}% reviewed</span></div>
    <div class="triage-summary"><article class="metric"><div class="metric-label">Needs review</div><div class="metric-value">${countFor('unreviewed')}</div><div class="metric-foot">Awaiting human assessment</div></article><article class="metric"><div class="metric-label">Confirmed issues</div><div class="metric-value">${countFor('confirmed')}</div><div class="metric-foot">Marked by reviewer</div></article><article class="metric"><div class="metric-label">False positives</div><div class="metric-value">${countFor('false_positive')}</div><div class="metric-foot">Requires documented reasoning</div></article><article class="metric"><div class="metric-label">Fix / retest / resolved</div><div class="metric-value">${countFor('fix_pending_retest') + countFor('resolved_verified')}</div><div class="metric-foot">Manual status tracking</div></article></div>
    <section class="panel"><div class="panel-heading"><div><h2>Finding review queue</h2><p>${escapeHTML(latestReport.app.file_name)} · SHA-256 ${escapeHTML(String(latestReport.app.sha256 || '').slice(0, 18))}…</p></div><span class="step-label">LATEST SCAN</span></div>
      ${findingsFilterPanel({ ...latestReport, findings: ordered })}
      <div class="analysis-notes"><strong>How to triage</strong><p>Open a finding, select a review outcome, add a short reason or next step, then click Save review. Review metadata is stored locally with the report and included in exports. A finding disappearing from a later scan does not automatically change its review status.</p></div>
    </section>`;
}

function reportsPage() {
  const history = scanHistory.length ? `<div class="history-list">${scanHistory.map((report, index) => `<article class="history-card"><div class="report-icon">${icon('file')}</div><div class="report-info"><strong>${escapeHTML(report.app.file_name)}</strong><span>${escapeHTML(report.app.package_name)} · ${formatDate(report.scannedAt)}</span><small>${report.summary?.total ?? report.findings.length} indicators · SHA-256 ${escapeHTML(String(report.app.sha256 || '').slice(0, 16))}…</small></div><div class="history-actions"><button class="button secondary" data-action="open-history" data-history-sha="${escapeHTML(report.app.sha256 || '')}">Open</button>${index === 0 ? '<span class="history-latest">LATEST</span>' : ''}</div></article>`).join('')}</div>` : `<div class="empty-state"><div class="empty-icon">${icon('file')}</div><strong>No report yet</strong><p>Run an analysis first. Scan history will be saved on this computer.</p><button class="button secondary" data-action="go-analyze">Analyze an APK</button></div>`;
  return `${heading('Reports', 'Review scan history and export security findings.')}
    <section class="panel"><div class="panel-heading"><div><h2>Latest report</h2><p>Exports contain the saved analysis evidence and documented limitations.</p></div>${latestReport ? `<div class="export-actions"><button class="button secondary" data-action="export" data-format="csv">${icon('download')} Export CSV</button><button class="button primary" data-action="export" data-format="json">${icon('download')} Export JSON</button><button class="button secondary" data-action="export" data-format="sarif">${icon('download')} Export SARIF</button><button class="button secondary" data-action="export" data-format="html">${icon('file')} HTML / PDF</button></div>` : ''}</div>${latestReport ? `<div class="report-card"><div class="report-icon">${icon('file')}</div><div class="report-info"><strong>${escapeHTML(latestReport.app.file_name)}</strong><span>${escapeHTML(latestReport.app.package_name)} · ${formatDate(latestReport.scannedAt)}</span><small>${latestReport.summary.total} indicators · SHA-256 ${escapeHTML(latestReport.app.sha256.slice(0, 20))}…</small></div><span class="status-pill"><span class="dot"></span> Available</span></div>` : ''}</section>
    <section class="panel history-panel"><div class="panel-heading"><div><h2>Saved scan history</h2><p>${scanHistory.length} scan record(s) stored locally and restored when AppPath opens.</p></div><span class="step-label">LOCAL HISTORY</span></div>${history}<div class="analysis-notes"><p>History is saved under Electron's user data folder on this computer. It is not uploaded to Supabase or a remote service. Reports can contain package metadata and security findings, so keep exported files private.</p></div>${noticeHTML()}</section>`;
}
function settingsPage() {
  return `${heading('Settings', 'Local configuration and scanner status.')}
    <section class="panel settings-list"><div class="panel-heading"><div><h2>Analysis environment</h2><p>Prototype configuration</p></div><span class="status-pill"><span class="dot"></span> Local-first</span></div><div class="setting-row"><div><strong>Python backend</strong><small>Uses the Python command available on this Windows computer.</small></div><span class="setting-value">python</span></div><div class="setting-row"><div><strong>Static APK parser</strong><small>Androguard must be installed using requirements.txt.</small></div><span class="setting-value">Androguard 4.1.4</span></div><div class="setting-row"><div><strong>Maximum APK size</strong><small>Limit chosen to reduce memory pressure on this machine.</small></div><span class="setting-value">100 MB</span></div><div class="setting-row"><div><strong>Cloud database</strong><small>Scan data is not sent to Supabase or a remote analysis service.</small></div><span class="setting-value">Not used</span></div><div class="analysis-notes"><h3>Current limitations</h3><ul><li>Static triage only; no dynamic execution or emulation.</li><li>Findings are heuristic indicators and must be validated.</li><li>Graph presents an APK-to-category-to-finding evidence hierarchy; candidate paths use conservative correlation rules and are not verified exploit chains.</li><li>Local AI can explain a selected finding only if Ollama and a model are installed; AI suggestions are not verified fixes.</li><li>JADX source mapping is optional and keyword-based; matching a source line does not establish reachability or taint flow.</li><li>Validation compares findings between scans; a missing indicator means 'not detected in this scan', not proof the issue is fixed.</li></ul></div></section>`;
}

function allMasvsGroups(report) {
  return report?.masvs_assessment?.length
    ? report.masvs_assessment
    : ['MASVS-STORAGE','MASVS-CRYPTO','MASVS-AUTH','MASVS-NETWORK','MASVS-PLATFORM','MASVS-CODE','MASVS-RESILIENCE','MASVS-PRIVACY'].map(group => {
        const ids = (report?.findings || []).filter(f => (f.masvs_groups || []).includes(group)).map(f => f.id);
        return { group, status: ids.length ? 'indicators-found' : 'no-supported-indicator-found', finding_ids: ids, note: 'Topic mapping only; not a control verification.' };
      });
}
function standardsPage() {
  if (!latestReport) return `${heading('MASVS checklist', 'Use OWASP MASVS categories to organize the static triage scope.')}${emptyWorkspace('Run an APK scan first', 'The checklist will map findings to broad OWASP mobile security topic groups. It will not claim compliance.', 'analyze')}`;
  const groups = allMasvsGroups(latestReport);
  return `${heading('MASVS checklist', 'A coverage map of broad OWASP mobile security topic groups.', '<button class="button secondary" data-action="export" data-format="json">Export evidence →</button>')}
    <div class="status-banner"><div class="status-icon">${icon('standards')}</div><div class="status-copy"><strong>Static topic mapping — not certification</strong><p>AppPath only checks a limited set of APK manifest and DEX indicators. No group can be marked compliant by this prototype.</p></div><span class="status-pill"><span class="dot pending"></span> Partial coverage</span></div>
    <section class="panel"><div class="panel-heading"><div><h2>OWASP MASVS topic groups</h2><p>Open a group to review the findings mapped to it.</p></div><span class="step-label">${groups.length} GROUPS</span></div>
    <div class="masvs-grid">${groups.map(item => {
      const count = (latestReport.findings || []).filter(f => (f.masvs_groups || []).includes(item.group)).length;
      const has = count > 0;
      return `<article class="masvs-card"><div class="masvs-card-head"><span class="masvs-icon">${icon('standards')}</span><span class="status-pill ${has ? 'masvs-alert' : ''}">${has ? `${count} indicator(s)` : 'No supported indicator'}</span></div><h3>${escapeHTML(item.group)}</h3><p>${escapeHTML(({ 'MASVS-STORAGE':'Data at rest, secrets and sensitive local data','MASVS-CRYPTO':'Cryptographic algorithms and key handling','MASVS-AUTH':'Authentication and authorization (limited checks)','MASVS-NETWORK':'Transport security and endpoint indicators','MASVS-PLATFORM':'Manifest, permissions and component exposure','MASVS-CODE':'Code quality and security-sensitive patterns','MASVS-RESILIENCE':'Reverse-engineering and tampering resistance (not assessed here)','MASVS-PRIVACY':'Permissions and privacy-related indicators' })[item.group] || 'Mobile security topic group')}</p><small>${has ? 'Findings mapped to this topic:' : 'No supported indicator was found. This is not a pass.'}</small>${has ? `<div class="masvs-finding-list">${latestReport.findings.filter(f => (f.masvs_groups || []).includes(item.group)).slice(0,5).map(f => `<button class="finding-title-button" data-finding-id="${escapeHTML(f.id)}">${escapeHTML(f.title)}</button>`).join('')}${count > 5 ? `<span class="muted">+${count-5} more</span>` : ''}</div>` : ''}</article>`;
    }).join('')}</div>
    <div class="analysis-notes"><strong>How to cite this screen in the project report</strong><p>“AppPath maps selected static findings to broad OWASP MASVS topic groups as a navigation aid. It does not implement all MASVS/MASTG tests and does not establish compliance.”</p></div></section>`;
}

async function refreshOllamaStatus(shouldRender = true) {
  ollamaStatus = { ...ollamaStatus, checked: true };
  if (shouldRender) { showNotice('Checking the local Ollama service…', 'success'); render(); }
  try {
    const result = await window.appPathAPI?.getOllamaStatus?.();
    ollamaStatus = { checked: true, available: Boolean(result?.available), models: Array.isArray(result?.models) ? result.models : [], error: result?.error || '' };
    if (ollamaStatus.models.length && (!ollamaStatus.models.some(m => m.name === aiSelectedModel))) {
      aiSelectedModel = ollamaStatus.models.find(m => m.name.toLowerCase().endsWith(':cloud'))?.name || ollamaStatus.models[0].name;
    }
  } catch (error) {
    ollamaStatus = { checked: true, available: false, models: [], error: error?.message || 'Could not query local Ollama.' };
  }
  if (shouldRender) { notice = ''; render(); }
}

function aiPage() {
  if (!latestReport) return `${heading('AI remediation', 'Use a small local model or Ollama Cloud to explain Android security findings.')}${emptyWorkspace('Scan an APK first', 'Choose a finding and request an explanation after a scan.', 'analyze')}`;
  const findings = latestReport.findings || [];
  if (findings.length && !findings.some(f => f.id === aiTargetFindingId)) aiTargetFindingId = findings[0].id;
  const selected = findings.find(f => f.id === aiTargetFindingId) || findings[0];
  const selectedCloud = String(aiSelectedModel || '').toLowerCase().endsWith(':cloud');
  const modelOptions = ollamaStatus.models.map(m => {
    const cloud = Boolean(m.isCloud) || String(m.name).toLowerCase().endsWith(':cloud');
    const label = cloud ? `${m.name} · CLOUD / internet` : `${m.name}${m.size ? ` · ${(m.size / (1024 ** 3)).toFixed(1)} GB` : ''}`;
    return `<option value="${escapeHTML(m.name)}" ${m.name === aiSelectedModel ? 'selected' : ''}>${escapeHTML(label)}</option>`;
  }).join('');
  const availability = !ollamaStatus.checked
    ? `<div class="notice">${icon('alert')}<span>Ollama connection has not been checked yet. Click Refresh Ollama models.</span></div>`
    : ollamaStatus.available
      ? `<div class="notice success">${icon('check')}<span>Ollama is reachable. Choose a local model or gemma4:cloud; the cloud option requires internet and Ollama sign-in.</span></div>`
      : `<div class="notice">${icon('alert')}<span>Ollama is not responding at 127.0.0.1:11434. Open Ollama and click Refresh Ollama models.</span></div>`;
  const privacy = selectedCloud
    ? `<div class="notice">${icon('alert')}<span><strong>Cloud privacy:</strong> The selected finding details, package name/version, and optional code snippet will be sent to Ollama Cloud for inference. The APK file itself is not sent by AppPath. Remove passwords, tokens, personal data, and proprietary snippets before using this mode.</span></div>`
    : `<div class="notice success">${icon('lock')}<span><strong>Local model:</strong> Prompts are sent to your local Ollama service. They stay on this computer unless the selected model is a cloud model.</span></div>`;
  return `${heading('AI remediation', 'Ask an Ollama model to explain a finding and suggest defensive changes.', '<button class="button secondary" data-action="refresh-ai">'+icon('refresh')+' Refresh Ollama models</button>')}
    ${availability}${privacy}${noticeHTML()}
    <div class="ai-layout"><section class="panel"><div class="panel-heading"><div><h2>Choose a finding</h2><p>AppPath sends selected finding metadata, package details, and your optional code snippet. It does not send the complete APK.</p></div><span class="step-label">${selectedCloud ? 'OLLAMA CLOUD' : 'LOCAL MODEL'}</span></div>
      <label class="field-label" for="ai-finding-select">Finding</label><select id="ai-finding-select" class="field-control">${findings.map(f => `<option value="${escapeHTML(f.id)}" ${f.id === aiTargetFindingId ? 'selected' : ''}>${escapeHTML(f.severity.toUpperCase())} · ${escapeHTML(f.title)}</option>`).join('')}</select>
      <div class="ai-selected-finding"><span class="severity ${sevClass(selected.severity)}">${escapeHTML(selected.severity.toUpperCase())}</span><h3>${escapeHTML(selected.title)}</h3><p>${escapeHTML(selected.description)}</p><pre>${escapeHTML(selected.evidence)}</pre></div>
      <label class="field-label" for="ai-code-snippet">Relevant Java/Kotlin source (optional)</label><textarea id="ai-code-snippet" class="field-control code-textarea" maxlength="8000" placeholder="Paste a short relevant snippet from source or decompiled code. Remove live tokens or personal data first.">${escapeHTML(aiCodeSnippet)}</textarea>
      <label class="field-label" for="ai-model">Ollama model</label><select id="ai-model" class="field-control" ${ollamaStatus.models.length ? '' : 'disabled'}>${modelOptions || '<option value="">No model option available</option>'}</select>
      <div class="scan-actions"><span class="hint">${icon(selectedCloud ? 'alert' : 'lock')} ${selectedCloud ? 'Cloud request · internet required' : 'Local inference selected'}</span><button class="button primary" data-action="run-ai" ${aiBusy || !ollamaStatus.available || !ollamaStatus.models.length ? 'disabled' : ''}>${aiBusy ? 'Generating response…' : 'Explain & suggest a fix →'}</button></div>
      ${aiResult ? `<div class="ai-output"><div class="panel-heading"><div><h2>Model response</h2><p>Formatted response · review and test changes in the original source project.</p></div><button class="text-button" data-action="clear-ai">Clear</button></div><div class="ai-markdown">${renderAiMarkdown(aiResult)}</div></div>` : `<div class="analysis-notes"><p>AI output is advisory. It cannot establish whether a vulnerability is exploitable, and it cannot verify a fix. If source is not provided, AppPath tells the model not to invent code or line numbers.</p></div>`}
    </section><aside class="panel requirements"><div class="large-shield">${icon(selectedCloud ? 'alert' : 'lock')}</div><h2>Data handling</h2><div class="requirement"><b>01</b><div><strong>${selectedCloud ? 'Ollama Cloud selected' : 'Local model selected'}</strong><small>${selectedCloud ? 'Requests are routed by the signed-in local Ollama service to Ollama Cloud. Internet access is required.' : 'Prompts are processed by the local model on this computer.'}</small></div></div><div class="requirement"><b>02</b><div><strong>Data minimization</strong><small>Only finding details, package name/version, and the optional snippet are sent, not the APK itself.</small></div></div><div class="requirement"><b>03</b><div><strong>Human review</strong><small>Validate suggestions, run tests, and re-scan a rebuilt APK before claiming remediation.</small></div></div></aside></div>`;
}

function codeMappingPage() {
  if (!latestReport) return `${heading('Vulnerable-code mapping', 'Connect static findings to relevant Java/Kotlin source where possible.')}${emptyWorkspace('Scan an APK first', 'Run a scan so AppPath has findings to correlate against decompiled source.', 'analyze')}`;
  const matches = codeMapResult?.matches || [];
  return `${heading('Vulnerable-code mapping', 'Optional JADX integration; keyword matches are contextual hints, not data-flow proof.', '<button class="button secondary" data-action="select-jadx">${icon(\'code\')} Locate JADX</button>')}
    <section class="panel"><div class="panel-heading"><div><h2>Decompile and map the selected APK</h2><p>JADX is optional. AppPath never installs or executes the APK, but decompilers process untrusted file structures so only analyze packages you are authorized to inspect.</p></div><span class="step-label">OPTIONAL TOOL</span></div>
      <div class="steps"><div class="step active"><b>1</b><span><strong>Choose APK</strong><small>${selectedFile ? escapeHTML(selectedFile.name) : 'Select it in Analyze APK'}</small></span></div><div class="step ${selectedJadxName ? 'active' : ''}"><b>2</b><span><strong>Locate JADX CLI</strong><small>${selectedJadxName ? escapeHTML(selectedJadxName) : 'Not configured'}</small></span></div><div class="step ${codeMapResult ? 'active' : ''}"><b>3</b><span><strong>Search source</strong><small>${codeMapResult ? `${matches.length} match(es)` : 'Waiting'}</small></span></div></div>
      <div class="scan-actions"><span class="hint">${icon('lock')} Output stays in the local user-data folder</span><button class="button primary" data-action="decompile-map" ${codeMapBusy || !selectedFile ? 'disabled' : ''}>${codeMapBusy ? 'Decompiling and mapping…' : 'Decompile & map findings →'}</button></div>
      ${codeMapStatus ? `<div class="notice ${codeMapResult ? 'success' : ''}">${icon(codeMapResult ? 'check' : 'alert')}<span>${escapeHTML(codeMapStatus)}</span></div>` : ''}
      ${codeMapResult ? `<div class="analysis-notes"><p>${codeMapResult.files_scanned} files and ${(codeMapResult.bytes_scanned / (1024*1024)).toFixed(1)} MiB of text searched. Output folder: ${escapeHTML(codeMapResult.outputDir || '')}</p><ul>${(codeMapResult.notes || []).map(note => `<li>${escapeHTML(note)}</li>`).join('')}</ul></div>${matches.length ? `<div class="table-wrap"><table class="findings-table"><thead><tr><th>Finding</th><th>Source location</th><th>Matched line</th></tr></thead><tbody>${matches.map(match => `<tr><td><button class="finding-title-button" data-finding-id="${escapeHTML(match.finding_id)}">${escapeHTML(match.finding_title)}</button><small>${escapeHTML(match.finding_id)} · term: ${escapeHTML(match.matched_term)}</small></td><td><code>${escapeHTML(match.file)}:${match.line}</code></td><td class="evidence-cell"><code>${escapeHTML(match.snippet)}</code></td></tr>`).join('')}</tbody></table></div>` : `<div class="empty-state compact"><strong>No keyword match found</strong><p>No matching source line was found using the current mapping rules. This is not evidence that the finding is false.</p></div>`}` : `<div class="analysis-notes"><h3>Setup instructions</h3><ul><li>Download JADX from its official GitHub releases and extract it.</li><li>Use “Locate JADX” to pick the command-line launcher, usually <code>bin\jadx.bat</code> on Windows.</li><li>Select the APK in Analyze APK first, then run decompile and map.</li></ul></div>`}
    </section>`;
}

function findingKey(f) {
  return [f.category || '', f.title || '', f.evidence || ''].map(v => String(v).toLowerCase().replace(/\s+/g, ' ').trim()).join('::');
}
function compareReports(baseline, current) {
  const base = baseline?.findings || [];
  const now = current?.findings || [];
  const currentKeys = new Set(now.map(findingKey));
  const baselineKeys = new Set(base.map(findingKey));
  return {
    baseline: baseline?.app?.sha256,
    current: current?.app?.sha256,
    sameHash: baseline?.app?.sha256 === current?.app?.sha256,
    resolved: base.filter(f => !currentKeys.has(findingKey(f))),
    newFindings: now.filter(f => !baselineKeys.has(findingKey(f))),
    persistent: now.filter(f => baselineKeys.has(findingKey(f))),
  };
}
function validationPage() {
  if (!latestReport) return `${heading('Remediation validation', 'Compare scan results before and after a developer change.')}${emptyWorkspace('Run an APK scan first', 'Build or obtain a changed APK after applying a fix, then scan that package to compare indicators.', 'analyze')}`;
  const baselines = scanHistory.filter(report => report.app?.sha256 !== latestReport.app.sha256);
  const defaultBaseline = baselines.find(report => report.app?.package_name === latestReport.app.package_name) || baselines[0];
  if (!validationBaselineSha && defaultBaseline) validationBaselineSha = defaultBaseline.app.sha256;
  const baseline = baselines.find(report => report.app?.sha256 === validationBaselineSha) || defaultBaseline;
  const diff = validationResult && baseline && validationResult.baseline === baseline.app.sha256 && validationResult.current === latestReport.app.sha256 ? validationResult : null;
  return `${heading('Remediation validation', 'Compare findings from a baseline scan with a later scan of a rebuilt APK.')}
    <section class="panel"><div class="panel-heading"><div><h2>Choose baseline and current report</h2><p>Current report: ${escapeHTML(latestReport.app.file_name)} · ${escapeHTML(String(latestReport.app.sha256).slice(0,16))}…</p></div><span class="step-label">SCAN DIFFERENCE</span></div>
      <label class="field-label" for="baseline-report">Baseline scan</label><select id="baseline-report" class="field-control" ${baselines.length ? '' : 'disabled'}>${baselines.map(r => `<option value="${escapeHTML(r.app.sha256)}" ${r.app.sha256 === (baseline?.app.sha256 || '') ? 'selected' : ''}>${escapeHTML(r.app.file_name)} · ${escapeHTML(r.app.package_name)} · ${formatDate(r.scannedAt)} · ${String(r.app.sha256).slice(0,8)}…</option>`).join('') || '<option value="">No earlier distinct scan</option>'}</select>
      <div class="scan-actions"><span class="hint">${icon('check')} Scans should be of the same package after a source change</span><button class="button primary" data-action="run-validation" ${!baseline ? 'disabled' : ''}>Compare scans →</button></div>
      ${diff ? diff.sameHash ? `<div class="notice">${icon('alert')}<span>Both reports have the same APK SHA-256. This is not a changed build; comparison cannot validate remediation.</span></div>` : `<div class="validation-summary"><div class="metric"><div class="metric-label">No longer detected</div><div class="metric-value">${diff.resolved.length}</div><div class="metric-foot">Indicators absent from current scan</div></div><div class="metric"><div class="metric-label">New indicators</div><div class="metric-value">${diff.newFindings.length}</div><div class="metric-foot">Only in current scan</div></div><div class="metric"><div class="metric-label">Still detected</div><div class="metric-value">${diff.persistent.length}</div><div class="metric-foot">Matched by category/title/evidence</div></div></div><div class="analysis-notes"><strong>Interpretation</strong><p>“No longer detected” does not prove the vulnerability is fixed. Static heuristics can change because the build changed, code was optimized, or patterns became harder to detect. Review the diff and run appropriate tests.</p></div>${[['Not detected in current scan',diff.resolved,baseline],['New in current scan',diff.newFindings,latestReport],['Still present',diff.persistent,latestReport]].map(([title,items,sourceReport]) => `<div class="validation-group"><h3>${title} (${items.length})</h3>${items.length ? items.map(f => `<button class="finding-title-button" data-finding-id="${escapeHTML(f.id)}" data-report-sha="${escapeHTML(sourceReport.app.sha256)}">${escapeHTML(f.title)}</button><p>${escapeHTML(f.evidence)}</p>`).join('') : '<p class="muted">None.</p>'}</div>`).join('')}` : `<div class="empty-state compact"><div class="empty-icon">${icon('validate')}</div><strong>${baselines.length ? 'Ready to compare' : 'No distinct baseline report yet'}</strong><p>${baselines.length ? 'Choose an earlier scan and compare it with the current report.' : 'Run a scan of a different APK build to make a meaningful before/after comparison.'}</p></div>`}
    </section>`;
}

function emptyWorkspace(title, description, page = 'analyze') {
  return `<section class="panel placeholder"><div class="placeholder-icon">${icon('graph')}</div><h2>${escapeHTML(title)}</h2><p>${escapeHTML(description)}</p><button class="button primary" data-page="${page}">Go to analysis →</button></section>`;
}
function render() {
  const pageTitles = { overview: 'Overview', analyze: 'Analyze APK', triage: 'Review desk', graph: 'Security graph', paths: 'Attack paths', code: 'Code mapping', ai: 'AI Fix', validate: 'Validation', standards: 'MASVS checklist', reports: 'Reports', settings: 'Settings' };
  let content;
  if (currentPage === 'overview') content = overviewPage();
  else if (currentPage === 'analyze') content = analyzePage();
  else if (currentPage === 'triage') content = reviewDeskPage();
  else if (currentPage === 'graph') content = graphPage();
  else if (currentPage === 'paths') content = pathsPage();
  else if (currentPage === 'code') content = codeMappingPage();
  else if (currentPage === 'ai') content = aiPage();
  else if (currentPage === 'validate') content = validationPage();
  else if (currentPage === 'standards') content = standardsPage();
  else if (currentPage === 'reports') content = reportsPage();
  else content = settingsPage();

  document.querySelector('#app').innerHTML = `<div class="app-shell"><aside class="sidebar"><div class="brand"><div class="brand-mark">${icon('shield')}</div><div><div class="brand-name">AppPath</div><div class="brand-subtitle">ANDROID SECURITY</div></div></div><div class="nav-caption">WORKSPACE</div><nav class="navigation">${navPages.map(p => `<button class="nav-item ${currentPage === p.id ? 'active' : ''}" data-page="${p.id}">${icon(p.id === 'overview' ? 'overview' : p.id === 'analyze' ? 'scan' : p.id)}<span>${p.label}</span>${p.tag ? `<small>${p.tag}</small>` : ''}</button>`).join('')}</nav><div class="sidebar-bottom"><div class="local-card">${icon('lock')}<div><strong>Local-first design</strong><small>Runs on this computer</small></div></div><button class="nav-item ${currentPage === 'settings' ? 'active' : ''}" data-page="settings">${icon('settings')}<span>Settings</span></button><div class="user-card"><div class="avatar">AP</div><div><strong>AppPath User</strong><small>Local workspace</small></div></div></div></aside><main class="main-area"><header class="topbar"><div class="breadcrumb">AppPath <span>/</span> <strong>${pageTitles[currentPage]}</strong></div><div class="environment"><span class="dot"></span> Local environment <div class="avatar">AP</div></div></header><div class="main-scroll"><div class="main-content">${content}<footer class="footer"><span>APPPATH · ANDROID SECURITY WORKSPACE</span><span>Static triage prototype · Findings require human review</span></footer></div></div></main></div>`;
  document.querySelector('#app').insertAdjacentHTML('beforeend', findingDetailsModal());
}

async function selectApk() {
  notice = '';
  if (!window.appPathAPI?.selectApk) {
    showNotice('AppPath native bridge is unavailable. Check src/preload.js and restart npm start.');
    render(); return;
  }
  try {
    const result = await window.appPathAPI.selectApk();
    if (result?.canceled) return;
    if (result?.error) showNotice(result.error);
    else if (result?.file) {
      selectedFile = result.file;
      showNotice(`Selected ${result.file.name}. Ready for local static analysis.`, 'success');
    }
  } catch (error) {
    showNotice(error?.message || 'Could not open the APK picker.');
  }
  render();
}
async function runScan() {
  notice = '';
  if (!selectedFile) {
    showNotice('Choose an APK first.');
    render(); return;
  }
  if (!window.appPathAPI?.analyzeSelectedApk) {
    showNotice('The native analysis bridge is unavailable. Restart AppPath after updating src/main.js and src/preload.js.');
    render(); return;
  }
  busy = true;
  showNotice('Analyzing the APK locally. Larger packages may take a few minutes.', 'success');
  render();
  try {
    const result = await window.appPathAPI.analyzeSelectedApk();
    if (!result?.ok) {
      showNotice(result?.error || 'The scan could not be completed.');
    } else {
      const previousSameApk = scanHistory.find(item => item.app?.sha256 && item.app.sha256 === result.app?.sha256);
      const previousById = new Map((previousSameApk?.findings || []).map(item => [item.id, item]));
      latestReport = { ...result, scannedAt: new Date().toISOString() };
      latestReport.findings = (latestReport.findings || []).map(item => {
        const previous = previousById.get(item.id);
        return previous ? { ...item, review_status: previous.review_status || 'unreviewed', review_note: previous.review_note || '', reviewed_at: previous.reviewed_at || null } : item;
      });
      findingSearchQuery = ''; findingSeverityFilter = 'all'; findingCategoryFilter = 'all'; findingReviewFilter = 'all';
      validationResult = null;
      codeMapResult = null;
      codeMapStatus = '';
      scanHistory = [latestReport, ...scanHistory.filter(r => r.app.sha256 !== latestReport.app.sha256)].slice(0, 25);
      try {
        const saved = await window.appPathAPI.saveHistory(scanHistory);
        if (!saved?.ok) showNotice(`Scan complete, but history could not be saved: ${saved?.error || 'local save failed'}`);
        else showNotice(`Analysis complete: ${latestReport.summary.total} indicators and ${(latestReport.candidate_paths || []).length} candidate path(s).`, 'success');
      } catch {
        showNotice('Scan completed, but local history could not be saved. The current results are still available.', 'warning');
      }
    }
  } catch (error) {
    showNotice(error?.message || 'Unexpected analysis error.');
  } finally {
    busy = false;
    render();
  }
}
async function saveFindingReview() {
  const sha = selectedFindingReportSha || latestReport?.app?.sha256 || '';
  const report = scanHistory.find(item => item.app?.sha256 === sha) || latestReport;
  const findingId = selectedFindingId || document.querySelector('[data-action="save-review"]')?.dataset.findingId;
  const finding = report?.findings?.find(item => item.id === findingId);
  const status = document.querySelector('#finding-review-status')?.value || 'unreviewed';
  const note = String(document.querySelector('#finding-review-note')?.value || '').slice(0, 3000).trim();
  if (!report || !finding) { showNotice('Could not find the selected report finding to save.'); render(); return; }
  if (!REVIEW_STATES.some(([value]) => value === status)) { showNotice('Choose a valid review state.'); render(); return; }
  finding.review_status = status;
  finding.review_note = note;
  finding.reviewed_at = new Date().toISOString();
  if (!scanHistory.some(item => item.app?.sha256 === report.app?.sha256)) {
    scanHistory = [report, ...scanHistory].slice(0, 25);
  }
  if (latestReport?.app?.sha256 === report.app?.sha256) latestReport = report;
  try {
    const result = await window.appPathAPI?.saveHistory?.(scanHistory.slice(0, 25));
    if (result && !result.ok) showNotice(`Review updated, but saving history failed: ${result.error || 'unknown error'}`);
    else showNotice(`Saved review for “${finding.title}”.`, 'success');
  } catch (error) {
    showNotice(`Review updated in this session, but saving history failed: ${error?.message || 'unknown error'}`);
  }
  render();
}

async function exportReport(format = 'json') {
  if (!latestReport) { showNotice('Run a scan before exporting a report.'); render(); return; }
  try {
    const result = await window.appPathAPI.exportReport(latestReport, format);
    if (result?.ok) showNotice(`${format.toUpperCase()} report saved to ${result.filePath}`, 'success');
    else if (!result?.canceled) showNotice(result?.error || 'Export failed.');
  } catch (error) {
    showNotice(error?.message || 'Could not export report.');
  }
  render();
}


async function runAiRemediation() {
  const findingId = document.querySelector('#ai-finding-select')?.value || aiTargetFindingId;
  const model = document.querySelector('#ai-model')?.value || aiSelectedModel;
  const codeSnippet = document.querySelector('#ai-code-snippet')?.value || '';
  aiCodeSnippet = codeSnippet.slice(0, 8000);
  aiTargetFindingId = findingId;
  aiSelectedModel = model;
  const finding = latestReport?.findings?.find(item => item.id === findingId);
  if (!finding) { aiResult = ''; showNotice('Choose a finding first.'); render(); return; }
  if (!model) { showNotice('Refresh Ollama models and choose a local model or gemma4:cloud first.'); render(); return; }
  if (!window.appPathAPI?.remediateFinding) { showNotice('Local AI bridge is unavailable. Replace src/preload.js and restart AppPath.'); render(); return; }
  aiBusy = true; aiResult = ''; showNotice(model.toLowerCase().endsWith(':cloud') ? 'Sending selected finding details to Ollama Cloud…' : 'Sending the finding details to the local model…', 'success'); render();
  try {
    const result = await window.appPathAPI.remediateFinding({
      model,
      finding: { id: finding.id, title: finding.title, description: finding.description, evidence: finding.evidence, recommendation: finding.recommendation, severity: finding.severity, category: finding.category },
      app: { package_name: latestReport.app.package_name, version_name: latestReport.app.version_name },
      codeSnippet: aiCodeSnippet,
    });
    if (result?.ok) { aiResult = result.response; showNotice(`Local remediation response generated using ${result.model}. Review and test every suggestion.`, 'success'); }
    else { aiResult = ''; showNotice(result?.error || 'Local remediation failed.'); }
  } catch (error) { aiResult = ''; showNotice(error?.message || 'Local remediation failed.'); }
  finally { aiBusy = false; render(); }
}

async function runCodeMapping() {
  if (!latestReport) { showNotice('Run a scan before mapping source code.'); render(); return; }
  if (!selectedFile) { codeMapStatus = 'Select the APK again on the Analyze APK page first. The main process needs its local path.'; render(); return; }
  if (!selectedJadxName) { codeMapStatus = 'Locate the JADX CLI launcher first.'; render(); return; }
  codeMapBusy = true; codeMapStatus = 'JADX is decompiling the selected package. This may take a few minutes…'; codeMapResult = null; render();
  try {
    const result = await window.appPathAPI?.decompileAndMap?.(latestReport.findings || []);
    if (result?.ok) { codeMapResult = result; codeMapStatus = `Completed static source mapping: ${result.matches?.length || 0} contextual match(es).`; }
    else { codeMapStatus = result?.error || 'JADX source mapping failed.'; }
  } catch (error) { codeMapStatus = error?.message || 'JADX source mapping failed.'; }
  finally { codeMapBusy = false; render(); }
}

document.addEventListener('input', event => {
  if (event.target.id === 'finding-search') {
    findingSearchQuery = event.target.value || '';
    updateFilteredFindings();
  }
});
document.addEventListener('change', event => {
  if (event.target.id === 'finding-severity') {
    findingSeverityFilter = event.target.value || 'all';
    updateFilteredFindings();
  } else if (event.target.id === 'finding-category') {
    findingCategoryFilter = event.target.value || 'all';
    updateFilteredFindings();
  } else if (event.target.id === 'finding-review') {
    findingReviewFilter = event.target.value || 'all';
    updateFilteredFindings();
  } else if (event.target.id === 'ai-finding-select') {
    aiTargetFindingId = event.target.value || '';
    aiResult = '';
    render();
  } else if (event.target.id === 'ai-model') {
    aiSelectedModel = event.target.value || '';
  } else if (event.target.id === 'ai-code-snippet') {
    aiCodeSnippet = event.target.value.slice(0, 8000);
  }
});

document.addEventListener('keydown', event => {
  if (event.key !== 'Enter' && event.key !== ' ') return;
  const node = event.target.closest?.('[data-finding-id][role="button"]');
  if (node && !node.dataset.action) {
    event.preventDefault();
    selectedFindingId = node.dataset.findingId;
    render();
  }
});

document.addEventListener('click', async event => {
  const insideModal = event.target.closest('[data-modal-panel]');
  if (insideModal && !event.target.closest('button[data-action], button[data-finding-id]')) return;
  if (event.target.classList?.contains('modal-backdrop')) { selectedFindingId = null; selectedFindingReportSha = ''; render(); return; }
  const closeButton = event.target.closest('button[data-action="close-finding"]');
  if (closeButton) { selectedFindingId = null; selectedFindingReportSha = ''; render(); return; }
  const findingButton = event.target.closest('[data-finding-id]');
  if (findingButton && !findingButton.dataset.action) { selectedFindingId = findingButton.dataset.findingId; selectedFindingReportSha = findingButton.dataset.reportSha || latestReport?.app?.sha256 || ''; render(); return; }
  const pageButton = event.target.closest('[data-page]');
  if (pageButton) {
    currentPage = pageButton.dataset.page;
    selectedFindingId = null; selectedFindingReportSha = '';
    notice = '';
    render();
    return;
  }
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const action = button.dataset.action;
  if (action === 'go-analyze') {
    currentPage = 'analyze'; notice = ''; render();
  } else if (action === 'browse') {
    await selectApk();
  } else if (action === 'remove-file') {
    selectedFile = null; notice = ''; render();
  } else if (action === 'scan') {
    await runScan();
  } else if (action === 'export') {
    await exportReport(button.dataset.format || 'json');
  } else if (action === 'save-review') {
    await saveFindingReview();
  } else if (action === 'open-history') {
    const saved = scanHistory.find(report => report.app?.sha256 === button.dataset.historySha);
    if (saved) { latestReport = saved; findingSearchQuery = ''; findingSeverityFilter = 'all'; findingCategoryFilter = 'all'; findingReviewFilter = 'all'; selectedFindingId = null; selectedFindingReportSha = saved.app?.sha256 || ''; currentPage = 'analyze'; notice = ''; render(); }
  } else if (action === 'ai-fix') {
    aiTargetFindingId = button.dataset.findingId || aiTargetFindingId;
    const sourceReport = scanHistory.find(report => report.app?.sha256 === selectedFindingReportSha);
    if (sourceReport) latestReport = sourceReport;
    selectedFindingId = null; selectedFindingReportSha = ''; currentPage = 'ai'; notice = ''; render();
  } else if (action === 'map-code') {
    aiTargetFindingId = button.dataset.findingId || aiTargetFindingId;
    const sourceReport = scanHistory.find(report => report.app?.sha256 === selectedFindingReportSha);
    if (sourceReport) latestReport = sourceReport;
    selectedFindingId = null; selectedFindingReportSha = ''; currentPage = 'code'; notice = ''; render();
  } else if (action === 'refresh-ai') {
    await refreshOllamaStatus(true);
  } else if (action === 'run-ai') {
    await runAiRemediation();
  } else if (action === 'clear-ai') {
    aiResult = ''; render();
  } else if (action === 'select-jadx') {
    try {
      const result = await window.appPathAPI?.selectJadx?.();
      if (result?.ok) { selectedJadxName = result.name; codeMapStatus = `Selected ${result.name}.`; codeMapResult = null; }
      else if (!result?.canceled) codeMapStatus = result?.error || 'Could not select JADX.';
    } catch (error) { codeMapStatus = error?.message || 'Could not select JADX.'; }
    render();
  } else if (action === 'decompile-map') {
    await runCodeMapping();
  } else if (action === 'run-validation') {
    const select = document.querySelector('#baseline-report');
    validationBaselineSha = select?.value || validationBaselineSha;
    const baseline = scanHistory.find(r => r.app?.sha256 === validationBaselineSha && r.app?.sha256 !== latestReport?.app?.sha256);
    validationResult = baseline ? compareReports(baseline, latestReport) : null;
    if (!baseline) showNotice('Choose a distinct baseline report before comparing.');
    render();
  }
});

render();
(async function restoreLocalHistory() {
  try {
    const saved = await window.appPathAPI?.loadHistory?.();
    if (saved?.ok && Array.isArray(saved.history) && saved.history.length) {
      scanHistory = saved.history.slice(0, 25);
      latestReport = scanHistory[0] || null;
      render();
    }
  } catch {
    // Opening the dashboard must remain possible if history is unavailable.
  }
})();
(async function checkLocalOllamaOnStartup() {
  try {
    const result = await window.appPathAPI?.getOllamaStatus?.();
    ollamaStatus = { checked: true, available: Boolean(result?.available), models: Array.isArray(result?.models) ? result.models : [], error: result?.error || '' };
    if (ollamaStatus.models.length && !aiSelectedModel) {
      aiSelectedModel = ollamaStatus.models.find(m => m.name.toLowerCase().endsWith(':cloud'))?.name || ollamaStatus.models[0].name;
    }
    render();
  } catch { /* The dashboard remains usable when Ollama is not installed. */ }
})();
