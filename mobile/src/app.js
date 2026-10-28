import { Capacitor, registerPlugin } from '@capacitor/core';
import { Preferences } from '@capacitor/preferences';
import { Clipboard } from '@capacitor/clipboard';
import { API_BASE } from './config.js';
import { quickCheck } from './heuristics.js';

const ShareIntake = registerPlugin('ShareIntake');   // native: android/.../ShareIntakePlugin.java

const APP_VERSION = '1.0.0';
const HISTORY_KEY = 'history.v1';
const HISTORY_MAX = 20;
const REQUEST_TIMEOUT_MS = 90_000;   // free hosting tiers can take ~1 min to wake
const SLOW_HINT_MS = 6_000;

const $ = (id) => document.getElementById(id);
const els = {
  input: $('input'), file: $('file'), fileChip: $('file-chip'),
  paste: $('btn-paste'), clear: $('btn-clear'), check: $('btn-check'), hint: $('check-hint'),
  back: $('btn-back'), retry: $('btn-retry'),
  verdict: $('verdict'), word: $('verdict-word'), sub: $('verdict-sub'), meter: $('meter-fill'), meta: $('verdict-meta'),
  offline: $('offline-note'), findings: $('findings'), steps: $('steps'), tech: $('tech'), techBody: $('tech-body'),
  historyList: $('history-list'), historyEmpty: $('history-empty'), clearHistory: $('btn-clear-history'),
};

let pickedFile = null;     // { name, text }
let lastSubmission = null; // for "try again"

/* ------------------------------------------------------------------ nav */
const screens = { check: 'screen-check', history: 'screen-history', about: 'screen-about', result: 'screen-result' };
function show(name) {
  for (const [k, id] of Object.entries(screens)) $(id).hidden = k !== name;
  const tab = name === 'result' ? 'check' : name;
  document.querySelectorAll('.tab').forEach(t => {
    if (t.dataset.tab === tab) t.setAttribute('aria-current', 'page'); else t.removeAttribute('aria-current');
  });
  if (name === 'history') renderHistory();
  window.scrollTo(0, 0);
}
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => show(t.dataset.tab)));
els.back.addEventListener('click', () => show('check'));

/* ---------------------------------------------------------------- input */
function syncClear() { els.clear.hidden = !(els.input.value || pickedFile); }
els.input.addEventListener('input', syncClear);

els.paste.addEventListener('click', async () => {
  try {
    const { value } = await Clipboard.read();
    if (value) { els.input.value = value; clearFile(); syncClear(); els.hint.textContent = ''; }
    else els.hint.textContent = 'The clipboard is empty. Copy the message first.';
  } catch {
    els.hint.textContent = 'Couldn\'t read the clipboard. Long-press the box and choose Paste.';
  }
});

els.clear.addEventListener('click', () => { els.input.value = ''; clearFile(); syncClear(); els.input.focus(); });

els.file.addEventListener('change', async () => {
  const f = els.file.files && els.file.files[0];
  if (!f) return;
  if (f.size > 2 * 1024 * 1024) { els.hint.textContent = 'That file is larger than 2 MB. Pick a single email (.eml).'; return; }
  pickedFile = { name: f.name || 'email.eml', text: await f.text() };
  els.fileChip.textContent = `Email file: ${pickedFile.name}`;
  els.fileChip.hidden = false;
  els.hint.textContent = '';
  syncClear();
});
function clearFile() { pickedFile = null; els.file.value = ''; els.fileChip.hidden = true; }

document.querySelectorAll('.example').forEach(b => b.addEventListener('click', () => {
  els.input.value = b.dataset.example; clearFile(); syncClear();
  b.closest('details').open = false;
  runCheck();
}));

els.check.addEventListener('click', runCheck);
els.retry.addEventListener('click', () => lastSubmission && runCheck(lastSubmission));

/* ---------------------------------------------------------------- check */
async function runCheck(resubmit) {
  const sub = resubmit && resubmit.text !== undefined ? resubmit
    : { text: els.input.value.trim(), file: pickedFile };
  if (!sub.text && !sub.file) { els.hint.textContent = 'Paste a link or message first.'; els.input.focus(); return; }
  lastSubmission = sub;

  setBusy(true);
  const slow = setTimeout(() => { els.hint.textContent = 'Waking up the analysis server. This can take up to a minute the first time.'; }, SLOW_HINT_MS);
  try {
    const report = await callApi(sub);
    const entry = fromServer(report, sub);
    await saveHistory(entry);
    renderResult(entry);
  } catch (err) {
    if (err.userFacing) { els.hint.textContent = err.message; return; }
    // Network failure, timeout or server error: fall back to the on-device check.
    const text = sub.file ? sub.file.text : sub.text;
    const q = quickCheck(text);
    const entry = fromOffline(q, sub);
    await saveHistory(entry);
    renderResult(entry);
  } finally {
    clearTimeout(slow);
    setBusy(false);
  }
}

function setBusy(on) {
  els.check.disabled = on;
  els.check.innerHTML = on ? '<span class="spinner" aria-hidden="true"></span>Checking…' : 'Check it';
  if (on) els.hint.textContent = '';
}

async function callApi(sub) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
  let res;
  try {
    if (sub.file) {
      const fd = new FormData();
      fd.append('file', new Blob([sub.file.text], { type: 'message/rfc822' }), sub.file.name);
      res = await fetch(`${API_BASE}/api/v1/scan`, { method: 'POST', body: fd, signal: ctrl.signal });
    } else {
      res = await fetch(`${API_BASE}/api/v1/scan`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: sub.text }), signal: ctrl.signal,
      });
    }
  } finally { clearTimeout(t); }

  let body = {};
  try { body = await res.json(); } catch { /* non-JSON error page */ }
  if (res.ok) return body;
  if ([400, 413, 422, 429].includes(res.status)) {
    const e = new Error(body.error || 'The server could not check this input.');
    e.userFacing = true; throw e;
  }
  throw new Error(`server ${res.status}`);
}

/* ------------------------------------------------------- normalise data */
const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

function fromServer(r, sub) {
  const ev = Array.isArray(r.evidence) ? r.evidence : [];
  const level = normLevel(r.risk_level);
  let findings = ev
    // On a risky verdict, show only the warning signs; low/benign items live in Technical evidence.
    .filter(e => level === 'LOW' || (e.detection_result !== 'Benign' && (SEV_RANK[e.severity] ?? 0) >= 2))
    .sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0))
    .map(e => ({ sev: e.severity || 'INFO', title: e.indicator, body: e.supporting_info }));
  const seen = new Set();
  findings = findings.filter(f => !seen.has(f.title) && seen.add(f.title)).slice(0, 7);
  if (!findings.length) findings = [{ sev: 'INFO', title: 'No warning signs found', body: r.summary || '' }];

  return {
    id: r.investigation_id || `local-${Date.now()}`,
    ts: Date.now(),
    preview: sub.file ? `Email file: ${sub.file.name}` : sub.text.slice(0, 160),
    level, score: Math.round(Number(r.risk_score) || 0),
    confidence: r.confidence_score, offline: false,
    findings,
    tech: {
      id: r.investigation_id, rationale: r.risk_rationale, summary: r.summary,
      type: r.request_type, humanReview: r.human_review_required,
      actions: (r.agent_actions || []).map(a => ({ step: a.step, tool: a.tool_name, finding: a.key_finding })),
      correlations: (r.correlations || []).map(c => ({ title: c.title, mitre: c.mitre_technique, severity: c.severity })),
      iocs: r.iocs || {},
      evidence: ev.map(e => ({ sev: e.severity, src: e.source, ind: e.indicator, res: e.detection_result })),
      recommendations: (r.recommendations || []).map(x => ({ action: x.action, phase: x.phase })),
    },
  };
}

function fromOffline(q, sub) {
  return {
    id: `offline-${Date.now()}`, ts: Date.now(),
    preview: sub.file ? `Email file: ${sub.file.name}` : sub.text.slice(0, 160),
    level: q.level, score: q.score, offline: true,
    findings: q.reasons.map(t => ({ sev: q.level === 'LOW' ? 'LOW' : q.level === 'UNKNOWN' ? 'INFO' : 'MEDIUM', title: t, body: '' })),
    tech: { offlineUrls: q.urls },
  };
}

function normLevel(l) {
  const s = String(l || '').toUpperCase();
  if (s.includes('CRITICAL') || s.includes('SEVERE')) return 'CRITICAL';
  if (s.includes('HIGH')) return 'HIGH';
  if (s.includes('MEDIUM') || s.includes('SUSPICIOUS') || s.includes('MODERATE')) return 'MEDIUM';
  if (s.includes('LOW')) return 'LOW';
  return 'UNKNOWN';
}

/* --------------------------------------------------------------- render */
const VERDICT = {
  CRITICAL: { word: 'Scam', sub: 'This has strong signs of fraud. Don\'t click, reply, call or pay.' },
  HIGH: { word: 'Scam', sub: 'This looks like a scam. Don\'t click, reply, call or pay.' },
  MEDIUM: { word: 'Careful', sub: 'Some warning signs. Don\'t act on it until you\'ve checked with the real organisation.' },
  LOW: { word: 'Looks safe', sub: 'No scam signs found. Still never share an OTP, PIN or password.' },
  UNKNOWN: { word: 'Not sure', sub: 'There wasn\'t enough to judge. Paste the full message including any link.' },
};

const STEPS = {
  danger: [
    'Don\'t open the link, call the number, or reply to the message.',
    'Never share an OTP, UPI PIN, CVV or password. No bank or government office asks for them.',
    'If you already clicked, entered details, or paid: call <a href="tel:1930">1930</a> now and report at <a href="https://cybercrime.gov.in" target="_blank" rel="noopener">cybercrime.gov.in</a>. Then call your bank to block the card or account.',
    'Report the sender as spam in your SMS or WhatsApp app, and report the number on <a href="https://sancharsaathi.gov.in" target="_blank" rel="noopener">Sanchar Saathi (Chakshu)</a>.',
    'Delete the message.',
  ],
  caution: [
    'Don\'t use the link or number in the message.',
    'Contact the organisation through its official app, or a number printed on your card or bill.',
    'Never share an OTP, UPI PIN, CVV or password, whoever is asking.',
    'If money has already left your account, call <a href="tel:1930">1930</a> immediately.',
  ],
  safe: [
    'You can go ahead, but type important addresses yourself instead of tapping links when money is involved.',
    'Never share an OTP, UPI PIN, CVV or password, even with someone claiming to be from your bank.',
  ],
};

function renderResult(e) {
  const v = VERDICT[e.level] || VERDICT.UNKNOWN;
  els.verdict.dataset.level = e.level;
  els.word.textContent = v.word;
  els.sub.textContent = v.sub;
  els.meta.textContent = e.offline
    ? `Offline rules score ${e.score}/100`
    : `Risk ${e.score}/100${e.confidence ? ` · confidence ${Math.round(e.confidence)}%` : ''}`;
  els.offline.hidden = !e.offline;
  els.retry.hidden = !(e.offline && lastSubmission);

  els.findings.replaceChildren(...e.findings.map(f => {
    const li = document.createElement('li');
    li.dataset.sev = f.sev;
    const t = document.createElement('span'); t.className = 'f-title'; t.textContent = f.title;
    li.append(t);
    if (f.body) { const b = document.createElement('span'); b.className = 'f-body'; b.textContent = f.body; li.append(b); }
    return li;
  }));

  const set = e.level === 'LOW' ? STEPS.safe : e.level === 'MEDIUM' || e.level === 'UNKNOWN' ? STEPS.caution : STEPS.danger;
  els.steps.innerHTML = set.map(s => `<li>${s}</li>`).join('');   // static trusted strings only

  renderTech(e);
  els.tech.open = false;

  show('result');
  els.verdict.classList.remove('enter');
  els.meter.style.width = '0';
  void els.verdict.offsetWidth;   // restart animation
  els.verdict.classList.add('enter');
  requestAnimationFrame(() => { els.meter.style.width = `${Math.max(3, e.score)}%`; });
}

function renderTech(e) {
  const t = e.tech || {};
  const body = els.techBody;
  body.replaceChildren();
  const add = (tag, text, cls) => { const n = document.createElement(tag); if (cls) n.className = cls; n.textContent = text; body.append(n); return n; };

  if (e.offline) {
    add('p', 'Checked on this phone with offline rules (no machine-learning model).');
    if (t.offlineUrls && t.offlineUrls.length) { add('h3', 'Links found'); t.offlineUrls.forEach(u => add('p', u).classList.add('mono')); }
    return;
  }
  add('p', `Case ${t.id || '—'} · ${t.type || 'auto'} investigation${t.humanReview ? ' · flagged for human review' : ''}`);
  if (t.rationale) add('p', t.rationale);

  if (t.actions && t.actions.length) {
    add('h3', 'Agent investigation steps');
    const table = document.createElement('table');
    for (const a of t.actions) {
      const tr = table.insertRow();
      tr.insertCell().textContent = a.step;
      const c = tr.insertCell();
      const code = document.createElement('code'); code.textContent = a.tool; c.append(code, document.createTextNode(` — ${a.finding || ''}`));
    }
    body.append(table);
  }
  if (t.evidence && t.evidence.length) {
    add('h3', `All evidence (${t.evidence.length})`);
    const table = document.createElement('table');
    for (const x of t.evidence) {
      const tr = table.insertRow();
      tr.insertCell().textContent = ({ CRITICAL: 'Crit', HIGH: 'High', MEDIUM: 'Med', LOW: 'Low' })[x.sev] || 'Info';
      const c = tr.insertCell();
      const code = document.createElement('code'); code.textContent = x.src || '';
      c.append(code, document.createTextNode(` — ${x.ind}${x.res ? ` (${x.res})` : ''}`));
    }
    body.append(table);
  }
  if (t.correlations && t.correlations.length) {
    add('h3', 'Correlated findings');
    t.correlations.forEach(c => add('p', `${c.title}${c.mitre ? ` (MITRE ATT&CK ${c.mitre})` : ''}`));
  }
  const iocs = Object.entries(t.iocs || {}).filter(([, v]) => Array.isArray(v) && v.length);
  if (iocs.length) {
    add('h3', 'Indicators of compromise');
    iocs.forEach(([k, v]) => add('p', `${k}: ${v.slice(0, 8).join(', ')}`));
  }
  if (t.recommendations && t.recommendations.length) {
    add('h3', 'For security teams');
    t.recommendations.forEach(r => add('p', `${r.phase ? r.phase + ': ' : ''}${r.action}`));
  }
}

/* -------------------------------------------------------------- history */
async function loadHistory() {
  try { const { value } = await Preferences.get({ key: HISTORY_KEY }); return value ? JSON.parse(value) : []; }
  catch { return []; }
}
async function saveHistory(entry) {
  const list = await loadHistory();
  list.unshift(entry);
  try { await Preferences.set({ key: HISTORY_KEY, value: JSON.stringify(list.slice(0, HISTORY_MAX)) }); } catch { /* storage full or unavailable */ }
}
async function renderHistory() {
  const list = await loadHistory();
  els.historyEmpty.hidden = list.length > 0;
  els.clearHistory.hidden = list.length === 0;
  const fmt = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit' });
  els.historyList.replaceChildren(...list.map(e => {
    const li = document.createElement('li');
    const b = document.createElement('button'); b.type = 'button';
    const badge = document.createElement('span'); badge.className = 'h-badge'; badge.dataset.level = e.level;
    badge.textContent = (VERDICT[e.level] || VERDICT.UNKNOWN).word;
    const txt = document.createElement('span');
    const p = document.createElement('span'); p.className = 'h-text'; p.textContent = e.preview;
    const time = document.createElement('span'); time.className = 'h-time';
    time.textContent = fmt.format(new Date(e.ts)) + (e.offline ? ' · offline check' : '');
    txt.append(p, time);
    b.append(badge, txt);
    b.addEventListener('click', () => renderResult(e));
    li.append(b);
    return li;
  }));
}
els.clearHistory.addEventListener('click', async () => {
  if (!confirm('Delete all checks from this phone?')) return;
  await Preferences.remove({ key: HISTORY_KEY });
  renderHistory();
});

/* ------------------------------------------------- shared into the app */
function acceptShared(text) {
  if (!text) return;
  els.input.value = String(text).slice(0, 20000);
  clearFile(); syncClear();
  show('check');
  runCheck();
}
if (Capacitor.isNativePlatform()) {
  ShareIntake.addListener('sharedText', ({ text }) => acceptShared(text));
  ShareIntake.getSharedText().then(({ text }) => acceptShared(text)).catch(() => {});
}

/* ---------------------------------------------------------------- about */
$('privacy-link').href = `${API_BASE}/privacy`;
$('version').textContent = `Version ${APP_VERSION}`;
