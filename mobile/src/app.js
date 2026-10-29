import { Capacitor, registerPlugin } from '@capacitor/core';
import { Preferences } from '@capacitor/preferences';
import { Clipboard } from '@capacitor/clipboard';
import { Haptics, NotificationType, ImpactStyle } from '@capacitor/haptics';
import { API_BASE } from './config.js';
import { quickCheck, findSpans, extractUrls } from './heuristics.js';
import { plainFinding } from './plain.js';
import { paintShield } from './shield.js';

const ShareIntake = registerPlugin('ShareIntake');   // native: android/.../ShareIntakePlugin.java

const APP_VERSION = '1.1.0';
const HISTORY_KEY = 'history.v1';
const WELCOME_KEY = 'welcomed.v1';
const HISTORY_MAX = 20;
const REQUEST_TIMEOUT_MS = 90_000;   // free hosting tiers can take ~1 min to wake
const SLOW_HINT_MS = 6_000;

const $ = (id) => document.getElementById(id);
const els = {
  input: $('input'), file: $('file'), fileChip: $('file-chip'),
  paste: $('btn-paste'), clear: $('btn-clear'), check: $('btn-check'), hint: $('check-hint'),
  back: $('btn-back'), retry: $('btn-retry'), bubbleWrap: $('bubble-wrap'),
  result: $('screen-result'), hero: $('verdict'), heroArt: $('hero-art'),
  word: $('verdict-word'), word2: $('verdict-word-2'), date: $('verdict-date'), pill: $('status-pill'),
  sub: $('verdict-sub'), meter: $('meter'), meta: $('verdict-meta'),
  statRisk: $('stat-risk'), statSigns: $('stat-signs'), statLinks: $('stat-links'),
  offline: $('offline-note'), findings: $('findings'), steps: $('steps'),
  tech: $('tech'), techBody: $('tech-body'),
  readout: $('readout'), legend: $('legend'), evidenceBlock: $('evidence-block'), dangerActions: $('danger-actions'),
  historyList: $('history-list'), historyEmpty: $('history-empty'), clearHistory: $('btn-clear-history'),
  welcome: $('screen-welcome'),
};

const haptic = {
  tap: () => Haptics.impact({ style: ImpactStyle.Light }).catch(() => {}),
  verdict: (level) => Haptics.notification({
    type: level === 'LOW' ? NotificationType.Success
      : level === 'MEDIUM' || level === 'UNKNOWN' ? NotificationType.Warning : NotificationType.Error,
  }).catch(() => {}),
};

document.querySelectorAll('.shield[data-tone]').forEach(el => paintShield(el));

let pickedFile = null;     // { name, text }
let lastSubmission = null; // for "try again"
let homeFilter = 'all';

/* ------------------------------------------------------------------ nav */
const screens = { home: 'screen-home', check: 'screen-check', history: 'screen-history', about: 'screen-about', result: 'screen-result' };
function show(name) {
  for (const [k, id] of Object.entries(screens)) {
    const el = $(id);
    el.hidden = k !== name;
    el.classList.remove('enter');
  }
  const cur = $(screens[name]);
  void cur.offsetWidth; cur.classList.add('enter');
  const tab = name === 'result' ? 'check' : name;
  document.querySelectorAll('.dock-btn').forEach(t => {
    if (t.dataset.tab === tab) t.setAttribute('aria-current', 'page'); else t.removeAttribute('aria-current');
  });
  if (name === 'history') renderHistory();
  if (name === 'home') renderHome();
  window.scrollTo(0, 0);
}
document.querySelectorAll('.dock-btn, [data-goto]').forEach(t => t.addEventListener('click', () => {
  haptic.tap(); show(t.dataset.tab || t.dataset.goto);
}));
els.back.addEventListener('click', () => show('check'));

/* ------------------------------------------------------------- welcome */
async function initWelcome() {
  let seen = null;
  try { seen = (await Preferences.get({ key: WELCOME_KEY })).value; } catch { /* storage unavailable */ }
  els.welcome.hidden = !!seen;
}
async function finishWelcome() {
  haptic.tap();
  els.welcome.hidden = true;
  try { await Preferences.set({ key: WELCOME_KEY, value: '1' }); } catch { /* ignore */ }
  show('home');
}
$('btn-start').addEventListener('click', finishWelcome);
$('btn-start-2').addEventListener('click', finishWelcome);

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
  runCheck();
}));

els.check.addEventListener('click', () => { haptic.tap(); runCheck(); });
els.retry.addEventListener('click', () => lastSubmission && runCheck(lastSubmission));

/* ---------------------------------------------------------------- check */
async function runCheck(resubmit) {
  const sub = resubmit && resubmit.text !== undefined ? resubmit
    : { text: els.input.value.trim(), file: pickedFile };
  if (!sub.text && !sub.file) { els.hint.textContent = 'Paste a link or message first.'; els.input.focus(); return; }
  lastSubmission = sub;
  if ($('screen-check').hidden) show('check');

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
    const entry = fromOffline(quickCheck(text), sub);
    await saveHistory(entry);
    renderResult(entry);
  } finally {
    clearTimeout(slow);
    setBusy(false);
  }
}

const STAGES = ['Reading the message', 'Checking the links', 'Looking for pressure tactics', 'Weighing the evidence'];
let stageTimer = null;
function setBusy(on) {
  els.check.disabled = on;
  els.bubbleWrap.classList.toggle('scanning', on);
  els.input.readOnly = on;
  clearInterval(stageTimer);
  if (on) {
    els.hint.textContent = '';
    let i = 0;
    const paint = () => {
      els.check.innerHTML = '<span><span class="dots" aria-hidden="true"><i></i><i></i><i></i></span><span class="cta-label"></span></span>';
      els.check.querySelector('.cta-label').textContent = STAGES[i++ % STAGES.length] + '…';
    };
    paint();
    stageTimer = setInterval(paint, 1400);
  } else {
    els.check.innerHTML = '<span class="cta-label">Check this message</span><span class="cta-go" aria-hidden="true">››</span>';
  }
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

function kindOf(sub, serverType) {
  if (sub.file) return 'email';
  if (serverType === 'email' || serverType === 'url' || serverType === 'message') return serverType;
  const t = sub.text.trim();
  if (/^(received|return-path|from|subject|message-id):/im.test(t.slice(0, 400))) return 'email';
  return (!/\s/.test(t) && extractUrls(t).length === 1) ? 'url' : 'message';
}

function fromServer(r, sub) {
  const ev = Array.isArray(r.evidence) ? r.evidence : [];
  const level = normLevel(r.risk_level);
  let findings = ev
    // On a risky verdict, show only the warning signs; low/benign items live in Technical evidence.
    .filter(e => level === 'LOW' || (e.detection_result !== 'Benign' && (SEV_RANK[e.severity] ?? 0) >= 2))
    .sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0))
    .map(e => ({ sev: e.severity || 'INFO', ...plainFinding(e.indicator, e.supporting_info) }));
  const seen = new Set();
  findings = findings.filter(f => !seen.has(f.title) && seen.add(f.title)).slice(0, 7);
  const signs = level === 'LOW' ? 0 : findings.length;
  if (!findings.length) findings = [{ sev: 'INFO', title: 'No warning signs found', body: r.summary || '' }];

  return {
    id: r.investigation_id || `local-${Date.now()}`,
    ts: Date.now(),
    kind: kindOf(sub, r.request_type),
    preview: sub.file ? `Email file: ${sub.file.name}` : sub.text.slice(0, 160),
    text: (sub.file ? sub.file.text : sub.text).slice(0, 4000),
    level, score: Math.round(Number(r.risk_score) || 0),
    confidence: r.confidence_score, offline: false,
    signs, links: (r.iocs && r.iocs.urls ? r.iocs.urls.length : 0),
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
  const sev = q.level === 'LOW' ? 'LOW' : q.level === 'UNKNOWN' ? 'INFO' : 'MEDIUM';
  return {
    id: `offline-${Date.now()}`, ts: Date.now(), kind: kindOf(sub),
    preview: sub.file ? `Email file: ${sub.file.name}` : sub.text.slice(0, 160),
    text: (sub.file ? sub.file.text : sub.text).slice(0, 4000),
    level: q.level, score: q.score, offline: true,
    signs: q.level === 'LOW' || q.level === 'UNKNOWN' ? 0 : q.reasons.length, links: q.urls.length,
    findings: q.reasons.map(t => ({ sev, title: t, body: '' })),
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

/* --------------------------------------------------------------- result */
const VERDICT = {
  CRITICAL: { a: 'Scam', b: 'detected', pill: 'Dangerous', tone: 'red', glyph: 'alert', short: 'Scam',
    sub: 'This has strong signs of fraud. Don\'t click, reply, call or pay.' },
  HIGH: { a: 'Likely', b: 'a scam', pill: 'Dangerous', tone: 'red', glyph: 'alert', short: 'Scam',
    sub: 'This looks like a scam. Don\'t click, reply, call or pay.' },
  MEDIUM: { a: 'Be', b: 'careful', pill: 'Suspicious', tone: 'amber', glyph: 'alert', short: 'Careful',
    sub: 'Some warning signs. Don\'t act on it until you\'ve checked with the real organisation.' },
  LOW: { a: 'Looks', b: 'safe', pill: 'Safe', tone: 'green', glyph: 'check', short: 'Safe',
    sub: 'No scam signs found. Still never share an OTP, PIN or password.' },
  UNKNOWN: { a: 'Not', b: 'sure', pill: 'Unclear', tone: 'grey', glyph: 'question', short: 'Unclear',
    sub: 'There wasn\'t enough to judge. Paste the full message including any link.' },
};

const STEPS = {
  danger: [
    'Don\'t open the link, call the number, or reply to the message.',
    'Never share an OTP, UPI PIN, CVV or password. No bank or government office asks for them.',
    'If you already clicked, entered details, or paid: call <a href="tel:1930">1930</a> now and report at <a href="https://cybercrime.gov.in" target="_blank" rel="noopener">cybercrime.gov.in</a>. Then call your bank to block the card or account.',
    'Report the sender as spam, and report the number on <a href="https://sancharsaathi.gov.in" target="_blank" rel="noopener">Sanchar Saathi (Chakshu)</a>.',
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

const dateFmt = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: 'numeric', minute: '2-digit' });

function renderResult(e) {
  const v = VERDICT[e.level] || VERDICT.UNKNOWN;
  els.result.className = `screen lv-${e.level}`;
  els.word.textContent = v.a;
  els.word2.textContent = v.b;
  els.pill.textContent = e.offline ? `${v.pill} · offline` : v.pill;
  els.date.textContent = dateFmt.format(new Date(e.ts));
  paintShield(els.heroArt, v.tone, v.glyph);
  els.sub.textContent = v.sub;

  const links = Math.max(e.links || 0, findSpans(e.text || '').filter(s => s.kind === 'link').length);
  els.statRisk.textContent = e.score;
  els.statSigns.textContent = e.signs ?? 0;
  els.statLinks.textContent = links;
  els.meta.textContent = e.offline ? 'Checked offline with on-device rules'
    : `Engine confidence ${e.confidence ? Math.round(e.confidence) + '%' : 'n/a'}`;
  els.offline.hidden = !e.offline;
  els.retry.hidden = !(e.offline && lastSubmission);

  els.findings.replaceChildren(...e.findings.map(f => row(f.sev, f.title, f.body)));
  const set = e.level === 'LOW' ? STEPS.safe : (e.level === 'MEDIUM' || e.level === 'UNKNOWN') ? STEPS.caution : STEPS.danger;
  els.steps.innerHTML = set.map(s => `<li><span>${s}</span></li>`).join('');   // static trusted strings only
  els.dangerActions.hidden = !(e.level === 'HIGH' || e.level === 'CRITICAL');

  renderReadout(e);
  renderTech(e);
  els.tech.open = false;

  show('result');
  els.result.classList.add('enter');
  els.hero.classList.remove('enter'); void els.hero.offsetWidth; els.hero.classList.add('enter');
  const bar = els.meter.firstElementChild;
  bar.style.width = '0';
  requestAnimationFrame(() => requestAnimationFrame(() => { bar.style.width = `${Math.max(3, e.score)}%`; }));
  setTimeout(() => haptic.verdict(e.level), 280);
}

function row(sev, title, body, aside) {
  const li = document.createElement('li');
  li.className = `lv-${sev}`;
  const dot = document.createElement('span'); dot.className = 'dot'; dot.setAttribute('aria-hidden', 'true');
  const txt = document.createElement('span');
  const b = document.createElement('b'); b.className = 't'; b.textContent = title;
  txt.append(b);
  if (body) { const s = document.createElement('small'); s.textContent = body; txt.append(s); }
  li.append(dot, txt);
  if (aside) { const t = document.createElement('time'); t.textContent = aside; li.append(t); }
  else li.append(document.createElement('span'));
  return li;
}

/** The user's own message, with the links and pressure words marked where they occur. */
function renderReadout(e) {
  const text = e.text || e.preview || '';
  const isEmail = /^(received|return-path|from|subject|message-id|dkim-signature|delivered-to|mime-version):/im.test(text.slice(0, 400));
  els.evidenceBlock.hidden = !text || isEmail;
  if (els.evidenceBlock.hidden) return;

  const spans = findSpans(text);
  const nodes = [];
  let pos = 0;
  for (const sp of spans) {
    if (sp.start > pos) nodes.push(document.createTextNode(text.slice(pos, sp.start)));
    const m = document.createElement('mark');
    m.className = sp.kind;
    m.textContent = text.slice(sp.start, sp.end);
    nodes.push(m);
    pos = sp.end;
  }
  if (pos < text.length) nodes.push(document.createTextNode(text.slice(pos)));
  els.readout.replaceChildren(...nodes);
  const safe = e.level === 'LOW';
  els.readout.classList.toggle('safe', safe);

  const kinds = new Set(spans.map(s => s.kind));
  const lgLink = els.legend.querySelector('.lg-link');
  els.legend.hidden = kinds.size === 0;
  lgLink.hidden = !kinds.has('link');
  lgLink.classList.toggle('safe', safe);
  lgLink.textContent = safe ? 'Link checked' : 'Risky link';
  els.legend.querySelector('.lg-pressure').hidden = !kinds.has('pressure');
}

function renderTech(e) {
  const t = e.tech || {};
  const body = els.techBody;
  body.replaceChildren();
  const add = (tag, text) => { const n = document.createElement(tag); n.textContent = text; body.append(n); return n; };
  const table = (rows) => {
    const tb = document.createElement('table');
    for (const [a, src, rest] of rows) {
      const tr = tb.insertRow();
      tr.insertCell().textContent = a;
      const c = tr.insertCell();
      const code = document.createElement('code'); code.textContent = src;
      c.append(code, document.createTextNode(` — ${rest}`));
    }
    body.append(tb);
  };

  if (e.offline) {
    add('p', 'Checked on this phone with offline rules (no machine-learning model).');
    if (t.offlineUrls && t.offlineUrls.length) { add('h3', 'Links found'); t.offlineUrls.forEach(u => add('p', u)); }
    return;
  }
  add('p', `Case ${t.id || '—'} · ${t.type || 'auto'} investigation${t.humanReview ? ' · flagged for human review' : ''}`);
  if (t.rationale) add('p', t.rationale);
  if (t.actions && t.actions.length) {
    add('h3', 'Agent investigation steps');
    table(t.actions.map(a => [a.step, a.tool, a.finding || '']));
  }
  if (t.evidence && t.evidence.length) {
    add('h3', `All evidence (${t.evidence.length})`);
    table(t.evidence.map(x => [({ CRITICAL: 'Crit', HIGH: 'High', MEDIUM: 'Med', LOW: 'Low' })[x.sev] || 'Info',
      x.src || '', `${x.ind}${x.res ? ` (${x.res})` : ''}`]));
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
  try { await Preferences.set({ key: HISTORY_KEY, value: JSON.stringify(list.slice(0, HISTORY_MAX)) }); } catch { /* storage full */ }
}

const agoFmt = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto', style: 'short' });
function ago(ts) {
  const s = Math.round((ts - Date.now()) / 1000);
  if (s > -60) return 'now';
  if (s > -3600) return agoFmt.format(Math.round(s / 60), 'minute');
  if (s > -86400) return agoFmt.format(Math.round(s / 3600), 'hour');
  return agoFmt.format(Math.round(s / 86400), 'day');
}

function historyRow(e) {
  const li = row(e.level, e.preview, `${(VERDICT[e.level] || VERDICT.UNKNOWN).short}${e.offline ? ' · offline check' : ''}`, ago(e.ts));
  li.classList.add('as-btn');
  li.tabIndex = 0;
  li.setAttribute('role', 'button');
  const open = () => renderResult(e);
  li.addEventListener('click', open);
  li.addEventListener('keydown', ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } });
  return li;
}

async function renderHistory() {
  const list = await loadHistory();
  els.historyEmpty.hidden = list.length > 0;
  els.clearHistory.hidden = list.length === 0;
  els.historyList.replaceChildren(...list.map(historyRow));
}
els.clearHistory.addEventListener('click', async () => {
  if (!confirm('Delete all checks from this phone?')) return;
  try { await Preferences.remove({ key: HISTORY_KEY }); } catch { /* ignore */ }
  renderHistory();
});

/* ----------------------------------------------------------------- home */
document.querySelectorAll('.pills [data-filter]').forEach(p => p.addEventListener('click', () => {
  haptic.tap();
  homeFilter = p.dataset.filter;
  document.querySelectorAll('.pills [data-filter]').forEach(x => x.setAttribute('aria-selected', String(x === p)));
  renderHome();
}));

function greeting() {
  const h = new Date().getHours();
  return h < 5 ? 'Good night' : h < 12 ? 'Good morning' : h < 17 ? 'Good afternoon' : 'Good evening';
}

async function renderHome() {
  $('greet').textContent = greeting();
  const all = await loadHistory();
  const list = homeFilter === 'all' ? all : all.filter(e => (e.kind || 'message') === homeFilter);
  const weekAgo = Date.now() - 7 * 86400e3;
  const week = list.filter(e => e.ts >= weekAgo);
  const caught = week.filter(e => e.level === 'HIGH' || e.level === 'CRITICAL').length;
  const careful = week.filter(e => e.level === 'MEDIUM').length;

  $('sc-caught').textContent = caught;
  $('sc-total').textContent = week.length;
  $('sc-badge').textContent = !week.length ? 'No checks yet' : caught ? 'Stay alert' : 'All clear';
  $('sc-bar').style.width = week.length ? `${Math.max(4, Math.round(caught / week.length * 100))}%` : '0';
  $('sc-foot').textContent = !week.length ? 'Check your first message to start'
    : caught ? `You stopped ${caught} scam${caught > 1 ? 's' : ''} this week${careful ? `, ${careful} more suspicious` : ''}`
    : careful ? `${careful} suspicious, nothing dangerous` : 'Everything you checked looked safe';

  // checks per day, last 7 days ending today
  $('week-total').textContent = week.length;
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - i);
    const next = d.getTime() + 86400e3;
    days.push({ label: d.toLocaleDateString(undefined, { weekday: 'narrow' }), n: list.filter(e => e.ts >= d.getTime() && e.ts < next).length });
  }
  const max = Math.max(1, ...days.map(d => d.n));
  $('week-bars').replaceChildren(...days.map(d => {
    const col = document.createElement('div');
    const bar = document.createElement('i');
    bar.style.height = `${d.n ? Math.max(14, Math.round(d.n / max * 100)) : 10}%`;
    if (!d.n) bar.className = 'zero';
    const lab = document.createElement('span'); lab.textContent = d.label;
    col.append(bar, lab);
    return col;
  }));

  const recent = list.slice(0, 3);
  $('recent-list').replaceChildren(...recent.map(historyRow));
  $('recent-empty').hidden = recent.length > 0;
}

/* -------------------------------------------------------- server status */
async function pingServer() {
  const dot = $('st-server'), txt = $('st-server-txt');
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch(`${API_BASE}/api/v1/health`, { signal: ctrl.signal, cache: 'no-store' });
    if (!r.ok) throw new Error();
    dot.className = 'ok'; txt.className = ''; txt.textContent = 'Online';
  } catch {
    dot.className = 'down'; txt.className = 'down';
    txt.textContent = navigator.onLine === false ? 'You\'re offline: on-device checks only' : 'Waking up: first check may take a minute';
  } finally { clearTimeout(t); }
}

/* ------------------------------------------------- shared into the app */
function acceptShared(text) {
  if (!text) return;
  els.welcome.hidden = true;
  els.input.value = String(text).slice(0, 20000);
  clearFile(); syncClear();
  show('check');
  runCheck();
}
if (Capacitor.isNativePlatform()) {
  ShareIntake.addListener('sharedText', ({ text }) => acceptShared(text));
  ShareIntake.getSharedText().then(({ text }) => acceptShared(text)).catch(() => {});
}

/* ----------------------------------------------------------------- boot */
$('privacy-link').href = `${API_BASE}/privacy`;
$('version').textContent = `Version ${APP_VERSION}`;
initWelcome();
show('home');
pingServer();
