"""
Mobile API for the FEIA Android app (Play Store build).

Design rules for a public, multi-user deployment:
  * Scans submitted from phones are NOT written to the shared
    investigations_db.json - one user's SMS must never appear on
    another user's dashboard.
  * Requests are size-limited and rate-limited per client IP.
  * Responses carry only what the agent actually observed (no geo/IP
    enrichment, which in app.py is synthetic).
"""
import os
import re
import time
import threading
from collections import defaultdict, deque

from flask import Blueprint, jsonify, request, render_template

mobile_bp = Blueprint('mobile', __name__)

API_VERSION = '1.0.0'
MAX_INPUT_CHARS = 20_000          # a pasted SMS / URL / short email
MAX_FILE_BYTES = 2 * 1024 * 1024  # .eml uploads
RATE_LIMIT = int(os.environ.get('MOBILE_RATE_LIMIT_PER_MIN', '20'))

_agent = None
_hits = defaultdict(deque)
_hits_lock = threading.Lock()

URL_RE = re.compile(r'(?i)\b((?:https?://|www\.)[^\s<>"\']+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>"\']*)?)')


def init_mobile_api(agent, ensure_models):
    """Wire the shared ForensicInvestigationAgent into this blueprint."""
    global _agent, _ensure_models
    _agent = agent
    _ensure_models = ensure_models


_ensure_models = lambda: None


def _client_ip():
    fwd = request.headers.get('X-Forwarded-For', '')
    return (fwd.split(',')[0].strip() if fwd else request.remote_addr) or 'unknown'


def _rate_limited():
    now = time.time()
    ip = _client_ip()
    with _hits_lock:
        q = _hits[ip]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return True
        q.append(now)
        # keep the dict from growing without bound
        if len(_hits) > 5000:
            for k in [k for k, v in _hits.items() if not v]:
                _hits.pop(k, None)
    return False


def _classify(text):
    """Pick how to investigate free text pasted or shared into the app.

    Returns (kind, payload):
      ('email', raw)        raw RFC 822 message with headers
      ('url', url)          a bare link
      ('message', urls)     SMS / WhatsApp text; urls may be empty
    """
    t = text.strip()
    head = t[:2000]
    if re.search(r'(?im)^(received|return-path|from|subject|message-id|dkim-signature):', head) and '\n' in head:
        return 'email', t
    if ' ' not in t and '\n' not in t and URL_RE.fullmatch(t):
        return 'url', t
    urls = []
    for m in URL_RE.finditer(t):
        u = m.group(1).rstrip(').,;!?\'"')
        if not re.match(r'(?i)https?://', u):
            u = 'http://' + u
        if u not in urls:
            urls.append(u)
    return 'message', urls[:3]


# Social-engineering signals in the message wording (not the link).
# Each: (regex, severity, indicator, explanation)
MESSAGE_SIGNALS = [
    (re.compile(r'\b(share|send|tell|give|forward)\b.{0,25}\b(otp|pin|cvv|password|passcode)\b', re.I),
     'HIGH', 'Asks for an OTP, PIN, CVV or password',
     'Banks, UPI apps and government offices never ask for these. Requests for them are the core of account-takeover fraud.'),
    (re.compile(r'\b(blocked|suspended|deactivated|frozen|disconnected?|terminated)\b', re.I),
     'MEDIUM', 'Threatens to block or cut off a service',
     'Fear of losing a bank account, SIM or electricity connection is used to rush the victim.'),
    (re.compile(r'\b(within|in)\s*\d+\s*(hours?|hrs?|minutes?|mins?)\b|\b(today|tonight)\b.{0,20}\b(\d{1,2}[:.]\d{2}|\d{1,2}\s*(am|pm))', re.I),
     'MEDIUM', 'Imposes a short deadline',
     'Artificial time pressure stops people from verifying the message.'),
    (re.compile(r'\b(kyc|pan|aadhaa?r)\b.{0,40}\b(update|link|verify|expired?|pending)\b', re.I),
     'MEDIUM', 'Fake KYC / PAN / Aadhaar update request',
     'KYC updates are done in-branch or in the official app, never through a link in an SMS.'),
    (re.compile(r'\b(won|winner|lottery|lucky draw|cashback|reward points?|prize|refund of)\b', re.I),
     'MEDIUM', 'Offers an unexpected prize, refund or reward',
     'Unexpected rewards are a common lure to collect card or UPI details.'),
    (re.compile(r'\b(call|contact|whatsapp)\b.{0,30}(\+?91[\s-]?)?[6-9]\d{9}\b', re.I),
     'MEDIUM', 'Asks you to call a private mobile number',
     'Real organisations use published customer-care numbers, not personal mobile numbers.'),
    (re.compile(r'\.apk\b|\b(anydesk|teamviewer|quick ?support|rustdesk)\b', re.I),
     'HIGH', 'Asks you to install an app or remote-access tool',
     'Sideloaded APKs and screen-sharing apps let fraudsters read OTPs and control the phone.'),
]


def _message_evidence(text):
    import uuid
    ev = []
    for rx, sev, indicator, why in MESSAGE_SIGNALS:
        if rx.search(text):
            ev.append({
                'id': f'EVD-MSG-{uuid.uuid4().hex[:6]}', 'source': 'MessageContentTool',
                'indicator': indicator, 'category': 'Social Engineering',
                'detection_result': 'Suspicious', 'confidence': 0.8 if sev == 'MEDIUM' else 0.92,
                'severity': sev, 'supporting_info': why, 'metadata': {},
            })
    return ev


def _level_for(score, critical_flags=0, high_flags=0):
    # Same thresholds as ForensicInvestigationAgent.assess_risk
    if score >= 80 or critical_flags >= 1:
        return 'CRITICAL'
    if score >= 60 or high_flags >= 2:
        return 'HIGH'
    if score >= 35:
        return 'MEDIUM'
    return 'LOW'


_LEVEL_RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}


def _investigate_message(text, urls):
    """SMS/WhatsApp text: agent-investigate each link, then layer message-wording evidence."""
    msg_ev = _message_evidence(text)
    reports = [_agent.investigate(request_type='url', input_data=u, file_content=None, options={}) for u in urls]
    if not reports and not msg_ev:
        return None

    if reports:
        base = max(reports, key=lambda r: r.get('risk_score', 0))
        # keep evidence from every link investigated, primary first
        others = [e for r in reports if r is not base for e in r.get('evidence', [])]
        base['evidence'] = list(base.get('evidence', [])) + others
        for r in reports:
            if r is base:
                continue
            for k, v in (r.get('iocs') or {}).items():
                base.setdefault('iocs', {}).setdefault(k, [])
                base['iocs'][k] = list(dict.fromkeys(base['iocs'][k] + list(v)))
        score = float(base.get('risk_score', 0))
        level = base.get('risk_level', 'LOW')
    else:
        import datetime, uuid
        base = {
            'investigation_id': f"INV-{datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
            'timestamp': datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + 'Z',
            'evidence': [], 'correlations': [], 'recommendations': [], 'iocs': {},
            'agent_actions': [], 'tools_used': [], 'confidence_score': 70.0,
            'human_review_required': True,
            'summary': 'Message analysed for social-engineering patterns. It contains no link.',
        }
        score, level = 10.0, 'LOW'

    if msg_ev:
        high = sum(1 for e in msg_ev if e['severity'] == 'HIGH')
        med = len(msg_ev) - high
        score = min(100.0, score + 25 * high + 10 * med)
        new_level = _level_for(score, high_flags=high + (1 if med >= 2 else 0))
        if _LEVEL_RANK[new_level] > _LEVEL_RANK.get(level, 0):
            level = new_level
        base['evidence'] = msg_ev + list(base.get('evidence', []))
        base['tools_used'] = list(base.get('tools_used', [])) + ['MessageContentTool']

    steps = base.setdefault('agent_actions', [])
    steps.append({
        'step': len(steps) + 1, 'tool_name': 'MessageContentTool', 'status': 'SUCCESS',
        'triggered_by': 'Mobile intake (shared SMS / chat message)',
        'reason': f'Scanned message wording for social-engineering patterns; investigated {len(urls)} embedded link(s).',
        'key_finding': f'{len(msg_ev)} pressure / fraud pattern(s) found in the message text.',
        'duration_ms': 0.0,
    })
    base['request_type'] = 'message'
    base['risk_score'] = round(score, 1)
    base['risk_level'] = level
    note = (f' Message wording adds {len(msg_ev)} social-engineering signal(s).' if msg_ev else '')
    base['risk_rationale'] = (base.get('risk_rationale') or f'Assessed as {level} ({round(score, 1)}/100).') + note
    return base


def _slim(report):
    """Drop the heavy dashboard-only structures the phone UI does not render."""
    keep = ('investigation_id', 'timestamp', 'request_type', 'risk_level', 'risk_score',
            'confidence_score', 'risk_rationale', 'summary', 'human_review_required',
            'evidence', 'correlations', 'recommendations', 'iocs', 'agent_actions', 'tools_used')
    out = {k: report.get(k) for k in keep if k in report}
    out['api_version'] = API_VERSION
    return out


@mobile_bp.after_request
def _cors(resp):
    # Capacitor serves the app from https://localhost on Android.
    origin = request.headers.get('Origin', '')
    allowed = {'https://localhost', 'http://localhost', 'capacitor://localhost'}
    extra = os.environ.get('MOBILE_ALLOWED_ORIGINS', '')
    allowed.update(o.strip() for o in extra.split(',') if o.strip())
    if origin in allowed:
        resp.headers['Access-Control-Allow-Origin'] = origin
        resp.headers['Vary'] = 'Origin'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@mobile_bp.route('/api/v1/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'api_version': API_VERSION})


@mobile_bp.route('/api/v1/scan', methods=['POST', 'OPTIONS'])
def scan():
    if request.method == 'OPTIONS':
        return ('', 204)
    if _rate_limited():
        return jsonify({'error': 'Too many scans. Please wait a minute and try again.'}), 429

    file_content = None
    req_type = None
    text = ''

    if 'file' in request.files:
        f = request.files['file']
        raw = f.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            return jsonify({'error': 'Email file is larger than 2 MB.'}), 413
        try:
            file_content = raw.decode('utf-8')
        except UnicodeDecodeError:
            file_content = raw.decode('latin1', errors='ignore')
        req_type = 'email'
        text = (f.filename or 'uploaded.eml')[:200]
    else:
        data = request.get_json(silent=True) or {}
        text = str(data.get('input', '') or '')
        req_type = data.get('type') or None
        if req_type not in (None, 'auto', 'url', 'email'):
            return jsonify({'error': 'type must be url, email or auto.'}), 400
        if req_type == 'auto':
            req_type = None

    if not text.strip() and not file_content:
        return jsonify({'error': 'Paste a link, message or email to scan.'}), 400
    if len(text) > MAX_INPUT_CHARS:
        return jsonify({'error': f'Input is longer than {MAX_INPUT_CHARS} characters.'}), 413

    _ensure_models()
    try:
        if file_content is not None:
            report = _agent.investigate(request_type='email', input_data=text,
                                        file_content=file_content, options={})
        else:
            kind, payload = _classify(text)
            if req_type == 'email' or kind == 'email':
                report = _agent.investigate(request_type='email', input_data='Pasted email',
                                            file_content=text, options={})
            elif req_type == 'url' or kind == 'url':
                target = payload if kind == 'url' else (payload[0] if payload else text.strip())
                report = _agent.investigate(request_type='url', input_data=target,
                                            file_content=None, options={})
            else:
                report = _investigate_message(text, payload)
                if report is None:
                    return jsonify({
                        'error': 'No link or warning signs found. Paste the full message, '
                                 'the link, or the raw email (with headers).'
                    }), 422
    except Exception as e:  # never leak a stack trace to the phone
        print(f'[mobile_api] investigation failed: {e}')
        return jsonify({'error': 'The analysis engine failed on this input. Please try again.'}), 500

    return jsonify(_slim(report))


@mobile_bp.route('/privacy', methods=['GET'])
def privacy():
    return render_template(
        'privacy.html',
        developer_name=os.environ.get('DEVELOPER_NAME', 'FEIA Project Team'),
        contact_email=os.environ.get('CONTACT_EMAIL', 'set-CONTACT_EMAIL@example.com'),
    )
