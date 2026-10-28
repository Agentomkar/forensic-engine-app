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
    """Pick the investigation type for free text pasted or shared into the app."""
    t = text.strip()
    head = t[:2000]
    if re.search(r'(?im)^(received|return-path|from|subject|message-id|dkim-signature):', head) and '\n' in head:
        return 'email', t
    if ' ' not in t and URL_RE.fullmatch(t):
        return 'url', t
    m = URL_RE.search(t)
    if m:
        # SMS / WhatsApp message containing a link: investigate the link,
        # but keep the full message text as context for the agent.
        return 'url', t
    return None, t


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

    if file_content is None:
        detected, text = _classify(text)
        req_type = req_type or detected
        if req_type is None:
            return jsonify({
                'error': 'No link or email headers found. Paste the full link, '
                         'the message that contains it, or the raw email (with headers).'
            }), 422
        if req_type == 'email':
            file_content, text = text, 'Pasted email'

    _ensure_models()
    try:
        report = _agent.investigate(request_type=req_type, input_data=text,
                                    file_content=file_content, options={})
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
