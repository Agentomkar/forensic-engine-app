"""
Tests for the Play Store mobile API (/api/v1/*).
Run:  PUBLIC_MODE=1 python -m pytest test_mobile_api.py -q
"""
import os
import shutil
import tempfile

os.environ.setdefault('PUBLIC_MODE', '1')
os.environ.setdefault('MOBILE_RATE_LIMIT_PER_MIN', '1000')

import pytest  # noqa: E402
import app as A  # noqa: E402
import mobile_api  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ORIGIN = {'Origin': 'https://localhost'}


@pytest.fixture(scope='module')
def client():
    db = A.INVESTIGATIONS_DB_PATH
    backup = tempfile.mktemp()
    if os.path.exists(db):
        shutil.copy(db, backup)
    with open(db, 'rb') if os.path.exists(db) else open(os.devnull, 'rb') as f:
        before = f.read()
    yield A.app.test_client()
    with open(db, 'rb') if os.path.exists(db) else open(os.devnull, 'rb') as f:
        after = f.read()
    if os.path.exists(backup):
        shutil.move(backup, db)
    assert before == after, 'mobile scans must never be written to the shared investigations DB'


def scan(client, text):
    r = client.post('/api/v1/scan', json={'input': text}, headers=ORIGIN)
    return r.status_code, r.get_json()


def test_health(client):
    assert client.get('/api/v1/health').get_json()['status'] == 'ok'


def test_kyc_sms_is_high_risk_and_link_is_analysed_not_the_whole_message(client):
    msg = ('Dear SBI customer, your KYC has expired and your account will be blocked within '
           '24 hours. Update immediately: http://sbi-kyc-update.top/verify')
    code, d = scan(client, msg)
    assert code == 200
    assert d['risk_level'] in ('HIGH', 'CRITICAL')
    assert d['request_type'] == 'message'
    indicators = ' '.join(e['indicator'] for e in d['evidence'])
    assert 'Dear SBI customer' not in indicators, 'URL tool must receive the link, not the SMS body'
    assert any(e['source'] == 'MessageContentTool' for e in d['evidence'])


def test_official_bank_url_is_low(client):
    code, d = scan(client, 'https://www.onlinesbi.sbi')
    assert code == 200 and d['risk_level'] == 'LOW'


def test_otp_request_without_link_is_flagged(client):
    code, d = scan(client, 'Sir I am calling from your bank, please share the OTP you received to stop the debit')
    assert code == 200
    assert d['risk_level'] in ('MEDIUM', 'HIGH', 'CRITICAL')


def test_plain_chat_is_rejected_with_guidance(client):
    code, d = scan(client, 'hi, see you at the canteen')
    assert code == 422 and 'link' in d['error'].lower()


def test_empty_and_oversized(client):
    assert scan(client, '')[0] == 400
    assert scan(client, 'a' * (mobile_api.MAX_INPUT_CHARS + 1))[0] == 413


def test_eml_upload_phishing(client):
    with open(os.path.join(HERE, 'sample_emails', 'phishing_appleid_locked.eml'), 'rb') as f:
        r = client.post('/api/v1/scan', data={'file': (f, 'apple.eml')},
                        content_type='multipart/form-data', headers=ORIGIN)
    d = r.get_json()
    assert r.status_code == 200 and d['request_type'] == 'email'
    assert d['risk_level'] in ('HIGH', 'CRITICAL')


def test_pasted_legit_email_is_low(client):
    with open(os.path.join(HERE, 'sample_emails', 'legit_github_security.eml')) as f:
        code, d = scan(client, f.read())
    assert code == 200 and d['request_type'] == 'email' and d['risk_level'] == 'LOW'


def test_cors_only_for_app_origins(client):
    ok = client.post('/api/v1/scan', json={'input': 'example.com'}, headers=ORIGIN)
    bad = client.post('/api/v1/scan', json={'input': 'example.com'}, headers={'Origin': 'https://evil.example'})
    assert ok.headers.get('Access-Control-Allow-Origin') == 'https://localhost'
    assert bad.headers.get('Access-Control-Allow-Origin') is None


@pytest.mark.parametrize('path', ['/api/investigations', '/api/history', '/api/dashboard/stats', '/api/report'])
def test_public_mode_blocks_private_routes(client, path):
    assert client.get(path).status_code == 403


def test_privacy_page(client):
    r = client.get('/privacy')
    assert r.status_code == 200 and b'Privacy Policy' in r.data


def test_rate_limit(client, monkeypatch):
    monkeypatch.setattr(mobile_api, 'RATE_LIMIT', 2)
    mobile_api._hits.clear()
    codes = [scan(client, 'example.com')[0] for _ in range(3)]
    mobile_api._hits.clear()
    assert codes[-1] == 429
