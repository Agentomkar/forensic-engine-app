import { test } from 'node:test';
import assert from 'node:assert/strict';
import { quickCheck, extractUrls } from '../src/heuristics.js';

test('KYC scam SMS is HIGH', () => {
  const r = quickCheck('Dear customer your SBI KYC expired, account will be blocked in 24 hours. Update at http://sbi-kyc-update.top/verify');
  assert.equal(r.level, 'HIGH');
});
test('real bank site is LOW', () => {
  assert.equal(quickCheck('https://www.onlinesbi.sbi').level, 'LOW');
  assert.equal(quickCheck('https://www.hdfcbank.com/personal').level, 'LOW');
});
test('government site is LOW', () => assert.equal(quickCheck('https://uidai.gov.in').level, 'LOW'));
test('apk download is flagged', () => assert.notEqual(quickCheck('Install http://bit.ly/x/app.apk').level, 'LOW'));
test('IP link flagged', () => assert.notEqual(quickCheck('http://185.220.101.42/login').level, 'LOW'));
test('plain chat is UNKNOWN', () => assert.equal(quickCheck('hi, see you at 5').level, 'UNKNOWN'));
test('OTP sharing request flagged', () => assert.notEqual(quickCheck('Please share the OTP you received to claim your cashback reward').level, 'LOW'));
test('url extraction strips trailing punctuation', () => {
  assert.equal(extractUrls('go to example.com/a).')[0].href, 'http://example.com/a');
});
