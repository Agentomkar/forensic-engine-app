import { test } from 'node:test';
import assert from 'node:assert/strict';
import { plainFinding } from '../src/plain.js';
test('ml finding becomes plain', () => assert.equal(plainFinding('RandomForest Phishing Classifier: 94.0%').title, 'AI model: 94% likely phishing'));
test('tld keeps domain', () => assert.match(plainFinding('High-Risk TLD: x.top').title, /x\.top/));
test('unknown passes through', () => assert.deepEqual(plainFinding('Threatens to block', 'why'), { title: 'Threatens to block', body: 'why' }));
