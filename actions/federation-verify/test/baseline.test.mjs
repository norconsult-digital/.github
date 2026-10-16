import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadJson, MissingBaselineError } from '../src/index.mjs';
import { missingBaselineMessage } from '../src/report.mjs';

test('loadJson signals a missing baseline (404) as MissingBaselineError, not a hard error', async () => {
  const fetch404 = async () => ({ status: 404, ok: false });
  await assert.rejects(
    loadJson('https://example.test/remotes/orders-remote/v2/remoteEntry.json', 'baseline', fetch404),
    MissingBaselineError
  );
});

test('loadJson returns parsed json when the baseline exists', async () => {
  const payload = { name: 'orders-remote', exposes: [] };
  const fetchOk = async () => ({ status: 200, ok: true, json: async () => payload });
  const result = await loadJson('https://example.test/remoteEntry.json', 'baseline', fetchOk);
  assert.deepEqual(result, payload);
});

test('loadJson still throws (non-missing) on other HTTP errors', async () => {
  const fetch500 = async () => ({ status: 500, ok: false, statusText: 'Server Error' });
  await assert.rejects(
    loadJson('https://example.test/remoteEntry.json', 'baseline', fetch500),
    (error) => !(error instanceof MissingBaselineError) && /500/.test(error.message)
  );
});

test('missing-baseline message names the new version and flags intent', () => {
  const message = missingBaselineMessage({ product: 'bim', module: 'orders', name: 'orders-remote', contractVersion: 2 }, '');
  assert.match(message, /bim-orders-remote v2/);
  assert.match(message, /NEW contract version/);
  assert.match(message, /intentional/);
});

test('missing-baseline message includes the subpath for localized builds', () => {
  const message = missingBaselineMessage({ product: 'bim', module: 'orders', name: 'orders-remote', contractVersion: 3 }, 'en');
  assert.match(message, /bim-orders-remote v3/);
  assert.match(message, /subpath en/);
});
