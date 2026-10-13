import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseContract, derivePublishedRemoteEntryUrl, contractNameMismatch } from '../src/contract.mjs';

test('parses a valid contract with integer version', () => {
  const contract = parseContract({ name: 'orders-remote', contractVersion: 1 }, 'contract.json');
  assert.equal(contract.name, 'orders-remote');
  assert.equal(contract.contractVersion, 1);
});

test('rejects semver-string contract versions — integers only', () => {
  assert.throws(
    () => parseContract({ name: 'orders-remote', contractVersion: '1.0.0' }, 'contract.json'),
    /not a valid contract\.json/
  );
});

test('rejects non-kebab-case remote names', () => {
  assert.throws(
    () => parseContract({ name: 'Orders_Remote', contractVersion: 1 }, 'contract.json'),
    /kebab-case/
  );
});

test('derives the standardized published remoteEntry URL from the contract (no subpath)', () => {
  const contract = { name: 'orders-remote', contractVersion: 2 };
  assert.equal(
    derivePublishedRemoteEntryUrl('https://stfedprod.blob.core.windows.net/remotes', contract, ''),
    'https://stfedprod.blob.core.windows.net/remotes/orders-remote/v2/remoteEntry.json'
  );
});

test('derivation tolerates trailing slashes and localized subpaths', () => {
  const contract = { name: 'orders-remote', contractVersion: 1 };
  assert.equal(
    derivePublishedRemoteEntryUrl('https://example.test/remotes/', contract, '/en/'),
    'https://example.test/remotes/orders-remote/v1/en/remoteEntry.json'
  );
});

test('name consistency: matching names pass', () => {
  assert.equal(
    contractNameMismatch({ name: 'orders-remote' }, { name: 'orders-remote' }),
    null
  );
});

test('name consistency: mismatch is a build-config error naming both sides', () => {
  const message = contractNameMismatch({ name: 'orders-remote' }, { name: 'order-remote' });
  assert.match(message, /orders-remote/);
  assert.match(message, /order-remote/);
  assert.match(message, /federation\.config/);
});
