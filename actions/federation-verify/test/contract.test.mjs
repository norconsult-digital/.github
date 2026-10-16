import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseContract, federationName, derivePublishedRemoteEntryUrl, contractNameMismatch } from '../src/contract.mjs';

const validContract = (overrides = {}) => ({
  product: 'bim',
  module: 'admin',
  name: 'admin-app',
  contractVersion: 1,
  ...overrides
});

test('parses a valid 4-field contract', () => {
  const contract = parseContract(validContract(), 'contract.json');
  assert.equal(contract.product, 'bim');
  assert.equal(contract.module, 'admin');
  assert.equal(contract.name, 'admin-app');
  assert.equal(contract.contractVersion, 1);
});

test('federation name is <product>-<name>', () => {
  assert.equal(federationName(validContract()), 'bim-admin-app');
});

test('rejects semver-string contract versions — integers only', () => {
  assert.throws(
    () => parseContract(validContract({ contractVersion: '1.0.0' }), 'contract.json'),
    /not a valid contract\.json/
  );
});

test('rejects non-kebab-case product', () => {
  assert.throws(
    () => parseContract(validContract({ product: 'BIM' }), 'contract.json'),
    /product: must be kebab-case/
  );
});

test('rejects non-kebab-case module', () => {
  assert.throws(
    () => parseContract(validContract({ module: 'Admin_Module' }), 'contract.json'),
    /module: must be kebab-case/
  );
});

test('rejects non-kebab-case name', () => {
  assert.throws(
    () => parseContract(validContract({ name: 'Admin_App' }), 'contract.json'),
    /name: must be kebab-case/
  );
});

test('rejects a missing field', () => {
  const { module, ...withoutModule } = validContract();
  assert.throws(() => parseContract(withoutModule, 'contract.json'), /module: must be kebab-case/);
});

test('derives the published remoteEntry URL from module + version (no subpath)', () => {
  assert.equal(
    derivePublishedRemoteEntryUrl('https://stfedprod.blob.core.windows.net/remotes', validContract({ contractVersion: 2 }), ''),
    'https://stfedprod.blob.core.windows.net/remotes/admin/v2/remoteEntry.json'
  );
});

test('derivation tolerates trailing slashes and localized subpaths', () => {
  assert.equal(
    derivePublishedRemoteEntryUrl('https://example.test/remotes/', validContract(), '/en/'),
    'https://example.test/remotes/admin/v1/en/remoteEntry.json'
  );
});

test('name consistency: remoteEntry named <product>-<name> passes', () => {
  assert.equal(
    contractNameMismatch(validContract(), { name: 'bim-admin-app' }),
    null
  );
});

test('name consistency: mismatch is a build-config error naming both sides', () => {
  const message = contractNameMismatch(validContract(), { name: 'admin-app' });
  assert.match(message, /bim-admin-app/);
  assert.match(message, /admin-app/);
  assert.match(message, /federation\.config/);
});
