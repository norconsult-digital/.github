import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

// contract.json — checked in at each remote project's root. Declares the
// federation identity and the current (integer) contract version. Bumping it
// is a deliberate, reviewable PR act.

const KEBAB_CASE = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;

export function parseContract(json, label) {
  const issues = [];
  if (typeof json !== 'object' || json === null || Array.isArray(json)) {
    throw new Error(`${label} is not a valid contract.json:\n  - (root): expected an object`);
  }
  if (typeof json.name !== 'string' || !KEBAB_CASE.test(json.name)) {
    issues.push('  - name: must be kebab-case, e.g. orders-remote');
  }
  if (typeof json.contractVersion !== 'number' || !Number.isInteger(json.contractVersion) || json.contractVersion < 1) {
    issues.push('  - contractVersion: expected a positive integer');
  }
  if (issues.length > 0) {
    throw new Error(`${label} is not a valid contract.json:\n${issues.join('\n')}`);
  }
  return json;
}

export async function loadContract(projectDir) {
  const path = join(projectDir, 'contract.json');
  let json;
  try {
    json = JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new Error(`could not read '${path}': ${error.message}`);
  }
  return parseContract(json, path);
}

// Builds the URL (or path) of the already-published remoteEntry.json that a new
// build is compared against. Layout is fixed by convention:
//   <base-url>/<name>/v<version>/[<subpath>/]remoteEntry.json
// name + version come from contract.json; subpath is optional and only used for
// localized/variant builds (e.g. 'en'). The remoteEntry.json filename is fixed.
export function derivePublishedRemoteEntryUrl(baseUrl, contract, subpath) {
  const segments = [
    baseUrl.replace(/\/+$/, ''),
    `${contract.name}`,
    `v${contract.contractVersion}`,
    ...(subpath ? [subpath.replace(/^\/+|\/+$/g, '')] : []),
    'remoteEntry.json'
  ];
  return segments.join('/');
}

// The remote's federation name is declared in two places that must agree:
// contract.json (drives registry paths) and federation.config.mjs (lands in
// the built remoteEntry). Mismatch = broken build config, not a contract break.
export function contractNameMismatch(contract, candidateRemoteEntry) {
  if (contract.name === candidateRemoteEntry.name) return null;
  return `contract.json declares name '${contract.name}' but the built remoteEntry is named '${candidateRemoteEntry.name}' — align contract.json with federation.config`;
}
