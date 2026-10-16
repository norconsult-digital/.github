import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

// contract.json — checked in at each remote project's root. Declares the
// federation identity and the current (integer) contract version. Bumping it
// is a deliberate, reviewable PR act. Two identities derive from it:
//   container      = module                 (storage path segment)
//   federationName = <product>-<name>        (the built remoteEntry's name)

const KEBAB_CASE = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;

export function parseContract(json, label) {
  const issues = [];
  if (typeof json !== 'object' || json === null || Array.isArray(json)) {
    throw new Error(`${label} is not a valid contract.json:\n  - (root): expected an object`);
  }
  for (const field of ['product', 'module', 'name']) {
    if (typeof json[field] !== 'string' || !KEBAB_CASE.test(json[field])) {
      issues.push(`  - ${field}: must be kebab-case, e.g. orders-remote`);
    }
  }
  if (typeof json.contractVersion !== 'number' || !Number.isInteger(json.contractVersion) || json.contractVersion < 1) {
    issues.push('  - contractVersion: expected a positive integer');
  }
  if (issues.length > 0) {
    throw new Error(`${label} is not a valid contract.json:\n${issues.join('\n')}`);
  }
  return json;
}

// The remote's federation name — what native-federation stamps as the
// remoteEntry's `name`. Composed from the product and the app name.
export function federationName(contract) {
  return `${contract.product}-${contract.name}`;
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
//   <base-url>/<module>/v<version>/[<subpath>/]remoteEntry.json
// module (the container) + version come from contract.json; subpath is optional
// and only used for localized/variant builds (e.g. 'en'). The remoteEntry.json
// filename is fixed.
export function derivePublishedRemoteEntryUrl(baseUrl, contract, subpath) {
  const segments = [
    baseUrl.replace(/\/+$/, ''),
    `${contract.module}`,
    `v${contract.contractVersion}`,
    ...(subpath ? [subpath.replace(/^\/+|\/+$/g, '')] : []),
    'remoteEntry.json'
  ];
  return segments.join('/');
}

// The remote's federation name is declared in two places that must agree:
// contract.json (as <product>-<name>) and federation.config.mjs (lands in the
// built remoteEntry). Mismatch = broken build config, not a contract break.
export function contractNameMismatch(contract, candidateRemoteEntry) {
  const expected = federationName(contract);
  if (expected === candidateRemoteEntry.name) return null;
  return `contract.json implies federation name '${expected}' but the built remoteEntry is named '${candidateRemoteEntry.name}' — align contract.json with federation.config`;
}
