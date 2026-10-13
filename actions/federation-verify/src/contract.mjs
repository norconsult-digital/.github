import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';

// contract.json — checked in at each remote project's root. Declares the
// federation identity and the current (integer) contract version. Bumping it
// is a deliberate, reviewable PR act.

export const contractSchema = z.looseObject({
  name: z
    .string()
    .regex(/^[a-z][a-z0-9]*(-[a-z0-9]+)*$/, 'must be kebab-case, e.g. orders-remote'),
  contractVersion: z.number().int().positive()
});

/** @returns {z.infer<typeof contractSchema>} */
export function parseContract(json, label) {
  const result = contractSchema.safeParse(json);
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('\n');
    throw new Error(`${label} is not a valid contract.json:\n${issues}`);
  }
  return result.data;
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
