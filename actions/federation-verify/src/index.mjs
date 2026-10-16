import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';
import { parseRemoteEntry } from './remote-entry.mjs';
import { diffRemoteEntries, BREAKING } from './diff.mjs';
import { formatText, emitAnnotations, writeStepSummary, reportMissingBaseline } from './report.mjs';
import { loadContract, derivePublishedRemoteEntryUrl, contractNameMismatch } from './contract.mjs';

// A missing published baseline (404) is not a failure — it means this is a new
// contract version with nothing to compare against. Signalled with a dedicated
// error type so main() can warn-and-pass instead of exiting 2.
export class MissingBaselineError extends Error {}

const USAGE = `federation-verify — remoteEntry.json contract drift check

Compares a freshly built remoteEntry.json against the one already published for
its contract version, and fails on contract-breaking changes.

The published remoteEntry.json URL is derived from conventions:
  <base-url>/<module>/v<version>/[<subpath>/]remoteEntry.json
where <module> (the container) and <version> come from contract.json (in
--project-dir) and <base-url> is the remote's public base (env
FEDERATION_REMOTE_BASE_URL).

Usage:
  FEDERATION_REMOTE_BASE_URL=<url> federation-verify --candidate <path> [options]

Options:
  --candidate <path>     Freshly built remoteEntry.json (required).
  --project-dir <path>   Remote project root containing contract.json (default: .)
  --subpath <path>       Optional directory for localized/variant builds within the
                         published build (e.g. 'en'). Default: none.

Output:
  Plain-text log on stdout; inline workflow annotations and a markdown step
  summary are emitted automatically when run under GitHub Actions.

Exit codes:
  0  no breaking changes (warnings/info may still be reported)
  1  breaking changes detected
  2  usage, IO, validation, or build-config error
`;

export async function loadJson(reference, label, fetchImpl = fetch) {
  if (/^https?:\/\//.test(reference)) {
    const response = await fetchImpl(reference);
    if (response.status === 404) {
      throw new MissingBaselineError(
        `${label}: no baseline found at ${reference}.`
      );
    }
    if (!response.ok) {
      throw new Error(`${label}: GET ${reference} failed with ${response.status} ${response.statusText}`);
    }
    return response.json();
  }
  try {
    return JSON.parse(await readFile(reference, 'utf8'));
  } catch (error) {
    throw new Error(`${label}: could not read '${reference}': ${error.message}`);
  }
}

async function resolvePublishedRemoteEntryUrl(contract, subpath) {
  const baseUrl = process.env.FEDERATION_REMOTE_BASE_URL;
  if (!baseUrl) {
    throw new Error(
      `FEDERATION_REMOTE_BASE_URL is not set; pass the base-url input ` +
      `(e.g. the repo variable) so the published remoteEntry.json URL can be derived`
    );
  }
  const url = derivePublishedRemoteEntryUrl(baseUrl, contract, subpath);
  console.log(`published remoteEntry derived from contract.json: ${url}`);
  return url;
}

async function main() {
  const { values } = parseArgs({
    options: {
      candidate: { type: 'string' },
      'project-dir': { type: 'string', default: '.' },
      subpath: { type: 'string', default: '' },
      help: { type: 'boolean', short: 'h', default: false }
    }
  });

  if (values.help || !values.candidate) {
    console.log(USAGE);
    process.exit(values.help ? 0 : 2);
  }

  const candidate = parseRemoteEntry(await loadJson(values.candidate, 'candidate'), 'candidate');

  // contract.json is required: it drives the published remoteEntry URL and the
  // name-consistency check against the built remoteEntry.
  const contract = await loadContract(values['project-dir']);
  const mismatch = contractNameMismatch(contract, candidate);
  if (mismatch) throw new Error(mismatch);

  const publishedUrl = await resolvePublishedRemoteEntryUrl(contract, values.subpath);

  let baselineJson;
  try {
    baselineJson = await loadJson(publishedUrl, 'baseline');
  } catch (error) {
    if (error instanceof MissingBaselineError) {
      // New contract version: warn loudly but don't fail — let it roll out.
      await reportMissingBaseline(contract, values.subpath, publishedUrl);
      return;
    }
    throw error;
  }
  const baseline = parseRemoteEntry(baselineJson, 'baseline');

  const violations = diffRemoteEntries(baseline, candidate);

  console.log(formatText(violations));
  emitAnnotations(violations);
  await writeStepSummary(violations);

  const breakingCount = violations.filter((violation) => violation.level === BREAKING).length;
  if (breakingCount > 0) {
    console.error(
      `\n${breakingCount} breaking change(s) under an unchanged contract version. ` +
      `Revert the changes, or bump contractVersion in contract.json and publish a new contract baseline.`
    );
    process.exit(1);
  }
}

// Run as a CLI only when invoked directly (not when imported by tests).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(`federation-verify failed: ${error.message}`);
    process.exit(2);
  });
}
