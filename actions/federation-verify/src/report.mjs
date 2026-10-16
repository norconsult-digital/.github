import { appendFile } from 'node:fs/promises';
import { BREAKING, WARNING, INFO } from './diff.mjs';

const ORDER = { [BREAKING]: 0, [WARNING]: 1, [INFO]: 2 };
const ICON = { [BREAKING]: '✖', [WARNING]: '⚠', [INFO]: 'ℹ' };

function sortViolations(violations) {
  return [...violations].sort((a, b) => ORDER[a.level] - ORDER[b.level]);
}

export function formatText(violations) {
  if (violations.length === 0) {
    return '✔ candidate is contract-compatible with the baseline';
  }
  const lines = sortViolations(violations).map(
    (violation) => `${ICON[violation.level]} [${violation.level}] ${violation.subject}: ${violation.message}`
  );
  return lines.join('\n');
}

function formatMarkdown(violations) {
  if (violations.length === 0) {
    return '✔ candidate is contract-compatible with the baseline\n';
  }
  const rows = sortViolations(violations).map(
    (violation) => `| ${violation.level} | \`${violation.subject}\` | ${violation.message} |`
  );
  return ['| Level | Subject | Change |', '| --- | --- | --- |', ...rows, ''].join('\n');
}

// Renders violations as workflow annotations (file-less, shown on the run summary page).
export function emitAnnotations(violations, log = console.log) {
  if (!process.env.GITHUB_ACTIONS) return;
  for (const violation of violations) {
    const command = violation.level === BREAKING ? 'error' : violation.level === WARNING ? 'warning' : 'notice';
    log(`::${command} title=contract ${violation.level} (${violation.subject})::${violation.message}`);
  }
}

export function missingBaselineMessage(contract, subpath) {
  const at = `${contract.name} v${contract.contractVersion}${subpath ? ` (subpath ${subpath})` : ''}`;
  return (
    `No published baseline for ${at} — treating as a NEW contract version. ` +
    `Nothing to compare against; ensure this version bump is intentional and human-reviewed.`
  );
}

// A missing baseline is not a contract break — it signals a new contract
// version with nothing to compare against. Warn loudly (annotation + step
// summary) but let the caller pass: new versions must be able to roll out, and
// the version bump itself is the reviewed gate.
export async function reportMissingBaseline(contract, subpath, url, log = console.log) {
  const message = missingBaselineMessage(contract, subpath);
  log(message);
  if (process.env.GITHUB_ACTIONS) {
    log(`::warning title=federation-verify: new contract version::${message}`);
  }
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    await appendFile(
      summaryPath,
      `## ⚠️ Federation contract: new version (no baseline)\n\n${message}\n\nExpected baseline: \`${url}\`\n`
    );
  }
}

export async function writeStepSummary(violations) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;
  const breakingCount = violations.filter((violation) => violation.level === BREAKING).length;
  const heading = breakingCount > 0
    ? `## ❌ Federation contract: ${breakingCount} breaking change(s)\n\n`
    : '## ✅ Federation contract: no breaking changes\n\n';
  await appendFile(summaryPath, heading + formatMarkdown(violations) + '\n');
}
