import semver from 'semver';

export const BREAKING = 'breaking';
export const WARNING = 'warning';
export const INFO = 'info';

/**
 * @typedef {object} Violation
 * @property {'breaking' | 'warning' | 'info'} level
 * @property {string} subject - package name, exposes key, or remote name
 * @property {string} message
 */

/**
 * Semantically diffs two parsed remoteEntry.json documents.
 * Chunk hashes, outFileNames and resolved `version` fields are ignored on
 * purpose: only the contract-relevant tuples are compared.
 *
 * @returns {Violation[]} empty when the candidate is fully compatible
 */
export function diffRemoteEntries(baseline, candidate) {
  return [
    ...checkRemoteName(baseline, candidate),
    ...diffExposes(baseline.exposes, candidate.exposes),
    ...diffShared(baseline.shared, candidate.shared)
  ];
}

function checkRemoteName(baseline, candidate) {
  if (baseline.name === candidate.name) return [];
  return [
    {
      level: BREAKING,
      subject: 'name',
      message: `remote name changed '${baseline.name}' -> '${candidate.name}'; hosts resolve remotes by name`
    }
  ];
}

function diffExposes(baselineExposes, candidateExposes) {
  const violations = [];
  const baselineKeys = new Set(baselineExposes.map((entry) => entry.key));
  const candidateKeys = new Set(candidateExposes.map((entry) => entry.key));

  for (const key of baselineKeys) {
    if (!candidateKeys.has(key)) {
      violations.push({
        level: BREAKING,
        subject: key,
        message: `exposed module '${key}' was removed; hosts importing it will fail to load`
      });
    }
  }
  for (const key of candidateKeys) {
    if (!baselineKeys.has(key)) {
      violations.push({ level: INFO, subject: key, message: `exposed module '${key}' was added` });
    }
  }
  return violations;
}

function diffShared(baselineShared, candidateShared) {
  const violations = [];
  const baselineByPackage = indexByPackage(baselineShared);
  const candidateByPackage = indexByPackage(candidateShared);

  for (const [packageName, baselineEntry] of baselineByPackage) {
    const candidateEntry = candidateByPackage.get(packageName);
    violations.push(
      ...(candidateEntry
        ? diffSharedEntry(packageName, baselineEntry, candidateEntry)
        : [removedPackage(packageName)])
    );
  }
  for (const [packageName, candidateEntry] of candidateByPackage) {
    if (!baselineByPackage.has(packageName)) {
      violations.push(addedPackage(packageName, candidateEntry));
    }
  }
  return violations;
}

function diffSharedEntry(packageName, baselineEntry, candidateEntry) {
  return [
    flagTightened(packageName, 'singleton', baselineEntry.singleton, candidateEntry.singleton),
    flagTightened(packageName, 'strictVersion', baselineEntry.strictVersion, candidateEntry.strictVersion),
    baselineEntry.requiredVersion !== candidateEntry.requiredVersion
      ? requiredVersionChanged(packageName, baselineEntry.requiredVersion, candidateEntry.requiredVersion)
      : null
  ].filter(Boolean);
}

function flagTightened(packageName, flag, was, is) {
  if (!was && is) {
    return {
      level: BREAKING,
      subject: packageName,
      message: `'${flag}' tightened false -> true; hosts must now satisfy this constraint`
    };
  }
  if (was && !is) {
    return { level: INFO, subject: packageName, message: `'${flag}' relaxed true -> false` };
  }
  return null;
}

function removedPackage(packageName) {
  return {
    level: WARNING,
    subject: packageName,
    message: 'shared package removed; the remote now bundles it (harmless unless another module consumed it through this remote)'
  };
}

function addedPackage(packageName, entry) {
  if (entry.singleton && entry.strictVersion) {
    return {
      level: BREAKING,
      subject: packageName,
      message: `new strict singleton '${packageName}@${entry.requiredVersion}' added; hosts not providing it will fail to load`
    };
  }
  return {
    level: WARNING,
    subject: packageName,
    message: `shared package added (singleton=${entry.singleton}, strictVersion=${entry.strictVersion}); review runtime fallback behavior`
  };
}

function requiredVersionChanged(packageName, oldRange, newRange) {
  // native federation leaves requiredVersion 'auto' unresolved in the built
  // remoteEntry (resolved at runtime against the host import map). 'auto' is
  // not a semver range, so any change involving it can't be decided
  // mechanically — flag for human review instead of a false breaking verdict.
  if (oldRange === 'auto' || newRange === 'auto') {
    return {
      level: WARNING,
      subject: packageName,
      message: `requiredVersion '${oldRange}' -> '${newRange}' involves 'auto' (runtime-resolved); review manually — semver comparison not possible`
    };
  }
  try {
    if (semver.subset(oldRange, newRange, { includePrerelease: true })) {
      return {
        level: INFO,
        subject: packageName,
        message: `requiredVersion widened '${oldRange}' -> '${newRange}'; every previously accepted version still satisfies`
      };
    }
    if (!semver.intersects(oldRange, newRange, { includePrerelease: true })) {
      return {
        level: BREAKING,
        subject: packageName,
        message: `requiredVersion '${oldRange}' -> '${newRange}' has no overlap; all current hosts will fail`
      };
    }
    return {
      level: BREAKING,
      subject: packageName,
      message: `requiredVersion narrowed '${oldRange}' -> '${newRange}'; hosts on versions outside the new range will fail`
    };
  } catch {
    return {
      level: BREAKING,
      subject: packageName,
      message: `requiredVersion '${oldRange}' -> '${newRange}' could not be parsed as semver ranges`
    };
  }
}

function indexByPackage(sharedEntries) {
  const byPackage = new Map();
  for (const entry of sharedEntries) {
    if (byPackage.has(entry.packageName)) {
      throw new Error(`remoteEntry contains duplicate shared entry for '${entry.packageName}'`);
    }
    byPackage.set(entry.packageName, entry);
  }
  return byPackage;
}
