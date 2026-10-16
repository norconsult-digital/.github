// Structural validation for native-federation remoteEntry.json files.
// Unknown fields pass through: the real artifact carries extra fields
// (outFileName, dev/prod entry maps, etc.) that are not contract-relevant.

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

export function parseRemoteEntry(json, label) {
  const issues = [];
  if (!isObject(json)) {
    throw new Error(`${label} is not a valid remoteEntry.json:\n  - (root): expected an object`);
  }
  if (!nonEmptyString(json.name)) {
    issues.push('  - name: expected a non-empty string');
  }

  const shared = normalizeShared(json.shared, issues);
  const exposes = normalizeExposes(json.exposes, issues);

  if (issues.length > 0) {
    throw new Error(`${label} is not a valid remoteEntry.json:\n${issues.join('\n')}`);
  }
  return { ...json, shared, exposes };
}

function normalizeShared(value, issues) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    issues.push('  - shared: expected an array');
    return [];
  }
  return value.map((entry, index) => {
    if (!isObject(entry)) {
      issues.push(`  - shared.${index}: expected an object`);
      return entry;
    }
    if (!nonEmptyString(entry.packageName)) {
      issues.push(`  - shared.${index}.packageName: expected a non-empty string`);
    }
    if (!nonEmptyString(entry.requiredVersion)) {
      issues.push(`  - shared.${index}.requiredVersion: expected a non-empty string`);
    }
    // version is the resolved build version — unused by the diff rules.
    return { ...entry, singleton: entry.singleton ?? false, strictVersion: entry.strictVersion ?? false };
  });
}

function normalizeExposes(value, issues) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    issues.push('  - exposes: expected an array');
    return [];
  }
  return value.map((entry, index) => {
    if (!isObject(entry)) {
      issues.push(`  - exposes.${index}: expected an object`);
      return entry;
    }
    if (!nonEmptyString(entry.key)) {
      issues.push(`  - exposes.${index}.key: expected a non-empty string`);
    }
    return entry;
  });
}
