import { test } from 'node:test';
import assert from 'node:assert/strict';
import { diffRemoteEntries, BREAKING, WARNING, INFO } from '../src/diff.mjs';
import { parseRemoteEntry } from '../src/remote-entry.mjs';

// Fixture-driven suite: each case is a (baseline, candidate, expected levels) triple.
// This file doubles as the executable documentation of what "breaking" means.

const shared = (packageName, overrides = {}) => ({
  packageName,
  version: '21.1.3',
  requiredVersion: '^21.0.0',
  singleton: true,
  strictVersion: true,
  ...overrides
});

const baselineRemote = (overrides = {}) => ({
  name: 'orders-remote',
  shared: [
    shared('@angular/core'),
    shared('@ngrx/signals'),
    shared('rxjs', { version: '7.8.2', requiredVersion: '^7.8.0', strictVersion: false }),
    shared('zone.js', { version: '0.16.2', requiredVersion: '~0.16.0', singleton: false, strictVersion: false })
  ],
  exposes: [
    { key: './routes', outFileName: 'routes-a1b2c3.js' },
    { key: './orders-widget', outFileName: 'orders-widget-d4e5f6.js' }
  ],
  ...overrides
});

const cases = [
  {
    name: 'identical contract tuples pass (only chunk hashes and resolved versions changed)',
    candidate: baselineRemote({
      shared: [
        shared('@angular/core', { version: '21.2.0' }), // resolved version is not contract-relevant
        shared('@ngrx/signals'),
        shared('rxjs', { version: '7.8.2', requiredVersion: '^7.8.0', strictVersion: false }),
        shared('zone.js', { version: '0.16.2', requiredVersion: '~0.16.0', singleton: false, strictVersion: false })
      ],
      exposes: [
        { key: './routes', outFileName: 'routes-zzz999.js' },
        { key: './orders-widget', outFileName: 'orders-widget-yyy888.js' }
      ]
    }),
    expectLevels: []
  },
  {
    name: 'added strict singleton is breaking',
    candidate: baselineRemote({
      shared: [...baselineRemote().shared, shared('@angular/material')]
    }),
    expectLevels: [BREAKING]
  },
  {
    name: 'added secondary entry point of a strict singleton root is info when the root range is covered',
    candidate: baselineRemote({
      shared: [...baselineRemote().shared, shared('@ngrx/signals/entities', { requiredVersion: '^21' })]
    }),
    expectLevels: [INFO]
  },
  {
    name: 'added secondary entry point with a narrower range than its root is breaking',
    candidate: baselineRemote({
      shared: [...baselineRemote().shared, shared('@ngrx/signals/entities', { requiredVersion: '^21.2.0' })]
    }),
    expectLevels: [BREAKING]
  },
  {
    name: 'added strict secondary entry point of a non-strict root is breaking',
    candidate: baselineRemote({
      shared: [...baselineRemote().shared, shared('rxjs/operators', { version: '7.8.2', requiredVersion: '^7.8.0' })]
    }),
    expectLevels: [BREAKING]
  },
  {
    name: 'added secondary entry point whose root is not shared is breaking',
    candidate: baselineRemote({
      shared: [...baselineRemote().shared, shared('@angular/forms/signals')]
    }),
    expectLevels: [BREAKING]
  },
  {
    name: 'added non-strict singleton is a warning',
    candidate: baselineRemote({
      shared: [...baselineRemote().shared, shared('chart.js', { requiredVersion: '^4.0.0', strictVersion: false })]
    }),
    expectLevels: [WARNING]
  },
  {
    name: 'added non-singleton package is a warning',
    candidate: baselineRemote({
      shared: [...baselineRemote().shared, shared('chart.js', { requiredVersion: '^4.0.0', singleton: false, strictVersion: false })]
    }),
    expectLevels: [WARNING]
  },
  {
    name: 'removed shared package is a warning, not breaking',
    candidate: baselineRemote({
      shared: baselineRemote().shared.filter((entry) => entry.packageName !== 'zone.js')
    }),
    expectLevels: [WARNING]
  },
  {
    name: 'narrowed requiredVersion is breaking',
    candidate: baselineRemote({
      shared: baselineRemote().shared.map((entry) =>
        entry.packageName === '@angular/core' ? { ...entry, requiredVersion: '^21.2.0' } : entry
      )
    }),
    expectLevels: [BREAKING]
  },
  {
    name: 'non-overlapping requiredVersion is breaking',
    candidate: baselineRemote({
      shared: baselineRemote().shared.map((entry) =>
        entry.packageName === '@angular/core' ? { ...entry, requiredVersion: '^22.0.0' } : entry
      )
    }),
    expectLevels: [BREAKING]
  },
  {
    name: 'widened requiredVersion is info',
    candidate: baselineRemote({
      shared: baselineRemote().shared.map((entry) =>
        entry.packageName === '@angular/core' ? { ...entry, requiredVersion: '>=21.0.0' } : entry
      )
    }),
    expectLevels: [INFO]
  },
  {
    name: 'singleton tightened false -> true is breaking',
    candidate: baselineRemote({
      shared: baselineRemote().shared.map((entry) =>
        entry.packageName === 'zone.js' ? { ...entry, singleton: true } : entry
      )
    }),
    expectLevels: [BREAKING]
  },
  {
    name: 'strictVersion tightened false -> true is breaking',
    candidate: baselineRemote({
      shared: baselineRemote().shared.map((entry) =>
        entry.packageName === 'rxjs' ? { ...entry, strictVersion: true } : entry
      )
    }),
    expectLevels: [BREAKING]
  },
  {
    name: 'strictVersion relaxed true -> false is info',
    candidate: baselineRemote({
      shared: baselineRemote().shared.map((entry) =>
        entry.packageName === '@angular/core' ? { ...entry, strictVersion: false } : entry
      )
    }),
    expectLevels: [INFO]
  },
  {
    name: 'removed exposes key is breaking',
    candidate: baselineRemote({
      exposes: [{ key: './routes', outFileName: 'routes-a1b2c3.js' }]
    }),
    expectLevels: [BREAKING]
  },
  {
    name: 'added exposes key is info',
    candidate: baselineRemote({
      exposes: [...baselineRemote().exposes, { key: './legacy-widget', outFileName: 'legacy-x7y8z9.js' }]
    }),
    expectLevels: [INFO]
  },
  {
    name: 'remote name change is breaking',
    candidate: baselineRemote({ name: 'orders-mfe' }),
    expectLevels: [BREAKING]
  },
  {
    name: 'unparseable requiredVersion is breaking',
    candidate: baselineRemote({
      shared: baselineRemote().shared.map((entry) =>
        entry.packageName === '@angular/core' ? { ...entry, requiredVersion: 'latest' } : entry
      )
    }),
    expectLevels: [BREAKING]
  },
  {
    name: "'auto' -> explicit range is a warning (runtime-resolved, not semver-comparable)",
    candidate: baselineRemote({
      shared: baselineRemote().shared.map((entry) =>
        entry.packageName === '@angular/core' ? { ...entry, requiredVersion: 'auto' } : entry
      )
    }),
    expectLevels: [WARNING]
  },
  {
    name: "'auto' -> explicit range is a warning (runtime-resolved, not semver-comparable)",
    candidate: baselineRemote({
      shared: baselineRemote().shared.map((entry) =>
        entry.packageName === '@angular/core' ? { ...entry, requiredVersion: 'auto' } : entry
      )
    }),
    expectLevels: [WARNING]
  }
];

for (const { name, candidate, expectLevels } of cases) {
  test(name, () => {
    const violations = diffRemoteEntries(baselineRemote(), candidate);
    assert.deepEqual(violations.map((violation) => violation.level).sort(), expectLevels.sort());
  });
}

test("'auto' on the baseline side is also a warning, not a parse failure", () => {
  const baseline = baselineRemote({
    shared: baselineRemote().shared.map((entry) =>
      entry.packageName === '@angular/core' ? { ...entry, requiredVersion: 'auto' } : entry
    )
  });
  const candidate = baselineRemote({
    shared: baselineRemote().shared.map((entry) =>
      entry.packageName === '@angular/core' ? { ...entry, requiredVersion: '^22.0.0' } : entry
    )
  });
  const violations = diffRemoteEntries(baseline, candidate);
  assert.deepEqual(violations.map((violation) => violation.level), [WARNING]);
});

test('remote name mismatch reports both names', () => {
  const [violation] = diffRemoteEntries(baselineRemote(), baselineRemote({ name: 'orders-mfe' }));
  assert.match(violation.message, /orders-remote/);
  assert.match(violation.message, /orders-mfe/);
});

test('malformed candidate fails validation with a readable message', () => {
  assert.throws(
    () => parseRemoteEntry({ name: 'orders-remote', shared: [{ requiredVersion: '^21.0.0' }] }, 'candidate'),
    /candidate is not a valid remoteEntry\.json/
  );
});
