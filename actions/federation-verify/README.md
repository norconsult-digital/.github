# federation-verify

Composite action + CLI that verifies a built native-federation `remoteEntry.json`
against the published baseline for its contract version. Blocks contract-breaking
changes under an unchanged contract version.

Part of the `federation-*` native-federation action suite in this repo — see
[`actions/README.md`](../README.md) for the full publish/retire/GC lifecycle.

## What counts as breaking

| Change (baseline → candidate) | Level |
| --- | --- |
| Added package with `singleton: true, strictVersion: true` | ❌ breaking |
| Added secondary entry point (`@angular/forms/signals`) whose root was already a strict singleton, with a range every version the root accepted satisfies | ℹ️ info |
| Added package, non-singleton or non-strict | ⚠️ warning |
| Removed package (incl. shared → `skip`) | ⚠️ warning |
| `requiredVersion` narrowed or non-overlapping | ❌ breaking |
| `requiredVersion` widened / identical | ℹ️ info / ok |
| `singleton` or `strictVersion` false → true | ❌ breaking |
| `singleton` or `strictVersion` true → false | ℹ️ info |
| Exposes key removed | ❌ breaking |
| Exposes key added | ℹ️ info |
| Remote `name` changed | ❌ breaking |

Ignored on purpose: chunk hashes / `outFileName`, and the resolved `version`
field (changes on every dependabot patch without contract impact).

## Usage in a workflow

The action is package-manager agnostic: the caller owns checkout/install/build.
The published `remoteEntry.json` to compare against is derived from conventions —
`contract.json` at the project root (its `module` + `version`), the `base-url`
input (the remote's public base, typically a repo variable), and the standardized
storage layout `/<module>/v<version>/[<subpath>/]remoteEntry.json`:

```yaml
- uses: actions/checkout@v5
- run: pnpm i --frozen-lockfile && pnpm run build
- uses: norconsult-digital/.github/actions/federation-verify@v1
  with:
    candidate: dist/browser/en/remoteEntry.json
    base-url: ${{ vars.FEDERATION_REMOTE_BASE_URL }}
    subpath: en   # Angular build-time localization; omit for a single build
```

That's the whole contract: one base URL + conventions. Per-locale checks (Angular
builds) are the caller's choice — matrix the action per locale when needed.
Runtime-localized frameworks publish a single build and omit `subpath`.

### Inputs

| Input | Required | Description |
| --- | --- | --- |
| `candidate` | yes | Path to the freshly built `remoteEntry.json` |
| `base-url` | yes | Public base URL this remote is served from (repo variable). The published remoteEntry.json to compare against is `<base-url>/<module>/v<version>/[<subpath>/]remoteEntry.json` |
| `project-dir` | no | Remote project root containing `contract.json` (default `.`) — monorepo support |
| `subpath` | no | Optional directory for localized/variant builds (e.g. `en`); default none. The `remoteEntry.json` filename is fixed |

Exit codes: `0` compatible · `1` breaking changes · `2` usage/IO/validation/config error.
Output: a plain-text log on stdout, plus inline workflow annotations and a markdown
step summary emitted automatically on GitHub Actions.

Additional behavior:

- **Name consistency**: `contract.json` is required; the built remoteEntry's
  `name` must equal `<product>-<name>` (catches contract/federation.config drift)
  — exit `2`.
- **Missing published baseline (404)**: treated as a **new contract version** —
  emits a warning annotation + step summary and exits `0`, so a `contractVersion`
  bump can roll out (the bump is the reviewed gate). A mistyped `base-url` also
  404s and warns-and-passes; `name` drift is still caught separately (exit `2`).
- **contract.json versioning**: `contractVersion` is an **integer** (`1`, `2`, …).
  Semver strings are rejected; patches ship continuously under the same version.

## CLI (local runs)

The CLI takes the base URL from `FEDERATION_REMOTE_BASE_URL` (the action maps the
`base-url` input to it) and derives the published remoteEntry URL from `contract.json`:

```sh
FEDERATION_REMOTE_BASE_URL=https://<storage>/<remote> \
  node dist/index.mjs --candidate dist/browser/en/remoteEntry.json --subpath en
```

## Development

```sh
npm install
npm test     # node:test fixture suite — doubles as the rule documentation
npm run build  # bundles src/ + deps into dist/index.mjs (committed; what the action runs)
```

`dist/` must be rebuilt and committed after any `src/` change.

## Demo

`.github/workflows/example-federation-contract-verify.yml` runs the action
against `example/fixtures/` — which mirrors the standardized storage layout
(`registry/orders-remote/v1/remoteEntry.json`): a compatible candidate (passes)
and a breaking candidate (fails, `continue-on-error` so the demo stays green).
Trigger with `workflow_dispatch`.
