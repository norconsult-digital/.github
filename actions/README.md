# Shared composite actions

Reusable composite actions for `norconsult-digital` repos. Reference them as
`norconsult-digital/.github/actions/<name>@<ref>`.

## Native-federation suite (`federation-*`)

Deploy and maintain [native-federation](https://github.com/angular-architects/module-federation-plugin)
remotes in versioned blob storage. A remote's identity lives in a checked-in
`contract.json` (`name` + integer `contractVersion`); the registry layout is
`<account>/<container>/v<version>/`. Old builds are **marked stale** and removed
by a scheduled GC after a retention window, so live clients keep loading the
previous build during a rollout.

| Action | Purpose | Typical caller |
| --- | --- | --- |
| [`federation-verify`](./federation-verify/) | Fail a PR on contract-breaking `remoteEntry.json` drift under an unchanged `contractVersion`. | CI (pull_request) |
| [`federation-publish`](./federation-publish/) | Orchestrator: resolve version → download artifact → OIDC login → upload → mark old builds stale. | CD (deploy) |
| [`federation-upload`](./federation-upload/) | Upload a built bundle (immutable chunks first, no-cache pointers last). Used by `federation-publish`. | internal |
| [`federation-mark-stale`](./federation-mark-stale/) | Idempotently stamp orphaned (or whole-scope) blobs with `stalesince` for deferred GC. | internal |
| [`federation-gc`](./federation-gc/) | Scheduled: delete blobs stamped stale longer than the retention window. | scheduled |
| [`federation-retire`](./federation-retire/) | Retire a whole contract version: stamp its `v<version>/` scope stale. | manual |
| [`federation-read-contract`](./federation-read-contract/) | Read `name`/`v<version>` from `contract.json`. Shared helper, internal. | internal |

### Lifecycle

```
PR:        federation-verify   — gate contract drift (no storage writes)
Deploy:    federation-publish  — upload v<version>/, mark prior build stale
Scheduled: federation-gc       — delete blobs past retention
Retire:    federation-retire   — stamp a whole version stale (then GC removes it)
```

Marking stale instead of deleting gives a retention window where the previous
build still serves live clients; re-publishing before GC runs rescues it.

### Conventions

- **OIDC**: `federation-publish`/`federation-retire` log in via `azure/login`
  (`client-id`/`tenant-id`/`subscription`) and `az storage ... --auth-mode login`.
  The service principal needs blob data read/write (and delete, for GC) on the account.
- **Runner**: `runs-on: ubuntu-*` — the scripts use GNU `date` and `jq`
  (preinstalled on GitHub-hosted Ubuntu).
- **Read path vs write path**: `federation-verify` fetches the published
  `remoteEntry.json` over public HTTPS, deriving
  `<base-url>/<name>/v<version>/[<subpath>/]remoteEntry.json` (`name`/`version` from
  `contract.json`, `<subpath>` only for localized/variant builds). The write actions
  instead take `account`/`container` and drive the authenticated Azure control plane.
  The public serving URL (static-website endpoint, CDN/Front Door, or custom domain)
  isn't derivable from `account`/`container`, so `base-url` is a deliberately separate
  per-repo variable.
- Internal sibling references use the `$/actions/<name>` self-repository syntax,
  so the orchestrators resolve their sub-actions from this repo at the running
  commit — no checkout, no version pinning, works when consumed cross-repo.

### Example caller — publish on deploy

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions: { id-token: write, contents: read }
    steps:
      - uses: actions/checkout@v7
      - run: pnpm i --frozen-lockfile && pnpm run build
      - uses: actions/upload-artifact@v7
        with: { name: remote-bundle, path: dist/browser }
      - uses: norconsult-digital/.github/actions/federation-publish@main
        with:
          artifact-name: remote-bundle
          project-dir: .
          account: stbimremotestest001
          container: admin-app
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription: ${{ vars.AZURE_SUBSCRIPTION_ID }}
```

### Example caller — scheduled GC

```yaml
on:
  schedule: [{ cron: "0 3 * * *" }]
jobs:
  gc:
    runs-on: ubuntu-latest
    permissions: { id-token: write, contents: read }
    steps:
      - uses: azure/login@v3
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
      - uses: norconsult-digital/.github/actions/federation-gc@main
        with:
          account: stbimremotestest001
          containers: "admin-app viewer-app"
          retention-days: "7"
```
