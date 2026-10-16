# Shared composite actions

Reusable composite actions for `norconsult-digital` repos. Reference them as
`norconsult-digital/.github/actions/<name>@<ref>`.

## Native-federation suite (`federation-*`)

Deploy and maintain [native-federation](https://github.com/angular-architects/module-federation-plugin)
remotes in versioned blob storage. A remote's identity lives in a checked-in
`contract.json` (`product` + `module` + `name` + integer `contractVersion`); the
registry layout is `<account>/<container>/v<version>/`, where the container is the
`module` and the federation name is `<product>-<name>`. Old builds are **marked
stale** and removed by a scheduled GC after a retention window, so live clients
keep loading the previous build during a rollout.

| Action | Purpose | Typical caller |
| --- | --- | --- |
| [`federation-verify`](./federation-verify/) | Fail a PR on contract-breaking `remoteEntry.json` drift under an unchanged `contractVersion`. | CI (pull_request) |
| [`federation-publish`](./federation-publish/) | Orchestrator: resolve version → OIDC login → upload bundle dir → mark old builds stale. | CD (deploy) |
| [`federation-upload`](./federation-upload/) | Upload a built bundle (immutable chunks first, no-cache pointers last). Used by `federation-publish`. | internal |
| [`federation-mark-stale`](./federation-mark-stale/) | Idempotently stamp orphaned (or whole-scope) blobs with `stalesince` for deferred GC. | internal |
| [`federation-gc`](./federation-gc/) | Scheduled: delete blobs stamped stale longer than the retention window. | scheduled |
| [`federation-retire`](./federation-retire/) | Retire a whole contract version: stamp its `v<version>/` scope stale. | manual |
| [`federation-read-contract`](./federation-read-contract/) | Read + validate `contract.json` fields (`product`/`module`/`name`/`contractVersion`). Shared helper, internal. | internal |

### Lifecycle

```
PR:        federation-verify   — gate contract drift (no storage writes)
Deploy:    federation-publish  — upload v<version>/, mark prior build stale
Scheduled: federation-gc       — delete blobs past retention
Retire:    federation-retire   — stamp a whole version stale (then GC removes it)
```

Marking stale instead of deleting gives a retention window where the previous
build still serves live clients; re-publishing before GC runs rescues it.

**New contract versions:** the first build of a bumped `contractVersion` has no
published baseline yet. `federation-verify` treats that 404 as a new version: it
warns (annotation + step summary) and passes so the rollout proceeds. The
version-bump PR and, in CD, the environment approval are the human gates.

### Conventions

- **OIDC**: `federation-publish`/`federation-retire` log in via `azure/login`
  (`client-id`/`tenant-id`/`subscription`) and `az storage ... --auth-mode login`.
  The service principal needs blob data read/write (and delete, for GC) on the account.
- **Runner**: `runs-on: ubuntu-*` — the scripts use GNU `date` and `jq`
  (preinstalled on GitHub-hosted Ubuntu).
- **Read path vs write path**: `federation-verify` fetches the published
  `remoteEntry.json` over public HTTPS, deriving
  `<base-url>/<module>/v<version>/[<subpath>/]remoteEntry.json` (`module`/`version`
  from `contract.json`, `<subpath>` only for localized/variant builds). The write
  actions instead take `account`/`container` and drive the authenticated Azure
  control plane.
  The public serving URL (static-website endpoint, CDN/Front Door, or custom domain)
  isn't derivable from `account`/`container`, so `base-url` is a deliberately separate
  per-repo variable.
- Internal sibling references use the `$/actions/<name>` self-repository syntax,
  so the orchestrators resolve their sub-actions from this repo at the running
  commit — no checkout, no version pinning, works when consumed cross-repo.
- **The container is the contract `module`.** `federation-verify` derives the
  public baseline `<base-url>/<module>/v<version>/…`, and `federation-publish`/
  `federation-retire` derive the write container from the same `contract.json`
  `module`; the federation name checked against the built remoteEntry is
  `<product>-<name>`. The low-level `federation-upload`/`federation-mark-stale`/
  `federation-gc` take an explicit `container`.
- **No-cache covers every locale.** `federation-upload`'s `no-cache-files` are
  filenames matched at any depth, so the default `remoteEntry.json` applies
  to both `v<version>/remoteEntry.json` and the per-locale pointers of a
  localized build (`v<version>/<locale>/remoteEntry.json`) — `federation-publish`
  needs no extra config for localized remotes.

### Example caller — publish on deploy

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions: { id-token: write, contents: read }
    steps:
      - uses: actions/checkout@v7
      - run: pnpm i --frozen-lockfile && pnpm run build
      - uses: norconsult-digital/.github/actions/federation-publish@main
        with:
          source: dist/browser
          project-dir: .
          account: stbimremotestest001
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription: ${{ vars.AZURE_SUBSCRIPTION_ID }}
```

### Example caller — verify then publish per environment (CD)

Build once and upload the bundle; each environment job verifies against *its own*
published baseline, then publishes. Key points this example encodes:

- **Checkout is required** in the deploy job — both verify and publish read
  local `contract.json` (`project-dir`).
- **Two different roots:** `candidate` points into the *downloaded artifact*,
  `project-dir` points at the *checked-out source*.
- **Per-environment config:** `base-url`/`account` are environment vars so each
  env verifies and publishes against itself (the container is derived from
  `contract.json`). The job's `environment:` gives the approval gate (especially
  for new versions).
- **Single download:** download once for verify; `source:` reuses it for publish.
- **Localized builds:** matrix `federation-verify` per locale with `subpath`.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - run: pnpm i --frozen-lockfile && pnpm run build
      - uses: actions/upload-artifact@v7
        with: { name: remote-bundle, path: dist/browser }

  deploy-test:
    needs: build
    runs-on: ubuntu-latest
    environment: test
    permissions: { id-token: write, contents: read }
    steps:
      - uses: actions/checkout@v7
      - uses: actions/download-artifact@v8
        with: { name: remote-bundle, path: bundle }
      - uses: norconsult-digital/.github/actions/federation-verify@main
        with:
          candidate: bundle/remoteEntry.json
          base-url: ${{ vars.FEDERATION_REMOTE_BASE_URL }}
          project-dir: .
      - uses: norconsult-digital/.github/actions/federation-publish@main
        with:
          source: bundle
          project-dir: .
          account: ${{ vars.AZURE_REMOTES_ACCOUNT }}
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription: ${{ vars.AZURE_SUBSCRIPTION_ID }}
  # deploy-stage (needs: deploy-test) and deploy-prod (needs: deploy-stage)
  # repeat the same steps with their own environment + vars.
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
          containers: "admin viewer"
          retention-days: "7"
```
