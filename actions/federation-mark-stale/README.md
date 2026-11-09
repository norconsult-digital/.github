# federation-mark-stale

Idempotently stamps blobs with a `stalesince` metadata timestamp for deferred
garbage collection (`federation-gc` deletes them after a retention window).
**Nothing is deleted here.** Two modes, selected by whether `source` is given:

- **with `source`** → publish/orphan mode: stamps blobs in scope that are NOT in
  the freshly built bundle (leftover chunks from previous builds).
- **without `source`** → retire mode: stamps every blob under `path`.

Already-stamped blobs are left untouched, so repeated runs never push the
deletion clock forward.

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `account` | yes | — | Storage account name. |
| `container` | yes | — | Blob container to stamp (e.g. `admin`). |
| `path` | no | `""` | Virtual-directory prefix (e.g. `v1`). Empty = whole container. |
| `source` | no | `""` | Built bundle whose files must be protected (never stamped). Omit to retire the whole scope. |

Auth: `az storage blob list --auth-mode login` and a storage token from
`az account get-access-token` — run `azure/login` first. The stamps are set
with parallel Set Blob Metadata REST calls (16 at a time), since one `az` call
per blob took tens of minutes on large bundles. Requires `runs-on: ubuntu-*`
(`jq`, `curl`, GNU `xargs`).
