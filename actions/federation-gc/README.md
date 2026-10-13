# federation-gc

Deferred garbage collection for native-federation remote bundles. Deletes blobs
whose `stalesince` metadata (set by `federation-mark-stale`) is older than the
retention window. Blobs WITHOUT a `stalesince` value are current/pointer files
and are never touched — so a long-idle site is safe even though its chunks are
immutable and long-cached. Schedule it from a periodic workflow.

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `account` | yes | — | Storage account name. |
| `containers` | yes | — | Space-separated container names to GC (e.g. `"admin viewer"`). |
| `retention-days` | no | `7` | Delete blobs marked stale more than this many days ago. |

Auth: `az storage ... --auth-mode login` — run `azure/login` first (needs blob
delete rights). Requires `runs-on: ubuntu-*`. See
[`actions/README.md`](../README.md) for a scheduled caller example.
