# federation-upload

Uploads a built native-federation remote bundle to a public blob container.
Content-hashed chunks go up first as immutable (1-year cache); the no-cache
pointer file(s) upload **last**, so no client can load a new `remoteEntry.json`
before its chunks exist. Upload only — stamping/GC are separate actions
(`federation-mark-stale` / `federation-gc`).

Used internally by `federation-publish`; usable standalone after an
`azure/login` step.

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `account` | yes | — | Storage account name (e.g. `stbimremotestest001`). |
| `container` | yes | — | Blob container / remote app name (e.g. `admin-app`). |
| `source` | yes | — | Path to the built bundle (the native-federation `browser/` dir). |
| `path` | no | `""` | Virtual-directory prefix inside the container (e.g. `v1`). Empty = container root. |
| `no-cache-files` | no | `remoteEntry.json,index.html` | Comma-separated files served no-cache and uploaded after all others. |

Auth: `az storage ... --auth-mode login` — run `azure/login` first. Requires
`runs-on: ubuntu-*`.
