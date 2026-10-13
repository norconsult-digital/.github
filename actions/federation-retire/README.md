# federation-retire

Retires a whole native-federation contract version by stamping every blob under
its `v<version>/` scope with `stalesince` (via `federation-mark-stale`, no
source). The scheduled `federation-gc` workflow then deletes them after the
retention window — so retirement is **deferred and reversible** (re-publishing
the version before GC runs rescues it). Nothing is deleted here.

Run from the release branch whose version is being retired: `federation-read-contract`
resolves that branch's `v<contractVersion>`.

## Inputs

| Input | Required | Description |
| --- | --- | --- |
| `project-dir` | yes | Remote project root containing `contract.json` (version to retire). |
| `account` | yes | Remotes storage account name. |
| `container` | yes | Blob container / remote app name. |
| `client-id` | yes | Azure service principal client id (OIDC). |
| `tenant-id` | yes | Azure tenant id. |
| `subscription` | yes | Azure subscription id. |

Needs `permissions: { id-token: write }` on the job. Requires `runs-on: ubuntu-*`.
