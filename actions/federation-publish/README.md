# federation-publish

Orchestrates the versioned-registry publish for a native-federation remote:
resolve the contract version (`federation-read-contract`) → download the built
bundle artifact → Azure OIDC login → upload into `v<version>/`
(`federation-upload`) → stamp the previous build's orphaned blobs stale for
deferred GC (`federation-mark-stale`). Keeps a CD job to a single step.

Produces:

```
<container>/v<version>/remoteEntry.json   (no-cache pointer)
<container>/v<version>/<hashed chunks>     (immutable, 1y cache)
```

## Inputs

| Input | Required | Description |
| --- | --- | --- |
| `artifact-name` | yes | Name of the uploaded build artifact (native-federation `browser/` dir). |
| `project-dir` | yes | Remote project root containing `contract.json` (drives `v<version>`). |
| `account` | yes | Remotes storage account name. |
| `container` | yes | Blob container / remote app name. |
| `client-id` | yes | Azure service principal client id (OIDC). |
| `tenant-id` | yes | Azure tenant id. |
| `subscription` | yes | Azure subscription id. |

Needs `permissions: { id-token: write }` on the job. Requires `runs-on: ubuntu-*`.
See [`actions/README.md`](../README.md) for a full caller example.
