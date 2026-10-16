# federation-publish

Orchestrates the versioned-registry publish for a native-federation remote:
resolve the contract version (`federation-read-contract`) → Azure OIDC login →
upload the built bundle dir into `v<version>/` (`federation-upload`) → stamp the
previous build's orphaned blobs stale for deferred GC (`federation-mark-stale`).
Keeps a CD job to a single step.

Takes an on-disk bundle dir (`source`); artifact transport is the caller's
concern. In a split CD deploy job the `actions/download-artifact` step already
feeds `federation-verify`, so publish reuses that dir; in a single build+publish
job, pass the build output (e.g. `dist/browser`) directly.

Produces (the container is the contract `module`, derived from `contract.json`):

```
<module>/v<version>/remoteEntry.json   (no-cache pointer)
<module>/v<version>/<hashed chunks>     (immutable, 1y cache)
```

## Inputs

| Input | Required | Description |
| --- | --- | --- |
| `source` | yes | Path to the built bundle dir to publish (the `browser/` output, e.g. `dist/browser`, or a dir downloaded from a build artifact). Uploaded as-is. |
| `project-dir` | yes | Remote project root containing `contract.json` (drives the container `module` and `v<version>`). |
| `account` | yes | Remotes storage account name. |
| `client-id` | yes | Azure service principal client id (OIDC). |
| `tenant-id` | yes | Azure tenant id. |
| `subscription` | yes | Azure subscription id. |

The blob container is derived from `contract.json`'s `module` — the same value
`federation-verify` reads.

Needs `permissions: { id-token: write }` on the job. Requires `runs-on: ubuntu-*`.
See [`actions/README.md`](../README.md) for a full caller example.
