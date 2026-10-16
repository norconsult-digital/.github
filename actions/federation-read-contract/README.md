# federation-read-contract

Reads the native-federation identity from a remote's checked-in `contract.json`
and echoes it for downstream steps. Shared helper — internal to the
`federation-*` suite.

`contract.json` (at `project-dir`) declares `name` (kebab-case) and a positive
integer `contractVersion`. Both are validated here (matching
`federation-verify`'s schema); the step fails if either is missing or malformed.

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `project-dir` | no | `.` | Remote project root containing `contract.json` (monorepo support). |

## Outputs

| Output | Description |
| --- | --- |
| `name` | Federation/contract name (e.g. `admin-app`). |
| `version` | Version segment `v<contractVersion>` for registry paths (e.g. `v1`). |

## Example

```yaml
- id: contract
  uses: norconsult-digital/.github/actions/federation-read-contract@main
  with: { project-dir: . }
- run: echo "${{ steps.contract.outputs.name }} ${{ steps.contract.outputs.version }}"
```

Requires `jq` (preinstalled on GitHub-hosted Ubuntu runners).
