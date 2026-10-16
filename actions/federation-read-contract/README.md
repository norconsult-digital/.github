# federation-read-contract

Reads the native-federation identity from a remote's checked-in `contract.json`
and echoes it for downstream steps. Shared helper — internal to the
`federation-*` suite.

`contract.json` (at `project-dir`) declares kebab-case `product`, `module` and
`name`, plus a positive integer `contractVersion`. All are validated here
(matching `federation-verify`'s schema); the step fails if any is missing or
malformed. Each field is echoed verbatim — how the fields map to a container,
version segment or federation name is the caller's decision.

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `project-dir` | no | `.` | Remote project root containing `contract.json` (monorepo support). |

## Outputs

| Output | Description |
| --- | --- |
| `product` | The `product` field from `contract.json` (e.g. `bim`). |
| `module` | The `module` field from `contract.json` (e.g. `admin`). |
| `name` | The `name` field from `contract.json` (e.g. `admin-app`). |
| `contractVersion` | The integer contract version (e.g. `1`). |

## Example

```yaml
- id: contract
  uses: norconsult-digital/.github/actions/federation-read-contract@main
  with: { project-dir: . }
- run: echo "${{ steps.contract.outputs.module }} v${{ steps.contract.outputs.contractVersion }}"
```

Requires `jq` (preinstalled on GitHub-hosted Ubuntu runners).
