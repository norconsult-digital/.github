## Norconsult Digital

Organization GitHub profile & shared workflow template library.

### What is this?
This `.github` repo holds:
- the org profile
- Reusable GitHub Actions workflow templates in `workflow-templates/`

### Use a template
Actions → New workflow → Pick a Norconsult Digital template → Commit. Edit only the marked customization spots.

### Add or update a template
PR with the `.yml` plus matching `.properties.json`. Keep it small, clear, and tested.

### Terraform plan result
The reusable [Terraform deploy workflow](.github/workflows/template-deploy-terraform.yml)
uploads a machine-readable result for successful pull request plans (exit code
0 or 2). The artifact is named `terraform-plan-result-<sha256>`, where the
suffix is the lowercase SHA-256 of the UTF-8 POSIX-normalized, repository-relative
root (`.` for the repository root). Absolute and escaping paths are rejected.
It contains only `result.json` and is retained for seven days.

The JSON contains `schema_version` (integer 1), `repository`, `pr_number`
(integer), `head_sha`, `base_sha`, `merge_sha`, `run_id` and `run_attempt`
(strings), `root` (string), `refreshed` (boolean), and `exit_code` (integer 0
or 2). `merge_sha` is the pull request workflow's checkout revision. Consumers
must verify the result against the trusted workflow run, PR revisions and
expected roots; a no-change decision also requires `refreshed: true` and
`exit_code: 0`. A failed or skipped plan does not produce a result.

### APIM specification updates
The reusable workflow [apim-push-spec-pr.yml](.github/workflows/apim-push-spec-pr.yml)
turns backend OpenAPI exports into a pull request in the target repository.

- Only Segment versioning is supported: dated OpenAPI exports and
  `/api/<date>/<resource>` backend paths, using the fixed `apimartifacts` root.
- Callers must supply nonempty, explicit, space-separated `VERSIONS` and upload
  an `<API_NAME>-openapi` artifact containing one `<version>.json` per date.
  Unversioned proposals, implicit/latest dates and custom artifact roots are not supported.
- The target repository must contain `tools/apim/prepare_segment_specifications.py`.
  The workflow always invokes this tool to generate specifications, dated API
  metadata/backend URLs, test/stage/prod overrides, missing Segment version sets
  and product memberships. No opt-in configuration or raw-copy fallback is used.
- Existing baseline metadata and environment URLs must already satisfy the
  convention. The tool preserves API-specific authentication, required headers
  and usage descriptions; it neither migrates Query/Header version sets nor
  onboards a new API.
- Missing tools, failed preparation and invalid manifests stop the workflow
  before a proposal commit. Only allowlisted manifest files are staged, including
  unchanged intended artifacts so Git determines the actual diff. Side-channel
  files such as the manifest and tool stdout are never staged.
- The membership allowlist includes reviewed local files (such as `policy.xml`)
  under the requested API/date's product membership directories, not product-level
  policies. The platform tool owns baseline cloning and policy-backfill checks.
- Unchanged artifacts produce no commit or PR.
- Changes require review and merge before publishing; this workflow never deploys
  directly. Environment override changes require full artifact publication and
  the relevant environment approvals.

### Support / Questions
Contact the Platform team (internal) or open an issue in the repo using the template.
