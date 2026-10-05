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
- Unchanged artifacts produce no commit or PR.
- Changes require review and merge before publishing; this workflow never deploys
  directly. Environment override changes require full artifact publication and
  the relevant environment approvals.

### Support / Questions
Contact the Platform team (internal) or open an issue in the repo using the template.
