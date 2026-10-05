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

- Existing APIs keep their current copy and metadata-inheritance behaviour.
- APIs explicitly configured for URL-segment versioning use the target's preparation
  tool to generate specifications, dated backend URLs and related APIM artifacts.
  Invalid configuration or preparation failure stops the workflow.
- Only generated files are included. Unchanged artifacts produce no commit or PR.
- Changes require review and merge before publishing; this workflow never deploys
  directly. Environment override changes require full artifact publication and
  the relevant environment approvals.

### Support / Questions
Contact the Platform team (internal) or open an issue in the repo using the template.
