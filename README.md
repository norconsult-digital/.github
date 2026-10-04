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

### APIM specification proposals
The reusable workflow [apim-push-spec-pr.yml](.github/workflows/apim-push-spec-pr.yml)
opens or updates a reviewable proposal in the target repository; it does not publish
to APIM. Callers without an explicit target-repository import opt-in retain the
existing raw specification copy and metadata inheritance.

Opted-in URL-segment APIs use the target repository's preparation tool, not a shared
document adapter. The tool owns operation-relative specifications, dated backend
URLs, environment overrides, Segment version sets and reviewed product-membership
cloning. It refuses contradictory reviewed version-set schemes. The workflow
validates and stages only explicitly reported generated files, never the raw copy
after preparation. Review the proposal's actual changed paths, including
environment overrides: those require full artifact publication and the relevant
environment approvals after merge.

The opt-in file is `tools/apim/specification-imports.json` in the **target**
checkout, with this interface:

```json
{"apis":{"project-controls":{"versioningScheme":"Segment","documentPrefix":"/api/{version}","usageParagraph":"project-controls"}}}
```

A missing file or absent API entry selects the legacy path. Invalid configuration,
a missing preparation tool, or preparation failure fails the proposal without
falling back. Opted-in preparation currently requires `ARTIFACT_FOLDER=apimartifacts`
and explicit `VERSIONS`. From the target checkout the workflow calls:

```bash
python3 tools/apim/prepare_segment_specifications.py \
  --api-name "$API_NAME" \
  --export-directory "$GITHUB_WORKSPACE/spec" \
  --versions <separate-date-arguments> \
  --repository-root . \
  --changed-path-manifest "$PWD/.apim-preparation/changed-paths.json"
```

The tool returns a sorted JSON array of exact repository-relative paths, including
unchanged intended files, in the manifest and on stdout. The shared workflow
validates the manifest against requested API/date artifacts, version-set metadata,
product membership files and test/stage/prod override paths, then converts it to a
NUL-delimited staging list. Git determines whether anything changed. Neither the
side-channel manifest nor unrelated repository files are staged. Preparation owns
all opted-in generation; the legacy copy/inheritance block is skipped entirely.

Roll out in this order: merge the platform tool without enabling opt-in, merge the
shared integration, then enable platform opt-in together with Segment version-set
artifacts and dated backend URLs. Do not run live proposals in the intermediate
state.

### Support / Questions
Contact the Platform team (internal) or open an issue in the repo using the template.
