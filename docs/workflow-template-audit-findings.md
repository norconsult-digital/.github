# Workflow Template Audit — Combined Findings & Actions Taken

## Summary

This document records validated findings from the workflow template audit (issue #54) and the actions taken in this combined PR. Changes are cross-referenced against consumer templates in `workflow-templates/` to verify backwards compatibility.

> **Note:** APIM files (`apim-*.yml`) are excluded per instructions.

---

## Group 1: Fixed in this PR (no consumer impact)

### H1 · Add `needs: [delay_deployment]` to deploy job
**Files:** `dotnet-cd-jobs.yml`, `python-cd-jobs.yml`
- The `deploy` job now depends on `delay_deployment`, making the delay actually gate deployment as intended.

### H2 · Standardize branch prefix to `release/`
**Files:** `dotnet-cd-jobs.yml`, `python-cd-jobs.yml`
- Changed `startsWith(github.ref_name, 'release')` → `startsWith(github.ref_name, 'release/')` for consistency.

### H3 · Configurable `bicepFolder` input
**File:** `deploy-bicep-files.yml`
- Added `bicepFolder` input (default: `b2c-poc/resources`) replacing hardcoded path. Updated template accordingly.

### H4 · Fix always-true deploy condition
**File:** `deploy-bicep-files.yml`
- Replaced `if: ${{ always() && inputs.runWhatIf == false || inputs.runWhatIf == true }}` with `if: ${{ inputs.runWhatIf == false }}`.
- Deploy now only runs when What-If is NOT requested, making What-If a true dry-run mode.

### H5 · Add `language` input to POEditor upload
**File:** `poeditor-upload.yml`
- Added configurable `language` input (default: `"en"`) replacing hardcoded value.

### H6 · Remove unused `dbConnection` from python-cd-jobs
**Files:** `python-cd-jobs.yml`, `python-cd-jobs-template.yml`
- The input was declared but never consumed by any step.

### H7 · Remove deprecated `optionalDbConnection1/2`
**File:** `dotnet-cd-jobs.yml`
- Removed self-described "TEMPORARY: WILL BE REMOVED WITHOUT WARNING" inputs and their steps.

### H8 · Add guard to default checkout
**File:** `dotnet-test.yml`
- Added `if: ${{ !inputs.gitRepo }}` so default checkout doesn't overwrite specific repo checkout.

### H10 · Fix Angular template
**File:** `angular-build-and-test-template.yml`
- Added missing `workflow_dispatch.inputs` declarations and moved `NX_CLOUD_CICD` to `secrets:` block.

### H11 · Fix invalid `$GITHUB_ACTOR_EMAIL`
**Files:** `poeditor-download.yml`, `poeditor-json-download.yml`, `poeditor-upload.yml`
- Replaced non-existent `$GITHUB_ACTOR_EMAIL` with `${GITHUB_ACTOR}@users.noreply.github.com`.

### H12 · Remove undeclared secrets from efcore template
**File:** `efcore-migrations-bundle-run-template.yml`
- Removed `secrets:` block — the callee only accepts `inputs`.

### H13 · Remove SONAR_TOKEN and AZURE_CLIENT_SECRET
**File:** `dotnet-ci-jobs-template.yml`
- Callee only declares `NUGET_CONFIG`. Replaced entire secrets block.

### H14 · Fix environmentName/allowedBranches in publish-bicep template
**File:** `publish-bicep-files-template.yml`
- Added `environmentName` and `allowedBranches` to `workflow_dispatch.inputs` so they resolve correctly.

### Medium secrets · Remove undeclared secret pass-throughs
**Files:** Multiple templates
- `docker-tag-and-push-template.yml`: Removed `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `GITHUB_TOKEN`
- `template-validate-kustomization-template.yml`: Removed `GITHUB_TOKEN`
- `poeditor-download-template.yml`: Removed `GITHUB_TOKEN`
- `poeditor-json-download-template.yml`: Removed `GITHUB_TOKEN`
- `poeditor-json-upload-template.yml`: Removed `GITHUB_TOKEN`
- `poeditor-upload-template.yml`: Removed `GITHUB_TOKEN`
- `template-renovate-template.yml`: Removed `RENOVATE_WEBHOOK_SECRET`
- `template-deploy-terraform-template.yml`: Removed `GITHUB_TOKEN`

### S1 · Move secrets to step-level env in Terraform
**File:** `template-deploy-terraform.yml`
- Moved secrets from workflow-level `env:` to step-level `env:` blocks (Init, Validate, Plan, Apply).
- Added configurable `subscription_id` input replacing hardcoded value.

### L3 · Fix echo before env var is set
**File:** `poeditor-upload.yml`
- Rewrote package manager detection to use local variable before writing to `$GITHUB_ENV`.

### M6 · Remove unused `instances` output
**File:** `get-db-connections.yml`
- Removed `echo "instances=$INSTANCES" >> $GITHUB_OUTPUT` — only `connectionStrings` is used.

---

## Additional fixes

- `dotnet-version-sweeper.yml`: Made `support` input optional (has default), gated debug step.
- `dotnet-version-sweeper` template: Fixed job name typo (`donet` → `dotnet`), added fallback default.
- `efcore-migrations-bundle-create.yml`: Made `dotnetVersion` optional (has default `7.*`).
- `python-test.yml` + template: Made `projectPath` optional (has default `.`).
- `zizmor-pipeline-lint.yml`: Fixed `cd` + relative path issue — use path argument directly.
- `template-renovate.yml`: Condensed multi-line RENOVATE_HOST_RULES to handle empty `acr_name`.

---

## Group 2: Deferred (requires consumer migration or investigation)

These are NOT addressed in this PR and require further work:

- **H5 (poeditor-upload language):** Multi-language upload needs team confirmation.
- **H9:** Needs investigation of private consumer repos.
- **D2 (NuGet.Config duplication):** Extract to composite action — future refactor.
