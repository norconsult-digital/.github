# Workflow template refactoring — validated action items

## Summary

This document contains validated findings from the workflow template audit (cross-referenced against consumer templates in `workflow-templates/`). Consumer repos in the `norconsult-digital` org are private and not visible via GitHub code search, so analysis is based on the official starter templates which define the consumer interface.

> **Note:** APIM files (`apim-*.yml`) are excluded per instructions.

---

## Group 1: Safe to fix now (no consumer impact)

These changes are internal to the reusable workflows or fix bugs in template-to-workflow relationships where the fix is backwards-compatible.

---

### H1 · `dotnet-cd-jobs.yml` + `python-cd-jobs.yml` — Add `needs: [delay_deployment]` to `deploy` job

**Files:** `.github/workflows/dotnet-cd-jobs.yml:64`, `.github/workflows/python-cd-jobs.yml:47`

**Change:** Add `needs: [delay_deployment]` to the `deploy` job definition.

**Consumer impact:** None — consumers already pass `deploymentDelayInMinutes` expecting it to gate deployment. This fix makes the delay actually work as intended. Currently the delay is a complete no-op.

**Verified:** Both `dotnet-cd-jobs-template.yml` and `python-cd-jobs-template.yml` pass `deploymentDelayInMinutes`. No consumer interface changes needed.

---

### H2 · `dotnet-cd-jobs.yml` + `python-cd-jobs.yml` — Standardize branch prefix to `release/`

**Files:** `.github/workflows/dotnet-cd-jobs.yml:59,67`, `.github/workflows/python-cd-jobs.yml:42,50`

**Change:** In `delay_deployment` job condition, change `startsWith(github.ref_name, 'release')` to `startsWith(github.ref_name, 'release/')` to match the `deploy` job condition.

**Consumer impact:** None for consumers using `release/` prefix (standard convention). Any consumer using `release-*` branches (without slash) was already broken — `delay_deployment` ran but `deploy` never did. Standardizing on `release/` makes both jobs consistent.

**Verified:** The template `allowedBranches` default is `'["main"]'`. The `release` matching is a secondary path. Standardizing to `release/` is the safer choice.

---

### H4 · `deploy-bicep-files.yml:106` — Fix always-true condition

**File:** `.github/workflows/deploy-bicep-files.yml:106`

**Change:** Replace:
```yaml
if: ${{ always() && inputs.runWhatIf == false || inputs.runWhatIf == true }}
```
With:
```yaml
if: ${{ always() }}
```

**Consumer impact:** None — the current condition is always `true` due to operator precedence (`(always() && false) || true` = `true`). The deploy step already always runs. The What-If step (line 94) runs only when `runWhatIf == true` as a preview — the actual deploy should always run regardless. If gating is intended, a separate fix would be needed to check What-If output.

**Verified:** The workflow structure shows What-If is informational (runs `--what-if --rollback-on-error`), then deploy always runs. Fix makes intent explicit.

---

### H7 · `dotnet-cd-jobs.yml:42-49` — Remove deprecated `optionalDbConnection1/2` inputs

**File:** `.github/workflows/dotnet-cd-jobs.yml:42-49` (declarations), lines 109-123 (steps)

**Change:** Remove `optionalDbConnection1` and `optionalDbConnection2` input declarations and their associated steps.

**Consumer impact:** None — the `dotnet-cd-jobs-template.yml` does NOT pass these inputs. These are self-described as "TEMPORARY: DO NOT USE" and "WILL BE REMOVED WITHOUT WARNING". No external consumer template references them.

**Verified:** Searched `dotnet-cd-jobs-template.yml` — no reference to `optionalDbConnection1` or `optionalDbConnection2`.

---

### H8 · `dotnet-test.yml:56` — Add guard to default checkout step

**File:** `.github/workflows/dotnet-test.yml:56`

**Change:** Add `if: ${{ inputs.gitRepo == '' }}` to the "Default checkout" step.

**Consumer impact:** None — this fixes a bug where the default checkout unconditionally overwrites the specific repo checkout. The `dotnet-ci-jobs-template.yml` passes `gitRepo` and expects it to work. This fix makes the `gitRepo` input functional.

**Verified:** `dotnet-ci-jobs-template.yml:64` passes `gitRepo: ${{ github.event.inputs.gitRepo }}`. Current behavior is broken (second checkout always overwrites).

---

### H11 · `poeditor-download.yml:54` and `poeditor-upload.yml:138` — Fix invalid `$GITHUB_ACTOR_EMAIL`

**Files:** `.github/workflows/poeditor-download.yml:54`, `.github/workflows/poeditor-upload.yml:138`

**Change:** Replace:
```bash
git config --global user.email "$GITHUB_ACTOR_EMAIL"
```
With:
```bash
git config --global user.email "$GITHUB_ACTOR@users.noreply.github.com"
```

**Consumer impact:** None — `$GITHUB_ACTOR_EMAIL` is not a valid GitHub Actions variable, so it currently resolves to empty string. Fix provides a valid noreply email. All consumers benefit from proper git commit attribution.

**Verified:** Standard GitHub Actions variables do not include `GITHUB_ACTOR_EMAIL`. The `$GITHUB_ACTOR` variable is available.

---

### H12 · `efcore-migrations-bundle-run-template.yml:42` — Remove `DB_CONNECTION_STRING` secret pass-through

**File:** `workflow-templates/efcore-migrations-bundle-run-template.yml:42`

**Change:** Remove `DB_CONNECTION_STRING: ${{ secrets.DB_CONNECTION_STRING }}` from the secrets block.

**Consumer impact:** None — `efcore-migrations-bundle-run.yml` declares no `secrets:` block. It uses `inputs.dbConnection` (a plain input) for the connection string. The secret is fetched at caller level and silently discarded.

**Verified:** Confirmed `efcore-migrations-bundle-run.yml` has no `secrets:` declaration — it only accepts `inputs`.

---

### H13 · `dotnet-ci-jobs-template.yml:79-80` — Remove `SONAR_TOKEN` and `AZURE_CLIENT_SECRET`

**File:** `workflow-templates/dotnet-ci-jobs-template.yml:79-80`

**Change:** Remove:
```yaml
SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
```

**Consumer impact:** None — `dotnet-ci-jobs.yml` only declares `NUGET_CONFIG` in its secrets block (line 61-63). These two secrets are fetched at caller level and silently dropped by GitHub Actions. Removing them reduces unnecessary secret exposure.

**Verified:** Confirmed `.github/workflows/dotnet-ci-jobs.yml` secrets block only contains `NUGET_CONFIG`.

---

### H14 · `publish-bicep-files-template.yml:27-28` — `environmentName` and `allowedBranches` always empty

**File:** `workflow-templates/publish-bicep-files-template.yml:27-28`

**Change:** Either:
- (Option A) Add `environmentName` and `allowedBranches` to the template's `workflow_dispatch.inputs:` block, OR
- (Option B) Remove lines 27-28 since `publish-bicep-files.yml` likely has defaults.

**Consumer impact:** None for removal — these inputs currently always resolve to empty string because they reference `github.event.inputs.environmentName` and `github.event.inputs.allowedBranches` which are not declared in the template's own `workflow_dispatch.inputs:`. Adding them (Option A) gives consumers new functionality without breaking anything.

**Verified:** The template's `workflow_dispatch.inputs:` only declares `bicepFolder` and `vmImage`. Lines 27-28 reference undeclared inputs.

---

### Medium secrets — Remove undeclared secret pass-throughs

These secrets are passed to callees that don't declare them. They are fetched at caller level and silently discarded.

| Template file | Secret to remove | Callee confirms no declaration |
|---|---|---|
| `docker-tag-and-push-template.yml:41-43` | `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `GITHUB_TOKEN` | `docker-tag-and-push.yml` has no `secrets:` block |
| `template-validate-kustomization-template.yml:33` | `GITHUB_TOKEN` | `template-validate-kustomization.yml` has no `secrets:` block |
| `poeditor-download-template.yml:32` | `GITHUB_TOKEN` | `poeditor-download.yml` only declares `API_KEY` |
| `poeditor-json-download-template.yml:32` | `GITHUB_TOKEN` | `poeditor-json-download.yml` only declares `API_KEY` |
| `poeditor-upload-template.yml:66` | `GITHUB_TOKEN` | `poeditor-upload.yml` only declares `API_KEY` |
| `poeditor-json-upload-template.yml:45` | `GITHUB_TOKEN` | `poeditor-json-upload.yml` only declares `API_KEY` |
| `template-renovate-template.yml:48` | `RENOVATE_WEBHOOK_SECRET` | `template-renovate.yml` only declares `RENOVATE_APP_ID` and `RENOVATE_PRIVATE_KEY` |

**Consumer impact:** None — secrets are already being silently dropped. Removing them reduces unnecessary secret exposure at the caller context.

---

### S1 · `template-deploy-terraform.yml` — Move secrets to step-level env

**File:** `.github/workflows/template-deploy-terraform.yml`

**Change:** Move secrets from workflow-level `env:` to only the specific step `env:` blocks where consumed.

**Consumer impact:** None — purely internal security improvement (least-privilege). No interface change.

---

### L3 · `poeditor-upload.yml:73` — Echo before env var is set

**File:** `.github/workflows/poeditor-upload.yml:73`

**Change:** Remove or move `echo "Using package manager: ${{ env.packageManager }}"` to after the env write (or to next step).

**Consumer impact:** None — cosmetic fix for debugging output.

---

### M6 · `get-db-connections.yml:93` — `instances` output is unused

**File:** `.github/workflows/get-db-connections.yml:93`

**Change:** The line `echo "instances=$INSTANCES" >> $GITHUB_OUTPUT` can be removed since no consumer reads this output (only `connectionStrings` is used).

**Consumer impact:** Low risk — verify no consumer reads `steps.parse_instances.outputs.instances`. Since the workflow only exposes job-level outputs and `instances` is not listed as a job output, it's safe to remove.

---

### D2 · NuGet.Config token-replacement block — Document as future refactor

**Files:** `docker-build-and-save.yml`, `angular-build-and-test.yml`, `efcore-migrations-bundle-create.yml`, `dotnet-test.yml`

**Change:** Extract the identical PowerShell NuGet.Config token-replacement block into a reusable composite action.

**Consumer impact:** None — internal refactor only. No workflow interface changes.

---

## Group 2: Requires consumer migration or further investigation

These changes affect the consumer interface or require additional context from private repos.

---

### H3 · `deploy-bicep-files.yml:74+77` — Hardcoded `./b2c-poc/resources` artifact path

**File:** `.github/workflows/deploy-bicep-files.yml:74,77`

**Issue:** The `Download Bicep artifact` step hardcodes `path: ./b2c-poc/resources` regardless of the `bicepFolder` input.

**Migration needed:** Must verify all consumers. If any consumer uses a `bicepFolder` other than `b2c-poc/resources`, they are currently deploying from the wrong path. The fix requires:
1. Replace hardcoded path with `path: ./${{ inputs.bicepFolder }}` (or similar)
2. Update `ARTIFACT_PATH` env accordingly
3. Test with all consumers to ensure artifact name/path alignment

**Risk:** HIGH — This is a live deployment bug for any non-b2c-poc consumer.

---

### H5 · `poeditor-upload.yml:122` — Language hardcoded to `"en"`

**File:** `.github/workflows/poeditor-upload.yml:122`

**Issue:** Upload always sends `-F language="en"`. No `language` input exists.

**Migration needed:**
1. Add a `language` input (default: `"en"`)
2. Update all consumers to pass their expected language

**Risk:** Any non-English project using this template is silently broken. However, the XLF extraction workflow implies English source → POEditor, so English-only upload may be intentional for this particular workflow (the JSON variant `poeditor-json-upload.yml` does accept a `language` input). Needs team confirmation on whether multi-language upload is needed here.

---

### H6 · `python-cd-jobs.yml:30-31` — `dbConnection` declared but never consumed

**File:** `.github/workflows/python-cd-jobs.yml:30-31`

**Issue:** `dbConnection` is declared but no step uses it (unlike `dotnet-cd-jobs.yml` which runs migrations).

**Migration needed:** The `python-cd-jobs-template.yml:44` passes `dbConnection`. If any consumer relies on this believing migrations run, they are silently broken.

**Options:**
- (A) Remove from both workflow AND template (breaking change for consumers passing it)
- (B) Add migration step to python workflow (matching dotnet behavior)

**Risk:** Consumers passing `dbConnection` believe migrations are running — they are not. Needs investigation of which Python projects require DB migrations.

---

### H9 · `nuget-build-and-test.yml:97-99` — Artifact uploads entire workspace

**File:** `.github/workflows/nuget-build-and-test.yml:97-99`

**Issue:** `path: ${{ github.workspace }}/**` uploads the entire repository.

**Migration needed:** Must verify what `nuget-publish.yml` expects when downloading this artifact. The fix requires scoping to NuGet output (e.g., `**/bin/Release/**/*.nupkg`), but the downstream consumer may depend on having the full workspace.

**Risk:** Medium — wasteful but functional. Requires checking `nuget-publish.yml` download path expectations.

---

### H10 · `angular-build-and-test-template.yml` — References non-existent inputs

**File:** `workflow-templates/angular-build-and-test-template.yml:13-16`

**Issue:** References `${{ inputs.vmImage }}`, `${{ inputs.workspaceDir }}`, `${{ inputs.disableNxCloud }}`, `${{ secrets.NX_CLOUD_CICD }}` but has no `workflow_dispatch.inputs:` block.

**Migration needed:** Add the missing inputs block. Any repo using this template currently passes empty values.

**Risk:** Low — the template is clearly non-functional as-is. Adding inputs is backwards-compatible for any consumer that already hardcodes these values in their copy.

---

### M1 · `efcore-migrations-bundle-create.yml:27-29` — `required: true` + `default` conflict

**File:** `.github/workflows/efcore-migrations-bundle-create.yml:27-29`

**Issue:** `dotnetVersion` is `required: true` with `default: "7.*"`. Also: the value is used as an EF Core Tools NuGet version, not an SDK version.

**Migration needed:** Check if any consumer omits `dotnetVersion`. If so, change to `required: false`. The EF Tools version mismatch needs separate investigation.

---

### M5 · `template-renovate.yml:91-99` — `acr_name` null-check gap

**File:** `.github/workflows/template-renovate.yml:91-99`

**Issue:** `RENOVATE_HOST_RULES` always injects an entry using `acr_name` even when empty, producing malformed entries.

**Migration needed:** Wrap in conditional. Check if any consumer omits `acr_name` — `template-renovate-template.yml:28` declares it as `required: false`, so yes, consumers can omit it.

**Fix:** Conditionally build the host rules JSON only when `acr_name` is not empty.

**Risk:** Medium — consumers without ACR get malformed Renovate host rules. However this may be silent (Renovate may ignore empty matchHost).

---

### M7 · `template-renovate.yml` — `regex_pattern` misleading name

**File:** `.github/workflows/template-renovate.yml:24`

**Issue:** Used as branch prefix and commit suffix, not a regex.

**Migration needed:** Renaming requires updating all consumers passing `regex_pattern`. The `template-renovate-template.yml:19` passes it.

**Risk:** Low functional risk but requires coordinated rename across all consumer repos.

---

### S2 · `template-deploy-terraform.yml:64` — Hardcoded subscription ID

**File:** `.github/workflows/template-deploy-terraform.yml:64`

**Issue:** `ARM_SUBSCRIPTION_ID: "fda77453-b07b-4860-b1cc-dd8365592842"` hardcoded with no input override.

**Migration needed:** Add `subscription_id` input. All consumers currently share the same subscription. If any consumer targets a different subscription, this template is unusable for them.

**Risk:** Low — adding an input with this value as default is non-breaking.

---

### Hardcoded org-wide values — Migrate to org variables

**Issue:** 6 values hardcoded across 20+ occurrences.

**Migration needed:**
1. Create org variables in GitHub Settings (e.g., `ORG_AZURE_TENANT_ID`, `ORG_ACR_ND_SHARED_PROD`, etc.)
2. Replace all hardcoded values with `${{ vars.ORG_<NAME> }}`
3. Verify no repo-level variable with same name exists

**Risk:** Low if org variables are created first — replacement is backwards-compatible. However, this requires GitHub org admin access and should be done in a coordinated manner.

---

### M2 · `python-test.yml:17-21` — `required: true` + `default` conflict

**File:** `.github/workflows/python-test.yml:17-21`

**Issue:** `projectPath` is `required: true` with `default: '.'`.

**Migration needed:** Check consumers. If any omit `projectPath`, change to `required: false`.

---

### M3 · `dotnet-version-sweeper.yml:9-11` — `required: true` on schedule trigger

**File:** `.github/workflows/dotnet-version-sweeper.yml:9-11`

**Issue:** `support` is `required: true` with `default: "STS"`. On schedule triggers, inputs aren't available.

**Migration needed:** Change to `required: false`. Verify scheduled runs use the default correctly.

---

### D1 · `tflint-scan.yml` + `trivy-scan.yml` — Duplicate changed-files logic

**Issue:** ~60 lines duplicated verbatim.

**Migration needed:** Extract to composite action. No consumer-facing change but requires creating a new action.

---

### D3 · ACR name resolution — Duplicate across 3-4 files

**Issue:** Repeated if/else logic for prod/non-prod ACR selection.

**Migration needed:** Best addressed as part of org variables migration — once ACR values come from org vars, the resolution logic simplifies.

---

## Priority Recommendation

### Immediate fixes (PR-ready):
1. **H1** — Add `needs: [delay_deployment]` (critical deployment bug)
2. **H2** — Standardize `release/` prefix
3. **H8** — Guard default checkout
4. **H11** — Fix `GITHUB_ACTOR_EMAIL`
5. **H7** — Remove deprecated optional DB connections
6. **H4** — Simplify always-true condition
7. **H12, H13** — Remove dead secret pass-throughs
8. **Medium secrets table** — Remove all undeclared secret pass-throughs
9. **H14** — Fix or remove empty inputs in publish-bicep-files-template

### Requires team decision:
1. **H3** — Bicep artifact path (live deployment bug, needs consumer audit)
2. **H5** — POEditor language (may be intentionally English-only)
3. **H6** — Python dbConnection (needs Python project audit)
4. **H9** — NuGet artifact scope (needs downstream verification)
5. **S2** + Org variables — Requires GitHub admin access

### Long-term improvements:
1. **D1, D2, D3** — Extract duplicate logic to composite actions
2. **M5** — Renovate acr_name null-check
3. **M7** — Rename `regex_pattern` (coordinated consumer update)
