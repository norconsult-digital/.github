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

### Security: Sensitive Content Checker
This repo includes an automated workflow that scans all workflow files for sensitive content such as hardcoded credentials, API keys, or improperly masked secrets. The checker runs on pull requests and categorizes findings by severity:
- 🔴 **CRITICAL**: Hardcoded secrets (immediate action required)
- 🟠 **HIGH**: Potential credential leaks (should be addressed soon)
- 🟡 **MEDIUM**: Improperly masked secrets (review recommended)
- 🔵 **LOW**: Best practice violations (improvement suggested)

For more details, see [`.github/scripts/README.md`](.github/scripts/README.md).

### Support / Questions
Contact the Platform team (internal) or open an issue in the repo using the template.
