# Sensitive Content Checker for GitHub Actions Workflows

This tool automatically scans GitHub Actions workflow files for sensitive content and categorizes findings by severity level.

## Overview

The sensitive content checker helps identify potential security issues in workflow files, such as:
- Hardcoded credentials (API keys, passwords, tokens)
- Improperly masked secrets
- Best practice violations

## Features

- **Automatic Scanning**: Runs on pull requests and pushes to main branch
- **Severity Categorization**: Issues are categorized as CRITICAL, HIGH, MEDIUM, or LOW
- **PR Comments**: Automatically posts scan results as comments on pull requests
- **JSON Reports**: Generates detailed JSON reports available as artifacts
- **Configurable Thresholds**: Can be configured to fail based on severity level

## Severity Levels

### 🔴 CRITICAL
Immediate action required. These are hardcoded secrets that pose a direct security risk.

Examples:
- Hardcoded passwords
- Hardcoded API keys
- Hardcoded access tokens
- Hardcoded private keys
- Hardcoded secret keys

### 🟠 HIGH
Should be addressed soon. Potential credential leaks that could be exploited.

Examples:
- Hardcoded authorization headers
- Hardcoded client secrets
- Hardcoded connection strings

### 🟡 MEDIUM
Review recommended. Secrets that may not be properly masked or handled.

Examples:
- Secrets potentially echoed to logs
- Secrets used in HTTP headers (ensure proper masking)

### 🔵 LOW
Best practice improvements.

Examples:
- Secrets marked as not required
- Passwords passed as workflow inputs (should use secrets instead)

## Usage

### Automatic Scanning

The workflow runs automatically on:
- Pull requests that modify workflow files
- Pushes to main branch that modify workflow files
- Manual workflow dispatch

### Manual Scanning

You can also run the scanner manually:

```bash
# Scan current directory
python .github/scripts/check-sensitive-content.py .

# Scan and save JSON report
python .github/scripts/check-sensitive-content.py . --json report.json

# Scan with custom fail threshold (critical, high, medium, low)
python .github/scripts/check-sensitive-content.py . --fail-on critical
```

### Command Line Options

- `directory`: Directory to scan (default: current directory)
- `--json <file>`: Save results to JSON file
- `--fail-on <level>`: Fail if issues of this severity or higher are found (default: high)
  - Choices: `critical`, `high`, `medium`, `low`

## Configuration

The workflow is configured in `.github/workflows/check-sensitive-content.yml`.

You can customize:
- When the workflow runs (triggers)
- The severity level that causes failures
- PR comment behavior

## Best Practices

To avoid sensitive content issues:

1. **Use GitHub Secrets**: Store all sensitive values as GitHub Secrets
   ```yaml
   steps:
     - name: Deploy
       env:
         API_KEY: ${{ secrets.API_KEY }}
   ```

2. **Mark secrets as required**: Always mark secrets as required in workflow_call
   ```yaml
   secrets:
     API_KEY:
       required: true
   ```

3. **Mask sensitive output**: Use `::add-mask::` to mask values in logs
   ```yaml
   - name: Mask value
     run: echo "::add-mask::${{ secrets.MY_SECRET }}"
   ```

4. **Avoid echoing secrets**: Never echo secret values directly
   ```yaml
   # ❌ Bad
   - run: echo "Token is ${{ secrets.TOKEN }}"
   
   # ✅ Good
   - run: echo "Token is configured"
   ```

## Interpreting Results

When the workflow runs, it will:

1. Scan all `.yml` and `.yaml` files in the repository
2. Categorize findings by severity
3. Post a comment on PRs with the results
4. Upload a detailed JSON report as an artifact
5. Fail the check if CRITICAL or HIGH severity issues are found (by default)

### Example Output

```
⚠️  Found 3 potential sensitive content issue(s) in workflow files:

🔴 CRITICAL (1 finding(s)):
--------------------------------------------------------------------------------
  File: .github/workflows/deploy.yml
  Line: 42
  Issue: Hardcoded API key detected
  Content: api_key: "sk-1234567890abcdef"...

🟡 MEDIUM (2 finding(s)):
--------------------------------------------------------------------------------
  File: .github/workflows/test.yml
  Line: 15
  Issue: Secret value potentially echoed to logs
  Content: echo ${{ secrets.MY_SECRET }}...
```

## Troubleshooting

### False Positives

If you encounter false positives, you can:

1. Ensure the pattern is actually safe (e.g., using proper variable substitution)
2. Review the pattern matching rules in `check-sensitive-content.py`
3. Update the script to exclude specific patterns if needed

### Workflow Fails on Safe Content

If the workflow fails but the content is safe:

1. Review the finding to understand why it was flagged
2. Refactor the code to follow best practices
3. If truly a false positive, consider updating the detection patterns

## Contributing

To add new detection patterns or improve existing ones:

1. Edit `.github/scripts/check-sensitive-content.py`
2. Add your pattern to `SENSITIVE_PATTERNS` array
3. Test the pattern against sample files
4. Submit a pull request

### Pattern Format

```python
{
    "pattern": r'regex pattern here',
    "severity": SeverityLevel.CRITICAL,  # or HIGH, MEDIUM, LOW
    "description": "Description of the issue",
    "example": 'example of problematic code'
}
```

## License

This tool is part of the Norconsult Digital organization's shared workflow library.
