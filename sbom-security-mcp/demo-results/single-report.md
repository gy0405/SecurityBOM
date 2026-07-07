# SBOM Security Analysis

- Candidate: sample-cyclonedx
- Components analyzed: 3
- Findings: 5
- Risk score: 87 (critical)
- SBOM quality score: 92
- Recommendation: Do not approve until critical findings are patched or accepted by exception.
- Severity mix: critical 1, high 1, medium 1, low 2

## Priority Findings

### 1. CVE-2021-44906 affects minimist

- Severity: critical
- Category: vulnerability
- Component: minimist 1.2.5 (npm)
- License: MIT
- Detail: Prototype pollution in minimist.
- Recommended action: Upgrade minimist to 1.2.6 or later.

### 2. CVE-2021-23337 affects lodash

- Severity: high
- Category: vulnerability
- Component: lodash 4.17.20 (npm)
- License: MIT
- Detail: Command injection risk in lodash template handling.
- Recommended action: Upgrade lodash to 4.17.21 or later.

### 3. Review license for internal-legacy-client

- Severity: medium
- Category: license
- Component: internal-legacy-client unknown (unknown)
- License: unknown
- Detail: Declared license is 'unknown'.
- Recommended action: Confirm policy fit before release approval.

### 4. Missing version for internal-legacy-client

- Severity: low
- Category: quality
- Component: internal-legacy-client unknown (unknown)
- License: unknown
- Detail: Versionless components cannot be reliably matched to advisories.
- Recommended action: Regenerate the SBOM with version metadata enabled.

### 5. Unknown ecosystem for internal-legacy-client

- Severity: low
- Category: quality
- Component: internal-legacy-client unknown (unknown)
- License: unknown
- Detail: Package ecosystem is missing or could not be inferred.
- Recommended action: Include package URLs or package manager metadata in the SBOM.
