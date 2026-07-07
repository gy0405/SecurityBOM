# SBOM Security Analysis

- Candidate: sample-cyclonedx
- Components analyzed: 3
- Findings: 9
- Risk score: 148 (critical)
- SBOM quality score: 92
- Recommendation: Do not approve until critical findings are patched or accepted by exception.
- Severity mix: critical 1, high 2, medium 4, low 2

## Priority Findings

### 1. CVE-2021-44906 affects minimist

- Severity: critical
- Category: vulnerability
- Component: minimist 1.2.5 (npm)
- License: MIT
- Detail: Prototype Pollution in minimist
- Recommended action: Upgrade to 1.2.6 or later.

### 2. CVE-2021-23337 affects lodash

- Severity: high
- Category: vulnerability
- Component: lodash 4.17.20 (npm)
- License: MIT
- Detail: Command Injection in lodash
- Recommended action: Upgrade to 4.17.21 or later.

### 3. CVE-2026-4800 affects lodash

- Severity: high
- Category: vulnerability
- Component: lodash 4.17.20 (npm)
- License: MIT
- Detail: lodash vulnerable to Code Injection via `_.template` imports key names
- Recommended action: Upgrade to 4.18.0 or later.

### 4. CVE-2020-28500 affects lodash

- Severity: medium
- Category: vulnerability
- Component: lodash 4.17.20 (npm)
- License: MIT
- Detail: Regular Expression Denial of Service (ReDoS) in lodash
- Recommended action: Upgrade to 4.17.21 or later.

### 5. CVE-2026-2950 affects lodash

- Severity: medium
- Category: vulnerability
- Component: lodash 4.17.20 (npm)
- License: MIT
- Detail: lodash vulnerable to Prototype Pollution via array path bypass in `_.unset` and `_.omit`
- Recommended action: Upgrade to 4.18.0 or later.

### 6. CVE-2025-13465 affects lodash

- Severity: medium
- Category: vulnerability
- Component: lodash 4.17.20 (npm)
- License: MIT
- Detail: Lodash has Prototype Pollution Vulnerability in `_.unset` and `_.omit` functions
- Recommended action: Upgrade to 4.17.23 or later.

### 7. Review license for internal-legacy-client

- Severity: medium
- Category: license
- Component: internal-legacy-client unknown (unknown)
- License: unknown
- Detail: Declared license is 'unknown'.
- Recommended action: Confirm policy fit before release approval.

### 8. Missing version for internal-legacy-client

- Severity: low
- Category: quality
- Component: internal-legacy-client unknown (unknown)
- License: unknown
- Detail: Versionless components cannot be reliably matched to advisories.
- Recommended action: Regenerate the SBOM with version metadata enabled.

### 9. Unknown ecosystem for internal-legacy-client

- Severity: low
- Category: quality
- Component: internal-legacy-client unknown (unknown)
- License: unknown
- Detail: Package ecosystem is missing or could not be inferred.
- Recommended action: Include package URLs or package manager metadata in the SBOM.
