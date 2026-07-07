# SBOM Candidate Comparison

- Recommended candidate: sample-cyclonedx-fixed
- Summary: Recommend sample-cyclonedx-fixed because it removes the vulnerable lodash/minimist versions and has the cleanest SBOM metadata.

## Ranking

| Rank | Candidate | Decision Score | Risk Score | Quality | Recommendation |
| --- | --- | ---: | ---: | ---: | --- |
| 1 | sample-cyclonedx-fixed | 0 | 0 | 100 | Acceptable for release from the current OSV lookup result. |
| 2 | sample-cyclonedx-rc | 30 | 22 | 92 | Approve only after license and SBOM metadata review. |
| 3 | sample-cyclonedx | 95 | 87 | 92 | Do not approve until critical findings are patched or accepted by exception. |

## Message For Developers

Use `sample-cyclonedx-fixed` as the release candidate. It patches the vulnerable npm packages from the original SBOM and avoids the unknown debug helper introduced in the RC candidate.
