# SBOM Candidate Comparison

- Recommended candidate: sample-cyclonedx-fixed
- Summary: Recommend sample-cyclonedx-fixed: decision score 0, risk score 0, SBOM quality 100.

## Ranking

| Rank | Candidate | Decision Score | Risk Score | Quality | Recommendation |
| --- | --- | ---: | ---: | ---: | --- |
| 1 | sample-cyclonedx-fixed | 0 | 0 | 100 | Acceptable for release from the current demo rule set. |
| 2 | sample-cyclonedx-rc | 30 | 22 | 92 | Approve only after license and SBOM metadata review. |
| 3 | sample-cyclonedx | 95 | 87 | 92 | Do not approve until critical findings are patched or accepted by exception. |

## Differences From First Candidate

### sample-cyclonedx

- Added components: 0
- Removed components: 0
- Changed versions: 0

### sample-cyclonedx-fixed

- Added components: 1
- Removed components: 1
- Changed versions: 2

- pkg:npm/lodash: 4.17.20 -> 4.17.21
- pkg:npm/minimist: 1.2.5 -> 1.2.6

### sample-cyclonedx-rc

- Added components: 1
- Removed components: 1
- Changed versions: 2

- pkg:npm/lodash: 4.17.20 -> 4.17.21
- pkg:npm/minimist: 1.2.5 -> 1.2.6
