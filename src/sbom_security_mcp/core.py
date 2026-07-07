"""SBOM analysis and release-candidate comparison logic."""

from __future__ import annotations

import csv
import json
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


SEVERITY_SCORE = {
    "critical": 40,
    "high": 25,
    "medium": 12,
    "low": 5,
    "unknown": 2,
}


OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "golang": "Go",
    "go": "Go",
    "crates.io": "crates.io",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "packagist": "Packagist",
}


RISKY_LICENSES = {
    "agpl-3.0",
    "agpl-3.0-only",
    "agpl-3.0-or-later",
    "gpl-2.0",
    "gpl-2.0-only",
    "gpl-2.0-or-later",
    "gpl-3.0",
    "gpl-3.0-only",
    "gpl-3.0-or-later",
    "unknown",
    "none",
}


@dataclass(frozen=True)
class Component:
    name: str
    version: str = "unknown"
    ecosystem: str = "unknown"
    package_url: str = ""
    license: str = "unknown"
    source: str = ""

    @property
    def key(self) -> str:
        if self.package_url:
            return self.package_url.split("@", 1)[0].lower()
        return f"{self.ecosystem}:{self.name}".lower()


@dataclass
class Finding:
    component: Component
    category: str
    severity: str
    title: str
    detail: str
    recommendation: str
    score: int = field(init=False)

    def __post_init__(self) -> None:
        self.score = SEVERITY_SCORE.get(self.severity.lower(), SEVERITY_SCORE["unknown"])


@dataclass
class AnalysisResult:
    label: str
    path: str
    components: list[Component]
    findings: list[Finding]
    quality: dict[str, Any]
    risk_score: int
    decision_score: int
    recommendation: str


@dataclass
class ComparisonResult:
    recommended: str
    summary: str
    candidates: list[AnalysisResult]
    differences: list[dict[str, Any]]


def normalize_name(value: str) -> str:
    return value.strip().lower()


def parse_version(version: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", version or "")
    return tuple(int(number) for number in numbers[:4]) if numbers else (0,)


def version_lt(current: str, required: str) -> bool:
    left = parse_version(current)
    right = parse_version(required)
    max_len = max(len(left), len(right))
    return left + (0,) * (max_len - len(left)) < right + (0,) * (max_len - len(right))


def normalize_severity(severity: str | None) -> str:
    value = (severity or "unknown").strip().lower()
    if value in {"critical", "high", "medium", "low"}:
        return value
    if value in {"moderate", "important"}:
        return "medium"
    return "unknown"


def infer_ecosystem(package_url: str, name: str) -> str:
    purl = package_url.lower()
    if purl.startswith("pkg:"):
        return purl.split("/", 1)[0].replace("pkg:", "")
    if ":" in name and name.startswith(("org.", "com.", "net.", "io.")):
        return "maven"
    return "unknown"


def extract_license(value: Any) -> str:
    if not value:
        return "unknown"
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        licenses = []
        for item in value:
            if isinstance(item, dict):
                license_obj = item.get("license", item)
                licenses.append(str(license_obj.get("id") or license_obj.get("name") or "unknown"))
            else:
                licenses.append(str(item))
        return ", ".join(licenses) if licenses else "unknown"
    return "unknown"


def parse_cyclonedx(data: dict[str, Any]) -> list[Component]:
    components = []
    for item in data.get("components", []):
        name = item.get("name") or item.get("bom-ref") or "unknown"
        purl = item.get("purl", "")
        components.append(
            Component(
                name=name,
                version=str(item.get("version") or "unknown"),
                ecosystem=infer_ecosystem(purl, name),
                package_url=purl,
                license=extract_license(item.get("licenses")),
                source="CycloneDX",
            )
        )
    return components


def parse_spdx(data: dict[str, Any]) -> list[Component]:
    components = []
    for item in data.get("packages", []):
        name = item.get("name") or "unknown"
        purl = ""
        for ref in item.get("externalRefs", []):
            if ref.get("referenceType", "").lower() == "purl":
                purl = ref.get("referenceLocator", "")
                break
        components.append(
            Component(
                name=name,
                version=str(item.get("versionInfo") or "unknown"),
                ecosystem=infer_ecosystem(purl, name),
                package_url=purl,
                license=str(item.get("licenseConcluded") or item.get("licenseDeclared") or "unknown"),
                source="SPDX",
            )
        )
    return components


def load_components(path: Path) -> list[Component]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if "bomFormat" in data or "components" in data:
        return parse_cyclonedx(data)
    if "spdxVersion" in data or "packages" in data:
        return parse_spdx(data)
    raise ValueError("Unsupported SBOM format. Use CycloneDX JSON or SPDX JSON.")


def osv_ecosystem(component: Component) -> str | None:
    return OSV_ECOSYSTEMS.get(component.ecosystem.lower())


def osv_package_name(component: Component) -> str:
    if component.ecosystem == "maven" and component.package_url:
        # pkg:maven/group/artifact@version -> group:artifact
        package = component.package_url.removeprefix("pkg:maven/")
        package = package.split("@", 1)[0]
        parts = package.split("/")
        if len(parts) >= 2:
            return f"{parts[-2]}:{parts[-1]}"
    return component.name


def osv_severity(vulnerability: dict[str, Any]) -> str:
    database_severity = vulnerability.get("database_specific", {}).get("severity")
    if isinstance(database_severity, str) and database_severity:
        return normalize_severity(database_severity)

    severity_items = vulnerability.get("severity") or []
    for item in severity_items:
        score = item.get("score", "")
        if isinstance(score, str) and score.startswith("CVSS:"):
            if "AV:N" in score and ("PR:N" in score or "UI:N" in score):
                return "high"
    return "unknown"


def osv_fixed_versions(vulnerability: dict[str, Any]) -> list[str]:
    fixes = []
    for affected in vulnerability.get("affected", []):
        for range_item in affected.get("ranges", []):
            for event in range_item.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    fixes.append(str(fixed))
    return sorted(set(fixes), key=parse_version)


def best_fixed_version(current: str, fixes: list[str]) -> str | None:
    newer_fixes = [fix for fix in fixes if not version_lt(fix, current)]
    if newer_fixes:
        return sorted(newer_fixes, key=parse_version)[0]
    return fixes[0] if fixes else None


def query_osv(component: Component, timeout: int = 10) -> list[Finding]:
    ecosystem = osv_ecosystem(component)
    if not ecosystem or component.version == "unknown":
        return []

    payload = {
        "package": {
            "name": osv_package_name(component),
            "ecosystem": ecosystem,
        },
        "version": component.version,
    }
    request = urllib.request.Request(
        OSV_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "sbom-security-mcp/0.1"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return [
            Finding(
                component=component,
                category="quality",
                severity="low",
                title=f"OSV lookup failed for {component.name}",
                detail="The vulnerability database lookup could not be completed.",
                recommendation="Retry with network access or use demo advisory mode for offline testing.",
            )
        ]

    findings = []
    for vulnerability in data.get("vulns", []):
        vuln_id = vulnerability.get("id", "OSV-UNKNOWN")
        aliases = vulnerability.get("aliases") or []
        title_id = aliases[0] if aliases else vuln_id
        fixes = osv_fixed_versions(vulnerability)
        fixed_version = best_fixed_version(component.version, fixes)
        recommendation = (
            f"Upgrade to {fixed_version} or later."
            if fixed_version
            else "Review the advisory and upgrade to a non-affected version."
        )
        findings.append(
            Finding(
                component=component,
                category="vulnerability",
                severity=osv_severity(vulnerability),
                title=f"{title_id} affects {component.name}",
                detail=vulnerability.get("summary") or vulnerability.get("details", "")[:240],
                recommendation=recommendation,
            )
        )
    return findings


def check_license(component: Component) -> list[Finding]:
    tokens = {token.strip().lower() for token in re.split(r"[,/()\s]+", component.license) if token.strip()}
    if tokens & RISKY_LICENSES:
        return [
            Finding(
                component=component,
                category="license",
                severity="medium",
                title=f"Review license for {component.name}",
                detail=f"Declared license is '{component.license}'.",
                recommendation="Confirm policy fit before release approval.",
            )
        ]
    return []


def check_quality(component: Component) -> list[Finding]:
    findings = []
    if component.version == "unknown":
        findings.append(
            Finding(
                component=component,
                category="quality",
                severity="low",
                title=f"Missing version for {component.name}",
                detail="Versionless components cannot be reliably matched to advisories.",
                recommendation="Regenerate the SBOM with version metadata enabled.",
            )
        )
    if component.ecosystem == "unknown":
        findings.append(
            Finding(
                component=component,
                category="quality",
                severity="low",
                title=f"Unknown ecosystem for {component.name}",
                detail="Package ecosystem is missing or could not be inferred.",
                recommendation="Include package URLs or package manager metadata in the SBOM.",
            )
        )
    return findings


def calculate_quality(components: list[Component]) -> dict[str, Any]:
    total = len(components) or 1
    missing_versions = sum(1 for component in components if component.version == "unknown")
    missing_purls = sum(1 for component in components if not component.package_url)
    unknown_licenses = sum(1 for component in components if component.license.lower() == "unknown")
    unknown_ecosystems = sum(1 for component in components if component.ecosystem == "unknown")
    duplicate_keys = len(components) - len({component.key for component in components})
    penalty = (
        missing_versions * 8
        + missing_purls * 5
        + unknown_licenses * 6
        + unknown_ecosystems * 5
        + duplicate_keys * 4
    )
    score = max(0, 100 - round((penalty / total)))
    return {
        "score": score,
        "missing_versions": missing_versions,
        "missing_purls": missing_purls,
        "unknown_licenses": unknown_licenses,
        "unknown_ecosystems": unknown_ecosystems,
        "duplicate_components": duplicate_keys,
    }


def analyze_components(components: list[Component]) -> list[Finding]:
    findings = []
    for component in components:
        findings.extend(query_osv(component))
        findings.extend(check_license(component))
        findings.extend(check_quality(component))
    return sorted(findings, key=lambda finding: finding.score, reverse=True)


def risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def recommendation_for(findings: list[Finding], quality: dict[str, Any]) -> str:
    critical = sum(1 for finding in findings if finding.severity == "critical")
    high = sum(1 for finding in findings if finding.severity == "high")
    license_reviews = sum(1 for finding in findings if finding.category == "license")
    if critical:
        return "Do not approve until critical findings are patched or accepted by exception."
    if high:
        return "Approve only with a near-term patch plan for high findings."
    if license_reviews:
        return "Approve only after license and SBOM metadata review."
    if quality["score"] < 80:
        return "Request a cleaner SBOM before relying on this result."
    return "Acceptable for release from the current OSV lookup result."


def analyze_sbom_file(
    path: str | Path,
    label: str | None = None,
) -> AnalysisResult:
    sbom_path = Path(path)
    components = load_components(sbom_path)
    findings = analyze_components(components)
    quality = calculate_quality(components)
    risk_score = sum(finding.score for finding in findings)
    decision_score = risk_score + max(0, 100 - int(quality["score"]))
    candidate_label = label or sbom_path.stem
    return AnalysisResult(
        label=candidate_label,
        path=str(sbom_path),
        components=components,
        findings=findings,
        quality=quality,
        risk_score=risk_score,
        decision_score=decision_score,
        recommendation=recommendation_for(findings, quality),
    )


def component_versions(result: AnalysisResult) -> dict[str, str]:
    return {component.key: component.version for component in result.components}


def compare_sbom_files(paths: list[str | Path]) -> ComparisonResult:
    if len(paths) < 2:
        raise ValueError("Provide at least two SBOM files to compare candidates.")
    candidates = [analyze_sbom_file(path) for path in paths]
    ranked = sorted(candidates, key=lambda item: (item.decision_score, -int(item.quality["score"])))
    recommended = ranked[0]
    baseline = candidates[0]
    baseline_components = component_versions(baseline)
    differences = []
    for candidate in candidates:
        candidate_components = component_versions(candidate)
        added = sorted(set(candidate_components) - set(baseline_components))
        removed = sorted(set(baseline_components) - set(candidate_components))
        changed = sorted(
            key
            for key in set(candidate_components) & set(baseline_components)
            if candidate_components[key] != baseline_components[key]
        )
        differences.append(
            {
                "candidate": candidate.label,
                "added_components": added,
                "removed_components": removed,
                "changed_versions": [
                    {
                        "component": key,
                        "from": baseline_components[key],
                        "to": candidate_components[key],
                    }
                    for key in changed
                ],
            }
        )
    return ComparisonResult(
        recommended=recommended.label,
        summary=(
            f"Recommend {recommended.label}: decision score {recommended.decision_score}, "
            f"risk score {recommended.risk_score}, SBOM quality {recommended.quality['score']}."
        ),
        candidates=ranked,
        differences=differences,
    )


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in ["critical", "high", "medium", "low", "unknown"]}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def render_analysis_markdown(result: AnalysisResult) -> str:
    counts = severity_counts(result.findings)
    lines = [
        "# SBOM Security Analysis",
        "",
        f"- Candidate: {result.label}",
        f"- Components analyzed: {len(result.components)}",
        f"- Findings: {len(result.findings)}",
        f"- Risk score: {result.risk_score} ({risk_level(result.risk_score)})",
        f"- SBOM quality score: {result.quality['score']}",
        f"- Recommendation: {result.recommendation}",
        f"- Severity mix: critical {counts['critical']}, high {counts['high']}, medium {counts['medium']}, low {counts['low']}",
        "",
        "## Priority Findings",
        "",
    ]
    if not result.findings:
        lines.append("No findings from OSV for the current SBOM components.")
        return "\n".join(lines)
    for index, finding in enumerate(result.findings, start=1):
        component = finding.component
        lines.extend(
            [
                f"### {index}. {finding.title}",
                "",
                f"- Severity: {finding.severity}",
                f"- Category: {finding.category}",
                f"- Component: {component.name} {component.version} ({component.ecosystem})",
                f"- License: {component.license}",
                f"- Detail: {finding.detail}",
                f"- Recommended action: {finding.recommendation}",
                "",
            ]
        )
    return "\n".join(lines)


def render_comparison_markdown(result: ComparisonResult) -> str:
    lines = [
        "# SBOM Candidate Comparison",
        "",
        f"- Recommended candidate: {result.recommended}",
        f"- Summary: {result.summary}",
        "",
        "## Ranking",
        "",
        "| Rank | Candidate | Decision Score | Risk Score | Quality | Recommendation |",
        "| --- | --- | ---: | ---: | ---: | --- |",
    ]
    for index, candidate in enumerate(result.candidates, start=1):
        lines.append(
            f"| {index} | {candidate.label} | {candidate.decision_score} | "
            f"{candidate.risk_score} | {candidate.quality['score']} | {candidate.recommendation} |"
        )
    lines.extend(["", "## Differences From First Candidate", ""])
    for item in result.differences:
        lines.extend(
            [
                f"### {item['candidate']}",
                "",
                f"- Added components: {len(item['added_components'])}",
                f"- Removed components: {len(item['removed_components'])}",
                f"- Changed versions: {len(item['changed_versions'])}",
                "",
            ]
        )
        for changed in item["changed_versions"][:8]:
            lines.append(f"- {changed['component']}: {changed['from']} -> {changed['to']}")
        if item["changed_versions"]:
            lines.append("")
    return "\n".join(lines)


def finding_rows(result: AnalysisResult) -> list[dict[str, Any]]:
    rows = []
    for finding in result.findings:
        rows.append(
            {
                "candidate": result.label,
                "severity": finding.severity,
                "category": finding.category,
                "component": finding.component.name,
                "version": finding.component.version,
                "ecosystem": finding.component.ecosystem,
                "license": finding.component.license,
                "title": finding.title,
                "recommendation": finding.recommendation,
            }
        )
    return rows


def write_findings_csv(path: str | Path, results: list[AnalysisResult]) -> None:
    rows = [row for result in results for row in finding_rows(result)]
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else ["candidate"])
        writer.writeheader()
        writer.writerows(rows)


def analysis_to_dict(result: AnalysisResult) -> dict[str, Any]:
    payload = asdict(result)
    payload["components"] = [asdict(component) for component in result.components]
    payload["findings"] = [
        {
            "severity": finding.severity,
            "category": finding.category,
            "title": finding.title,
            "detail": finding.detail,
            "recommendation": finding.recommendation,
            "component": asdict(finding.component),
            "score": finding.score,
        }
        for finding in result.findings
    ]
    return payload


def comparison_to_dict(result: ComparisonResult) -> dict[str, Any]:
    return {
        "recommended": result.recommended,
        "summary": result.summary,
        "candidates": [analysis_to_dict(candidate) for candidate in result.candidates],
        "differences": result.differences,
    }
