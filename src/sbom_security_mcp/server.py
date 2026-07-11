"""MCP and CLI entry point for secuBOM (sbom-security-mcp)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .core import (
    analyze_sbom_file,
    analysis_to_dict,
    compare_sbom_files,
    comparison_to_dict,
    render_analysis_markdown,
    render_comparison_markdown,
    write_findings_csv,
)

try:
    from mcp.server.fastmcp import FastMCP
    from mcp.types import ToolAnnotations
except ImportError:  # pragma: no cover - allows local CLI use before installing mcp.
    FastMCP = None
    ToolAnnotations = None


if FastMCP:
    mcp = FastMCP(
        "secuBOM",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        stateless_http=True,
        json_response=True,
    )

    @mcp.tool(
        annotations=ToolAnnotations(
            title="secuBOM: Inspect SBOM",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    def inspect_sbom(path: str) -> dict:
        """[secuBOM] Analyze one CycloneDX or SPDX SBOM and return prioritized security findings.

        secuBOM inspects a single SBOM file, detects vulnerable packages via the OSV
        database, flags license and SBOM-quality risks, and returns a release recommendation.
        """
        result = analyze_sbom_file(path)
        payload = analysis_to_dict(result)
        payload["markdown_report"] = render_analysis_markdown(result)
        return payload

    @mcp.tool(
        annotations=ToolAnnotations(
            title="secuBOM: Compare SBOM Candidates",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    def compare_sbom_candidates(paths: list[str]) -> dict:
        """[secuBOM] Compare multiple SBOM candidates and recommend the safest release option.

        secuBOM analyzes each SBOM candidate, ranks them by combined security risk and
        SBOM quality, reports version differences, and recommends the safest build to ship.
        """
        result = compare_sbom_files(paths)
        payload = comparison_to_dict(result)
        payload["markdown_report"] = render_comparison_markdown(result)
        return payload


def run_cli() -> int:
    parser = argparse.ArgumentParser(description="secuBOM: SBOM security analysis and candidate comparison.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze one SBOM")
    analyze_parser.add_argument("sbom", type=Path)
    analyze_parser.add_argument("--markdown", type=Path)
    analyze_parser.add_argument("--csv", type=Path)

    compare_parser = subparsers.add_parser("compare", help="Compare two or more SBOM candidates")
    compare_parser.add_argument("sboms", type=Path, nargs="+")
    compare_parser.add_argument("--markdown", type=Path)
    compare_parser.add_argument("--csv", type=Path)

    args = parser.parse_args()

    if args.command == "analyze":
        result = analyze_sbom_file(args.sbom)
        markdown = render_analysis_markdown(result)
        print(markdown)
        if args.markdown:
            args.markdown.write_text(markdown, encoding="utf-8")
        if args.csv:
            write_findings_csv(args.csv, [result])
        return 0

    result = compare_sbom_files(args.sboms)
    markdown = render_comparison_markdown(result)
    print(markdown)
    if args.markdown:
        args.markdown.write_text(markdown, encoding="utf-8")
    if args.csv:
        write_findings_csv(args.csv, result.candidates)
    return 0


def main() -> None:
    if FastMCP:
        mcp.run(transport=os.getenv("MCP_TRANSPORT", "streamable-http"))
        return
    raise SystemExit("mcp is not installed. Use CLI mode with `python -m sbom_security_mcp.server analyze ...`.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(run_cli())
    main()
