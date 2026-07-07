# sbom-security-mcp

SBOM을 보안 담당자의 조치 목록과 배포 후보 선택 근거로 바꿔주는 MCP입니다.

하나의 CycloneDX/SPDX 파일을 분석해 위험 패키지를 찾을 수 있고, 여러 SBOM 후보를 비교해 어떤 빌드나 릴리스를 선택하는 것이 나은지도 추천할 수 있습니다.

## 문제 정의

SBOM은 점점 많이 만들어지고 있지만, 현장에서 바로 답하기 어려운 질문은 따로 있습니다.

- 이 SBOM에서 지금 위험한 패키지는 무엇인가?
- Critical 취약점이 있어도 실제 배포 승인을 막아야 하는가?
- 여러 빌드 후보 중 어떤 SBOM이 가장 안전한가?
- 패치된 후보가 정말 위험을 줄였는가?
- 라이선스 문제와 SBOM 품질 문제는 누가 확인해야 하는가?
- 개발팀에는 어떤 문장으로 조치를 요청해야 하는가?

이 MCP는 SBOM을 단순히 펼쳐 보여주는 도구가 아니라, 보안 실무자가 취약점 검토, 라이선스 검토, 패치 우선순위 결정, 배포 후보 선택을 한 흐름으로 처리하도록 돕는 분석 워크플로우를 제공합니다.

## 핵심 기능

- CycloneDX/SPDX SBOM 파싱
- 패키지, 버전, 생태계, Package URL 정규화
- OSV 취약점 DB 기반 위험 패키지 탐지
- 라이선스 검토 대상 분류
- 버전 누락, 생태계 누락 같은 SBOM 품질 점수화
- 단일 SBOM 분석 리포트 생성
- 여러 SBOM 후보 비교 및 추천
- 보안 담당자용 Markdown/CSV 리포트 생성

## 예상 도구

초기 MCP 도구 설계는 `docs/tool-design.md`에 정리되어 있습니다.

우선 구현 후보:

- `inspect_sbom`
- `compare_sbom_candidates`
- `find_vulnerable_components`
- `check_license_risks`
- `make_remediation_plan`
- `export_triage_report`

## 데모 흐름

데모 시나리오는 `docs/demo-scenario.md`에 정리되어 있습니다.

핵심 흐름:

1. 단일 SBOM을 읽고 위험 패키지를 찾습니다.
2. SBOM 품질과 라이선스 검토 대상을 함께 확인합니다.
3. 여러 SBOM 후보가 있으면 위험 점수와 품질 점수를 비교합니다.
4. 어떤 후보를 배포 승인하기 좋은지 추천합니다.
5. 개발팀에 전달할 조치 메시지를 만듭니다.

## 실행

단일 SBOM 분석:

```powershell
$env:PYTHONPATH=".\src"
python -m sbom_security_mcp.server analyze .\examples\sample-cyclonedx.json --markdown .\demo-results\single-report.md --csv .\demo-results\single-findings.csv
```

여러 SBOM 후보 비교:

```powershell
$env:PYTHONPATH=".\src"
python -m sbom_security_mcp.server compare .\examples\sample-cyclonedx.json .\examples\sample-cyclonedx-fixed.json .\examples\sample-cyclonedx-rc.json --markdown .\demo-results\comparison-report.md --csv .\demo-results\comparison-findings.csv
```

MCP 서버 실행:

```powershell
python -m sbom_security_mcp.server
```

## 데이터 소스

MVP에서는 OSV 취약점 DB를 조회합니다.

확장 후보:

- NVD
- CISA KEV
- GitHub Advisory DB
- 조직별 라이선스 정책
- 서비스 중요도 태그

## 프로젝트 구조

```text
sbom-security-mcp/
  docs/
    tool-design.md
    demo-scenario.md
  examples/
    sample-cyclonedx.json
    sample-cyclonedx-fixed.json
    sample-cyclonedx-rc.json
    sample-output.md
  demo-results/
    single-report.md
    single-findings.csv
    comparison-report.md
    comparison-findings.csv
  src/
    sbom_security_mcp/
      core.py
      server.py
      tools/
  tests/
  pyproject.toml
```

## 개발 시작

Python 3.11 이상을 권장합니다.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## 보안 원칙

실제 고객 SBOM, 내부 시스템명, 비공개 취약점 정보는 저장소에 커밋하지 않습니다.

예시에는 공개 패키지와 샘플 데이터만 사용합니다.
