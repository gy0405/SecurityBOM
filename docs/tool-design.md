# MCP 도구 설계 초안

| 도구명 | 구분 | 우선순위 | 목적 |
| --- | --- | --- | --- |
| `inspect_sbom` | 분석 | P0 | 단일 CycloneDX/SPDX 파일을 읽고 취약점, 라이선스, 품질 이슈를 정리합니다. |
| `compare_sbom_candidates` | 판단 | P0 | 여러 SBOM 후보를 비교해 보안 관점에서 더 나은 배포 후보를 추천합니다. |
| `find_vulnerable_components` | 분석 | P0 | 컴포넌트 이름과 버전을 기준으로 취약점 후보를 찾습니다. |
| `check_license_risks` | 분석 | P0 | 라이선스 누락, unknown, GPL/AGPL 계열처럼 검토가 필요한 항목을 분리합니다. |
| `score_sbom_quality` | 분석 | P0 | 버전, Package URL, 라이선스, 생태계 누락률로 SBOM 품질을 점수화합니다. |
| `make_remediation_plan` | 판단 | P1 | 심각도, 패치 가능성, SBOM 품질 문제를 합쳐 조치 순서를 만듭니다. |
| `explain_risk_to_team` | 전달 | P1 | 보안팀/개발팀이 이해할 수 있는 짧은 조치 설명을 생성합니다. |
| `export_triage_report` | 내보내기 | P1 | Markdown 또는 CSV 형태로 분석 결과를 저장합니다. |

## 도구별 입출력

### inspect_sbom

입력:

- `path`

출력:

- 컴포넌트 수
- 취약점/라이선스/품질 findings
- 위험 점수
- SBOM 품질 점수
- 권장 조치
- Markdown 리포트

### compare_sbom_candidates

입력:

- `paths`

출력:

- 추천 후보
- 후보별 위험 점수
- 후보별 SBOM 품질 점수
- 첫 번째 후보 대비 추가/삭제/버전 변경 컴포넌트
- 선택 이유
- Markdown 리포트

### find_vulnerable_components

입력:

- `components`
- `osv_lookup_enabled`

출력:

- 취약점 ID
- 심각도
- 영향받는 컴포넌트
- 현재 버전
- 권장 버전
- 근거 요약

### check_license_risks

입력:

- `components`
- `restricted_licenses`

출력:

- 검토 필요 라이선스
- 라이선스 누락 컴포넌트
- 정책 확인이 필요한 컴포넌트
- 담당자에게 전달할 메시지

### score_sbom_quality

입력:

- `components`

출력:

- 품질 점수
- 버전 누락 수
- Package URL 누락 수
- 라이선스 unknown 수
- 생태계 unknown 수
- 중복 컴포넌트 수

### make_remediation_plan

입력:

- `vulnerability_findings`
- `license_findings`
- `quality_warnings`
- `service_context`

출력:

- 오늘 처리할 항목
- 이번 주 처리할 항목
- 예외 승인 또는 추가 확인 항목
- 개발팀 전달 메시지

### export_triage_report

입력:

- `analysis_result`
- `format`

출력:

- Markdown 리포트
- CSV 파일
