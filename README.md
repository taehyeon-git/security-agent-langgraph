# Security Agent LangGraph

## 1. 프로젝트 개요

Security Agent LangGraph는 소스코드와 설정 파일을 분석하여 보안 취약점, 민감정보 노출, 위험한 코드 패턴을 탐지하는 1차 보안 분석 에이전트입니다. LLM이 기존 보안 Tool을 선택해 파일을 읽고 정적 검사한 뒤 근거와 대응 방법을 한글로 설명합니다.

미들웨어 계층은 요청 처리의 공통 관심사를 에이전트 로직과 분리하기 위해 추가했습니다. 모든 요청을 같은 순서로 기록·검증하고, 탐지 건수에 따라 위험도를 계산하며, 일관된 최종 응답을 제공합니다.

## 2. 전체 아키텍처

```text
사용자
  ↓
Request Logging Middleware
  ↓
Input Validation Middleware
  ↓
Security Agent ──→ Security Tools (tools.py)
  ↓
Risk Assessment Middleware
  ↓
Response Middleware
  ↓
최종 응답
```

공유 State의 주요 필드는 다음과 같습니다.

| 필드 | 타입 | 설명 |
|---|---|---|
| `messages` | `list[AnyMessage]` | 사용자, 에이전트, Tool 및 최종 응답 메시지 |
| `file_path` | `str` | 검증 후 절대 경로로 정규화된 분석 파일 |
| `findings` | `list[dict]` | 보안 Tool이 탐지한 항목 |
| `risk_level` | `str` | Low, Medium, High, Critical 중 하나 |

## 3. Middleware 설명

### Request Logging Middleware

- 역할: 사용자 요청, 대상 파일, UTC 요청 시각을 콘솔에 기록합니다.
- 입력: `messages`, `file_path`
- 출력: `request_time`
- 예시: `2026-08-27T01:30:00+00:00 | file_path=app.py | request=보안 검사해줘`

### Input Validation Middleware

- 역할: 파일 존재 여부와 일반 파일 여부, 5MB 이하 크기, 기본 소스/설정 파일 확장자를 검증합니다.
- 입력: `file_path`
- 출력: 절대 경로로 정규화된 `file_path`
- 예시: 존재하지 않는 `missing.py`를 전달하면 `FileNotFoundError`가 발생합니다. 실행 파일처럼 지원하지 않는 확장자는 `ValueError`가 발생합니다.

### Risk Assessment Middleware

- 역할: `findings` 개수를 다음 기준으로 위험도에 매핑합니다.
- 입력: `findings`
- 출력: `risk_level`
- 예시: 탐지 결과가 4건이면 `High`입니다.

| 탐지 개수 | 위험도 |
|---:|---|
| 0~1 | Low |
| 2~3 | Medium |
| 4~5 | High |
| 6 이상 | Critical |

### Response Middleware

- 역할: 분석 파일, 탐지 건수, 위험도, 권장 조치를 포함하는 Markdown 최종 요약을 추가합니다.
- 입력: `file_path`, `findings`, `risk_level`, `messages`
- 출력: 최종 `AIMessage`
- 예시: `탐지 결과: 4건 / 위험도: High / 권장 조치: 신속히 수정한 뒤 재검사`

## 4. 프로젝트 구조

```text
security-agent/
├── agent.py          # Security Agent 및 StateGraph 연결
├── tools.py          # 파일·민감정보·정적 분석 보안 Tool
├── middleware.py     # 네 가지 Middleware와 SecurityState
├── langgraph.json    # LangGraph 실행 설정
└── README.md         # 프로젝트 문서
```

추가로 `pyproject.toml`과 `uv.lock`은 Python 의존성을 관리하고, `.env`는 로컬 환경변수를 보관합니다.

## 5. 실행 방법

Python 3.11 이상과 uv가 필요합니다.

1. 의존성을 설치합니다.

   ```bash
   uv sync
   ```

2. 프로젝트 루트의 `.env`에 OpenAI API Key를 설정합니다. 실제 키는 Git에 커밋하지 마세요.

   ```dotenv
   OPENAI_API_KEY=your_openai_api_key_here
   ```

3. LangGraph 개발 서버를 실행합니다.

   ```bash
   uv run langgraph dev
   ```

   Windows PowerShell에서 reload 문제가 있으면 다음 명령을 사용할 수 있습니다.

   ```powershell
   $env:PYTHONUTF8=1; uv run langgraph dev --no-reload --allow-blocking
   ```

`langgraph.json`의 `agent` 그래프를 선택하고 아래와 같이 State를 전달합니다. `file_path`는 필수입니다.

```json
{
  "messages": [
    {"role": "user", "content": "이 파일의 민감정보와 위험한 코드 패턴을 검사해줘."}
  ],
  "file_path": "tools.py",
  "findings": [],
  "risk_level": "Low"
}
```

## 6. 동작 예시

사용자 요청:

```text
file_path: examples/insecure.py
message: 이 파일의 민감정보와 정적 보안 취약점을 검사해줘.
```

분석 결과 예시:

```text
발견 사항
- 하드코딩된 API Key 의심 패턴
- shell=True 사용
- eval 사용
- TLS 인증 verify=False 사용
```

4건이 탐지되었으므로 위험도 계산은 `4 → High`입니다. Response Middleware는 다음 형식의 최종 요약을 메시지에 추가합니다.

```markdown
## 보안 분석 최종 요약

- 분석 파일: `examples/insecure.py`
- 탐지 결과: 4건
- 위험도: **High**
- 권장 조치: 영향 범위를 확인하고 탐지 항목을 신속히 수정한 뒤 재검사하세요.
```

Security Agent의 상세 응답과 이 최종 요약은 `messages`에서 함께 확인할 수 있습니다.

## 7. 향후 발전 방향

- 변경 불가능한 저장소를 이용한 Audit Logging
- 사용자 인증
- 역할 기반 권한 관리
- Semgrep 연동
- Bandit 연동
- Trivy 연동
- PDF 보고서 생성
- GitHub Actions 연동
- 파일 형식별 탐지 규칙과 CVSS 기반 위험도 산정 고도화

> 이 프로젝트는 정규식과 LLM을 활용한 1차 점검 도구이며 전문 SAST, 비밀 탐지, 컨테이너 스캐너를 완전히 대체하지 않습니다.
