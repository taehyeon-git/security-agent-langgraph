"""Security Agent의 LangGraph 미들웨어 노드 모음."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AIMessage, AnyMessage, SystemMessage
from langchain_core.messages import ToolMessage
from langchain.agents.middleware import AgentMiddleware, ModelRequest, ModelResponse, after_agent, before_agent
from langgraph.graph.message import add_messages
from langgraph.runtime import Runtime
from tools import load_skills

logger = logging.getLogger("security_agent.middleware")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False

# 기본 입력 검증 정책입니다.
ALLOWED_EXTENSIONS = {
    ".c", ".conf", ".cpp", ".cs", ".css", ".env", ".go", ".h", ".html",
    ".ini", ".java", ".js", ".json", ".jsx", ".kt", ".md", ".php", ".properties",
    ".py", ".rb", ".rs", ".sh", ".sql", ".toml", ".ts", ".tsx", ".txt", ".xml",
    ".yaml", ".yml",
}
SPECIAL_FILENAMES = {"dockerfile", "makefile"}
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


class SecurityState(TypedDict, total=False):
    """Security Agent 그래프에서 노드 사이에 공유하는 상태."""

    messages: Annotated[list[AnyMessage], add_messages]
    file_path: str
    findings: list[dict[str, Any]]
    risk_level: str
    request_time: str
    skill_name: str
    active_skills: list[str]


@before_agent(state_schema=SecurityState)
def request_logging_middleware(state: SecurityState, runtime: Runtime) -> dict[str, str]:
    """사용자 요청과 UTC 요청 시각을 콘솔에 기록합니다."""

    request_time = datetime.now(timezone.utc).isoformat()
    messages = state.get("messages", [])
    last_message = messages[-1].content if messages else "(메시지 없음)"
    logger.info(
        "보안 분석 요청 | time=%s | file_path=%s | request=%s",
        request_time,
        state.get("file_path", "(없음)"),
        str(last_message).replace("\n", " ")[:500],
    )
    return {"request_time": request_time}


@before_agent(state_schema=SecurityState)
def input_validation_middleware(state: SecurityState, runtime: Runtime) -> dict[str, str]:
    """대상 파일이 지정된 경우 존재 여부, 크기 및 확장자를 검증합니다.

    Raises:
        ValueError: 크기/확장자 정책을 위반한 경우.
        FileNotFoundError: 대상 파일이 존재하지 않는 경우.
        IsADirectoryError: 대상이 일반 파일이 아닌 경우.
        OSError: 파일 정보를 읽을 수 없는 경우.
    """

    raw_path = state.get("file_path", "").strip()
    if not raw_path:
        return {}

    path = Path(raw_path).expanduser()
    try:
        if not path.exists():
            raise FileNotFoundError(f"분석 대상 파일이 존재하지 않습니다: {raw_path}")
        if not path.is_file():
            raise IsADirectoryError(f"분석 대상은 일반 파일이어야 합니다: {raw_path}")
        file_size = path.stat().st_size
    except (FileNotFoundError, IsADirectoryError):
        raise
    except OSError as exc:
        raise OSError(f"파일 정보를 확인할 수 없습니다: {raw_path}") from exc

    if file_size > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"파일 크기가 제한({MAX_FILE_SIZE_BYTES // (1024 * 1024)}MB)을 초과했습니다: {file_size} bytes"
        )

    suffix = path.suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS and path.name.lower() not in SPECIAL_FILENAMES:
        raise ValueError(f"지원하지 않는 파일 확장자입니다: {suffix or '(확장자 없음)'}")

    normalized_path = str(path.resolve())
    logger.info("입력 검증 완료 | file_path=%s | size=%d", normalized_path, file_size)
    return {"file_path": normalized_path}


class SkillMiddleware(AgentMiddleware[SecurityState, Any]):
    """요청과 명시 선택값에 맞는 로컬 스킬 지침을 모델 호출에 주입합니다."""
    state_schema = SecurityState
    KEYWORDS = {
        "security-agent-upgrade": ("에이전트 업그레이드", "프로젝트 업그레이드", "langgraph 개선", "langgraph 에이전트", "에이전트를 고도화", "에이전트 고도화", "production ready"),
        "semgrep-rule-authoring": ("semgrep rule", "semgrep 규칙", "규칙 작성", "rule yaml"),
        "semgrep-security": ("semgrep", "sast", "정적 분석", "정적분석"),
        "security-review": ("security review", "보안 리뷰", "코드 보안", "취약점 검토"),
        "threat-model-generation": ("threat model", "위협 모델", "stride"),
        "secrets-gitleaks": ("gitleaks", "secret", "시크릿", "비밀 탐지", "credential"),
        "dependency-scanning": ("dependency", "의존성", "supply chain", "공급망", "cve"),
    }

    def __init__(self, max_skills: int = 3) -> None:
        self.skills = load_skills()
        self.max_skills = max_skills

    def select_skills(self, state: SecurityState) -> list[str]:
        explicit = state.get("skill_name", "").strip().lower()
        if explicit:
            requested = [item.strip() for item in explicit.split(",") if item.strip()]
            return [name for name in requested if name in self.skills][:self.max_skills]
        messages = state.get("messages", [])
        query = str(messages[-1].content).lower() if messages else ""
        selected = [name for name, words in self.KEYWORDS.items() if name in self.skills and any(word in query for word in words)]
        return selected[:self.max_skills]

    def _apply_skills(self, request: ModelRequest) -> ModelRequest | None:
        """선택된 스킬 지침을 시스템 메시지에 주입한 요청을 반환합니다.

        선택된 스킬이 없으면 None을 반환하여 원본 요청을 그대로 사용하도록 합니다.
        동기/비동기 경로가 공유하는 순수 로직으로 I/O를 수행하지 않습니다.
        """

        selected = self.select_skills(request.state)
        if not selected:
            return None
        blocks = [f"<skill name=\"{name}\">\n{self.skills[name]['instructions']}\n</skill>" for name in selected]
        current = request.system_message.content if request.system_message else ""
        updated_state = dict(request.state)
        updated_state["active_skills"] = selected
        logger.info("스킬 활성화 | skills=%s", ",".join(selected))
        return request.override(
            system_message=SystemMessage(content=f"{current}\n\n## Activated project skills\n" + "\n\n".join(blocks)),
            state=updated_state,
        )

    def wrap_model_call(self, request: ModelRequest, handler: Any) -> ModelResponse:
        updated = self._apply_skills(request)
        return handler(updated if updated is not None else request)

    async def awrap_model_call(self, request: ModelRequest, handler: Any) -> ModelResponse:
        updated = self._apply_skills(request)
        return await handler(updated if updated is not None else request)


skill_middleware = SkillMiddleware()


def calculate_risk_level(finding_count: int) -> str:
    """탐지 결과 개수에 따라 위험 등급을 반환합니다."""

    if finding_count <= 1:
        return "Low"
    if finding_count <= 3:
        return "Medium"
    if finding_count <= 5:
        return "High"
    return "Critical"


@after_agent(state_schema=SecurityState)
def risk_assessment_middleware(state: SecurityState, runtime: Runtime) -> dict[str, Any]:
    """State의 탐지 결과 개수를 기준으로 위험도를 계산합니다."""

    findings = list(state.get("findings", []))
    if not findings:
        for message in state.get("messages", []):
            if not isinstance(message, ToolMessage):
                continue
            match = re.search(r"총\s+(\d+)건(?:의|\s)", str(message.content))
            if not match:
                continue
            tool_name = getattr(message, "name", None) or "security_tool"
            findings.extend(
                {"source": tool_name, "index": index + 1}
                for index in range(int(match.group(1)))
            )

    finding_count = len(findings)
    risk_level = calculate_risk_level(finding_count)
    logger.info("위험도 계산 완료 | findings=%d | risk=%s", finding_count, risk_level)
    return {"findings": findings, "risk_level": risk_level}


@after_agent(state_schema=SecurityState)
def response_middleware(state: SecurityState, runtime: Runtime) -> dict[str, list[AIMessage]]:
    """위험도와 권장 조치를 포함하는 통일된 최종 응답을 추가합니다."""

    findings = state.get("findings", [])
    risk_level = state.get("risk_level", "Low")
    recommendations = {
        "Low": "현재 상태를 유지하고 정기적인 보안 점검을 수행하세요.",
        "Medium": "탐지 항목을 검토하고 우선순위에 따라 수정 계획을 수립하세요.",
        "High": "영향 범위를 확인하고 탐지 항목을 신속히 수정한 뒤 재검사하세요.",
        "Critical": "즉시 노출을 차단하고 담당자에게 알린 뒤 긴급 수정 및 재검사를 수행하세요.",
    }
    content = (
        "## 보안 분석 최종 요약\n\n"
        f"- 분석 파일: `{state.get('file_path', '알 수 없음')}`\n"
        f"- 탐지 결과: {len(findings)}건\n"
        f"- 위험도: **{risk_level}**\n"
        f"- 권장 조치: {recommendations[risk_level]}"
    )
    return {"messages": [AIMessage(content=content, name="response_middleware")]}
