"""Security Agent의 LangGraph 미들웨어 노드 모음."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AIMessage, AnyMessage
from langgraph.graph.message import add_messages

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


def request_logging_middleware(state: SecurityState) -> dict[str, str]:
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


def input_validation_middleware(state: SecurityState) -> dict[str, str]:
    """대상 파일의 존재 여부, 크기 및 확장자를 검증합니다.

    Raises:
        ValueError: 경로가 없거나 크기/확장자 정책을 위반한 경우.
        FileNotFoundError: 대상 파일이 존재하지 않는 경우.
        IsADirectoryError: 대상이 일반 파일이 아닌 경우.
        OSError: 파일 정보를 읽을 수 없는 경우.
    """

    raw_path = state.get("file_path", "").strip()
    if not raw_path:
        raise ValueError("분석할 file_path가 필요합니다.")

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


def calculate_risk_level(finding_count: int) -> str:
    """탐지 결과 개수에 따라 위험 등급을 반환합니다."""

    if finding_count <= 1:
        return "Low"
    if finding_count <= 3:
        return "Medium"
    if finding_count <= 5:
        return "High"
    return "Critical"


def risk_assessment_middleware(state: SecurityState) -> dict[str, str]:
    """State의 탐지 결과 개수를 기준으로 위험도를 계산합니다."""

    finding_count = len(state.get("findings", []))
    risk_level = calculate_risk_level(finding_count)
    logger.info("위험도 계산 완료 | findings=%d | risk=%s", finding_count, risk_level)
    return {"risk_level": risk_level}


def response_middleware(state: SecurityState) -> dict[str, list[AIMessage]]:
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
