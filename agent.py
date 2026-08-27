"""Security Agent와 미들웨어 StateGraph 구성."""

from __future__ import annotations

import re
from typing import Any

from langchain.agents import create_agent
from langchain_core.messages import AnyMessage, HumanMessage, ToolMessage
from langgraph.graph import END, START, StateGraph

from middleware import (
    SecurityState,
    input_validation_middleware,
    request_logging_middleware,
    response_middleware,
    risk_assessment_middleware,
)
from tools import SECURITY_TOOLS


def create_security_agent() -> Any:
    """보안 분석 전용 에이전트를 생성합니다."""

    system_prompt = """당신은 소스코드와 설정 파일을 분석하는 방어 중심의 사이버보안 전문 에이전트입니다.

주요 역할:
- 소스코드의 보안 취약 패턴을 점검합니다.
- 파일에 포함된 API Key, 비밀번호, 토큰 등 민감정보 노출 가능성을 확인합니다.
- 웹/API/Python/컨테이너/클라우드 환경의 보안 체크리스트를 제공합니다.
- 발견된 문제의 원인, 영향, 위험도, 수정 방법을 설명합니다.
- 필요한 경우 파일을 먼저 읽고 실제 내용을 근거로 분석합니다.

사용 가능한 보안 도구:
- read_file: 분석 대상 파일의 내용을 읽습니다.
- list_directory: 분석 가능한 파일과 폴더를 확인합니다.
- scan_sensitive_information: 파일 안의 민감정보 노출 패턴을 탐지합니다.
- static_security_scan: 소스코드의 대표적인 취약 패턴을 정적으로 점검합니다.
- security_checklist: 대상 영역별 보안 점검 항목을 제공합니다.
- calculate_risk_score: 발생 가능성과 영향도를 바탕으로 위험도를 계산합니다.

작업 원칙:
1. 파일 분석 요청을 받으면 추측하지 말고 먼저 관련 파일을 읽거나 검사 도구를 사용하세요.
2. 발견한 취약점은 가능하면 파일명, 줄 번호, 근거와 함께 설명하세요.
3. 결과는 '요약 → 발견 사항 → 위험도 → 대응 방법' 순서로 정리하세요.
4. 실제 비밀번호, API Key, 토큰 등 민감정보는 응답에 그대로 노출하지 마세요.
5. 확실하지 않은 내용은 취약점이라고 단정하지 말고 '추가 확인 필요'로 표시하세요.
6. 공격이나 우회를 위한 실행보다 방어, 점검, 수정 및 예방을 우선하세요.
7. 파일을 임의로 삭제하거나 시스템 명령을 실행하지 마세요.
8. 모든 응답은 한글로 작성하세요.
"""

    agent_executor = create_agent(
        model="gpt-5.4-mini",
        tools=SECURITY_TOOLS,
        system_prompt=system_prompt,
    )

    return agent_executor


def _extract_findings(messages: list[AnyMessage]) -> list[dict[str, Any]]:
    """기존 보안 Tool 메시지의 탐지 건수를 State findings로 변환합니다."""

    findings: list[dict[str, Any]] = []
    for message in messages:
        if not isinstance(message, ToolMessage):
            continue
        # tools.py의 기존 출력 형식("총 N건 ...")을 그대로 활용합니다.
        match = re.search(r"총\s+(\d+)건(?:의|\s)", str(message.content))
        if not match:
            continue
        tool_name = getattr(message, "name", None) or "security_tool"
        for index in range(int(match.group(1))):
            findings.append({"source": tool_name, "index": index + 1})
    return findings


security_agent = create_security_agent()


def security_agent_node(state: SecurityState) -> dict[str, Any]:
    """기존 Tool 호출 방식을 유지한 채 보안 에이전트를 실행합니다."""

    input_messages = state.get("messages", [])
    # file_path가 사용자 문장에 없더라도 에이전트가 검증된 대상만 분석하게 합니다.
    agent_messages = [
        *input_messages,
        HumanMessage(
            content=f"분석 대상 파일의 검증된 절대 경로는 다음과 같습니다: {state['file_path']}"
        ),
    ]
    try:
        result = security_agent.invoke({"messages": agent_messages})
    except Exception as exc:
        raise RuntimeError("Security Agent 실행 중 오류가 발생했습니다.") from exc

    result_messages: list[AnyMessage] = result.get("messages", [])
    return {
        "messages": result_messages[len(agent_messages):],
        "findings": _extract_findings(result_messages),
    }


def create_security_graph() -> Any:
    """모든 미들웨어와 Security Agent를 순서대로 연결합니다."""

    builder = StateGraph(SecurityState)
    builder.add_node("request_logging", request_logging_middleware)
    builder.add_node("input_validation", input_validation_middleware)
    builder.add_node("security_agent", security_agent_node)
    builder.add_node("risk_assessment", risk_assessment_middleware)
    builder.add_node("response", response_middleware)
    builder.add_edge(START, "request_logging")
    builder.add_edge("request_logging", "input_validation")
    builder.add_edge("input_validation", "security_agent")
    builder.add_edge("security_agent", "risk_assessment")
    builder.add_edge("risk_assessment", "response")
    builder.add_edge("response", END)
    return builder.compile()


# LangGraph Studio에서 사용할 미들웨어 포함 그래프 내보내기
agent = create_security_graph()
