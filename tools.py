from langchain.tools import tool
import os
import re


# ============================================
# 공통 설정
# ============================================

MAX_FILE_SIZE = 1_000_000  # 1 MB


def _read_text_file(file_path: str) -> tuple[str | None, str | None]:
    """내부에서 공통으로 사용하는 안전한 파일 읽기 함수."""

    if not os.path.exists(file_path):
        return None, f"오류: 파일을 찾을 수 없습니다: {file_path}"

    if not os.path.isfile(file_path):
        return None, f"오류: 파일이 아닙니다: {file_path}"

    try:
        size = os.path.getsize(file_path)

        if size > MAX_FILE_SIZE:
            return None, (
                f"오류: 파일 크기가 너무 큽니다: {size} bytes "
                f"(최대 {MAX_FILE_SIZE} bytes)"
            )

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as f:
            return f.read(), None

    except PermissionError:
        return None, (
            f"오류: 파일에 대한 읽기 권한이 없습니다: {file_path}"
        )

    except Exception as e:
        return None, f"오류: {str(e)}"


# ============================================
# 1. 파일 읽기 도구
# ============================================

@tool(parse_docstring=True)
def read_file(file_path: str) -> str:
    """보안 분석 대상 파일의 내용을 읽습니다.

    Args:
        file_path: 읽을 파일의 상대 경로 또는 절대 경로.

    Returns:
        파일 내용 또는 오류 메시지.
    """

    content, error = _read_text_file(file_path)

    if error:
        return error

    line_count = len(content.splitlines())

    return (
        f"파일: {file_path}\n"
        f"총 {line_count}줄\n\n"
        f"{content}"
    )


# ============================================
# 2. 디렉터리 조회 도구
# ============================================

@tool(parse_docstring=True)
def list_directory(dir_path: str = ".") -> str:
    """보안 분석을 위해 디렉터리의 파일과 하위 폴더를 조회합니다.

    Args:
        dir_path: 조회할 디렉터리 경로. 기본값은 현재 디렉터리입니다.

    Returns:
        파일 및 폴더 목록 또는 오류 메시지.
    """

    try:
        if not os.path.exists(dir_path):
            return (
                f"오류: 디렉터리를 찾을 수 없습니다: {dir_path}"
            )

        if not os.path.isdir(dir_path):
            return (
                f"오류: 디렉터리가 아닙니다: {dir_path}"
            )

        folders = []
        files = []

        for item in sorted(os.listdir(dir_path)):
            item_path = os.path.join(dir_path, item)

            if os.path.isdir(item_path):
                folders.append(f"[폴더] {item}/")

            else:
                try:
                    size = os.path.getsize(item_path)
                    files.append(
                        f"[파일] {item} ({size} bytes)"
                    )

                except OSError:
                    files.append(
                        f"[파일] {item} (크기 확인 불가)"
                    )

        if not folders and not files:
            return (
                f"디렉터리가 비어있습니다: {dir_path}"
            )

        result = [
            f"디렉터리: {dir_path}"
        ]

        if folders:
            result.append(
                "\n폴더:\n" + "\n".join(folders)
            )

        if files:
            result.append(
                "\n파일:\n" + "\n".join(files)
            )

        return "\n".join(result)

    except PermissionError:
        return (
            f"오류: 디렉터리에 대한 읽기 권한이 없습니다: "
            f"{dir_path}"
        )

    except Exception as e:
        return f"오류: {str(e)}"


# ============================================
# 3. 민감정보 패턴
# ============================================

SENSITIVE_PATTERNS = {

    "OpenAI API Key": re.compile(
        r"\bsk-[A-Za-z0-9_-]{20,}\b"
    ),

    "AWS Access Key": re.compile(
        r"\bAKIA[0-9A-Z]{16}\b"
    ),

    "Private Key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),

    "JWT": re.compile(
        r"\beyJ[A-Za-z0-9_-]+\."
        r"[A-Za-z0-9_-]+\."
        r"[A-Za-z0-9_-]+\b"
    ),

    "비밀번호 하드코딩": re.compile(
        r"""(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*["'][^"']+["']"""
    ),

    "Secret 하드코딩": re.compile(
        r"""(?i)\b(?:secret|api_key|apikey|access_token|auth_token)\b\s*[:=]\s*["'][^"']+["']"""
    ),

    "주민등록번호": re.compile(
        r"\b\d{6}-\d{7}\b"
    ),

    "신용카드 형태": re.compile(
        r"\b(?:\d{4}[- ]?){3}\d{4}\b"
    ),
}


# ============================================
# 4. 민감정보 탐지 도구
# ============================================

@tool(parse_docstring=True)
def scan_sensitive_information(file_path: str) -> str:
    """파일에서 API Key, 비밀번호, 토큰 등 민감정보 노출 패턴을 검사합니다.

    실제 민감값은 출력하지 않고 탐지 유형과 줄 번호만 반환합니다.

    Args:
        file_path: 민감정보 노출 여부를 검사할 파일 경로.

    Returns:
        탐지된 민감정보 유형과 줄 번호 또는 안전 메시지.
    """

    content, error = _read_text_file(file_path)

    if error:
        return error

    findings = []

    for line_number, line in enumerate(
        content.splitlines(),
        start=1
    ):

        for pattern_name, pattern in (
            SENSITIVE_PATTERNS.items()
        ):

            if pattern.search(line):

                findings.append(
                    (
                        line_number,
                        pattern_name
                    )
                )

    if not findings:
        return (
            "민감정보 점검 완료: "
            "의심 패턴이 발견되지 않았습니다.\n"
            f"파일: {file_path}"
        )

    result = [
        "민감정보 점검 결과",
        f"파일: {file_path}",
        f"총 {len(findings)}건의 의심 패턴 발견",
        "",
    ]

    for line_number, pattern_name in findings:

        result.append(
            f"- [주의] {pattern_name} "
            f"/ {line_number}줄"
        )

    result.append(
        "\n주의: 정규식 기반 탐지이므로 "
        "오탐 또는 누락 가능성이 있습니다."
    )

    return "\n".join(result)


# ============================================
# 5. 정적 보안 분석 규칙
# ============================================

SECURITY_RULES = [

    {
        "name": "eval 사용",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\beval\s*\("
        ),
        "description": (
            "검증되지 않은 입력이 전달되면 "
            "임의 코드 실행 위험이 있습니다."
        ),
    },

    {
        "name": "exec 사용",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\bexec\s*\("
        ),
        "description": (
            "동적 코드 실행으로 인해 "
            "임의 코드 실행 위험이 있습니다."
        ),
    },

    {
        "name": "os.system 사용",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\bos\.system\s*\("
        ),
        "description": (
            "외부 입력이 포함되면 "
            "OS 명령어 인젝션 위험이 있습니다."
        ),
    },

    {
        "name": "subprocess shell=True",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\bsubprocess\.[A-Za-z_]+\s*"
            r"\([^)]*shell\s*=\s*True"
        ),
        "description": (
            "쉘을 통한 명령 실행은 "
            "명령어 인젝션 위험을 높입니다."
        ),
    },

    {
        "name": "pickle 역직렬화",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\bpickle\.(?:load|loads)\s*\("
        ),
        "description": (
            "신뢰할 수 없는 pickle 데이터의 "
            "역직렬화는 코드 실행으로 이어질 수 있습니다."
        ),
    },

    {
        "name": "TLS 인증서 검증 비활성화",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"\bverify\s*=\s*False\b"
        ),
        "description": (
            "TLS 인증서 검증을 끄면 "
            "중간자 공격 위험이 증가합니다."
        ),
    },

    {
        "name": "디버그 모드 활성화",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"\bdebug\s*=\s*True\b"
        ),
        "description": (
            "운영 환경의 디버그 모드는 "
            "내부 정보 노출 위험이 있습니다."
        ),
    },

    {
        "name": "yaml.load 사용",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"\byaml\.load\s*\("
        ),
        "description": (
            "신뢰할 수 없는 YAML을 처리한다면 "
            "안전한 로더 사용 여부를 확인해야 합니다."
        ),
    },
]


# ============================================
# 내부용 코드 마스킹
# ============================================

def _safe_snippet(
    line: str,
    max_length: int = 120
) -> str:

    masked = line.strip()

    # 실제 Secret이 결과에 노출되지 않도록 마스킹
    for pattern in SENSITIVE_PATTERNS.values():

        masked = pattern.sub(
            "[REDACTED]",
            masked
        )

    if len(masked) > max_length:

        masked = (
            masked[:max_length]
            + "..."
        )

    return masked


# ============================================
# 6. 정적 보안 분석 도구
# ============================================

@tool(parse_docstring=True)
def static_security_scan(file_path: str) -> str:
    """소스코드의 대표적인 위험 함수와 보안 설정 패턴을 정적으로 검사합니다.

    Args:
        file_path: 정적 보안 분석을 수행할 소스코드 파일 경로.

    Returns:
        발견된 보안 의심 패턴, 심각도, 줄 번호 및 설명.
    """

    content, error = _read_text_file(file_path)

    if error:
        return error

    findings = []

    for line_number, line in enumerate(
        content.splitlines(),
        start=1
    ):

        for rule in SECURITY_RULES:

            if rule["pattern"].search(line):

                findings.append(
                    {
                        "line": line_number,
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "snippet": _safe_snippet(line),
                    }
                )

    if not findings:

        return (
            "정적 보안 점검 완료: "
            "현재 정의된 위험 패턴이 발견되지 않았습니다.\n"
            f"파일: {file_path}\n\n"
            "주의: 간단한 패턴 기반 검사이므로 "
            "전문 SAST 도구를 대체하지 않습니다."
        )

    severity_order = {
        "HIGH": 0,
        "MEDIUM": 1,
        "LOW": 2,
    }

    findings.sort(
        key=lambda item: (
            severity_order.get(
                item["severity"],
                99
            ),
            item["line"],
        )
    )

    result = [
        "정적 보안 점검 결과",
        f"파일: {file_path}",
        f"총 {len(findings)}건 발견",
        "",
    ]

    for finding in findings:

        result.extend(
            [
                (
                    f"[{finding['severity']}] "
                    f"{finding['name']} "
                    f"- {finding['line']}줄"
                ),

                (
                    f"  근거: "
                    f"{finding['snippet']}"
                ),

                (
                    f"  설명: "
                    f"{finding['description']}"
                ),

                "",
            ]
        )

    result.append(
        "주의: 정규식 기반의 1차 점검 결과입니다. "
        "실제 데이터 흐름과 사용자 입력 경로를 "
        "추가로 확인해야 합니다."
    )

    return "\n".join(result)


# ============================================
# 7. 보안 체크리스트 도구
# ============================================

@tool(parse_docstring=True)
def security_checklist(target_type: str) -> str:
    """대상 영역에 맞는 기본 보안 점검 체크리스트를 반환합니다.

    Args:
        target_type: 점검 영역. web, api, python, container, cloud 중 하나.

    Returns:
        선택한 영역의 기본 보안 체크리스트.
    """

    checklists = {

        "web": [
            "입력값 검증 및 출력 인코딩",
            "SQL Injection 방어",
            "XSS 방어",
            "CSRF 방어",
            "인증 및 인가 검증",
            "세션 및 쿠키 보안 설정",
            "파일 업로드 검증",
            "보안 헤더 및 CSP 확인",
        ],

        "api": [
            "인증 및 토큰 검증",
            "객체 단위 인가(BOLA) 확인",
            "Rate Limit 적용",
            "요청 스키마 및 입력값 검증",
            "민감정보 응답 노출 여부",
            "CORS 정책 확인",
            "API Key 및 Secret 관리",
            "감사 로그 기록",
        ],

        "python": [
            "eval/exec 등 동적 코드 실행 확인",
            "subprocess 및 os.system 입력 검증",
            "하드코딩된 Secret 여부",
            "pickle 등 위험한 역직렬화 확인",
            "예외 메시지의 민감정보 노출 여부",
            "의존성 취약점 확인",
            "파일 경로 입력 검증",
        ],

        "container": [
            "root 사용자 실행 여부",
            "privileged 모드 확인",
            "불필요한 Linux Capability 제거",
            "이미지 내 Secret 포함 여부",
            "Base Image 및 패키지 취약점",
            "읽기 전용 파일시스템 검토",
            "네트워크 정책 및 포트 노출",
        ],

        "cloud": [
            "IAM 최소 권한 적용",
            "공개 Storage/Bucket 여부",
            "Security Group/Firewall 규칙",
            "MFA 적용",
            "Secret 및 Access Key 관리",
            "감사 로그 활성화",
            "네트워크 분리",
            "불필요한 외부 공개 서비스 확인",
        ],
    }

    key = target_type.strip().lower()

    if key not in checklists:

        return (
            "지원 영역: "
            "web, api, python, container, cloud"
        )

    items = "\n".join(
        f"{index}. {item}"
        for index, item in enumerate(
            checklists[key],
            start=1
        )
    )

    return (
        f"{key.upper()} 보안 체크리스트\n\n"
        f"{items}"
    )


# ============================================
# 8. 위험도 계산 도구
# ============================================

@tool(parse_docstring=True)
def calculate_risk_score(
    likelihood: int,
    impact: int
) -> str:
    """발생 가능성과 영향도를 이용해 간단한 보안 위험도를 계산합니다.

    Args:
        likelihood: 발생 가능성 점수. 1에서 5 사이의 정수.
        impact: 영향도 점수. 1에서 5 사이의 정수.

    Returns:
        25점 만점 위험 점수와 Low, Medium, High, Critical 등급.
    """

    if not 1 <= likelihood <= 5:

        return (
            "오류: likelihood는 "
            "1~5 사이의 정수여야 합니다."
        )

    if not 1 <= impact <= 5:

        return (
            "오류: impact는 "
            "1~5 사이의 정수여야 합니다."
        )

    score = likelihood * impact

    if score >= 20:
        level = "Critical"

    elif score >= 12:
        level = "High"

    elif score >= 6:
        level = "Medium"

    else:
        level = "Low"

    return (
        "위험도 계산 결과\n"
        f"- 발생 가능성: {likelihood}/5\n"
        f"- 영향도: {impact}/5\n"
        f"- 점수: {score}/25\n"
        f"- 등급: {level}"
    )


# ============================================
# 보안 에이전트 도구 export
# ============================================

CUSTOM_TOOLS = [
    scan_sensitive_information,
    static_security_scan,
    security_checklist,
    calculate_risk_score,
]


FILE_TOOLS = [
    read_file,
    list_directory,
]


SECURITY_TOOLS = (
    FILE_TOOLS
    + CUSTOM_TOOLS
)