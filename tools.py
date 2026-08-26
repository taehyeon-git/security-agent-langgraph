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
        "file_types": {"python", "javascript"},
        "remediation": "eval 대신 허용 목록과 안전한 파서를 사용하세요.",
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
        "file_types": {"python", "javascript"},
        "remediation": "동적 코드 실행을 제거하고 명시적인 함수 호출로 바꾸세요.",
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
        "file_types": {"python"},
        "remediation": "subprocess를 shell=False와 인자 배열 방식으로 호출하세요.",
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
        "file_types": {"python"},
        "remediation": "shell=False를 사용하고 명령과 인자를 리스트로 분리하세요.",
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
        "file_types": {"python"},
        "remediation": "JSON 등 안전한 직렬화 형식을 사용하고 입력의 무결성을 검증하세요.",
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
        "file_types": {"python", "javascript", "yaml", "env"},
        "remediation": "인증서 검증을 활성화하고 신뢰할 CA를 설정하세요.",
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
        "file_types": {"python", "javascript", "yaml", "env"},
        "remediation": "운영 설정에서 디버그 모드를 끄고 환경별 설정을 분리하세요.",
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
        "file_types": {"python"},
        "remediation": "yaml.safe_load를 사용하거나 SafeLoader를 명시하세요.",
    },

    {
        "name": "SQL 문자열 조합",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?i)(?:execute|executemany|query|raw)\s*\([^\n]*(?:f[\"']|\.format\s*\(|%s|\+\s*\w+|\$\{)"
        ),
        "description": "외부 입력이 SQL 문자열에 합쳐지면 SQL Injection으로 이어질 수 있습니다.",
        "file_types": {"python", "javascript"},
        "remediation": "문자열 조합 대신 DB 드라이버의 매개변수 바인딩을 사용하세요.",
    },

    {
        "name": "XSS 위험 DOM 삽입",
        "severity": "HIGH",
        "pattern": re.compile(r"(?i)\.(?:innerHTML|outerHTML)\s*=|document\.write\s*\("),
        "description": "검증되지 않은 값이 HTML로 해석되면 XSS가 발생할 수 있습니다.",
        "file_types": {"javascript"},
        "remediation": "textContent를 사용하거나 검증된 HTML sanitizer로 값을 정화하세요.",
    },

    {
        "name": "XSS 위험 템플릿 렌더링",
        "severity": "HIGH",
        "pattern": re.compile(r"\brender_template_string\s*\("),
        "description": "사용자 입력을 템플릿 문자열로 렌더링하면 XSS나 템플릿 인젝션 위험이 있습니다.",
        "file_types": {"python"},
        "remediation": "고정된 템플릿 파일과 자동 이스케이프를 사용하세요.",
    },

    {
        "name": "경로 조작 가능 입력",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?i)(?:open|send_file|send_from_directory|path\.(?:join|resolve))\s*\([^\n]*(?:request|params|query|body|argv|input)"
        ),
        "description": "외부 입력이 파일 경로에 직접 사용되면 상위 경로 탈출이나 임의 파일 접근 위험이 있습니다.",
        "file_types": {"python", "javascript"},
        "remediation": "기준 디렉터리로 정규화한 뒤 결과 경로가 그 내부인지 확인하고 파일명 허용 목록을 적용하세요.",
    },

    {
        "name": "SSRF 가능 외부 URL 요청",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?i)(?:requests\.(?:get|post|put|delete|request)|httpx\.(?:get|post|request)|fetch|axios\.(?:get|post)|urllib\.request\.urlopen)\s*\([^\n]*(?:request|params|query|body|url)"
        ),
        "description": "사용자가 제어하는 URL로 서버가 요청하면 내부망 또는 메타데이터 서비스가 노출될 수 있습니다.",
        "file_types": {"python", "javascript"},
        "remediation": "허용된 스킴·호스트·포트만 통과시키고 사설/루프백 IP와 리다이렉트를 차단하세요.",
    },

    {
        "name": "과도한 CORS 허용",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"(?i)(?:allow_origins|allowedOrigins|cors_origins|access-control-allow-origin)\s*[:=]\s*(?:[\"']\*[\"']|\[\s*[\"']\*[\"']\s*\])"
        ),
        "description": "모든 출처를 허용하는 CORS 정책은 의도하지 않은 웹 사이트의 접근을 허용할 수 있습니다.",
        "file_types": {"python", "javascript", "yaml", "env"},
        "remediation": "신뢰할 수 있는 출처를 명시적으로 나열하고 credentials 사용 여부를 함께 검토하세요.",
    },

    {
        "name": "컨테이너 privileged 모드",
        "severity": "HIGH",
        "pattern": re.compile(r"(?i)^\s*privileged\s*:\s*true\b"),
        "description": "privileged 컨테이너는 호스트에 광범위한 권한을 가집니다.",
        "file_types": {"yaml"},
        "remediation": "privileged를 끄고 필요한 capability만 선택적으로 추가하세요.",
    },

    {
        "name": "Docker root 사용자",
        "severity": "MEDIUM",
        "pattern": re.compile(r"(?i)^\s*USER\s+(?:root|0)\s*$"),
        "description": "컨테이너가 root 권한으로 실행되면 침해 시 영향이 커집니다.",
        "file_types": {"dockerfile"},
        "remediation": "전용 비권한 사용자를 만들고 USER 지시문으로 전환하세요.",
    },

    {
        "name": "Docker curl 파이프 실행",
        "severity": "HIGH",
        "pattern": re.compile(r"(?i)\b(?:curl|wget)\b[^|]*\|\s*(?:sh|bash)\b"),
        "description": "원격 스크립트를 검증 없이 셸로 실행하면 공급망 공격에 노출될 수 있습니다.",
        "file_types": {"dockerfile"},
        "remediation": "파일을 먼저 내려받아 고정된 체크섬이나 서명을 검증한 뒤 실행하세요.",
    },

    {
        "name": "환경 설정의 전체 CORS 허용",
        "severity": "MEDIUM",
        "pattern": re.compile(r"(?i)^\s*(?:CORS_ORIGINS|ALLOWED_ORIGINS)\s*=\s*\*\s*$"),
        "description": "환경 설정에서 모든 출처를 허용하고 있습니다.",
        "file_types": {"env"},
        "remediation": "쉼표로 구분된 신뢰 출처 목록을 환경별로 지정하세요.",
    },
]


FILE_TYPE_STRATEGIES = {
    "python": "Python 함수 호출, 웹 프레임워크, 역직렬화 및 명령 실행 규칙",
    "javascript": "JavaScript/TypeScript DOM, 네트워크 요청, 명령 실행 및 SQL 규칙",
    "yaml": "YAML 인프라·컨테이너 설정과 권한/CORS 규칙",
    "dockerfile": "Docker 이미지 빌드, 사용자 권한 및 원격 스크립트 실행 규칙",
    "env": ".env 운영 설정, 민감정보 및 보안 옵션 규칙",
    "generic": "파일 형식을 특정할 수 없어 공통 보안 규칙만 적용",
}


def _detect_file_type(file_path: str) -> str:
    """파일 이름과 확장자를 이용해 적용할 분석 전략을 선택합니다."""

    name = os.path.basename(file_path).lower()
    extension = os.path.splitext(name)[1]

    if name == "dockerfile" or name.startswith("dockerfile."):
        return "dockerfile"
    if name == ".env" or name.startswith(".env."):
        return "env"
    if extension == ".py":
        return "python"
    if extension in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        return "javascript"
    if extension in {".yaml", ".yml"}:
        return "yaml"
    return "generic"


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
    """파일 형식에 맞는 취약 패턴을 선택해 정적으로 검사합니다.

    Args:
        file_path: 정적 보안 분석을 수행할 소스코드 파일 경로.

    Returns:
        발견된 보안 의심 패턴, 심각도, 줄·열 번호, 코드 근거 및 수정 안내.
    """

    content, error = _read_text_file(file_path)

    if error:
        return error

    file_type = _detect_file_type(file_path)
    lines = content.splitlines()
    findings = []

    for line_number, line in enumerate(
        lines,
        start=1
    ):

        for rule in SECURITY_RULES:

            supported_types = rule.get("file_types")

            if (
                file_type == "generic"
                and supported_types
            ):
                continue

            if (
                file_type != "generic"
                and supported_types
                and file_type not in supported_types
            ):
                continue

            match = rule["pattern"].search(line)

            if match:

                findings.append(
                    {
                        "line": line_number,
                        "column": match.start() + 1,
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "remediation": rule["remediation"],
                        "context_start": max(1, line_number - 1),
                        "context_end": min(len(lines), line_number + 1),
                    }
                )

    if not findings:

        return (
            "정적 보안 점검 완료: "
            "현재 정의된 위험 패턴이 발견되지 않았습니다.\n"
            f"파일: {file_path}\n"
            f"분석 형식: {file_type}\n"
            f"적용 전략: {FILE_TYPE_STRATEGIES[file_type]}\n\n"
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
        f"분석 형식: {file_type}",
        f"적용 전략: {FILE_TYPE_STRATEGIES[file_type]}",
        f"총 {len(findings)}건 발견",
        "",
    ]

    for finding in findings:

        result.extend(
            [
                (
                    f"[{finding['severity']}] "
                    f"{finding['name']} "
                    f"- {finding['line']}줄 "
                    f"{finding['column']}열"
                ),
                (
                    f"  설명: "
                    f"{finding['description']}"
                ),
            ]
        )

        result.append("  코드 근거:")

        for context_line_number in range(
            finding["context_start"],
            finding["context_end"] + 1,
        ):
            marker = ">" if context_line_number == finding["line"] else " "
            snippet = _safe_snippet(lines[context_line_number - 1])
            result.append(
                f"  {marker} {context_line_number:4} | {snippet}"
            )

        result.extend(
            [
                f"  수정 안내: {finding['remediation']}",
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
