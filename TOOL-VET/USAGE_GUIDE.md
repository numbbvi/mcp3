# TOOL-VET 사용 가이드

## 개요

TOOL-VET은 MCP (Model Context Protocol) 서버의 보안 취약점을 자동으로 분석하는 도구입니다. GitHub 저장소를 클론하고, MCP 서버를 sandbox 환경에서 실행한 후, `tools/list`와 `tools/call`을 통해 취약점을 검사합니다.

## 아키텍처

### 디렉토리 구조

```
TOOL-VET/
├── main.py                 # 진입점
├── dast/
│   ├── orchestrator.py    # 메인 오케스트레이터 (전체 흐름 제어)
│   ├── utils.py           # 유틸리티 함수 (저장소 클론 등)
│   ├── mitm.py            # mitmproxy CA 인증서 처리
│   └── proxy_logger.py    # 프록시 로그 수집
├── auto/
│   └── runtime.py         # 런타임 자동 감지 (Go/npm)
├── harness/
│   ├── builtin.py         # stdio 기반 MCP 클라이언트
│   ├── http_client.py     # HTTP 기반 MCP 클라이언트
│   └── http_harness.py    # HTTP 하네스 실행
├── scanner/
│   ├── mcp_specific.py    # MCP 특화 취약점 스캔
│   └── mcp_verifier.py    # 취약점 검증
├── extractor/
│   ├── openapi_extractor.py  # OpenAPI 스펙에서 API 추출
│   └── graphql_extractor.py # GraphQL 스키마에서 API 추출
└── report/
    └── curl_generator.py  # API 호출을 curl 명령어로 변환
```

## 실행 흐름

### 1. 진입점: `main.py`
```python
from dast.orchestrator import main
main()  # orchestrator.py의 main() 함수 호출
```

### 2. 오케스트레이터: `dast/orchestrator.py`

#### 2.1 인자 파싱
```python
--git-url: MCP 서버 GitHub URL (필수)
--output-dir: 결과 저장 디렉터리 (기본값: ./output)
--env-file: 환경변수 파일 경로 (기본값: .env)
--auto: 런타임 자동 감지 (기본값: True)
```

#### 2.2 실행 단계

**Step 1: 저장소 클론**
- `clone_repository()`: GitHub URL에서 저장소를 임시 디렉토리에 클론
- `extract_repo_name()`: 저장소 이름 추출

**Step 2: 런타임 감지**
- `detect_runtime()`: 저장소에서 Go 또는 npm 프로젝트 자동 감지
  - Go: `go.mod` 파일 존재 확인
  - npm: `package.json` 파일 존재 확인
- `RuntimePlan` 생성:
  - `install_steps`: 의존성 설치 명령어 (`npm install`, `go mod download`)
  - `server_command`: MCP 서버 실행 명령어
  - `transport_type`: "stdio" 또는 "http"
  - `http_url`: HTTP transport인 경우 URL

**Step 3: 의존성 설치**
- `run_command()`: `install_steps` 실행
  - npm: `npm install`, `npm run build` (있는 경우)
  - Go: `go mod download`

**Step 4: 프록시 시작**
- `start_mitmdump()`: mitmdump 실행 (HTTP 요청 캡처용)
- 포트 8081-8090 중 사용 가능한 포트 선택
- 프록시 로그를 JSONL 형식으로 저장

**Step 5: MCP 서버 실행**
- `start_mcp_server()`: sandbox 환경에서 MCP 서버 프로세스 시작
- 환경 변수 설정:
  - `HTTP_PROXY`, `HTTPS_PROXY`: mitmdump 프록시 URL
  - `.env` 파일의 환경 변수들 (API 키 등)
  - SSL 인증서 경로 (mitmproxy CA)
- HTTP 서버인 경우: 백그라운드 실행, health check 수행
- stdio 서버인 경우: stdin/stdout 파이프로 통신

**Step 6: tools/list 호출**
- HTTP 서버: `run_http_harness()` → `HTTPMCPClient`
  - `{http_url}/mcp`로 JSON-RPC 요청
- stdio 서버: `run_builtin_harness()` → `MCPClient`
  - 프로세스 stdin/stdout으로 JSON-RPC 통신
- `initialize()` → `list_tools()` → 각 tool에 대해 `call_tool()` 호출

**Step 7: API 추출**
- OpenAPI 스펙 파일에서 API 추출 (`extract_apis_from_openapi()`)
- GraphQL 스키마에서 API 추출 (`extract_operations_from_schema()`)
- 프록시 로그에서 실제 HTTP 요청 추출

**Step 8: 취약점 스캔**
- `scan_mcp_specific()`: MCP 특화 취약점 검사
- `verify_mcp_vulnerability()`: 실제 HTTP 요청으로 취약점 검증
- `verify_tool_api_correlation()`: tool과 API의 연관성 검증

**Step 9: 리포트 생성**
- `generate_curl_from_api()`: API 호출을 curl 명령어로 변환
- JSON 리포트 파일 생성: `{repo_name}-report.json`

## 사용 방법

### Docker 컨테이너에서 실행

```bash
# 1. 컨테이너 빌드 및 시작
cd final/test-mcp/TOOL-VET
docker-compose up -d --build

# 2. 컨테이너 내부에서 실행
docker exec -it mcp-vetting python main.py \
  --git-url https://github.com/modelcontextprotocol/servers \
  --output-dir /app/output \
  --env-file /app/temp_env/.env \
  --auto
```

### 백엔드에서 실행 (riskAssessmentController.js)

```javascript
const toolVetArgs = [
  'exec', TOOL_VET_CONTAINER_NAME,
  'python', 'main.py',
  '--git-url', github_url,
  '--output-dir', '/app/output',
  '--env-file', containerEnvPath,  // 선택적
  '--auto'
];
const toolVetProcess = spawn('docker', toolVetArgs, { cwd: TOOL_VET_ROOT });
```

## 주요 컴포넌트 상세

### 1. 런타임 감지 (`auto/runtime.py`)

**Go 프로젝트 감지:**
- `go.mod` 파일 존재 확인
- `server_command` 생성:
  - `go run ./cmd/server stdio` (일반적인 경우)
  - `go run . stdio` (main.go가 루트에 있는 경우)
  - `go run ./... stdio` (기타)

**npm 프로젝트 감지:**
- `package.json` 파일 존재 확인
- `server_command` 생성:
  - `npm run start` (scripts.start가 있는 경우)
  - `npx --yes {package_name}` (bin이 있는 경우)
  - `node {main_file}` (main 필드가 있는 경우)
- HTTP transport 감지:
  - package 이름이나 description에 "http" 포함
  - `--transport http` 옵션 사용

### 2. MCP 클라이언트 (`harness/`)

**stdio 클라이언트 (`builtin.py`):**
- `MCPClient` 클래스: 프로세스 stdin/stdout으로 JSON-RPC 통신
- `initialize()`: MCP 프로토콜 초기화
- `list_tools()`: `tools/list` 호출
- `call_tool()`: `tools/call` 호출

**HTTP 클라이언트 (`http_client.py`):**
- `HTTPMCPClient` 클래스: HTTP JSON-RPC 통신
- `{base_url}/mcp` 엔드포인트로 POST 요청
- 세션 ID 관리

### 3. 취약점 스캐너 (`scanner/`)

**MCP 특화 스캔 (`mcp_specific.py`):**
- tool의 inputSchema 분석
- API 엔드포인트 패턴 매칭
- 인증/인가 취약점 검사

**취약점 검증 (`mcp_verifier.py`):**
- 실제 HTTP 요청으로 취약점 재현
- tool과 API의 연관성 검증

### 4. API 추출기 (`extractor/`)

**OpenAPI 추출 (`openapi_extractor.py`):**
- OpenAPI 스펙 파일 찾기
- 경로 및 메서드 추출
- 스키마 분석

**GraphQL 추출 (`graphql_extractor.py`):**
- GraphQL 엔드포인트 감지
- 스키마 인트로스펙션
- 쿼리/뮤테이션 추출

## 환경 변수

`.env` 파일에 다음 환경 변수를 설정할 수 있습니다:

```env
# API 키 (MCP 서버에서 필요할 수 있음)
GITHUB_TOKEN=your_token_here
NOTION_TOKEN=your_token_here
OPENAI_API_KEY=your_key_here

# 기타 환경 변수
CUSTOM_VAR=value
```

환경 변수는 MCP 서버 프로세스에 전달됩니다.

## 출력 형식

### 리포트 파일: `{repo_name}-report.json`

```json
{
  "tools": [
    {
      "name": "tool_name",
      "description": "...",
      "inputSchema": {...},
      "api_endpoints": [
        {
          "method": "GET",
          "url": "https://api.example.com/endpoint",
          "vulnerabilities": [...]
        }
      ],
      "harness_result": {
        "success": true,
        "error": null
      }
    }
  ],
  "vulnerabilities": [...],
  "summary": {
    "total_tools": 10,
    "total_endpoints": 5,
    "total_vulnerabilities": 2
  }
}
```

## 문제 해결

### 1. MCP 서버 시작 실패
- **원인**: 의존성 설치 실패, 실행 명령어 오류
- **해결**: 런타임 감지 로직 확인, `server_command` 수정

### 2. tools/list 실패
- **원인**: MCP 서버 프로세스 종료, JSON-RPC 통신 오류
- **해결**: 서버 로그 확인, 타임아웃 증가

### 3. HTTP 서버 health check 실패
- **원인**: 서버 시작 시간 부족, 포트 충돌
- **해결**: 대기 시간 증가, 포트 확인

### 4. 환경 변수 미적용
- **원인**: `.env` 파일 경로 오류, 파일 형식 오류
- **해결**: 절대 경로 사용, 파일 형식 확인

## 확장 가능성

### 새로운 런타임 추가
`auto/runtime.py`에 새로운 `_RuntimeDetector` 클래스 추가:
- `detect()`: 런타임 감지 로직
- `create_plan()`: `RuntimePlan` 생성

### 새로운 취약점 검사 추가
`scanner/mcp_specific.py`에 새로운 검사 로직 추가

### 새로운 API 추출기 추가
`extractor/` 디렉토리에 새로운 추출기 모듈 추가

