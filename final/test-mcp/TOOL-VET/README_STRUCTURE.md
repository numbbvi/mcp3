# TOOL-VET 구조 및 실행 흐름

## 전체 구조

TOOL-VET은 MCP 서버의 보안 취약점을 분석하는 도구입니다.

## 실행 흐름

### 1. 진입점: `main.py`
- `dast.orchestrator.main()` 호출

### 2. 오케스트레이터: `dast/orchestrator.py`
- **저장소 클론**: GitHub URL에서 저장소를 임시 디렉토리에 클론
- **런타임 감지**: `auto.runtime.detect_runtime()` - Go 또는 npm 프로젝트 자동 감지
- **의존성 설치**: `npm install` 또는 `go mod download`
- **MCP 서버 실행**: `start_mcp_server()` - sandbox 환경에서 MCP 서버 프로세스 시작
- **프록시 실행**: `start_mitmdump()` - HTTP 요청을 캡처하기 위한 프록시

### 3. tools/list 호출: `harness/`
- **HTTP 서버인 경우**: `harness/http_harness.run_http_harness()`
  - `HTTPMCPClient` 사용
  - `{http_url}/mcp`로 JSON-RPC 요청
- **내장 서버인 경우**: `harness/builtin.run_builtin_harness()`
  - `MCPClient` 사용
  - 프로세스 stdin/stdout으로 JSON-RPC 통신

### 4. 취약점 스캔: `scanner/`
- `scanner.mcp_specific.scan_mcp_specific()` - MCP 특화 취약점 검사
- `scanner.mcp_verifier.verify_mcp_vulnerability()` - 실제 HTTP 요청으로 검증

### 5. 리포트 생성: `report/`
- `report.curl_generator.generate_curl_from_api()` - API 호출을 curl 명령어로 변환
- JSON 리포트 파일 생성

## 주요 특징

1. **Sandbox 실행**: MCP 서버를 임시 디렉토리에서 실행하여 안전하게 테스트
2. **자동 감지**: Go 또는 npm 프로젝트를 자동으로 감지하고 실행 명령 생성
3. **프록시 캡처**: mitmdump를 통해 MCP 서버의 HTTP 요청을 캡처
4. **Docker 컨테이너**: `mcp-vetting` 컨테이너 내부에서 실행

## 문제 해결

### tools/list 실패 원인
1. MCP 서버가 시작되지 않음
2. MCP 서버가 시작 후 즉시 종료됨
3. JSON-RPC 통신 실패 (타임아웃, 프로토콜 오류)
4. 환경 변수 누락 (API 키 등)

