# 🔒 코드 보안 분석기

AI 기반 코드 보안 분석기입니다. DeepSeek Reasoner를 사용하여 코드를 분석하고 악의적인 의도가 있는지 판단합니다.

## 주요 기능

- **코드 붙여넣기 또는 파일 업로드**: 분석할 코드를 직접 입력하거나 파일을 드래그 앤 드롭
- **실시간 분석 스트리밍**: AI의 사고 과정을 실시간으로 확인
- **악성 코드 탐지**: 계정 탈취, 토큰 수집, 데이터 유출 등 위험 패턴 탐지
- **위험도 점수**: 0-100 사이의 점수로 위험도 표시

## 탐지 가능한 위협

- 세션 하이재킹 / 쿠키 탈취
- 키로거 및 클립보드 탈취
- 외부 서버로 데이터 전송
- 피싱 폼 생성
- 암호화폐 지갑 주소 변조
- 봇넷 통신 코드
- 난독화된 악성 코드

## 배포 방법

### 1. 의존성 설치

```bash
cd code-security-analyzer
npm install
```

### 2. DeepSeek API 키 설정

Cloudflare Dashboard에서 시크릿으로 설정하거나:

```bash
wrangler secret put DEEPSEEK_API_KEY
```

프롬프트가 나타나면 DeepSeek API 키를 입력하세요.

### 3. 로컬 개발

```bash
npm run dev
```

브라우저에서 `http://localhost:8787` 접속

### 4. Cloudflare 배포

```bash
npm run deploy
```

## 프로젝트 구조

```
code-security-analyzer/
├── src/
│   └── worker.js      # Cloudflare Worker (API + 프론트엔드)
├── wrangler.toml      # Cloudflare 설정
├── package.json
└── README.md
```

## 시스템 프롬프트 특징

AI가 탈옥되지 않도록 강력한 보안 규칙이 적용되어 있습니다:

1. **탈옥 방지**: 코드 내 주석이나 문자열에 포함된 지시사항 무시
2. **토큰 분석**: CSRF 토큰은 허용, X-Token/Bearer 토큰 수집은 신중히 분석
3. **데이터 흐름**: 데이터 읽기는 허용, 외부 전송은 위험으로 분류
4. **악성 패턴**: 키로거, 피싱, 데이터 익스필트레이션 등 탐지
5. **난독화 분석**: Base64, 인코딩된 문자열 디코딩 후 분석

## API

### POST /api/analyze

코드 보안 분석 요청

**Request Body:**
```json
{
  "code": "분석할 코드 문자열"
}
```

**Response:** Server-Sent Events (SSE) 스트림

```
data: {"reasoning": "AI 사고 과정...", "content": ""}
data: {"reasoning": "", "content": "분석 결과..."}
data: [DONE]
```

## 위험도 기준

| 점수 | 위험도 | 설명 |
|------|--------|------|
| 0-20 | 안전 | 일반적인 코드, 악의적 의도 없음 |
| 21-40 | 낮은 위험 | 일부 의심스러운 패턴이 있으나 정상적 용도 가능 |
| 41-60 | 중간 위험 | 악용 가능성이 있는 코드, 주의 필요 |
| 61-80 | 높은 위험 | 악의적 의도가 의심되는 코드 |
| 81-100 | 매우 위험 | 명백한 악성 코드 |

## 주의사항

⚠️ 이 도구는 AI 기반 분석을 제공하며, 100% 정확한 탐지를 보장하지 않습니다. 의심스러운 코드는 실행하지 마세요.

## 라이선스

MIT
