# Keycloak SSO 실습

Keycloak 하나로 두 웹 서비스(A: TeamBoard 팀 게시판, B: PlanIt 일정 캘린더)에 SSO를 적용한 과제 프로젝트입니다.

| 구성 요소 | 주소 | 역할 |
|---|---|---|
| Keycloak 26.8.2 (Docker) | http://localhost:8080 | 인증 서버 (Realm `sso-lab`) |
| 서비스 A · TeamBoard | http://localhost:3001 | 카테고리별 게시글, 검색, 댓글. 작성자만 수정·삭제 |
| 서비스 B · PlanIt | http://localhost:3002 | 월간 달력, 일정 등록·수정·삭제, 다가오는 일정. 토큰 분석·ECDSA 검증 도구 |

두 서비스 모두 SQLite(`data.db`, 첫 실행 시 자동 생성)에 데이터를 저장하고, 모든 폼 요청에 CSRF 토큰을 검사합니다.

## 실행 방법 (Windows PowerShell)

```powershell
# 1. Keycloak
docker compose up -d

# 2. Python 가상환경 (프로젝트 루트에서 1회)
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt

# 3. 각 서비스의 .env 작성 (.env.example 복사 후 값 채우기)
copy service-a\.env.example service-a\.env
copy service-b\.env.example service-b\.env

# 4. 서비스 실행 (터미널 2개)
.venv\Scripts\python service-a\app.py
.venv\Scripts\python service-b\app.py
```

## 인증 흐름

- 로그인: Authorization Code Flow + PKCE(S256)
- 로그아웃: Keycloak `end_session_endpoint` 호출(RP-initiated logout) + 다른 서비스는 백채널 로그아웃(`/backchannel-logout`)으로 세션 삭제
- 토큰은 서버 메모리에만 저장하고, 브라우저 쿠키에는 로컬 세션 ID만 저장

## 가점: ECDSA(ES256) 직접 검증

- Keycloak 토큰 서명을 ES256(ECDSA, NIST P-256)으로 설정
- `service-b/ecdsa_manual.py`: 외부 암호 라이브러리 없이 확장 유클리드 알고리즘, 타원곡선 점 덧셈·2배·스칼라 곱, ECDSA 검증 수식을 직접 구현
- 서비스 B `/ecdsa` 화면 (세션 정보 → 보안 도구): 직접 검증 결과, PyJWT 검증 결과, 변조 토큰 검증 결과를 비교하고 중간 계산값(H(m), w, u1, u2, X)을 표시
