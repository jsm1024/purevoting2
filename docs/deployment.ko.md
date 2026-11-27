# PureVoting 2.0 배포·실행 안내

> 기준일 2026-11-24 · 기준 커밋 `18ca1bf`(main) · 범위 결정 D-31 반영(2026-11-27)
>
> 시스템을 빌드하고, 설정하고, 실행하고, 밖에서 접속할 수 있게 여는 방법을 정리했습니다. 시스템이 무엇인지는 `docs/design-proposal.ko.md`를 먼저 보세요.
> 명령과 기본값은 `docker-compose.yml`, `docker-compose.integration.yml`, `.env.example`에서 확인한 것입니다. 확인하지 못한 내용은 **(미확인)** 으로 표시했습니다.
> 이 문서에는 비밀값을 적지 않습니다. `<...>` 표시는 직접 채울 자리입니다.

## 목차

1. 준비물
2. compose 파일과 서비스
3. 포트
4. 환경 변수(`.env`)
5. 처음 설치하는 순서(통합 스택)
6. 시작·중지·상태 확인
7. 개발용 mock 스택
8. 공개 접속(D-29)
9. 시연 진행 순서
10. 문제 해결
11. 데이터와 백업
12. 보안 주의사항

---

## 1. 준비물

| 준비물 | 용도 | 비고 |
|---|---|---|
| Docker Desktop(Compose v2 포함) | 전체 스택 실행 | 리눅스 컨테이너, **amd64 호스트**(체인 바이너리가 linux-amd64 전용) |
| `purechain-geth` `1.13.15-purechain-1.0.1` linux-amd64 바이너리 | 검증 노드 | 저장소에 없음. 원장 담당자의 키트에서 받아 `ledger/bin/purechain-geth`에 둠(`ledger/bin/`은 git에서 제외). `chain-init`이 sha256을 검사 |
| Python 3.11 이상 | 호스트에서 돌리는 스크립트(키 생성, 계약 검증, 시나리오) | 컨테이너 이미지는 Core·규칙 엔진 3.11, 게이트웨이 3.12 |
| Node.js 22.18 이상 | 웹 개발·시험(`web/`)에만 필요 | compose로 실행만 할 때는 불필요(이미지 안에서 빌드) |
| POSIX 셸(Windows는 Git Bash) | `tools/trustees.sh` 실행 | Git Bash는 `/`로 시작하는 인자(`/keys/...`)를 Windows 경로로 바꿀 수 있으므로 `MSYS_NO_PATHCONV=1`을 붙여 실행하기를 권합니다(Windows에서 이 스크립트 자체는 아직 다시 확인하지 않음) |
| Tailscale | 밖에서 접속할 때만(8절) | 무료 Personal 플랜 |

스택은 PC 한 대에서 실행합니다. 클라우드 호스팅은 하지 않습니다(D-29).

---

## 2. compose 파일과 서비스

파일은 둘이고, 통합 스택은 두 파일을 **겹쳐서** 씁니다.

| 실행 방식 | 명령의 파일 지정 | 용도 |
|---|---|---|
| 통합 스택 | `-f docker-compose.yml -f docker-compose.integration.yml` | 실제 체인·게이트웨이·규칙 엔진. 시연과 시험은 이것 |
| mock 스택 | `docker-compose.yml` + `--profile mock` | 체인 없이 Core·웹 개발(7절) |

아래에서는 통합 스택 명령을 줄여 쓰기 위해 다음 변수를 씁니다. 예시는 POSIX 셸(Windows는 Git Bash) 기준이며, PowerShell에서는 `$COMPOSE` 자리에 전체 명령을 그대로 적습니다.

```sh
export COMPOSE="docker compose -f docker-compose.yml -f docker-compose.integration.yml"
```

| 서비스 | 정의된 파일 | 종류 | 하는 일 |
|---|---|---|---|
| `db` | 기본 | 상주 | PostgreSQL 16.4. 첫 시작 때 `core/db/init/`으로 역할·스키마 생성 |
| `core` | 기본(통합에서 설정 덮어씀) | 상주 | Core API. `/readyz`로 준비 상태 확인 |
| `web` | 기본 | 상주 | nginx: 빌드된 웹 + Core `/v1/` + 게이트웨이 읽기 경로 2개. **유일한 공개 입구** |
| `ledger-gateway` | 기본(`mock` 프로필) | 상주 | 가짜 게이트웨이(체인 없음, 서명·키 검사 없음). 통합 스택에서는 같은 이름의 실제 게이트웨이로 바뀜 |
| `chain-init` | 통합 | 1회 | 검증 노드 3개의 계정·genesis·노드 키를 이 PC에서 생성(노드 볼륨 안에만 있음) |
| `node-commission`, `node-observer`, `node-neutral` | 통합 | 상주 | 기관별 검증 노드(Clique, 블록 주기 1초) |
| `contract-build` | 통합 | 1회 | solc 0.8.28로 `PureVotingLedger.sol` 컴파일 |
| `registry-setup` | 통합 | 1회 | 계약 배포(`CONTRACT_ADDRESS`가 비어 있을 때), 세 기관 서명키 등록, 운영 기관·게이트웨이 계정·규칙 엔진 서명키 확인, `.env`에 체인 설정 3개 기록 |
| `staff-setup` | 통합 | 1회 | 선관위 관리자 계정 생성(이미 있으면 그대로 둠) |
| `ledger-gateway` | 통합 | 상주 | 실제 원장 게이트웨이. 중립 기관 노드로 트랜잭션 전송 |
| `rule-engine` | 통합 | 상주 | 규칙 엔진 워커(R1–R5) |

- 기동 순서는 compose의 의존 관계로 강제됩니다: 노드 → 계약 빌드·배포·레지스트리 설정 → 직원 계정 → Core·게이트웨이 → 규칙 엔진.
- 감사 보고서 생성기(`audit-agent`)는 통합 파일에 주석으로만 있습니다(PR #15 병합 뒤 편입 예정).
- mock 스택에는 규칙 엔진이 없습니다.

---

## 3. 포트

모든 호스트 포트는 `127.0.0.1`에만 열립니다. 밖에서 닿는 것은 터널이 넘겨주는 `web` 포트 하나뿐입니다.

| 서비스 | 호스트 포트 변수 | 기본값 | 컨테이너 포트 | 비고 |
|---|---|---|---|---|
| `web` | `WEB_PORT` | 3000 | 8080 | 웹과 API의 입구. 터널이 공개하는 유일한 포트 |
| `core` | `CORE_PORT` | 8000 | 8000 | 로컬 점검용(`/readyz`, `/docs`) |
| `ledger-gateway` | `GATEWAY_PORT` | 8100 | 8100 | 로컬 점검·시나리오 스크립트용 |
| `db` | `POSTGRES_PORT` | 5432 | 5432 | 로컬 전용 |
| `node-commission` | `NODE_RPC_PORT` | 8545 | 8545 | 통합 스택만. 나머지 두 노드는 호스트에 열지 않음 |

- 검증 노드끼리는 고정 주소의 내부 네트워크 `<CHAIN_NET_PREFIX>.0/24`(기본 `172.29.42`)를 씁니다. 호스트에서 이미 쓰는 대역이면 `CHAIN_NET_PREFIX`를 바꿉니다.
- 컨테이너끼리는 서비스 이름과 컨테이너 포트로 통신합니다(예: `http://core:8000`). `*_PORT`는 호스트 쪽 번호만 바꿉니다.
- `.env.example`의 `MAILHOG_UI_PORT`는 현재 어느 서비스도 쓰지 않습니다.

---

## 4. 환경 변수(`.env`)

`.env.example`을 `.env`로 복사해 채웁니다. **`.env`는 커밋하지 않습니다**(`.gitignore`에 들어 있음). 값은 여기에 옮겨 적지 않으며, 아래는 이름과 뜻입니다.

### 4.1 직접 정하는 값

| 변수 | 뜻 | 값의 출처 |
|---|---|---|
| `POSTGRES_DB` | DB 이름(기본 `purevoting`) | 기본값 사용 |
| `POSTGRES_SUPERUSER_PASSWORD` | DB 최고 관리자 비밀번호 | 배포마다 새 무작위 값 |
| `DB_CORE_PASSWORD` | Core의 DB 로그인 역할(`pv2_core`) 비밀번호 | 배포마다 새 무작위 값 |
| `CORE_KEY`, `RULE_KEY`, `AGENT_KEY`, `GATEWAY_KEY` | 서비스 간 호출 키(`X-Service-Key`), 서비스마다 하나 | 배포마다 새 무작위 값 |
| `AUDITOR_KEY` | 게이트웨이 **읽기 전용** 키. 기관의 복호화 검사와 노드 상태 화면이 사용 | 배포마다 새 무작위 값. 기관·감사인에게만 전달 |
| `JWT_SECRET` | 직원 로그인 토큰 서명 비밀값 | 배포마다 새 무작위 값 |
| `STAFF_ADMIN_USERNAME`, `STAFF_ADMIN_PASSWORD` | `staff-setup`이 만드는 선관위 관리자 계정(비밀번호 8자 이상) | 직접 정함 |
| `VOTER_WEB_URL` | 일회용 링크의 앞부분(기본 `http://127.0.0.1:3000`). 공개할 때는 Funnel 주소 | 8절 |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `MAIL_FROM` | 링크 메일 발송(선택). `SMTP_USER`·`SMTP_PASSWORD`가 없으면 아무것도 보내지 않고 CSV만 | 선거 전용 메일 계정의 앱 비밀번호(`docs/roles/core-web.md` 4.4) |

### 4.2 도구가 만들어 주는 값

| 변수 | 뜻 | 만드는 도구 |
|---|---|---|
| `ORG_COMMISSION_SIGNER_KEY`, `ORG_OBSERVER_SIGNER_KEY`, `ORG_NEUTRAL_SIGNER_KEY` | 세 기관의 서명키(체인 레지스트리에 등록) | `ledger/tools/gen_keys.py` |
| `ORG_*_NODE_ACCOUNT_KEY`(3개) | 레지스트리에 쓰는 기관 노드 계정 키 | 〃 |
| `RULE_ENGINE_SIGNER_KEY` | finding 서명키(규칙 엔진만 사용) | 〃 |
| `GATEWAY_ACCOUNT_KEY` | 게이트웨이의 체인 계정 키(게이트웨이만 사용) | 〃 |
| `RULE_ENGINE_CHAIN_ACCOUNT_KEY` | 규칙 엔진의 직접 제출용 계정(선택 경로) | 〃 |
| `CHAIN_ID`, `CONTRACT_ADDRESS`, `PINNED_NODE_URL` | 고정 체인 설정. 모든 서비스가 같은 값을 씀 | `registry-setup`이 `.env`에 기록. 새 체인에서는 `CONTRACT_ADDRESS`를 비워 둠 |

### 4.3 동작을 바꾸는 값(기본값이 있음)

| 변수 | 기본값 | 뜻 |
|---|---|---|
| `CONFIRMATION_DEPTH` | 2 | 확정 깊이 D(D-27). Core·게이트웨이·규칙 엔진이 같은 값을 써야 함 |
| `CREATION_CHECK_MODE` | `node` | 선거 생성 인자를 고정 노드에서 직접 대조. `stub`은 개발 전용 |
| `BALLOT_SCHEME` | `ELGAMAL_ED25519_V1` | 새 선거의 표 방식(D-30). `SEALED_BOX_V1`은 이전 방식으로 되돌릴 때만 |
| `ALL_VOTED_CLOSE` | 통합 `false`, mock `true` | 전원 투표 시 조기 마감 허용(결정 v1.5). 통합 스택에서는 이 버전으로 배포한 계약일 때만 `true` |
| `ANCHOR_BATCH_SECONDS`, `ANCHOR_BATCH_MAX_EVENTS` | 60, 50 | 게이트웨이 배치 크기(D-04, 고정값) |
| `RULE_POLL_SECONDS` | 60 | 규칙 엔진 폴링 주기 |
| `NODE_LIST` | 세 노드 | 게이트웨이 `GET /v1/nodes`가 보여 줄 노드 목록 |
| `PURECHAIN_GETH_BIN`, `PURECHAIN_GETH_SHA256`, `PURECHAIN_CHAIN_ID`, `CHAIN_NET_PREFIX` | `./ledger/bin/purechain-geth`, 고정 해시, 424242, `172.29.42` | 검증 노드 설정 |
| `BOOTSTRAP_RPC_URL`, `BOOTSTRAP_PINNED_NODE_URL` | 선관위 노드 / 참관·선관위 노드 | `registry-setup`이 쓰는 노드와 `PINNED_NODE_URL`에 적을 값 |
| `CHAIN_ENV_FILE` | `./.env` | `registry-setup`이 값을 기록할 파일 |
| `AI_PROVIDER`, `AI_BASE_URL`, `AI_MODEL` | `none` | 감사 보고서 생성기 설정(현재 compose에서 쓰는 서비스 없음) |
| `DEMO_TIME_BUCKET_SECONDS`, `DEMO_CHECKPOINT_INTERVAL_SECONDS` | 60, 60 | 시연 스크립트만 사용 |

`trustee-keys/`의 위치는 `TRUSTEE_KEYS_DIR`(셸 환경 변수, 기본 `./trustee-keys`)로 바꿉니다.

---

## 5. 처음 설치하는 순서(통합 스택)

저장소 루트에서 실행합니다. 근거: `tests/scenarios/T01/README.md`, `docker-compose.integration.yml` 머리말.

### 5.1 설정 파일과 키

```sh
cp .env.example .env                               # 4.1절의 값을 채움
python -I ledger/tools/gen_keys.py --env .env      # 4.2절의 키 9줄 생성(이미 값이 있으면 건드리지 않음)
```

- `ledger/bin/purechain-geth`에 바이너리를 둡니다.
- `.env`의 `CONTRACT_ADDRESS`는 비워 둡니다.
- **`.env`를 저장소 밖 안전한 곳에 백업합니다.** 체인에 등록된 기관 키가 들어 있고, 다음 단계가 이 파일을 제자리에서 고칩니다.

### 5.2 체인 초기화와 레지스트리 설정

```sh
$COMPOSE run --rm registry-setup
```

이 한 줄이 의존 서비스를 차례로 실행합니다: `chain-init`(`tools/chain_init_job.py`) → 검증 노드 3개 → `contract-build` → `registry-setup`(`tools/registry_setup_job.sh`).
끝나면 `.env`에 `CHAIN_ID`, `CONTRACT_ADDRESS`, `PINNED_NODE_URL`이 들어갑니다.

compose는 명령을 시작할 때 `.env`를 한 번만 읽으므로, **이 단계를 따로 먼저 실행해야** 다음 명령의 서비스들이 새 값을 받습니다.
건너뛰면 Core의 `/readyz`가 `chain_config_missing`으로 남습니다.

### 5.3 전체 시작과 직원 계정

```sh
$COMPOSE up -d --build
```

`staff-setup`이 선관위 관리자 계정을 만듭니다. 참관·중립 기관 계정은 직접 만듭니다(계정 API는 없습니다).

```sh
$COMPOSE exec core python -m app.scripts.create_staff --username <참관-계정> --org org_observer --role approver
$COMPOSE exec core python -m app.scripts.create_staff --username <중립-계정> --org org_neutral  --role approver
```

비밀번호는 물어보는 대로 입력하거나 `STAFF_PASSWORD` 환경 변수로 넘깁니다. 명령줄 인자로 적지 마세요.

### 5.4 세 기관의 복호화 열쇠(D-30)

```sh
tools/trustees.sh keygen        # COMPOSE 변수가 위와 같이 설정돼 있어야 함
# Windows Git Bash: MSYS_NO_PATHCONV=1 tools/trustees.sh keygen
```

- 세 기관의 열쇠를 만들어 `trustee-keys/<org_id>.secret.json`(비밀)과 `<org_id>.public.json`(공개 기록)에 두고, 공개 기록을 Core DB에 등록합니다. DB마다 한 번입니다.
- 하지 않으면 선거 생성이 422 `TRUSTEES_NOT_REGISTERED`로 거부됩니다.
- 이 스크립트는 **한 사람이 세 기관을 모두 맡는 시연용**입니다. 실제 배포에서는 기관마다 자기 PC에서 `python -m app.scripts.trustee keygen`을 실행해 비밀 파일을 자기만 보관하고, 공개 기록만 넘겨 `app.scripts.register_trustee`로 등록합니다.
- ElGamal 도입 전에 만든 DB를 계속 쓰려면 `core/db/migrations/001_elgamal.sql`을 한 번 적용합니다(칸과 테이블만 추가).

### 5.5 웹에서 쓰는 열쇠 파일

기관 직원이 웹의 "우리 기관 복호화" 카드에서 고르는 파일은 `<org_id>.web-key.json`입니다. 위의 `<org_id>.secret.json` 내용에 게이트웨이 읽기 키(`AUDITOR_KEY`)를 `gateway_auditor_key` 항목으로 더한 사본이며, 브라우저 안에서만 읽고 서버로 올리지 않습니다.

- 카드에는 읽기 키 입력칸이 없습니다. 키는 이 파일에서 읽습니다. 파일에 키가 없으면, 같은 탭의 "블록체인 노드 상태 보기"에서 먼저 넣은 키를 씁니다. 둘 다 없으면 파일 선택이 거부됩니다.
- 이 사본을 만들어 주는 도구는 저장소에 없습니다. 시연에서는 따로 만든 사본을 썼고, 필요하면 `secret.json` 사본에 항목을 직접 추가합니다 **(절차는 미확인)**. 사본도 비밀 파일과 똑같이 다룹니다.

### 5.6 설치 확인

- `$COMPOSE ps`: 노드 3개, `core`, `ledger-gateway`, `rule-engine`, `web`, `db`가 healthy이고 1회 서비스 4개는 0으로 종료.
- `http://127.0.0.1:8000/readyz`가 `ready`.
- `$COMPOSE logs registry-setup`: 세 기관, operatorOrg, gatewayAccount, ruleEngineSigner가 `ok`.
- `http://127.0.0.1:3000/admin`에서 관리자 로그인.

---

## 6. 시작·중지·상태 확인

| 하려는 일 | 명령 |
|---|---|
| 시작(이미지 그대로) | `$COMPOSE up -d` |
| 코드 변경 뒤 다시 빌드해 시작 | `$COMPOSE up -d --build` |
| 한 서비스만 다시 빌드 | `$COMPOSE up -d --build <서비스>` |
| 상태 | `$COMPOSE ps` |
| 로그 | `$COMPOSE logs -f --tail 100 <서비스>` |
| 잠시 멈춤(데이터 유지) | `$COMPOSE stop` → 다시 `$COMPOSE start` |
| 컨테이너 제거(데이터 유지) | `$COMPOSE down` |
| **모든 데이터 삭제** | `$COMPOSE down -v` — 11절을 먼저 읽을 것 |

- `.env`를 바꾼 뒤에는 해당 서비스를 `up -d`로 다시 만들어야 값이 반영됩니다. `VOTER_WEB_URL`은 Core 시작 전에 정하고, 선거가 열려 있는 동안 바꾸지 않습니다.
- 같은 PC에 스택을 둘 띄우려면 프로젝트 이름(`-p <이름>`), 호스트 포트(`*_PORT`), 노드 대역(`CHAIN_NET_PREFIX`)이 서로 달라야 하고, 각자의 env 파일(`--env-file`, `CHAIN_ENV_FILE`)을 써야 합니다.

자동 시험(스택 없이 실행, 각 줄은 저장소 루트에서 따로 실행):

```sh
pip install -r tools/requirements.txt && python tools/validate_contracts.py     # 계약 검증
(cd core && pip install -r requirements-dev.txt && pytest -q)                   # Core
python -m pip install -r rules/requirements-lock.txt && python -m pytest -q -c rules/pytest.ini rules/tests   # 규칙 엔진(루트에서)
(cd web && npm ci && npm test)                                                  # 웹
```

---

## 7. 개발용 mock 스택

체인 없이 Core와 웹만 빠르게 띄울 때 씁니다(`core/README.md`).

```sh
docker compose --profile mock up --build
docker compose exec core python -m app.scripts.create_staff --username <계정> --org org_commission --role admin
COMPOSE="docker compose" tools/trustees.sh keygen      # 복호화 열쇠(ElGamal 선거를 만들려면 필요)
```

- `.env`에 `PINNED_NODE_URL=http://ledger-gateway:8100/rpc`와 0이 아닌 임의의 `CONTRACT_ADDRESS`가 있어야 Core가 준비 상태가 됩니다(부트스트랩 작업이 없음).
- 가짜 게이트웨이는 서명도 키도 검사하지 않고, 규칙 엔진이 없어 finding이 생기지 않습니다. 감사·확정 조건의 검증에는 쓸 수 없습니다.
- **mock 스택에서는 Funnel을 켜지 않습니다**(읽기 경로가 키 없이 열림).
- 웹만 개발할 때는 `cd web && npm install && npm run dev`(메모리 안의 가짜 API), 실제 Core에 붙이려면 `VITE_API_MODE=real npm run dev`.

---

## 8. 공개 접속(D-29)

### 8.1 원칙

- 밖에서 닿는 것은 compose의 `web`(nginx) **하나뿐**입니다. `127.0.0.1:${WEB_PORT}`에 열리고 터널이 이 포트만 넘겨줍니다.
- 입구가 통과시키는 것: 웹 화면, Core `/v1/`, 게이트웨이 읽기 2개(`GET /ledger/v1/events`, `GET /ledger/v1/nodes` — 호출자가 보낸 읽기 전용 키를 그대로 전달하고, 키가 틀리면 게이트웨이가 401).
- 막는 것: `/internal/v1/*`, API 문서, 상태 확인 경로(404), `..`이나 인코딩된 경로 문자(400). DB·Core·게이트웨이·노드 포트는 터널에 연결되지 않습니다.
- 사이트 전체 요청 제한: 로그인 분당 30회, redeem·투표·선거 조회 초당 20회, 영수증 조회 초당 30회, 원장 읽기 초당 5회. 넘으면 429와 `Retry-After`를 받습니다.
- 입구는 요청 로그를 남기지 않습니다(정확한 시각이 익명성 장치를 무력화하기 때문).

### 8.2 Tailscale Funnel로 열기

1. 호스트에 Tailscale을 설치하고 로그인합니다(Windows는 관리자 계정에서). 관리 콘솔에서 MagicDNS와 HTTPS 인증서를 켜고, CLI가 물으면 Funnel을 허용합니다. `tailscale version`을 기록해 둡니다.
2. 엽니다. 공개 DNS 반영에 최대 10분쯤 걸리므로 미리 켭니다.
   ```sh
   tailscale funnel --bg 3000      # 누구나 접속. 팀원끼리만이면: tailscale serve --bg 3000
   tailscale funnel status
   ```
   주소는 `https://<your-tailnet-host>` 형태로 고정됩니다. Funnel이 쓸 수 있는 포트는 443, 8443, 10000입니다.
3. `.env`의 `VOTER_WEB_URL`을 그 주소로 바꾸고 Core를 다시 시작한 뒤 링크를 발급합니다. **순서: Funnel 켜기 → `VOTER_WEB_URL` → Core 시작 → 링크 발급.**
4. 끝나면 반드시 끕니다. `--bg` 설정은 재부팅 뒤에도 남습니다.
   ```sh
   tailscale funnel reset          # serve를 썼다면 tailscale serve reset
   tailscale funnel status         # 아무것도 없어야 함
   ```

주의:

- **Funnel은 필요한 동안만 켭니다.** 공개 주소에서는 시연용 키와 가짜 명단만 씁니다.
- 선거가 열려 있는 동안 주소가 바뀌면 안 됩니다(기기 이름을 바꾸면 주소가 바뀜).
- 외부의 반복 로그인 시도 때문에 직원 로그인이 막히면(제한이 사이트 전체 기준) Funnel을 끕니다.
- 투표 화면은 보안 컨텍스트가 필요합니다. `https://` 주소나 `127.0.0.1`·`localhost`에서만 투표할 수 있고, `http://<LAN IP>`로는 안 됩니다.
- Funnel은 베타 기능이고 버전에 따라 동작하지 않은 사례가 있습니다. 안 되면 다른 Tailscale 버전을 시도합니다.

### 8.3 대체 수단: Cloudflare Quick Tunnel

Funnel이 안 될 때만 씁니다. 실행할 때마다 주소가 바뀌고(이미 발급한 링크가 무효가 됨), TLS가 호스트가 아니라 Cloudflare에서 풀립니다. 채택하지 않은 다른 방법과 이유는 D-29에 있습니다.

---

## 9. 시연 진행 순서

통합 스택이 5절대로 준비돼 있다고 가정합니다. 시연의 기본 경로는 로컬(`http://127.0.0.1:3000`)이고, 공개 주소는 현장 네트워크에서 될 때만 보여 줍니다.

| # | 누가 | 어디서 | 하는 일 | 확인할 것 |
|---|---|---|---|---|
| 1 | 선관위 관리자 | `/admin` | 로그인, 선거 만들기(후보, 투표 기간) | 생성 인자 대조 통과 |
| 2 | 선관위 관리자 | 선거 화면 | 명단 등록 → 명단 고정 → 링크 발급(CSV 내려받기) | 상태 `ROSTER_FROZEN` |
| 3 | — | — | 시작 시각까지 대기 | 원장이 수락한 뒤 `OPEN` |
| 4 | 투표자 | 링크 | 후보 선택, 제출, 영수증 확인 | 영수증이 `ANCHORED`(구간이 끝난 뒤 수십 초~수 분) |
| 5 | — | 선거 화면 | 체크포인트마다 감사 결과 표시 | R1–R5 PASS |
| 6 | — | — | 종료 시각에 마감(`ALL_VOTED_CLOSE=true`이면 전원 투표 뒤 관리자가 마감 가능) | 상태 `CLOSED` |
| 7 | 세 기관 직원(각자 계정) | 선거 화면의 "우리 기관 복호화" | 자기 열쇠 파일 선택 → 검사 → 조각 전송 | 조각 3개 접수. 한 선거는 같은 브라우저에서, 시크릿 창 금지 |
| 8 | 선관위 관리자 | 선거 화면 | 개표 | 득표수, 상태 `TALLIED` |
| 9 | — | 선거 화면 | `TALLY` 체크포인트의 감사 결과 대기 | R1–R5 PASS |
| 10 | 선관위 관리자 | 선거 화면 | 결과 확정 | 원장 수락 뒤 `FINALIZED` |
| 11 | 중립 기관 직원 | 목록 화면 | 노드 3개 상태(연결, 블록 높이, 연결된 노드 수) | |

- 10단계는 대체되지 않은 FAIL·INCONCLUSIVE가 하나라도 있으면 거부됩니다. FAIL이 난 선거는 확정되지 않은 채 남습니다(D-31). 기관 서명 검토와 무효 처리는 범위에서 제외했습니다.
- 7단계는 명령줄로도 할 수 있습니다: `AUDITOR_KEY=<읽기 전용 키> tools/trustees.sh decrypt <election_id>`.
- 결함 시연(승인 없는 명단 변경 T05, DB 표 변조 T08 등)은 `tests/scenarios/`의 스크립트로 주입합니다. 실행 방법과 조건은 `tests/scenarios/T01/README.md`, `SETUP_T05_T08.md`에 있습니다(T02·T04·T15는 `SETUP_T02_T04.md`, `SETUP_T15.md`). 주입한 변경은 DB에 남으므로 **실행마다 새 선거**를 쓰고, 시연용 스택에서만 실행합니다.
- 시연 설정은 명단 100명, 투표 기간 10분, 시간 구간·체크포인트 60초입니다. 시스템 이벤트는 구간이 끝날 때 원장으로 나가므로 단계마다 최대 한 구간을 기다립니다.

---

## 10. 문제 해결

| 증상 | 원인 | 해결 |
|---|---|---|
| 재부팅 뒤 호스트 포트 바인딩 실패(예: 59000, 59545처럼 높은 번호로 옮겨 둔 포트) | Windows가 재부팅 때 동적 포트 범위 일부를 예약함 | `netsh int ipv4 show excludedportrange protocol=tcp`로 예약 범위를 확인하고, 범위 밖 번호를 `*_PORT` 변수(`WEB_PORT`, `CORE_PORT`, `GATEWAY_PORT`, `POSTGRES_PORT`, `NODE_RPC_PORT`)에 지정 |
| 콜드 스타트 뒤 검증 노드가 몇 분간 unhealthy | 노드가 서로 연결되고 블록을 다시 만들기까지 시간이 걸림(선관위 노드가 먼저, 나머지는 60초·120초 뒤 단독 생성으로 넘어감) | 몇 분 기다린 뒤 `$COMPOSE ps`. 계속 unhealthy면 `$COMPOSE logs node-commission` |
| finding이 늦게 나타남 | 규칙 엔진은 선거를 **순서대로** 처리하므로, 여러 선거가 동시에 진행되면 뒤쪽 선거의 결과가 밀림. 앵커 대기(최대 `2 × ANCHOR_BATCH_SECONDS + 60`초)도 있음 | 기다림. 시연·시험 때는 동시에 여는 선거 수를 줄임. `$COMPOSE logs rule-engine` |
| Core `/readyz`가 `chain_config_missing` | `.env`에 체인 설정 3개가 없는 채로 시작 | 5.2절을 먼저 실행한 뒤 `up -d` |
| 선거 생성이 422 `TRUSTEES_NOT_REGISTERED` | 기관 열쇠 미등록 | 5.4절 |
| `chain-init` 실패 | 바이너리가 없거나 sha256 불일치, 또는 ARM 호스트 | `ledger/bin/purechain-geth` 확인 |
| 노드 네트워크 생성 실패 | `172.29.42.0/24`가 이미 사용 중 | 첫 설치 전에 `CHAIN_NET_PREFIX`를 다른 대역으로 지정 |
| 전원 투표 마감 뒤 Core는 `CLOSED`, 체인은 `OPEN` | 이전 버전으로 배포한 계약 | 새 체인에 다시 배포하거나 `ALL_VOTED_CLOSE=false` |
| 웹에서 429 | 입구의 사이트 전체 제한 | 잠시 뒤 재시도(Core에 닿지 않았으므로 안전). 외부 공격이면 Funnel 끄기 |
| 복호화 카드가 열쇠 파일을 거부 | 다른 기관의 파일이거나, 선거의 기관 열쇠 목록에 없는 열쇠 | 로그인한 기관의 파일인지, 선거 생성 뒤 열쇠를 다시 만들지 않았는지 확인 |
| 복호화 검사에서 원장을 읽지 못함(401) | 읽기 키가 없거나 틀림 | `AUDITOR_KEY` 입력 |
| DB 초기화 스크립트를 고쳤는데 반영 안 됨 | `pgdata` 볼륨이 비어 있을 때만 실행됨 | 11절의 결정 뒤 볼륨 재생성 |
| 링크 메일이 안 감 | SMTP 설정 없음 | 4.1절. 설정이 없으면 CSV로만 전달하는 것이 정상 동작 |

---

## 11. 데이터와 백업

### 11.1 볼륨

| 볼륨 | 내용 | 잃으면 |
|---|---|---|
| `pgdata` | Core DB: 선거, 명단, 암호화된 표, 체크포인트, finding 본문, 등록된 기관 공개 열쇠 | 모든 선거 데이터 소실 |
| `node-commission-data`, `node-observer-data`, `node-neutral-data` | 체인 데이터, 노드 계정과 키 | 체인 소실(원장 증거 전부) |
| `ledger-gateway-data` | 게이트웨이의 이벤트 저장소 | 원장 이벤트 본문 소실 |
| `rules-state` | 규칙 엔진의 finding 보관함과 진행 기록 | 미전송 finding 본문 소실(확정이 막힐 수 있음) |
| `chain-build` | 컴파일된 계약 | 다시 빌드하면 됨 |

볼륨 밖에 있는 것: `.env`(모든 키와 체인 설정), `trustee-keys/`(복호화 열쇠). **복호화 열쇠를 잃으면 그 열쇠로 만든 선거는 영영 개표할 수 없습니다.**

### 11.2 규칙

- **볼륨은 "지우기로 결정한 뒤에만" 지웁니다.** `down -v`는 프로젝트의 모든 볼륨을 한꺼번에 지웁니다. 다른 작업을 하다가 곁들여 실행하지 않습니다.
- DB, 체인, 게이트웨이, 규칙 엔진 상태는 서로 맞물려 있어 **일부만 지우면 안 됩니다.** 새로 시작할 때는 전부 함께 지우고, `.env`의 `CONTRACT_ADDRESS`를 비운 뒤 5.2절부터 다시 합니다. 기관 열쇠 등록(5.4절)과 직원 계정(5.3절)도 다시 필요합니다.
- 보존할 스택이 있으면 `stop`/`down`(옵션 없이)만 쓰고, 지우기 전에 `docker volume ls`로 대상 프로젝트의 볼륨인지 확인합니다.
- 백업 대상: `.env`, `trustee-keys/`, 필요하면 볼륨 덤프(예: `$COMPOSE exec db pg_dump ...`). 백업 파일에는 비밀값과 개인정보가 들어 있으므로 저장소 밖 암호화된 곳에 둡니다. 볼륨 전체를 복원하는 절차는 시험하지 않았습니다 **(미확인)**.
- 시나리오 실행 기록(`t01-runs/` 등)에는 토큰·투표권·영수증을 남기지 않도록 돼 있고 git에서 제외됩니다.

---

## 12. 보안 주의사항

- **`.env`와 비밀 열쇠 파일은 절대 커밋하지 않습니다.** `.gitignore`가 `.env`, `.env.*`, `*.pem`, `*.key`, `trustee-keys/`, `ledger/bin/`을 제외하지만, 다른 이름으로 복사한 사본은 걸러지지 않습니다. 커밋 전에 `git status`로 확인합니다.
- 키와 비밀번호를 명령줄 인자, 이슈, PR, 채팅, 화면 공유에 노출하지 않습니다. 도구들은 값을 환경 변수나 파일로 읽고 출력하지 않습니다.
- 서명키와 서비스 키는 **배포마다 새로** 만듭니다(다른 배포의 서명 재사용 방지, `contracts/hashing.md`).
- `AUDITOR_KEY`는 읽기 전용이지만 원장 이벤트 본문을 볼 수 있으므로 기관과 초청 감사인에게만 줍니다.
- 시연에서는 한 PC의 `.env`와 `trustee-keys/`에 세 기관의 키가 모두 있습니다. 이 구성에서는 기관별 서명의 독립성도 표의 비밀도 그 PC의 관리자에 대해서는 성립하지 않습니다. 실제 운영에서는 기관마다 자기 키를 자기 장비에 보관해야 합니다.
- 공개 주소에는 실제 명단이나 실제 선거를 올리지 않습니다. Funnel은 쓰고 나면 끕니다.
- 운영 중인 DB를 직접 고치지 않습니다. 결함 주입 스크립트는 시험용 스택에서만 실행합니다.
- 메일로 링크를 보내면 운영 기관 메일 계정의 보낸편지함에도 링크가 남습니다(D-16의 공개된 한계).
