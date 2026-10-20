# Core 개발 기록 (승민)

> Core API·웹 담당의 작업 기록입니다. 무엇을 했는지, 왜 그렇게 했는지, 무엇을 확인했고 무엇이 아직 확인되지 않았는지를 적습니다.
> 기준 문서: `docs/roles/core-web.md`, `contracts/` v1.0.

---

## 2026-10-19 — 1주차 시작: FastAPI 골격, docker-compose, 해시 라이브러리·벡터 테스트, DB init SQL

### 한눈에 보기

| 항목 | 결과 | 확인 방법 |
|---|---|---|
| 해시 라이브러리 | 공용 벡터 39개 모두 재현 | pytest 통과 |
| FastAPI 골격 | `/healthz`, `/readyz` 동작 | pytest 통과 |
| DB init SQL | 역할 3개, 스키마 2개, 테이블, 투표 쪽 함수 2개 | 파서 검사 통과 → **실제 PostgreSQL 16.4에서 실행·스모크 테스트 통과**(7절) |
| docker-compose | DB + Core | **실제 기동 확인**: 두 컨테이너 healthy, `/readyz` = ready(7절) |
| CI | 단위 테스트 job, 실제 PostgreSQL 16에서 init·스모크 테스트를 돌리는 job | push 후 GitHub Actions에서 처음 실행됨 |

전체 단위 테스트는 45개 통과입니다. 경고 1건은 테스트 도구(Starlette TestClient) 내부의 것이라 우리 코드와는 관계없습니다.

### 1. 해시 라이브러리와 벡터 테스트

**만든 것**
- `core/app/hashing.py`: `contracts/hashing.md`의 계산을 그대로 옮겼습니다.
  - 기본: `H`, `canonical`(RFC 8785), `Hc`, `merkle_root`, `set_root`
  - 값: leaf_hash, rejection_leaf, rejections_root, receipt_hash, roster_hash, token_set_root, ballot_set_root, target_hash, snapshot_hash
  - 서명 다이제스트: 요청·승인, finding 기록, 검토
- `core/tests/test_hash_vectors.py`: `tests/vectors/hash-vectors.json`의 벡터를 하나씩 계산해 기대값과 비교합니다.
  - 새 벡터가 추가됐는데 Core 계산이 없으면 실패하게 했습니다(그냥 건너뛰지 않도록).
  - 벡터 개수도 함께 확인합니다.

**왜**
- 세 모듈(Core, Gateway, 규칙 엔진)은 같은 값을 각자 계산하고, R4·R5가 그 값을 서로 비교합니다. 한 비트라도 다르면 R5가 계속 FAIL을 냅니다.
- 그래서 설계안 7장 #3에서 "공용 벡터 재현"을 1주차 필수 조건으로 정했고, Core가 가장 먼저 끝냈습니다.

**바로잡은 것: 벡터 수 41개 → 39개**
- 지금까지 문서와 보고에서 벡터가 41개라고 했는데, 실제로는 **39개**입니다.
- 처음에 `"name"` 글자 수를 세면서 후보 정보 안의 `name` 필드까지 같이 셌기 때문입니다. 개수 확인 테스트를 넣자마자 드러났습니다.
- 저장소 문서에는 개수가 적혀 있지 않았습니다. 다운로드 폴더의 진행 현황 md는 39개로 고쳤습니다.
- 팀원에게 개수를 말할 일이 있으면 39개라고 하면 됩니다.

### 2. DB init SQL

**만든 것**
- `core/db/init/00_roles.sh`: DB를 처음 만들 때 한 번 실행됩니다. 역할 세 개를 만듭니다.
  - `pv2_credential`: 로그인 불가. `credential` 스키마의 주인입니다.
  - `pv2_ballot`: 로그인 불가. `ballot` 스키마의 주인입니다.
  - `pv2_core`: Core가 접속할 때 쓰는 계정입니다.
- `core/db/init/10_schema.sql`: 스키마, 테이블, 함수, 권한을 만듭니다.
  - `credential` 스키마
    - 선거와 상태 이력
    - 스냅샷 대상 테이블: `roster`, `token_status`, `admin_actions`(+상태 이력), `rejected_attempts`
    - 운영용 테이블: seq 카운터, outbox, 체크포인트, 직원 계정
  - `ballot` 스키마
    - 스냅샷 대상 테이블: `credential_issuance`, `ballot_receipts`
    - 투표 쪽 함수 2개: `register_nullifier`, `cast_ballot`
- `core/db/tests/smoke.sql`: `pv2_core`로 접속해 다음을 확인합니다.
  - 투표권 등록과 중복 거부
  - 투표 결과 네 가지(UNKNOWN / CREATED / RETRY / CONFLICT)
  - `pv2_core`가 투표 테이블을 직접 수정·삭제할 수 없음
  - 사용된 토큰은 폐기할 수 없음
  - `track_commit_timestamp`가 꺼져 있음

**왜 이렇게 했나**

| 결정 | 이유 |
|---|---|
| 스키마 2개를 서로 다른 역할이 소유 | D-06의 권한 분리. 명단 쪽과 투표 쪽을 같은 주인이 갖지 않게 함 |
| 투표 쪽 쓰기는 SECURITY DEFINER 함수 2개로만 | 권한 분리와 "redeem은 한 트랜잭션"을 둘 다 지키려면 방법이 필요했음(감독관 DB 검토의 지적). Core 계정은 함수만 호출할 수 있고, 투표 행을 직접 수정·삭제할 수 없음. 한 번 쓴 투표 행은 바뀌지 않음 |
| 두 스키마 사이에 잇는 열이 없음 | 토큰과 투표권을 연결하지 못하게 하는 설계(D-07, 위협 모델 S2) |
| 투표 쪽 행에는 시각 대신 구간·체크포인트만 저장, 기본키는 무작위 ID나 해시 | contracts "Shared conventions"의 투표 쪽 저장 규칙 |
| 바뀌는 값은 바뀐 체크포인트 번호와 함께 저장(`used_checkpoint` 등), 상태는 이력 테이블로 관리 | view를 "체크포인트 k 기준"으로 언제 읽어도 같은 결과가 나오게 하기 위함(스냅샷 해시 재계산, R5) |
| seq는 SERIAL·SEQUENCE를 쓰지 않고 카운터 테이블 사용 | SEQUENCE는 실패한 트랜잭션에서 번호가 비어 seq에 빈칸이 생김. contracts는 빈칸 없는 seq를 요구함 |
| `track_commit_timestamp=off` 강제 | 커밋 시각이 남으면 토큰 사용과 투표권 등록을 시각으로 짝지을 수 있음 |
| `CHECK (used_checkpoint IS NULL OR revoked_checkpoint IS NULL)` | "사용된 토큰은 폐기할 수 없다"는 규칙(R1)을 DB 차원에서도 막음 |
| 선거 설정 테이블은 스냅샷 대상 아님 | contracts 정의상 `election_config`는 스냅샷 대상이 아니고 `config_hash`로 확인함 |

**남은 한계(공개된 것)**
- DB 최고 관리자(superuser)는 여전히 두 스키마를 연결하거나 행을 고칠 수 있습니다(위협 모델 S2). 그래서 R5가 사후 변조를 탐지합니다.
- `pv2_core`는 view와 개표 때문에 투표 테이블을 읽을 수는 있습니다.

### 3. FastAPI 골격

**만든 것**
- `core/app/main.py`
  - `/healthz`: 프로세스가 떠 있는지 확인합니다.
  - `/readyz`: DB까지 응답하는지 확인합니다. DB가 없으면 503을 돌려주고, 오류 내용은 응답에 넣지 않습니다.
- `core/app/config.py`: 환경 변수에서 설정을 읽습니다. DB URL, 서비스 키, 고정 체인 설정 등입니다.
- `core/app/db.py`: SQLAlchemy 엔진입니다. "변경과 outbox 기록은 한 트랜잭션" 원칙을 주석으로 적어 두었습니다.
- `requirements.txt`(버전 고정), `requirements-dev.txt`, `Dockerfile`, `.dockerignore`, `pytest.ini`

**왜**
- 2주차부터 API를 붙이려면 앱, 설정, DB 연결의 뼈대가 먼저 있어야 합니다.
- `/readyz`는 docker-compose의 healthcheck에 씁니다. 다른 서비스가 Core가 준비됐는지 확인하고 기동하게 하기 위해서입니다(설계안 7장 #6 기동 순서).
- 라이브러리 버전은 고정했습니다. 새 PC에서 같은 결과가 나와야 하기 때문입니다(T14).

### 4. docker-compose와 CI

**만든 것**
- 저장소 루트 `docker-compose.yml`
  - `db`(postgres:16.4): init 스크립트를 마운트하고, `track_commit_timestamp=off`, healthcheck를 둡니다.
  - `core`: Dockerfile로 빌드하고, DB가 healthy가 된 뒤 기동합니다. healthcheck는 `/readyz`입니다.
  - 포트는 `127.0.0.1`에만 엽니다. 외부에 노출하지 않기 위해서입니다.
- `.env.example`: DB 비밀번호 항목을 `DB_CORE_PASSWORD` 하나로 정리했습니다. 스키마 주인 역할은 로그인하지 않으므로 비밀번호가 필요 없습니다.
- `.github/workflows/core.yml`
  - `unit`: 단위 테스트를 돌립니다(해시 벡터 39개 포함).
  - `db`: GitHub Actions의 PostgreSQL 16 서비스에서 `00_roles.sh` → `10_schema.sql` → `smoke.sql`(pv2_core로 접속)을 실제로 실행합니다.

**왜**
- 설계안 7장 #6에 따라 `docker compose up` 한 번으로 전체가 떠야 합니다. 1주차에는 DB와 Core부터 시작하고, Harits·Anik이 2주차까지 자기 서비스 블록을 보내면 합칩니다.
- 이 PC에는 Docker와 PostgreSQL이 없어서, SQL이 실제 DB에서 도는지 로컬에서 확인할 수 없었습니다. 그래서 무료인 GitHub Actions에서 실제 PostgreSQL로 검사하는 job을 넣었습니다.

### 5. 확인한 것 / 아직 확인하지 않은 것

**확인함**
- 단위 테스트 45개 통과: 해시 벡터 39개, 벡터 개수, health 2개, SQL 파싱 2개, SERIAL·IDENTITY 금지 1개
- `10_schema.sql`과 `smoke.sql`이 PostgreSQL 문법으로 파싱되고, PL/pgSQL 함수 본문 2개와 DO 블록 2개도 파싱됨(pglast)
- `docker-compose.yml`과 CI YAML의 구조

**아직 확인하지 않음**
- GitHub Actions의 `core` 워크플로(`unit`, `db` job). 커밋·push 후 처음 실행됩니다. 로컬 실제 DB에서는 같은 내용을 확인했습니다(7절).

### 6. 다음 할 일(2주차)
1. 커밋·push하고, CI `core` 워크플로의 `unit`·`db` job이 통과하는지 확인합니다.
2. 선거 생성(공개키 쌍, `config_hash`, 생성 인자 대조 stub)과 명단·명단 고정(D-10 구간 크기 검사)을 만듭니다.
3. redeem(토큰 잠금 → USED → `register_nullifier` → outbox, 한 트랜잭션), ballots(`cast_ballot`)를 만듭니다.
4. outbox 워커(seq, 구간 단위 전송, 결과 처리), 체크포인트·view, 내부 API(`/internal/v1/elections`, `/checkpoints`, `/views`, `POST /internal/v1/findings`)를 만듭니다.
5. 직원 계정 설정 스크립트를 만듭니다(2주차, T01에 admin JWT 필요).

### 7. 실제 DB 실행 확인 (같은 날 추가)

**한 것**
- 이 PC에 Docker Desktop 4.95.0을 설치했습니다(winget). Docker 29.8.2, Compose v5.6.0이고 WSL2를 씁니다.
- PostgreSQL은 Windows에 따로 설치하지 않았습니다. Docker가 받은 공식 이미지 `postgres:16.4`가 실제 PostgreSQL입니다. Windows에 따로 깔면 같은 5432 포트로 충돌할 수 있습니다.
- 로컬 `.env`를 만들었습니다. 비밀번호와 키는 무작위로 생성했고, `.gitignore`에 걸려 Git에 올라가지 않는 것을 확인했습니다.
- `docker compose up --build -d`로 DB와 Core를 기동했습니다.

**결과**
- 컨테이너: `db`, `core` 둘 다 `healthy`
- DB 초기화 로그: `00_roles.sh`(CREATE ROLE 3회), `10_schema.sql` 실행, 오류 없음
- `GET /healthz` → `{"status":"ok"}`, `GET /readyz` → `{"status":"ready"}`. Core가 `pv2_core` 계정으로 DB에 접속됨
- 스모크 테스트(`core/db/tests/smoke.sql`)를 `pv2_core`로 실제 DB에서 실행해 `smoke ok`가 나왔습니다. 테스트 데이터가 남지 않게 트랜잭션으로 감싸고 롤백했고, 끝난 뒤 남은 행이 0개인 것도 확인했습니다.
- 구조 확인
  - 역할: `pv2_core`(login), `pv2_credential`·`pv2_ballot`(nologin)
  - 스키마 주인: `credential` = `pv2_credential`, `ballot` = `pv2_ballot`
  - 테이블: credential 11개, ballot 2개
  - `pv2_core`의 `ballot.ballot_receipts` 권한: select만 true, insert·update·delete는 false
  - 함수 2개: SECURITY DEFINER, 주인 `pv2_ballot`
  - `track_commit_timestamp=off`, 서버 16.4

**참고**
- 설치 직후 이 터미널에는 Docker 경로(`C:\Program Files\Docker\Dockeresourcesin`)가 PATH에 없어서, `docker-credential-desktop`을 찾지 못하는 오류가 한 번 났습니다. 세션 PATH에 추가해서 해결했고, 새로 로그인하거나 새 터미널을 열면 자동으로 잡힙니다.
- DB init 스크립트는 `pgdata` 볼륨이 비어 있을 때만 실행됩니다. 스크립트를 고친 뒤에는 `docker compose down -v`로 볼륨을 지우고 다시 올려야 합니다.
- 멈추기: `docker compose down`(데이터 유지), `docker compose down -v`(데이터까지 삭제).
