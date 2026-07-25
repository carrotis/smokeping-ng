# CLAUDE.md

smokeping-py — SmokePing의 Python 재구현. agent(프로브 실행) + server(수집/저장) 분리,
ClickHouse/PostgreSQL 저장, Grafana 전용 시각화. 자체 웹 UI는 만들지 않는다.

## 실행

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[all]"

pytest                              # 전부 오프라인, 네트워크 불필요
ruff check src tests
smoke-agent probes                  # 이 호스트에서 쓸 수 있는 프로브 확인
smoke-agent test -c config/agent.example.yaml --probe curl --host https://example.com
```

스키마 SQL은 **손으로 고치지 말 것**. 드라이버 코드가 원본이고 파일은 생성물이다:

```bash
smoke-server schema --driver clickhouse > deploy/clickhouse/initdb/01-schema.sql
smoke-server schema --driver postgresql > deploy/postgres/initdb/01-schema.sql
```

`tests/test_schema_files.py`가 둘이 어긋나면 실패시킨다.

## 구조

```
src/smokecommon/   wire 모델, JSON 로깅, 설정 로더, subprocess 헬퍼 (양쪽 공유)
src/smokeagent/    probes/, scheduler, shipper, spool, config, cli
src/smokeserver/   app(FastAPI), auth, config, storage/{clickhouse,postgres}
```

프로브는 **"명령줄 만들기"와 "출력 파싱"이 분리**되어 있다. 그래서 리눅스 CI에서 윈도우
`ping` 파서를 테스트할 수 있고, raw socket 권한 없이 mtr 파서를 테스트할 수 있다.
프로브를 고칠 때 이 분리를 깨지 말 것 — 깨면 테스트가 네트워크에 의존하게 된다.

---

## 바꾸기 전에 이유를 먼저 읽어야 하는 것들

아래는 전부 **의도된 설계**다. 언뜻 보면 버그나 과잉으로 보이지만 각각 이유가 있고,
대부분 실제 버그를 잡고 나서 그렇게 된 것이다. 되돌리기 전에 여기를 읽을 것.

### 1. 인제스트 실패 규약 (이 프로젝트의 척추)

- 인제스트는 **동기**. 저장소가 write를 확정한 뒤에만 201을 준다.
- 저장 실패 → **503** → agent가 디스크 spool에 넣고 나중에 재시도.
- 잘못된 페이로드(400/413/422) → agent가 **폐기**. 재시도하면 poison batch가 큐를 막는다.

write 전에 ack하도록 바꾸면 서버 재시작마다 조용히 데이터가 사라진다. 지연 모니터링은
네트워크가 망가졌을 때 가장 값어치 있는데, 그때가 바로 agent가 서버에 못 닿는 때다.
spool은 "장애가 장애의 증거를 지우는 것"을 막는 장치다.

### 2. API 키는 `agent_ids`에 바인딩한다

와일드카드 키는 그걸 가진 누구나 **아무 location으로나** 측정값을 쓸 수 있게 한다.
그런데 location이 이 데이터의 가치 전부다. 뚫린 엣지 agent가 다른 지점을 사칭하면
데이터 전체가 무의미해진다. 예제 설정도 와일드카드가 아니라 바인딩을 보여주도록
되어 있고, `tests/test_server_config.py`가 그걸 강제한다.

키 비교는 SHA-256 + `hmac.compare_digest`, 그리고 **매치된 뒤에도 전체 키를 다 순회**한다.
일찍 빠져나가면 응답 시간이 "몇 번째 키가 맞았는지"를 흘린다. 최적화하지 말 것.

### 3. mtr `path_complete` = "마지막 hop이 목적지 IP와 같다"

"마지막 hop이 응답했다"가 **아니다**. agent가 mtr 실행 전에 타겟을 resolve해 두고,
마지막 hop 주소와 비교한다.

라이브 테스트에서 잡은 실제 버그다: `max_hops=12`로 `1.1.1.1`을 추적하니 12번째
중계 라우터(`211.56.189.162`)에서 멈췄는데, 코드가 그걸 목적지로 보고 그 라우터의
지연을 타겟의 지연이라고 보고했다. per-IP 대시보드가 무고한 hop을 범인으로 지목한다.

도달 못 하면: `unreachable`로 기록, `latency_ms`와 `destination_*`는 null,
`truncated_at_max_hops`로 max_hops 탓인지 표시, `last_responding_ip`로 어디까지
갔는지 남긴다. hop 테이블은 어느 쪽이든 전부 저장한다. `resolved_ip`는 **항상 겨냥한
주소** — per-IP 집계가 중계 hop으로 묶이면 안 되니까.

### 4. mtr `worst_hop`은 손실 최대 hop이 아니다

ICMP TTL-exceeded를 rate limit하는 라우터는 트래픽은 멀쩡히 넘기면서 손실 100%로
보인다. 진짜 손실은 전파된다 — 뒤의 모든 hop이 최소한 그만큼 손실을 물려받는다.
그래서 **하류 최소 손실 >= 자기 손실**일 때만 진짜 범인으로 친다.

실측 경로에서 hop들이 100%/40%/20% 손실을 보이는데 목적지는 0%인 상황을 확인했고,
`worst_hop`이 올바르게 `None`을 반환했다. 순진하게 최대 손실 hop을 고르면 오탐이다.

### 5. ping 파서는 키워드를 안 쓴다

윈도우 `ping.exe`는 OS 레벨에서 현지화되고 `LC_ALL`을 무시한다. 한국어 윈도우에서
응답 줄은 `바이트=32 시간=35ms TTL=115`다.

규칙: **한 줄에 `ms` 값이 정확히 1개면 응답 줄**. 요약 줄
(`최소 = 34ms, 최대 = 35ms, 평균 = 34ms`)은 3개라서 걸러진다. 키워드 매칭으로
바꾸지 말 것 — 로케일마다 깨진다.

### 6. curl은 `count`번을 **별도 프로세스**로 실행한다 (`--next` 금지)

`--next`로 묶으면 프로세스 하나로 끝나서 싸 보이지만, **curl이 커넥션을 재사용한다**:

```
transfer 1: num_connects=1  connect=0.116s  appconnect=0.145s  total=0.155s
transfer 2: num_connects=0  connect=0.000s  appconnect=0.000s  total=0.006s
```

결과가 두 가지로 망가진다. 샘플 1개는 cold connect, 나머지는 warm hit이라 분포가
커넥션 캐싱의 부산물이 되고 — smoke 그래프의 전제가 깨진다 — 대표 리포트의
DNS/TCP/TLS가 영원히 0으로 찍혀서 대시보드의 "HTTP timing breakdown" 패널이
죽는다. `count=1`(기본값)에선 안 드러나므로 테스트에 걸리기 어렵다.

요청당 fork 하나를 지불하는 게 맞다. 최적화한답시고 되돌리지 말 것.

### 7. `Measurement`의 stats는 모델 불변식이다

`stats`/`latency_ms`/`loss_pct`는 `model_validator`에서 채워진다. 특정 생성자에만
넣으면, 손으로 만든 객체나 옛 agent가 보낸 spool 파일에서 percentile 컬럼이 비게 된다.

### 8. spool은 **가장 최신 파일은 절대 안 지운다**

배치 하나가 `max_bytes`보다 크면, 한도를 지키느라 방금 쓴 것까지 지워서 spool이
영원히 비게 된다. 설정된 것처럼 보이면서 전부 버리는 게, 잠깐 한도를 넘기는 것보다
훨씬 나쁘다.

### 9. 실패한 측정은 저장한다, 구멍으로 두지 않는다

부분 패킷 손실은 **성공한 측정**이다(그게 SmokePing이 보여주려는 신호다).
완전 실패도 `error_type` + 도구의 원문 메시지와 함께 행으로 저장한다.

---

## 알아두면 좋은 것

- **`resolved_ip`의 의미는 프로브마다 다르다.** ping/fping/curl/nc는 통신한 주소,
  dig는 **응답한 리졸버**(응답 레코드가 아님 — anycast PoP 구분용, 레코드는
  `details.answer_ips`), mtr은 겨냥한 목적지.
- **dig는 정수 ms만 보고한다.** 로컬 캐시의 서브밀리초 응답은 진짜로 `0`이다.
  파싱 버그가 아니다.
- **fping만 batch 프로브다.** 같은 interval/options을 가진 타겟들을 scheduler가 묶어
  프로세스 하나로 처리한다. `probe_many()`를 구현하고 `supports_batch = True`.
- **`details`는 프로브별 자유 JSON.** 새 필드 추가에 마이그레이션이 필요 없다.
  대시보드에 노출하려면 `v_curl`/`v_dig`/`v_mtr` 뷰에 컬럼을 추가하면 된다.
- **hop은 별도 테이블(`mtr_hops`).** hop별 분석은 쿼리 모양이 완전히 달라서
  (수천 사이클에 걸쳐 hop IP로 group by) 배열 unnest로는 못 쓴다.
- 로깅은 구조화 JSON. `extra={...}`로 넘긴 게 최상위 키가 된다. f-string으로
  메시지에 값을 박지 말 것.

## 테스트 규칙

- 프로브 테스트는 **실제 바이너리의 실제 출력**을 픽스처로 쓴다. 새 파싱 케이스를
  추가할 땐 진짜 출력을 붙여넣을 것.
- `tests/test_end_to_end.py`는 진짜 scheduler → shipper → HTTP → server app을
  ASGI로 연결한다(장애 후 spool 재전송 경로 포함). 프로브와 DB만 대역이다.
- Grafana 대시보드 JSON도 테스트한다 — 쿼리가 참조하는 컬럼이 스키마에 실제로
  있는지 검사한다.
