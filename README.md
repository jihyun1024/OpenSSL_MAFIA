# Liar Game

OpenSSL 기반 암호화 통신을 사용하는 3~4인용 라이어 게임입니다.
서버는 한 게임을 진행한 뒤 종료합니다.

## 요구 사항

- Linux
- C11 지원 컴파일러 (`gcc` 또는 `clang`)
- `make`
- POSIX Threads
- OpenSSL 3.x 개발 라이브러리

Ubuntu/Debian에서는 다음 명령으로 빌드 도구를 설치할 수 있습니다.

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

## 컴파일

프로젝트 루트에서 실행합니다.

```bash
make
```

다음 실행 파일이 생성됩니다.

- `liar_game`: 게임 서버 및 클라이언트
- `security_demo`: 보안 기능 검증 프로그램

전체 소스를 다시 컴파일하려면 다음과 같이 실행합니다.

```bash
make -B
```

빌드 결과물을 삭제하려면 다음 명령을 사용합니다.

```bash
make clean
```

## 서버 실행

기본 형식은 다음과 같습니다.

```bash
./liar_game server <port> [words_dir] [players] [encrypted_key_file]
```

인자 설명:

- `port`: 서버가 사용할 TCP 포트
- `words_dir`: 제시어 파일 디렉터리, 기본값은 `WORDS`
- `players`: 참가 인원, `3` 또는 `4`, 기본값은 `4`
- `encrypted_key_file`: 암호화된 서버 개인키 파일, 기본값은 `server-key.enc`

기본 설정으로 9000번 포트에서 4인 게임을 시작하는 예시:

```bash
./liar_game server 9000
```

모든 인자를 지정해 3인 게임을 시작하는 예시:

```bash
./liar_game server 9000 WORDS 3 server-key.enc
```

처음 실행하면 개인키 암호를 입력하라는 메시지가 나옵니다. 서버 개인키가
없으면 새로 생성하며, 이후 실행에서는 같은 파일과 암호를 사용해야 합니다.

## 클라이언트 실행

서버와 별도의 터미널에서 실행합니다.

```bash
./liar_game client <IPv4 주소> <port> [encrypted_key_file]
```

예시:

```bash
./liar_game client 127.0.0.1 9000 alice-key.enc
```

한 컴퓨터에서 여러 클라이언트를 실행할 때는 각 플레이어가 서로 다른 키
파일을 사용해야 합니다.

```bash
./liar_game client 127.0.0.1 9000 alice-key.enc
./liar_game client 127.0.0.1 9000 bob-key.enc
./liar_game client 127.0.0.1 9000 carol-key.enc
./liar_game client 127.0.0.1 9000 dave-key.enc
```

각 명령은 별도의 터미널에서 실행합니다. 서버에서 3인 게임을 선택했다면
클라이언트도 3개만 실행합니다.

## 개인키 암호 입력

기본적으로 서버와 클라이언트는 개인키 암호를 터미널에서 입력받습니다.
자동 실행이 필요하면 `LIAR_KEY_PASSWORD` 환경 변수를 사용할 수 있습니다.

```bash
LIAR_KEY_PASSWORD='your-password' ./liar_game server 9000
```

```bash
LIAR_KEY_PASSWORD='your-password' \
  ./liar_game client 127.0.0.1 9000 alice-key.enc
```

개인키 파일은 PBKDF2로 유도한 키와 AES-256-GCM으로 암호화되며 파일 권한
`0600`으로 생성됩니다. 실제 운영에서는 셸 기록이나 프로세스 환경에 암호가
노출될 수 있으므로 터미널 입력 방식을 권장합니다.

## 게임 방법

1. 필요한 인원의 클라이언트가 접속하고 `READY`를 전송합니다.
2. 서버가 카테고리와 제시어를 배정합니다. 라이어에게는 카테고리만 보입니다.
3. 접속 순서대로 두 번씩 발언합니다.
4. 모든 발언이 끝나면 라이어라고 생각하는 슬롯에 투표합니다.
5. 서버가 결과와 라이어 커밋 공개값을 전송합니다.

발언 차례에는 설명 문장을 그대로 입력합니다.

```text
보통 따뜻한 곳에서 볼 수 있습니다.
```

투표 단계에서는 다음 형식으로 입력합니다.

```text
vote 2
```

`2`는 화면에 표시된 플레이어 슬롯 번호입니다.

- 한 번의 발언 제한 시간: 60초
- 투표에는 제한 시간이 없으며 전원이 투표를 마치면 집계합니다.
- 발언 시간이 끝나면 다음 플레이어로 넘어갑니다.
- 최다 득표가 동점이면 라이어가 승리합니다.

## 서버 공개키 확인

클라이언트는 첫 접속 시 서버 공개키를 다음 파일에 저장합니다.

```text
<클라이언트 키 파일>.server.pub
```

이후 서버 공개키가 달라지면 접속을 거부합니다. 서버 키를 의도적으로
교체했다면 서버가 올바른지 먼저 확인한 다음 해당 `.server.pub` 파일을 직접
삭제하고 다시 접속해야 합니다.

## 로그

- 서버 로그: `server.log`
- 클라이언트 로그: `client-<공개키 기반 ID>.log`

## 보안 시나리오 테스트

다음 명령은 프로젝트를 빌드한 뒤 보안 및 게임 규칙 테스트를 실행합니다.

```bash
make test
```

검증 대상은 다음과 같습니다.

- 패킷 재전송 차단
- AES-GCM 암호문 및 헤더 변조 탐지
- 위조된 RSA-PSS 투표 서명 거부
- 플레이어당 발언 2회 제한
- 정상 투표와 동점 판정
- 발언 시간 초과 처리
- 라이어 커밋과 종료 서명 검증
- PBKDF2/AES-GCM 개인키 저장 및 재로딩

별도의 하이브리드 암호화 예제를 빌드하려면 다음 명령을 사용합니다.

```bash
make hybrid_demo
./hybrid_demo
```
