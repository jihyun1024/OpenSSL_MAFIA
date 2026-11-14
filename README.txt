빌드
====

    make

기본 게임은 4명이며 서버 실행 인자에서 3명 또는 4명을 선택할 수 있습니다.
서버 프로세스는 한 판을 진행한 뒤 종료합니다.

실행
====

서버:

    ./liar_game server 9000 WORDS 4 SERVER/server-key.enc

클라이언트(각 플레이어가 서로 다른 키 파일을 사용):

    ./liar_game client 127.0.0.1 9000 CLIENT/alice-key.enc
    ./liar_game client 127.0.0.1 9000 CLIENT/bob-key.enc
    ./liar_game client 127.0.0.1 9000 CLIENT/carol-key.enc
    ./liar_game client 127.0.0.1 9000 CLIENT/dave-key.enc

서버 키와 로그는 SERVER/ 폴더, 클라이언트 키와 로그는 CLIENT/ 폴더에
보관됩니다. 두 폴더는 실행 시 자동으로 생성됩니다. 키 경로를 지정하지 않으면
각각 SERVER/server-key.enc, CLIENT/client-key.enc를 사용합니다.

개인키 암호는 실행할 때 터미널에서 입력합니다. 자동 실행이 필요하면
LIAR_KEY_PASSWORD 환경 변수를 설정할 수 있습니다. 개인키 파일은 PBKDF2로
유도한 키와 AES-256-GCM으로 암호화되며 mode 0600으로 생성됩니다.

클라이언트는 첫 접속에 서버 공개키를 <클라이언트 키 파일>.server.pub에
고정합니다(TOFU). 이후 서버 키가 바뀌면 접속을 거부합니다. 서버 키를
의도적으로 바꿨다면 해당 핀 파일을 확인한 뒤 직접 삭제하고 다시 접속해야
합니다.

게임 입력
=========

- 발언 차례: 설명 문장을 입력합니다.
- 투표 단계: `vote N`을 입력합니다. N은 화면에 나온 슬롯 번호입니다.
- 발언 제한 시간은 60초이며 투표에는 제한 시간이 없습니다.
- 발언 시간 초과 시 다음 사람으로 넘어가며, 투표는 전원이 마칠 때까지
  기다립니다. 최다 득표가 동점이면 라이어가 승리합니다.

폴더 구조
=========

- SERVER/: 서버 개인키(server-key.enc), 서버 로그(server.log)
- CLIENT/: 클라이언트 개인키(*-key.enc), 서버 공개키 핀(*.server.pub),
  클라이언트 로그(client-<공개키 기반 ID>.log)

방어 시나리오 검증
==================

    make test

security_demo는 재전송 패킷, GCM 암호문 변조, 위조 투표 서명, 커밋 공개값
변조를 거부하는지 확인합니다. 발언 2회 제한, 정상 지목, 동점 판정,
암호화된 개인키 재로딩도 함께 검사합니다.
