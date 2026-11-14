#ifndef SERVER_H
#define SERVER_H

#include "game.h"
#include "protocol.h"
#include "crypto.h"
#include "util.h"

// 서버 실행: 지정 포트에서 expected_players(3~4명)를 받아 한 판을 진행한다.
// 서버 개인키는 key_path에 password로 암호화해 유지한다. 성공 1 / 실패 0.
int server_run(int port, const char* words_dir, int expected_players,
               const char* key_path,
               const unsigned char* password, size_t password_len);

#endif
