#ifndef CLIENT_H
#define CLIENT_H

#include "crypto.h"
#include "protocol.h"
#include "util.h"

// key_path의 개인키를 password로 복호화하거나 새로 생성해 저장한 뒤 참여한다.
// 성공 1 / 실패 0.
int client_run(const char* host, int port, const char* key_path,
               const unsigned char* password, size_t password_len);

#endif
