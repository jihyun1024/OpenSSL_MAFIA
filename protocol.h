// 프로젝트에서 프로토콜 관련 기능만 모아놓은 헤더 파일
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "crypto.h"
#include "util.h"
#include <stddef.h>

// 프로토콜 상수
#define PROTOCOL_VERSION    1                   // HELLO의 ver 필드 값에 해당
#define CLIENT_ID_BYTE      GAME_ID_BYTE
#define NONCE_BYTE          COMMIT_NONCE_BYTE   // client, server 공통

// 세션 키 2개를 이어붙인 평문 길이, RSA_OAEP로 암호화되는 대상
#define SESSION_KEYS_BYTE   (AEAD_KEY_BYTE * 2)

// Challenge 서명 대상: client_nonce || server_nonce || client_id
#define SIGN2_INPUT_BYTE    (NONCE_BYTE + NONCE_BYTE + CLIENT_ID_BYTE)
// AUTH 서명 대상: server_nonce || client_nonce
#define SIGN3_INPUT_BYTE    (NONCE_BYTE + NONCE_BYTE)

// AUTH_OK의 AES-GCM 평문 & 암호문 길이 
// GCM은 암호문 길이 = 평문 길이, but sizeof AUTH_OK_PLAINTEXT = 3
#define AUTH_OK_PLAINTEXT   "OK"
#define AUTH_OK_CT_BYTE     2


// 메시지 타입
typedef enum {
    MSG_HELLO     = 1,
    MSG_CHALLENGE = 2,
    MSG_AUTH      = 3,
    MSG_AUTH_OK   = 4,
    MSG_ERROR     = 0xFF
} msg_type;


// 메시지 구조체 4가지
// 주의: 아래 구조체는 논리적 표현으로, 컴파일러 패딩과 엔디안 문제 때문에 
//      구조체를 그대로 send()하지 말고, encode/decode 함수를 통해
//      바이트 버퍼로 변환해서 주고받아야 함
typedef struct {
    unsigned char ver;
    unsigned char client_id[CLIENT_ID_BYTE];
    unsigned char client_nonce[NONCE_BYTE];
} msg_hello;

typedef struct {
    unsigned char server_nonce[NONCE_BYTE];
    unsigned char signature[RSA_MODULUS_BYTE];
} msg_challenge;

typedef struct {
    unsigned char signature[RSA_MODULUS_BYTE];
    unsigned char enc_keys[RSA_MODULUS_BYTE];
} msg_auth;

typedef struct {
    unsigned char nonce[AEAD_NONCE_BYTE];
    unsigned char ciphertext[AUTH_OK_CT_BYTE];
    unsigned char tag[AEAD_TAG_BYTE];
} msg_auth_ok;


// 핸드셰이크 세션 상태
// 핸드셰이크 단계
typedef enum {
    HS_INIT,            // 시작 전 초기화
    HS_HELLO_SENT,      // 클라이언트: HELLO 전송 / 서버: HELLO 수신
    HS_CHALLENGED,      // CHALLENGE 전송 완료
    HS_AUTHED,          // AUTH 전송 완료
    HS_ESTABLISHED,     // AUTH_OK 확인, 채널 수립
    HS_FAILED           // 핸드셰이크 실패
} handshake_state;

// 핸드셰이크 진행 중 양쪽이 누적하는 상태
typedef struct {
    unsigned char client_id[CLIENT_ID_BYTE];
    unsigned char client_nonce[NONCE_BYTE];
    unsigned char server_nonce[NONCE_BYTE];
    unsigned char k_c2s[AEAD_KEY_BYTE];     // Client -> Server 방향 세션키
    unsigned char k_s2c[AEAD_KEY_BYTE];     // Server -> Client 방향 세션키

    // hs_ctx_init 함수 호출 때 초기화 & 외부에서 주는 값 -> 따로 memcpy 할 필요 없음
    EVP_PKEY* self_priv;                    // 자신의 개인키
    EVP_PKEY* peer_pub;                     // 상대방의 공개키
    handshake_state state;                  // 핸드셰이크 단계
} handshake_ctx;


// 함수 선언부 (Client와 Server는 서로 송수신하는 메시지가 정반대)
// handshake_ctx를 안전하게 시작하고 안전하게 끝내기 위한 함수
int hs_ctx_init(handshake_ctx* ctx, EVP_PKEY* self_priv, EVP_PKEY* peer_pub);
int hs_ctx_free(handshake_ctx* ctx);

// 인코딩/디코딩 관련 (구조체 <-> 바이트 버퍼)
int encode_hello    (const msg_hello* m,     unsigned char* out, size_t* out_len);
int decode_hello    (const unsigned char* in, size_t in_len, msg_hello* m);
int encode_challenge(const msg_challenge* m, unsigned char* out, size_t* out_len);
int decode_challenge(const unsigned char* in, size_t in_len, msg_challenge* m);
int encode_auth     (const msg_auth* m,      unsigned char* out, size_t* out_len);
int decode_auth     (const unsigned char* in, size_t in_len, msg_auth* m);
int encode_auth_ok  (const msg_auth_ok* m,   unsigned char* out, size_t* out_len);
int decode_auth_ok  (const unsigned char* in, size_t in_len, msg_auth_ok* m);

// Client측 처리
int client_hello(handshake_ctx* ctx, const unsigned char client_id[CLIENT_ID_BYTE], msg_hello* out);
int client_recv_challenge(handshake_ctx* ctx, const msg_challenge* in);
// 성립된 방향별 세션키를 호출자 버퍼(k_c2s / k_s2c)로도 내보낸다.
// 핸드셰이크 종료 뒤 게임 프로토콜에서 계속 사용하기 위함.
int client_auth(handshake_ctx* ctx, msg_auth* out,
                unsigned char k_c2s[AEAD_KEY_BYTE], unsigned char k_s2c[AEAD_KEY_BYTE]);
int client_recv_auth_ok(handshake_ctx* ctx, const msg_auth_ok* in);

// Server측 처리
int server_recv_hello(handshake_ctx* ctx, const msg_hello* in);
int server_challenge(handshake_ctx* ctx, msg_challenge* out);
// 복호화한 방향별 세션키를 호출자 버퍼(k_c2s / k_s2c)로도 내보낸다.
int server_recv_auth(handshake_ctx* ctx, const msg_auth* in,
                     unsigned char k_c2s[AEAD_KEY_BYTE], unsigned char k_s2c[AEAD_KEY_BYTE]);
int server_auth_ok(handshake_ctx* ctx, msg_auth_ok* out);

#endif