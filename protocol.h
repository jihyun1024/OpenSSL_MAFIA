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
// AUTH 서명 대상: label || version || client_id || client_nonce ||
//                  server_nonce || OAEP(session_keys)
#define AUTH_LABEL          "LIAR_AUTH_V1"
#define AUTH_LABEL_BYTE     12
#define SIGN3_INPUT_BYTE    (AUTH_LABEL_BYTE + 1 + CLIENT_ID_BYTE + \
                             NONCE_BYTE + NONCE_BYTE + RSA_MODULUS_BYTE)

// AUTH_OK의 AES-GCM 평문 & 암호문 길이 
// GCM은 암호문 길이 = 평문 길이, but sizeof AUTH_OK_PLAINTEXT = 3
#define AUTH_OK_PLAINTEXT   "OK"
#define AUTH_OK_CT_BYTE     2

// VOTE 서명 대상: target(1B) || voter_id(CLIENT_ID_BYTE)
#define VOTE_SIGN_INPUT_BYTE  (1 + CLIENT_ID_BYTE)
// VOTE 패킷 평문: target(1B) || signature(RSA_MODULUS_BYTE)
#define VOTE_PLAINTEXT_BYTE   (1 + RSA_MODULUS_BYTE)
// COMMIT 패킷 평문: commit_hash(SHA256_BYTE) || signature(RSA_MODULUS_BYTE)
#define COMMIT_PLAINTEXT_BYTE (SHA256_BYTE + RSA_MODULUS_BYTE)
// LOBBY 평문: phase(1B) || player_count(1B) || receiver_slot(1B)
#define LOBBY_PLAINTEXT_BYTE  3
// END 평문: result(1B) || liar_id(1B) || nonce || signature
#define END_SIGN_INPUT_BYTE   (1 + 1 + COMMIT_NONCE_BYTE + SHA256_BYTE)
#define END_PLAINTEXT_BYTE    (1 + 1 + COMMIT_NONCE_BYTE + RSA_MODULUS_BYTE)


// 메시지 타입
typedef enum {
    MSG_HELLO     = 0x01,
    MSG_CHALLENGE = 0x02,
    MSG_AUTH      = 0x03,
    MSG_AUTH_OK   = 0x04,
    MSG_READY     = 0x10,
    MSG_LOBBY     = 0x11,
    MSG_ASSIGN    = 0x20,
    MSG_COMMIT    = 0x21,
    MSG_TURN      = 0x22,
    MSG_HINT      = 0x23,
    MSG_VOTE      = 0x24,
    MSG_END       = 0x25,
    MSG_PKT_ERROR = 0x7F    // 게임 프로토콜 패킷 오류 응답 코드
} msg_type;

// 게임 프로토콜 패킷 구조 (핸드셰이크 이후 AES-GCM 보호 채널)
//   와이어: len(4B) + type(1B) + seq(8B) + nonce(12B) + ciphertext + tag(16B)
//   len 필드는 자신을 제외한 나머지 전체 길이
//   AAD = type(1B) || seq(8B) || sender_id(CLIENT_ID_BYTE)
#define PKT_LEN_BYTE        4
#define PKT_TYPE_BYTE       1
#define PKT_SEQ_BYTE        8
#define PKT_HEADER_BYTE     (PKT_TYPE_BYTE + PKT_SEQ_BYTE + AEAD_NONCE_BYTE)
#define PKT_AAD_BYTE        (PKT_TYPE_BYTE + PKT_SEQ_BYTE + CLIENT_ID_BYTE)
// len 필드가 덮는 최소 길이 (평문 0바이트일 때): type+seq+nonce+tag
#define PKT_MIN_BODY_BYTE   (PKT_TYPE_BYTE + PKT_SEQ_BYTE + AEAD_NONCE_BYTE + AEAD_TAG_BYTE)
#define PKT_MAX_PLAINTEXT   4096

// 암호 채널 세션 문맥: 핸드셰이크로 성립된 세션키와 방향별 seq 카운터를 보관
typedef struct {
    unsigned char k_tx[AEAD_KEY_BYTE];        // 송신 방향 키
    unsigned char k_rx[AEAD_KEY_BYTE];        // 수신 방향 키
    unsigned char self_id[CLIENT_ID_BYTE];    // 자신의 sender_id (AAD용)
    unsigned char peer_id[CLIENT_ID_BYTE];    // 상대 sender_id (수신 AAD용)
    unsigned long long tx_seq;                // 다음 송신 seq (1부터 증가)
    unsigned long long rx_seq;                // 마지막으로 수용한 수신 seq
} sec_channel;


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


// ===== 게임 프로토콜 패킷 프레이밍 (암호 채널) =====

// 세션 문맥 초기화: 방향별 키와 양쪽 sender_id를 저장하고 seq를 0으로 둔다.
// is_server가 참이면 송신=k_s2c/수신=k_c2s, 거짓이면 그 반대로 매핑한다.
int sec_channel_init(sec_channel* ch, int is_server,
                     const unsigned char k_c2s[AEAD_KEY_BYTE],
                     const unsigned char k_s2c[AEAD_KEY_BYTE],
                     const unsigned char self_id[CLIENT_ID_BYTE],
                     const unsigned char peer_id[CLIENT_ID_BYTE]);
// 세션 문맥 소거.
void sec_channel_free(sec_channel* ch);

// 평문 메시지 한 건을 패킷으로 직렬화(암호화)한다.
//   ch->tx_seq를 하나 올려 seq로 쓰고, 랜덤 nonce를 생성해 암호화.
//   out_len: 호출 시 버퍼 용량, 반환 시 실제 패킷 길이.
//   성공 1 / 실패 0.
int packet_seal(sec_channel* ch, unsigned char type,
                const unsigned char* plaintext, size_t plaintext_len,
                unsigned char* out, size_t* out_len);

// 수신 패킷을 검증(태그/seq)하고 복호화한다.
//   seq가 ch->rx_seq 이하이면 재전송으로 보고 폐기(0 반환).
//   성공 시 ch->rx_seq를 갱신하고 평문/타입을 출력.
//   plaintext_len: 호출 시 버퍼 용량, 반환 시 실제 평문 길이.
//   성공 1 / 실패 0.
int packet_open(sec_channel* ch,
                const unsigned char* in, size_t in_len,
                unsigned char* out_type,
                unsigned char* plaintext, size_t* plaintext_len);


// ===== 소켓 I/O 헬퍼 (TCP) =====

// 정확히 len 바이트를 쓰거나 읽는다 (부분 전송 처리). 성공 1 / 실패 0.
int io_write_all(int fd, const unsigned char* buf, size_t len);
int io_read_all(int fd, unsigned char* buf, size_t len);

// 길이(4B big-endian) 프리픽스 blob 송수신 (공개키 등 가변 데이터용).
int io_write_blob(int fd, const unsigned char* data, size_t len);
int io_read_blob(int fd, unsigned char* buf, size_t* len);

// 완성 패킷 한 건 송수신 (앞 4B len 필드로 경계 파악).
int io_write_packet(int fd, const unsigned char* pkt, size_t pkt_len);
int io_read_packet(int fd, unsigned char* buf, size_t* len);


// ===== 투표 서명 (RSA-PSS) =====

// VOTE 평문 구성: target과 voter_id로 서명 대상을 만들고 self_priv로 서명해
// out[VOTE_PLAINTEXT_BYTE] = target(1B) || signature 를 채운다. 성공 1 / 실패 0.
int vote_build(EVP_PKEY* self_priv, unsigned char target,
               const unsigned char voter_id[CLIENT_ID_BYTE],
               unsigned char* out, size_t* out_len);

// VOTE 평문 검증: voter_pub로 서명을 확인하고 target을 돌려준다.
// 성공(서명 유효) 1 / 실패 0.
int vote_verify(EVP_PKEY* voter_pub,
                const unsigned char voter_id[CLIENT_ID_BYTE],
                const unsigned char* in, size_t in_len,
                unsigned char* out_target);

// 서버 커밋 해시와 RSA-PSS 서명을 구성하고 검증한다.
int commit_build(EVP_PKEY* server_priv,
                 const unsigned char hash[SHA256_BYTE],
                 unsigned char out[COMMIT_PLAINTEXT_BYTE]);
int commit_verify(EVP_PKEY* server_pub, const unsigned char* in, size_t in_len,
                  unsigned char out_hash[SHA256_BYTE]);

// 결과, 공개값, 최초 커밋을 묶어 서버가 서명한 END를 구성하고 검증한다.
int end_build(EVP_PKEY* server_priv, unsigned char result, unsigned char liar_id,
              const unsigned char nonce[COMMIT_NONCE_BYTE],
              const unsigned char commit[SHA256_BYTE],
              unsigned char out[END_PLAINTEXT_BYTE]);
int end_verify(EVP_PKEY* server_pub, const unsigned char* in, size_t in_len,
               const unsigned char commit[SHA256_BYTE]);

#endif
