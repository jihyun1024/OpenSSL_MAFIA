#include "protocol.h"

#include <string.h>   
#include <stddef.h>   
#include <unistd.h>
#include <errno.h>


// =====================================================================
// 와이어 포맷 (직렬화 규칙)
//
//   HELLO     : [type=1][ver 1B][client_id 16B][client_nonce 32B]
//   CHALLENGE : [type=2][server_nonce 32B][signature 384B]
//   AUTH      : [type=3][signature 384B][enc_keys 384B]
//   AUTH_OK   : [type=4][nonce 12B][ciphertext 2B][tag 16B]
//
//   encode: out 버퍼에 직렬화. 호출 시 *out_len에 버퍼 용량을 담아 전달하고,
//           반환 시 실제 기록 길이로 갱신된다. 버퍼가 작으면 0(실패).
//   decode: in 버퍼를 구조체로 역직렬화. 선두 타입 태그가 기대값과
//           다르거나 길이가 안 맞으면 0(실패).
// =====================================================================

// 각 메시지의 직렬화 총 길이 (타입 태그 1바이트 포함)
#define WIRE_HELLO_BYTE     (1 + 1 + CLIENT_ID_BYTE + NONCE_BYTE)
#define WIRE_CHALLENGE_BYTE (1 + NONCE_BYTE + RSA_MODULUS_BYTE)
#define WIRE_AUTH_BYTE      (1 + RSA_MODULUS_BYTE + RSA_MODULUS_BYTE)
#define WIRE_AUTH_OK_BYTE   (1 + AEAD_NONCE_BYTE + AUTH_OK_CT_BYTE + AEAD_TAG_BYTE)


int encode_hello(const msg_hello* m, unsigned char* out, size_t* out_len) {
    if (m == NULL || out == NULL || out_len == NULL) return 0;
    if (*out_len < WIRE_HELLO_BYTE) return 0;   // 버퍼 용량 확인

    size_t off = 0;
    out[off++] = (unsigned char)MSG_HELLO;      // 타입 태그
    out[off++] = m->ver;
    memcpy(out + off, m->client_id, CLIENT_ID_BYTE);     off += CLIENT_ID_BYTE;
    memcpy(out + off, m->client_nonce, NONCE_BYTE);      off += NONCE_BYTE;

    *out_len = off;   // 실제 기록 길이
    return 1;
}

int decode_hello(const unsigned char* in, size_t in_len, msg_hello* m) {
    if (in == NULL || m == NULL) return 0;
    if (in_len != WIRE_HELLO_BYTE) return 0;             // 길이 정확히 일치
    if (in[0] != (unsigned char)MSG_HELLO) return 0;     // 타입 태그 확인

    size_t off = 1;
    m->ver = in[off++];
    memcpy(m->client_id, in + off, CLIENT_ID_BYTE);      off += CLIENT_ID_BYTE;
    memcpy(m->client_nonce, in + off, NONCE_BYTE);       off += NONCE_BYTE;

    return 1;
}


int encode_challenge(const msg_challenge* m, unsigned char* out, size_t* out_len) {
    if (m == NULL || out == NULL || out_len == NULL) return 0;
    if (*out_len < WIRE_CHALLENGE_BYTE) return 0;

    size_t off = 0;
    out[off++] = (unsigned char)MSG_CHALLENGE;
    memcpy(out + off, m->server_nonce, NONCE_BYTE);      off += NONCE_BYTE;
    memcpy(out + off, m->signature, RSA_MODULUS_BYTE);   off += RSA_MODULUS_BYTE;

    *out_len = off;
    return 1;
}


int decode_challenge(const unsigned char* in, size_t in_len, msg_challenge* m) {
    if (in == NULL || m == NULL) return 0;
    if (in_len != WIRE_CHALLENGE_BYTE) return 0;
    if (in[0] != (unsigned char)MSG_CHALLENGE) return 0;

    size_t off = 1;
    memcpy(m->server_nonce, in + off, NONCE_BYTE);       off += NONCE_BYTE;
    memcpy(m->signature, in + off, RSA_MODULUS_BYTE);    off += RSA_MODULUS_BYTE;

    return 1;
}


int encode_auth(const msg_auth* m, unsigned char* out, size_t* out_len) {
    if (m == NULL || out == NULL || out_len == NULL) return 0;
    if (*out_len < WIRE_AUTH_BYTE) return 0;

    size_t off = 0;
    out[off++] = (unsigned char)MSG_AUTH;
    memcpy(out + off, m->signature, RSA_MODULUS_BYTE);   off += RSA_MODULUS_BYTE;
    memcpy(out + off, m->enc_keys, RSA_MODULUS_BYTE);    off += RSA_MODULUS_BYTE;

    *out_len = off;
    return 1;
}


int decode_auth(const unsigned char* in, size_t in_len, msg_auth* m) {
    if (in == NULL || m == NULL) return 0;
    if (in_len != WIRE_AUTH_BYTE) return 0;
    if (in[0] != (unsigned char)MSG_AUTH) return 0;

    size_t off = 1;
    memcpy(m->signature, in + off, RSA_MODULUS_BYTE);    off += RSA_MODULUS_BYTE;
    memcpy(m->enc_keys, in + off, RSA_MODULUS_BYTE);     off += RSA_MODULUS_BYTE;

    return 1;
}


int encode_auth_ok(const msg_auth_ok* m, unsigned char* out, size_t* out_len) {
    if (m == NULL || out == NULL || out_len == NULL) return 0;
    if (*out_len < WIRE_AUTH_OK_BYTE) return 0;

    size_t off = 0;
    out[off++] = (unsigned char)MSG_AUTH_OK;
    memcpy(out + off, m->nonce, AEAD_NONCE_BYTE);        off += AEAD_NONCE_BYTE;
    memcpy(out + off, m->ciphertext, AUTH_OK_CT_BYTE);   off += AUTH_OK_CT_BYTE;
    memcpy(out + off, m->tag, AEAD_TAG_BYTE);            off += AEAD_TAG_BYTE;

    *out_len = off;
    return 1;
}


int decode_auth_ok(const unsigned char* in, size_t in_len, msg_auth_ok* m) {
    if (in == NULL || m == NULL) return 0;
    if (in_len != WIRE_AUTH_OK_BYTE) return 0;
    if (in[0] != (unsigned char)MSG_AUTH_OK) return 0;

    size_t off = 1;
    memcpy(m->nonce, in + off, AEAD_NONCE_BYTE);         off += AEAD_NONCE_BYTE;
    memcpy(m->ciphertext, in + off, AUTH_OK_CT_BYTE);    off += AUTH_OK_CT_BYTE;
    memcpy(m->tag, in + off, AEAD_TAG_BYTE);             off += AEAD_TAG_BYTE;

    return 1;
}

// --- 세션 컨텍스트 수명주기 ------------------------------------------

// 핸드셰이크 컨텍스트 초기화.
//   - ctx 전체를 0으로 밀어 쓰레기 값을 제거
//   - 넘겨받은 키 포인터를 저장한다. 키의 소유권은 호출자에게 있으며,
//     hs_ctx_free는 이 키들을 해제하지 않음
int hs_ctx_init(handshake_ctx* ctx, EVP_PKEY* self_priv, EVP_PKEY* peer_pub) {
    if (ctx == NULL) return 0;

    memset(ctx, 0, sizeof(*ctx));   // nonce/키 버퍼 0, 포인터 NULL로 정리

    ctx->self_priv = self_priv;     // 자신의 개인키 (서명/복호화용)
    ctx->peer_pub  = peer_pub;      // 상대 공개키 (검증/암호화용)
    ctx->state     = HS_INIT;

    return 1;
}

// 핸드셰이크 컨텍스트 정리.
//   - 핵심은 메모리에 남은 세션 키를 소거하는 것. (따라서, 상위 호출부의 맨 뒤에 사용)
//   - self_priv / peer_pub는 호출자 소유이므로 여기서 해제하지 않고
//     단순히 참조만 끊는다. (세션 간 공유 키를 실수로 free하는 것 방지)
int hs_ctx_free(handshake_ctx* ctx) {
    if (ctx == NULL) return 0;

    OPENSSL_cleanse(ctx->k_c2s, sizeof(ctx->k_c2s));
    OPENSSL_cleanse(ctx->k_s2c, sizeof(ctx->k_s2c));
    OPENSSL_cleanse(ctx->client_nonce, sizeof(ctx->client_nonce));
    OPENSSL_cleanse(ctx->server_nonce, sizeof(ctx->server_nonce));

    // 키는 소유하지 않으므로 해제하지 않고 참조만 끊는다.
    ctx->self_priv = NULL;
    ctx->peer_pub  = NULL;

    ctx->state = HS_INIT;
    return 1;
}


// --- Client 측 처리 ------------------------------------------
//CLIENT_HELLO를 보내는 부분
int client_hello(handshake_ctx* ctx, const unsigned char client_id[CLIENT_ID_BYTE], msg_hello* out) {
    if (ctx == NULL || client_id == NULL || out == NULL) return 0;
    if (ctx->state != HS_INIT) return 0;

    int success = 0;

    // client_id를 자기 ctx에 보관, 이후에도 사용
    memcpy(ctx->client_id, client_id, CLIENT_ID_BYTE);
    if (rand_bytes(ctx->client_nonce, NONCE_BYTE) != 1) goto done;

    // out 데이터 채우기
    out->ver = PROTOCOL_VERSION;
    memcpy(out->client_id, ctx->client_id, CLIENT_ID_BYTE);
    memcpy(out->client_nonce, ctx->client_nonce, NONCE_BYTE);
    ctx->state = HS_HELLO_SENT;

    success = 1;

done:
    if (success == 1) {
        util_log_write(LOG_INFO, "client_hello: HELLO 생성 완료, 핸드셰이크 상태: HS_HELLO_SENT");
    } else {
        if (ctx != NULL) ctx->state = HS_FAILED;
        util_log_write(LOG_ERROR, "client_hello: 실패, 핸드셰이크 상태: HS_FAILED");
    }
    return success;
}

// SERVER_CHALLENGE를 받는 부분
int client_recv_challenge(handshake_ctx* ctx, const msg_challenge* in) {
    if (ctx == NULL || in == NULL) return 0;
    if (ctx->state != HS_HELLO_SENT) return 0;

    int success = 0;

    // server_nonce를 ctx에 보관
    memcpy(ctx->server_nonce, in->server_nonce, NONCE_BYTE);

    // Server에게서 받은 RSA-PSS로 서명된 데이터 검증
    unsigned char to_verify[SIGN2_INPUT_BYTE];
    size_t offset = 0;
    memcpy(to_verify + offset, ctx->client_nonce, NONCE_BYTE);      offset += NONCE_BYTE;
    memcpy(to_verify + offset, ctx->server_nonce, NONCE_BYTE);      offset += NONCE_BYTE;
    memcpy(to_verify + offset, ctx->client_id, CLIENT_ID_BYTE);

    if (rsa_pss_verify(ctx->peer_pub, to_verify, SIGN2_INPUT_BYTE, 
                       in->signature, RSA_MODULUS_BYTE) != 1) goto done;

    ctx->state = HS_CHALLENGED;
    success = 1;

done:
    if (success == 1) {
        util_log_write(LOG_INFO, "client_recv_challenge: 서버 서명 검증 성공, 핸드셰이크 상태: HS_CHALLENGED");
    } else {
        if (ctx != NULL) ctx->state = HS_FAILED;
        util_log_write(LOG_ERROR, "client_recv_challenge: 서버 서명 검증 실패, 핸드셰이크 상태: HS_FAILED");
    }
    return success;
}

// CLIENT_AUTH 전송 및 RSA 키 교환
int client_auth(handshake_ctx* ctx, msg_auth* out,
                unsigned char k_c2s[AEAD_KEY_BYTE], unsigned char k_s2c[AEAD_KEY_BYTE]) {
    if (ctx == NULL || out == NULL || k_c2s == NULL || k_s2c == NULL) return 0;
    if (ctx->state != HS_CHALLENGED) return 0;

    int success = 0;
    unsigned char keys[SESSION_KEYS_BYTE] = {0};

    // Client <-> Server 방향 세션키를 생성하고 자기 ctx에 복사
    if (rand_bytes(ctx->k_c2s, AEAD_KEY_BYTE) != 1 ||
        rand_bytes(ctx->k_s2c, AEAD_KEY_BYTE) != 1) goto done;

    // RSA-PSS 서명 대상 데이터 조립 및 서명
    unsigned char to_sign[SIGN3_INPUT_BYTE];
    size_t offset = 0;
    memcpy(to_sign + offset, ctx->server_nonce, NONCE_BYTE);    offset += NONCE_BYTE;
    memcpy(to_sign + offset, ctx->client_nonce, NONCE_BYTE);
    if (rsa_pss_sign(ctx->self_priv, to_sign, SIGN3_INPUT_BYTE,
                    out->signature, RSA_MODULUS_BYTE) != 1) goto done;

    // 세션키 2개를 이어붙여 RSA-OAEP 암호화
    memcpy(keys, ctx->k_c2s, AEAD_KEY_BYTE);
    memcpy(keys + AEAD_KEY_BYTE, ctx->k_s2c, AEAD_KEY_BYTE);

    size_t enc_len = sizeof(out->enc_keys);
    if (rsa_oaep_encrypt(ctx->peer_pub, keys, SESSION_KEYS_BYTE,
                         out->enc_keys, &enc_len) != 1) goto done;

    // 만들어진 세션키 두 개를 내보냄
    memcpy(k_c2s, ctx->k_c2s, AEAD_KEY_BYTE);
    memcpy(k_s2c, ctx->k_s2c, AEAD_KEY_BYTE);

    ctx->state = HS_AUTHED;
    success = 1;

done:
    OPENSSL_cleanse(keys, sizeof keys);   // 세션키 평문 사본 소거 (성공/실패 공통)
    if (success == 1) {
        util_log_write(LOG_INFO, "client_auth: 서명/세션키 교환 완료, 핸드셰이크 상태: HS_AUTHED");
    } else {
        if (ctx != NULL) ctx->state = HS_FAILED;
        util_log_write(LOG_ERROR, "client_auth: 실패, 핸드셰이크 상태: HS_FAILED");
    }
    return success;
}

// CLIENT_RECV_AUTH_OK: AUTH_OK를 받아 복호화하고 "OK"인지 확인하는 부분
int client_recv_auth_ok(handshake_ctx* ctx, const msg_auth_ok* in) {
    if (ctx == NULL || in == NULL) return 0;
    if (ctx->state != HS_AUTHED) return 0;

    int success = 0;
    unsigned char plaintext[AUTH_OK_CT_BYTE] = {0};

    // AAD는 암호화 측(server_auth_ok)과 완전히 동일하게 재구성해야 한다.
    // 순서: [client_nonce][server_nonce]
    unsigned char aad[NONCE_BYTE + NONCE_BYTE];
    memcpy(aad, ctx->client_nonce, NONCE_BYTE);
    memcpy(aad + NONCE_BYTE, ctx->server_nonce, NONCE_BYTE);

    // nonce는 서버가 실어 보낸 in->nonce를 그대로 사용.
    // 복호화는 server_auth_ok와 같은 방향키(k_s2c)로 수행.
    size_t pt_len = 0;

    if (aead_decrypt(ctx->k_s2c, in->nonce, aad, sizeof aad,
                     in->ciphertext, AUTH_OK_CT_BYTE,
                     plaintext, &pt_len, in->tag) != 1) goto done;

    // 평문이 정확히 "OK"(AUTH_OK_CT_BYTE 바이트)인지 확인.
    const unsigned char expected[] = AUTH_OK_PLAINTEXT;   // {'O','K','\0'}
    if (pt_len != AUTH_OK_CT_BYTE) goto done;
    if (memcmp(plaintext, expected, AUTH_OK_CT_BYTE) != 0) goto done;

    ctx->state = HS_ESTABLISHED;
    success = 1;

done:
    OPENSSL_cleanse(plaintext, sizeof plaintext);
    if (success == 1) {
        util_log_write(LOG_INFO, "client_recv_auth_ok: AUTH_OK 복호화/검증 성공, 핸드셰이크 수립(HS_ESTABLISHED)");
    } else {
        if (ctx != NULL) ctx->state = HS_FAILED;
        util_log_write(LOG_ERROR, "client_recv_auth_ok: AUTH_OK 복호화/검증 실패, 핸드셰이크 상태: HS_FAILED");
    }
    return success;
}


// --- Server 측 처리 ------------------------------------------
// CLIENT_HELLO를 받는 부분
int server_recv_hello(handshake_ctx* ctx, const msg_hello* in) {
    if (ctx == NULL || in == NULL) return 0;
    if (ctx->state != HS_INIT || in->ver != PROTOCOL_VERSION) {
        util_log_write(LOG_WARN, "server_recv_hello: 거부 (핸드셰이크 상태 불일치 또는 프로토콜 버전 불일치)");
        return 0;
    }

    // client_id, nonce를 자기 ctx에 보관, 이후에도 사용
    memcpy(ctx->client_id, in->client_id, CLIENT_ID_BYTE);
    memcpy(ctx->client_nonce, in->client_nonce, NONCE_BYTE);

    ctx->state = HS_HELLO_SENT;
    util_log_write(LOG_INFO, "server_recv_hello: HELLO 수신 처리 완료, 핸드셰이크 상태: HS_HELLO_SENT");
    return 1;
}

// SERVER_CHALLENGE를 보내는 부분
int server_challenge(handshake_ctx* ctx, msg_challenge* out) {
    if (ctx == NULL || out == NULL) return 0;
    if (ctx->state != HS_HELLO_SENT) return 0;

    int success = 0;

    // server nonce 생성, 자기 ctx에 보관
    if (rand_bytes(ctx->server_nonce, NONCE_BYTE) != 1) goto done;
    memcpy(out->server_nonce, ctx->server_nonce, NONCE_BYTE);

    // 서명 대상 데이터 조립 및 서명
    unsigned char to_sign[SIGN2_INPUT_BYTE];
    size_t offset = 0;
    memcpy(to_sign + offset, ctx->client_nonce, NONCE_BYTE);    offset += NONCE_BYTE;
    memcpy(to_sign + offset, ctx->server_nonce, NONCE_BYTE);    offset += NONCE_BYTE;
    memcpy(to_sign + offset, ctx->client_id, CLIENT_ID_BYTE);

    if (rsa_pss_sign(ctx->self_priv, to_sign, SIGN2_INPUT_BYTE,
                    out->signature, RSA_MODULUS_BYTE) != 1) goto done;

    ctx->state = HS_CHALLENGED;
    success = 1;

done:
    if (success == 1) {
        util_log_write(LOG_INFO, "server_challenge: CHALLENGE 서명 생성 완료, 핸드셰이크 상태: HS_CHALLENGED");
    } else {
        if (ctx != NULL) ctx->state = HS_FAILED;
        util_log_write(LOG_ERROR, "server_challenge: 실패, 핸드셰이크 상태: HS_FAILED");
    }
    return success;
}

// CLIENT_AUTH 수신 및 RSA 키 교환 (복호화한 키 두 개를 호출자 버퍼로 내보냄)
int server_recv_auth(handshake_ctx* ctx, const msg_auth* in,
                     unsigned char k_c2s[AEAD_KEY_BYTE], unsigned char k_s2c[AEAD_KEY_BYTE]) {
    if (ctx == NULL || in == NULL || k_c2s == NULL || k_s2c == NULL) return 0;
    if (ctx->state != HS_CHALLENGED) return 0;

    int success = 0;
    unsigned char keys[SESSION_KEYS_BYTE] = {0};

    // RSA-PSS 서명 검증
    unsigned char to_verify[SIGN3_INPUT_BYTE];
    size_t offset = 0;
    memcpy(to_verify + offset, ctx->server_nonce, NONCE_BYTE);  offset += NONCE_BYTE;
    memcpy(to_verify + offset, ctx->client_nonce, NONCE_BYTE);

    if (rsa_pss_verify(ctx->peer_pub, to_verify, SIGN3_INPUT_BYTE,
                       in->signature, RSA_MODULUS_BYTE) != 1) goto done;

    // RSA-OAEP로 세션키 복호화
    size_t keys_len = sizeof keys;
    if (rsa_oaep_decrypt(ctx->self_priv, in->enc_keys, RSA_MODULUS_BYTE,
                         keys, &keys_len) != 1 || keys_len != SESSION_KEYS_BYTE) goto done;

    memcpy(ctx->k_c2s, keys, AEAD_KEY_BYTE);
    memcpy(ctx->k_s2c, keys + AEAD_KEY_BYTE, AEAD_KEY_BYTE);

    // 만들어진 세션키 두 개를 내보냄
    memcpy(k_c2s, ctx->k_c2s, AEAD_KEY_BYTE);
    memcpy(k_s2c, ctx->k_s2c, AEAD_KEY_BYTE);

    ctx->state = HS_AUTHED;
    success = 1;

done:
    OPENSSL_cleanse(keys, sizeof keys);   // 세션키 평문 사본 소거 (성공/실패 공통)
    if (success == 1) {
        util_log_write(LOG_INFO, "server_recv_auth: 클라 서명 검증/세션키 복호화 성공, 핸드셰이크 상태: HS_AUTHED");
    } else {
        if (ctx != NULL) ctx->state = HS_FAILED;
        util_log_write(LOG_ERROR, "server_recv_auth: 클라 서명 검증 또는 세션키 복호화 실패, 핸드셰이크 상태: HS_FAILED");
    }
    return success;
}

// SERVER_AUTH_OK를 보내는 부분
int server_auth_ok(handshake_ctx* ctx, msg_auth_ok* out) {
    if (ctx == NULL || out == NULL) return 0;
    if (ctx->state != HS_AUTHED) return 0;

    int success = 0;

    // AUTH_OK 평문: "OK"
    // nonce: 랜덤 생성해서 암호문과 태그에 같이 실어 보냄
    // AAD: [client_nonce][server_nonce]
    unsigned char aad[NONCE_BYTE + NONCE_BYTE];
    memcpy(aad, ctx->client_nonce, NONCE_BYTE);
    memcpy(aad + NONCE_BYTE, ctx->server_nonce, NONCE_BYTE);

    unsigned char nonce[AEAD_NONCE_BYTE];
    if (rand_bytes(nonce, AEAD_NONCE_BYTE) != 1) goto done;

    const unsigned char plaintext[] = AUTH_OK_PLAINTEXT;
    unsigned char tag[AEAD_TAG_BYTE] = {0};
    unsigned char ciphertext[AUTH_OK_CT_BYTE] = {0};
    size_t ct_len = 0;

    // 암호화 수행(k_s2c 사용)
    // 평문 길이는 널 종단 문자를 뺀 AUTH_OK_CT_BYTE(2). sizeof plaintext(3)를
    // 쓰면 암호문이 ciphertext 버퍼(AUTH_OK_CT_BYTE)를 넘겨 오버플로우가 난다.
    if (aead_encrypt(ctx->k_s2c, nonce, aad, sizeof aad,
                     plaintext, AUTH_OK_CT_BYTE, ciphertext, &ct_len, tag) != 1) goto done;

    // 데이터 내보내기
    memcpy(out->nonce, nonce, AEAD_NONCE_BYTE);
    memcpy(out->ciphertext, ciphertext, ct_len);
    memcpy(out->tag, tag, AEAD_TAG_BYTE);

    ctx->state = HS_ESTABLISHED;
    success = 1;

done:
    if (success == 1) {
        util_log_write(LOG_INFO, "server_auth_ok: AUTH_OK 암호화 완료, 핸드셰이크 수립(HS_ESTABLISHED)");
    } else {
        if (ctx != NULL) ctx->state = HS_FAILED;
        util_log_write(LOG_ERROR, "server_auth_ok: AUTH_OK 암호화 실패, 핸드셰이크 상태: HS_FAILED");
    }
    return success;
}


// ===== 게임 프로토콜 패킷 프레이밍 =====

// 8바이트 big-endian 쓰기/읽기
static void put_u64_be(unsigned char* p, unsigned long long v) {
    for (int i = 7; i >= 0; i--) { p[i] = (unsigned char)(v & 0xFF); v >>= 8; }
}
static unsigned long long get_u64_be(const unsigned char* p) {
    unsigned long long v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static void put_u32_be(unsigned char* p, unsigned int v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)(v & 0xFF);
}
static unsigned int get_u32_be(const unsigned char* p) {
    return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
           ((unsigned int)p[2] << 8)  | (unsigned int)p[3];
}

// AAD = type(1B) || seq(8B) || sender_id(CLIENT_ID_BYTE)
static void build_aad(unsigned char* aad, unsigned char type,
                      unsigned long long seq, const unsigned char* sender_id) {
    aad[0] = type;
    put_u64_be(aad + PKT_TYPE_BYTE, seq);
    memcpy(aad + PKT_TYPE_BYTE + PKT_SEQ_BYTE, sender_id, CLIENT_ID_BYTE);
}

int sec_channel_init(sec_channel* ch, int is_server,
                     const unsigned char k_c2s[AEAD_KEY_BYTE],
                     const unsigned char k_s2c[AEAD_KEY_BYTE],
                     const unsigned char self_id[CLIENT_ID_BYTE],
                     const unsigned char peer_id[CLIENT_ID_BYTE]) {
    if (ch == NULL || k_c2s == NULL || k_s2c == NULL ||
        self_id == NULL || peer_id == NULL) return 0;

    // 서버는 s2c로 보내고 c2s로 받는다. 클라는 그 반대.
    if (is_server) {
        memcpy(ch->k_tx, k_s2c, AEAD_KEY_BYTE);
        memcpy(ch->k_rx, k_c2s, AEAD_KEY_BYTE);
    } else {
        memcpy(ch->k_tx, k_c2s, AEAD_KEY_BYTE);
        memcpy(ch->k_rx, k_s2c, AEAD_KEY_BYTE);
    }
    memcpy(ch->self_id, self_id, CLIENT_ID_BYTE);
    memcpy(ch->peer_id, peer_id, CLIENT_ID_BYTE);
    ch->tx_seq = 0;
    ch->rx_seq = 0;
    return 1;
}

void sec_channel_free(sec_channel* ch) {
    if (ch == NULL) return;
    OPENSSL_cleanse(ch->k_tx, sizeof ch->k_tx);
    OPENSSL_cleanse(ch->k_rx, sizeof ch->k_rx);
    ch->tx_seq = 0;
    ch->rx_seq = 0;
}

int packet_seal(sec_channel* ch, unsigned char type,
                const unsigned char* plaintext, size_t plaintext_len,
                unsigned char* out, size_t* out_len) {
    if (ch == NULL || out == NULL || out_len == NULL) return 0;
    if (plaintext_len > PKT_MAX_PLAINTEXT) return 0;
    if (plaintext_len > 0 && plaintext == NULL) return 0;

    size_t need = PKT_LEN_BYTE + PKT_MIN_BODY_BYTE + plaintext_len;
    if (*out_len < need) return 0;

    unsigned long long seq = ch->tx_seq + 1;

    unsigned char nonce[AEAD_NONCE_BYTE];
    if (rand_bytes(nonce, AEAD_NONCE_BYTE) != 1) return 0;

    unsigned char aad[PKT_AAD_BYTE];
    build_aad(aad, type, seq, ch->self_id);

    // 레이아웃: len(4) | type(1) | seq(8) | nonce(12) | ct | tag(16)
    unsigned char* p_type  = out + PKT_LEN_BYTE;
    unsigned char* p_seq   = p_type + PKT_TYPE_BYTE;
    unsigned char* p_nonce = p_seq + PKT_SEQ_BYTE;
    unsigned char* p_ct    = p_nonce + AEAD_NONCE_BYTE;
    unsigned char* p_tag   = p_ct + plaintext_len;

    *p_type = type;
    put_u64_be(p_seq, seq);
    memcpy(p_nonce, nonce, AEAD_NONCE_BYTE);

    size_t ct_len = 0;
    if (aead_encrypt(ch->k_tx, nonce, aad, sizeof aad,
                     plaintext, plaintext_len, p_ct, &ct_len, p_tag) != 1)
        return 0;
    if (ct_len != plaintext_len) return 0;

    unsigned int body = (unsigned int)(PKT_MIN_BODY_BYTE + plaintext_len);
    put_u32_be(out, body);

    *out_len = PKT_LEN_BYTE + body;
    ch->tx_seq = seq;   // 성공 후에만 증가

    util_log_write(LOG_DEBUG, "packet_seal: type=0x%02X seq=%llu len=%zu",
                   type, seq, *out_len);
    return 1;
}

int packet_open(sec_channel* ch,
                const unsigned char* in, size_t in_len,
                unsigned char* out_type,
                unsigned char* plaintext, size_t* plaintext_len) {
    if (ch == NULL || in == NULL || plaintext_len == NULL) return 0;
    if (in_len < PKT_LEN_BYTE + PKT_MIN_BODY_BYTE) return 0;

    unsigned int body = get_u32_be(in);
    if ((size_t)body + PKT_LEN_BYTE != in_len) return 0;          // 길이 불일치
    if (body < PKT_MIN_BODY_BYTE) return 0;

    size_t ct_len = body - PKT_MIN_BODY_BYTE;
    if (ct_len > PKT_MAX_PLAINTEXT) return 0;
    if (*plaintext_len < ct_len) return 0;

    const unsigned char* p_type  = in + PKT_LEN_BYTE;
    const unsigned char* p_seq   = p_type + PKT_TYPE_BYTE;
    const unsigned char* p_nonce = p_seq + PKT_SEQ_BYTE;
    const unsigned char* p_ct    = p_nonce + AEAD_NONCE_BYTE;
    const unsigned char* p_tag   = p_ct + ct_len;

    unsigned char type = *p_type;
    unsigned long long seq = get_u64_be(p_seq);

    // 재전송 방어: seq가 직전 수용 값 이하이면 폐기
    if (seq <= ch->rx_seq) {
        util_log_write(LOG_WARN, "packet_open: 재전송 의심 seq=%llu (last=%llu), 폐기",
                       seq, ch->rx_seq);
        return 0;
    }

    // AAD는 상대 sender_id로 재구성 (헤더 변조 시 태그 검증 실패)
    unsigned char aad[PKT_AAD_BYTE];
    build_aad(aad, type, seq, ch->peer_id);

    size_t pt_len = *plaintext_len;
    if (aead_decrypt(ch->k_rx, p_nonce, aad, sizeof aad,
                     p_ct, ct_len, plaintext, &pt_len, p_tag) != 1) {
        util_log_write(LOG_WARN, "packet_open: 태그 검증/복호화 실패 (type=0x%02X seq=%llu)",
                       type, seq);
        return 0;
    }

    ch->rx_seq = seq;   // 검증 성공 후에만 갱신
    if (out_type != NULL) *out_type = type;
    *plaintext_len = pt_len;

    util_log_write(LOG_DEBUG, "packet_open: type=0x%02X seq=%llu plaintext=%zu",
                   type, seq, pt_len);
    return 1;
}


// ===== 소켓 I/O 헬퍼 =====

int io_write_all(int fd, const unsigned char* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) { if (errno == EINTR) continue; return 0; }
        if (n == 0) return 0;
        off += (size_t)n;
    }
    return 1;
}

int io_read_all(int fd, unsigned char* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) { if (errno == EINTR) continue; return 0; }
        if (n == 0) return 0;   // 상대가 연결 종료
        off += (size_t)n;
    }
    return 1;
}

int io_write_blob(int fd, const unsigned char* data, size_t len) {
    if (data == NULL && len > 0) return 0;
    unsigned char hdr[4];
    put_u32_be(hdr, (unsigned int)len);
    if (io_write_all(fd, hdr, 4) != 1) return 0;
    if (len > 0 && io_write_all(fd, data, len) != 1) return 0;
    return 1;
}

int io_read_blob(int fd, unsigned char* buf, size_t* len) {
    if (buf == NULL || len == NULL) return 0;
    unsigned char hdr[4];
    if (io_read_all(fd, hdr, 4) != 1) return 0;
    unsigned int n = get_u32_be(hdr);
    if (n > *len) return 0;             // 버퍼 용량 초과
    if (n > 0 && io_read_all(fd, buf, n) != 1) return 0;
    *len = n;
    return 1;
}

int io_write_packet(int fd, const unsigned char* pkt, size_t pkt_len) {
    if (pkt == NULL || pkt_len < PKT_LEN_BYTE) return 0;
    return io_write_all(fd, pkt, pkt_len);   // 패킷 선두에 이미 len 필드 포함
}

int io_read_packet(int fd, unsigned char* buf, size_t* len) {
    if (buf == NULL || len == NULL) return 0;
    if (*len < PKT_LEN_BYTE) return 0;
    // 선두 4B len 필드 읽기
    if (io_read_all(fd, buf, PKT_LEN_BYTE) != 1) return 0;
    unsigned int body = get_u32_be(buf);
    size_t total = (size_t)PKT_LEN_BYTE + body;
    if (total > *len || body == 0) return 0;
    if (io_read_all(fd, buf + PKT_LEN_BYTE, body) != 1) return 0;
    *len = total;
    return 1;
}
