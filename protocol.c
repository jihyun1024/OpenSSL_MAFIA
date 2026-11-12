#include "protocol.h"

#include <string.h>   
#include <stddef.h>   


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
    if (success != 1 && ctx != NULL) ctx->state = HS_FAILED;
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
    if (success != 1 && ctx != NULL) ctx->state = HS_FAILED;
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
    if (success != 1 && ctx != NULL) ctx->state = HS_FAILED;
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
    if (success != 1 && ctx != NULL) ctx->state = HS_FAILED;
    return success;
}


// --- Server 측 처리 ------------------------------------------
// CLIENT_HELLO를 받는 부분
int server_recv_hello(handshake_ctx* ctx, const msg_hello* in) {
    if (ctx == NULL || in == NULL) return 0;
    if (ctx->state != HS_INIT || in->ver != PROTOCOL_VERSION) return 0;

    // client_id, nonce를 자기 ctx에 보관, 이후에도 사용
    memcpy(ctx->client_id, in->client_id, CLIENT_ID_BYTE);
    memcpy(ctx->client_nonce, in->client_nonce, NONCE_BYTE);

    ctx->state = HS_HELLO_SENT;
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
    if (success != 1 && ctx != NULL) ctx->state = HS_FAILED;
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
    if (success != 1 && ctx != NULL) ctx->state = HS_FAILED;
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
    if (success != 1 && ctx != NULL) ctx->state = HS_FAILED;
    return success;
}