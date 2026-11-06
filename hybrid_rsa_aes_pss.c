/* OpenSSL 3.x: RSA-OAEP + AES-256-GCM + RSA-PSS demo */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#define KEY_LEN 32
#define NONCE_LEN 12
#define TAG_LEN 16

typedef struct {
    unsigned char *wrapped_key, *ciphertext, *signature;
    size_t wrapped_len, ciphertext_len, signature_len;
    unsigned char nonce[NONCE_LEN], tag[TAG_LEN];
} Envelope;

static void dump_error(void) { ERR_print_errors_fp(stderr); }
static void free_envelope(Envelope *e) {
    free(e->wrapped_key); free(e->ciphertext); free(e->signature);
    memset(e, 0, sizeof(*e));
}
static EVP_PKEY *make_rsa_key(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY *key = NULL;
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0) {
        if (key != NULL) EVP_PKEY_free(key); 
        key = NULL;
    }
    if (ctx != NULL) EVP_PKEY_CTX_free(ctx);
    return key;
}
static int configure_oaep(EVP_PKEY_CTX *ctx) {
    return EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0 &&
           EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) > 0 &&
           EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) > 0;
}
static int wrap_key(EVP_PKEY *recipient_pub, const unsigned char aes_key[KEY_LEN], Envelope *e) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(recipient_pub, NULL);
    int ok = ctx && EVP_PKEY_encrypt_init(ctx) > 0 && configure_oaep(ctx) &&
        EVP_PKEY_encrypt(ctx, NULL, &e->wrapped_len, aes_key, KEY_LEN) > 0;
    if (ok) {
        e->wrapped_key = malloc(e->wrapped_len);
        ok = e->wrapped_key && EVP_PKEY_encrypt(ctx, e->wrapped_key,
                      &e->wrapped_len, aes_key, KEY_LEN) > 0;
    }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}
static int unwrap_key(EVP_PKEY *recipient_private, const Envelope *e,
                      unsigned char aes_key[KEY_LEN]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(recipient_private, NULL);
    unsigned char *tmp = NULL;
    size_t len = 0;
    int ok = ctx && EVP_PKEY_decrypt_init(ctx) > 0 && configure_oaep(ctx) &&
        EVP_PKEY_decrypt(ctx, NULL, &len, e->wrapped_key, e->wrapped_len) > 0;
    size_t cap = len;
    if (ok) {
        tmp = malloc(cap);
        ok = tmp && EVP_PKEY_decrypt(ctx, tmp, &len, e->wrapped_key,
                                     e->wrapped_len) > 0 && len == KEY_LEN;
    }
    if (ok) memcpy(aes_key, tmp, KEY_LEN);
    if (tmp) { OPENSSL_cleanse(tmp, cap); free(tmp); }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}
static int encrypt_gcm(const unsigned char *data, size_t n,
                       const unsigned char key[KEY_LEN], Envelope *e) {
    if (n > INT_MAX) return 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, fin = 0;
    e->ciphertext = malloc(n ? n : 1);
    int ok = ctx && e->ciphertext && RAND_bytes(e->nonce, NONCE_LEN) == 1 &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, e->nonce) == 1 &&
        EVP_EncryptUpdate(ctx, e->ciphertext, &len, data, (int)n) == 1;
    if (ok) {
        e->ciphertext_len = (size_t)len;
        ok = EVP_EncryptFinal_ex(ctx, e->ciphertext + len, &fin) == 1;
    }
    if (ok) {
        e->ciphertext_len += (size_t)fin;
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, e->tag) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
static int decrypt_gcm(const Envelope *e, const unsigned char key[KEY_LEN],
                       unsigned char **out, size_t *out_len) {
    if (e->ciphertext_len > INT_MAX) return 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *buf = malloc(e->ciphertext_len + 1);
    int len = 0, fin = 0;
    int ok = ctx && buf && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
                   key, e->nonce) == 1 &&
        EVP_DecryptUpdate(ctx, buf, &len, e->ciphertext,
                          (int)e->ciphertext_len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                            (void *)e->tag) == 1 &&
        EVP_DecryptFinal_ex(ctx, buf + len, &fin) == 1;
    if (ok) {
        *out_len = (size_t)len + (size_t)fin;
        buf[*out_len] = '\0';
        *out = buf;
    } else if (buf) {
        OPENSSL_cleanse(buf, e->ciphertext_len + 1);
        free(buf);
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
/* Canonical encoding: domain separator + 64-bit lengths + payload fields.
   Includes all ciphertext metadata in signature. */
static void be64(unsigned char out[8], uint64_t n) {
    for (int i = 7; i >= 0; --i) { out[i] = (unsigned char)n; n >>= 8; }
}
static int sign_parts(EVP_MD_CTX *ctx, const Envelope *e) {
    unsigned char sizes[16];
    const unsigned char domain[] = "HYBRID-DEMO-V1";
    be64(sizes, (uint64_t)e->wrapped_len);
    be64(sizes + 8, (uint64_t)e->ciphertext_len);
    return EVP_DigestSignUpdate(ctx, domain, sizeof(domain)) == 1 &&
        EVP_DigestSignUpdate(ctx, sizes, sizeof(sizes)) == 1 &&
        EVP_DigestSignUpdate(ctx, e->wrapped_key, e->wrapped_len) == 1 &&
        EVP_DigestSignUpdate(ctx, e->nonce, NONCE_LEN) == 1 &&
        EVP_DigestSignUpdate(ctx, e->ciphertext, e->ciphertext_len) == 1 &&
        EVP_DigestSignUpdate(ctx, e->tag, TAG_LEN) == 1;
}
static int verify_parts(EVP_MD_CTX *ctx, const Envelope *e) {
    unsigned char sizes[16];
    const unsigned char domain[] = "HYBRID-DEMO-V1";
    be64(sizes, (uint64_t)e->wrapped_len);
    be64(sizes + 8, (uint64_t)e->ciphertext_len);
    return EVP_DigestVerifyUpdate(ctx, domain, sizeof(domain)) == 1 &&
        EVP_DigestVerifyUpdate(ctx, sizes, sizeof(sizes)) == 1 &&
        EVP_DigestVerifyUpdate(ctx, e->wrapped_key, e->wrapped_len) == 1 &&
        EVP_DigestVerifyUpdate(ctx, e->nonce, NONCE_LEN) == 1 &&
        EVP_DigestVerifyUpdate(ctx, e->ciphertext, e->ciphertext_len) == 1 &&
        EVP_DigestVerifyUpdate(ctx, e->tag, TAG_LEN) == 1;
}
static int config_pss(EVP_PKEY_CTX *pkctx) {
    return EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, RSA_PSS_SALTLEN_DIGEST) > 0;
}
static int sign_envelope(EVP_PKEY *sender_private, Envelope *e) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pkctx = NULL;
    int ok = ctx && EVP_DigestSignInit(ctx, &pkctx, EVP_sha256(), NULL,
                                      sender_private) == 1 && config_pss(pkctx) &&
             sign_parts(ctx, e) && EVP_DigestSignFinal(ctx, NULL,
                                                     &e->signature_len) == 1;
    if (ok) {
        e->signature = malloc(e->signature_len);
        ok = e->signature && EVP_DigestSignFinal(ctx, e->signature,
                                                &e->signature_len) == 1;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}
static int verify_envelope(EVP_PKEY *sender_pub, const Envelope *e) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pkctx = NULL;
    int ok = ctx && EVP_DigestVerifyInit(ctx, &pkctx, EVP_sha256(), NULL,
                                        sender_pub) == 1 && config_pss(pkctx) &&
             verify_parts(ctx, e) && EVP_DigestVerifyFinal(ctx, e->signature,
                                              e->signature_len) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}
static void hex_start(const char *name, const unsigned char *p, size_t len) {
    printf("%s (%zu B): ", name, len);
    for (size_t i = 0; i < len && i < 16; ++i) printf("%02X", p[i]);
    if (len > 16) printf("...");
    putchar('\n');
}
int main(void) {
    const unsigned char message[] = "Hello hybrid encryption and RSA-PSS!";
    Envelope env = {0};
    EVP_PKEY *recipient = NULL, *sender = NULL;
    unsigned char aes_key[KEY_LEN] = {0}, recovered_key[KEY_LEN] = {0};
    unsigned char *decoded = NULL;
    size_t decoded_len = 0;
    int ok = 0;

    recipient = make_rsa_key();  /* Receiver's private/public pair */
    sender = make_rsa_key();     /* Sender's signing private/public pair */
    if (!recipient || !sender || RAND_bytes(aes_key, KEY_LEN) != 1) goto cleanup;
    if (!wrap_key(recipient, aes_key, &env) ||
        !encrypt_gcm(message, sizeof(message)-1, aes_key, &env) ||
        !sign_envelope(sender, &env)) goto cleanup;
    printf("[Sender] message: %s\n", message);
    hex_start("Wrapped AES key", env.wrapped_key, env.wrapped_len);
    hex_start("GCM nonce", env.nonce, NONCE_LEN);
    hex_start("Ciphertext", env.ciphertext, env.ciphertext_len);
    hex_start("GCM tag", env.tag, TAG_LEN);
    hex_start("RSA-PSS signature", env.signature, env.signature_len);

    /* Receiver MUST verify signature before decrypting. */
    if (!verify_envelope(sender, &env)) { puts("Signature: FAIL"); goto cleanup; }
    puts("Signature: SUCCESS");
    if (!unwrap_key(recipient, &env, recovered_key) ||
        !decrypt_gcm(&env, recovered_key, &decoded, &decoded_len)) goto cleanup;
    printf("[Receiver] plaintext: %.*s\n", (int)decoded_len, decoded);
    if (decoded_len != sizeof(message)-1 ||
        memcmp(decoded, message, decoded_len) != 0) goto cleanup;
    puts("Decryption: SUCCESS");

    /* Demonstrate integrity: changing one bit breaks RSA-PSS signature. */
    env.ciphertext[0] ^= 1;
    printf("Tampered ciphertext signature check: %s\n",
           verify_envelope(sender, &env) ? "UNEXPECTED SUCCESS" : "FAIL (expected)");
    env.ciphertext[0] ^= 1;
    ok = 1;
cleanup:
    if (!ok) dump_error();
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    OPENSSL_cleanse(recovered_key, sizeof(recovered_key));
    if (decoded) { OPENSSL_cleanse(decoded, decoded_len + 1); free(decoded); }
    free_envelope(&env);
    EVP_PKEY_free(recipient);
    EVP_PKEY_free(sender);
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
