#include <string.h>
#include <stdio.h>
#include <limits.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include "crypto.h"


// 디버깅용 16진수 프린트 함수
static void hexprint(const unsigned char* p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02X", p[i]);
    printf("\n");
}

// PBKDF2로 사용자 패스워드를 키로 변환
int pbkdf2_derive_key(
    const unsigned char* password, size_t password_len, 
    const unsigned char salt[PBKDF2_SALT_BYTE], 
    unsigned char key_out[PBKDF2_KEY_BYTE]
) {
    EVP_KDF* kdf = NULL;
    EVP_KDF_CTX* ctx = NULL;
    unsigned int iterations = PBKDF2_ITERATIONS;
    int success = 0;

    if (key_out == NULL) return 0;
    if (password == NULL || salt == NULL)       goto done;

    kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);  if (kdf == NULL) goto done;
    ctx = EVP_KDF_CTX_new(kdf);                 if (ctx == NULL) goto done;
    char digest[] = "SHA256";

    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD, (void*)password, password_len),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, (void*)salt, PBKDF2_SALT_BYTE),
        OSSL_PARAM_construct_uint(
            OSSL_KDF_PARAM_ITER, &iterations),
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end()
    };

    success = EVP_KDF_derive(ctx, key_out, PBKDF2_KEY_BYTE, p) == 1;

done:
    if (!success && key_out != NULL)
        OPENSSL_cleanse(key_out, PBKDF2_KEY_BYTE);
    if (ctx != NULL) EVP_KDF_CTX_free(ctx);
    if (kdf != NULL) EVP_KDF_free(kdf);
    return success;
}


// AEAD로 암호화 + 인증 (패킷 헤더 정보 || 사용자 식별자 정보를 AAD로)
int aead_encrypt(
    const unsigned char key[AEAD_KEY_BYTE],
    const unsigned char nonce[AEAD_NONCE_BYTE],
    const unsigned char* aad, size_t aad_len,
    const unsigned char* plaintext, size_t plaintext_len,
    unsigned char* ciphertext, size_t* ciphertext_len,
    unsigned char tag_out[AEAD_TAG_BYTE]
) {
    EVP_CIPHER* cipher = NULL;
    EVP_CIPHER_CTX* ctx = NULL;
    unsigned char final_buf[EVP_MAX_BLOCK_LENGTH];
    int len = 0;
    int final_len = 0;
    size_t produced = 0;
    int success = 0;

    if (ciphertext_len == NULL)
        return 0;
    *ciphertext_len = 0;

    if (key == NULL || nonce == NULL || tag_out == NULL ||
        (aad_len > 0 && aad == NULL) ||
        (plaintext_len > 0 && (plaintext == NULL || ciphertext == NULL)))
        goto done;

    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if (cipher == NULL ||
        EVP_CIPHER_get_mode(cipher) != EVP_CIPH_GCM_MODE ||
        EVP_CIPHER_get_key_length(cipher) != AEAD_KEY_BYTE ||
        EVP_CIPHER_get_iv_length(cipher) != AEAD_NONCE_BYTE)
        goto done;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, cipher, NULL, key, nonce) != 1)
        goto done;

    if (aad_len > 0 &&
        EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
        goto done;

    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(
                ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1 ||
            len < 0 || (size_t)len > plaintext_len)
            goto done;

        produced = (size_t)len;
    }

    if (EVP_EncryptFinal_ex(ctx, final_buf, &final_len) != 1 ||
        final_len < 0 || (size_t)final_len > plaintext_len - produced)
        goto done;

    if (final_len > 0) {
        if (ciphertext == NULL)
            goto done;
        memcpy(ciphertext + produced, final_buf, (size_t)final_len);
        produced += (size_t)final_len;
    }

    if (produced != plaintext_len ||
        EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_GET_TAG, AEAD_TAG_BYTE, tag_out) != 1)
        goto done;

    *ciphertext_len = produced;
    success = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return success;
}


// AEAD로 복호화
int aead_decrypt(
    const unsigned char key[AEAD_KEY_BYTE],
    const unsigned char nonce[AEAD_NONCE_BYTE],
    const unsigned char* aad, size_t aad_len,
    const unsigned char* ciphertext, size_t ciphertext_len,
    unsigned char* plaintext, size_t* plaintext_len,
    const unsigned char tag[AEAD_TAG_BYTE]
) {
    EVP_CIPHER* cipher = NULL;
    EVP_CIPHER_CTX* ctx = NULL;
    unsigned char final_buf[EVP_MAX_BLOCK_LENGTH];
    unsigned char tag_copy[AEAD_TAG_BYTE];
    int len = 0;
    int final_len = 0;
    size_t produced = 0;
    int success = 0;

    if (plaintext_len == NULL) return 0;
    *plaintext_len = 0;

    if (key == NULL || nonce == NULL || tag == NULL || 
        (aad_len > 0 && aad == NULL) ||
        (ciphertext_len > 0 && (ciphertext == NULL || plaintext == NULL)))
        goto done;

    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if (cipher == NULL ||
        EVP_CIPHER_get_mode(cipher) != EVP_CIPH_GCM_MODE ||
        EVP_CIPHER_get_key_length(cipher) != AEAD_KEY_BYTE ||
        EVP_CIPHER_get_iv_length(cipher) != AEAD_NONCE_BYTE)
        goto done;

    ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, nonce) != 1)
        goto done;

    if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
        goto done;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1 ||
        len < 0 || (size_t)len > ciphertext_len)
        goto done;

    produced = (size_t)len;

    memcpy(tag_copy, tag, sizeof tag_copy);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AEAD_TAG_BYTE, tag_copy) != 1)
        goto done;

    if (EVP_DecryptFinal_ex(ctx, final_buf, &final_len) != 1 ||
        final_len < 0 || (size_t)final_len > ciphertext_len - produced)
        goto done;

    if (plaintext == NULL)  goto done;
    memcpy(plaintext + produced, final_buf, (size_t)final_len);
    produced += (size_t)final_len;    

    if (produced != ciphertext_len)
        goto done;

    *plaintext_len = produced;
    success = 1;

done:
    if (!success) {
        if (plaintext_len != NULL)
            *plaintext_len = 0;
    }
    OPENSSL_cleanse(final_buf, sizeof final_buf);
    OPENSSL_cleanse(tag_copy, sizeof tag_copy);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return success;
}


// RSA-OAEP로 안전하게 세션키 암호화
int rsa_oaep_encrypt(
    EVP_PKEY* public_key,
    const unsigned char* plaintext, size_t plaintext_len,
    unsigned char* ciphertext, size_t* ciphertext_len
) {
    EVP_PKEY_CTX* ctx = NULL;
    size_t output_len;
    int success = 0;

    if (ciphertext_len == NULL)
        return 0;
    *ciphertext_len = 0;

    if (public_key == NULL || ciphertext == NULL ||
        (plaintext_len > 0 && plaintext == NULL))
        return 0;

    ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 || 
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 || 
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 || 
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        goto done;
    }

    output_len = *ciphertext_len;
    if (EVP_PKEY_encrypt(ctx, ciphertext, &output_len, plaintext, plaintext_len) <= 0) {
        goto done;
    }

    *ciphertext_len = output_len;
    success = 1;
done:
    EVP_PKEY_CTX_free(ctx);
    return success;
}


// RSA-OAEP로 복호화
int rsa_oaep_decrypt(
    EVP_PKEY* private_key,
    const unsigned char* ciphertext, size_t ciphertext_len,
    unsigned char* plaintext, size_t* plaintext_len
) {
    EVP_PKEY_CTX* ctx = NULL;
    unsigned char* decrypted = NULL;
    size_t capacity;
    size_t output_len;
    int max_output_len;
    int success = 0;

    if (plaintext_len == NULL)
        return 0;
    capacity = *plaintext_len;
    *plaintext_len = 0;

    if (private_key == NULL || ciphertext == NULL || plaintext == NULL ||
        ciphertext_len == 0 || capacity == 0)
        return 0;

    max_output_len = EVP_PKEY_get_size(private_key);
    if (max_output_len <= 0)
        return 0;

    decrypted = OPENSSL_malloc((size_t)max_output_len);
    if (decrypted == NULL)
        return 0;

    ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 || 
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        goto done;
    }

    output_len = (size_t)max_output_len;
    if (EVP_PKEY_decrypt(ctx, decrypted, &output_len, ciphertext, ciphertext_len) <= 0 ||
        output_len > capacity) {
        goto done;
    }

    memcpy(plaintext, decrypted, output_len);
    *plaintext_len = output_len;
    success = 1;

done:
    OPENSSL_clear_free(decrypted, (size_t)(max_output_len > 0 ? max_output_len : 0));
    EVP_PKEY_CTX_free(ctx);
    return success;
}  


// RSA-PSS로 전자서명
int rsa_pss_sign(
    EVP_PKEY* private_key, 
    const unsigned char* message, size_t message_len,
    unsigned char* signature, size_t signature_len
) {

}


// RSA-PSS로 검증
int rsa_pss_verify(
    EVP_PKEY* public_key,
    const unsigned char* message, size_t message_len,
    const unsigned char* signature, size_t signature_len
) {
    
}


// RSA-PSS 동작 확인용 (RSA-OAEP에서 키쌍 제외 코드만 수정해서)
int main() {
    EVP_PKEY_CTX* keyctx = NULL;
    EVP_PKEY* key = NULL;
    unsigned char session_key[PBKDF2_KEY_BYTE] = {0};
    unsigned char ciphertext[RSA_MODULUS_BYTE] = {0};
    unsigned char pt[PBKDF2_KEY_BYTE] = {0};
    size_t ct_len = sizeof ciphertext;
    size_t pt_len = sizeof pt;
    int result = 1;

    if (RAND_bytes(session_key, PBKDF2_KEY_BYTE) != 1) {
        fprintf(stderr, "Session Key generation Failed");
        goto done;
    }

    // 공개키-개인키 쌍 생성 (RSA-OAEP 코드에는 없기 때문)
    keyctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!keyctx || EVP_PKEY_keygen_init(keyctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(keyctx, RSA_KEY_BIT) <= 0 || 
        EVP_PKEY_keygen(keyctx, &key) <= 0) {
        fprintf(stderr, "RSA 3072-bit key pair has not generated");
        goto done;
    }

    if (rsa_oaep_encrypt(key, session_key, PBKDF2_KEY_BYTE, ciphertext, &ct_len) != 1) {
        fprintf(stderr, "RSA-OAEP encryption Failed");
        goto done;
    }

    printf("RSA-OAEP ENCRYPTION SUCCESS!!!!\n");
    printf("\nCIPHERTEXT: "); hexprint(ciphertext, ct_len);
    printf("\nORIGINAL: "); hexprint(session_key, PBKDF2_KEY_BYTE);

    if (rsa_oaep_decrypt(key, ciphertext, ct_len, pt, &pt_len) != 1) {
        fprintf(stderr, "RSA-OAEP decryption Failed");
        goto done;
    }
    if (pt_len != sizeof session_key ||
        CRYPTO_memcmp(pt, session_key, sizeof session_key) != 0) {
        fprintf(stderr, "RSA-OAEP plaintext does not match\n");
        goto done;
    }

    printf("RSA-OAEP DECRYPTION SUCCESS!!!\n");
    printf("\nDECRYPTED: "); hexprint(pt, pt_len);
    result = 0;

done:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(keyctx);
    return result;
}