#define _POSIX_C_SOURCE 200809L
#include "crypto.h"

#include <string.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/x509.h>


// SHA-256(liar_id || nonce). 서버와 클라이언트가 같은 정규 형식으로 계산한다.
int commit_hash(
    unsigned char liar_id,
    const unsigned char nonce[COMMIT_NONCE_BYTE], unsigned char out[SHA256_BYTE]
) {
    unsigned int out_len = 0;
    int success = 0;
    EVP_MD_CTX* ctx = NULL;

    if (nonce == NULL || out == NULL) goto done;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL ||
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, &liar_id, 1) != 1 ||
        EVP_DigestUpdate(ctx, nonce, COMMIT_NONCE_BYTE) != 1 ||
        EVP_DigestFinal_ex(ctx, out, &out_len) != 1 || out_len != SHA256_BYTE)
        goto done;

    success = 1;

done:
    EVP_MD_CTX_free(ctx);
    return success;
}


// OpenSSL의 RAND_bytes 함수를 "crypto.h" 헤더 파일 포함만으로 사용할 수 있게 하는 함수
int rand_bytes(unsigned char* buf, size_t n) {
    if (buf == NULL || n > INT_MAX) return 0;
    return RAND_bytes(buf, (int)n) == 1 ? 1 : 0;
}

EVP_PKEY* rsa_generate_key(void) {
    EVP_PKEY* key = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BIT) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

int rsa_public_key_id(EVP_PKEY* key, unsigned char out[GAME_ID_BYTE]) {
    if (key == NULL || out == NULL) return 0;

    unsigned char* der = NULL;
    int der_len = i2d_PUBKEY(key, &der);
    if (der_len <= 0) return 0;

    unsigned char digest[SHA256_BYTE];
    unsigned int digest_len = 0;
    int success = EVP_Digest(der, (size_t)der_len, digest, &digest_len,
                             EVP_sha256(), NULL) == 1 &&
                  digest_len == SHA256_BYTE;
    if (success) memcpy(out, digest, GAME_ID_BYTE);

    OPENSSL_cleanse(digest, sizeof digest);
    OPENSSL_free(der);
    return success;
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
    const unsigned char key[AEAD_KEY_BYTE], const unsigned char nonce[AEAD_NONCE_BYTE],
    const unsigned char* aad, size_t aad_len, const unsigned char* plaintext, size_t plaintext_len,
    unsigned char* ciphertext, size_t* ciphertext_len, unsigned char tag_out[AEAD_TAG_BYTE]
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
        aad_len > INT_MAX || plaintext_len > INT_MAX ||
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
    const unsigned char key[AEAD_KEY_BYTE], const unsigned char nonce[AEAD_NONCE_BYTE],
    const unsigned char* aad, size_t aad_len, const unsigned char* ciphertext, size_t ciphertext_len,
    unsigned char* plaintext, size_t* plaintext_len, const unsigned char tag[AEAD_TAG_BYTE]
) {
    EVP_CIPHER* cipher = NULL;
    EVP_CIPHER_CTX* ctx = NULL;
    unsigned char final_buf[EVP_MAX_BLOCK_LENGTH], tag_copy[AEAD_TAG_BYTE];
    int len = 0, final_len = 0, success = 0;
    size_t produced = 0;

    if (plaintext_len == NULL) return 0;
    size_t capacity = *plaintext_len;
    *plaintext_len = 0;

    if (key == NULL || nonce == NULL || tag == NULL ||
        aad_len > INT_MAX || ciphertext_len > INT_MAX || capacity < ciphertext_len ||
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
    if (ctx == NULL || EVP_DecryptInit_ex(ctx, cipher, NULL, key, nonce) != 1)
        goto done;

    if (aad_len > 0 &&
        EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
        goto done;

    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
                              (int)ciphertext_len) != 1 ||
            len < 0 || (size_t)len > ciphertext_len)
            goto done;
        produced = (size_t)len;
    }

    memcpy(tag_copy, tag, sizeof tag_copy);

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AEAD_TAG_BYTE, tag_copy) != 1 ||
        EVP_DecryptFinal_ex(ctx, final_buf, &final_len) != 1 ||
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
    output_len = *ciphertext_len;
    *ciphertext_len = 0;

    if (public_key == NULL || ciphertext == NULL || output_len == 0 ||
        plaintext_len > INT_MAX || (plaintext_len > 0 && plaintext == NULL))
        return 0;

    ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 || 
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 || 
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 || 
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        goto done;
    }

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
    size_t capacity, output_len;
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
    EVP_MD_CTX* ctx = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    int success = 0;
    int expected_len = private_key != NULL ? EVP_PKEY_get_size(private_key) : 0;

    if (private_key == NULL || signature == NULL || expected_len <= 0 ||
        signature_len < (size_t)expected_len ||
        (message_len > 0 && message == NULL))
        return 0;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL ||
        EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), NULL, private_key) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0 ||
        EVP_DigestSignUpdate(ctx, message, message_len) <= 0 ||
        EVP_DigestSignFinal(ctx, signature, &signature_len) <= 0 ||
        signature_len != (size_t)expected_len)
        goto done;

    success = 1;
done:
    if (!success) ERR_clear_error();
    EVP_MD_CTX_free(ctx);
    return success;
}

// RSA-PSS로 검증
int rsa_pss_verify(
    EVP_PKEY* public_key,
    const unsigned char* message, size_t message_len,
    const unsigned char* signature, size_t signature_len
) {
    EVP_MD_CTX* ctx = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    int success = 0;
    int expected_len = public_key != NULL ? EVP_PKEY_get_size(public_key) : 0;

    if (public_key == NULL || signature == NULL || expected_len <= 0 ||
        signature_len != (size_t)expected_len ||
        (message_len > 0 && message == NULL))
        return 0;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL ||
        EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, public_key) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0 ||
        EVP_DigestVerifyUpdate(ctx, message, message_len) <= 0 ||
        EVP_DigestVerifyFinal(ctx, signature, signature_len) <= 0)
        goto done;

    success = 1;
done:
    if (!success) ERR_clear_error();
    EVP_MD_CTX_free(ctx);
    return success;
}

// ===== AEAD로 보호된 개인키 파일 =====
// magic/version || salt || nonce || ciphertext_len || ciphertext || GCM tag
#define KEY_FILE_HEADER_BYTE (8 + PBKDF2_SALT_BYTE + AEAD_NONCE_BYTE + 4)
#define KEY_FILE_MAX_BYTE    16384

static const unsigned char KEY_FILE_MAGIC[8] = {
    'L', 'I', 'A', 'R', 'K', 'E', 'Y', 1
};

static void key_put_u32(unsigned char out[4], unsigned int value) {
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static unsigned int key_get_u32(const unsigned char in[4]) {
    return ((unsigned int)in[0] << 24) | ((unsigned int)in[1] << 16) |
           ((unsigned int)in[2] << 8) | (unsigned int)in[3];
}

static int key_write_all(int fd, const unsigned char* data, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        ssize_t written = write(fd, data + offset, len - offset);
        if (written < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        if (written == 0) return 0;
        offset += (size_t)written;
    }
    return 1;
}

static int encrypted_private_key_save(const char* path,
                                      const unsigned char* password,
                                      size_t password_len, EVP_PKEY* key) {
    int success = 0;
    int fd = -1;
    char* temp_path = NULL;
    unsigned char* der = NULL;
    unsigned char* ciphertext = NULL;
    unsigned char salt[PBKDF2_SALT_BYTE];
    unsigned char nonce[AEAD_NONCE_BYTE];
    unsigned char derived[PBKDF2_KEY_BYTE];
    unsigned char tag[AEAD_TAG_BYTE];
    unsigned char header[KEY_FILE_HEADER_BYTE];

    int der_len = i2d_PrivateKey(key, NULL);
    if (der_len <= 0 || der_len > KEY_FILE_MAX_BYTE) goto done;
    der = OPENSSL_malloc((size_t)der_len);
    ciphertext = OPENSSL_malloc((size_t)der_len);
    if (der == NULL || ciphertext == NULL) goto done;

    unsigned char* cursor = der;
    if (i2d_PrivateKey(key, &cursor) != der_len) goto done;
    if (rand_bytes(salt, sizeof salt) != 1 ||
        rand_bytes(nonce, sizeof nonce) != 1 ||
        pbkdf2_derive_key(password, password_len, salt, derived) != 1)
        goto done;

    memcpy(header, KEY_FILE_MAGIC, sizeof KEY_FILE_MAGIC);
    memcpy(header + 8, salt, sizeof salt);
    memcpy(header + 8 + sizeof salt, nonce, sizeof nonce);
    key_put_u32(header + KEY_FILE_HEADER_BYTE - 4, (unsigned int)der_len);

    size_t ciphertext_len = 0;
    if (aead_encrypt(derived, nonce, header, sizeof header,
                     der, (size_t)der_len, ciphertext, &ciphertext_len, tag) != 1 ||
        ciphertext_len != (size_t)der_len)
        goto done;

    size_t temp_len = strlen(path) + 16;
    temp_path = malloc(temp_len);
    if (temp_path == NULL) goto done;
    snprintf(temp_path, temp_len, "%s.tmp.XXXXXX", path);
    fd = mkstemp(temp_path);
    if (fd < 0 || fchmod(fd, S_IRUSR | S_IWUSR) != 0 ||
        key_write_all(fd, header, sizeof header) != 1 ||
        key_write_all(fd, ciphertext, ciphertext_len) != 1 ||
        key_write_all(fd, tag, sizeof tag) != 1 || fsync(fd) != 0)
        goto done;

    if (close(fd) != 0) {
        fd = -1;
        goto done;
    }
    fd = -1;
    if (link(temp_path, path) != 0) goto done;
    unlink(temp_path);
    success = 1;

done:
    if (fd >= 0) close(fd);
    if (temp_path != NULL) unlink(temp_path);
    free(temp_path);
    if (der != NULL) OPENSSL_clear_free(der, (size_t)(der_len > 0 ? der_len : 0));
    if (ciphertext != NULL)
        OPENSSL_clear_free(ciphertext, (size_t)(der_len > 0 ? der_len : 0));
    OPENSSL_cleanse(derived, sizeof derived);
    OPENSSL_cleanse(tag, sizeof tag);
    return success;
}

static int encrypted_private_key_load(const char* path,
                                      const unsigned char* password,
                                      size_t password_len, EVP_PKEY** out_key) {
    int success = 0;
    int fd = -1;
    unsigned char* file = NULL;
    unsigned char* der = NULL;
    EVP_PKEY* key = NULL;
    struct stat st;
    memset(&st, 0, sizeof st);
    unsigned char derived[PBKDF2_KEY_BYTE];
    size_t der_size = 0;

    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (st.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
        st.st_size < KEY_FILE_HEADER_BYTE + AEAD_TAG_BYTE ||
        st.st_size > KEY_FILE_MAX_BYTE + KEY_FILE_HEADER_BYTE + AEAD_TAG_BYTE)
        goto done;

    size_t file_len = (size_t)st.st_size;
    file = OPENSSL_malloc(file_len);
    if (file == NULL) goto done;

    size_t offset = 0;
    while (offset < file_len) {
        ssize_t n = read(fd, file + offset, file_len - offset);
        if (n < 0) {
            if (errno == EINTR) continue;
            goto done;
        }
        if (n == 0) goto done;
        offset += (size_t)n;
    }

    if (CRYPTO_memcmp(file, KEY_FILE_MAGIC, sizeof KEY_FILE_MAGIC) != 0) goto done;
    der_size = key_get_u32(file + KEY_FILE_HEADER_BYTE - 4);
    if (der_size == 0 || der_size > KEY_FILE_MAX_BYTE ||
        file_len != KEY_FILE_HEADER_BYTE + der_size + AEAD_TAG_BYTE)
        goto done;

    const unsigned char* salt = file + 8;
    const unsigned char* nonce = salt + PBKDF2_SALT_BYTE;
    const unsigned char* ciphertext = file + KEY_FILE_HEADER_BYTE;
    const unsigned char* tag = ciphertext + der_size;
    if (pbkdf2_derive_key(password, password_len, salt, derived) != 1) goto done;

    der = OPENSSL_malloc(der_size);
    if (der == NULL) goto done;
    size_t plaintext_len = der_size;
    if (aead_decrypt(derived, nonce, file, KEY_FILE_HEADER_BYTE,
                     ciphertext, der_size, der, &plaintext_len, tag) != 1 ||
        plaintext_len != der_size)
        goto done;

    const unsigned char* cursor = der;
    key = d2i_AutoPrivateKey(NULL, &cursor, (long)der_size);
    if (key == NULL || cursor != der + der_size ||
        EVP_PKEY_get_base_id(key) != EVP_PKEY_RSA ||
        EVP_PKEY_get_bits(key) != RSA_KEY_BIT)
        goto done;

    *out_key = key;
    key = NULL;
    success = 1;

done:
    if (fd >= 0) close(fd);
    EVP_PKEY_free(key);
    if (file != NULL) OPENSSL_clear_free(file, (size_t)st.st_size);
    if (der != NULL) OPENSSL_clear_free(der, der_size);
    OPENSSL_cleanse(derived, sizeof derived);
    return success;
}

int private_key_load_or_create(const char* path,
                               const unsigned char* password, size_t password_len,
                               EVP_PKEY** out_key) {
    if (path == NULL || path[0] == '\0' || password == NULL || password_len == 0 ||
        out_key == NULL)
        return 0;
    *out_key = NULL;

    if (access(path, F_OK) == 0)
        return encrypted_private_key_load(path, password, password_len, out_key);
    if (errno != ENOENT) return 0;

    EVP_PKEY* key = rsa_generate_key();
    if (key == NULL) return 0;
    if (encrypted_private_key_save(path, password, password_len, key) != 1) {
        EVP_PKEY_free(key);
        // 다른 프로세스가 같은 경로를 먼저 만들었다면 그 파일을 사용한다.
        if (access(path, F_OK) == 0)
            return encrypted_private_key_load(path, password, password_len, out_key);
        return 0;
    }
    *out_key = key;
    return 1;
}
