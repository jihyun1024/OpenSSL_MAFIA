// 프로젝트에서 암호 관련 기능만 모아놓은 헤더 파일
#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include <stddef.h>

#define PBKDF2_SALT_BYTE    16
#define PBKDF2_KEY_BYTE     32
#define PBKDF2_ITERATIONS   200000

#define AEAD_KEY_BYTE       32
#define AEAD_NONCE_BYTE     12
#define AEAD_TAG_BYTE       16

#define RSA_KEY_BIT         3072
#define RSA_MODULUS_BYTE    384
#define RSA_PSS_SALT_BYTE   32

#define GAME_ID_BYTE        16
#define COMMIT_NONCE_BYTE   32
#define SHA256_BYTE         32

// 함수 선언부
int commit_hash(
    unsigned char liar_id,
    const unsigned char nonce[COMMIT_NONCE_BYTE], unsigned char out[SHA256_BYTE]
);

// 3072비트 RSA 키쌍 생성.
EVP_PKEY* rsa_generate_key(void);

// 공개키 DER의 SHA-256 앞 16바이트를 안정적인 클라이언트 ID로 사용한다.
int rsa_public_key_id(EVP_PKEY* key, unsigned char out[GAME_ID_BYTE]);

// PBKDF2와 AES-256-GCM으로 암호화한 개인키 파일을 불러온다.
// 파일이 없으면 새 키를 생성해 mode 0600 파일로 저장한다.
int private_key_load_or_create(const char* path,
                               const unsigned char* password, size_t password_len,
                               EVP_PKEY** out_key);

int rand_bytes(unsigned char* buf, size_t n);

int pbkdf2_derive_key(
    const unsigned char* password, size_t password_len, 
    const unsigned char salt[PBKDF2_SALT_BYTE], unsigned char key_out[PBKDF2_KEY_BYTE]
);

int aead_encrypt(
    const unsigned char key[AEAD_KEY_BYTE], const unsigned char nonce[AEAD_NONCE_BYTE],
    const unsigned char* aad, size_t aad_len, const unsigned char* plaintext, size_t plaintext_len,
    unsigned char* ciphertext, size_t* ciphertext_len, unsigned char tag_out[AEAD_TAG_BYTE]
);

int aead_decrypt(
    const unsigned char key[AEAD_KEY_BYTE], const unsigned char nonce[AEAD_NONCE_BYTE],
    const unsigned char* aad, size_t aad_len, const unsigned char* ciphertext, size_t ciphertext_len, 
    unsigned char* plaintext, size_t* plaintext_len, const unsigned char tag[AEAD_TAG_BYTE]
);

int rsa_oaep_encrypt(
    EVP_PKEY* public_key,
    const unsigned char* plaintext, size_t plaintext_len,
    unsigned char* ciphertext, size_t* ciphertext_len
);

int rsa_oaep_decrypt(
    EVP_PKEY* private_key,
    const unsigned char* ciphertext, size_t ciphertext_len,
    unsigned char* plaintext, size_t* plaintext_len
);

int rsa_pss_sign(
    EVP_PKEY* private_key,
    const unsigned char* message, size_t message_len, 
    unsigned char* signature, size_t signature_len
);

int rsa_pss_verify(
    EVP_PKEY* public_key,
    const unsigned char* message, size_t message_len,
    const unsigned char* signature, size_t signature_len
);

#endif