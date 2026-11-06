// 프로젝트에서 암호 관련 기능만 모아놓은 헤더 파일
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <openssl/evp.h>

#define PBKDF2_SALT_BYTE    16
#define PBKDF2_KEY_BYTE     32
#define PBKDF2_ITERATIONS   200000

#define AEAD_KEY_BYTE       32
#define AEAD_NONCE_BYTE     12
#define AEAD_TAG_BYTE       16

#define RSA_KEY_BIT         3072
#define RSA_MODULUS_BYTE    384
#define RSA_PSS_SALT_BYTE   32


static void hexprint(const unsigned char* p, size_t n);

// 함수 선언부
int pbkdf2_derive_key(
    const unsigned char* password, size_t password_len, 
    const unsigned char salt[PBKDF2_SALT_BYTE],
    unsigned char key_out[PBKDF2_KEY_BYTE]
);

int aead_encrypt(
    const unsigned char key[AEAD_KEY_BYTE],
    const unsigned char nonce[AEAD_NONCE_BYTE],
    const unsigned char* aad, size_t aad_len,
    const unsigned char* plaintext, size_t plaintext_len,
    unsigned char* ciphertext, size_t* ciphertext_len,
    unsigned char tag_out[AEAD_TAG_BYTE]
);

int aead_decrypt(
    const unsigned char key[AEAD_KEY_BYTE],
    const unsigned char nonce[AEAD_NONCE_BYTE],
    const unsigned char* aad, size_t aad_len,
    const unsigned char* ciphertext, size_t ciphertext_len,
    unsigned char* plaintext, size_t* plaintext_len,
    const unsigned char tag[AEAD_TAG_BYTE]
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