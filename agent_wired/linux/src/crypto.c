#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "crypto.h"

const unsigned char FIXED_SALT[SALT_SIZE] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

void handle_errors(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void derive_key_iv(const unsigned char *pass, const unsigned char *salt,
                   unsigned char *key, unsigned char *iv) {
    unsigned char key_iv[KEY_SIZE + IV_SIZE];
    if (!PKCS5_PBKDF2_HMAC((const char *)pass, strlen((const char *)pass),
                           salt, SALT_SIZE, ITERATIONS, EVP_sha256(),
                           sizeof(key_iv), key_iv)) {
        handle_errors("Erro ao derivar chave e IV");
    }
    memcpy(key, key_iv, KEY_SIZE);
    memcpy(iv, key_iv + KEY_SIZE, IV_SIZE);
}

int encrypt(const unsigned char *data, int data_len, const unsigned char *pass,
            unsigned char **out, int *out_len) {
    unsigned char key[KEY_SIZE], iv[IV_SIZE];
    derive_key_iv(pass, FIXED_SALT, key, iv);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors("Erro ao criar contexto");

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors("Erro ao iniciar criptografia");

    *out = malloc(SALT_SIZE + data_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    if (!*out) handle_errors("Erro ao alocar saída");

    memcpy(*out, FIXED_SALT, SALT_SIZE);

    int len, total_len = 0;
    if (!EVP_EncryptUpdate(ctx, *out + SALT_SIZE, &len, data, data_len))
        handle_errors("Erro ao criptografar dados");
    total_len = len;

    if (!EVP_EncryptFinal_ex(ctx, *out + SALT_SIZE + len, &len))
        handle_errors("Erro ao finalizar criptografia");
    total_len += len;

    *out_len = SALT_SIZE + total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int decrypt(const unsigned char *enc_data, int enc_len, const unsigned char *pass,
            unsigned char **out, int *out_len) {
    const unsigned char *salt = enc_data;

    unsigned char key[KEY_SIZE], iv[IV_SIZE];
    derive_key_iv(pass, salt, key, iv);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors("Erro ao criar contexto");

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors("Erro ao iniciar descriptografia");

    *out = malloc(enc_len);

    int len, total_len = 0;
    if (!EVP_DecryptUpdate(ctx, *out, &len, enc_data + SALT_SIZE, enc_len - SALT_SIZE))
        handle_errors("Erro ao descriptografar dados");
    total_len = len;

    if (!EVP_DecryptFinal_ex(ctx, *out + len, &len))
        handle_errors("Erro ao finalizar descriptografia");
    total_len += len;

    *out_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}
