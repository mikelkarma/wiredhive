#ifndef CRYPTO_H
#define CRYPTO_H

#define SALT_SIZE 8
#define KEY_SIZE 32
#define IV_SIZE 16
#define ITERATIONS 10000

extern const unsigned char FIXED_SALT[SALT_SIZE];

void handle_errors(const char *msg);
void derive_key_iv(const unsigned char *pass, const unsigned char *salt,
                   unsigned char *key, unsigned char *iv);

int encrypt(const unsigned char *data, int data_len, const unsigned char *pass,
            unsigned char **out, int *out_len);

int decrypt(const unsigned char *enc_data, int enc_len, const unsigned char *pass,
            unsigned char **out, int *out_len);

#endif
