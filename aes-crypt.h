#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <gpg-error.h>
#include <getopt.h>

#define CIPHER         GCRY_CIPHER_AES256
#define HMAC           GCRY_MAC_HMAC_SHA512
#define D_ALGO         GCRY_KDF_PBKDF2
#define D_SUBALGO      GCRY_MD_SHA512
#define KDF_ITER       50000
#define KDF_SALT_SIZE  128
#define ENCRYPTED      1
#define PLAINTEXT      0
#define SECMEM_SIZE    16384

static size_t key_len = 0;
static size_t blk_len = 0;
static size_t hmac_len = 0;
static size_t hmac_key_len = 0;

static void noopt(void);
static void help(void) __attribute__ ((noreturn));
static void die(gcry_error_t err, char *desc) __attribute__ ((noreturn));
static void clean_death(gcry_error_t err, 
                char *desc,
                gcry_cipher_hd_t h,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *buf,
                unsigned char *hmac_key,
                unsigned char *salt,
                unsigned char *keys);

static void get_algo_len(void);
static size_t write_file(char *os, unsigned char *buf, size_t len);
static size_t read_file(char *is, unsigned char **buf);
static void init_gcrypt(void);
static gcry_error_t init_cipher(gcry_cipher_hd_t *hd, unsigned char *key, unsigned char *iv);
static int encrypt(char *is, char * os, char* pw);
static int decrypt(char *is, char *os, char *pw);
