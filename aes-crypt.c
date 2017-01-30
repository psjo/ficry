#include <gcrypt.h>
#include <gpg-error.h>

#define GCRY_CIPHER GCRY_CIPHER_AES256   // Pick the cipher here
//#define GCRY_CIPHER GCRY_CIPHER_AES128   // Pick the cipher here
/*
   Called from my main function:

   aesTest(GCRY_CIPHER_MODE_ECB, "a test ini value");
   aesTest(GCRY_CIPHER_MODE_ECB, "different value!");
   aesTest(GCRY_CIPHER_MODE_CBC, "a test ini value");
   aesTest(GCRY_CIPHER_MODE_CBC, "different value!");
   */
static void
die(gcry_error_t err, char *desc) {
        fprintf(stderr, "Error: %s\n", desc);
        if (err) {
                fprintf(stderr, "%s/%s\n",
                        gcry_strsource(err),
                        gcry_strerror(err));
        }
        exit(1);
}

static void
aes_crypt(int gcry_mode, char * iniVector, char* buf) {
        gcry_error_t     gErr;
        // init gcrypt
        if (!gcry_check_version(GCRYPT_VERSION)) {
                fprintf(stderr, "libcrypt version mismatch\n");
                exit(2);
        }
        gErr = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
        if (gErr) die(gErr, "Suspend secmem warning");
        gErr = gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
        if (gErr) die(gErr, "Init secmem");
        gErr = gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
        if (gErr) die(gErr, "Resume secmem warning");
        gErr = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
        if (gErr) die(gErr, "Init finished");
        // init done

        gcry_cipher_hd_t hd;
        size_t index;
        size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
        if (!keyLength) die(0, "keylen");
        size_t blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
        if (!blkLength) die(0, "blklen");
        char * txtBuffer = "123456789 abcdefghijklmnopqrstuvwzyz ABCDEFGHIJKLMNOPQRSTUVWZYZ";
        size_t txtLength = strlen(txtBuffer)+1; // string plus termination
        char * encBuffer = gcry_xmalloc_secure(txtLength); //free this
        if (encBuffer == NULL) exit(1);
        char * outBuffer = malloc(txtLength);
        char * aesSymKey = "one test AES key"; // 16 bytes

        gErr = gcry_cipher_open(
                        &hd, // gcry_cipher_hd_t *
                        GCRY_CIPHER,   // int
                        gcry_mode,     // int
                        GCRY_CIPHER_SECURE);            // unsigned int
        if (gErr) die(gErr, "gcry_cipher_open");

        gErr = gcry_cipher_setkey(hd, aesSymKey, keyLength);
        if (gErr) die(gErr, "gcry_cipher_setkey");

        gErr = gcry_cipher_setiv(hd, iniVector, blkLength);
        if (gErr) die(gErr, "gcry_cipher_setiv");

        gErr = gcry_cipher_encrypt(
                        hd, // gcry_cipher_hd_t
                        encBuffer,    // void *
                        txtLength,    // size_t
                        txtBuffer,    // const void *
                        txtLength);   // size_t
        if (gErr) die(gErr, "gcry_cipher_encrypt");

        gErr = gcry_cipher_setiv(hd, iniVector, blkLength);
        if (gErr) die(gErr, "gcry_cipher_setiv");

        gErr = gcry_cipher_decrypt(
                        hd, // gcry_cipher_hd_t
                        outBuffer,    // void *
                        txtLength,    // size_t
                        encBuffer,    // const void *
                        txtLength);   // size_t
        if (gErr) die(gErr, "gcry_cipher_decrypt");

        printf("gcry_mode = %s\n", gcry_mode == GCRY_CIPHER_MODE_ECB ? "ECB" : "CBC");
        printf("keyLength = %d\n", (int)keyLength);
        printf("blkLength = %d\n", (int)blkLength);
        printf("txtLength = %d\n", (int)txtLength);
        printf("aesSymKey = %s\n", aesSymKey);
        printf("iniVector = %s\n", iniVector);
        printf("txtBuffer = %s\n", txtBuffer);

        printf("encBuffer = ");
        for (index = 0; index < txtLength; index++)
                printf("%02X", (unsigned char)encBuffer[index]);
        printf("\n");

        printf("outBuffer = %s\n", outBuffer);

        // clean up after ourselves
        gcry_cipher_close(hd);
        gcry_free(encBuffer);
        free(outBuffer);
}

int
main(int argc, char** argv) {

        aes_crypt(GCRY_CIPHER_MODE_CBC, "a test ini value", "Encrypt this shit for me please!");
}
