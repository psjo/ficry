#include <gcrypt.h>
#include <gpg-error.h>


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
init_gcrypt(void) {
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
        return;
}

static void
cleanDeath(gcry_error_t err, char *desc, gcry_cipher_hd_t h,
                unsigned char *key, unsigned char *iv, unsigned char *buf) {
        if (h) gcry_cipher_close(h);
        if (key) gcry_free(key);
        if (iv) gcry_free(iv);
        if (buf) gcry_free(buf);
        die(err, desc);
}

static void
encrypt(char *is, char * os, char* pw) {
        init_gcrypt();
        gcry_error_t     gErr;

        gcry_cipher_hd_t hd;
        size_t index;
        size_t keyLen = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
        if (!keyLen) die(0, "keylen");
        size_t blkLen = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
        if (!blkLen) die(0, "blklen");
        char * txtBuf = "123456789 abcdefghijklmnopqrstuvwzyz ABCDEFGHIJKLMNOPQRSTUVWZYZaå@ä~#~µ&*Œ@oe";
        size_t txtLen = strlen(txtBuf)+1; // string plus termination
        //char * outBuf = malloc(txtLen);
        char * aesSymKey = "one test AES key"; // 16 bytes
        unsigned char *key = gcry_xmalloc_secure(keyLen);
        if (!key) cleanDeath(0, "key xmalloc", 0, NULL, NULL, NULL);
        unsigned char *iv = gcry_xmalloc_secure(blkLen);
        if (!iv) cleanDeath(0, "iv xmalloc", 0, key, NULL, NULL);
        unsigned char * buf = gcry_xmalloc_secure(txtLen); //free this
        if (!buf) cleanDeath(0, "buf xmalloc", 0, key, iv, NULL);

        gErr = gcry_cipher_open(
                        &hd, // gcry_cipher_hd_t *
                        GCRY_CIPHER_AES256,   // int
                        GCRY_CIPHER_MODE_CBC,     // int
                        GCRY_CIPHER_CBC_CTS | GCRY_CIPHER_SECURE);            // unsigned int
        if (gErr) cleanDeath(gErr, "gcry_cipher_open", 0, key, iv, buf);

        gErr = gcry_cipher_setkey(hd, aesSymKey, keyLen);
        if (gErr) cleanDeath(gErr, "cipher setkey", hd, key, iv, buf);

        gErr = gcry_cipher_setiv(hd, iv, blkLen);
        if (gErr) cleanDeath(gErr, "cipher setiv", hd, key, iv, buf);

        gErr = gcry_cipher_encrypt(
                        hd, // gcry_cipher_hd_t
                        buf,    // void *
                        txtLen,    // size_t
                        NULL,    // const void *
                        0);   // size_t
        if (gErr) cleanDeath(gErr, "cipher enc", hd, key, iv, buf);
        
        printf("encBuffer = ");
        for (index = 0; index < txtLen; index++)
                printf("%02X", buf[index]);
        printf("\n");

        gErr = gcry_cipher_setiv(hd, iv, blkLen);
        if (gErr) cleanDeath(gErr, "cipher setiv", hd, key, iv, buf);

        gErr = gcry_cipher_decrypt(
                        hd, // gcry_cipher_hd_t
                        buf,    // void *
                        txtLen,    // size_t
                        NULL,    // const void *
                        0);   // size_t
        if (gErr) cleanDeath(gErr, "cipher dec", hd, key, iv, buf);

        printf("gcry_mode = %s\n", "CBC");
        printf("keyLength = %d\n", (int)keyLen);
        printf("blkLength = %d\n", (int)blkLen);
        printf("txtLength = %d\n", (int)txtLen);
        printf("aesSymKey = %s\n", aesSymKey);
        printf("iniVector = %s\n", iv);
        printf("txtBuffer = %s\n", txtBuf);
/*
        printf("encBuffer = ");
        for (index = 0; index < txtLength; index++)
                printf("%02X", (unsigned char)encBuffer[index]);
        printf("\n");
*/
        printf("outBuffer = %s\n", buf);

        // clean up after ourselves
        gcry_cipher_close(hd);
        gcry_free(buf);
        //free(outBuffer);
}

int
main(int argc, char** argv) {
        if (argc != 4) die(0, "bastard");

        char *infile;
        char *outfile;
        char *password;

        encrypt(infile, outfile, password);
}
