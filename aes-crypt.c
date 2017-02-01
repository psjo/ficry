#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <gpg-error.h>

#define CIPHER GCRY_CIPHER_AES256
#define HMAC GCRY_MAC_HMAC_SHA512
#define D_ALGO GCRY_KDF_PBKDF2
#define D_SUBALGO GCRY_MD_SHA512
#define KDF_ITER 50000
#define KDF_SALT_SIZE 128
#define ENCRYPTED 1
#define PLAINTEXT 0
#define SECMEM_SIZE 16384

static size_t key_len = 0;
static size_t blk_len = 0;
static size_t hmac_len = 0;
static size_t hmac_key_len = 0;

static void
noopt(void) {
        fprintf(stderr, "Not a valid argument!\n\n");
        return;
}

static void
help(void) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "      -e|-d: encrypt/decrypt, required\n");
        fprintf(stderr, "      -i <infile>: file, required\n");
        fprintf(stderr, "      -o <outfile>: file, optional\n");
        fprintf(stderr, "      -p <password>: duh\n");
        fprintf(stderr, "      -h: this\n");
        exit(0);
}

static void
die(gcry_error_t err, char *desc) {
        fprintf(stderr, "Error: %s\n", desc);
        if (err) {
                fprintf(stderr, "%s/%s\n",
                        gcry_strsource(err),
                        gcry_strerror(err));
        }
        exit(err ? err : 1);
}

static void
clean_death(gcry_error_t err, char *desc,
                gcry_cipher_hd_t h,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *buf,
                unsigned char *hmac_key,
                unsigned char *salt,
                unsigned char *keys) {

        if (h) gcry_cipher_close(h);
        if (key) gcry_free(key);
        if (iv) gcry_free(iv);
        if (buf) free(buf);
        if (hmac_key) gcry_free(hmac_key);
        if (salt) gcry_free(salt);
        if (keys) gcry_free(keys);
        
        die(err, desc);
}

static void
get_algo_len(void) {
        key_len = gcry_cipher_get_algo_keylen(CIPHER);
        if (!key_len) die(0, "key len");
        blk_len = gcry_cipher_get_algo_blklen(CIPHER);
        if (!blk_len) die(0, "blk len");
        hmac_key_len = gcry_mac_get_algo_keylen(HMAC);
        if (!hmac_key_len) die(0, "hmac len");
        hmac_len = gcry_mac_get_algo_maclen(HMAC);
        if (!hmac_len) die(0, "hmac len");
}

static size_t
write_file(char *os, unsigned char *buf, size_t len) {
        FILE *f = fopen(os, "wb");
        if (!f) die(0, "fopen write");
        size_t rc;

        fprintf(stderr, "writing file: %s\n", os);
        rc = fwrite(buf, 1, len, f);

        fclose(f);
        return rc;
}


static size_t
read_file(char *is, unsigned char **buf) {
        FILE *f = fopen(is, "rb");
        if (!f) die(0, "fopen fail");
        size_t sz, rc;
        fseek(f, 0, SEEK_END);
        sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (sz >= SECMEM_SIZE) { // - key, iv, mac... 
                fclose(f);
                die(0, "File too large");
        }

        //if (sec)
        *buf = malloc(sz + 1); //free this
        if (!*buf) clean_death(0, "buf xmalloc", 0, NULL, NULL, NULL, NULL, NULL, NULL);

        rc = fread(*buf, 1, sz, f);
        if (rc ^ sz) {
                fclose(f);
                clean_death(0, "fread to buffer", 0, NULL, NULL, *buf, NULL, NULL, NULL);
        }

        fclose(f);
        return rc;
}

static void
init_gcrypt(void) {

        gcry_error_t     err;

        if (!gcry_check_version(GCRYPT_VERSION)) {
                fprintf(stderr, "libcrypt version mismatch\n");
                exit(2);
        }
        err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
        if (err) die(err, "Suspend secmem warning");
        err = gcry_control(GCRYCTL_INIT_SECMEM, SECMEM_SIZE, 0);
        if (err) die(err, "Init secmem"); // option to go on without secmem?
        err = gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
        if (err) die(err, "Resume secmem warning");
        err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
        if (err) die(err, "Init finished");

        return;
}

static gcry_error_t
init_cipher(gcry_cipher_hd_t *hd, unsigned char *key, unsigned char *iv) {
        gcry_error_t err;

        err = gcry_cipher_open(
                        hd, // gcry_cipher_hd_t *
                        CIPHER,   // int
                        GCRY_CIPHER_MODE_CBC,     // int
                        GCRY_CIPHER_CBC_CTS | GCRY_CIPHER_SECURE);            // unsigned int
        if (err) return err; //clean_death(err, "gcry_cipher_open", 0, key, iv, buf);

        err = gcry_cipher_setkey(*hd, key, key_len);
        if (err) return err; //clean_death(err, "cipher setkey", hd, key, iv, buf);

        err = gcry_cipher_setiv(*hd, iv, blk_len);
        if (err) return err; //clean_death(err, "cipher setiv", hd, key, iv, buf);

        return 0;
}

static int 
encrypt(char *is, char * os, char* pw) {
        gcry_error_t     err;
        gcry_cipher_hd_t hd = 0;
        gcry_mac_hd_t mac = 0;
        unsigned char *key = NULL, *iv = NULL, *buf = NULL, *hmac_key = NULL, *keys = NULL, *salt = NULL;
        unsigned char *cbuf;
        size_t len, blocks, tot_len;

        fprintf(stderr, "encryption wanted on: %s\n", is);

        get_algo_len();
        len = read_file(is, &buf);
        blocks = len / blk_len;
        if (len % blk_len) blocks++;

        salt = gcry_xmalloc_secure(KDF_SALT_SIZE);
        if (!salt) clean_death(0, "salt xmalloc", 0, key, iv, buf, hmac_key, salt, keys);
        gcry_create_nonce(salt, KDF_SALT_SIZE);
        keys = gcry_xmalloc_secure(key_len + hmac_len);
        if (!keys) clean_death(0, "keys xmalloc", 0, key, iv, buf, hmac_key, salt, keys);

        err = gcry_kdf_derive(pw, strlen(pw), D_ALGO, D_SUBALGO, salt,
                        KDF_SALT_SIZE, KDF_ITER, key_len + hmac_len, keys);
        if (err) clean_death(err, "kdf derive", 0, key, iv, buf, hmac_key, salt, keys);

        key = gcry_xmalloc_secure(key_len);
        if (!key) clean_death(0, "key xmalloc", 0, NULL, NULL, NULL, NULL, salt, keys);
        hmac_key = gcry_xmalloc_secure(hmac_key_len);
        if (!hmac_key) clean_death(0, "hmac xmalloc", 0, key, iv, buf, hmac_key, salt, keys);
        if (!memcpy(key, keys, key_len)) clean_death(0, "memcpy key", 0, key, iv, buf, hmac_key, salt, keys);
        if (!memcpy(hmac_key, keys + key_len, hmac_key_len))
                clean_death(0, "memcpy hmac", 0, key, iv, buf, hmac_key, salt, keys);
        gcry_free(keys);
        keys = NULL;

        iv = gcry_xmalloc_secure(blk_len);
        if (!iv) clean_death(0, "iv xmalloc", 0, key, iv, buf, hmac_key, salt, keys);
        gcry_create_nonce(iv, blk_len);

        err = init_cipher(&hd, key, iv);
        if (err) clean_death(err, "init_cipher", hd, key, iv, buf, hmac_key, salt, keys);
        fprintf(stderr, "cipher initiated\n");

        cbuf = calloc(blocks, blk_len);
        if (!cbuf) clean_death(0, "cbuf malloc", hd, key, iv, buf, hmac_key, salt, keys); 
        memcpy(cbuf, buf, len);
        free(buf);
        buf = NULL;

        fprintf(stderr, "encrypting %s\n", is);
        err = gcry_cipher_encrypt( hd, cbuf, blocks * blk_len, NULL, 0);
        if (err) clean_death(err, "cipher enc", hd, key, iv, buf, hmac_key, salt, keys);
        
        gcry_cipher_close(hd);
        tot_len = KDF_SALT_SIZE + blk_len + blocks * blk_len + hmac_len;
        buf = malloc(tot_len);
        if (!buf) clean_death(err, "buffer malloc", 0, key, iv, buf, hmac_key, salt, keys); 
        memcpy(buf, salt, KDF_SALT_SIZE);
        memcpy(buf + KDF_SALT_SIZE, iv, blk_len);
        memcpy(buf + KDF_SALT_SIZE + blk_len, cbuf, blocks * blk_len);

        gcry_free(key); key = NULL;
        gcry_free(iv); iv = NULL;
        gcry_free(salt); salt = NULL;
        
        free(cbuf);
        cbuf = malloc(hmac_len);
        if (!cbuf) clean_death(err, "hmac xmalloc", 0, key, iv, buf, hmac_key, salt, keys); 

        err = gcry_mac_open(&mac, HMAC, GCRY_MAC_FLAG_SECURE, NULL);
        if (err) clean_death(err, "hmac open", 0, key, iv, buf, hmac_key, salt, keys); 
        err = gcry_mac_setkey(mac, hmac_key, hmac_key_len);
        if (err) clean_death(err, "hmac setkey", 0, key, iv, buf, hmac_key, salt, keys); 
        err = gcry_mac_write(mac, buf, tot_len - hmac_len);
        if (err) clean_death(err, "hmac write", 0, key, iv, buf, hmac_key, salt, keys); 
        err = gcry_mac_read(mac, cbuf, &hmac_len);
        if (err) clean_death(err, "hmac read", 0, key, iv, buf, hmac_key, salt, keys); 
        gcry_mac_close(mac);
        memcpy(buf + KDF_SALT_SIZE + blk_len + blocks * blk_len, cbuf, hmac_len);
        gcry_free(hmac_key);
        free(cbuf);

        len = write_file(os, buf, tot_len);
        free(buf);
        if (len ^ tot_len) die(0, "write fail");
        return 0;
}

static int
decrypt(char *is, char *os, char *pw) {
        gcry_error_t     err;
        gcry_cipher_hd_t hd = 0;
        gcry_mac_hd_t mac = 0;
        unsigned char *key = NULL, *iv = NULL, *buf = NULL, *hmac = NULL, *salt = NULL;
        unsigned char *keys = NULL, *cbuf = NULL, *hmac_key;
        size_t tot_len, len;

        fprintf(stderr, "decryption wanted on: %s\n", is);

        tot_len = read_file(is, &buf);

        get_algo_len();

        salt = gcry_xmalloc(KDF_SALT_SIZE);
        if (!salt) clean_death(0, "salt xmalloc", 0, key, iv, buf, NULL, salt, NULL);
        iv = gcry_xmalloc_secure(blk_len);
        if (!iv) clean_death(0, "iv xmalloc", 0, key, iv, buf, NULL, salt, NULL);
        cbuf = malloc(tot_len - KDF_SALT_SIZE - blk_len - hmac_len);
        if (!cbuf) clean_death(0, "hmac xmalloc", 0, key, iv, buf, NULL, salt, NULL); 
        hmac = malloc(hmac_len);
        if (!hmac) clean_death(0, "hmac xmalloc", 0, key, iv, buf, NULL, salt, NULL); 

        memcpy(salt, buf, KDF_SALT_SIZE);
        memcpy(iv, buf + KDF_SALT_SIZE, blk_len);
        memcpy(cbuf, buf + KDF_SALT_SIZE + blk_len, tot_len - KDF_SALT_SIZE - blk_len - hmac_len);
        memcpy(hmac, buf + tot_len - hmac_len, hmac_len);
        len = tot_len - KDF_SALT_SIZE - blk_len - hmac_len;

        keys = gcry_xmalloc_secure(key_len + hmac_len);
        if (!keys) clean_death(0, "keys xmalloc", 0, key, iv, buf, NULL, salt, keys);
        err = gcry_kdf_derive(pw, strlen(pw), D_ALGO, D_SUBALGO, salt,
                        KDF_SALT_SIZE, KDF_ITER, key_len + hmac_len, keys);
        if (err) clean_death(err, "kdf derive", 0, key, iv, buf, NULL, salt, keys);

        key = gcry_xmalloc_secure(key_len);
        if (!key) clean_death(0, "key xmalloc", 0, NULL, iv, NULL, NULL, salt, keys);
        hmac_key = gcry_xmalloc_secure(hmac_key_len);
        if (!hmac_key) clean_death(0, "hmac xmalloc", 0, key, iv, buf, hmac_key, salt, keys);
        if (!memcpy(key, keys, key_len)) clean_death(0, "memcpy key", 0, key, iv, buf, hmac_key, salt, keys);
        if (!memcpy(hmac_key, keys + key_len, hmac_key_len))
                clean_death(0, "memcpy hmac", 0, key, iv, buf, hmac_key, salt, keys);
        gcry_free(keys);
        keys = NULL;

        err = gcry_mac_open(&mac, HMAC, GCRY_MAC_FLAG_SECURE, NULL);
        if (err) clean_death(err, "hmac open", 0, key, iv, buf, hmac_key, salt, keys); 
        err = gcry_mac_setkey(mac, hmac_key, hmac_key_len);
        if (err) clean_death(err, "hmac setkey", 0, key, iv, buf, hmac_key, salt, keys); 
        err = gcry_mac_write(mac, buf, tot_len - hmac_len);
        if (err) clean_death(err, "hmac write", 0, key, iv, buf, hmac_key, salt, keys); 
        err = gcry_mac_verify(mac, hmac, hmac_len);
        if (err) clean_death(err, "hmac verification failed", 0, key, iv, buf, hmac_key, salt, keys); 
        else fprintf(stderr, "HMAC VALID\n");
        gcry_mac_close(mac);
        fprintf(stderr, "decrypting %s\n", is);

        err = init_cipher(&hd, key, iv);
        if (err) clean_death(err, "cipher setiv", hd, key, iv, buf, hmac, NULL, NULL);

        err = gcry_cipher_decrypt( hd, cbuf, len, NULL, 0);
        if (err) clean_death(err, "cipher dec", hd, key, iv, buf, hmac, NULL, NULL);

        //printf("plaintext = %s\n", cbuf);
        write_file(os, cbuf, len);
        // clean up after ourselves
        gcry_cipher_close(hd);
        free(buf);
        free(cbuf);

        return 0;
}

int
main(int argc, char** argv) {
        if (argc < 2) help();//die(0, "bastard");
        int enc = -1, opt = 0;
        char *infile = NULL;
        char *outfile = NULL;
        char *pass = NULL;

        while ( EOF != (opt = getopt(argc, argv, "edi:o:p:h"))) {
                switch(opt) {
                        case 'i': infile = optarg;
                                  break;
                        case 'o': outfile = optarg;
                                  break;
                        case 'p': pass = optarg;
                                  break;
                        case 'h': help();
                                  break;
                        case 'e': enc = 1;
                                  break;
                        case 'd': enc = 0;
                                  break;
                        case '?':
                                  if (optopt == 'i' || optopt == 'o' || optopt == 'p') {
                                        noopt();
                                        help();
                                  }
                        default: //noopt();
                                 help();
                }
        }
        if (enc < 0)
                help();
        if (!pass) // || !pubkey)
                die(0, "No password? Really?\n");
        if (!infile)
                help();
        else if (access(infile, 0)) {
                fprintf(stderr, "No file: %s\n", infile);
                die(0,  "No infile");
        }
        if (!outfile) {
                fprintf(stderr, "Write over %s with encrypted data? [y/N]: ", infile);
                char c = getchar();
                if (c == 'y' || c == 'Y')
                        die(0, "todo, when it all works"); //outfile = infile;
                else
                        noopt(); //help();
        } else if (!access(outfile, 0)) {
                fprintf(stderr, "Output file: %s exists\nWrite over? [y/N]: ", outfile);
                char c = getchar();
                if (c != 'y' || c != 'Y')
                        die(0,  "Output file exists");
        }
        for (int i = optind; i < argc; i++)
                fprintf(stderr, "No option arg: %s\n", argv[i]);

        init_gcrypt();
        if (enc)
                encrypt(infile, outfile, pass);
        else
                decrypt(infile, outfile, pass);
        //init_gcrypt();
        //decrypt(infile, outfile, pass);
        //free(infile);
        //if (outfile) free(outfile);
        //free(pass);
}

