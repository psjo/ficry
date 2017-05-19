/*
 * insert stuff here...
 */
#include "aes-crypt.h"

static void
noopt(void)
{
        fprintf(stderr, "Not a valid argument!\n\n");
        return;
}

static void
help(void)
{
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "      -e|-d: encrypt/decrypt, required\n");
        fprintf(stderr, "      -i <infile>: file, required\n");
        fprintf(stderr, "      -o <outfile>: file, optional\n");
        fprintf(stderr, "      -p <password>: duh\n");
        fprintf(stderr, "      -h: this\n");
        exit(0);
}

static void
die(gcry_error_t err, char *desc)
{
        fprintf(stderr, "Error: %s\n", desc);
        if (err) {
                fprintf(stderr, "%s/%s\n",
                        gcry_strsource(err),
                        gcry_strerror(err));
        }
        exit(err ? err : 1);
}

static void
clean_death(gcry_error_t err, 
                char *desc,
                gcry_cipher_hd_t h,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *buf,
                unsigned char *hmac_key,
                unsigned char *salt,
                unsigned char *keys)
{
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
get_algo_len(void)
{
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
write_file(char *os, unsigned char *buf, size_t len)
{

        FILE *f = fopen(os, "wb");
        if (!f) die(0, "fopen write");

        size_t rc;

        fprintf(stderr, "writing file: %s\n", os);
        rc = fwrite(buf, 1, len, f);

        fclose(f);
        return rc;
}


static size_t
read_file(char *is, unsigned char **buf)
{

        FILE *f = fopen(is, "rb");
        if (!f) die(0, "fopen fail");
        size_t sz, rc;
        fseek(f, 0, SEEK_END);
        sz = ftell(f);
        fseek(f, 0, SEEK_SET);

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
init_gcrypt(void)
{

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
init_cipher(gcry_cipher_hd_t *hd, unsigned char *key, unsigned char *iv)
{
        gcry_error_t err;

        err = gcry_cipher_open(
                        hd, // gcry_cipher_hd_t *
                        CIPHER,   // int
                        GCRY_CIPHER_MODE_CBC,     // int
                        GCRY_CIPHER_CBC_CTS); // | GCRY_CIPHER_SECURE);            // unsigned int
        if (err) return err;

        err = gcry_cipher_setkey(*hd, key, key_len);
        if (err) return err;

        err = gcry_cipher_setiv(*hd, iv, blk_len);
        if (err) return err;

        return 0;
}

static int 
encrypt(char *is, char * os, char* pw)
{
        gcry_error_t     err;
        gcry_cipher_hd_t hd = 0;
        gcry_mac_hd_t mac = 0;
        unsigned char *key = NULL, *iv = NULL, *buf = NULL, *hmac_key = NULL, *keys = NULL, *salt = NULL;
        unsigned char *cbuf;
        size_t len, blocks, tot_len;

        fprintf(stderr, "encryption wanted on: %s\nPassword: \"%s\"\n", is, pw);

        get_algo_len();
        len = read_file(is, &buf);
        blocks = len / blk_len;

        if ((sizeof(size_t) + len) % blk_len) blocks++;

        fprintf(stderr, "Creating salt\n");
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

        memcpy(cbuf, &len, sizeof(size_t));
        memcpy(cbuf + sizeof(size_t), buf, len);
        free(buf);
        buf = NULL;

        fprintf(stderr, "encrypting %s\n%x\n", is, iv[0]);
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

        fprintf(stderr, "Calculating HMAC\n");
        
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
decrypt(char *is, char *os, char *pw)
{
        gcry_error_t     err;
        gcry_cipher_hd_t hd = 0;
        gcry_mac_hd_t    mac = 0;
        unsigned char    *key = NULL, *iv = NULL, *buf = NULL, *hmac = NULL, *salt = NULL;
        unsigned char    *keys = NULL, *cbuf = NULL, *hmac_key;
        size_t tot_len, len, flen;

        fprintf(stderr, "decryption wanted on: %s\nPassword: \"%s\"\n", is, pw);

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

        fprintf(stderr, "Verifying HMAC\n");
        
        err = gcry_mac_open(&mac, HMAC, GCRY_MAC_FLAG_SECURE, NULL);
        if (err) clean_death(err, "hmac open", 0, key, iv, buf, hmac_key, salt, keys); 
        
        err = gcry_mac_setkey(mac, hmac_key, hmac_key_len);
        if (err) clean_death(err, "hmac setkey", 0, key, iv, buf, hmac_key, salt, keys); 
        
        err = gcry_mac_write(mac, buf, tot_len - hmac_len);
        if (err) clean_death(err, "hmac write", 0, key, iv, buf, hmac_key, salt, keys); 
        
        err = gcry_mac_verify(mac, hmac, hmac_len);
        if (err) {
                fprintf(stderr, "\nWARNING!\nVerification FAILED.\n\nContinue with decryption [y/N]: ");
                char c = getchar();
                while ((getchar()) != '\n');
                if (c != 'y' || c != 'Y') clean_death(err, "hmac verification failed", 0, key, iv, buf, hmac_key, salt, keys); 
        }
        else fprintf(stderr, "HMAC VALID\n");
        
        gcry_mac_close(mac);
        
        fprintf(stderr, "decrypting %s\n", is);

        err = init_cipher(&hd, key, iv);
        if (err) clean_death(err, "cipher setiv", hd, key, iv, buf, hmac, NULL, NULL);

        err = gcry_cipher_decrypt( hd, cbuf, len, NULL, 0);
        if (err) clean_death(err, "cipher dec", hd, key, iv, buf, hmac, NULL, NULL);
        
        free(buf);
        memcpy(&flen, cbuf, sizeof(size_t));
        fprintf(stderr, "file size: %d\n", (int)flen);
        buf = malloc(flen);
        memcpy(buf, cbuf + sizeof(size_t), flen);
        //printf("plaintext = %s\n", cbuf);
        write_file(os, buf, flen);
        // clean up after ourselves
        gcry_cipher_close(hd);
        gcry_free(key);
        gcry_free(hmac_key);
        gcry_free(salt);
        gcry_free(iv);
        free(buf);
        free(cbuf);
        free(hmac);

        return 0;
}

int
main(int argc, char** argv)
{
        if (argc < 2) help();//die(0, "bastard");
        int enc = -1, opt = 0;
        char *infile = NULL;
        char *outfile = NULL;
        char *pass = NULL;
        char *pw = NULL;

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
        if (!pass) {// || !pubkey)
                pw = calloc(1, 512);
                if (!pw) die(0, "Password alloc failed");
                fprintf(stderr, "Enter password/phrase (max 511 chars): ");
                fgets(pw, 511, stdin);

                if (!strlen(pw)) die(0, "No password? Really?\n");
                if (pw[strlen(pw) - 1] == '\n') pw[strlen(pw) - 1] = '\0';
                pass = pw;
        }
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
                        outfile = "crapfile.out"; //noopt();
                while ((getchar()) != '\n');
        } else if (!access(outfile, 0)) {
                // this is temporary, non working crap
                fprintf(stderr, "Output file: %s exists\nWrite over? [y/N]: ", outfile);
                char c = getchar();
                if (c != 'y' || c != 'Y')
                        die(0,  "Output file exists");
                while ((getchar()) != '\n');
        }
        for (int i = optind; i < argc; i++)
                fprintf(stderr, "No option arg: %s\n", argv[i]);

        init_gcrypt();
        if (enc)
                encrypt(infile, outfile, pass);
        else
                decrypt(infile, outfile, pass);

        fprintf(stderr, "%s is done\n", argv[0]);
        if (pw) free(pw);
}

