/* Bradford Smith (bsmith8)
 * CS 579 Lab 1 pv_encrypt.c
 * 04/10/2016
 * "I pledge my honor that I have abided by the Stevens Honor System."
 */

#include "pv.h"

void encrypt_file(const char *ctxt_fname, void *raw_sk, size_t raw_len, int fin)
{
    /***************************************************************************
     * Task: Read the content from file descriptor fin, encrypt it using raw_sk,
     *       and place the resulting ciphertext in a file named ctxt_fname.
     *       The encryption should be CCA-secure, which is the level of
     *       cryptographic protection that you should always expect of any
     *       implementation of an encryption algorithm.
     *
     * As we have learned in class, the gold standard for encryption is
     * CCA-security. The approach that we will take in this lab is to
     * use AES in CTR-mode (AES-CTR), and then append an AES-CBC-MAC mac
     * of the resulting ciphertext. (Always mac after encrypting!) The
     * dcrypt library contains an implementation of AES (see source at
     * ~nicolosi/devel/libdcrypt/src/aes.c), but you need to implement
     * the logic for using AES in CTR-mode and in CBC-MAC'ing.
     *
     * Notice that the keys used to compute AES-CTR and AES-CBC-MAC mac
     * must be different. Never use the same cryptographic key for two
     * different purposes: bad interference could occur.  For this
     * reason, the key raw_sk actually consists of two pieces, one for
     * use in AES-CTR and the other for AES-CBC-MAC. The length of each
     * piece (and hence the cryptographic strength of the encryption) is
     * specified by the constant CCA_STRENGTH in pv.h; the default is
     * 128 bits, or 16 bytes.
     *
     * Recall that AES works on blocks of 128 bits; in the case that the
     * length (in bytes) of the plaintext is not a multiple of 16, just
     * discard the least-significant bytes that you obtains from the
     * CTR-mode operation.
     *
     * Thus, the overall layout of an encrypted file will be:
     *
     *         +--------------------------+---+
     *         |             Y            | W |
     *         +--------------------------+---+
     *
     * where Y = AES-CTR (K_CTR, plaintext)
     *       W = AES-CBC-MAC (K_MAC, Y)
     *
     * As for the sizes of the various components of a ciphertext file,
     * notice that:
     *
     * - the length of Y (in bytes) is just 16 bytes more than the length
     *   of the plaintext, and thus it may not be a multiple of 16;
     * - the hash value AES-CBC-MAC (K_MAC, Y) is 16-byte long;
     *
     ***************************************************************************/
    int fdctxt = 0;
    char *k_ctr = NULL;
    char *k_mac = NULL;
    char *iv = NULL;
    char *nonce = NULL;
    char buf[CCA_STRENGTH + 1];
    char output[CCA_STRENGTH + 1];
    unsigned int counter = 0;
    int n = 0;
    int i = 0;
    aes_ctx *ctx = NULL;

    /* Create the ciphertext file---the content will be encrypted,
     * so it can be world-readable! */
    if ((fdctxt = open(ctxt_fname, O_WRONLY|O_TRUNC|O_CREAT, 0644)) == -1)
    {
        perror(getprogname());

        /* scrub the buffer that's holding the key before exiting */
        bzero(raw_sk, raw_len);

        exit(-1);
    }

    /* initialize the pseudorandom generator (for the IV) */
    ri();

    /* The buffer for the symmetric key actually holds two keys: */
    /* use the first key for the AES-CTR encryption ...*/
    k_ctr = (char*)memcpy((void*)k_ctr, raw_sk, raw_len/2);
    aes_setkey(ctx, k_ctr, raw_len/2);

    /* ... and the second part for the AES-CBC-MAC */
    raw_sk = raw_sk + (raw_len/2) - 1;
    k_mac = (char*)memcpy((void*)k_mac, raw_sk, raw_len/2);

    /* Now start processing the actual file content using symmetric encryption */
    /* Remember that CTR-mode needs a random IV (Initialization Vector) */
    prng_getbytes(iv, CCA_STRENGTH - sizeof(counter));
    if ((n = write(fdctxt, iv, CCA_STRENGTH - sizeof(counter))) == -1)
    {
        perror(getprogname());

        bzero(k_ctr, raw_len/2);
        bzero(k_mac, raw_len/2);
        bzero(iv, CCA_STRENGTH);

        exit(-1);
    }

    /* read `CCA_STRENGTH` bytes at a time */
    while ((n = read(fin, buf, CCA_STRENGTH)) != 0)
    {
        nonce = (char*)memcpy((void*)nonce, iv, CCA_STRENGTH - sizeof(counter));
        nonce = (char*)memcpy((void*)&nonce[CCA_STRENGTH - sizeof(counter)], (void*)&counter, sizeof(counter));
        counter++;

        if (n <= 0)
        {
            /* we reached the end of the file */
            break;
        }
        else if (n < CCA_STRENGTH)
        {
            /* Don't forget to pad the last block with trailing zeroes */
            while (n < CCA_STRENGTH)
                buf[n++] = 0;

            /* aes nonce and key -> output */
            aes_encrypt(ctx, output, nonce);

            for (i = 0; i < CCA_STRENGTH; i++)
            {
                buf[i] = buf[i] ^ output[i];
            }

            /* write the last chunk */
            write_chunk(fdctxt, buf, CCA_STRENGTH);
        }
        else
        {
            /* aes nonce and key -> output */
            aes_encrypt(ctx, output, nonce);

            for (i = 0; i < CCA_STRENGTH; i++)
            {
                buf[i] = buf[i] ^ output[i];
            }

            /* Compute the AES-CBC-MAC while you go */
            write_chunk(fdctxt, buf, CCA_STRENGTH);
        }
    }

    /* Finish up computing the AES-CBC-MAC and write the resulting
     * 16-byte MAC after the last chunk of the AES-CTR ciphertext */

    bzero(k_ctr, raw_len/2);
    bzero(k_mac, raw_len/2);
    bzero(iv, CCA_STRENGTH);
}

void usage(const char *pname)
{
    printf("Personal Vault: Encryption \n");
    printf("Usage: %s SK-FILE PTEXT-FILE CTEXT-FILE\n", pname);
    printf("       Exits if either SK-FILE or PTEXT-FILE don't exist.\n");
    printf("       Otherwise, encrpyts the content of PTEXT-FILE under\n");
    printf("       sk, and place the resulting ciphertext in CTEXT-FILE.\n");
    printf("       If CTEXT-FILE existed, any previous content is lost.\n");

    exit(1);
}

int main(int argc, char **argv)
{
    int fdsk, fdptxt;
    char *raw_sk;
    size_t raw_len;

    /* YOUR CODE HERE */


    if (argc != 4)
    {
        usage(argv[0]);
    }   /* Check if argv[1] and argv[2] are existing files */
    else if (((fdsk = open(argv[1], O_RDONLY)) == -1)
            || ((fdptxt = open(argv[2], O_RDONLY)) == -1))
    {
        if (errno == ENOENT)
        {
            usage(argv[0]);
        }
        else
        {
            perror(argv[0]);

            exit(-1);
        }
    }
    else
    {
        setprogname(argv[0]);

        /* Import symmetric key from argv[1] */
        if (!(import_sk_from_file(&raw_sk, &raw_len, fdsk)))
        {
            printf("%s: no symmetric key found in %s\n", argv[0], argv[1]);

            close(fdsk);
            exit(2);
        }
        close(fdsk);

        /* Enough setting up---let's get to the crypto... */
        encrypt_file(argv[3], raw_sk, raw_len, fdptxt);

        /* scrub the buffer that's holding the key before exiting */
        bzero(raw_sk, raw_len);

        close(fdptxt);
    }

    return 0;
}
