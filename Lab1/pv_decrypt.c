/* Bradford Smith (bsmith8)
 * CS 579 Lab 1 pv_decrypt.c
 * 04/13/2016
 * "I pledge my honor that I have abided by the Stevens Honor System."
 */

#include "pv.h"

void decrypt_file(const char *ptxt_fname, void *raw_sk, size_t raw_len, int fin)
{
    /***************************************************************************
     * Task: Read the ciphertext from the file descriptor fin, decrypt it using
     *       sk, and place the resulting plaintext in a file named ptxt_fname.
     *
     * This procedure basically `undoes' the operations performed by pv_encrypt;
     * it expects a ciphertext featuring the following structure (please refer
     * to the comments in edu_encrypt.c for more details):
     *
     *
     *         +--------------------------+---+
     *         |             Y            | W |
     *         +--------------------------+---+
     *
     * where Y = AES-CTR (K_CTR, plaintext)
     *       W = AES-CBC-MAC (K_MAC, Y)
     *
     * Note that the length of Y (in bytes) is not necessarily a
     * multiple of 16 (aes_blocklen) (it is just 16 bytes more than the
     * length of the original plaintext), whereas W is exactly 16-byte
     * long.  So to figure out the split between Y and W, you could
     * repeatedly attempt to perform `long read' of (2 * aes_blocklen +
     * 1) bytes: once we get to the end of the ciphertext and only the
     * last chunk of Y has to be read, such "long reads" will encounter
     * the end-of-file, at which point we will know where Y ends, and
     * how to finish reading the last bytes of the ciphertext.
     *
     */
    int fdptxt = 0;
    char *k_ctr = NULL;
    char *k_mac = NULL;
    char *k_mac_b = NULL;
    char *k_mac_e = NULL;
    char *iv = NULL;
    char mac[CCA_STRENGTH];
    char buf[CCA_STRENGTH + 1];
    char output[CCA_STRENGTH + 1];
    const char body[16] = {'b', 'o', 'd', 'y', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const char end[16] = {'e', 'n', 'd', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned int counter = 0;
    int n = 0;
    int i = 0;
    aes_ctx *ctx = NULL;

    /* use the first part of the symmetric key for the AES-CTR decryption ...*/
    k_ctr = (char*)memcpy((void*)k_ctr, raw_sk, raw_len/2);

    /* ... and the second for the AES-CBC-MAC */
    raw_sk = raw_sk + (raw_len/2) - 1;
    k_mac = (char*)memcpy((void*)k_mac, raw_sk, raw_len/2);
    aes_setkey(ctx, k_mac, raw_len/2);
    aes_encrypt(ctx, k_mac_b, body);
    aes_encrypt(ctx, k_mac_e, end);

    /* Reading Y */
    /* First, read the IV (Initialization Vector) */
    if ((n = read(fin, iv, CCA_STRENGTH)) <= 0)
    {
        perror(getprogname());

        /* scrub the buffer that's holding the key before exiting */
        bzero(raw_sk, raw_len);

        exit(-1);
    }

    /* compute the AES-CBC-MAC as you go */

    /* Create plaintext file---may be confidential info, so permission is 0600 */
    if ((fdptxt = open(ptxt_fname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1)
    {
        perror(getprogname());

        /* scrub the buffer that's holding the key before exiting */
        bzero(raw_sk, raw_len);

        exit(-1);
    }

    /* CTR-mode decryption */

    /* If this is the last block and its length is less than
     * aes_blocklen, remember to chop off the least-significant bytes
     * output by AES.
     */

    /* Recall that we are reading aes_blocklen + 1 bytes ahead: now that
     * we just consumed aes_blocklen bytes from the front of the buffer, let's
     * shift the remaining aes_blocklen + 1 bytes by aes_blocklen bytes
     */

    /* write the decrypted chunk to the plaintext file */

    /* now we can finish computing the AES-CBC-MAC */

    /* compare the AES-CBC-MAC we computed with the value read from
       fin */

    /* NB: if the AES-CBC-MAC value stored in the ciphertext file does
     * not match what we just computed, destroy the whole plaintext
     * file! That means that somebody tampered with the ciphertext file,
     * and you should not decrypt it.  Otherwise, the CCA-security is
     * gone.
     */

    /* write the last chunk of plaintext---remember that it may be
     *  shorter than aes_blocklen
     */

}

void usage(const char *pname)
{
    printf("Simple File Decryption Utility\n");
    printf("Usage: %s SK-FILE CTEXT-FILE PTEXT-FILE\n", pname);
    printf("       Exits if either SK-FILE or CTEXT-FILE don't exist, or\n");
    printf("       if a symmetric key sk cannot be found in SK-FILE.\n");
    printf("       Otherwise, tries to use sk to decrypt the content of\n");
    printf("       CTEXT-FILE: upon success, places the resulting plaintext\n");
    printf("       in PTEXT-FILE; if a decryption problem is encountered\n");
    printf("       after the processing started, PTEXT-FILE is truncated\n");
    printf("       to zero-length and its previous content is lost.\n");

    exit(1);
}

int main(int argc, char **argv)
{
    int fdsk, fdctxt;
    char *sk = NULL;
    size_t sk_len = 0;

    if (argc != 4)
    {
        usage(argv[0]);
    }   /* Check if argv[1] and argv[2] are existing files */
    else if (((fdsk = open(argv[1], O_RDONLY)) == -1)
            || ((fdctxt = open(argv[2], O_RDONLY)) == -1))
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
        if (!(sk = import_sk_from_file (&sk, &sk_len, fdsk)))
        {
            printf("%s: no symmetric key found in %s\n", argv[0], argv[1]);

            close(fdsk);
            exit(2);
        }
        close(fdsk);

        /* Enough setting up---let's get to the crypto... */
        decrypt_file(argv[3], sk, sk_len, fdctxt);

        /* scrub the buffer that's holding the key before exiting */
        bzero(sk, sk_len);

        close(fdctxt);
    }

    return 0;
}
