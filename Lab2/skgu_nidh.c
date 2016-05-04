/* Bradford Smith (bsmith8)
 * CS 579 Lab 2 skgu_nidh.c
 * 05/03/2016
 * "I pledge my honor that I have abided by the Stevens Honor System."
 */

#include "skgu.h"

#define DEFAULT_LABEL "skgu_key"

struct rawpub
{
    mpz_t p;          /* Prime */
    mpz_t q;          /* Order */
    mpz_t g;          /* Element of given order */
    mpz_t y;          /* g^x mod p */
};
typedef struct rawpub rawpub;

struct rawpriv
{
    mpz_t p;          /* Prime */
    mpz_t q;          /* Order */
    mpz_t g;          /* Element of given order */
    mpz_t x;          /* x mod q */
};
typedef struct rawpriv rawpriv;

int get_rawpub(rawpub *rpub_ptr, dckey *pub) {
    const char *pub_as_str = (const char *)dcexport(pub);

    if (skip_str(&pub_as_str, ELGAMAL_STR)
            || skip_str(&pub_as_str, ":Pub,p="))
        return -1;

    mpz_init(rpub_ptr->p);
    mpz_init(rpub_ptr->q);
    mpz_init(rpub_ptr->g);
    mpz_init(rpub_ptr->y);

    if (read_mpz(&pub_as_str, rpub_ptr->p)
            || skip_str(&pub_as_str, ",q=")
            || read_mpz(&pub_as_str, rpub_ptr->q)
            || skip_str(&pub_as_str, ",g=")
            || read_mpz(&pub_as_str, rpub_ptr->g)
            || skip_str(&pub_as_str, ",y=")
            || read_mpz(&pub_as_str, rpub_ptr->y))
    {
        return -1;
    }

    return 0;
}

int get_rawpriv(rawpriv *rpriv_ptr, dckey *priv) {
    const char *priv_as_str = (const char *)dcexport(priv);

    if (skip_str(&priv_as_str, ELGAMAL_STR)
            || skip_str(&priv_as_str, ":Priv,p="))
        return -1;

    mpz_init(rpriv_ptr->p);
    mpz_init(rpriv_ptr->q);
    mpz_init(rpriv_ptr->g);
    mpz_init(rpriv_ptr->x);

    if (read_mpz(&priv_as_str, rpriv_ptr->p)
            || skip_str(&priv_as_str, ",q=")
            || read_mpz(&priv_as_str, rpriv_ptr->q)
            || skip_str(&priv_as_str, ",g=")
            || read_mpz(&priv_as_str, rpriv_ptr->g)
            || skip_str(&priv_as_str, ",x=")
            || read_mpz(&priv_as_str, rpriv_ptr->x))
    {
        return -1;
    }

    return 0;
}

void usage(const char *pname)
{
    printf("Simple Shared-Key Generation Utility\n");
    printf("Usage: %s PRIV-FILE PRIV-CERT PRIV-ID PUB-FILE PUB-CERT PUB-ID [LABEL]\n", pname);
    exit(-1);
}

void nidh(dckey *priv, dckey *pub, char *priv_id, char *pub_id, char *label)
{
    rawpub rpub;
    rawpriv rpriv;
    mpz_t sec; /* secret */
    char* hexsec; /* secret in hex */
    int outfd; /* output file descriptor */
    char* outname;
    int name_len;
    int hash_len;
    char* key_km;
    char* key_ks0;
    char* key_ks1;
    char* input_ks0;
    char* input_ks1;
    char* key_ks;
    char* aes = "AES-CTR";
    char* cbc = "CBC-MAC";
    char* hash;
    char* buf;

    /* step 0: check that the private and public keys are compatible,
       i.e., they use the same group parameters */

    if ((-1 == get_rawpub(&rpub, pub))
            || (-1 == get_rawpriv(&rpriv, priv)))
    {
        printf("%s: trouble importing GMP values from ElGamal-like keys\n",
                getprogname());

        printf("priv:\n%s\n", dcexport_priv(priv));
        printf("pub:\n%s\n", dcexport_pub(pub));

        exit (-1);
    } else if (mpz_cmp(rpub.p, rpriv.p)
            || mpz_cmp(rpub.q, rpriv.q)
            || mpz_cmp(rpub.g, rpriv.g))
    {
        printf("%s:  the private and public keys are incompatible\n",
                getprogname());

        printf("priv:\n%s\n", dcexport_priv(priv));
        printf("pub:\n%s\n", dcexport_pub(pub));

        exit(-1);
    }
    else
    {

        /* step 1a: compute the Diffie-Hellman secret
           (use mpz_init, mpz_powm, mpz_clear; look at elgamal.c in
           the libdcrypt source directory for sample usage
           */

        mpz_init(sec);

        /* secret = y^x mod p */
        mpz_powm(sec, rpub.y, rpriv.x, rpriv.p);

        /* step 1b: order the IDs lexicographically */
        char *fst_id = NULL, *snd_id = NULL;

        if (strcmp(priv_id, pub_id) < 0)
        {
            fst_id = priv_id;
            snd_id = pub_id;
        }
        else
        {
            fst_id = pub_id;
            snd_id = priv_id;
        }

        /* step 1c: hash DH secret and ordered id pair into a master key */

        hexsec = NULL;
        if (cat_mpz(&hexsec, sec) < 0)
        {
            perror(getprogname());

            exit(-1);
        }

        hash_len = strlen(hexsec) + strlen(fst_id) + strlen(snd_id) + 1;
        hash = (char*)malloc(hash_len * sizeof(char));

        /* make sure hash buffer is empty */
        bzero(hash, hash_len * sizeof(char));

        /* create the data to hash */
        strcat(hash, hexsec);
        strcat(hash, fst_id);
        strcat(hash, snd_id);

        /* actually hash it */
        key_km = (char*)malloc(20*sizeof(char));
        bzero(key_km, 20 * sizeof(char));
        sha1_hash(key_km, hash, hash_len);

        /* step 2: derive the shared key from the label and the master key */
        /* shared key 'key_ks' is according to:
         *      key_km = sha1(dh(alice.pub, bob.pub) || fst_id || snd_id)
         *      key_ks0 = hmac_sha1(km, label || "AES-CTR")
         *      key_ks1 = hmac_sha1(km, label || "CBC-MAC")
         *      key_ks = first 16 bytes of key_ks0 || first 16 bytes of key_ks1
         */

        if ((input_ks0 = (char*)malloc((strlen(label) + 8)*sizeof(char))) == NULL)
        {
            perror(getprogname());

            mpz_clear(sec);
            free(hexsec);
            free(hash);
            free(key_km);
            exit(-1);
        }

        /* zero input_ks0 */
        bzero(input_ks0, (strlen(label) + 8)*sizeof(char));

        strcat(input_ks0, label);
        strcat(input_ks0, aes);

        if ((key_ks0 = (char*)malloc(21*sizeof(char))) == NULL)
        {
            perror(getprogname());

            mpz_clear(sec);
            free(hexsec);
            free(hash);
            free(key_km);
            free(input_ks0);
            exit(-1);
        }

        bzero(key_ks0, 21*sizeof(char));

        /* hmac key_ks0 */
        hmac_sha1(key_km, 20, key_ks0, input_ks0, strlen(label) + 7);

        if ((input_ks1 = (char*)malloc((strlen(label) + 8)*sizeof(char))) == NULL)
        {
            perror(getprogname());

            mpz_clear(sec);
            free(hexsec);
            free(hash);
            free(key_km);
            free(input_ks0);
            free(key_ks0);
            exit(-1);
        }

        /* zero input_ks1 */
        bzero(input_ks1, (strlen(label) + 8)*sizeof(char));

        strcat(input_ks1, label);
        strcat(input_ks1, cbc);

        if ((key_ks1 = (char*)malloc(21*sizeof(char))) == NULL)
        {
            perror(getprogname());

            mpz_clear(sec);
            free(hexsec);
            free(hash);
            free(key_km);
            free(input_ks0);
            free(key_ks0);
            free(input_ks0);
            exit(-1);
        }

        bzero(key_ks1, 21*sizeof(char));

        /* hmac key_ks1 */
        hmac_sha1(key_km, 20, key_ks1, input_ks1, strlen(label) + 7);

        if ((key_ks = (char*)malloc(33*sizeof(char))) == NULL)
        {
            perror(getprogname());

            mpz_clear(sec);
            free(hexsec);
            free(hash);
            free(key_km);
            free(input_ks0);
            free(key_ks0);
            free(input_ks0);
            free(key_ks1);
            exit(-1);
        }

        bzero(key_ks, 33*sizeof(char));

        strncat(key_ks, key_ks0, 16);
        strncat(key_ks, key_ks1, 16);

        /* step 3: armor the shared key and write it to file.
           Filename should be of the form <label>-<priv_id>.b64 */

        name_len = strlen(label) + strlen(priv_id);
        if ((outname = (char*)malloc((name_len + 6)*sizeof(char))) == NULL)
        {
            perror(getprogname());

            mpz_clear(sec);
            free(hexsec);
            free(hash);
            free(key_km);
            free(input_ks0);
            free(key_ks0);
            free(input_ks1);
            free(key_ks1);
            free(key_ks);
            exit(-1);
        }

        /* make sure buffer is empty before starting */
        bzero(outname, (name_len + 6)*sizeof(char));

        /* create the file name in 'outname' */
        strcat(outname, label);
        strcat(outname, "-");
        strcat(outname, priv_id);
        strcat(outname, ".b64");

        if ((outfd = open(outname, O_WRONLY|O_TRUNC|O_CREAT, 0644)) == -1)
        {
            perror(getprogname());

            mpz_clear(sec);
            free(hexsec);
            free(hash);
            free(key_km);
            free(input_ks0);
            free(key_ks0);
            free(input_ks1);
            free(key_ks1);
            free(key_ks);
            exit(-1);
        }

        /* armor the key_km and write it */
        buf = armor64(key_ks, strlen(key_ks));
        if (write(outfd, buf, strlen(buf)) == -1)
        {
            perror(getprogname());

            mpz_clear(sec);
            free(hexsec);
            free(hash);
            free(key_km);
            free(input_ks0);
            free(key_ks0);
            free(input_ks1);
            free(key_ks1);
            free(key_ks);
            free(outname);
            exit(-1);
        }

        /* clean up */
        mpz_clear(sec);
        free(hexsec);
        free(hash);
        free(key_km);
        free(input_ks0);
        free(key_ks0);
        free(input_ks1);
        free(key_ks1);
        free(key_ks);
        free(outname);
        close(outfd);
    }
}

int main(int argc, char **argv)
{
    int arg_idx = 0;
    char *privcert_file = NULL;
    char *pubcert_file = NULL;
    char *priv_file = NULL;
    char *pub_file = NULL;
    char *priv_id = NULL;
    char *pub_id = NULL;
    char *label = DEFAULT_LABEL;
    dckey *priv = NULL;
    dckey *pub = NULL;
    cert *priv_cert = NULL;
    cert *pub_cert = NULL;

    if ((7 > argc) || (8 < argc))
        usage(argv[0]);

    ri();

    priv_file = argv[++arg_idx];
    privcert_file = argv[++arg_idx];
    priv_id = argv[++arg_idx];
    pub_file  = argv[++arg_idx];
    pubcert_file = argv[++arg_idx];
    pub_id = argv[++arg_idx];
    if (argc - 2 == arg_idx)
    {
        /* there was a label */
        label = argv[++arg_idx];
    }

    pub_cert = pki_check(pubcert_file, pub_file, pub_id);
    /* check above won't return if something was wrong */
    pub = pub_cert->public_key;

    if (!cert_verify(priv_cert = cert_read(privcert_file)))
    {
        printf("%s: trouble reading certificate from %s, "
                "or certificate expired\n", getprogname(), privcert_file);
        perror(getprogname());

        exit(-1);
    }
    else if (!dcareequiv(pub_cert->issuer,priv_cert->issuer))
    {
        printf("%s: certificates issued by different CAs.\n",
                getprogname());
        printf("\tOwn (%s's) certificate in %s\n", priv_id, privcert_file);
        printf("\tOther (%s's) certificate in %s\n", pub_id, pubcert_file);
    }
    else
    {
        priv = priv_from_file(priv_file);

        nidh(priv, pub, priv_id, pub_id, label);
    }

    return 0;
}
