// Stubs for tor functions, unused functions
// include an abort to ensure they aren't actually
// called

void memwipe(void *mem, uint8_t byte, size_t sz)
{
    (void)mem;
    (void)byte;
    (void)sz;

    abort();
}

void crypto_strongest_rand(uint8_t* out, size_t out_len)
{
    (void)out;
    (void)out_len;

    abort();
}

// Stubs for unused openssl functions

int RAND_bytes(unsigned char *buf, int num)
{
    (void)buf;
    (void)num;

    abort();
    return -1;
}

int SHA512_Init(struct SHA512_CTX *c)
{
    (void)c;

    abort();
    return -1;
}

int SHA512_Update(struct SHA512_CTX *c, const void *data, size_t len)
{
    (void)c;
    (void)data;
    (void)len;

    abort();
    return -1;
}

int SHA512_Final(unsigned char *md, struct SHA512_CTX *c)
{
    (void)md;
    (void)c;

    abort();
    return -1;
}

unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md)
{
    (void)d;
    (void)n;
    (void)md;

    abort();
    return NULL;
}
