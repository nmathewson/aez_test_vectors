
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

typedef unsigned char u8;
typedef unsigned char byte;

void
rng(u8 *buf, size_t n)
{
  arc4random_buf(buf, n);
}

unsigned
rng_u(unsigned limit)
{
  return arc4random_uniform(limit);
}

void
dump(const u8 *buf, size_t n)
{
  int i;
  putc('\"', stdout);
  for (i = 0; i < n; ++i)
    printf("%02x", buf[i]);
  putc('\"', stdout);
}

/* Test vectors for Extract */
void Extract(byte *K, unsigned kbytes, byte extracted_key[3*16]);

void
single_extract(const u8 *s, size_t n)
{
  byte key[3*16];
  Extract((u8*)s, n, key);
  printf("  (");
  dump(s, n);
  printf(", ");
  dump(key, sizeof(key));
  printf("),\n");
}

void
tv_extract(void)
{
  const char long_string[] = "This is a string of at least eighty characters"
    "to ensure we cover multiple blake2b blocks.\x00\xff\xf0\xa0 Also those.";
  puts("EXTRACT_VECTORS = [");
  puts("  # (a,b)  ==>  Extract(a) = b.");
  single_extract((u8*)"", 0);
  single_extract((u8*)"", 1);
  single_extract((u8*)"a", 1);

  unsigned i;
  for (i = 0; i <= sizeof(long_string); ++i) {
    single_extract((u8*)long_string, i);
  }
  puts("]\n\n");
}

/* Now the core piece. We're going to do tests for the tweakable block cipher,
 * E. Not every implementation will have an E that takes arbitrary
 * arguments.
 *
 * We're also checking j,i combinations that AEZ never uses.
 */
void E(byte *K, unsigned kbytes, int j, unsigned i,
       byte src[16], byte dst[16]);

void
e_single(u8 key[48], int j, int i, u8 src[16])
{
  u8 dst[16];
  E(key, 48, j, i, src, dst);
  printf("  (");
  dump(key, 48);
  printf(", %d, %d, ", j, i);
  dump(src, 16);
  printf(", ");
  dump(dst, 16);
  printf("),\n");
}

void
e_rand(int j, int i)
{
  u8 key[48];
  u8 src[16];
  rng(key, sizeof(key));
  rng(src, sizeof(src));
  e_single(key, j, i, src);
}

void
tv_e(void)
{
  int i, j;
  puts("E_VECTORS = [");
  puts("  # (K,j,i,a,b)  ==>  E_K^{j,i}(a) = b.");
  for (j = -1; j <= 2; ++j) {
    for (i = 0; i <= 32; ++i) {
      e_rand(j, i);
      e_rand(j, i);
    }
  }
  for (j = 3; j <= 17; ++j) {
    for (i = 0; i <= 17; ++i) {
      e_rand(j, i);
    }
  }
  puts("]\n\n");
}

/* Now we're going to check AEZ-hash, which takes a key and a vector of
 * strings.
 */
void AEZhash(byte *K, unsigned kbytes, byte *N, unsigned nbytes,
             byte *A[], unsigned abytes[], unsigned veclen, unsigned tau,
             byte *result);

/* The first string is a nonce */
void
hash_single(u8 key[48], unsigned tau, int n_strings, unsigned *lengths,
            u8 **strings)
{
  u8 result[16];
  assert(n_strings >= 1);
  AEZhash(key, 48,
          strings[0], lengths[0],
          strings+1, lengths+1, n_strings - 1,
          tau,
          result);

  printf("  (");
  dump(key, 48);
  printf(", %u, [", tau);
  int i;
  for (i = 0; i < n_strings; ++i) {
    dump(strings[i], lengths[i]);
    if (i == n_strings - 1)
      break;
    printf(", ");
  }
  printf("], ");
  dump(result, 16);
  printf("),\n");
}

void
tv_hash(void)
{
  puts("HASH_VECTORS = [");
  puts("  # (K, tau, [N, A...], V) ==> AEZ-hash(K, ([tau]_128, N, A...)) = V");

  int n_strings, i;
  const int max_string = 100;
  u8 *strings[18];
  unsigned lengths[18];
  for (i = 0; i < 18; ++i)
    strings[i] = malloc(max_string);

  u8 key[48];

  for (n_strings = 1; n_strings < 18; ++n_strings) {
    rng(key, sizeof(key));
    unsigned tau = rng_u(513);
    for (i = 0; i < n_strings; ++i) {
      lengths[i] = rng_u(max_string);
      rng(strings[i], lengths[i]);
    }
    hash_single(key, tau, n_strings, lengths, strings);
  }

  /* Try 0 tau. */
  hash_single(key, 0, 1, lengths, strings);

  /* Try multiple empty strings */
  for (i = 0; i < 18; ++i) {
    lengths[i] = 0;
  }
  hash_single(key, 0, 1, lengths, strings);
  hash_single(key, 0, 2, lengths, strings);
  hash_single(key, 0, 3, lengths, strings);

  for (i = 0; i < 18; ++i)
    free(strings[i]);

  puts("]\n\n");
}

/* Now test the PRF function */
void AEZprf(byte *K, unsigned kbytes, byte delta[16],
            unsigned bytes, byte *result);

void
prf_single(u8 key[48],
           u8 delta[16],
           unsigned bytes)
{
  u8 *r = malloc(bytes+1);
  AEZprf(key, 48, delta, bytes, r);
  printf("  (");
  dump(key, 48);
  printf(", ");
  dump(delta, 16);
  printf(", %u, ", bytes);
  dump(r, bytes);
  printf("),\n");
  free(r);
}

void
tv_prf(void)
{
  puts("PRF_VECTORS = [");
  puts("  # (K, delta, tau, R) ==> AEZ-prf(K, T, tau*8) = R where delta = AEZ-hash(K,T)");
  int i;
  u8 k[48];
  u8 d[16];

  for (i = 0; i < 8; ++i) {
    rng(k, sizeof(k));
    rng(d, sizeof(d));
    prf_single(k,d, 15 + rng_u(20));
  }
  for (i = 0; i < 8; ++i) {
    rng(k, sizeof(k));
    rng(d, sizeof(d));
    prf_single(k,d, rng_u(256));
  }

  puts("]");
}

/* Finally, tests for encrypt.  These are mostly glassbox to select different
 * lengths.  We assume that AEZ-hash is wired up correctly, so that we don't
 * need to test too many varieties of additional data. */
void Encrypt(byte *K, unsigned kbytes,
             byte *N, unsigned nbytes,
             byte *AD[], unsigned adbytes[],
             unsigned veclen, unsigned abytes,
             byte *M, unsigned mbytes, byte *C);
void
encrypt_single(u8 key[48],
               u8 nonce[16],
               u8 *ad[], unsigned adbytes[], unsigned veclen,
               u8 taubytes,
               u8 *msg, unsigned msgbytes)
{
  unsigned clen = msgbytes + taubytes;
  u8 *ciphertext = malloc(clen);
  Encrypt(key, 48,
          nonce, 16,
          ad, adbytes, veclen,
          taubytes,
          msg, msgbytes, ciphertext);

  printf("  (");
  dump(key, 48);
  printf(", ");
  dump(nonce, 16);
  printf(", [");
  int i;
  for (i = 0; i < veclen; ++i) {
    dump(ad[i], adbytes[i]);
    if (i == veclen-1)
      break;
    printf(", ");
  }
  printf("], %u, ", taubytes);
  dump(msg, msgbytes);
  printf(", ");
  dump(ciphertext, clen);
  printf("),\n");
  free(ciphertext);
}

void
encrypt_rand(u8 taubytes, size_t msglen)
{
  u8 k[48];
  u8 n[16];
  u8 *ad[3];
  unsigned adlen[3] = { 10, 0, 15 };

  rng(k, 48);
  rng(n, 16);
  ad[0] = malloc(10);
  ad[1] = malloc(1);
  ad[2] = malloc(15);
  rng(ad[0], 10);
  rng(ad[1], 0);
  rng(ad[2], 15);
  u8 *msg = malloc(msglen);
  rng(msg, msglen);

  encrypt_single(k, n, ad, adlen, 3, taubytes, msg, msglen);

  free(msg);
  free(ad[0]);
  free(ad[1]);
  free(ad[2]);
}

void
tv_encrypt(void)
{
  int i;

  puts("ENCRYPT_VECTORS = [");
  puts("  # (K, N, A, taubytes, M, C) ==> Encrypt(K,N,A,taubytes*8,M) = C");
  for (i = 0; i < 512; ++i) {
    encrypt_rand(0, i);
    encrypt_rand(16, i);
  }
  puts("]\n\n");
}


int
main(int argc, char **argv)
{
  tv_extract();
  tv_e();
  tv_hash();
  tv_prf();

  tv_encrypt();

  return 0;
}
