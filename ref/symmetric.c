#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "symmetric.h"

void ascon_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t extkey[KYBER_SYMBYTES+1];

  memcpy(extkey, key, KYBER_SYMBYTES);
  extkey[KYBER_SYMBYTES] = nonce;

  ascon_xof(out, outlen, extkey, sizeof(extkey));
}



void ascon_rkprf(unsigned char* out, unsigned long long outlen,
  const unsigned char* in, unsigned long long inlen,
  const unsigned char* k) {
if (KYBER_SSBYTES && outlen > KYBER_SSBYTES) return ;
/* load key */
const uint64_t K0 = LOADBYTES(k, 8);
const uint64_t K1 = LOADBYTES(k + 8, 8);
int i;
printbytes("k", k, KYBER_SSBYTES);
printbytes("m", in, inlen);
/* initialize */
ascon_state_t s;
s.x[0] = ASCON_PRF_IV;
s.x[1] = K0;
s.x[2] = K1;
s.x[3] = 0;
s.x[4] = 0;
printstate("initial value", &s);
P12(&s);
printstate("initialization", &s);

/* absorb full plaintext words */
i = 0;
while (inlen >= 8) {
((uint64_t*)(&s.x[0]))[i] ^= LOADBYTES(in, 8);
if (++i == 4) i = 0;
if (i == 0) printstate("absorb plaintext", &s);
if (i == 0) P12(&s);
in += 8;
inlen -= 8;
}
/* absorb final plaintext word */
((uint64_t*)(&s.x[0]))[i] ^= LOADBYTES(in, inlen);
((uint64_t*)(&s.x[0]))[i] ^= PAD(inlen);
printstate("pad plaintext", &s);
/* domain separation */
s.x[4] ^= DSEP();
printstate("domain separation", &s);

/* squeeze */
P12(&s);
/* squeeze output words */
i = 0;
while (outlen > 8) {
STOREBYTES(out, ((uint64_t*)(&s.x[0]))[i], 8);
if (++i == 2) i = 0;
if (i == 0) printstate("squeeze output", &s);
if (i == 0) P12(&s);
out += 8;
outlen -= 8;
}
/* squeeze final output word */
STOREBYTES(out, ((uint64_t*)(&s.x[0]))[i], outlen);
printstate("squeeze output", &s);
printbytes("t", out, KYBER_SSBYTES);
print("\n");
}
