#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "ascon_hash.h"


#define ascon_prf KYBER_NAMESPACE(ascon_prf)
void ascon_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

#define ascon_rkprf KYBER_NAMESPACE(ascon_rkprf)
void ascon_rkprf(unsigned char* out, unsigned long long outlen,
    const unsigned char* in, unsigned long long inlen,
    const unsigned char* k);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) ascon_hash_32(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) ascon_hash_64(OUT, IN, INBYTES)

#define kdf(OUT, IN, INBYTES) ascon_xof(OUT, KYBER_SSBYTES, IN, INBYTES)
#define xof_ascon(OUT, OUTLEN, EXTSEED, LEN) ascon_xof(OUT, OUTLEN, EXTSEED, LEN)

#define prf(OUT, OUTBYTES, KEY, NONCE) ascon_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) ascon_rkprf(OUT,KYBER_SSBYTES, INPUT, KYBER_CIPHERTEXTBYTES, KEY)

#endif /* SYMMETRIC_H */
