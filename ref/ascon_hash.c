#include "ascon_hash.h" //api.h
#include <stdio.h>
#include <string.h>

/*************************************************
* Name:       ascon_hash 32
*
* Description: 32 Bytes output
*
**************************************************/
void ascon_hash_32(uint8_t *out, const uint8_t *in, size_t len)
{
    printbytes("m", in, len);
    /* initialize */
    ascon_state_t s;
    s.x[0] = ASCON_HASH_IV;
    s.x[1] = 0;
    s.x[2] = 0;
    s.x[3] = 0;
    s.x[4] = 0;
    printstate("initial value", &s);
    P8(&s);
    printstate("initialization", &s);
  
    /* absorb full plaintext blocks */
    while (len >= ASCON_HASH_RATE) {
      s.x[0] ^= LOADBYTES(in, 8);
      printstate("absorb plaintext", &s);
      P8(&s);
      in += ASCON_HASH_RATE;
      len -= ASCON_HASH_RATE;
    }
    /* absorb final plaintext block */
    s.x[0] ^= LOADBYTES(in, len);
    s.x[0] ^= PAD(len);
    printstate("pad plaintext", &s);
    P8(&s);
  
    /* squeeze full output blocks */
    len = 32;
    while (len > ASCON_HASH_RATE) {
      STOREBYTES(out, s.x[0], 8);
      printstate("squeeze output", &s);
      P8(&s);
      out += ASCON_HASH_RATE;
      len -= ASCON_HASH_RATE;
    }
    /* squeeze final output block */
    STOREBYTES(out, s.x[0], len);
    printstate("squeeze output", &s);
    printbytes("h", out + len - 32, 32);
}
/*************************************************
* Name:       ascon_hash 64
*
* Description: 64 Bytes output
*
**************************************************/
void ascon_hash_64(uint8_t *out, const uint8_t *in, size_t len)
{
    printbytes("m", in, len);
    /* initialize */
    ascon_state_t s;
    s.x[0] = ASCON_HASH_IV;
    s.x[1] = 0;
    s.x[2] = 0;
    s.x[3] = 0;
    s.x[4] = 0;
    printstate("initial value", &s);
    P8(&s);
    printstate("initialization", &s);
  
    /* absorb full plaintext blocks */
    while (len >= ASCON_HASH_RATE) {
      s.x[0] ^= LOADBYTES(in, 8);
      printstate("absorb plaintext", &s);
      P8(&s);
      in += ASCON_HASH_RATE;
      len -= ASCON_HASH_RATE;
    }
    /* absorb final plaintext block */
    s.x[0] ^= LOADBYTES(in, len);
    s.x[0] ^= PAD(len);
    printstate("pad plaintext", &s);
    P8(&s);
  
    /* squeeze full output blocks */
    len = 64;
    while (len > ASCON_HASH_RATE) {
      STOREBYTES(out, s.x[0], 8);
      printstate("squeeze output", &s);
      P8(&s);
      out += ASCON_HASH_RATE;
      len -= ASCON_HASH_RATE;
    }
    /* squeeze final output block */
    STOREBYTES(out, s.x[0], len);
    printstate("squeeze output", &s);
    printbytes("h", out + len - 64, 64);
}

/*************************************************
* Name:        ascon_xof
*
* Description: 
*
**************************************************/
void ascon_xof(uint8_t *out,size_t outlen, const uint8_t *in, size_t inlen)
{
    printbytes("m", in, inlen);
  /* initialize */
  ascon_state_t s;
  s.x[0] = ASCON_XOF_IV;
  s.x[1] = 0;
  s.x[2] = 0;
  s.x[3] = 0;
  s.x[4] = 0;
  printstate("initial value", &s);
  P6(&s);
  printstate("initialization", &s);

  /* absorb full plaintext blocks */
  while (inlen >= ASCON_HASH_RATE) {
    s.x[0] ^= LOADBYTES(in, 8);
    printstate("absorb plaintext", &s);
    P6(&s);
    in += ASCON_HASH_RATE;
    inlen -= ASCON_HASH_RATE;
  }
  /* absorb final plaintext block */
  s.x[0] ^= LOADBYTES(in, inlen);
  s.x[0] ^= PAD(inlen);
  printstate("pad plaintext", &s);
  P6(&s);

  /* squeeze full output blocks */
  inlen = outlen;
  while (inlen > ASCON_HASH_RATE) {
    STOREBYTES(out, s.x[0], 8);
    printstate("squeeze output", &s);
    P6(&s);
    out += ASCON_HASH_RATE;
    inlen -= ASCON_HASH_RATE;
  }
  /* squeeze final output block */
  STOREBYTES(out, s.x[0], inlen);
  printstate("squeeze output", &s);
  printbytes("h", out + inlen - outlen, outlen);
}
