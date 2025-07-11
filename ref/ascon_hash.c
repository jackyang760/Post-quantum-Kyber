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
    P6(&s);
    printstate("initialization", &s);
  
    /* absorb full plaintext blocks */
    while (len >= ASCON_HASH_RATE) {
      s.x[0] ^= LOADBYTES(in, 8);
      printstate("absorb plaintext", &s);
      P6(&s);
      in += ASCON_HASH_RATE;
      len -= ASCON_HASH_RATE;
    }
    /* absorb final plaintext block */
    s.x[0] ^= LOADBYTES(in, len);
    s.x[0] ^= PAD(len);
    printstate("pad plaintext", &s);
    P6(&s);
  
    /* squeeze full output blocks */
    len = 32;
    while (len > ASCON_HASH_RATE) {
      STOREBYTES(out, s.x[0], 8);
      printstate("squeeze output", &s);
      P6(&s);
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
    s.x[0] = ASCON_XOF_IV;
    s.x[1] = 0;
    s.x[2] = 0;
    s.x[3] = 0;
    s.x[4] = 0;
    printstate("initial value", &s);
    P6(&s);
    printstate("initialization", &s);
  
    /* absorb full plaintext blocks */
    while (len >= ASCON_HASH_RATE) {
      s.x[0] ^= LOADBYTES(in, 8);
      printstate("absorb plaintext", &s);
      P6(&s);
      in += ASCON_HASH_RATE;
      len -= ASCON_HASH_RATE;
    }
    /* absorb final plaintext block */
    s.x[0] ^= LOADBYTES(in, len);
    s.x[0] ^= PAD(len);
    printstate("pad plaintext", &s);
    P6(&s);
  
    /* squeeze full output blocks */
    len = 64;
    while (len > ASCON_HASH_RATE) {
      STOREBYTES(out, s.x[0], 8);
      printstate("squeeze output", &s);
      P6(&s);
      out += ASCON_HASH_RATE;
      len -= ASCON_HASH_RATE;
    }
    /* squeeze final output block */
    STOREBYTES(out, s.x[0], len);
    printstate("squeeze output", &s);
    printbytes("h", out + len - 64, 64);
}

void ascon_hash_64_P12(uint8_t *out, const uint8_t *in, size_t len)
{
    printbytes("m", in, len);
    /* initialize */
    ascon_state_t s;
    s.x[0] = ASCON_XOF_IV;
    s.x[1] = 0;
    s.x[2] = 0;
    s.x[3] = 0;
    s.x[4] = 0;
    printstate("initial value", &s);
    P12(&s);
    printstate("initialization", &s);
  
    /* absorb full plaintext blocks */
    while (len >= ASCON_HASH_RATE) {
      s.x[0] ^= LOADBYTES(in, 8);
      printstate("absorb plaintext", &s);
      P12(&s);
      in += ASCON_HASH_RATE;
      len -= ASCON_HASH_RATE;
    }
    /* absorb final plaintext block */
    s.x[0] ^= LOADBYTES(in, len);
    s.x[0] ^= PAD(len);
    printstate("pad plaintext", &s);
    P12(&s);
  
    /* squeeze full output blocks */
    len = 64;
    while (len > ASCON_HASH_RATE) {
      STOREBYTES(out, s.x[0], 8);
      printstate("squeeze output", &s);
      P12(&s);
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

// 初始化函数
void ascon_init(ascon_state_t *state) {
  // ASCON_XOF_IV = Ascon的初始化向量(根据规范定义)
  state->x[0] = ASCON_XOF_IV;
  state->x[1] = 0;
  state->x[2] = 0;
  state->x[3] = 0;
  state->x[4] = 0;
  state->absorbed = 0;
  
  // 初始置换（6轮）
  P6(state);
}

// 吸收数据（支持多次调用）
void ascon_absorb(ascon_state_t *state, const uint8_t *data, size_t len) {
  size_t block_size = ASCON_HASH_RATE; // 通常为8字节
  size_t offset = state->absorbed % block_size;
  
  // 1. 处理未完成的块
  if (offset > 0) {
      size_t to_fill = block_size - offset;
      if (len < to_fill) {
          // 部分填充当前块
          memcpy((uint8_t*)&state->x[0] + offset, data, len);
          state->absorbed += len;
          return;
      }
      
      // 完成当前块
      memcpy((uint8_t*)&state->x[0] + offset, data, to_fill);
      state->x[0] ^= 0; // 避免未定义行为
      P6(state);
      
      data += to_fill;
      len -= to_fill;
      state->absorbed += to_fill;
  }
  
  // 2. 处理完整块
  while (len >= block_size) {
      state->x[0] ^= LOADBYTES(data, block_size);;
      P6(state);
      
      data += block_size;
      len -= block_size;
      state->absorbed += block_size;
  }
  
  // 3. 保存部分块
  if (len > 0) {
      memcpy(&state->x[0], data, len);
      state->absorbed += len;
  }
}

// 结束吸收并应用填充
void ascon_finalize(ascon_state_t *state) {
  size_t block_size = ASCON_HASH_RATE;
  size_t rem = state->absorbed % block_size;
  
  // 应用填充：0x80后跟0s
  uint8_t pad_byte = 0x80;
  if (rem == 0) {
      // 全零块 + 填充
      state->x[0] ^= (uint64_t)pad_byte << 56; // 大端序处理
  } else {
      // 部分块填充
      ((uint8_t*)&state->x[0])[rem] = pad_byte;
      memset((uint8_t*)&state->x[0] + rem + 1, 0, block_size - rem - 1);
  }
  
  P6(state);
}

// 输出任意长度的摘要
void ascon_squeeze(ascon_state_t *state, uint8_t *out, size_t outlen) {
  size_t block_size = ASCON_HASH_RATE;
  
  while (outlen > 0) {
      size_t to_copy = outlen < block_size ? outlen : block_size;
      
      STOREBYTES(out, state->x[0], to_copy);
      out += to_copy;
      outlen -= to_copy;
      
      if (outlen > 0) {
          P6(state);  // 需要更多输出时再置换
      }
  }
}

// 统一的XOF函数（保持兼容性）
void ascon_xof(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
  ascon_state_t state;
  ascon_init(&state);
  ascon_absorb(&state, in, inlen);
  ascon_finalize(&state);
  ascon_squeeze(&state, out, outlen);
}

/* 在文件开头添加 Ascon 批量生成函数 */
void ascon_xof_init(ascon_state_t *state, 
  const uint8_t seed[KYBER_SYMBYTES],
  uint16_t nonce)
{
  uint8_t nonce_bytes[2] = { nonce & 0xFF, (nonce >> 8) & 0xFF };
  ascon_init(state);
  ascon_absorb(state, seed, KYBER_SYMBYTES);
  ascon_absorb(state, nonce_bytes, 2);
  ascon_finalize(state);
}

/* 批量挤压优化版 */
void ascon_xof_squeezeblocks(ascon_state_t *state, 
           uint8_t *out, 
           size_t nblocks)
{
  const size_t block_size = ASCON_HASH_RATE;
  for (size_t i = 0; i < nblocks; i++) {
    ascon_squeeze(state, out + i * block_size, block_size);
  }
}