#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"

#include <stdio.h>

// void print_buf_prefix(const uint8_t *buf, size_t len) {
//   printf("前 %zu 个字节的值：\n", len);
//   for (size_t i = 0; i < len; i++) {
//       printf("%02x ", buf[i]);  // 以十六进制格式打印
//       if ((i + 1) % 16 == 0) printf("\n");  // 每行显示 16 个字节
//   }
//   printf("\n");
// }
const uint32_t COMPRESS_LUT[32] = {
  // 第一部分: 修改的Blake2b初值
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
  
  // 第二部分: SHA-256常量
  0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
  0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
  
  // 第三部分: 自定义加密常数
  0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
  0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
  
  // 第四部分: 质数衍生的常数
  0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
  0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA
};

// LUT压缩函数 - 输出16字节摘要
void lut_compress(uint8_t output[16], const uint8_t *data, size_t len)
{
    uint32_t state[4] = {0};  // 128位内部状态
    size_t blocks = len / 16; // 完整块数量
    
    // 处理完整16字节块
    for (size_t i = 0; i <= blocks; i++) {
        uint32_t block_words[4] = {0};
        const uint8_t *current = data + i*16;
        size_t bytes_left = (i == blocks) ? (len % 16) : 16;
        
        // 组装当前块为4个32位字
        for (size_t j = 0; j < bytes_left; j++) {
            block_words[j/4] |= (uint32_t)(current[j]) << (8*(j%4));
        }
        
        // LUT轮变换
        for (int j = 0; j < 4; j++) {
            // 1. 获取当前状态的低5位作为LUT索引(0-31)
            uint32_t lut_index = (state[j] & 0x1F);
            
            // 2. 从LUT获取值并与状态混合
            uint32_t lut_value = COMPRESS_LUT[lut_index];
            
            // 3. 状态循环移位操作
            uint32_t shift = (lut_value % 24) + 8; // 8-32位移位
            state[j] = (state[j] << shift) | (state[j] >> (32 - shift));
            
            // 4. 核心混合：状态 = (状态 ^ 数据字) + LUT值
            state[j] = (state[j] ^ block_words[j]) + lut_value;
        }
    }
    
    // 输出处理后的状态
    for (int i = 0; i < 4; i++) {
        output[i*4]   = (state[i] >> 24) & 0xFF;
        output[i*4+1] = (state[i] >> 16) & 0xFF;
        output[i*4+2] = (state[i] >> 8)  & 0xFF;
        output[i*4+3] = state[i] & 0xFF;
    }
}

// 奇偶校验生成 - 输出4字节校验和
void generate_parity(uint8_t parity[4], const uint8_t *ct, size_t len)
{
    uint32_t sum = 0;
    uint32_t product = 1;
    
    // 两层校验：简单累加和乘法模运算
    for (size_t i = 0; i < len; i++) {
        sum += ct[i];
        product = (product * (ct[i] | 1)) % 0x9B73F; // 655359附近的大质数
    }
    
    // 组合两种校验值
    uint32_t combined = (sum + (product << 16)) % 0xFFFFFF;
    
    // 转为4字节输出
    parity[0] = (combined >> 16) & 0xFF;
    parity[1] = (combined >> 8)  & 0xFF;
    parity[2] = combined & 0xFF;
    parity[3] = (sum ^ product) & 0xFF; // 异或验证
}

/*************************************************
* Name:        crypto_kem_keypair_derand
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*              - uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with 2*KYBER_SYMBYTES random bytes)
**
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair_derand(uint8_t *pk,
                              uint8_t *sk,
                              const uint8_t *coins)
{
  indcpa_keypair_derand(pk, sk, coins);
  memcpy(sk+KYBER_POLYVECBYTES, pk, KYBER_PUBLICKEYBYTES);

  lut_compress(sk+KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
  generate_parity(sk+KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + KYBER_LUTBYTES, pk, KYBER_PUBLICKEYBYTES);
  
  /* Value z for pseudo-random output on reject */
  memcpy(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, coins+KYBER_SYMBYTES, KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk)
{
  uint8_t coins[2*KYBER_SYMBYTES];
  randombytes(coins, 2*KYBER_SYMBYTES);
  crypto_kem_keypair_derand(pk, sk, coins);
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc_derand
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - const uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with KYBER_SYMBYTES random bytes)
**
* Returns 0 (success)
**************************************************/
int crypto_kem_enc_derand(uint8_t *ct,
                          uint8_t *ss,
                          const uint8_t *pk,
                          const uint8_t *coins)
{
  uint8_t buf[KYBER_SYMBYTES + 1 + KYBER_LUTBYTES + KYBER_PARITYBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];

  memcpy(buf, coins, KYBER_SYMBYTES);
  buf[KYBER_SYMBYTES] = 0x02;

  /* Multitarget countermeasure for coins + contributory KEM */
  // hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_h(buf+KYBER_SYMBYTES+1, pk, KYBER_PUBLICKEYBYTES);

  lut_compress(buf+KYBER_SYMBYTES + 1, pk, KYBER_PUBLICKEYBYTES);
  generate_parity(buf+KYBER_SYMBYTES + 1 + KYBER_LUTBYTES, pk, KYBER_PUBLICKEYBYTES);

  // hash_g(kr, buf, 2*KYBER_SYMBYTES);
  hash_g(kr, buf, KYBER_SYMBYTES + 1 + KYBER_LUTBYTES + KYBER_PARITYBYTES);

  // printf("加密明文\n");
  // print_buf_prefix(buf, 32);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  memcpy(ss,kr,KYBER_SYMBYTES);
  // kr的前32字节作为共享密钥

  memset(buf, 0, sizeof(buf));
  memset(kr, 0, sizeof(kr));

  return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk)
{
  uint8_t coins[KYBER_SYMBYTES];
  randombytes(coins, KYBER_SYMBYTES);
  crypto_kem_enc_derand(ct, ss, pk, coins);
  return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  int fail;
  uint8_t buf[KYBER_SYMBYTES + 1 + KYBER_LUTBYTES + KYBER_PARITYBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  // uint8_t cmp[KYBER_CIPHERTEXTBYTES+KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  // printf("解密明文\n");
  // print_buf_prefix(buf, 32);

  /* Multitarget countermeasure for coins + contributory KEM */
  buf[KYBER_SYMBYTES] = 0x02;
  // memcpy(buf+KYBER_SYMBYTES, sk+SMALL_SECRETKEYBYTES-2*KYBER_SYMBYTES, KYBER_SYMBYTES);
  memcpy(buf+KYBER_SYMBYTES + 1, sk + KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES, KYBER_LUTBYTES + KYBER_PARITYBYTES);
  hash_g(kr, buf, KYBER_SYMBYTES + 1 + KYBER_LUTBYTES + KYBER_PARITYBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  rkprf(ss,sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES,ct);

  cmov(ss,kr,KYBER_SYMBYTES,!fail);

  memset(buf, 0, sizeof(buf));
  memset(kr, 0, sizeof(kr));
  memset(cmp, 0, sizeof(cmp));

  return 0;
}
