#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "../kem.h"
#include "../randombytes.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>



typedef struct {
  uint8_t kyber_pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t rsa_pk[550];  // 例如 RSA 4096 公钥 PEM 格式长度预估
  // 2048 位 RSA 公钥的 PEM 格式通常约 400-450 字节
  // 4096 位 RSA 公钥的 PEM 格式可能达到 800 字节以上
  // uint8_t rsa_pk[1024]; // 增加为 1024 字节
} hybrid_publickey_t;

typedef struct {
  uint8_t kyber_sk[CRYPTO_SECRETKEYBYTES];
  EVP_PKEY *rsa_sk; // OpenSSL RSA 私钥结构体
} hybrid_secretkey_t;

// 添加这些原型声明
int generate_hybrid_keypair(hybrid_publickey_t *hpk, hybrid_secretkey_t *hsk);
int hybrid_encrypt(const hybrid_publickey_t *hpk, const uint8_t *plaintext, int plen,
                   uint8_t *out_ciphertext, int *outlen, uint8_t *iv, uint8_t *tag);
// int hybrid_decrypt(const hybrid_secretkey_t *hsk, const uint8_t *cipher_in, int clen,
//                    const uint8_t *iv, const uint8_t *tag, uint8_t *plaintext_out);
int hybrid_decrypt(const hybrid_secretkey_t *hsk, const uint8_t *cipher_in, int clen,
                    uint8_t *plaintext_out);

#define AES_KEY_LEN 32  // 256 bits
#define AES_IV_LEN 12   // GCM standard IV length
#define AES_TAG_LEN 16  // GCM tag length

static void print_bytes(const char *label, const uint8_t *buf, size_t len) {
  printf("%s = ", label);
  for (size_t i = 0; i < len; i++) {
    printf("%02x", buf[i]);
    if ((i + 1) % 32 == 0) printf("\n");  // 每32字节换行
  }
  if (len % 32 != 0) printf("\n");
  printf("\n");
}

// AES 对称加密
static int aes_gcm_encrypt(const uint8_t *plaintext, int plaintext_len,
  const uint8_t *key,
  uint8_t *iv, uint8_t *ciphertext, uint8_t *tag) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len, ciphertext_len;

  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, NULL);
  EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

  EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
  ciphertext_len = len;

  EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
  ciphertext_len += len;

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag);
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

//AES 对称解密
static int aes_gcm_decrypt(const uint8_t *ciphertext, int ciphertext_len,
  const uint8_t *tag, const uint8_t *key,
  const uint8_t *iv, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len, ret;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN, (void *)tag);
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
      plaintext_len += len;
      return plaintext_len;
    } else {
    return -1; // decryption failed
  }
}

static int test_keys(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  const char *message = "Secret Message!";
  uint8_t iv[AES_IV_LEN];
  uint8_t tag[AES_TAG_LEN];
  uint8_t ciphertext[128];
  uint8_t decrypted[128];

  RAND_bytes(iv, sizeof(iv));  // generate random IV

  //Alice 生成抗量子公钥私钥
  crypto_kem_keypair(pk, sk);
  print_bytes("pk", pk, CRYPTO_PUBLICKEYBYTES);
  print_bytes("sk", sk, CRYPTO_SECRETKEYBYTES);

  //Bob 利用公钥pk生成共享秘钥ss(key_b)和密文ct
  crypto_kem_enc(ct, key_b, pk);
  print_bytes("key_b", key_b, CRYPTO_BYTES);
  print_bytes("ct", ct, CRYPTO_CIPHERTEXTBYTES);
  
  // bob 利用共享秘钥ss(key_b) 对称加密消息 message 获得消息密文 ciphertext
  int clen = aes_gcm_encrypt((const uint8_t *)message, strlen(message),
  key_b, iv, ciphertext, tag);
  printf("Original message: %s\n", message);
  print_bytes("Ciphertext", ciphertext, clen);
  print_bytes("IV", iv, AES_IV_LEN);
  print_bytes("TAG", tag, AES_TAG_LEN);

  //Alice 利用私钥sk解密密文ct获得共享秘钥ss(key_a)
  crypto_kem_dec(key_a, ct, sk);
  print_bytes("key_a", key_a, CRYPTO_BYTES);

  if(memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR keys\n");
    return 1;
  }

  // Alice 利用共享秘钥ss(key_a) 对称对称解密消息密文 ciphertext 获得消息decrypted
  int dlen = aes_gcm_decrypt(ciphertext, clen, tag, key_b, iv, decrypted);
  if (dlen >= 0) {
    decrypted[dlen] = '\0';
    printf("Decrypted message: %s\n", decrypted);
  } else {
    printf("Decryption failed!\n");
  }

  //if(memcmp(message, decrypted, 128)) {
  if(memcmp(message, decrypted, dlen)) {  // 使用实际解密长度
    printf("ERROR message\n");
    return 1;
  }

  return 0;
}

// 生成 Kyber + RSA 的组合密钥
int generate_hybrid_keypair(hybrid_publickey_t *hpk, hybrid_secretkey_t *hsk) {
  // 1. Kyber
  crypto_kem_keypair(hpk->kyber_pk, hsk->kyber_sk);

  // 2. RSA
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);  // 可设为4096
  EVP_PKEY *rsa_key = NULL;
  EVP_PKEY_keygen(ctx, &rsa_key);
  EVP_PKEY_CTX_free(ctx);

  hsk->rsa_sk = rsa_key;

  // 提取公钥到内存
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(bio, rsa_key);
  int len = BIO_read(bio, hpk->rsa_pk, sizeof(hpk->rsa_pk));
  BIO_free(bio);

  return (len > 0) ? 0 : -1;
}

// /*
// 混合加密:
//   明文 → 用 RSA 公钥加密（传统） → 得到 RSA 密文

//   使用 Kyber 公钥进行 KEM → 得到共享密钥（ss），并封装密文（ct）

//   使用共享密钥（ss）进行 AES 加密（对称加密明文） → 得到 AES 密文

//   传输：发送封装包：[RSA密文 | AES密文 | Kyber密文 | IV | TAG]
// */
// int hybrid_encrypt(const hybrid_publickey_t *hpk, const uint8_t *plaintext, int plen,
//   uint8_t *out_ciphertext, int *outlen, uint8_t *iv, uint8_t *tag) {
//   uint8_t ss[CRYPTO_BYTES]; // Kyber 共享密钥
//   uint8_t ct_kyber[CRYPTO_CIPHERTEXTBYTES];
//   uint8_t rsa_cipher[512]; // 临时 buffer 存 RSA 加密结果

//   // 1. RSA 公钥加载
//   BIO *bio = BIO_new_mem_buf(hpk->rsa_pk, -1);
//   EVP_PKEY *rsa_pub = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
//   BIO_free(bio);
  
//   // 2. RSA 公钥加密明文plaintext 获得密文rsa_cipher
//   EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsa_pub, NULL);
//   EVP_PKEY_encrypt_init(ctx);
//   size_t rsa_len = sizeof(rsa_cipher);
//   EVP_PKEY_encrypt(ctx, rsa_cipher, &rsa_len, plaintext, plen);
//   EVP_PKEY_CTX_free(ctx);
//   EVP_PKEY_free(rsa_pub);

//   // 3. Kyber 用公钥pk生成共享秘钥 ss 的密文ct_kyber
//   crypto_kem_enc(ct_kyber, ss, hpk->kyber_pk);

//   // 4. 利用共享秘钥 ss 对称加密 RSA 密文 获得 out_ciphertext
//   int enc_len = aes_gcm_encrypt(rsa_cipher, rsa_len, ss, iv, out_ciphertext, tag);

//   // 5.密文拼接：out_ciphertext = RSA密文的密文 + 共享秘钥ss的密文ct_kyber
//   memcpy(out_ciphertext + enc_len, ct_kyber, CRYPTO_CIPHERTEXTBYTES);
//   *outlen = enc_len + CRYPTO_CIPHERTEXTBYTES;

//   return 0;
// }

// /*
// 混合解密：
//   解出 Kyber 密文，用 Kyber 私钥还原出共享密钥（ss）

//   用共享密钥解 AES 密文 → 得到 RSA 密文

//   用 RSA 私钥解密 → 明文
// */
// int hybrid_decrypt(const hybrid_secretkey_t *hsk, const uint8_t *cipher_in, int clen,
//   const uint8_t *iv, const uint8_t *tag, uint8_t *plaintext_out) {
//   uint8_t ss[CRYPTO_BYTES];
  
//   // 1.解包密文[out_ciphertext|ct_kyber]
//   const uint8_t *ct_kyber = cipher_in + clen - CRYPTO_CIPHERTEXTBYTES;
//   int aes_len = clen - CRYPTO_CIPHERTEXTBYTES; // 获取out_ciphertext的长度

//   // 1. Kyber 解密出共享密钥 ss
//   crypto_kem_dec(ss, ct_kyber, hsk->kyber_sk); 

//   // 2. 对称解密out_ciphertext得到 RSA 密文 rsa_cipher
//   uint8_t rsa_cipher[512];
//   int rsa_len = aes_gcm_decrypt(cipher_in, aes_len, tag, ss, iv, rsa_cipher);
//   if (rsa_len < 0) return -1;

//   // 3. 使用 RSA 私钥解密 得到明文ctx
//   EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(hsk->rsa_sk, NULL);
//   EVP_PKEY_decrypt_init(ctx);
//   size_t plen = 256;
//   EVP_PKEY_decrypt(ctx, plaintext_out, &plen, rsa_cipher, rsa_len);
//   // size_t max_plen = EVP_PKEY_size(hsk->rsa_sk); // RSA 密钥的最大输出大小
//   // EVP_PKEY_decrypt(ctx, plaintext_out, &max_plen, rsa_cipher, rsa_len);
//   EVP_PKEY_CTX_free(ctx);

//   return plen;
//   // return max_plen;
// }

// static int test_hybrid_keys(void)
// {
//   hybrid_publickey_t pubkey;
//   hybrid_secretkey_t seckey;

//   // 生成kyber和RSA秘钥对
//   generate_hybrid_keypair(&pubkey, &seckey);

//   const char *msg = "Hybrid PQ + RSA test!";
//   uint8_t iv[AES_IV_LEN], tag[AES_TAG_LEN];
//   // uint8_t ciphertext[1024], decrypted[512];
//   uint8_t ciphertext[2048], decrypted[512];
//   int clen;

//   RAND_bytes(iv, AES_IV_LEN);
  
//   // 混合加密 利用kyber公钥和rsa公钥 加密明文msg，返回密文ciphertext和密文长度clen
//   hybrid_encrypt(&pubkey, (const uint8_t *)msg, strlen(msg),
//                  ciphertext, &clen, iv, tag);
  
//   // 混合解密
//   int plen = hybrid_decrypt(&seckey, ciphertext, clen, iv, tag, decrypted);
//   decrypted[plen] = '\0';

//   printf("Recovered message: %s\n", decrypted);
//   EVP_PKEY_free(seckey.rsa_sk);
//   return 0;
// }

/*
混合加密:
  明文 → 用 RSA 公钥加密（传统） → 得到 RSA 密文

  使用 Kyber 公钥进行 KEM → 得到共享密钥（ss），并封装密文（ct）

  使用共享密钥（ss）进行 AES 加密（对称加密明文） → 得到 AES 密文

  传输：发送封装包：[RSA密文的对称加密密文 | 共享秘钥ss的密文 | IV | TAG]
*/
int hybrid_encrypt(const hybrid_publickey_t *hpk, const uint8_t *plaintext, int plen,
  uint8_t *out_ciphertext, int *outlen, uint8_t *iv, uint8_t *tag) {
  uint8_t ss[CRYPTO_BYTES]; // Kyber 共享密钥
  uint8_t ct_kyber[CRYPTO_CIPHERTEXTBYTES];
  uint8_t rsa_cipher[512]; // 临时 buffer 存 RSA 加密结果

  // 1. RSA 公钥加载
  BIO *bio = BIO_new_mem_buf(hpk->rsa_pk, -1);
  EVP_PKEY *rsa_pub = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free(bio);
  
  // 2. RSA 公钥加密明文plaintext 获得密文rsa_cipher
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsa_pub, NULL);
  EVP_PKEY_encrypt_init(ctx);
  size_t rsa_len = sizeof(rsa_cipher);
  EVP_PKEY_encrypt(ctx, rsa_cipher, &rsa_len, plaintext, plen);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(rsa_pub);

  // 3. Kyber 用公钥pk生成共享秘钥 ss 的密文ct_kyber
  crypto_kem_enc(ct_kyber, ss, hpk->kyber_pk);

  // 4. 利用共享秘钥 ss 对称加密 RSA 密文 获得 out_ciphertext
  int enc_len = aes_gcm_encrypt(rsa_cipher, rsa_len, ss, iv, out_ciphertext, tag);

  // 5.密文拼接：out_ciphertext = RSA密文的密文 + 共享秘钥ss的密文ct_kyber + iv + tag
  memcpy(out_ciphertext + enc_len, ct_kyber, CRYPTO_CIPHERTEXTBYTES);
  memcpy(out_ciphertext + enc_len + CRYPTO_CIPHERTEXTBYTES, iv, AES_IV_LEN);
  memcpy(out_ciphertext + enc_len + CRYPTO_CIPHERTEXTBYTES + AES_IV_LEN, tag, AES_TAG_LEN);
  *outlen = enc_len + CRYPTO_CIPHERTEXTBYTES + AES_IV_LEN + AES_TAG_LEN;

  return 0;
}

/*
混合解密：
  解出 Kyber 密文，用 Kyber 私钥还原出共享密钥（ss）

  用共享密钥解 AES 密文 → 得到 RSA 密文

  用 RSA 私钥解密 → 明文
*/
int hybrid_decrypt(const hybrid_secretkey_t *hsk, const uint8_t *cipher_in, int clen,
   uint8_t *plaintext_out) {
  uint8_t ss[CRYPTO_BYTES];

  // 1.解包密文[out_ciphertext|ct_kyber|IV|TAG]
  const uint8_t *ct_kyber = cipher_in + clen - CRYPTO_CIPHERTEXTBYTES - AES_IV_LEN - AES_TAG_LEN;
  const uint8_t *iv = ct_kyber + CRYPTO_CIPHERTEXTBYTES;
  const uint8_t *tag = iv + AES_IV_LEN;
  int aes_len = clen - CRYPTO_CIPHERTEXTBYTES - AES_IV_LEN - AES_TAG_LEN; // 获取out_ciphertext的长度

  // 1. Kyber 解密出共享密钥 ss
  crypto_kem_dec(ss, ct_kyber, hsk->kyber_sk); 

  // 2. 对称解密out_ciphertext得到 RSA 密文 rsa_cipher
  uint8_t rsa_cipher[512];
  int rsa_len = aes_gcm_decrypt(cipher_in, aes_len, tag, ss, iv, rsa_cipher);
  if (rsa_len < 0) return -1;

  // 3. 使用 RSA 私钥解密 得到明文ctx
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(hsk->rsa_sk, NULL);
  EVP_PKEY_decrypt_init(ctx);
  size_t plen = 256;
  EVP_PKEY_decrypt(ctx, plaintext_out, &plen, rsa_cipher, rsa_len);
  // size_t max_plen = EVP_PKEY_size(hsk->rsa_sk); // RSA 密钥的最大输出大小
  // EVP_PKEY_decrypt(ctx, plaintext_out, &max_plen, rsa_cipher, rsa_len);
  EVP_PKEY_CTX_free(ctx);

  return plen;
  // return max_plen;
}

static int test_hybrid_keys(void)
{
  hybrid_publickey_t pubkey;
  hybrid_secretkey_t seckey;

  // 生成kyber和RSA秘钥对
  generate_hybrid_keypair(&pubkey, &seckey);

  const char *msg = "Hybrid PQ + RSA test!";
  uint8_t iv[AES_IV_LEN], tag[AES_TAG_LEN];
  // uint8_t ciphertext[1024], decrypted[512];
  uint8_t ciphertext[2048], decrypted[512];
  int clen;

  RAND_bytes(iv, AES_IV_LEN);
  
  // 混合加密 利用kyber公钥和rsa公钥 加密明文msg，返回密文ciphertext和密文长度clen
  hybrid_encrypt(&pubkey, (const uint8_t *)msg, strlen(msg),
                 ciphertext, &clen, iv, tag);
  
  // 混合解密
  int plen = hybrid_decrypt(&seckey, ciphertext, clen, decrypted);
  decrypted[plen] = '\0';

  printf("Recovered message: %s\n", decrypted);
  EVP_PKEY_free(seckey.rsa_sk);
  return 0;
}

int main(void)
{
  // unsigned int i;
  int r;
  printf("==============测试基本流程==================\n");
  r  = test_keys();
  if(r)
    return 1;

  printf("==============测试混合加密==================\n");
  r = test_hybrid_keys();

  printf("==============测试完毕===================\n");
  printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_CIPHERTEXTBYTES: %d\n",CRYPTO_CIPHERTEXTBYTES);

  return 0;
}
