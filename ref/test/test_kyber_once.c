#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "../kem.h"
#include "../randombytes.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>  // 添加SHA-256支持

#define AES_KEY_LEN 32  // 256 bits
#define AES_IV_LEN 12   // GCM standard IV length
#define AES_TAG_LEN 16  // GCM tag length
#define HASH_SS_LEN 32  // SHA-256哈希长度

typedef struct {
  uint8_t kyber_pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t rsa_pk[550];  // 例如 RSA 4096 公钥 PEM 格式长度预估
} hybrid_publickey_t;

typedef struct {
  uint8_t kyber_sk[CRYPTO_SECRETKEYBYTES];
  EVP_PKEY *rsa_sk; // OpenSSL RSA 私钥结构体
} hybrid_secretkey_t;

// 添加这些原型声明
int generate_hybrid_keypair(hybrid_publickey_t *hpk, hybrid_secretkey_t *hsk);
int hybrid_encrypt(const hybrid_publickey_t *hpk, const uint8_t *plaintext, int plen,
  uint8_t *out_ciphertext, int *outlen, uint8_t *iv, uint8_t *tag, uint8_t *ss_hash);
int hybrid_decrypt(const hybrid_secretkey_t *hsk, const uint8_t *cipher_in, int clen,
                    uint8_t *plaintext_out);

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

static void print_bytes(const char *label, const uint8_t *buf, size_t len) {
  printf("%s (长度 %zu):\n", label, len);
  for (size_t i = 0; i < len; i++) {
    printf("%02x", buf[i]);
    if ((i + 1) % 32 == 0) printf("\n");  // 每32字节换行
  }
  if (len % 32 != 0) printf("\n");
  printf("\n");
}

static void print_rsa_private_key(EVP_PKEY *pkey) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);

  char *pem_data;
  long len = BIO_get_mem_data(bio, &pem_data);
  printf("RSA私钥(pem格式):\n%.*s\n", (int)len, pem_data);

  BIO_free(bio);
}

// 生成 Kyber + RSA 的组合密钥
int generate_hybrid_keypair(hybrid_publickey_t *hpk, hybrid_secretkey_t *hsk) {
  
  // 1. Kyber生成密钥对
  crypto_kem_keypair(hpk->kyber_pk, hsk->kyber_sk);

  printf("Phrase 1.1 : 接收方Alice生成抗量子公钥kyber_pk和私钥kyber_sk:\n");
  print_bytes("Kyber公钥pk", hpk->kyber_pk, CRYPTO_PUBLICKEYBYTES);
  print_bytes("Kyber私钥sk", hsk->kyber_sk, CRYPTO_SECRETKEYBYTES);

  // 2. RSA 生成公私钥匙
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!ctx) {
    fprintf(stderr, "创建EVP_PKEY_CTX失败\n");
    return -1;
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    fprintf(stderr, "EVP_PKEY_keygen_init失败\n");
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) { //可设为4096
    fprintf(stderr, "设置RSA密钥长度失败\n");
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY *rsa_key = NULL;
  if (EVP_PKEY_keygen(ctx, &rsa_key) <= 0) {
    fprintf(stderr, "RSA密钥生成失败\n");
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY_CTX_free(ctx);

  hsk->rsa_sk = rsa_key;

  // 提取公钥到内存
  BIO *bio = BIO_new(BIO_s_mem());
  if (PEM_write_bio_PUBKEY(bio, rsa_key) == 0) {
      fprintf(stderr, "PEM_write_bio_PUBKEY失败\n");
      BIO_free(bio);
      return -1;
  }
  
  int len = BIO_read(bio, hpk->rsa_pk, sizeof(hpk->rsa_pk) - 1);
  BIO_free(bio);
  
  if (len <= 0) {
      fprintf(stderr, "读取RSA公钥失败\n");
      return -1;
  }
  hpk->rsa_pk[len] = '\0';  // 确保以NULL结尾

  printf("Phrase 1.2 : 接收方Alice生成RSA公钥rsa_pk和私钥rsa_sk:\n");
  printf("RSA公钥(pem格式):\n%s\n", hpk->rsa_pk);
  print_rsa_private_key(hsk->rsa_sk);

  return 0;
}

/*
混合加密:
  明文 → 用 RSA 公钥加密（传统） → 得到 RSA 密文

  使用 Kyber 公钥进行 KEM → 得到共享密钥（ss），并封装密文（ct）

  使用共享密钥（ss）进行 AES 加密（对称加密明文） → 得到 AES 密文

  传输：发送封装包：[RSA密文的对称加密密文 | 共享秘钥ss的密文 | IV | TAG]
  |------------------------------------ 密文包 ------------------------------------------|
  |  AES加密的RSA密文 (变长) |        Kyber密文 (固定长度)     | IV (12字节) | TAG (16字节) |
  |<------- aes_len ------->|<--- CRYPTO_CIPHERTEXTBYTES --->|<--- 12 --->|<---- 16 ---->|

*/
int hybrid_encrypt(const hybrid_publickey_t *hpk, const uint8_t *plaintext, int plen,
  uint8_t *out_ciphertext, int *outlen, uint8_t *iv, uint8_t *tag, uint8_t *ss_hash_out) {

  uint8_t ss[CRYPTO_BYTES]; // Kyber 共享密钥
  uint8_t ct_kyber[CRYPTO_CIPHERTEXTBYTES];
  uint8_t rsa_cipher[512]; // 临时 buffer 存 RSA 加密结果

  // 1. RSA 公钥加载
  BIO *bio = BIO_new_mem_buf(hpk->rsa_pk, -1);
  if (!bio) {
    fprintf(stderr, "创建BIO失败\n");
    return -1;
  }
  
  EVP_PKEY *rsa_pub = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free(bio);

  if (!rsa_pub) {
    fprintf(stderr, "读取RSA公钥失败\n");
    return -1;
  }
  
  // 2. RSA 公钥加密明文plaintext 获得密文rsa_cipher
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsa_pub, NULL);
  if (!ctx) {
    fprintf(stderr, "创建EVP_PKEY_CTX失败\n");
    EVP_PKEY_free(rsa_pub);
    return -1;
  }
  
  if (EVP_PKEY_encrypt_init(ctx) <= 0) {
    fprintf(stderr, "RSA加密初始化失败\n");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(rsa_pub);
    return -1;
  }
  size_t rsa_len = sizeof(rsa_cipher);
  if (EVP_PKEY_encrypt(ctx, rsa_cipher, &rsa_len, plaintext, plen) <= 0) {
    fprintf(stderr, "RSA加密失败\n");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(rsa_pub);
    return -1;
  }
  
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(rsa_pub);

  printf("Phrase 2.1 : 发送方Bob生成利用RSA公钥rsa_pk加密明文message获得密文rsa_cipher:\n");
  print_bytes("密文rsa_cipher", rsa_cipher, rsa_len);
  
  // 3. Kyber 用公钥pk生成共享秘钥 ss 的密文ct_kyber
  crypto_kem_enc(ct_kyber, ss, hpk->kyber_pk);

  printf("Phrase 2.2 : 发送方Bob生成利用抗量子公钥kyber_pk生成共享密钥ss以及共享密钥的密文ct_kyber:\n");
  print_bytes("对称密钥ss", ss, CRYPTO_BYTES);
  print_bytes("共享密钥的密文ct_kyber", ct_kyber, CRYPTO_CIPHERTEXTBYTES);

  // 4. 为共享密钥ss生成SHA-256哈希
  SHA256(ss, CRYPTO_BYTES, ss_hash_out);
  printf("步骤 2.3: Bob计算共享密钥ss的哈希\n");
  print_bytes("共享密钥哈希", ss_hash_out, HASH_SS_LEN);

  // 5. 利用共享秘钥 ss 对称加密 RSA 密文 获得 out_ciphertext
  int enc_len = aes_gcm_encrypt(rsa_cipher, rsa_len, ss, iv, out_ciphertext, tag);
  if (enc_len < 0) {
    fprintf(stderr, "AES-GCM加密失败\n");
    return -1;
  }

  printf("Phrase 2.4 : 发送方Bob利用共享密钥ss对称加密RSA密文rsa_cipher获得AES加密的RSA密文out_ciphertext:\n");
  print_bytes("AES加密的RSA密文out_ciphertext", out_ciphertext, enc_len);

  /* 
    6. 密文拼接: 
    完整结构: 
      [AES-GCM密文 | Kyber密文 | IV | TAG | SS_HASH]
  */
  uint8_t *p = out_ciphertext + enc_len;
  memcpy(p, ct_kyber, CRYPTO_CIPHERTEXTBYTES);     // 添加Kyber密文
  p += CRYPTO_CIPHERTEXTBYTES;
  memcpy(p, iv, AES_IV_LEN);                      // 添加IV
  p += AES_IV_LEN;
  memcpy(p, tag, AES_TAG_LEN);                    // 添加TAG
  p += AES_TAG_LEN;
  memcpy(p, ss_hash_out, HASH_SS_LEN);            // 添加ss的哈希
 
  *outlen = enc_len + CRYPTO_CIPHERTEXTBYTES + AES_IV_LEN + AES_TAG_LEN + HASH_SS_LEN;

  printf("Phrase 2.5 : 发送方Bob封装密钥格式为[ out_ciphertext | ct_kyber | IV | TAG | ss_Hash ]\n");
  print_bytes("最终封装密钥", out_ciphertext, *outlen);

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

  int total_overhead = CRYPTO_CIPHERTEXTBYTES + AES_IV_LEN + AES_TAG_LEN + HASH_SS_LEN;
  
  if (clen < total_overhead) {
    fprintf(stderr, "无效的消息长度: 消息太短\n");
    return -1;
  }

  uint8_t ss[CRYPTO_BYTES];

  // 1.解包密文[out_ciphertext|ct_kyber|IV|TAG|ss_hash]
  // 最后32字节是ss_hash
  const uint8_t *ss_hash_ptr = cipher_in + clen - HASH_SS_LEN;
  // 在ss_hash之前是TAG
  const uint8_t *tag = ss_hash_ptr - AES_TAG_LEN;
  // 在TAG之前是IV
  const uint8_t *iv = tag - AES_IV_LEN;
  // 在IV之前是Kyber密文
  const uint8_t *ct_kyber = iv - CRYPTO_CIPHERTEXTBYTES;
  //   开头是AES-GCM密文
  const uint8_t *aes_ciphertext = cipher_in;
  // AES加密部分长度
  int aes_len = clen - total_overhead;  

  printf("Phrase 3.1 : 接收方Alice解包密钥:\n");
  print_bytes("AES-GCM加密部分", cipher_in, aes_len);
  print_bytes("Kyber密文", ct_kyber, CRYPTO_CIPHERTEXTBYTES);
  print_bytes("AES IV", iv, AES_IV_LEN);
  print_bytes("AES TAG ", tag, AES_TAG_LEN);
  print_bytes("Kyber密钥哈希", ss_hash_ptr, HASH_SS_LEN);

  // 2. Kyber 解密出共享密钥 ss
  crypto_kem_dec(ss, ct_kyber, hsk->kyber_sk); 
  printf("Phrase 3.2 : 接收方Alice用Kyber私钥kyber_sk解密密文ct_kyber获得共享秘钥ss:\n");
  print_bytes("对称密钥ss", ss, CRYPTO_BYTES);

  // 3. 验证共享密钥哈希
  uint8_t ss_hash_calc[HASH_SS_LEN];
  SHA256(ss, CRYPTO_BYTES, ss_hash_calc);

  printf("步骤 3.3 : Alice验证共享密钥哈希\n");
  print_bytes("接收到的哈希", ss_hash_ptr, HASH_SS_LEN);
  print_bytes("计算出的哈希", ss_hash_calc, HASH_SS_LEN);

  if (memcmp(ss_hash_ptr, ss_hash_calc, HASH_SS_LEN) != 0) {
    fprintf(stderr, "✘ 共享密钥哈希验证失败: 可能遭受中间人攻击!\n");
    return -1;
  }
  printf("✓ 共享密钥哈希验证成功\n\n");

  // 4. 使用共享密钥解AES密文得到RSA密文
  uint8_t rsa_cipher[512] = {0};  // 初始化为0
  int rsa_len = aes_gcm_decrypt(aes_ciphertext, aes_len, tag, ss, iv, rsa_cipher);
  
  if (rsa_len < 0) {
    fprintf(stderr, "AES-GCM解密失败\n");
    return -1;
  }
  
  printf("Phrase 3.4 : 接收方Alice用共享密钥ss解密AES加密的RSA密文out_ciphertext获得RSA密文rsa_cipher:\n");
  print_bytes("密文rsa_cipher", rsa_cipher, rsa_len);

  // 5. 使用 RSA 私钥解密 得到明文ctx
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(hsk->rsa_sk, NULL);
  if (!ctx) {
    fprintf(stderr, "创建EVP_PKEY_CTX失败\n");
    return -1;
  }
  
  if (EVP_PKEY_decrypt_init(ctx) <= 0) {
    fprintf(stderr, "RSA解密初始化失败\n");
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  
  size_t plen = 256;
  if (EVP_PKEY_decrypt(ctx, plaintext_out, &plen, rsa_cipher, rsa_len) <= 0) {
    fprintf(stderr, "RSA解密失败\n");
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  
  EVP_PKEY_CTX_free(ctx);

  printf("Phrase 3.5 : 接收方Alice用RSA私钥rsa_sk解密RSA密文，得到明文message:\n");
  printf("\n恢复的消息: %s\n", plaintext_out);


  return plen;
}

static int test_hybrid_keys(void)
{
  hybrid_publickey_t pubkey;
  hybrid_secretkey_t seckey;
  const char *msg = "Hybrid PQ + RSA test!";
  uint8_t iv[AES_IV_LEN], tag[AES_TAG_LEN], ss_hash[HASH_SS_LEN];;
  uint8_t ciphertext[2048], decrypted[512];
  int clen = 0;

  // 生成kyber和RSA秘钥对
  printf("\n===== 第1阶段: 密钥生成 =====\n");
  if (generate_hybrid_keypair(&pubkey, &seckey) != 0) {
    return -1;
  }

  // 混合加密 利用kyber公钥和rsa公钥 加密明文msg，返回密文ciphertext和密文长度clen
  printf("\n===== 第2阶段: 消息加密 =====\n");

  printf("原始消息: \"%s\"\n", msg);

  // 生成随机IV
  if (RAND_bytes(iv, AES_IV_LEN) != 1) {
    fprintf(stderr, "生成随机IV失败\n");
    return -1;
  }

  // 混合加密
  if (hybrid_encrypt(&pubkey, (const uint8_t *)msg, strlen(msg),
    ciphertext, &clen, iv, tag, ss_hash) != 0) {
    fprintf(stderr, "加密失败\n");
    return -1;
  }
  
  // 混合解密
  printf("\n===== 第3阶段: 消息解密 =====\n");
  int plen = hybrid_decrypt(&seckey, ciphertext, clen, decrypted);
  if (plen < 0) {
    fprintf(stderr, "解密失败\n");
    EVP_PKEY_free(seckey.rsa_sk);
    return -1;
  }

  // 添加终止符
  decrypted[plen] = '\0';

  // 验证消息完整性
  EVP_PKEY_free(seckey.rsa_sk);

  if (strcmp(msg, (const char *)decrypted) == 0) {
    printf("✓ 测试成功: 原始消息与解密消息一致\n");
    return 0;
  } else {
    printf("✗ 测试失败: 原始消息与解密消息不一致\n");
    return -1;
  }
}

int main(void)
{
  int r;
  printf("============== 开始测试混合加密方案 ==================\n");

  r = test_hybrid_keys();

  if (r != 0) {
    fprintf(stderr, "测试失败！\n");
    return 1;
  }

  printf("================== 测试完毕 ===================\n");

  // printf("技术参数:\n");
  // printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
  // printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
  // printf("CRYPTO_CIPHERTEXTBYTES: %d\n",CRYPTO_CIPHERTEXTBYTES);
  // printf("AES_IV 长度:            %d\n", AES_IV_LEN); 
  // printf("AES_TAG 长度:           %d\n", AES_TAG_LEN); 
  // printf("SS_HASH 长度:           %d\n", HASH_SS_LEN);
  
  return 0;
}
