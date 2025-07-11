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
#define RSA_CIPHERTEXT_LEN 256  // RSA 2048 的密文长度
// #define RSA_CIPHERTEXT_LEN KYBER_POLYCOMPRESSEDBYTES  // RSA 2048 加密输出固定长度


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
  uint8_t *out_ciphertext, int *outlen, uint8_t *iv, uint8_t *tag);
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

  printf("步骤 1.1 : 接收方Alice调用crypto_kem_keypair函数，生成抗量子公钥kyber_pk和私钥kyber_sk:\n"); 
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

  printf("步骤 1.2 : 接收方Alice调用OpenSSL库，生成RSA公钥rsa_pk和私钥rsa_sk:\n");
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
  uint8_t *out_ciphertext, int *outlen, uint8_t *iv, uint8_t *tag) {

  uint8_t ss[CRYPTO_BYTES]; // Kyber 共享密钥
  uint8_t ct_kyber[CRYPTO_CIPHERTEXTBYTES];
  uint8_t kyber_ct_cipher[256]; // 加密后的部分 ct_kyber

  printf("要加密的消息: ");
  fwrite(plaintext, 1, plen, stdout);
  printf(" (%d 字节)\n", plen);

  // === 1.Kyber 用公钥生成共享密钥 ss 和密文 ct_kyber ===

  // Kyber利用公钥生成共享密钥获取共享密钥ss和对应密文ct_kyber
  crypto_kem_enc(ct_kyber, ss, hpk->kyber_pk);

  printf("步骤 2.1: 发送方Bob调用crypto_kem_enc函数，使用抗量子公钥kyber_pk加密共享密钥ss，获得抗量子密文ct_kyber\n");
  print_bytes("共享密钥(ss)", ss, CRYPTO_BYTES);
  print_bytes("Kyber密文(ct_kyber)", ct_kyber, CRYPTO_CIPHERTEXTBYTES);

  // === 2.使用共享密钥ss加密原始消息 ===

  // 生成随机的IV
  if (RAND_bytes(iv, AES_IV_LEN) != 1) {
    fprintf(stderr, "生成随机IV失败\n");
    return -1;
  }

  //对称加密
  int enc_len = aes_gcm_encrypt(plaintext, plen, ss, iv, out_ciphertext, tag);
  if (enc_len < 0) {
    fprintf(stderr, "AES-GCM加密消息失败\n");
    return -1;
  }

  printf("步骤 2.2: 发送方Bob调用OpenSSL库，使用共享密钥ss对称加密原始消息，获得AES密文\n");
  print_bytes("AES加密的消息", out_ciphertext, enc_len);
  print_bytes("AES IV", iv, AES_IV_LEN);
  print_bytes("AES TAG", tag, AES_TAG_LEN);

  // === 3.使用RSA公钥部分加密对称密钥(ct_kyber) ===

  // 加载RSA公钥
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
  
  // 使用RSA加密ct_kyber的后KYBER_POLYCOMPRESSEDBYTES个字节
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

  size_t ct_cipher_len = sizeof(kyber_ct_cipher);
  // if (EVP_PKEY_encrypt(ctx, rsa_cipher, &rsa_len, ct_kyber + KYBER_POLYVECCOMPRESSEDBYTES, KYBER_POLYCOMPRESSEDBYTES) <= 0) {
  if (EVP_PKEY_encrypt(ctx, kyber_ct_cipher, &ct_cipher_len, ct_kyber + KYBER_POLYVECCOMPRESSEDBYTES, KYBER_POLYCOMPRESSEDBYTES) <= 0) {
    fprintf(stderr, "RSA加密共享密钥失败\n");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(rsa_pub);
    return -1;
  }
  
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(rsa_pub);

  printf("步骤 2.3: 发送方Bob调用OpenSSL库，使用RSA公钥rsa_pk加密，加密共享密钥的密文ct_kyber\n");
  print_bytes("RSA加密结果(RSA(Ct_kyber))", kyber_ct_cipher, ct_cipher_len);

  // === 5. 封装: [AES加密的消息 | RSA(Ct_kyber) | IV | TAG] ===
  uint8_t *p = out_ciphertext + enc_len ;
  memcpy(p, ct_kyber, CRYPTO_CIPHERTEXTBYTES); // 添加 Ct_kyber

  p += KYBER_POLYVECCOMPRESSEDBYTES;
  memcpy(p, kyber_ct_cipher, ct_cipher_len); // 替换 Ct_kyber 后半部分为 RSA密文
  
  p += ct_cipher_len;
  memcpy(p, iv, AES_IV_LEN); // 添加IV

  p += AES_IV_LEN;
  memcpy(p, tag, AES_TAG_LEN); // 添加TAG
  
  *outlen = enc_len + KYBER_POLYVECCOMPRESSEDBYTES + ct_cipher_len + AES_IV_LEN + AES_TAG_LEN;

  printf("步骤 2.4: 发送方Bob，封装所有密文发送给接收方Alice\n");
  printf("封装格式: [AES加密的消息 | RSA(Ct_kyber) | IV | TAG]\n");
  print_bytes("最终密文", out_ciphertext, *outlen);

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

  int total_overhead = KYBER_POLYVECCOMPRESSEDBYTES + RSA_CIPHERTEXT_LEN + AES_IV_LEN + AES_TAG_LEN;
  
  if (clen < total_overhead) {
    fprintf(stderr, "无效的消息长度: 消息太短\n");
    return -1;
  }

  uint8_t ss[CRYPTO_BYTES];
  uint8_t ct_kyber[CRYPTO_CIPHERTEXTBYTES];
  uint8_t kyber_ct_decrypted[512];

  // === 1. 拆封消息结构[AES加密的消息 | RSA(Ct_kyber) | IV | TAG] ===
  int aes_msg_len = clen - total_overhead;  // AES加密的消息长度
  const uint8_t *aes_cipher = cipher_in;    // 前段: AES加密的消息
  const uint8_t *rsa_ct_kyber = cipher_in + aes_msg_len;  // 中段: RSA部分加密的ct_kyber
  const uint8_t *iv = rsa_ct_kyber + KYBER_POLYVECCOMPRESSEDBYTES + RSA_CIPHERTEXT_LEN;      // IV紧随其后
  const uint8_t *tag = iv + AES_IV_LEN;                 // TAG在最后

  printf("步骤 3.1 : 接收方Alice接收到密文并解包，密文结构：[AES加密的消息 | RSA(Ct_kyber) | IV | TAG] :\n");
  print_bytes("AES加密消息长度", cipher_in, aes_msg_len);
  print_bytes("RSA(Ct_kyber)", rsa_ct_kyber, KYBER_POLYVECCOMPRESSEDBYTES + RSA_CIPHERTEXT_LEN);
  print_bytes("AES IV", iv, AES_IV_LEN);
  print_bytes("AES TAG", tag, AES_TAG_LEN);

  // === 2. 使用RSA私钥解密密文RSA(ct_kyber)获得ct_kyber ===
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

  size_t ct_len = sizeof(kyber_ct_decrypted);
  if (EVP_PKEY_decrypt(ctx, kyber_ct_decrypted, &ct_len, rsa_ct_kyber + KYBER_POLYVECCOMPRESSEDBYTES, RSA_CIPHERTEXT_LEN) <= 0) {
    fprintf(stderr, "RSA解密失败\n");
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY_CTX_free(ctx);

  // 替换 Ct_kyber 后半部分为 RSA明文
  memcpy(ct_kyber , rsa_ct_kyber, KYBER_POLYVECCOMPRESSEDBYTES);
  memcpy(ct_kyber + KYBER_POLYVECCOMPRESSEDBYTES, kyber_ct_decrypted, KYBER_POLYCOMPRESSEDBYTES);

  printf("步骤 3.2: 接收方Alice调用OpenSSL函数库，使用RSA私钥rsa_sk解密RSA(ct_kyber)\n");
  print_bytes("Ct_kyber", ct_kyber, CRYPTO_CIPHERTEXTBYTES);

  // === 3. 用Kyber私钥解封装ct_kyber获得共享密钥ss ===
  crypto_kem_dec(ss, ct_kyber, hsk->kyber_sk); 
  printf("步骤 3.3: 接收方Alice调用crypto_kem_dec函数，使用抗量子私钥kyber_sk解密密文ct_kyber，获得共享密钥ss\n");
  print_bytes("对称密钥ss", ss, CRYPTO_BYTES);

  // === 4. 使用ss解密消息 ===
  int plen = aes_gcm_decrypt(aes_cipher, aes_msg_len, tag, ss, iv, plaintext_out);
  if (plen < 0) {
    fprintf(stderr, "AES-GCM解密失败\n");
    return -1;
  }

  printf("步骤 3.4 : 接收方Alice调用OpenSSL函数库，使用共享密钥ss解密AES密文，得到明文message:\n");
  printf("\n恢复的消息: %s\n", plaintext_out);
  return plen;
}

static int test_hybrid_keys(void)
{
  hybrid_publickey_t pubkey;
  hybrid_secretkey_t seckey;
  const char *msg = "Hybrid PQ + RSA test!";
  uint8_t ciphertext[2048], decrypted[256];
  uint8_t iv[AES_IV_LEN], tag[AES_TAG_LEN];
  int clen = 0;

  // 生成kyber和RSA秘钥对
  printf("\n===== 第1阶段: 密钥生成 =====\n");
  if (generate_hybrid_keypair(&pubkey, &seckey) != 0) {
    return -1;
  }

  // 混合加密 利用kyber公钥和rsa公钥 加密明文msg，返回密文ciphertext和密文长度clen
  printf("\n===== 第2阶段: 消息加密 =====\n");

  printf("原始消息: \"%s\"\n", msg);

  // 混合加密
  if (hybrid_encrypt(&pubkey, (const uint8_t *)msg, strlen(msg),
    ciphertext, &clen, iv, tag) != 0) {
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
  
  return 0;
}
