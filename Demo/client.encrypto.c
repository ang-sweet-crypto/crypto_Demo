#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define PORT 8080                  // 与服务端端口一致
#define AES_KEY_SIZE 32            // AES-256密钥长度
#define IV_SIZE 12                 // GCM模式IV长度
#define TAG_SIZE 16                // GCM认证标签长度
#define SERVER_PUB_KEY "ecc_keys/server_public.pem"  // 服务端公钥（用于验签和ECDH）
#define CLIENT_PRIV_KEY "ecc_keys/client_private.pem"// 客户端私钥（用于签名和ECDH）
#define SERVER_IP "127.0.0.1"      // 服务端IP
#define BUFFER_SIZE 1024           // 缓冲区大小

// 确保接收指定长度的数据
int recv_all(int fd, void *buf, int len) {
    int total = 0;
    while (total < len) {
        int n = recv(fd, (char*)buf + total, len - total, 0);
        if (n <= 0) {
            fprintf(stderr, "recv failed (received %d/%d)\n", total, len);
            return -1;
        }
        total += n;
    }
    return total;
}

// 读取EC密钥（私钥/公钥）
EC_KEY* read_ec_key(const char* filename, int is_private) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open key file");
        return NULL;
    }
    EC_KEY* key = NULL;
    if (is_private) {
        key = PEM_read_ECPrivateKey(fp, &key, NULL, NULL);
    } else {
        key = PEM_read_EC_PUBKEY(fp, &key, NULL, NULL);
    }
    fclose(fp);
    if (!key) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    return key;
}

// 生成AES密钥（基于ECDH共享密钥）
void generate_aes_key(const unsigned char *shared_secret, int secret_len, unsigned char *aes_key) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, shared_secret, secret_len);
    unsigned int key_len;
    EVP_DigestFinal_ex(mdctx, aes_key, &key_len);
    EVP_MD_CTX_free(mdctx);
}

// AES-GCM加密
int aes_gcm_encrypt(const unsigned char *plaintext, int plain_len,
                   const unsigned char *key, const unsigned char *iv,
                   unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    int len, cipher_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plain_len);
    cipher_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    cipher_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
    EVP_CIPHER_CTX_free(ctx);
    return cipher_len;
}

// AES-GCM解密
int aes_gcm_decrypt(const unsigned char *ciphertext, int cipher_len,
                   const unsigned char *tag, const unsigned char *key,
                   const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag);
    int len, plain_len = 0;
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len);
    plain_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plain_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plain_len;
}

// 生成签名（先SHA256哈希）
int generate_signature(const unsigned char *message, int msg_len,
                      unsigned char *signature, EC_KEY *priv_key) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(message, msg_len, hash); // 与服务端一致：先哈希再签名
    unsigned int sig_len;
    if (ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, signature, &sig_len, priv_key) != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return sig_len;
}

// 验证签名（先SHA256哈希）
int verify_signature(const unsigned char *message, int msg_len,
                    const unsigned char *signature, int sig_len,
                    EC_KEY *pub_key) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(message, msg_len, hash); // 与服务端一致：先哈希再验签
    int ret = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature, sig_len, pub_key);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
    }
    return ret;
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;

    // 创建Socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror(" Socket创建失败");
        exit(EXIT_FAILURE);
    }

    // 配置服务端地址
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror(" 服务端IP无效");
        exit(EXIT_FAILURE);
    }

    // 连接服务端
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror(" 连接服务端失败（请先启动服务端）");
        exit(EXIT_FAILURE);
    }
    printf(" 已连接到服务端 %s:%d\n", SERVER_IP, PORT);

    // 读取密钥（客户端私钥+服务端公钥）
    EC_KEY* client_priv = read_ec_key(CLIENT_PRIV_KEY, 1);
    EC_KEY* server_pub = read_ec_key(SERVER_PUB_KEY, 0);
    if (!client_priv || !server_pub) {
        exit(EXIT_FAILURE);
    }

    // 1. 计算ECDH共享密钥（与服务端一致）
    unsigned char shared_secret[32];
    int secret_len = ECDH_compute_key(shared_secret, sizeof(shared_secret),
                                      EC_KEY_get0_public_key(server_pub),  // 用服务端公钥
                                      client_priv, NULL);                  // 用客户端私钥
    if (secret_len <= 0) {
        fprintf(stderr, " ECDH共享密钥计算失败\n");
        goto cleanup;
    }
    unsigned char aes_key[AES_KEY_SIZE];
    generate_aes_key(shared_secret, secret_len, aes_key);  // 生成AES密钥

    // 循环发送消息
    char msg[BUFFER_SIZE];
    while (1) {
        printf("\n请输入消息（输入exit退出）：");
        fgets(msg, sizeof(msg), stdin);
        msg[strcspn(msg, "\n")] = '\0';  // 去除换行符

        if (strcmp(msg, "exit") == 0) {
            printf(" 退出客户端\n");
            break;
        }
        int msg_len = strlen(msg);

        // 2. 生成随机IV
        unsigned char iv[IV_SIZE];
        FILE *urandom = fopen("/dev/urandom", "r");
        if (!urandom || fread(iv, 1, IV_SIZE, urandom) != IV_SIZE) {
            perror(" 生成IV失败");
            goto cleanup;
        }
        fclose(urandom);

        // 3. 加密消息（AES-GCM）
        unsigned char ciphertext[BUFFER_SIZE];
        unsigned char tag[TAG_SIZE];
        int cipher_len = aes_gcm_encrypt((unsigned char*)msg, msg_len, aes_key, iv, ciphertext, tag);
        if (cipher_len <= 0) {
            fprintf(stderr, " 消息加密失败\n");
            goto cleanup;
        }

        // 4. 对明文消息签名
        unsigned char signature[BUFFER_SIZE];
        int sig_len = generate_signature((unsigned char*)msg, msg_len, signature, client_priv);
        if (sig_len <= 0) {
            fprintf(stderr, " 签名生成失败\n");
            goto cleanup;
        }

        // 5. 发送数据（与服务端接收顺序一致）：
        //    IV → 密文长度（网络序） → 密文 → Tag → 签名长度（网络序） → 签名
        if (send(sock, iv, IV_SIZE, 0) != IV_SIZE) {
            perror(" 发送IV失败");
            goto cleanup;
        }

        int cipher_len_net = htonl(cipher_len);  // 转换为网络序
        if (send(sock, &cipher_len_net, sizeof(cipher_len_net), 0) != sizeof(cipher_len_net)) {
            perror(" 发送密文长度失败");
            goto cleanup;
        }

        if (send(sock, ciphertext, cipher_len, 0) != cipher_len) {
            perror(" 发送密文失败");
            goto cleanup;
        }

        if (send(sock, tag, TAG_SIZE, 0) != TAG_SIZE) {
            perror(" 发送Tag失败");
            goto cleanup;
        }

        int sig_len_net = htonl(sig_len);  // 转换为网络序
        if (send(sock, &sig_len_net, sizeof(sig_len_net), 0) != sizeof(sig_len_net)) {
            perror(" 发送签名长度失败");
            goto cleanup;
        }

        if (send(sock, signature, sig_len, 0) != sig_len) {
            perror(" 发送签名失败");
            goto cleanup;
        }
        printf(" 消息已加密并发送\n");

        // 6. 接收服务端回复（与服务端发送顺序一致）
        unsigned char reply_iv[IV_SIZE];
        if (recv_all(sock, reply_iv, IV_SIZE) != IV_SIZE) {
            fprintf(stderr, " 接收回复IV失败\n");
            goto cleanup;
        }

        int reply_cipher_len_net;
        if (recv_all(sock, &reply_cipher_len_net, sizeof(reply_cipher_len_net)) != sizeof(reply_cipher_len_net)) {
            fprintf(stderr, " 接收回复密文长度失败\n");
            goto cleanup;
        }
        int reply_cipher_len = ntohl(reply_cipher_len_net);  // 转换为主机序
        if (reply_cipher_len <= 0 || reply_cipher_len > BUFFER_SIZE) {
            fprintf(stderr, " 无效的回复密文长度：%d\n", reply_cipher_len);
            goto cleanup;
        }

        unsigned char reply_cipher[BUFFER_SIZE];
        if (recv_all(sock, reply_cipher, reply_cipher_len) != reply_cipher_len) {
            fprintf(stderr, " 接收回复密文失败\n");
            goto cleanup;
        }

        unsigned char reply_tag[TAG_SIZE];
        if (recv_all(sock, reply_tag, TAG_SIZE) != TAG_SIZE) {
            fprintf(stderr, " 接收回复Tag失败\n");
            goto cleanup;
        }

        int reply_sig_len_net;
        if (recv_all(sock, &reply_sig_len_net, sizeof(reply_sig_len_net)) != sizeof(reply_sig_len_net)) {
            fprintf(stderr, " 接收回复签名长度失败\n");
            goto cleanup;
        }
        int reply_sig_len = ntohl(reply_sig_len_net);  // 转换为主机序
        if (reply_sig_len <= 0 || reply_sig_len > BUFFER_SIZE) {
            fprintf(stderr, " 无效的回复签名长度：%d\n", reply_sig_len);
            goto cleanup;
        }

        unsigned char reply_signature[BUFFER_SIZE];
        if (recv_all(sock, reply_signature, reply_sig_len) != reply_sig_len) {
            fprintf(stderr, " 接收回复签名失败\n");
            goto cleanup;
        }

        // 7. 解密回复并验签
        unsigned char server_reply[BUFFER_SIZE];
        int reply_len = aes_gcm_decrypt(reply_cipher, reply_cipher_len, reply_tag, aes_key, reply_iv, server_reply);
        if (reply_len <= 0) {
            fprintf(stderr, " 回复解密失败\n");
            goto cleanup;
        }
        server_reply[reply_len] = '\0';

        int verify_res = verify_signature(server_reply, reply_len, reply_signature, reply_sig_len, server_pub);
        if (verify_res == 1) {
            printf(" 服务端回复（已验证）：%s\n", server_reply);
        } else {
            printf(" 服务端签名无效！\n");
            goto cleanup;
        }
    }

cleanup:
    // 释放资源
    EC_KEY_free(client_priv);
    EC_KEY_free(server_pub);
    close(sock);
    return 0;
}