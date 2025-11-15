#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define AES_KEY_SIZE 32    // AES-256密钥长度
#define IV_SIZE 12         // GCM模式推荐IV长度
#define TAG_SIZE 16        // GCM认证标签长度（固定16字节）
#define BUFFER_SIZE 1024   // 数据缓冲区大小

// 确保接收指定长度的数据（解决网络分片问题）
int recv_all(int fd, void *buf, int len) {
    int total = 0;
    while (total < len) {
        int n = recv(fd, (char*)buf + total, len - total, 0);
        if (n <= 0) {
            fprintf(stderr, "recv failed (total received: %d/%d)\n", total, len);
            return -1; // 接收失败或连接断开
        }
        total += n;
    }
    return total; // 成功接收完整数据
}

// 生成AES密钥（基于ECDH共享密钥通过SHA256导出）
void generate_aes_key(const unsigned char *shared_secret, int secret_len, unsigned char *aes_key) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        exit(1);
    }
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    EVP_DigestUpdate(mdctx, shared_secret, secret_len);
    unsigned int key_len;
    EVP_DigestFinal_ex(mdctx, aes_key, &key_len);
    EVP_MD_CTX_free(mdctx);
}

// AES-GCM加密（生成密文+认证标签）
int aes_gcm_encrypt(const unsigned char *plaintext, int plain_len,
                   const unsigned char *key, const unsigned char *iv,
                   unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return -1;
    }

    // 初始化加密上下文（AES-256-GCM）
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len, cipher_len = 0;
    // 加密明文到密文
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plain_len) != 1) {
        fprintf(stderr, "EVP_EncryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    cipher_len = len;

    // 完成加密并生成认证标签（16字节）
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    cipher_len += len;

    // 获取认证标签（必须在Final之后调用）
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) {
        fprintf(stderr, "EVP_CTRL_GCM_GET_TAG failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return cipher_len;
}

// AES-GCM解密（验证标签+解密）
int aes_gcm_decrypt(const unsigned char *ciphertext, int cipher_len,
                   const unsigned char *tag, const unsigned char *key,
                   const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return -1;
    }

    // 初始化解密上下文
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        fprintf(stderr, "EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // 设置认证标签用于验证（必须在Update之前）
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag) != 1) {
        fprintf(stderr, "EVP_CTRL_GCM_SET_TAG failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len, plain_len = 0;
    // 解密密文到明文
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len) != 1) {
        fprintf(stderr, "EVP_DecryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plain_len = len;

    // 完成解密并验证标签（验证失败会返回0）
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        fprintf(stderr, "EVP_DecryptFinal_ex failed (tag verification failed?)\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plain_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plain_len;
}

// 生成ECDSA签名（使用私钥）
int generate_signature(const unsigned char *message, int msg_len,
                      unsigned char *signature, EC_KEY *priv_key) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(message, msg_len, hash); // 先对消息哈希

    unsigned int sig_len;
    if (ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, signature, &sig_len, priv_key) != 1) {
        fprintf(stderr, "ECDSA_sign failed\n");
        return -1;
    }
    return sig_len;
}

// 验证ECDSA签名（使用公钥）
int verify_signature(const unsigned char *message, int msg_len,
                    const unsigned char *signature, int sig_len,
                    EC_KEY *pub_key) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(message, msg_len, hash); // 对消息重新哈希

    int ret = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature, sig_len, pub_key);
    if (ret != 1) {
        fprintf(stderr, "ECDSA_verify failed (ret: %d)\n", ret);
    }
    return ret;
}

int main() {
    // 1. 加载密钥对（服务端私钥 + 客户端公钥）
    FILE *server_priv_fd = fopen("ecc_keys/server_private.pem", "r");
    if (!server_priv_fd) {
        fprintf(stderr, "Failed to open server private key (ecc_keys/server_private.pem)\n");
        return 1;
    }
    EC_KEY *server_priv = PEM_read_ECPrivateKey(server_priv_fd, NULL, NULL, NULL);
    fclose(server_priv_fd);
    if (!server_priv) {
        fprintf(stderr, "Failed to load server private key\n");
        return 1;
    }

    FILE *client_pub_fd = fopen("ecc_keys/client_public.pem", "r");
    if (!client_pub_fd) {
        fprintf(stderr, "Failed to open client public key (ecc_keys/client_public.pem)\n");
        EC_KEY_free(server_priv);
        return 1;
    }
    EC_KEY *client_pub = PEM_read_EC_PUBKEY(client_pub_fd, NULL, NULL, NULL);
    fclose(client_pub_fd);
    if (!client_pub) {
        fprintf(stderr, "Failed to load client public key\n");
        EC_KEY_free(server_priv);
        return 1;
    }

    // 2. 创建Socket并监听
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "socket creation failed\n");
        EC_KEY_free(server_priv);
        EC_KEY_free(client_pub);
        return 1;
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(8080)
    };
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "bind failed\n");
        close(sockfd);
        EC_KEY_free(server_priv);
        EC_KEY_free(client_pub);
        return 1;
    }

    if (listen(sockfd, 5) < 0) {
        fprintf(stderr, "listen failed\n");
        close(sockfd);
        EC_KEY_free(server_priv);
        EC_KEY_free(client_pub);
        return 1;
    }
    printf("Server started, waiting for client on port 8080...\n");

    // 3. 接受客户端连接
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        fprintf(stderr, "accept failed\n");
        close(sockfd);
        EC_KEY_free(server_priv);
        EC_KEY_free(client_pub);
        return 1;
    }
    printf("Client connected: %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    // 4. 接收客户端消息（顺序：IV → 密文长度 → 密文 → 标签 → 签名长度 → 签名）
    unsigned char iv[IV_SIZE];
    if (recv_all(client_fd, iv, IV_SIZE) != IV_SIZE) {
        fprintf(stderr, "Failed to receive IV\n");
        goto cleanup;
    }

    int cipher_len_net;
    if (recv_all(client_fd, &cipher_len_net, sizeof(cipher_len_net)) != sizeof(cipher_len_net)) {
        fprintf(stderr, "Failed to receive cipher length\n");
        goto cleanup;
    }
    int cipher_len = ntohl(cipher_len_net);
    if (cipher_len <= 0 || cipher_len > BUFFER_SIZE) {
        fprintf(stderr, "Invalid cipher length: %d\n", cipher_len);
        goto cleanup;
    }

    unsigned char ciphertext[BUFFER_SIZE];
    if (recv_all(client_fd, ciphertext, cipher_len) != cipher_len) {
        fprintf(stderr, "Failed to receive ciphertext\n");
        goto cleanup;
    }

    unsigned char tag[TAG_SIZE];
    if (recv_all(client_fd, tag, TAG_SIZE) != TAG_SIZE) {
        fprintf(stderr, "Failed to receive tag\n");
        goto cleanup;
    }

    int sig_len_net;
    if (recv_all(client_fd, &sig_len_net, sizeof(sig_len_net)) != sizeof(sig_len_net)) {
        fprintf(stderr, "Failed to receive signature length\n");
        goto cleanup;
    }
    int sig_len = ntohl(sig_len_net);
    if (sig_len <= 0 || sig_len > BUFFER_SIZE) {
        fprintf(stderr, "Invalid signature length: %d\n", sig_len);
        goto cleanup;
    }

    unsigned char signature[BUFFER_SIZE];
    if (recv_all(client_fd, signature, sig_len) != sig_len) {
        fprintf(stderr, "Failed to receive signature\n");
        goto cleanup;
    }

    // 5. 计算ECDH共享密钥并生成AES密钥
    unsigned char shared_secret[32];
    int secret_len = ECDH_compute_key(shared_secret, sizeof(shared_secret),
                                      EC_KEY_get0_public_key(client_pub),
                                      server_priv, NULL);
    if (secret_len <= 0) {
        fprintf(stderr, "ECDH_compute_key failed\n");
        goto cleanup;
    }
    unsigned char aes_key[AES_KEY_SIZE];
    generate_aes_key(shared_secret, secret_len, aes_key);

    // 6. 解密并验证客户端消息
    unsigned char client_msg[BUFFER_SIZE];
    int client_msg_len = aes_gcm_decrypt(ciphertext, cipher_len, tag, aes_key, iv, client_msg);
    if (client_msg_len <= 0) {
        fprintf(stderr, "Failed to decrypt client message\n");
        goto cleanup;
    }
    client_msg[client_msg_len] = '\0'; // 确保字符串结束
    printf("\nReceived from client: %s\n", client_msg);

    int verify_res = verify_signature(client_msg, client_msg_len, signature, sig_len, client_pub);
    if (verify_res == 1) {
        printf("✅ Client signature verified successfully\n");
    } else {
        printf("❌ Client signature verification failed\n");
        goto cleanup; // 签名验证失败，终止通信
    }

    // 7. 服务端输入回复消息
    unsigned char server_reply[BUFFER_SIZE];
    printf("Enter reply to client: ");
    if (fgets((char*)server_reply, BUFFER_SIZE, stdin) == NULL) {
        fprintf(stderr, "Failed to read input\n");
        goto cleanup;
    }
    server_reply[strcspn((char*)server_reply, "\n")] = '\0'; // 去除换行符
    int reply_len = strlen((char*)server_reply);
    if (reply_len <= 0) {
        fprintf(stderr, "Empty reply\n");
        goto cleanup;
    }

    // 8. 对回复消息签名（服务端私钥）
    unsigned char reply_signature[BUFFER_SIZE];
    int reply_sig_len = generate_signature(server_reply, reply_len, reply_signature, server_priv);
    if (reply_sig_len <= 0) {
        fprintf(stderr, "Failed to generate reply signature\n");
        goto cleanup;
    }

    // 9. 加密回复消息（生成新IV和Tag）
    unsigned char reply_iv[IV_SIZE];
    FILE *urandom = fopen("/dev/urandom", "r");
    if (!urandom || fread(reply_iv, 1, IV_SIZE, urandom) != IV_SIZE) {
        fprintf(stderr, "Failed to generate random IV\n");
        if (urandom) fclose(urandom);
        goto cleanup;
    }
    fclose(urandom);

    unsigned char reply_cipher[BUFFER_SIZE];
    unsigned char reply_tag[TAG_SIZE];
    int reply_cipher_len = aes_gcm_encrypt(server_reply, reply_len, aes_key, reply_iv, reply_cipher, reply_tag);
    if (reply_cipher_len <= 0) {
        fprintf(stderr, "Failed to encrypt reply\n");
        goto cleanup;
    }

    // 10. 发送回复给客户端（顺序：IV → 密文长度 → 密文 → 标签 → 签名长度 → 签名）
    if (send(client_fd, reply_iv, IV_SIZE, 0) != IV_SIZE) {
        fprintf(stderr, "Failed to send reply IV\n");
        goto cleanup;
    }

    int reply_cipher_len_net = htonl(reply_cipher_len);
    if (send(client_fd, &reply_cipher_len_net, sizeof(reply_cipher_len_net), 0) != sizeof(reply_cipher_len_net)) {
        fprintf(stderr, "Failed to send reply cipher length\n");
        goto cleanup;
    }

    if (send(client_fd, reply_cipher, reply_cipher_len, 0) != reply_cipher_len) {
        fprintf(stderr, "Failed to send reply ciphertext\n");
        goto cleanup;
    }

    if (send(client_fd, reply_tag, TAG_SIZE, 0) != TAG_SIZE) {
        fprintf(stderr, "Failed to send reply tag\n");
        goto cleanup;
    }

    int reply_sig_len_net = htonl(reply_sig_len);
    if (send(client_fd, &reply_sig_len_net, sizeof(reply_sig_len_net), 0) != sizeof(reply_sig_len_net)) {
        fprintf(stderr, "Failed to send reply signature length\n");
        goto cleanup;
    }

    if (send(client_fd, reply_signature, reply_sig_len, 0) != reply_sig_len) {
        fprintf(stderr, "Failed to send reply signature\n");
        goto cleanup;
    }

    printf("Reply sent to client successfully\n");

cleanup:
    // 清理资源
    close(client_fd);
    close(sockfd);
    EC_KEY_free(server_priv);
    EC_KEY_free(client_pub);
    return 0;
}