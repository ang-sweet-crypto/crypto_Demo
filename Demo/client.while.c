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

#define PORT 8080                  // 与服务端端口一致
#define SERVER_PUB_KEY "ecc_keys/server_public.pem"  // 服务端公钥路径
#define CLIENT_PRIV_KEY "ecc_keys/client_private.pem"// 客户端私钥路径
#define SERVER_IP "127.0.0.1"      // 服务端IP（本地测试用127.0.0.1，公网替换为实际IP）
#define BUFFER_SIZE 1024           // 缓冲区大小，需与服务端一致

// 读取EC密钥（私钥/公钥）
EC_KEY* read_ec_key(const char* filename, int is_private) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open key file");
        return NULL;
    }
    EC_KEY* key = NULL;
    if (is_private) {
        key = PEM_read_ECPrivateKey(fp, &key, NULL, NULL);  // 读取私钥
    } else {
        key = PEM_read_EC_PUBKEY(fp, &key, NULL, NULL);     // 读取公钥
    }
    fclose(fp);
    if (!key) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    return key;
}

// 发送带签名的消息
int send_signed_message(int sock, const char* msg, EC_KEY* client_priv) {
    if (strlen(msg) >= BUFFER_SIZE) {
        printf("消息过长（最大%d字符）\n", BUFFER_SIZE - 1);
        return -1;
    }
    unsigned char sig[ECDSA_size(client_priv)];
    unsigned int sig_len;
    if (ECDSA_sign(0, (unsigned char*)msg, strlen(msg), sig, &sig_len, client_priv) != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    // 发送格式：消息长度 -> 消息内容 -> 签名长度 -> 签名
    int msg_len = strlen(msg);
    if (send(sock, &msg_len, sizeof(msg_len), 0) != sizeof(msg_len)) {
        perror("消息长度发送失败");
        return -1;
    }
    if (send(sock, msg, msg_len, 0) != msg_len) {
        perror("消息内容发送失败");
        return -1;
    }
    if (send(sock, &sig_len, sizeof(sig_len), 0) != sizeof(sig_len)) {
        perror("签名长度发送失败");
        return -1;
    }
    if (send(sock, sig, sig_len, 0) != sig_len) {
        perror("签名内容发送失败");
        return -1;
    }
    return 0;
}

// 接收并验签服务端回复
int recv_and_verify(int sock, EC_KEY* server_pub) {
    char buffer[BUFFER_SIZE] = {0};
    unsigned char sig[ECDSA_size(server_pub)];
    int msg_len, sig_len;

    // 接收消息长度
    if (recv(sock, &msg_len, sizeof(msg_len), 0) != sizeof(msg_len)) {
        perror("接收消息长度失败");
        return -1;
    }
    if (msg_len <= 0 || msg_len >= BUFFER_SIZE) {
        printf("无效的消息长度（%d）\n", msg_len);
        return -1;
    }

    // 接收消息内容
    if (recv(sock, buffer, msg_len, 0) != msg_len) {
        perror("接收消息内容失败");
        return -1;
    }
    buffer[msg_len] = '\0';

    // 接收签名长度
    if (recv(sock, &sig_len, sizeof(sig_len), 0) != sizeof(sig_len)) {
        perror("接收签名长度失败");
        return -1;
    }
    if (recv(sock, sig, sig_len, 0) != sig_len) {
        perror("接收签名内容失败");
        return -1;
    }

    // 验签
    int verify_ok = ECDSA_verify(0, (unsigned char*)buffer, msg_len, sig, sig_len, server_pub);
    if (verify_ok) {
        printf("服务端回复（已验证）：%s\n", buffer);
    } else {
        printf("服务端签名无效！\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;

    // 创建TCP Socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket创建失败");
        exit(EXIT_FAILURE);
    }

    // 配置服务端地址
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("服务端IP无效");
        exit(EXIT_FAILURE);
    }

    // 连接服务端
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("连接服务端失败（请先启动服务端）");
        exit(EXIT_FAILURE);
    }
    printf("已连接到服务端 %s:%d\n", SERVER_IP, PORT);

    // 读取密钥
    EC_KEY* client_priv = read_ec_key(CLIENT_PRIV_KEY, 1);
    EC_KEY* server_pub = read_ec_key(SERVER_PUB_KEY, 0);
    if (!client_priv || !server_pub) {
        exit(EXIT_FAILURE);
    }

    // 循环发送消息（直到输入exit）
    char msg[BUFFER_SIZE];
    while (1) {
        printf("\n请输入消息（输入exit退出）：");
        fgets(msg, sizeof(msg), stdin);
        msg[strcspn(msg, "\n")] = '\0';  // 去除换行符

        if (strcmp(msg, "exit") == 0) {
            printf(" 退出客户端\n");
            break;
        }

        if (send_signed_message(sock, msg, client_priv) != 0) {
            printf("消息发送失败\n");
            break;
        }
        printf("消息已发送\n");

        if (recv_and_verify(sock, server_pub) < 0) {
            printf("接收回复失败\n");
            break;
        }
    }

    // 释放资源
    EC_KEY_free(client_priv);
    EC_KEY_free(server_pub);
    close(sock);
    return 0;
}