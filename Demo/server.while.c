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

#define PORT 8080                  // 与客户端端口一致
#define SERVER_PRIV_KEY "ecc_keys/server_private.pem"  // 服务端私钥路径
#define CLIENT_PUB_KEY "ecc_keys/client_public.pem"    // 客户端公钥路径
#define BUFFER_SIZE 1024           // 缓冲区大小，需与客户端一致

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

// 处理客户端连接（循环交互，直到任一方输入exit）
void handle_client(int client_fd, EC_KEY* server_priv, EC_KEY* client_pub) {
    while (1) {
        char client_msg[BUFFER_SIZE] = {0};
        unsigned char client_sig[ECDSA_size(client_pub)];
        int msg_len, sig_len;

        // 1. 接收客户端消息长度
        if (recv(client_fd, &msg_len, sizeof(msg_len), 0) <= 0) {
            printf("Client disconnected. Closing connection.\n");
            close(client_fd);
            return;
        }
        if (msg_len <= 0 || msg_len >= BUFFER_SIZE) {
            printf("Invalid message length from client: %d. Closing connection.\n", msg_len);
            close(client_fd);
            return;
        }

        // 2. 接收客户端消息内容
        if (recv(client_fd, client_msg, msg_len, 0) != msg_len) {
            perror("Failed to receive client message");
            close(client_fd);
            return;
        }
        client_msg[msg_len] = '\0';
        printf("Received from client: %s\n", client_msg);

        // 若客户端输入exit，断开连接
        if (strcmp(client_msg, "exit") == 0) {
            printf("Client requested exit. Closing connection.\n");
            close(client_fd);
            return;
        }

        // 3. 接收客户端签名并验签
        if (recv(client_fd, &sig_len, sizeof(sig_len), 0) != sizeof(sig_len)) {
            perror("Failed to receive client signature length");
            close(client_fd);
            return;
        }
        if (recv(client_fd, client_sig, sig_len, 0) != sig_len) {
            perror("Failed to receive client signature");
            close(client_fd);
            return;
        }
        int verify_ok = ECDSA_verify(0, (unsigned char*)client_msg, msg_len, client_sig, sig_len, client_pub);
        if (!verify_ok) {
            printf("Client signature invalid! Message may be tampered. Closing connection.\n");
            close(client_fd);
            return;
        }
        printf("Client signature verified.\n");

        // 4. 服务端手动输入回复
        char server_reply[BUFFER_SIZE];
        printf("Enter server reply (type 'exit' to close connection): ");
        fgets(server_reply, sizeof(server_reply), stdin);
        server_reply[strcspn(server_reply, "\n")] = '\0';  // 去除换行符

        if (strcmp(server_reply, "exit") == 0) {
            printf("Server requested exit. Closing connection.\n");
            close(client_fd);
            return;
        }

        // 5. 对回复签名并发送
        int reply_len = strlen(server_reply);
        unsigned char reply_sig[ECDSA_size(server_priv)];
        unsigned int reply_sig_len;
        if (ECDSA_sign(0, (unsigned char*)server_reply, reply_len, reply_sig, &reply_sig_len, server_priv) != 1) {
            ERR_print_errors_fp(stderr);
            close(client_fd);
            return;
        }

        // 发送格式：回复长度 -> 回复内容 -> 签名长度 -> 签名
        send(client_fd, &reply_len, sizeof(reply_len), 0);
        send(client_fd, server_reply, reply_len, 0);
        send(client_fd, &reply_sig_len, sizeof(reply_sig_len), 0);
        send(client_fd, reply_sig, reply_sig_len, 0);
        printf("Replied to client: %s\n", server_reply);
    }
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // 创建TCP Socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 配置地址（监听所有网卡，端口PORT）
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // 绑定Socket
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // 监听连接
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    printf("Server started, waiting for client on port %d...\n", PORT);

    // 读取密钥
    EC_KEY* server_priv = read_ec_key(SERVER_PRIV_KEY, 1);
    EC_KEY* client_pub = read_ec_key(CLIENT_PUB_KEY, 0);
    if (!server_priv || !client_pub) {
        printf("Failed to load keys. Check ecc_keys directory!\n");
        exit(EXIT_FAILURE);
    }

    // 循环接受客户端连接
    while (1) {
        if ((client_fd = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            continue;
        }
        printf("Client connected from: %s:%d\n", 
               inet_ntoa(address.sin_addr), ntohs(address.sin_port));
        
        handle_client(client_fd, server_priv, client_pub);
    }

    // 释放资源
    EC_KEY_free(server_priv);
    EC_KEY_free(client_pub);
    close(server_fd);
    return 0;
}