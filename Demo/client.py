import socket
import threading
import sys
import os
import time
# 引入之前写好的高级协议模块
from protocol import HTLSProtocol


def receive_loop(proto, peer_name):
    """
    后台线程：接收消息
    """
    try:
        while True:
            msg = proto.recv_secure()
            if not msg:
                print(f"\n[!] {peer_name} 断开了连接。")
                os._exit(0)
            print(f"\n[{peer_name}]: {msg}")
            print("我 (Client): ", end='', flush=True)
    except Exception as e:
        print(f"\n[!] 接收错误: {e}")
        os._exit(1)


def get_connection(host, port, max_retries=10):
    """
    带重试机制的连接函数 (适配 Docker 启动慢的问题)
    """
    for i in range(max_retries):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            return sock
        except ConnectionRefusedError:
            print(f"[*] 等待 Bob ({host}:{port}) 启动... ({i + 1}/{max_retries})")
            time.sleep(2)
        except Exception as e:
            print(f"[!] 连接错误: {e}")
            time.sleep(2)
    return None


def main():

    host = 'secure-server' if os.environ.get('DOCKER_ENV') else 'localhost'
    port = 9999

    # 获取连接
    sock = get_connection(host, port)
    if not sock:
        print("[!] 无法连接到服务器。")
        sys.exit(1)

    print(f"[*] 已连接到 Bob ({host}:{port})")

    # 初始化协议
    proto = HTLSProtocol(sock)

    try:
        # --- 握手阶段 ---
        print("[*] 正在初始化 H-TLS 协议...")
        proto.handshake_as_client()
        print("[*] 安全通道建立完毕！现在可以开始加密聊天了。")
        print("[*] 输入 'exit' 退出。")

        # --- 通信阶段 ---

        # 启动接收线程
        recv_thread = threading.Thread(target=receive_loop, args=(proto, "Server"))
        recv_thread.daemon = True
        recv_thread.start()

        # 主线程循环输入
        while True:
            try:
                msg = input("我 (Client): ")
                if not msg: continue

                if msg.lower() == 'exit':
                    break

                proto.send_secure(msg)

            except EOFError:
                break
            except KeyboardInterrupt:
                break

    except Exception as e:
        print(f"[!] 错误: {e}")
    finally:
        sock.close()
        print("[-] 客户端已退出")


if __name__ == '__main__':
    main()
