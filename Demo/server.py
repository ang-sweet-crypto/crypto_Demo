import socket
import threading
import sys
import os
# 引入之前写好的高级协议模块
from protocol import HTLSProtocol


def receive_loop(proto, peer_name):
    """
    后台线程：专门负责接收加密消息，解密后打印
    """
    try:
        while True:
            # 使用 HTLS 协议接收解密后的数据
            msg = proto.recv_secure()
            if not msg:
                print(f"\n[!] {peer_name} 断开了连接。")
                os._exit(0)  # 对方断开，直接退出程序

            # 打印对方消息，并重新输出提示符，保持界面整洁
            print(f"\n[{peer_name}]: {msg}")
            print("我 (Server): ", end='', flush=True)
    except Exception as e:
        print(f"\n[!] 接收线程错误: {e}")
        os._exit(1)


def handle_client(conn, addr):
    print(f"[*] 连接来自: {addr}")

    # 初始化高级协议对象
    proto = HTLSProtocol(conn)

    try:
        # --- 握手阶段 (集成 RSA + ECDH + Lattice) ---
        print("[*] 正在进行抗量子安全握手 (H-TLS)...")
        proto.handshake_as_server()
        print("[*] 握手成功！安全通道已建立。")

        # --- 通信阶段 (多线程交互) ---

        # 1. 启动接收线程
        recv_thread = threading.Thread(target=receive_loop, args=(proto, "Client"))
        recv_thread.daemon = True
        recv_thread.start()

        # 2. 主线程负责输入发送
        while True:
            try:
                msg = input("我 (Server): ")
                if not msg: continue

                if msg.lower() == 'exit':
                    print("[*] 正在关闭连接...")
                    break

                # 使用 HTLS 协议加密发送
                proto.send_secure(msg)

            except EOFError:
                break

    except Exception as e:
        print(f"[!] 发生错误: {e}")
    finally:
        conn.close()
        print("[-] 服务已关闭")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 9999))
    server.listen(1)
    print("[*] Bob (Server) 正在监听端口 9999...")

    try:
        # 简单起见，这里只处理一个连接
        conn, addr = server.accept()
        handle_client(conn, addr)
    except KeyboardInterrupt:
        print("\n[!] 服务器停止。")


if __name__ == '__main__':
    main()
