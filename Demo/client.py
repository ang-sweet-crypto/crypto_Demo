import socket
import threading
import sys  # 用于获取命令行参数
from crypto_utils import SecurityManager
from protocol import SecureProtocol

# 存储对方昵称（从第一条接收的消息中获取）
peer_nickname = "对方"


def receive_messages(proto):
    """实时接收服务器转发的消息（线程函数）"""
    global peer_nickname  # 引用全局变量存储对方昵称
    while True:
        msg = proto.recv_decrypted()
        if not msg:
            print("\n[System] 与对方断开连接！")
            break

        # 第一条消息是对方昵称，后续是聊天内容
        if peer_nickname == "对方" and msg.startswith("[昵称]"):
            peer_nickname = msg.replace("[昵称]", "").strip()
            print(f"\n[System] 对方昵称已设置为：{peer_nickname}")
            print("请输入消息：", end="", flush=True)
        else:
            print(f"\n[{peer_nickname}] {msg}")
            print("请输入消息：", end="", flush=True)

def main():
    host = 'localhost'
    port = 9999

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        print(f"已连接到转发服务器 ({host}:{port})")
    except Exception as e:
        print(f"连接失败: {e}")
        return

    sec = SecurityManager()
    proto = SecureProtocol(sock, sec)

    try:
        # --- 添加角色判断（发起方/响应方）---
        is_initiator = "--init" in sys.argv  # 命令行带--init则为发起方
        if is_initiator:
            print("[System] 作为发起方，正在发起握手...")
            proto.handshake_initiate()  # 发起方逻辑
        else:
            print("[System] 作为响应方，等待对方发起握手...")
            if not proto.handshake_respond():  # 响应方逻辑
                raise Exception("响应握手失败，请确保对方已启动")

        # --- 发送昵称（第一条消息）---
        nickname = input("请输入你的昵称：").strip()
        while not nickname:
            nickname = input("昵称不能为空，请重新输入：").strip()

        proto.send_encrypted(f"[昵称]{nickname}")
        print(f"\n[System] 昵称设置成功：{nickname}（输入 exit 退出）")

        # --- 启动接收消息线程 ---
        recv_thread = threading.Thread(target=receive_messages, args=(proto,))
        recv_thread.daemon = True
        recv_thread.start()

        while True:
            text = input("请输入消息：").strip()
            if not text:
                continue
            if text.lower() == "exit":
                print("[System] 正在退出...")
                break
            proto.send_encrypted(text)

    except Exception as e:
        print(f"\n[Error] 发生异常: {e}")
    finally:
        sock.close()


if __name__ == '__main__':
    main()
