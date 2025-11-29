import socket
import threading
import struct

HOST = '0.0.0.0'
PORT = 9999
clients = []  # 存储客户端连接：[(conn, addr), ...]
lock = threading.Lock()

def _recv_packet(conn):
    """接收原始数据包（不解密）"""
    try:
        # 读取 5 字节 header (4 字节长度 + 1 字节类型)
        header = conn.recv(5)
        if not header:
            return None, None
        length, msg_type = struct.unpack("!IB", header)

        # 读取 payload
        payload = b""
        while len(payload) < length:
            chunk = conn.recv(length - len(payload))
            if not chunk:
                return None, None
            payload += chunk
        return msg_type, payload
    except Exception as e:
        print(f"[Server] 接收数据包失败: {e}")
        return None, None

def _send_packet(conn, msg_type, payload):
    """发送原始数据包（不加密）"""
    try:
        header = struct.pack("!IB", len(payload), msg_type)
        conn.sendall(header + payload)
    except Exception as e:
        print(f"[Server] 发送数据包失败: {e}")
        # 发送失败则移除客户端
        with lock:
            for i, (c_conn, _) in enumerate(clients):
                if c_conn == conn:
                    clients.pop(i)
                    break
        conn.close()

def handle_client(conn, addr):
    """处理客户端连接，仅转发数据包"""
    print(f"[Server] 客户端 {addr} 连接成功")
    try:
        while True:
            msg_type, payload = _recv_packet(conn)
            if not msg_type:
                break  # 客户端断开连接

            # 仅转发 MSG_DATA (加密消息) 和握手相关消息
            with lock:
                for (c_conn, c_addr) in clients:
                    if c_conn != conn:  # 不转发给自己
                        _send_packet(c_conn, msg_type, payload)
                        print(f"[Server] 转发数据包 from {addr} to {c_addr} (类型: {msg_type})")
    except Exception as e:
        print(f"[Server] 客户端 {addr} 连接异常: {e}")
        
    finally:
        # 清理连接
        with lock:
            for i, (c_conn, _) in enumerate(clients):
                if c_conn == conn:
                    clients.pop(i)
                    break
        conn.close()
        print(f"[Server] 客户端 {addr} 断开连接，当前在线: {len(clients)}")


def main():
    """启动纯转发服务器"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(2)  # 支持最多 2 个客户端（A 和 B）
    print(f"[Server] 纯转发服务器启动，监听 {HOST}:{PORT}")
    print(f"[Server] 等待客户端连接 (最多 2 个)...")

    try:
        while True:
            conn, addr = server.accept()
            with lock:
                if len(clients) >= 2:
                    print(f"[Server] 客户端 {addr} 连接被拒绝（已达最大连接数）")
                    conn.close()
                    continue
                clients.append((conn, addr))
                print(f"[Server] 客户端 {addr} 加入，当前在线: {len(clients)}")

            # 启动线程处理该客户端
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\n[Server] 正在关闭服务器...")
        with lock:
            for conn, _ in clients:
                conn.close()
        server.close()
        print("[Server] 服务器已关闭")

if __name__ == '__main__':
    main()
