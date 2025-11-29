import struct
import json
import socket
import os

# 消息类型定义
MSG_HELLO = 0x01  # 握手开始
MSG_KEY_EXCH = 0x02  # 交换临时公钥 + 签名
MSG_FINISHED = 0x03  # 握手结束
MSG_DATA = 0x04  # 加密聊天数据
MSG_ERROR = 0xFF  # 错误消息

class SecureProtocol:
    def __init__(self, socket_conn, crypto_manager):
        self.sock = socket_conn
        self.crypto = crypto_manager
        self.buffer = b""

    def send_packet(self, msg_type, payload: bytes):
        """发送协议数据包"""
        length = len(payload)
        # Header: 4 bytes length + 1 byte type
        header = struct.pack("!IB", length, msg_type)
        self.sock.sendall(header + payload)

    def receive_packet(self):
        """接收完整的数据包"""
        # 先读 Header (5 bytes)
        header_data = self._recv_n(5)
        if not header_data:
            return None, None

        length, msg_type = struct.unpack("!IB", header_data)
        payload = self._recv_n(length)
        return msg_type, payload

    def _recv_n(self, n):
        """确保接收 n 个字节"""
        data = b""
        while len(data) < n:
            packet = self.sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def handshake_initiate(self):
        """客户端发起握手"""
        print("[Protocol] Sending Client Hello...")
        # 1. Client Hello (这里可以加上 LWE 加密的一小段随机数作为 Proof of Concept)
        self.send_packet(MSG_HELLO, b"CLIENT_HELLO")

        # 2. 接收 Server Key Exchange
        m_type, payload = self.receive_packet()
        if m_type != MSG_KEY_EXCH: raise Exception("Handshake Error")

        data = json.loads(payload.decode())
        server_id_pub = data['id_pub'].encode()
        server_eph_pub = data['eph_pub'].encode()
        signature = bytes.fromhex(data['sign'])
        salt = bytes.fromhex(data['salt'])

        # 3. 验证签名 (防中间人攻击)
        # 注：实际场景中客户端应预先知道服务器公钥，这里简化为信任首次接收的公钥
        print("[Protocol] Verifying Server Signature...")
        if not self.crypto.verify_signature(server_id_pub, server_eph_pub, signature):
            raise Exception("Server Signature Verification Failed!")

        # 4. 生成自己的临时密钥并计算共享密钥
        my_eph_pub = self.crypto.generate_ephemeral_keys()
        self.crypto.compute_shared_secret(server_eph_pub, salt)

        # 5. 发送 Client Key Exchange
        sign = self.crypto.sign_message(my_eph_pub)  # 对自己的临时公钥签名
        resp = {
            'id_pub': self.crypto.get_identity_pub_pem().decode(),
            'eph_pub': my_eph_pub.decode(),
            'sign': sign.hex()
        }
        self.send_packet(MSG_KEY_EXCH, json.dumps(resp).encode())
        print("[Protocol] Handshake Completed. Secure Channel Established.")

    def handshake_respond(self):
        """服务端响应握手"""
        print("[Protocol] Waiting for Client Hello...")
        m_type, payload = self.receive_packet()
        if m_type != MSG_HELLO: return False

        # 1. 生成临时密钥
        my_eph_pub = self.crypto.generate_ephemeral_keys()

        # 2. 签名临时公钥
        sign = self.crypto.sign_message(my_eph_pub)
        salt = os.urandom(16)  # 服务器生成 Salt

        # 3. 发送 Server Key Exchange
        msg = {
            'id_pub': self.crypto.get_identity_pub_pem().decode(),
            'eph_pub': my_eph_pub.decode(),
            'sign': sign.hex(),
            'salt': salt.hex()
        }
        self.send_packet(MSG_KEY_EXCH, json.dumps(msg).encode())

        # 4. 接收 Client Key Exchange
        m_type, payload = self.receive_packet()
        data = json.loads(payload.decode())
        client_id_pub = data['id_pub'].encode()
        client_eph_pub = data['eph_pub'].encode()
        client_sign = bytes.fromhex(data['sign'])

        # 5. 验证客户端签名
        if not self.crypto.verify_signature(client_id_pub, client_eph_pub, client_sign):
            raise Exception("Client Signature Verification Failed!")

        # 6. 计算共享密钥
        self.crypto.compute_shared_secret(client_eph_pub, salt)
        print("[Protocol] Handshake Completed.")
        return True

    def send_encrypted(self, text):
        encrypted = self.crypto.symmetric_encrypt(text.encode())
        self.send_packet(MSG_DATA, encrypted)

    def recv_decrypted(self):
        m_type, payload = self.receive_packet()
        if m_type == MSG_DATA:
            try:
                decrypted = self.crypto.symmetric_decrypt(payload)
                return decrypted.decode()
            except Exception as e:
                print(f"Decryption Error: {e}")
                return None
        return None
