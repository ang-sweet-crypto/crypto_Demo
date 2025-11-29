import struct

class PacketLayer:
    """
    [PROTOCOL INFRASTRUCTURE]
    负责网络字节流的成帧 (Framing) 与解析。
    Header Format: [Type (1B)] [Version (1B)] [Length (4B)]
    """
    HEADER_SIZE = 6
    VERSION = 0x01
    
    # 消息类型定义
    TYPE_HANDSHAKE = 0x10
    TYPE_DATA      = 0x20
    TYPE_ERROR     = 0xFF

    def __init__(self, sock):
        self.sock = sock

    def send_frame(self, msg_type, payload):
        length = len(payload)
        header = struct.pack('>BBI', msg_type, self.VERSION, length)
        self.sock.sendall(header + payload)

    def recv_frame(self):
        # 1. Read Header
        header_data = self._recv_n_bytes(self.HEADER_SIZE)
        if not header_data:
            return None, None
        
        msg_type, ver, length = struct.unpack('>BBI', header_data)
        
        if ver != self.VERSION:
            raise Exception(f"Protocol Version Mismatch: {ver}")
            
        # 2. Read Payload
        payload = self._recv_n_bytes(length)
        if not payload:
            raise Exception("Socket closed while reading payload")
            
        return msg_type, payload

    def _recv_n_bytes(self, n):
        """Helper to handle packet fragmentation"""
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
