import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecurityManager:
    def __init__(self):
        print("[Crypto] 初始化安全模块，生成临时身份密钥...")
        # 1. RSA 密钥对：用于“身份认证”和“数字签名”
        # 2048位是目前的工业标准安全长度
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        
        # 2. ECDH 密钥对：用于“密钥协商”
        # 每次会话生成新的（临时），保证前向安全性
        self.ecdh_private_key = ec.generate_private_key(ec.SECP256R1())
        self.ecdh_public_key = self.ecdh_private_key.public_key()
        
        self.session_key = None # 最终协商出来的 AES 密钥

    def get_rsa_public_bytes(self):
        """导出 RSA 公钥为 PEM 格式，以便通过网络发送"""
        return self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_ecdh_public_bytes(self):
        """导出 ECDH 公钥为 PEM 格式"""
        return self.ecdh_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign_data(self, data):
        """核心功能：用我的私钥对数据签名，证明‘这是我发的’"""
        signature = self.rsa_private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, rsa_pub_bytes, data, signature):
        """核心功能：用对方的公钥验签，防止中间人篡改数据"""
        peer_rsa_pub = serialization.load_pem_public_key(rsa_pub_bytes)
        try:
            peer_rsa_pub.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"[Crypto] 验签失败: {e}")
            return False

    def derive_session_key(self, peer_ecdh_pub_bytes):
        """核心功能：Diffie-Hellman 密钥协商"""
        # 加载对方发来的 ECDH 公钥
        peer_ecdh_pub = serialization.load_pem_public_key(peer_ecdh_pub_bytes)
        
        # 魔法时刻：我的私钥 + 你的公钥 = 共享密钥
        shared_key = self.ecdh_private_key.exchange(ec.ECDH(), peer_ecdh_pub)
        
        # 使用 HKDF 算法将共享密钥转化为标准的 AES 256位 密钥
        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure_chat_handshake',
        ).derive(shared_key)
        print(f"[Crypto] 协商完成，AES 密钥指纹: {self.session_key.hex()[:8]}...")

    def encrypt_message(self, plaintext):
        """AES-GCM 加密：同时提供加密和防篡改校验"""
        if not self.session_key:
            raise Exception("错误：未建立安全连接")
        
        # 这里的 Nonce (随机数) 是防止重放攻击的关键
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        # 将 Nonce 拼在密文前面一起发过去，解密时需要用到
        return nonce + ciphertext

    def decrypt_message(self, payload):
        """AES-GCM 解密"""
        if not self.session_key:
            raise Exception("错误：未建立安全连接")
        
        nonce = payload[:12] # 取出前12字节的随机数
        ciphertext = payload[12:]
        
        aesgcm = AESGCM(self.session_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception:
            return "[解密失败：数据损坏或密钥错误]"
