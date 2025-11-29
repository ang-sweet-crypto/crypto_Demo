import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecurityManager:
    def __init__(self):
        # RSA 身份密钥（长期）
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

        # ECDH 临时密钥（每次会话生成）
        self.ecdh_private_key = None
        self.ecdh_public_key = None
        self.session_key = None

    def get_identity_pub_pem(self):
        """获取 RSA 公钥（PEM 格式）"""
        return self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def generate_ephemeral_keys(self):
        """生成 ECDH 临时密钥对，返回公钥（PEM 格式）"""
        self.ecdh_private_key = ec.generate_private_key(ec.SECP256R1())
        self.ecdh_public_key = self.ecdh_private_key.public_key()
        return self.ecdh_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign_message(self, data):
        """用 RSA 私钥签名数据"""
        return self.rsa_private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify_signature(self, pub_key_pem, data, signature):
        """用 RSA 公钥验证签名"""
        pub_key = serialization.load_pem_public_key(pub_key_pem)
        try:
            pub_key.verify(
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
            print(f"验签失败: {e}")
            return False

    def compute_shared_secret(self, peer_ecdh_pub_pem, salt):
        """计算 ECDH 共享密钥，派生 AES 会话密钥"""
        peer_ecdh_pub = serialization.load_pem_public_key(peer_ecdh_pub_pem)
        shared_secret = self.ecdh_private_key.exchange(ec.ECDH(), peer_ecdh_pub)

        # HKDF 派生 32 字节 AES 密钥
        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'secure_chat_handshake',
        ).derive(shared_secret)
        print(f"[System] 会话密钥协商成功 (Hex): {self.session_key.hex()[:10]}...")

    def symmetric_encrypt(self, plaintext_bytes):
        """AES-GCM 加密（返回 Nonce + 密文）"""
        if not self.session_key:
            raise Exception("会话密钥未建立")
        nonce = os.urandom(12)  # 12 字节 Nonce（AES-GCM 推荐）
        aesgcm = AESGCM(self.session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
        return nonce + ciphertext  # 前 12 字节是 Nonce，后面是密文

    def symmetric_decrypt(self, ciphertext_with_nonce):
        """AES-GCM 解密（输入 Nonce + 密文）"""
        if not self.session_key:
            raise Exception("会话密钥未建立")
        nonce = ciphertext_with_nonce[:12]
        ciphertext = ciphertext_with_nonce[12:]
        aesgcm = AESGCM(self.session_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
