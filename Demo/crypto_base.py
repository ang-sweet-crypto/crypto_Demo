import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoBase:
    def __init__(self):
        # RSA 用于身份签名
        self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # ECDH 用于常规密钥协商
        self.ecdh_key = ec.generate_private_key(ec.SECP256R1())

    def get_rsa_pub_bytes(self):
        return self.rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_ecdh_pub_bytes(self):
        return self.ecdh_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, message):
        return self.rsa_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    @staticmethod
    def verify(pub_pem, message, signature):
        try:
            pub_key = serialization.load_pem_public_key(pub_pem)
            pub_key.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def compute_ecdh_secret(self, peer_pub_pem):
        peer_pub = serialization.load_pem_public_key(peer_pub_pem)
        return self.ecdh_key.exchange(ec.ECDH(), peer_pub)

    @staticmethod
    def hkdf_expand(ikm, info, length=32):
        """
        Hybrid Key Derivation:
        IKM (Input Keying Material) 将是 ECDH Secret + Lattice Secret 的混合体
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None, # 可选，生产环境建议加入随机盐
            info=info
        )
        return hkdf.derive(ikm)

    @staticmethod
    def aes_gcm_encrypt(key, plaintext):
        """AES-GCM 加密，提供机密性和完整性"""
        nonce = os.urandom(12) # 96 bits nonce
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    @staticmethod
    def aes_gcm_decrypt(key, payload):
        nonce = payload[:12]
        ciphertext = payload[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
