import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoPrimitives:
    def __init__(self):
        self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ecdh_key = ec.generate_private_key(ec.SECP256R1())

    def get_rsa_pub_pem(self):
        return self.rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_ecdh_pub_pem(self):
        return self.ecdh_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, data):
        return self.rsa_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    @staticmethod
    def verify(pub_pem, data, signature):
        try:
            pub_key = serialization.load_pem_public_key(pub_pem)
            pub_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def compute_ecdh_shared(self, peer_pub_pem):
        peer_pub = serialization.load_pem_public_key(peer_pub_pem)
        return self.ecdh_key.exchange(ec.ECDH(), peer_pub)

    @staticmethod
    def hkdf_derive(ikm, salt, info_bytes, length=32):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info_bytes)
        return hkdf.derive(ikm)

    @staticmethod
    def aes_encrypt(key, plaintext):
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    @staticmethod
    def aes_decrypt(key, payload):
        nonce = payload[:12]
        ct = payload[12:]
        return AESGCM(key).decrypt(nonce, ct, None)
