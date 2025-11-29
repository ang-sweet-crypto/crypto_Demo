import struct
from crypto_base import CryptoBase
from lattice_lwe import LWE_KEM
from packet_layer import PacketLayer


class HTLSProtocol:
    """
    Hybrid-TLS Protocol Logic
    State machine handling the handshake and secure record exchange.
    """

    def __init__(self, sock):
        self.net = PacketLayer(sock)
        self.crypto = CryptoBase()
        self.lwe = LWE_KEM()
        self.session_key = None
        self.peer_id = "Unknown"

    def handshake_as_server(self):
        print("[H-TLS] Server: Waiting for ClientHello...")

        # 1. Receive ClientHello
        # Payload structure: [RSA_Pub_Len][RSA_Pub][ECDH_Pub_Len][ECDH_Pub][LWE_PK]
        m_type, payload = self.net.recv_frame()
        if m_type != PacketLayer.TYPE_HANDSHAKE: raise Exception("Expected Handshake")

        offset = 0
        rsa_len = struct.unpack('>I', payload[offset:offset + 4])[0];
        offset += 4
        client_rsa = payload[offset:offset + rsa_len];
        offset += rsa_len

        ecdh_len = struct.unpack('>I', payload[offset:offset + 4])[0];
        offset += 4
        client_ecdh = payload[offset:offset + ecdh_len];
        offset += ecdh_len

        lwe_pk_raw = payload[offset:]
        client_lwe_pk = self.lwe.deserialize_pk(lwe_pk_raw)

        print("[H-TLS] Server: Received keys. Computing Hybrid Secret...")

        # 2. Server Computations
        # A. ECDH Shared Secret
        ecdh_secret = self.crypto.compute_ecdh_secret(client_ecdh)

        # B. Lattice KEM Encapsulation (Quantum Safe Layer)
        # Server chooses the random secret, encrypts it with Client's LWE Public Key
        lwe_ciphertexts, lwe_secret_byte = self.lwe.encapsulate(client_lwe_pk)
        print(f"[H-TLS] Server: Lattice Secret Generated: {lwe_secret_byte.hex()}")

        # C. Derive Session Key (Hybrid)
        # Input Key Material = ECDH_Secret || Lattice_Secret
        ikm = ecdh_secret + lwe_secret_byte
        self.session_key = self.crypto.hkdf_expand(ikm, b'H-TLS v1')

        # 3. Send ServerHello
        # Payload: [RSA_Pub][ECDH_Pub][LWE_Ciphertexts][Signature]
        my_rsa = self.crypto.get_rsa_pub_bytes()
        my_ecdh = self.crypto.get_ecdh_pub_bytes()
        lwe_ct_bytes = self.lwe.serialize_ciphertexts(lwe_ciphertexts)

        body_to_sign = (
                struct.pack('>I', len(my_rsa)) + my_rsa +
                struct.pack('>I', len(my_ecdh)) + my_ecdh +
                struct.pack('>I', len(lwe_ct_bytes)) + lwe_ct_bytes
        )

        signature = self.crypto.sign(body_to_sign)  # Sign identity

        full_payload = body_to_sign + struct.pack('>I', len(signature)) + signature
        self.net.send_frame(PacketLayer.TYPE_HANDSHAKE, full_payload)
        print("[H-TLS] Server: Handshake Complete. Secure Channel Ready.")

    def handshake_as_client(self):
        print("[H-TLS] Client: Starting Handshake...")

        # 1. Prepare ClientHello
        # Client generates LWE Keypair (Receiver)
        lwe_pk, self.lwe_sk = self.lwe.key_gen()
        lwe_pk_bytes = self.lwe.serialize_pk(lwe_pk)

        my_rsa = self.crypto.get_rsa_pub_bytes()
        my_ecdh = self.crypto.get_ecdh_pub_bytes()

        payload = (
                struct.pack('>I', len(my_rsa)) + my_rsa +
                struct.pack('>I', len(my_ecdh)) + my_ecdh +
                lwe_pk_bytes
        )
        self.net.send_frame(PacketLayer.TYPE_HANDSHAKE, payload)

        # 2. Receive ServerHello
        m_type, resp = self.net.recv_frame()

        offset = 0
        rsa_len = struct.unpack('>I', resp[offset:offset + 4])[0];
        offset += 4
        server_rsa = resp[offset:offset + rsa_len];
        offset += rsa_len

        ecdh_len = struct.unpack('>I', resp[offset:offset + 4])[0];
        offset += 4
        server_ecdh = resp[offset:offset + ecdh_len];
        offset += ecdh_len

        lwe_ct_len = struct.unpack('>I', resp[offset:offset + 4])[0];
        offset += 4
        lwe_ct_raw = resp[offset:offset + lwe_ct_len];
        offset += lwe_ct_len

        sig_len = struct.unpack('>I', resp[offset:offset + 4])[0];
        offset += 4
        signature = resp[offset:offset + sig_len]

        # 3. Verify Signature (Integrity & Auth)
        signed_part = resp[:offset - 4 - sig_len]
        if not self.crypto.verify(server_rsa, signed_part, signature):
            raise Exception("Server Signature Verification Failed!")
        print("[H-TLS] Client: Server Identity Verified.")

        # 4. Compute Secrets
        ecdh_secret = self.crypto.compute_ecdh_secret(server_ecdh)

        # Decapsulate LWE
        lwe_ciphertexts = self.lwe.deserialize_ciphertexts(lwe_ct_raw)
        lwe_secret_byte = self.lwe.decapsulate(self.lwe_sk, lwe_ciphertexts)
        print(f"[H-TLS] Client: Lattice Secret Recovered: {lwe_secret_byte.hex()}")

        ikm = ecdh_secret + lwe_secret_byte
        self.session_key = self.crypto.hkdf_expand(ikm, b'H-TLS v1')
        print("[H-TLS] Client: Secure Channel Ready.")

    def send_secure(self, plaintext):
        if not self.session_key: raise Exception("No Session Key")
        ciphertext = self.crypto.aes_gcm_encrypt(self.session_key, plaintext.encode())
        self.net.send_frame(PacketLayer.TYPE_DATA, ciphertext)

    def recv_secure(self):
        m_type, payload = self.net.recv_frame()
        if m_type != PacketLayer.TYPE_DATA: return None
        plaintext = self.crypto.aes_gcm_decrypt(self.session_key, payload)
        return plaintext.decode()
