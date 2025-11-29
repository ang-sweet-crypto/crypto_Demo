from math_core import MatrixMath
import random

class LWE_KEM:
    """
    [BONUS IMPLEMENTATION]
    基于 Learning With Errors (LWE) 问题的密钥封装机制。
    包含 KeyGen, Encapsulate, Decapsulate 三大原语。
    
    参数集 (Toy Parameters for Demo):
    n: 维度
    q: 模数
    m: 样本数
    """
    def __init__(self, n=32, q=1021, m=64):
        self.n = n
        self.q = q  # 必须是素数
        self.m = m
        self.math = MatrixMath()

    def key_gen(self):
        """
        生成公私钥对。
        Secret key s: 随机向量
        Public key (A, b): A是随机矩阵, b = A*s + e
        """
        # 1. 生成私钥 s (n维)
        s = self.math.gen_uniform_vector(self.n, self.q)
        
        # 2. 生成公钥矩阵 A (m x n)
        A = self.math.gen_uniform_matrix(self.m, self.n, self.q)
        
        # 3. 生成误差向量 e (m维)
        e = self.math.gen_error_vector(self.m, self.q, bound=2)
        
        # 4. 计算 b = As + e
        As = self.math.mat_mul_vec(A, s, self.q)
        b = self.math.vec_add(As, e, self.q)
        
        pk = {'A': A, 'b': b}
        sk = {'s': s}
        return pk, sk

    def encapsulate(self, pk):
        """
        封装一个比特。为了安全通信，我们通常通过多次调用
        或者使用更高级的 LWE 变体来协商一个多字节密钥。
        本 Demo 为了代码清晰，演示协商 1 个 Byte (8 bits)。
        
        Returns: (ciphertext_list, shared_secret_byte)
        """
        ciphertexts = []
        bits = []
        
        for _ in range(8): # 重复8次以生成1字节
            # 1. 随机选择向量 r (m维, 0/1分量)
            r = [random.randint(0, 1) for _ in range(self.m)]
            
            # 2. 计算 u = A^T * r
            A_T = self.math.mat_transpose(pk['A'])
            u = self.math.mat_mul_vec(A_T, r, self.q)
            
            # 3. 生成 1 bit 随机共享秘密
            bit = random.randint(0, 1)
            bits.append(bit)
            
            # 4. 编码: v = b * r + bit * floor(q/2)
            b_dot_r = self.math.vec_dot(pk['b'], r, self.q)
            scale = self.q // 2
            encoded_val = (bit * scale) % self.q
            v = (b_dot_r + encoded_val) % self.q
            
            ciphertexts.append({'u': u, 'v': v})
            
        # 将 bits 转为 int byte
        secret_int = int("".join(str(x) for x in bits), 2)
        return ciphertexts, bytes([secret_int])

    def decapsulate(self, sk, ciphertexts):
        """
        解密出共享密钥。
        Msg ≈ v - s * u
        """
        bits = []
        for ct in ciphertexts:
            u = ct['u']
            v = ct['v']
            s = sk['s']
            
            # 计算 s * u
            s_dot_u = self.math.vec_dot(s, u, self.q)
            
            # 计算差值 diff = v - s*u
            # 注意模运算下的减法
            diff = (v - s_dot_u) % self.q
            
            # 解码: 判断 diff 离 0 近还是离 q/2 近
            center = self.q // 2
            # 距离 0 的距离
            dist_0 = min(diff, self.q - diff)
            # 距离 q/2 的距离
            dist_center = abs(diff - center)
            
            if dist_center < dist_0:
                bits.append(1)
            else:
                bits.append(0)
                
        secret_int = int("".join(str(x) for x in bits), 2)
        return bytes([secret_int])

    # --- KEM 序列化 ---
    def serialize_pk(self, pk):
        bytes_A = self.math.serialize_matrix(pk['A'])
        bytes_b = self.math.serialize_vector(pk['b'])
        return bytes_A + bytes_b

    def deserialize_pk(self, data):
        A, offset = self.math.deserialize_matrix(data)
        b, _ = self.math.deserialize_vector(data[offset:])
        return {'A': A, 'b': b}

    def serialize_ciphertexts(self, cts):
        buffer = bytearray()
        buffer.extend(struct.pack('>I', len(cts)))
        for ct in cts:
            u_bytes = self.math.serialize_vector(ct['u'])
            buffer.extend(u_bytes)
            buffer.extend(struct.pack('>H', ct['v']))
        return bytes(buffer)
    
    def deserialize_ciphertexts(self, data):
        offset = 0
        count = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        cts = []
        for _ in range(count):
            u, len_u = self.math.deserialize_vector(data[offset:])
            offset += len_u
            v = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            cts.append({'u': u, 'v': v})
        return cts

