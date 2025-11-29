import random
import struct

class MatrixMath:
    """
    [ALGORITHM CORE]
    自定义矩阵与向量运算库。
    用于支撑上层格密码算法，不依赖 numpy 以展示算法实现细节。
    """

    @staticmethod
    def new_vector(size, default_val=0):
        return [default_val] * size

    @staticmethod
    def new_matrix(rows, cols, default_val=0):
        return [[default_val for _ in range(cols)] for _ in range(rows)]

    @staticmethod
    def gen_uniform_vector(size, modulus):
        """生成均匀分布的随机向量"""
        return [random.randint(0, modulus - 1) for _ in range(size)]

    @staticmethod
    def gen_uniform_matrix(rows, cols, modulus):
        """生成均匀分布的随机矩阵"""
        return [[random.randint(0, modulus - 1) for _ in range(cols)] for _ in range(rows)]

    @staticmethod
    def gen_error_vector(size, modulus, bound=1):
        """生成小误差向量 (中心二项分布或高斯分布的离散近似)"""
        # 简单的在 [-bound, bound] 之间取值
        return [random.randint(-bound, bound) % modulus for _ in range(size)]

    @staticmethod
    def vec_add(v1, v2, modulus):
        if len(v1) != len(v2):
            raise ValueError("Vector dimension mismatch in add")
        return [(x + y) % modulus for x, y in zip(v1, v2)]

    @staticmethod
    def vec_sub(v1, v2, modulus):
        if len(v1) != len(v2):
            raise ValueError("Vector dimension mismatch in sub")
        return [(x - y) % modulus for x, y in zip(v1, v2)]

    @staticmethod
    def vec_dot(v1, v2, modulus):
        """向量点积"""
        if len(v1) != len(v2):
            raise ValueError("Vector dimension mismatch in dot")
        res = 0
        for i in range(len(v1)):
            res = (res + v1[i] * v2[i]) % modulus
        return res

    @staticmethod
    def vec_scalar_mul(scalar, v, modulus):
        return [(scalar * x) % modulus for x in v]

    @staticmethod
    def mat_mul_vec(matrix, vector, modulus):
        """矩阵乘向量: res = A * v"""
        rows = len(matrix)
        cols = len(matrix[0])
        if len(vector) != cols:
            raise ValueError(f"Dimension mismatch: Matrix {rows}x{cols} vs Vector {len(vector)}")
        
        result = []
        for i in range(rows):
            val = MatrixMath.vec_dot(matrix[i], vector, modulus)
            result.append(val)
        return result

    @staticmethod
    def mat_transpose(matrix):
        """矩阵转置"""
        rows = len(matrix)
        cols = len(matrix[0])
        new_mat = MatrixMath.new_matrix(cols, rows)
        for i in range(rows):
            for j in range(cols):
                new_mat[j][i] = matrix[i][j]
        return new_mat

    # --- 序列化辅助函数 ---
    
    @staticmethod
    def serialize_vector(v):
        """
        将向量序列化为字节流。
        为了演示方便，假设每个元素不超过 2字节 (uint16)。
        """
        buffer = bytearray()
        buffer.extend(struct.pack('>I', len(v))) # 长度
        for val in v:
            buffer.extend(struct.pack('>H', val))
        return bytes(buffer)

    @staticmethod
    def deserialize_vector(data):
        offset = 0
        length = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        v = []
        for _ in range(length):
            val = struct.unpack('>H', data[offset:offset+2])[0]
            v.append(val)
            offset += 2
        return v, offset

    @staticmethod
    def serialize_matrix(m):
        buffer = bytearray()
        rows = len(m)
        cols = len(m[0]) if rows > 0 else 0
        buffer.extend(struct.pack('>II', rows, cols))
        for row in m:
            for val in row:
                buffer.extend(struct.pack('>H', val))
        return bytes(buffer)

    @staticmethod
    def deserialize_matrix(data):
        offset = 0
        rows, cols = struct.unpack('>II', data[offset:offset+8])
        offset += 8
        matrix = []
        for _ in range(rows):
            row = []
            for _ in range(cols):
                val = struct.unpack('>H', data[offset:offset+2])[0]
                row.append(val)
                offset += 2
            matrix.append(row)
        return matrix, offset
