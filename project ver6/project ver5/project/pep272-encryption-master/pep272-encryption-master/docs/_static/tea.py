import struct

from pep272_encryption import PEP272Cipher
from pep272_encryption import MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, \
                              MODE_CTR

block_size = 8  # 64-bit blocks
key_size = 16   # 128-bit keys


def new(*args, **kwargs):
    return TEACipher(*args, **kwargs)


class TEACipher(PEP272Cipher):
    block_size = block_size

    def encrypt_block(self, key, block, **kwargs):
        return encrypt_tea(block, key, 
                           kwargs.get('endian', '!'), 
                           kwargs.get('rounds', 64))

    def decrypt_block(self, key, block, **kwargs):
        return decrypt_tea(block, key, 
                           kwargs.get('endian', '!'), 
                           kwargs.get('rounds', 64))


def encrypt_tea(value, key, endian="!", rounds=64):
    v0, v1 = struct.unpack(endian + "2L", value)
    k = struct.unpack(endian + "4L", key)

    # mask is an uint32 helper
    delta, mask, sum = 0x9e3779b9, 0xffffffff, 0

    for i in range(rounds//2):
        sum = (sum + delta) & mask
        v0 = v0 + ( ((v1<<4) + k[0]) ^ (v1 + sum) ^ ((v1>>5) + k[1]) ) & mask
        v1 = v1 + ( ((v0<<4) + k[2]) ^ (v0 + sum) ^ ((v0>>5) + k[3]) ) & mask

    return struct.pack(endian + "2L", v0, v1)


def decrypt_tea(value, key, endian="!", rounds=64):
    v0, v1 = struct.unpack(endian + "2L", value)
    k = struct.unpack(endian + "4L", key)

    # mask is an uint32 helper
    delta, mask = 0x9e3779b9, 0xffffffff
    sum = (delta * rounds // 2) & mask

    for i in range(rounds//2):
        v1 = v1 - ( ((v0<<4) + k[2]) ^ (v0 + sum) ^ ((v0>>5) + k[3]) ) & mask
        v0 = v0 - ( ((v1<<4) + k[0]) ^ (v1 + sum) ^ ((v1>>5) + k[1]) ) & mask
        sum = (sum - delta) & mask

    return struct.pack(endian + "2L", v0, v1)
