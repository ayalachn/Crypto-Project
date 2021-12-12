from abc import ABC

from pep272_encryption import PEP272Cipher
from pep272_encryption.util import split_blocks, xor_strings

MODE_XEX = 500


class XEXCipher(ABC, PEP272Cipher):
    def __init__(self, key, mode, **kwargs):
        self.key1 = kwargs.pop("key1", b'\x00' * self.block_size)
        self.key2 = kwargs.pop("key2", b'\x00' * self.block_size)

        PEP272Cipher.__init__(self, key, mode, **kwargs)

    def encrypt(self, string):
        if self.mode == MODE_XEX:
            out = []
            for block in split_blocks(string, self.block_size):
                inner = xor_strings(block, self.key1)
                encrypted = self.encrypt_block(self.key, inner, **self.kwargs)
                outer = xor_strings(encrypted, self.key2)
                out.append(outer)
            return b"".join(out)
        else:
            PEP272Cipher.encrypt(self, string)

    def decrypt(self, string):
        if self.mode == MODE_XEX:
            out = []
            for block in split_blocks(string, self.block_size):
                encrypted = xor_strings(block, self.key2)
                inner = self.decrypt_block(self.key, encrypted, **self.kwargs)
                plain = xor_strings(inner, self.key1)
                out.append(plain)
            return b"".join(out)
        else:
            PEP272Cipher.decrypt(self, string)
