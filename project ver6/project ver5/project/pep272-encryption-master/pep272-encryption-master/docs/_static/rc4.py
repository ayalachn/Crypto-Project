from pep272_encryption import PEP272Cipher, MODE_ECB

block_size = 1
key_size = 0


def new(*args, **kwargs):
    return RC4Cipher(*args, **kwargs)


class RC4Cipher(PEP272Cipher):
    block_size = 1
    key_size = 0

    def __init__(self, key, mode=MODE_ECB, **kwargs):
        if mode != MODE_ECB:
            raise ValueError("Stream ciphers only support ECB mode")

        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

        self.i = self.j = 0

        PEP272Cipher.__init__(self, key, mode, **kwargs)

    def encrypt_block(self, key, block, **kwargs):
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]

        K = self.S[(self.S[self.i] + self.S[self.j]) % 256]
        return bytes([block[0] ^ K])

    def decrypt_block(self, key, block, **kwargs):
        return self.encrypt_block(key, block, **kwargs)


assert RC4Cipher(b'\x01\x02\x03\x04\x05').encrypt(b'\x00'*16) \
       == b"\xb29c\x05\xf0=\xc0'\xcc\xc3RJ\n\x11\x18\xa8"
