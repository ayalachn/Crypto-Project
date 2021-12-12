#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util import Counter
from pep272_encryption import PEP272Cipher


TEST_KEY = b'\00' * 16
TEST_IV = b'\00' * 16
TEST_BLOCK = b'\00' * 16 * 3


class FakeCounter:
    def __call__(self):
        return TEST_IV


class CipherClass(PEP272Cipher):
    block_size = 16

    def encrypt_block(self, key, block, **kwargs):
        return AES.new(key, AES.MODE_ECB).encrypt(block)

    def decrypt_block(self, key, block, **kwargs):
        return AES.new(key, AES.MODE_ECB).decrypt(block)


class Identity(PEP272Cipher):
    block_size = 16

    def encrypt_block(self, key, block, **kwargs):
        return block

    def decrypt_block(self, key, block, **kwargs):
        return block


def cipher_objects(mode, **kwargs):
    """Creates TWO working cipher object:
 - one from PyCrypto
 - one of own implementation."""
    return (
        AES.new(TEST_KEY, mode, **kwargs),
        CipherClass(TEST_KEY, mode, **kwargs)
        )


def test_ecb():
    reference, compare = cipher_objects(AES.MODE_ECB)
    assert reference.encrypt(TEST_BLOCK) == compare.encrypt(TEST_BLOCK)
    reference, compare = cipher_objects(AES.MODE_ECB)
    assert reference.decrypt(TEST_BLOCK) == compare.decrypt(TEST_BLOCK)


def test_cbc():
    reference, compare = cipher_objects(AES.MODE_CBC, IV=TEST_IV)
    assert reference.encrypt(TEST_BLOCK) == compare.encrypt(TEST_BLOCK)

    reference, compare = cipher_objects(AES.MODE_CBC, IV=TEST_IV)
    assert reference.decrypt(TEST_BLOCK) == compare.decrypt(TEST_BLOCK)


def test_cfb8():
    reference, compare = cipher_objects(AES.MODE_CFB, IV=TEST_IV,
                                        segment_size=8)
    assert reference.encrypt(TEST_BLOCK) == compare.encrypt(TEST_BLOCK)

    reference, compare = cipher_objects(AES.MODE_CFB, IV=TEST_IV,
                                        segment_size=8)
    assert reference.decrypt(TEST_BLOCK) == compare.decrypt(TEST_BLOCK)


def test_cfb128():
    reference, compare = cipher_objects(AES.MODE_CFB, IV=TEST_IV,
                                        segment_size=128)
    assert reference.encrypt(TEST_BLOCK) == compare.encrypt(TEST_BLOCK)

    reference, compare2 = cipher_objects(AES.MODE_CFB, IV=TEST_IV,
                                         segment_size=128)
    assert reference.decrypt(TEST_BLOCK) == compare2.decrypt(TEST_BLOCK)


def test_ofb():
    reference, compare = cipher_objects(AES.MODE_OFB, IV=TEST_IV)
    assert reference.encrypt(TEST_BLOCK) == compare.encrypt(TEST_BLOCK)

    reference, compare = cipher_objects(AES.MODE_OFB, IV=TEST_IV)
    assert reference.decrypt(TEST_BLOCK) == compare.decrypt(TEST_BLOCK)


def test_ctr():
    # Unfortunately PyCryptome is not PEP compliant anymore.
    nullcipher = Identity(TEST_KEY, AES.MODE_CTR, counter=FakeCounter())
    assert nullcipher.encrypt(TEST_BLOCK) == FakeCounter()()*3

    reference, _ = cipher_objects(AES.MODE_CTR, counter=Counter.new(128))
    _, compare = cipher_objects(AES.MODE_CTR, counter=Counter.new(128))

    assert reference.encrypt(TEST_BLOCK) == compare.encrypt(TEST_BLOCK)
    assert reference.encrypt(TEST_BLOCK) == compare.encrypt(TEST_BLOCK)
    

if __name__ == "__main__":
    for i in ("ecb", "cbc", "cfb8", "cfb128", "ofb", "ctr"):
        print(i)
        exec("test_{}()".format(i))
