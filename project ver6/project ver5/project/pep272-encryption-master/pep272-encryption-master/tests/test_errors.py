#!/usr/bin/env python3
"""
Test for the correct raise of errors.
"""
from pep272_encryption import PEP272Cipher
from pep272_encryption import \
     MODE_ECB, MODE_CBC, MODE_CFB, \
     MODE_PGP, MODE_CTR, MODE_OFB
from pep272_encryption.util import Counter

import unittest

TEST_KEY = b'\00' * 16
TEST_IV = b'\00' * 16
TEST_BLOCK = b'\00' * 16 * 3

MODES_WITH_IV = [MODE_CBC, MODE_CFB, MODE_OFB, MODE_PGP]
MODES_FREE_LENGTH = [MODE_OFB, MODE_CTR]
MODES_BLOCK_LENGTH = [MODE_ECB, MODE_CBC, MODE_CFB]


class DummyCipher(PEP272Cipher):
    block_size = 16

    def encrypt_block(self, key, block, **kwargs):
        return PEP272Cipher.encrypt_block(self, key, block, **kwargs)

    def decrypt_block(self, key, block, **kwargs):
        return PEP272Cipher.encrypt_block(self, key, block, **kwargs)


def cipher_object(mode, **kwargs):
    """Creates ONE working cipher object."""
    return (
        DummyCipher(TEST_KEY, mode, **kwargs)
        )


class AbcCannotInstantiated(unittest.TestCase):
    def test_instantiation(self):
        with self.assertRaises(TypeError):
            PEP272Cipher(b'\x00'*16, mode=MODE_ECB)


class NotImplementedTestCase(unittest.TestCase):
    def test_not_implemented_encryption(self):
        with self.assertRaises(NotImplementedError):
            cipher_object(mode=MODE_ECB).encrypt(TEST_BLOCK)

    def test_not_implemented_decryption(self):
        with self.assertRaises(NotImplementedError):
            cipher_object(mode=MODE_ECB).decrypt(TEST_BLOCK)


class IVTestCase(unittest.TestCase):
    def test_iv(self):
        for mode in MODES_WITH_IV:
            cipher_object(mode=mode, IV=TEST_IV)

    def test_no_iv_typeerror(self):
        for mode in MODES_WITH_IV:
            with self.assertRaises(TypeError):
                cipher_object(mode=mode)

    def test_iv_length(self):
        for mode in MODES_WITH_IV:
            allowed_iv_lengths = [DummyCipher.block_size]
            if mode == MODE_PGP:
                allowed_iv_lengths.append(DummyCipher.block_size + 2)
            for length in range(100):
                iv = b'\00'*length
                if length == 0:  # == not given
                    with self.assertRaises(TypeError) as context:
                        cipher_object(mode=mode, IV=iv)
                elif length not in allowed_iv_lengths:
                    with self.assertRaises(ValueError) as context:
                        cipher_object(mode=mode, IV=iv)
                    self.assertTrue('block_size' in str(context.exception))
                else:
                    cipher_object(mode=mode, IV=iv)

    def test_iv_without_caps(self):
        for mode in MODES_WITH_IV:
            cipher_object(mode=mode, iv=TEST_IV)


class CounterTestCase(unittest.TestCase):
    def test_counter_missing(self):
        with self.assertRaises(TypeError):
            cipher_object(mode=MODE_CTR)

    def test_counter_not_callable(self):
        with self.assertRaises(TypeError):
            cipher_object(mode=MODE_CTR, counter=b' '*16)

    def test_counter_correct(self):
        """Gives a 'correct' (but horribly insecure) counter. "
As no encrypt_block is defined, must raise NotImplementedError"""
        with self.assertRaises(NotImplementedError):
            cipher_object(mode=MODE_CTR, counter=lambda: b' '*16).encrypt(
                TEST_BLOCK)

    def test_counter_invalid_return_length(self):
        with self.assertRaises(TypeError):
            cipher_object(mode=MODE_CTR, counter=lambda: b' '*15).encrypt(
                TEST_BLOCK)


class InputLengthTestCase(unittest.TestCase):
    def test_valid_block_lengths_ecb(self):
        c = cipher_object(mode=MODE_ECB)
        for i in range(1, 100):
            with self.assertRaises(NotImplementedError):
                c.encrypt(b' '*i*c.block_size)
            with self.assertRaises(NotImplementedError):
                c.decrypt(b' '*i*c.block_size)

    def test_invalid_block_lengths_ecb(self):
        c = cipher_object(mode=MODE_ECB)
        for i in range(1, 100):
            if not i % c.block_size:
                continue
            with self.assertRaises(ValueError) as context:
                c.encrypt(b' '*i)
            self.assertTrue("block_size" in str(context.exception))
            with self.assertRaises(ValueError) as context:
                c.decrypt(b' '*i)
            self.assertTrue("block_size" in str(context.exception))

    def test_valid_block_lengths_cbc(self):
        c = cipher_object(mode=MODE_CBC, IV=TEST_IV)
        for i in range(1, 100):
            with self.assertRaises(NotImplementedError):
                c.encrypt(b' '*i*c.block_size)
            with self.assertRaises(NotImplementedError):
                c.decrypt(b' '*i*c.block_size)

    def test_invalid_block_lengths_cbc(self):
        c = cipher_object(mode=MODE_CBC, IV=TEST_IV)
        for i in range(1, 100):
            if not i % c.block_size:
                continue
            with self.assertRaises(ValueError) as context:
                c.encrypt(b' '*i)
            self.assertTrue("block_size" in str(context.exception))
            with self.assertRaises(ValueError) as context:
                c.decrypt(b' '*i)
            self.assertTrue("block_size" in str(context.exception))

    def test_valid_block_lengths_cfb(self):
        c = cipher_object(mode=MODE_CFB, IV=TEST_IV, segment_size=128)
        for i in range(1, 100):
            with self.assertRaises(NotImplementedError):
                c.encrypt(b' '*i*c.block_size)
            with self.assertRaises(NotImplementedError):
                c.decrypt(b' '*i*c.block_size)

    def test_invalid_block_lengths_cfb(self):
        c = cipher_object(mode=MODE_CFB, IV=TEST_IV, segment_size=128)
        for i in range(1, 100):
            if not i % c.block_size:
                continue
            with self.assertRaises(ValueError) as context:
                c.encrypt(b' '*i)
            self.assertTrue("block_size" in str(context.exception))
            with self.assertRaises(ValueError) as context:
                c.decrypt(b' '*i)
            self.assertTrue("block_size" in str(context.exception))

    def test_valid_segemt_size_cfb(self):
        for i in range(16):
            cipher_object(mode=MODE_CFB, IV=TEST_IV, segment_size=(1+i)*8)

    def test_invalid_segemt_size_cfb(self):
        for i in range(16):
            with self.assertRaises(TypeError) as context:
                cipher_object(mode=MODE_CFB, IV=TEST_IV, 
                              segment_size=(1+i)*8+1)

            errstr = str(context.exception)
            self.assertTrue("segment_size" in errstr and "multiple" in errstr)

            with self.assertRaises(TypeError) as context:
                cipher_object(mode=MODE_CFB, IV=TEST_IV, 
                              segment_size=(1+i)*8-1)

            errstr = str(context.exception)
            self.assertTrue("segment_size" in errstr and "multiple" in errstr)


    def test_zero_segemt_size_cfb(self):
        with self.assertRaises(TypeError) as context:
                cipher_object(mode=MODE_CFB, IV=TEST_IV, 
                              segment_size=None)

        self.assertTrue("missing" in str(context.exception))


    def test_arbitrary_keylength(self):
        for mode in MODES_FREE_LENGTH:
            for i in range(1, 100):
                kwargs = {'IV': TEST_IV, 'counter': lambda: b' '*16}
                c = cipher_object(mode=mode, **kwargs)
                with self.assertRaises(NotImplementedError):
                    c.encrypt(b' '*i)


class KeylengthTestCase(unittest.TestCase):
    def test_zero_keylength(self):
        with self.assertRaises(ValueError):
            DummyCipher(b'', MODE_ECB)

    def test_nonzero_keylength(self):
        DummyCipher(b' ', MODE_ECB)


class InvalidModeTestCase(unittest.TestCase):
    def test_invalid_mode_encryption(self):
        d = DummyCipher(b' ', mode=700)
        with self.assertRaises(ValueError) as context:
            d.encrypt(b' ')
        
        self.assertTrue("Unknown mode of operation" in str(context.exception))

    def test_invalid_mode_decryption(self):
        d = DummyCipher(b' ', mode=700)
        with self.assertRaises(ValueError) as context:
            d.decrypt(b' ')        

        self.assertTrue("Unknown mode of operation" in str(context.exception))


class ExceptionsInCounterTestCase(unittest.TestCase):
    def test_invalid_endian(self):
        with self.assertRaises(ValueError) as e:
            Counter(endian='bla')

        self.assertIn("Invalid endian", e.exception.args[0])

    def test_iv_nonce(self):
        with self.assertRaises(ValueError) as e:
            Counter(iv=b'123', nonce=b'123')

        self.assertIn("'iv' may not be used with", e.exception.args[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
