#!/usr/bin/env python3

import doctest
from pep272_encryption import util


def test_length():
    for i in range(1, 65):
        c = util.Counter(block_size=i)
        for j in range(32):
            assert len(c()) == i


def test_presence_nonce_suffix():
    c = util.Counter(b'N', 0, b'S', block_size=16)
    assert c() == b'N' + b'\x00' * 14 + b'S'
    assert c() == b'N' + b'\x00' * 13 + b'\x01' + b'S'
    assert c() == b'N' + b'\x00' * 13 + b'\x02' + b'S'
    assert c() == b'N' + b'\x00' * 13 + b'\x03' + b'S'
    assert c() == b'N' + b'\x00' * 13 + b'\x04' + b'S'
    assert c() == b'N' + b'\x00' * 13 + b'\x05' + b'S'


def test_doctest_0():
    c = util.Counter()  # random nonce
    assert c().endswith(b"\x00")
    assert c().endswith(b"\x01")
    assert c().endswith(b"\x02")


def test_doctest_1():
    c = util.Counter(nonce=b'\x00\x01\x02', initial_value=0xff01,
                     block_size=8)
    assert c() == b'\x00\x01\x02\x00\x00\x00\xff\x01'
    assert c() == b'\x00\x01\x02\x00\x00\x00\xff\x02'


def test_doctest_2():
    c = util.Counter(IV=b'\x00' * 4, endian="little")
    assert c() == b'\x00\x00\x00\x00'
    assert c() == b'\x01\x00\x00\x00'