#!/usr/bin/env python3

from pep272_encryption import util


def test_from_bytes_little():
    assert util.from_bytes(b'\x01\x02\x03', 'little') == 0x030201
    assert util.from_bytes(b'\x03\x02\x01', 'little') == 0x010203

    assert util.from_bytes(b'\x00\x00\x00', 'little') == 0


def test_from_bytes_big():
    assert util.from_bytes(b'\x01\x02\x03', 'big') == 0x010203
    assert util.from_bytes(b'\x03\x02\x01', 'big') == 0x030201

    assert util.from_bytes(b'\x00\x00\x00', 'big') == 0


def test_to_bytes_little():
    assert util.to_bytes(0x010203, 3, 'little') == b'\x03\x02\x01'
    assert util.to_bytes(0x010203, 5, 'little') == b'\x03\x02\x01\x00\x00'

    assert util.to_bytes(0x030201, 3, 'little') == b'\x01\x02\x03'
    assert util.to_bytes(0x030201, 5, 'little') == b'\x01\x02\x03\x00\x00'

    assert util.to_bytes(0, 5, 'little') == b'\x00'*5


def test_to_bytes_big():
    assert util.to_bytes(0x010203, 3, 'big') == b'\x01\x02\x03'
    assert util.to_bytes(0x010203, 5, 'big') == b'\x00\x00\x01\x02\x03'

    assert util.to_bytes(0x030201, 3, 'big') == b'\x03\x02\x01'
    assert util.to_bytes(0x030201, 5, 'big') == b'\x00\x00\x03\x02\x01'

    assert util.to_bytes(0, 5, 'little') == b'\x00' * 5
