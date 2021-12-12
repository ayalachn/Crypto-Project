"""
Utility library for compatibility with Python 2 and 3.
A counter to use with CTR is also included.

There are versions of ``chr`` and ``ord``-methods to work with bytes
with Python 3 and strings with Python 2.

"""

import codecs
import os
import sys

try:
    from ._fast_xor import fast_xor
except ImportError:
    fast_xor = None

PY_3 = sys.version_info.major >= 3

_endian_dict = {
    "little": "little",
    "<": "little",
    "big": "big",
    ">": "big",
    "!": "big"
}


if PY_3:

    def b_chr(ordinal):
        """Return a byte string of one character with 0 <= ordinal <= 255.

        :param int ordinal: The Unicode code point of a single char
        :return: The byte string representation of the ordinal
        :rtype: bytes"""
        return bytes([ordinal])


    def to_bytes(integer, length, byteorder):
        """Convert an integer to a bytestring.

        :param int integer: The integer to convert.
        :param int length: Length of the created byte string.
        :param str byteorder: either 'big' or 'little'.
        :rtype: bytes"""
        return integer.to_bytes(length, byteorder)


    def from_bytes(bytestring, byteorder):
        """Convert a bytestring to an interger.

        :param bytes bytestring: The byte string to convert.
        :param str byteorder: either 'big' or 'little'
        :rtype: int"""
        return int.from_bytes(bytestring, byteorder)

else:

    def b_chr(ordinal):
        """Return a byte string of one character with 0 <= ordinal <= 255.

        :param int ordinal: The Unicode code point of a single char
        :return: The byte string representation of the ordinal
        :rtype: bytes"""
        return chr(ordinal)


    def to_bytes(integer, length, byteorder):
        """Convert an integer to a bytestring.

        :param int integer: The integer to convert.
        :param int length: Length of the created byte string.
        :param str byteorder: either 'big' or 'little'.
        :rtype: bytes"""
        hex_encoded = (b'%x' % integer)
        hex_padded = (
            b'0' + hex_encoded if len(hex_encoded) % 2
            else hex_encoded
        )
        bytes_short = codecs.decode(hex_padded, 'hex')
        padded = bytes_short.rjust(length, b'\x00')

        if byteorder == 'little':
            padded = padded[::-1]

        return padded


    def from_bytes(bytestring, byteorder):
        """Convert a bytestring to an interger.

        :param bytes bytestring: The byte string to convert.
        :param str byteorder: either 'big' or 'little'
        :rtype: int"""
        if byteorder == 'little':
            bytestring = bytestring[::-1]
        return int(codecs.encode(bytestring, "hex"), 16)


def b_ord(byte):
    """Return the Unicode code point for a byte or iteration product \
of a byte string alike object (e.g. bytearray).

    :param byte: The single byte or iteration product of a byte string to \
convert
    :type byte: bytes or str or int
    :return: Unicode code point
    :rtype: int"""
    return byte if isinstance(byte, int) else ord(byte)


def xor_strings(one, two):
    """xor two bytestrings together.

    :param bytes one: First string
    :param bytes two: Second string
    :return: The xored strings
    :rtype: bytes
    """

    if fast_xor is not None:
        return fast_xor(one, two)

    one, two = bytearray(one), bytearray(two)
    return bytes(bytearray(x ^ y for x, y in zip(one, two)))


def split_blocks(bytestring, block_size):
    """Splits bytestring in block_size-sized blocks.

    Raises an error if len(string) % blocksize != 0.
    """
    if block_size == 1:
        return map(b_chr, bytearray(bytestring))

    rest_size = len(bytestring) % block_size

    if rest_size:
        raise ValueError("Input 'bytestring' must be a multiple of "
                         "block_size / segment_size (CFB mode) in length")

    block_count = len(bytestring) // block_size

    return (
        bytestring[i * block_size:((i + 1) * block_size)]
        for i in range(block_count))


class Counter:
    r"""Counter for usage in CTR mode.

    Big endian is as assumed for all counter operations by default.

    :param bytes nonce: Prefix for counter operations.
    :param int initial_value: Initial integer value.
    :param bytes suffix: Suffix to add after output.
    :param bytes iv: Counter output to resume.
        The usage of `iv` prohibits the use of
        `nonce`, `initial_value`, `block_size` and
        `suffix`.
    :param bytes IV: Alternative for `iv`.
    :param int block_size: Size of counter in-/output
    :param str endian: Endian for number/byte conversions.
    :param bool wrap_around: If an exception should not be raised
        if the counter returns the same value twice.
        For security reasons, setting this value to true is
        not recommended.

    The counter is not thread safe.

    Without arguments, it generates a random nonce,
    with the counter starts at 0:

        >>> c = Counter()  # random nonce
        >>> c().endswith(b"\x00")
        True
        >>> c().endswith(b"\x01")
        True
        >>> c().endswith(b"\x02")
        True

    Alternatively, a nonce and an initial value can be set:

        >>> c = Counter(nonce=b'\x00\x01\x02', initial_value=0xff01,
        ...                   block_size=8)
        >>> c()
        b'\x00\x01\x02\x00\x00\x00\xff\x01'
        >>> c()
        b'\x00\x01\x02\x00\x00\x00\xff\x02'

    The third alternative is to give a full start string.
    Counter length is determined by the IV length:

        >>> c = Counter(IV=b'\x00'*4, endian="little")
        >>> c()
        b'\x00\x00\x00\x00'
        >>> c()
        b'\x01\x00\x00\x00'
    """
    block_size = 16  #: Used by many algorithms

    def __init__(self, nonce=None, initial_value=0, suffix=None,
                 iv=None, IV=None, block_size=None, endian="big",
                 wrap_around=False):
        try:
            self.endian = _endian_dict[endian.lower()]
        except KeyError:
            raise ValueError(
                "Invalid endian specified, possible values are either "
                "big ('big', '>', '!') or little ('little', '<')"
                "endian!")

        self.block_size = block_size or self.block_size
        self.value = initial_value
        self.wrap_around = wrap_around

        iv = iv or IV

        if iv is not None:
            if (
                initial_value != 0 or
                nonce is not None or
                suffix is not None or
                block_size is not None
            ):
                raise ValueError("'iv' may not be used with nonce, "
                                 "initial_value, suffix or block_size!")

            self.block_size = len(iv)
            self.nonce = b""
            self.suffix = b""
            initial_value = from_bytes(iv, self.endian)

        else:
            if nonce is None:  # Like Pycryptodome
                nonce = os.urandom(self.block_size // 2)

            self.nonce = nonce

            if suffix is None:
                suffix = b""

            self.suffix = suffix

        self.initial_value = self.value = initial_value
        self.__first = True

    def __call__(self):
        """Increase the counter by 1."""
        if (
                not self.__first and
                self.value == self.initial_value
                and not self.wrap_around
        ):
            raise ValueError("Counter overflow detected.")

        value_bytes = (
                self.block_size -
                len(self.nonce) -
                len(self.suffix)
        )

        self.__first = False
        out = self.nonce
        out += to_bytes(self.value,
                        value_bytes,
                        self.endian)
        out += self.suffix

        self.value += 1
        self.value &= 2**(8*value_bytes)-1

        return out


if __name__ == "__main__":
    # Doctests are here for faster development.
    # They run additionally to normal tests.
    import doctest
    doctest.testmod()
