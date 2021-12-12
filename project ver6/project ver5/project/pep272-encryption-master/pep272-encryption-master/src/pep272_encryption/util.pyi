from typing import ByteString, Callable, Iterable, Union

Buffer = Union[bytes, bytearray, memoryview]

fast_xor: Union[None, Callable[[Buffer, Buffer], bytes]]


def b_chr(ordinal: int) -> bytes:
    ...

def b_ord(byte: Union[bytes, int]) -> int:
    ...

def from_bytes(bytestring: ByteString, byteorder: str) -> int:
    ...

def to_bytes(integer: int, length: int, byteorder: str) -> bytes:
    ...

def xor_strings(one: ByteString, two: ByteString) -> bytes:
    ...

def split_blocks(bytestring: ByteString, block_size: int) -> Iterable[bytes]:
    ...


class Counter:
    block_size: int
    value: int
    initial_value: int

    wrap_around: bool

    prefix: ByteString
    nonce: ByteString
    suffix: ByteString

    endian: str

    def __init__(self, nonce: ByteString=None, initial_value: int=0,
                 suffix: ByteString=None, iv: ByteString=None,
                 IV: ByteString=None, block_size: int=None,
                 endian: str="big",
                 wrap_around: bool=False):
        ...

    def __call__(self) -> bytes:
        ...