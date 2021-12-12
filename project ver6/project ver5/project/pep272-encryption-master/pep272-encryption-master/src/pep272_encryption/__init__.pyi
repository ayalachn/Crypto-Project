from abc import abstractmethod
from typing import Any, ByteString, Callable, Generator, Mapping, Optional, \
    Union

from abc import ABC

MODE_ECB: int
MODE_CBC: int
MODE_CFB: int
MODE_PGP: int
MODE_OFB: int
MODE_CTR: int


class PEP272Cipher(ABC):
    block_size: int

    IV: Union[None, ByteString]

    key: Any
    kwargs: Mapping[str, Any]
    mode: int
    segment_size: int

    _counter: Callable[[], ByteString]
    _status: ByteString
    _keystream: Optional[Generator[int, None, None]]

    def __init__(self, key: Any, mode: int, IV: ByteString = None, *,
                 counter: Union[Callable[[], ByteString], Mapping] = None,
                 segment_size: int = 0,
                 **kwargs):
        ...

    def _check_iv(self) -> None:
        ...

    def _check_segment_size(self) -> None:
        ...

    def _check_counter(self) -> None:
        ...

    def _check_arguments(self) -> None:
        ...

    def _create_keystream(self) -> Optional[Generator[int, None, None]]:
        ...

    def _encrypt_with_keystream(self, data: ByteString) -> bytes:
        ...

    def _encrypt_cfb(self, data: ByteString, decrypt: bool=...) -> bytes:
        ...

    def encrypt(self, string: ByteString) -> bytes:
        ...

    def decrypt(self, string: ByteString) -> bytes:
        ...

    @abstractmethod
    def encrypt_block(self, key, block: ByteString, **kwargs) -> ByteString:
        ...

    @abstractmethod
    def decrypt_block(self, key, block: ByteString, **kwargs) -> ByteString:
        ...