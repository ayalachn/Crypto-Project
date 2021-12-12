.. _example:

Examples
--------

.. note::
   This library is for creation of *block cipher interfaces* only!
   It does not contain or implement any ciphers by itself.

Implementing a block cipher
+++++++++++++++++++++++++++

0. The TEA block cipher
***********************

In this example, a PEP-272 interface for the TEA block cipher is created.
TEA uses 128-bit (16 bytes) keys and 64-bit (8 bytes) blocks.

Below is an simple implementation of TEA:

::

    import struct

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

1. Constant definition
**********************

Import the pep272-encryption module and set module level constants, as defined per PEP-272:

::

   from pep272_encryption import PEP272Cipher, MODE_ECB, MODE_CBC, \
                                               MODE_CFB, MODE_OFB, \
                                               MODE_CTR

   block_size = 8  # 64-bit blocks
   key_size = 16   # 128-bit keys

2. The TEACipher class
**********************

Subclass the PEP272Cipher class, setting the block size parameter and
override `encrypt_block` and `decrypt_block` methods:

::

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


   def new(*args, **kwargs):
       return TEACipher(*args, **kwargs)

You successfully have written a PEP 272 interface for TEA.

3. Complete example
*******************

Below is the full example code of all snippets combined: A PEP-272 compliant
implementation of the TEA block cipher in pure python, that is interchangeable
with other ciphers.

.. literalinclude:: _static/tea.py
   :linenos:

This library can then be used easily:

::

   >>> import tea
   >>> cipher = tea.new(b'16-bytes key 123', mode=tea.MODE_OFB, IV=b'\00'*8)
   >>> cipher.encrypt(b'123456'*6)
   b"k\xaf F\xfb*\xeb\x00'kP\x9c\xc9M\xb99\x1cy\xda\x99\xb1\xf0H\x14\x9c\xae@\xddxe`\x01\x85\xc9p\x85"


Implementing a custom mode of operation
+++++++++++++++++++++++++++++++++++++++

In this example a "xor-encrypt-xor" mode is implemented.
It takes two additional keys, that are XORed with the plain- and ciphertext.
Otherwise it works like ECB.

The mode of operation is passed to the object's constructor.
In this example *500* is assigned to the `MODE_XEX` constant.

``PEP272Cipher`` is subclassed with the parameters `key1` and `key2`:


.. literalinclude:: _static/xex.py
   :linenos:

Implementing a stream cipher
++++++++++++++++++++++++++++

While the PEP272 Interface and this library is designed for block ciphers,
it may also be used for implementing stream ciphers.

Below is an implementation of the RC4 cipher.


.. literalinclude:: _static/rc4.py
   :linenos: