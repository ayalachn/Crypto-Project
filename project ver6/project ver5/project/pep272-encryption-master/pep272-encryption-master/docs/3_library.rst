.. _library:

Library reference
=================

.. automodule:: pep272_encryption

The PEP272Cipher class
--------------------------

Subclass and overwrite the PEP272Cipher.encrypt_block and 
PEP272Cipher.decrypt_block methods and the block_size attribute.

.. autoclass:: pep272_encryption.PEP272Cipher
   :members:

.. _api-modes:

Block cipher mode of operation
------------------------------

.. note::
    For mote details about different modes of operation,
    see Discussions/:ref:`discussion-modes`.

.. _PEP-272: https://www.python.org/dev/peps/pep-0272/

Block ciphers can be used in different modes of operation.
The mode of operation can be set by passing one of the constants
to the cipher object. Different modes of operation may require to pass extra
arguments to the constructor.

Below is an example from the mostly PEP-272_ compliant  PyCryptodome__.

.. _PyCrypto: https://www.dlitz.net/software/pycrypto/
__ https://www.pycryptodome.org/

::

   >>> from Crypto.Cipher import AES
   >>> iv = b'random 16 bytes!'
   >>> key = b'0123456789abcdef'
   >>> cipher = AES.new(key, mode=AES.MODE_CBC, IV=iv)
   >>> cipher.encrypt(b'\00'*16)
   b'j\xa2\xb5\x80\xf7\xbd\xb4I\xda\xea\x9aN\x9d\xb5\x9a\x17'


This library supports following modes of operation:

 - Electronic code book (ECB)
 - Cipher Block Chaining (CBC)
 - Cipher Feedback (CFB)
 - Output Feedback (OFB)
 - Counter (CTR)

The CFB variant of PGP is not supported.

Planned modes are (extending to PEP-272_):

 - Propagating Cipher Block Chaining (PCBC), used in older Kerberos versions
 - Infinite Garble Extension (IGE), used by Telegram.
 - OpenPGP mode, compatible to PyCrypto_ or PyCryptodome_.

`Authenticated encryption (AE) or authenticated encryption with associated data (AEAD)`_
are currently not supported, as they would require additional methods to finalize
the encryption and sometimes have special requirements.

.. _Authenticated encryption (AE) or authenticated encryption with associated data (AEAD): https://en.wikipedia.org/wiki/Authenticated_encryption


+------------------+--------+-------------------------+-------------+------------------------------+
| Constant         | Number | Source                  | Implemented | Specification                |
+==================+========+=========================+=============+==============================+
| ``MODE_ECB``     | 1      | PEP-272_                | Yes         | NIST.SP.800-38A_             |
+------------------+--------+-------------------------+-------------+------------------------------+
| ``MODE_CBC``     | 2      | PEP-272_                | Yes         | NIST.SP.800-38A_             |
+------------------+--------+-------------------------+-------------+------------------------------+
| ``MODE_CFB``     | 3      | PEP-272_                | Yes         | NIST.SP.800-38A_             |
+------------------+--------+-------------------------+-------------+------------------------------+
| ``MODE_PGP``     | 4      | PEP-272_                | No          | `RFC 4880`_                  |
+------------------+--------+-------------------------+-------------+------------------------------+
| ``MODE_OFB``     | 5      | PEP-272_                | Yes         | NIST.SP.800-38A_             |
+------------------+--------+-------------------------+-------------+------------------------------+
| ``MODE_CTR``     | 6      | PEP-272_                | Yes         | NIST.SP.800-38A_             |
+------------------+--------+-------------------------+-------------+------------------------------+
| ``MODE_OPENPGP`` | 7      | PyCrypto__              | No          | `RFC 4880`_                  |
+------------------+--------+-------------------------+-------------+------------------------------+
| ``MODE_XTS``     | **8**  | PyCryptoPlus_           | No          | `IEEE P1619`_ and            |
|                  |        |                         |             | NIST.SP.800-38E_             |
+------------------+--------+-------------------------+-------------+------------------------------+
| ``MODE_CCM``     | **8**  | PyCrypto (unreleased) / | No          | NIST.SP.800-38C_             |
|                  |        | PyCryptodome_           |             |                              |
+------------------+--------+-------------------------+-------------+------------------------------+
| ``MODE_EAX``     | 9      | PyCrypto (unreleased) / | No          | `The EAX Mode of Operation`_ |
|                  |        | PyCryptodome_           |             |                              |
+------------------+--------+-------------------------+-------------+------------------------------+
| ``MODE_SIV``     | 10     | PyCrypto (unreleased) / | No          | `RFC 5297`_                  |
|                  |        | PyCryptodome_           |             |                              |
+------------------+--------+-------------------------+-------------+------------------------------+
| ``MODE_GCM``     | 11     | PyCrypto (unreleased) / | No          | NIST.SP.800-38D_             |
|                  |        | PyCryptodome_           |             |                              |
+------------------+--------+-------------------------+-------------+------------------------------+
| ``MODE_OCB``     | 12     | PyCrypto (unreleased) / | No          | `RFC 7253`_                  |
|                  |        | PyCryptodome_           |             |                              |
+------------------+--------+-------------------------+-------------+------------------------------+

.. _The EAX Mode of Operation: https://web.cs.ucdavis.edu/~rogaway/papers/eax.html
.. _IEEE P1619: http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf
.. _NIST.SP.800-38A: https://doi.org/10.6028/NIST.SP.800-38A
.. _NIST.SP.800-38C: https://doi.org/10.6028/NIST.SP.800-38C
.. _NIST.SP.800-38D: https://doi.org/10.6028/NIST.SP.800-38D
.. _NIST.SP.800-38E: https://doi.org/10.6028/NIST.SP.800-38E
.. _RFC 4880: https://tools.ietf.org/html/rfc4880#section-13.9
.. _RFC 5297: https://tools.ietf.org/html/rfc5297
.. _RFC 7253: https://tools.ietf.org/html/rfc7253
.. _PyCryptodome: https://www.pycryptodome.org/en/latest/src/cipher/modern.html#
.. _PyCryptoPlus: https://github.com/doegox/python-cryptoplus/blob/a5a1f8aecce4ddf476b2d80b586822d9e91eeb7d/src/CryptoPlus/Cipher/blockcipher.py#L31
__ https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.blockalgo-module.html#MODE_OPENPGP


Utility functions
-----------------

.. automodule:: pep272_encryption.util
   :members:
