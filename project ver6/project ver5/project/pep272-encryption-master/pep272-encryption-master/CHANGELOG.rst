Changelog
=========

0.4
---

New
***

- Type hints
- Build manylinux wheels, universal wheel is limited to Python 2 and PyPy
- In addition to callables, the *counter* argument for CTR mode now accepts counters from PyCryptodome now

Changed
*******

- Extension module is in pure C, instead of being written in Cython
- *__init__* signature is slightly different: *IV* can be given as a positional argument
- ``PEP272Cipher.IV`` does change again when using one of CBC, CFB or OFB modes.
  This behaviour is PEP-272 compliant (" After encrypting or decrypting a string, this value is updated to reflect
  the modified feedback text."), including it being read-only now ("It is read-only, and cannot be assigned a new
  value.")

0.3 - 2019-06-14
----------------

Added
*****

- ``PEP272Cipher`` is a new style class on Python 2.
- Documentation
- Optional extensions module for more speed. CBC and CFB are now two times faster!

Changed
*******

- ``PEP272Cipher.IV`` does not change in mode using a CBC

0.1 - 2019-03-03
----------------

- Initial release.
