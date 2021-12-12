"""
Installation script of pep272-encryption.
Usage (pip):
    pip install .
Usage (direct):
    setup.py build  # "Build" + Checkup
    setup.py install  # Installation
"""

from setuptools import setup, Extension

from distutils.errors import (
    CCompilerError,
    DistutilsExecError,
    DistutilsPlatformError
)

import re
import platform
import sys
import traceback

EXCLUDE_EXTENSION_FLAG = '--exclude-extension'
BUILD_EXTENSION = not any((
    platform.python_implementation() != "CPython",
    sys.version_info[0] < 3,
    (sys.platform == 'win32'
        and sys.version_info[0] == 3
        and sys.version_info[1] == 4),
    'test' in sys.argv[1:],
    'develop' in sys.argv[1:],
    EXCLUDE_EXTENSION_FLAG in sys.argv
))

if EXCLUDE_EXTENSION_FLAG in sys.argv:
    sys.argv.pop(sys.argv.index(EXCLUDE_EXTENSION_FLAG))


def get_file(name):
    try:
        with open(name) as f:
            return f.read()
    except IOError:  # OSError on Py3
        return ''


META_FILE = get_file("src/pep272_encryption/version.py")


def find_meta(meta):
    """
    Extract __*meta*__ from META_FILE.

    Source: https://github.com/python-attrs/attrs/blob/master/setup.py#L73
    """
    meta_match = re.search(
        r"^__{meta}__ = ['\"]([^'\"]*)['\"]".format(meta=meta), META_FILE, re.M
    )
    if meta_match:
        return meta_match.group(1)

    raise RuntimeError("Unable to find __{meta}__ string.".format(meta=meta))


with open('README.rst') as description_file:
    long_description = description_file.read()


args = dict(
    name='pep272-encryption',
    version=find_meta('version'),
    author=find_meta('author'),
    author_email=find_meta('email'),
    license=find_meta('license'),
    url=find_meta('url'),
    platforms='any',

    description='Library for easy creation of PEP-272 cipher classes',
    long_description=long_description,

    project_urls={
        'Documentation': 'https://pep272-encryption.readthedocs.org',
        'Source': 'https://github.com/Varbin/pep272-encryption',
        'Tracker': 'https://github.com/Varbin/pep272-encryption/issues'
    },

    packages=['pep272_encryption'],
    package_dir={'': 'src'},
    package_data={
        "": ["py.typed", "*.pyi"],
    },

    classifiers=[
        'License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries',
        'Typing :: Typed'
    ],
    setup_requires=['pytest-runner'],
    tests_require=['pytest', 'pycryptodome'],
    python_requires='>=2.7,!=3.0.*,!=3.1.*,!=3.2.*',
)


if BUILD_EXTENSION:
    n_args = args.copy()
    n_args["ext_modules"] = [
        Extension('pep272_encryption._fast_xor',
                  sources=['src/pep272_encryption/fast_xor.c'],
                  optional=True,
                  py_limited_api=True)
    ]

    try:
        setup(**n_args)
    except CCompilerError:
        sys.stderr.write("Could not install extension module - "
                         "is your C compiler working correctly?\n")
    except DistutilsPlatformError:
        sys.stderr.write("Could not install extension module - "
                         "platform error?\n")
    except DistutilsExecError:
        sys.stderr.write("Could not install extension module - "
                         "is a C compiler installed?\n")
    except Exception as e:  # noqa
        sys.stderr.write("Could not install with extension module, "
                         "but this might not be the cause.\n")
        sys.stderr.write("This is the error:\n")
        traceback.print_exc()
    else:
        sys.exit(0)

setup(**args)
