#!/usr/bin/env python3
#
# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2019, 2023 Axel Gembe <axel@gembe.net>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import contextlib
import sys
from typing import List, Iterable, Optional

from .abstract_base import AbstractQrCodeReader, AbstractQrCodeReaderType, QrCodeResult
from ..util import print_error


class MissingLib(RuntimeError):
    """Raised by underlying implementation if missing libs"""

    pass


@contextlib.contextmanager
def missing_lib_handler(*args, **kwds):
    try:
        yield None
    except (MissingLib, ModuleNotFoundError) as e:
        print_error("[get_qr_reader]", str(e))


_QR_READERS: List[AbstractQrCodeReaderType] = []

with missing_lib_handler():
    from .zxing import ZxingCppQrCodeReader
    ZxingCppQrCodeReader()
    _QR_READERS.append(ZxingCppQrCodeReader)

with missing_lib_handler():
    from .zbar import ZbarQrCodeReader
    ZbarQrCodeReader()
    _QR_READERS.append(ZbarQrCodeReader)

if sys.platform == "darwin":
    with missing_lib_handler():
        from .osxqrdetect import OSXQRDetect
        OSXQRDetect()
        _QR_READERS.append(OSXQRDetect)


def get_supported_qr_reader_types() -> Iterable[AbstractQrCodeReaderType]:
    """
    Get all supported QR code reader types for the current platform.
    The returned QR reader types should be in order of priority.
    """

    for reader in _QR_READERS:
        yield reader


def get_qr_reader(name: Optional[str] = None) -> AbstractQrCodeReader:
    """
    Gets an instance of the user selected QR code reader or the default
    for the current platform.
    """

    for reader_type in get_supported_qr_reader_types():
        if not name or reader_type.__name__ == name:
            return reader_type()

    return None
