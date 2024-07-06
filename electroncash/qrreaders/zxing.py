# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2023 Axel Gembe <axel@gembe.net>
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

import ctypes
from typing import List

try:
    import zxingcpp
except ModuleNotFoundError:
    import sys
    print("\n\nzxing-cpp module missing. Please try installing it with: python3 -m pip install 'zxing-cpp>=2.2.0'"
          " --user\n\n", file=sys.stderr)
    raise

from .utils import find_center

from .abstract_base import AbstractQrCodeReader, QrCodeResult


_PyMemoryView_FromMemory = ctypes.pythonapi.PyMemoryView_FromMemory
_PyMemoryView_FromMemory.argtypes = [ctypes.c_void_p, ctypes.c_ssize_t, ctypes.c_int]
_PyMemoryView_FromMemory.restype = ctypes.py_object

_PyBUF_READ: ctypes.c_int = 0x100


class ZxingCppQrCodeReader(AbstractQrCodeReader):
    """
    Reader that uses zxing-cpp
    """

    @classmethod
    def reader_name(cls) -> str:
        return "ZXing-C++"

    def read_qr_code(
        self,
        buffer: ctypes.c_void_p,
        buffer_size: int,
        rowlen_bytes: int,
        width: int,
        height: int,
        frame_id: int = -1,
    ) -> List[QrCodeResult]:
        assert rowlen_bytes == width  # ZXing-C++ doesn't support image lines != width
        pybuffer = _PyMemoryView_FromMemory(buffer, buffer_size, _PyBUF_READ).cast("B", (height, width))

        results = []

        for result in zxingcpp.read_barcodes(
            image=pybuffer, formats=zxingcpp.BarcodeFormat.QRCode, text_mode=zxingcpp.TextMode.Plain
        ):
            result_points = [
                (result.position.top_left.x, result.position.top_left.y),
                (result.position.top_right.x, result.position.top_right.y),
                (result.position.bottom_right.x, result.position.bottom_right.y),
                (result.position.bottom_left.x, result.position.bottom_left.y),
            ]
            results.append(QrCodeResult(result.text, find_center(result_points), result_points))

        return results
