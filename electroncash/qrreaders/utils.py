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

from typing import Iterable, Tuple

def find_center(points: Iterable[Tuple[int, int]]) -> Tuple[int, int]:
    """Find the center by getting the average values of the corners x and y coordinates

    Args:
        points (Iterable[tuple[int, int]]): A list of points of which to find the center

    Returns:
        tuple[int, int]: The center point
    """

    points_len = len(points)
    points_sum_x = sum([l[0] for l in points])
    points_sum_y = sum([l[1] for l in points])
    return (int(points_sum_x / points_len), int(points_sum_y / points_len))
