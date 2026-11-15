# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2020 The Electron Cash Developers
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
import os

from collections import namedtuple
from typing import Optional, Union, Iterable, Tuple

from .util import print_error

def bits_to_target(bits: int) -> int:
    size = bits >> 24
    assert size <= 0x1d

    word = bits & 0x00ffffff
    assert 0x8000 <= word <= 0x7fffff

    if size <= 3:
        return word >> (8 * (3 - size))
    else:
        return word << (8 * (size - 3))

def _trunc_div(n: int, d: int) -> int:
    """Integer division truncating toward zero, matching the C++ reference.

    Python's // floors, which differs for negative numerators; both BCHN and
    the ASERT spec's integer procedure truncate toward zero. The legacy code
    got this from int(a / b) via float division, which additionally loses
    up to an ulp of the quotient.
    """
    return -((-n) // d) if n < 0 else n // d


class TickSchedule:
    """Height -> cumulative tick mapping, per CHIP-2025-03.

    T(0) == 0 and T(h) == T(h-1) + tau(h), where tau(h) is block h's own target
    interval in ticks. An entry (h, tau) sets the interval of every block
    strictly above h, until the next entry.

    No entries means the uniform 600-tick schedule every network had before
    CHIP-2025-03, under which T(h) == 600 * h and the tick arithmetic below
    reduces exactly to the legacy height arithmetic.
    """

    BASE_TAU = 600

    def __init__(self, entries: Iterable[Tuple[int, int]] = ()):
        self.entries = tuple(sorted(entries))
        prev = -1
        for h, tau in self.entries:
            if h < 0 or h <= prev:
                raise ValueError("tick schedule heights must be strictly ascending")
            if tau < 1 or tau > self.BASE_TAU or self.BASE_TAU % tau:
                raise ValueError("tick schedule tau must divide 600 and be in [1, 600]")
            prev = h

    def __bool__(self) -> bool:
        return bool(self.entries)

    def tau(self, height: int) -> int:
        """Target interval of block `height` itself."""
        t = self.BASE_TAU
        for h, tau in self.entries:
            if h >= height:
                break
            t = tau
        return t

    def next_tau(self, height: int) -> int:
        """Target interval of block `height + 1`."""
        return self.tau(height + 1)

    def tick(self, height: int) -> int:
        """T(height): cumulative ticks through block `height`, inclusive."""
        if height <= 0:
            return 0
        total = 0
        cursor = 1
        cur = self.BASE_TAU
        for h, tau in self.entries:
            end = min(h, height)
            if end >= cursor:
                total += (end - cursor + 1) * cur
                cursor = end + 1
            if h >= height:
                break
            cur = tau
        if cursor <= height:
            total += (height - cursor + 1) * cur
        return total


_UNIFORM_SCHEDULE = TickSchedule()

def _get_asert_activation_mtp():
    """ Returns 1605441600 (Nov 15, 2020 12:00:00 UTC) or whatever override may
    be set by the env variable ASERT_MTP """
    default_mtp = 1605441600  # Nov 15, 2020 12:00:00 UTC
    mtp = os.environ.get('ASERT_MTP', default_mtp)
    try: mtp = int(mtp)
    except: pass
    if not isinstance(mtp, int) or mtp <= 1510600000:
        print_error("Error: Environment variable ASERT_MTP ignored because it is invalid: {}".format(str(mtp)))
        mtp = default_mtp
    if mtp != default_mtp:
        print_error("ASERT_MTP of {} will be used".format(mtp))
    return mtp

class Anchor(namedtuple("Anchor", "height bits prev_time")):
    pass

class ASERTDaa:
    """ Parameters and methods for the ASERT DAA. Instances of these live in
    networks.TestNet, networks.MainNet as part of the chain params. """

    MTP_ACTIVATION_TIME = _get_asert_activation_mtp()  # Normally Nov. 15th, 2020 UTC 12:00:00

    IDEAL_BLOCK_TIME = 10 * 60  # 10 mins
    HALF_LIFE = 2 * 24 * 3600  # for mainnet, testnet has 3600 (1 hour) half-life
    # Integer implementation uses these for fixed point math
    RBITS = 16  # number of bits after the radix for fixed-point math
    RADIX = 1 << RBITS
    # POW Limit
    MAX_BITS = 0x1d00ffff

    MAX_TARGET = bits_to_target(MAX_BITS)

    # If left as none, blockchain.py will calculate this at runtime as we read headers.
    anchor: Optional[Anchor] = None

    # CHIP-2025-03: the "+1" of the legacy formula is the anchor block's own
    # interval. Per the spec this is a per-network constant that MUST NOT be
    # derived from the tick schedule, so it is pinned here and not read from
    # `tick_schedule`.
    ANCHOR_IDEAL_BLOCK_TIME = 600

    # Height-keyed intervals. None == uniform 600 ticks, i.e. pre-activation
    # behaviour on every network.
    tick_schedule: Optional[TickSchedule] = None

    def __init__(self, is_testnet=False):
        if is_testnet:
            # From ASERT spec, testnet has 1 hour half-life
            self.HALF_LIFE = 3600

    @staticmethod
    def bits_to_target(bits: int) -> int:  return bits_to_target(bits)

    def target_to_bits(self, target: int) -> int:
        assert target > 0
        if target > self.MAX_TARGET:
            print_error('Warning: target went above maximum ({} > {})'.format(target, self.MAX_TARGET))
            target = self.MAX_TARGET
        size = (target.bit_length() + 7) // 8
        mask64 = 0xffffffffffffffff
        if size <= 3:
            compact = (target & mask64) << (8 * (3 - size))
        else:
            compact = (target >> (8 * (size - 3))) & mask64

        if compact & 0x00800000:
            compact >>= 8
            size += 1

        assert compact == (compact & 0x007fffff)
        assert size < 256
        return compact | size << 24

    @staticmethod
    def bits_to_work(bits: int) -> int:
        return (2 << 255) // (bits_to_target(bits) + 1)

    @staticmethod
    def target_to_hex(target: int) -> str:
        h = hex(target)[2:]
        return '0' * (64 - len(h)) + h

    def _aserti3_2d(self, anchor_bits: int, time_diff: int,
                    ideal_elapsed: int, interval_ratio: int = 1) -> int:
        """ASERTI3-2D over an ideal elapsed time expressed in ticks."""
        target = self.bits_to_target(anchor_bits)

        delta = time_diff - ideal_elapsed
        assert abs(delta) < (1 << (63 - self.RBITS))
        exponent = _trunc_div(delta * self.RADIX, self.HALF_LIFE)

        # 2^x = 2 * 2^(x-1): shift the exponent into [0, 1)
        shifts = exponent >> self.RBITS
        exponent -= shifts * self.RADIX
        assert exponent >= 0 and exponent < self.RADIX

        # target * 2^frac, in fixed point
        # 2^x ~= (1 + 0.695502049*x + 0.2262698*x**2 + 0.0782318*x**3)
        target *= self.RADIX + ((195766423245049 * exponent
                                 + 971821376 * exponent ** 2
                                 + 5127 * exponent ** 3 + 2 ** 47)
                                >> (self.RBITS * 3))

        if shifts < 0:
            target >>= -shifts
        else:
            target <<= shifts
        target >>= self.RBITS

        if interval_ratio != 1:
            # CHIP-2025-03: anchor_ideal_block_time / next_ideal_block_time.
            # Exact because a conforming schedule's tau divides 600, so the
            # ratio is a whole number. Python ints do not wrap, so the C++
            # pre-multiply overflow guard is unnecessary; the clamp below is
            # equivalent to it.
            target *= interval_ratio

        if target == 0:
            return self.target_to_bits(1)
        if target > self.MAX_TARGET:
            return self.MAX_BITS
        return self.target_to_bits(target)

    def next_bits_aserti3_2d(self, anchor_bits: int, time_diff: Union[float, int],
                             height_diff: int) -> int:
        """Legacy height-keyed entry point.

        Kept for callers that have not migrated; identical to
        next_bits_aserti3_2d_ticks() on a uniform 600-tick schedule.
        """
        return self._aserti3_2d(
            anchor_bits, time_diff,
            self.IDEAL_BLOCK_TIME * (height_diff + 1))

    def next_bits_aserti3_2d_ticks(self, anchor_bits: int, anchor_height: int,
                                   prev_height: int, prev_time: int,
                                   anchor_prev_time: int,
                                   schedule: Optional[TickSchedule] = None) -> int:
        sched = schedule or self.tick_schedule or _UNIFORM_SCHEDULE
        anchor_tick = self.IDEAL_BLOCK_TIME * anchor_height
        tick_delta = sched.tick(prev_height) - anchor_tick
        ideal_elapsed = tick_delta + self.ANCHOR_IDEAL_BLOCK_TIME

        next_tau = sched.next_tau(prev_height)
        assert self.IDEAL_BLOCK_TIME % next_tau == 0
        interval_ratio = self.IDEAL_BLOCK_TIME // next_tau

        return self._aserti3_2d(anchor_bits, prev_time - anchor_prev_time,
                                ideal_elapsed, interval_ratio)
