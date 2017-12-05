# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def cashaddr_polymod(values):
    """Internal function that computes the cashaddr checksum."""
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07ffffffff) << 5) ^ d;
        if (c0 & 0x01):
            c ^= 0x98f2bc8e61 
        if (c0 & 0x02):
            c ^= 0x79b76d99e2 
        if (c0 & 0x04):
            c ^= 0xf33e5fb3c4 
        if (c0 & 0x08):
            c ^= 0xae2eabe2a8 
        if (c0 & 0x10):
            c ^= 0x1e4f43e470 
    retval= c ^ 1
    return retval


def cashaddr_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    retval = [ord(x) & 0x1f for x in hrp]
    # Append null separator
    retval.append(0)
    return retval


def cashaddr_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    return cashaddr_polymod(cashaddr_hrp_expand(hrp) + data) == 0


def cashaddr_create_checksum(hrp, data):
    """Compute the checksum values given HRP and data."""
    values = cashaddr_hrp_expand(hrp) + data
    polymod = cashaddr_polymod(values + [0, 0, 0, 0, 0, 0, 0, 0])
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(8)]


def cashaddr_encode(hrp, data):
    """Compute a cashaddr string given HRP and data values."""
    combined = data + cashaddr_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])


def cashaddr_decode(bech):
    """Validate a cashaddr string, and determine HRP and data."""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind(':')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None)
    if not all(x in CHARSET for x in bech[pos+1:]):
        return (None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]
    if not cashaddr_verify_checksum(hrp, data):
        return (None, None)
    # 40 bits in chunks of 5 bits is 8 bytes total that we don't want to include
    return (hrp, data[:-8])


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        acc = ((acc << frombits) | value ) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)

    if not pad and bits:
        return ret, False
    elif pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)

    return ret, True


def decode(hrp, addr):
    """Decode a cashaddr address."""
    hrpgot, data = cashaddr_decode(addr)
    if hrpgot != hrp:
        return (None, None)
    decoded, padded = convertbits(data, 5, 8, False)
    witver = decoded[0]
    withash = decoded[1:]
    if decoded is None or len(withash) < 2 or len(withash) > 40:
        return (None, None)
    if witver > 16:
        return (None, None)
    if witver == 0 and len(withash) != 20 and len(withash) != 32:
        return (None, None)
    return (witver, withash)


def encode(hrp, witver, witprog):
    """Encode a cashaddr address."""
    ret = cashaddr_encode(hrp, [witver] + convertbits(witprog, 8, 5))
    if decode(hrp, ret) == (None, None):
        return None
    return ret
