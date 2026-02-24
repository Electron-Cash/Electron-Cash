#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
# This file (c) 2022-2025 Calin Culianu <calin.culianu@gmail.com>
# Part of the Electron Cash SPV Wallet
# License: MIT
"""Encapsulation of Cash Token data in a transaction output"""

import struct
from decimal import Decimal as PyDecimal
from enum import IntEnum
from typing import Optional, Tuple, Union

from .bitcoin import OpCodes
from .i18n import _
from .serialize import BCDataStream, SerializationError
from .util import print_error

from . import wallet

# By consensus, NFT commitment byte blobs may not exceed this length
MAX_CONSENSUS_COMMITMENT_LENGTH = 40


class Structure(IntEnum):
    HasAmount = 0x10
    HasNFT = 0x20
    HasCommitmentLength = 0x40


class Capability(IntEnum):
    NoCapability = 0x00
    Mutable = 0x01
    Minting = 0x02


class OutputData:
    __slots__ = ("id", "bitfield", "amount", "commitment")

    def __init__(self, id: Union[bytes, bytearray, str] = b'\x00' * 32, amount: int = 1,
                 commitment: Union[bytes, bytearray, str] = b'',
                 bitfield: Union[int, str, bytes, bytearray] = Structure.HasAmount):
        if isinstance(id, str):
            # Convert from hex and reverse
            id = bytes.fromhex(id)[::-1]
        elif isinstance(id, bytearray):
            # Support bytearray arg
            id = bytes(id)
        if isinstance(commitment, str):
            # Convert from hex, don't reverse
            commitment = bytes.fromhex(commitment)
        elif isinstance(commitment, bytearray):
            # Support bytearray arg
            commitment = bytes(commitment)
        if isinstance(bitfield, str):
            # Convert from hex (must be 1 byte hex)
            assert len(bitfield) == 2
            bitfield = bytes.fromhex(bitfield)[0]
        elif isinstance(bitfield, (bytes, bytearray)):
            # Convert from bytes (must be length 1)
            assert len(bitfield) == 1
            bitfield = bitfield[0]
        assert len(id) == 32 and (isinstance(id, bytes) and isinstance(commitment, bytes) and isinstance(bitfield, int)
                                  and isinstance(amount, int))
        self.id = id
        self.amount = amount
        self.commitment = commitment
        self.bitfield = bitfield

    def __eq__(self, other) -> bool:
        if not isinstance(other, OutputData):
            return False
        return (self.id, self.bitfield, self.amount, self.commitment) == (other.id, other.bitfield, other.amount,
                                                                          other.commitment)

    def __repr__(self) -> str:
        return f"<token.OutputData(id={self.id_hex}, bitfield={self.bitfield:02x}, amount={self.amount}, " \
               f"commitment={self.commitment[:MAX_CONSENSUS_COMMITMENT_LENGTH].hex()})>"

    @classmethod
    def fromhex(cls, hexdata: str) -> Optional[object]:
        """Convenience: Attempts to parse hexdata (which should already have PREFIX_BYTE chopped off) as if it were a
        serialized token as one would get from self.tohex(). Returns None on parse failure, or a valid
        token.OutputData instance on success."""
        ret = OutputData()
        try:
            ret.deserialize(buffer=bytes.fromhex(hexdata))
            return ret
        except SerializationError:
            return None

    def hex(self):
        return self.serialize().hex()

    @property
    def id_hex(self) -> str:
        return self.id[::-1].hex()

    @id_hex.setter
    def id_hex(self, hex: str):
        b = bytes.fromhex(hex)
        assert len(b) == 32
        self.id = b[::-1]

    def deserialize(self, *, buffer: Optional[bytes] = None, ds: Optional[BCDataStream] = None):
        assert bool(buffer is not None) + bool(ds is not None) == 1  # Exactly one of these must be valid
        if ds is None:
            ds = BCDataStream(buffer)
        self.id = ds.read_bytes(32, strict=True)
        self.bitfield = struct.unpack("<B", ds.read_bytes(1, strict=True))[0]
        if self.has_commitment_length():
            self.commitment = ds.read_bytes(strict=True)
        else:
            self.commitment = b''
        if self.has_amount():
            self.amount = ds.read_compact_size(strict=True)
        else:
            self.amount = 0
        if (not self.is_valid_bitfield() or (self.has_amount() and not self.amount)
                or self.amount < 0 or self.amount > 2**63-1
                or (self.has_commitment_length() and not self.commitment)
                or (not self.amount and not self.has_nft())):
            # Bad bitfield or 0 serialized amount or bad amount or empty serialized commitment is
            # a deserialization error
            raise SerializationError('Unable to parse token data or token data is invalid')

    def serialize(self) -> bytes:
        ds = BCDataStream()
        ds.write(self.id)
        ds.write(struct.pack("B", self.bitfield))
        if self.has_commitment_length():
            ds.write_compact_size(len(self.commitment))
            ds.write(self.commitment)
        if self.has_amount():
            ds.write_compact_size(self.amount)
        return bytes(ds.input)

    def get_capability(self) -> int:
        return self.bitfield & 0x0f

    def has_commitment_length(self) -> bool:
        return bool(self.bitfield & Structure.HasCommitmentLength)

    def has_amount(self) -> bool:
        return bool(self.bitfield & Structure.HasAmount)

    def has_nft(self) -> bool:
        return bool(self.bitfield & Structure.HasNFT)

    def is_minting_nft(self) -> bool:
        return self.has_nft() and self.get_capability() == Capability.Minting

    def is_mutable_nft(self) -> bool:
        return self.has_nft() and self.get_capability() == Capability.Mutable

    def is_immutable_nft(self) -> bool:
        return self.has_nft() and self.get_capability() == Capability.NoCapability

    def is_valid_bitfield(self) -> bool:
        s = self.bitfield & 0xf0
        if s >= 0x80 or s == 0x00:
            return False
        if self.bitfield & 0x0f > 2:
            return False
        if not self.has_nft() and not self.has_amount():
            return False
        if not self.has_nft() and (self.bitfield & 0x0f) != 0:
            return False
        if not self.has_nft() and self.has_commitment_length():
            return False
        return True


PREFIX_BYTE = bytes([OpCodes.SPECIAL_TOKEN_PREFIX])


def wrap_spk(token_data: Optional[OutputData], script_pub_key: bytes) -> bytes:
    if not token_data:
        return script_pub_key
    buf = bytearray()
    assert len(PREFIX_BYTE) == 1
    buf += PREFIX_BYTE
    buf += token_data.serialize()
    buf += script_pub_key
    return bytes(buf)


def unwrap_spk(wrapped_spk: bytes) -> Tuple[Optional[OutputData], bytes]:
    assert len(PREFIX_BYTE) == 1
    if not wrapped_spk or wrapped_spk[0] != PREFIX_BYTE[0]:
        return None, wrapped_spk
    token_data = OutputData()
    ds = BCDataStream(wrapped_spk)
    pfx = ds.read_bytes(1, strict=True)  # consume prefix byte
    assert pfx == PREFIX_BYTE
    try:
        token_data.deserialize(ds=ds)  # unserialize token_data from buffer after prefix_byte
    except SerializationError:
        # Unable to deserialize or parse token data. This is ok. Just return all the bytes as the full scriptPubKey
        return None, wrapped_spk
    # leftover bytes go to real spk
    spk = wrapped_spk[ds.read_cursor:]
    return token_data, spk  # Parsed ok


def heuristic_dust_limit_for_token_bearing_output() -> int:
    """If calculating dust, wallet.dust_threshold should be used instead of a new function, but it may be desirable 
    to retain this function beyond deprecation to support hypothetical private plugins."""
    #return 800
    """800 was hard-coded at implementation and expected to be enough to cover all conceivable token-bearing UTXOs
    however, if my math is correct and there aren't any conflicts between components of the UTXO, worst-case for a
    standard transaction may at least theoretically be 1392 (output size of 316 bytes)."""
    return wallet.dust_threshold(None, output_bytes=118) # This should return 798, supports same UTXOs as 800.


def get_nft_flag_text(td: OutputData) -> Optional[str]:
    """Returns a UI-friendly string to describe the NFT, or None if the token does not have an NFT."""
    if td.is_minting_nft():
        return _('Minting')
    elif td.is_mutable_nft():
        return _('Mutable')
    elif td.is_immutable_nft():
        return _('Immutable')


def nft_flag_text_sorter(txt: str) -> int:
    """Usable by UI code to sort NFT flag texts in order of importance.
    Assumption is txt came from get_nft_flag_text() above."""
    if txt == _("Minting"):
        return 0
    elif txt == _("Mutable"):
        return 1
    else:
        return 2 + abs(hash(txt))


def format_fungible_amount(x: int, decimal_point: int, num_zeros=0, precision=None, is_diff=False, whitespaces=False,
                           append_tokentoshis=False):
    """Inspired by format_satoshis(), but always uses decimal.Decimal for exact precision"""
    assert decimal_point >= 0
    if x is None:
        return _('Unknown')
    if decimal_point == 0 and not is_diff and not whitespaces:
        # Short-circuit for the common case of unknown tokens with decimals defaulting to 0
        return str(x)
    if precision is None:
        precision = decimal_point
    decimal_format = "." + str(precision) if precision > 0 else ""
    if is_diff:
        decimal_format = '+' + decimal_format
    try:
        scale = pow(10, decimal_point)
        pd = PyDecimal(x)
        if scale > 1:
            pd /= scale
        result = ("{:" + decimal_format + "f}").format(pd)
    except ArithmeticError as e:
        # Normally doesn't happen unless X is a bad value
        print_error("token.format_amount:", repr(e))
        return 'unknown'
    parts = result.split(".")
    integer_part = parts[0]
    if len(parts) >= 2:
        fract_part = parts[1].rstrip("0")
    else:
        fract_part = ""
    dp = '.'
    if not integer_part:
        integer_part = "0"
    if len(fract_part) < num_zeros:
        fract_part += "0" * (num_zeros - len(fract_part))
    result = integer_part
    if len(fract_part) > 0:
        result += dp + fract_part
    if whitespaces:
        result += " " * (decimal_point - len(fract_part))
        result = " " * (19 - len(result)) + result
    if decimal_point == 0 and result.endswith("."):
        result = result.rstrip('.')
    if decimal_point > 0 and append_tokentoshis and x != 0:
        result += " (" + str(x) + ")"
    return result


def parse_fungible_amount(x: str, decimal_point: int) -> int:
    """Convert formatted amount string to token-level units (token sats), without losing precision"""
    assert decimal_point >= 0
    parts = x.strip().split('.')
    if len(parts) < 2:
        parts.append("0")
    int_part, frac_part = parts
    if len(frac_part) < decimal_point:
        frac_part += "0" * (decimal_point - len(frac_part))
    elif len(frac_part) > decimal_point:
        frac_part = frac_part[:decimal_point]
    if not frac_part:
        frac_part = "0"
    if not int_part:
        int_part = "0"
    scale = pow(10, decimal_point)
    return int(int_part) * scale + int(frac_part)
