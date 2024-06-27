# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2017-2023 The Electron Cash Developers
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

# Many of the functions in this file are copied from ElectrumX

import hashlib
import struct
from collections import namedtuple
from typing import Union

from . import cashaddr, networks
from .bitcoin import EC_KEY, is_minikey, minikey_to_private_key, SCRIPT_TYPES, OpCodes, push_script_bytes, ripemd160
from .util import cachedproperty, inv_dict

_sha256 = hashlib.sha256
_new_hash = hashlib.new
hex_to_bytes = bytes.fromhex


class AddressError(Exception):
    """Exception used for Address errors."""


class ScriptError(Exception):
    """Exception used for Script errors."""


P2PKH_prefix = bytes([OpCodes.OP_DUP, OpCodes.OP_HASH160, 20])
P2PKH_suffix = bytes([OpCodes.OP_EQUALVERIFY, OpCodes.OP_CHECKSIG])

P2SH_prefix = bytes([OpCodes.OP_HASH160, 20])
P2SH_suffix = bytes([OpCodes.OP_EQUAL])

P2SH32_prefix = bytes([OpCodes.OP_HASH256, 32])
P2SH32_suffix = P2SH_suffix


# Utility functions

def to_bytes(x):
    """Convert to bytes which is hashable."""
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    raise TypeError('{} is not bytes ({})'.format(x, type(x)))


def hash_to_hex_str(x):
    """Convert a big-endian binary hash to displayed hex string.

    Display form of a binary hash is reversed and converted to hex.
    """
    return bytes(reversed(x)).hex()


def hex_str_to_hash(x):
    """Convert a displayed hex string to a binary hash."""
    return bytes(reversed(hex_to_bytes(x)))


def bytes_to_int(be_bytes):
    """Interprets a big-endian sequence of bytes as an integer"""
    return int.from_bytes(be_bytes, 'big')


def int_to_bytes(value):
    """Converts an integer to a big-endian sequence of bytes"""
    return value.to_bytes((value.bit_length() + 7) // 8, 'big')


def sha256(x):
    """Simple wrapper of hashlib sha256."""
    return _sha256(x).digest()


def double_sha256(x):
    """SHA-256 of SHA-256, as used extensively in bitcoin."""
    return sha256(sha256(x))


def hash160(x):
    """RIPEMD-160 of SHA-256.

    Used to make bitcoin addresses from pubkeys."""
    return ripemd160(sha256(x))


class UnknownAddress(namedtuple("UnknownAddress", "meta")):

    def __new__(cls, meta=None):
        return super(UnknownAddress, cls).__new__(cls, meta)

    def to_ui_string(self, *, net=None):
        if self.meta is not None:
            meta = self.meta
            meta = (isinstance(meta, (bytes, bytearray)) and meta.hex()) or meta
            if isinstance(meta, str) and len(meta) > 10:
                l = len(meta) // 2
                meta = "…" + meta[l-4:l+4] + "…"
            return f'<UnknownAddress meta={meta}>'
        return '<UnknownAddress>'

    def __str__(self):
        return self.to_ui_string()

    def __repr__(self):
        return self.to_ui_string()


class PublicKey(namedtuple("PublicKeyTuple", "pubkey")):

    TO_ADDRESS_OPS = [OpCodes.OP_DUP, OpCodes.OP_HASH160, -1,
                      OpCodes.OP_EQUALVERIFY, OpCodes.OP_CHECKSIG]

    @classmethod
    def from_pubkey(cls, pubkey):
        """Create from a public key expressed as binary bytes."""
        if isinstance(pubkey, str):
            pubkey = hex_to_bytes(pubkey)
        cls.validate(pubkey)
        return cls(to_bytes(pubkey))

    @classmethod
    def privkey_from_WIF_privkey(cls, WIF_privkey, *, net=None):
        """Given a WIF private key (or minikey), return the private key as
        binary and a boolean indicating whether it was encoded to
        indicate a compressed public key or not.
        """
        if net is None: net = networks.net
        if is_minikey(WIF_privkey):
            # The Casascius coins were uncompressed
            return minikey_to_private_key(WIF_privkey), False
        raw = Base58.decode_check(WIF_privkey)
        if not raw:
            raise ValueError('Private key WIF decode error; unable to decode.')
        if raw[0] != net.WIF_PREFIX:
            # try and generate a helpful error message as this propagates up to the UI if they are creating a new
            # wallet.
            extra = inv_dict(SCRIPT_TYPES).get(int(raw[0]-net.WIF_PREFIX), '')
            if extra:
                extra = "; this corresponds to a key of type: '{}' which is unsupported for importing from WIF key.".format(extra)
            raise ValueError("Private key has invalid WIF version byte (expected: 0x{:x} got: 0x{:x}){}".format(net.WIF_PREFIX, raw[0], extra))
        if len(raw) == 34 and raw[-1] == 1:
            return raw[1:33], True
        if len(raw) == 33:
            return raw[1:], False
        raise ValueError('invalid private key')

    @classmethod
    def from_WIF_privkey(cls, WIF_privkey):
        """Create a compressed or uncompressed public key from a private key."""
        privkey, compressed = cls.privkey_from_WIF_privkey(WIF_privkey)
        ec_key = EC_KEY(privkey)
        return cls.from_pubkey(ec_key.GetPubKey(compressed))

    @classmethod
    def from_string(cls, string):
        """Create from a hex string."""
        return cls.from_pubkey(hex_to_bytes(string))

    @classmethod
    def validate(cls, pubkey):
        if not isinstance(pubkey, (bytes, bytearray)):
            raise TypeError('pubkey must be of bytes type, not {}'
                            .format(type(pubkey)))
        if len(pubkey) == 33 and pubkey[0] in (2, 3):
            return  # Compressed
        if len(pubkey) == 65 and pubkey[0] == 4:
            return  # Uncompressed
        raise AddressError('invalid pubkey {}'.format(pubkey))

    @cachedproperty
    def address(self):
        """Convert to an Address object."""
        return Address(hash160(self.pubkey), Address.ADDR_P2PKH)

    def is_compressed(self):
        """Returns True if the pubkey is compressed."""
        return len(self.pubkey) == 33

    def to_ui_string(self, *, net=None):
        """Convert to a hexadecimal string."""
        return self.pubkey.hex()

    def to_storage_string(self):
        """Convert to a hexadecimal string for storage."""
        return self.pubkey.hex()

    def to_script(self):
        """Note this returns the P2PK script."""
        return Script.P2PK_script(self.pubkey)

    def to_script_hex(self):
        """Return a script to pay to the address as a hex string."""
        return self.to_script().hex()

    def to_scripthash(self):
        """Returns the hash of the script in binary."""
        return sha256(self.to_script())

    def to_scripthash_hex(self):
        """Like other bitcoin hashes this is reversed when written in hex."""
        return hash_to_hex_str(self.to_scripthash())

    def to_P2PKH_script(self):
        """Return a P2PKH script."""
        return self.address.to_script()

    def __str__(self):
        return self.to_ui_string()

    def __repr__(self):
        return '<PubKey {}>'.format(self.__str__())


class ScriptOutput(namedtuple("ScriptAddressTuple", "script")):

    @classmethod
    def from_string(self, string):
        """Instantiate from a mixture of opcodes and raw data."""
        script = bytearray()
        for word in string.split():
            if word.startswith('OP_'):
                try:
                    opcode = OpCodes[word]
                except KeyError:
                    raise AddressError('unknown opcode {}'.format(word))
                script.append(opcode)
            else:
                import binascii
                script.extend(Script.push_data(binascii.unhexlify(word)))
        return ScriptOutput.protocol_factory(bytes(script))

    def to_ui_string(self, ignored=None, *, net=None):
        """Convert to user-readable OP-codes (plus pushdata as text if possible)
        eg OP_RETURN (12) "Hello there!"
        """
        try:
            ops = Script.get_ops(self.script)
        except ScriptError:
            # Truncated script -- so just default to hex string.
            return 'Invalid script: ' + self.script.hex()
        def lookup(x):
            try:
                return OpCodes(x).name
            except ValueError:
                return '('+str(x)+')'
        parts = []
        for op, data in ops:
            if data is not None:
                # Attempt to make a friendly string, or fail to hex
                try:
                    astext = data.decode('utf8')

                    friendlystring = repr(astext)

                    # if too many escaped characters, it's too ugly!
                    if friendlystring.count('\\')*3 > len(astext):
                        friendlystring = None
                except:
                    friendlystring = None

                if not friendlystring:
                    friendlystring = data.hex()

                parts.append(lookup(op) + " " + friendlystring)
            else:  # isinstance(op, int):
                parts.append(lookup(op))
        return ', '.join(parts)

    def to_script(self):
        return self.script

    def is_opreturn(self):
        """ Returns True iff this script is an OP_RETURN script (starts with
        the OP_RETURN byte) """
        return bool(self.script and self.script[0] == OpCodes.OP_RETURN)

    def to_scripthash(self):
        """Returns the hash of the script in binary."""
        return sha256(self.to_script())

    def to_scripthash_hex(self):
        """Like other bitcoin hashes this is reversed when written in hex."""
        return hash_to_hex_str(self.to_scripthash())

    def __str__(self):
        return self.to_ui_string(True)

    def __repr__(self):
        return '<ScriptOutput {}>'.format(self.__str__())


    ###########################################
    # Protocol system methods and class attrs #
    ###########################################

    # subclasses of ScriptOutput that handle protocols. Currently this will
    # contain a cashacct.ScriptOutput instance.
    #
    # NOTE: All subclasses of this class must be hashable. Please implement
    # __hash__ for any subclasses. (This is because our is_mine cache in
    # wallet.py assumes all possible types that pass through it are hashable).
    #
    protocol_classes = set()

    def make_complete(self, block_height=None, block_hash=None, txid=None):
        """ Subclasses implement this, noop here. """
        pass

    def is_complete(self):
        """ Subclasses implement this, noop here. """
        return True

    @classmethod
    def find_protocol_class(cls, script_bytes):
        """ Scans the protocol_classes set, and if the passed-in script matches
        a known protocol, returns that class, otherwise returns our class. """
        for c in cls.protocol_classes:
            if c.protocol_match(script_bytes):
                return c
        return __class__

    @staticmethod
    def protocol_factory(script):
        """ One shot -- find the right class and construct object based on script """
        return __class__.find_protocol_class(script)(script)


class Address(namedtuple("AddressTuple", "hash kind")):
    """A namedtuple for easy comparison and unique hashing.
    Note that member .hash may be 20 or 32 bytes (it may be either a hash160 or a hash256 for P2SH32)."""

    # Address kinds
    ADDR_P2PKH = cashaddr.PUBKEY_TYPE  # 0 (cashaddr.TOKEN_PUBKEY_TYPE also gets flattened down to this one here)
    ADDR_P2SH = cashaddr.SCRIPT_TYPE   # 1 (cashaddr.TOKEN_SCRIPT_TYPE also gets flattened down to this one here)

    # Address formats
    FMT_CASHADDR = 0
    FMT_LEGACY = 1
    FMT_TOKEN = 2

    _NUM_FMTS = 3  # <-- Be sure to update this if you add a format above!

    # Default to CashAddr
    FMT_UI = FMT_CASHADDR

    def __new__(cls, addr_hash, kind):
        addr_hash = to_bytes(addr_hash)
        ret = super().__new__(cls, addr_hash, kind)
        ret._addr2str_cache = [None] * cls._NUM_FMTS
        ret._check_sanity()
        return ret

    def _check_sanity(self):
        assert self.kind in (self.ADDR_P2PKH, self.ADDR_P2SH), f"Unknown kind: {self.kind}"
        hlen = len(self.hash)
        assert hlen in (20, 32), f"Only 20-byte or 32-byte hashes are accepted, got hash of length: {hlen}"
        if self.kind == self.ADDR_P2PKH:
            assert hlen == 20, "P2PKH may only have hash length 20"

    @property
    def hash160(self):
        """The member .hash used to be called .hash160. This property method is here so as to continue to support
        old call-sites expecting addr.hash160 to continue to exist, so that plugins and other dependent code doesn't
        break.  Note that despite the name, the hash returned may be 32-bytes in the case of P2SH32."""
        return self.hash

    @classmethod
    def show_cashaddr(cls, on):
        cls.FMT_UI = cls.FMT_CASHADDR if on else cls.FMT_LEGACY

    @classmethod
    def from_cashaddr_string(cls, string, *, net=None, return_ca_type=False):
        """Construct from a cashaddress string. If return_ca_type=True then it will return a tuple of
        (Address, cashaddress_type), otherwise it will just return the Address object. """
        if net is None: net = networks.net
        prefix = net.CASHADDR_PREFIX
        if string.upper() == string:
            prefix = prefix.upper()
        if not string.startswith(prefix + ':'):
            string = ':'.join([prefix, string])
        try:
            addr_prefix, ca_type, addr_hash = cashaddr.decode(string)
        except ValueError as e:
            raise AddressError(str(e))
        if addr_prefix != prefix:
            raise AddressError('address has unexpected prefix {}'.format(addr_prefix))
        if ca_type in (cashaddr.PUBKEY_TYPE, cashaddr.TOKEN_PUBKEY_TYPE):
            # Since this class encapsulates a locking script, irrespective of display format, we flatten down
            # the token vs non-token encoding types to 1 here.
            kind = cls.ADDR_P2PKH
        elif ca_type in (cashaddr.SCRIPT_TYPE, cashaddr.TOKEN_SCRIPT_TYPE):
            # Since this class encapsulates a locking script, irrespective of display format, we flatten down
            # the token vs non-token encoding types to 1 here.
            kind = cls.ADDR_P2SH
        else:
            raise AddressError('address has unexpected cashaddr type {}'.format(ca_type))
        if kind == cls.ADDR_P2PKH and len(addr_hash) != 20:
            raise AddressError('address has wrong hash length, P2PKH may only have a 20-byte hash')
        try:
            ret = cls(addr_hash, kind)
        except AssertionError as e:
            raise AddressError(str(e))
        if return_ca_type:
            return ret, ca_type
        return ret

    @classmethod
    def from_string(cls, string, *, net=None):
        """Construct from an address string."""
        if net is None: net = networks.net

        # First, try cashaddr decode
        try:
            return cls.from_cashaddr_string(string, net=net)
        except AddressError as e:
            cashaddr_exc = AddressError(f'invalid address: {string} (' + str(e) + ')')

        # Proceed down to try legacy as a fallback
        try:
            raw = Base58.decode_check(string)
        except Base58Error as e:
            raise cashaddr_exc or AddressError(str(e))

        # Require version byte(s) plus hash
        if len(raw) not in (21, 33):
            raise AddressError('invalid address: {}'.format(string))

        verbyte, addr_hash = raw[0], raw[1:]
        if verbyte == net.ADDRTYPE_P2PKH:
            kind = cls.ADDR_P2PKH
        elif verbyte == net.ADDRTYPE_P2SH:
            kind = cls.ADDR_P2SH
        else:
            raise AddressError(f'invalid address: {string} (unknown version byte: {verbyte})')

        try:
            return cls(addr_hash, kind)
        except AssertionError as e:
            raise AddressError(f'invalid address: {string} (' + str(e) + ')')

    @classmethod
    def is_valid(cls, string, *, net=None):
        if net is None: net = networks.net
        try:
            cls.from_string(string, net=net)
            return True
        except Exception:
            return False

    @classmethod
    def from_strings(cls, strings, *, net=None):
        """Construct a list from an iterable of strings."""
        if net is None: net = networks.net
        return [cls.from_string(string, net=net) for string in strings]

    @classmethod
    def from_pubkey(cls, pubkey):
        """Returns a P2PKH address from a public key.  The public key can be bytes or a hex string."""
        if isinstance(pubkey, str):
            pubkey = hex_to_bytes(pubkey)
        PublicKey.validate(pubkey)
        return cls(hash160(pubkey), cls.ADDR_P2PKH)

    @classmethod
    def from_P2PKH_hash(cls, hash160):
        """Construct from a P2PKH hash160."""
        assert len(hash160) == 20
        return cls(hash160, cls.ADDR_P2PKH)

    @classmethod
    def from_P2SH_hash(cls, hash160_or_hash256):
        """Construct from a P2SH hash160 or hash256 (for P2SH32)."""
        assert len(hash160_or_hash256) in (20, 32)
        return cls(hash160_or_hash256, cls.ADDR_P2SH)

    @classmethod
    def from_multisig_script(cls, script):
        """Construct a P2SH address (20-byte hash) given a multi-sig script."""
        return cls(hash160(script), cls.ADDR_P2SH)

    @classmethod
    def to_strings(cls, fmt, addrs, *, net=None):
        """Construct a list of strings from an iterable of Address objects."""
        if net is None: net = networks.net
        return [addr.to_string(fmt, net=net) for addr in addrs]

    @staticmethod
    def is_legacy(address: str, net=None) -> bool:
        """Find if the string of the address is in legacy format"""
        if net is None:
            net = networks.net
        try:
            raw = Base58.decode_check(address)
        except Base58Error:
            return False

        if len(raw) not in (21, 33):
            return False

        verbyte = raw[0]
        legacy_formats = (
            net.ADDRTYPE_P2PKH,
            net.ADDRTYPE_P2SH
        )
        if verbyte not in legacy_formats:
            return False
        if verbyte == net.ADDRTYPE_P2PKH and len(raw) != 21:
            # p2pkh only supports 20-byte hashes
            return False
        return True

    @classmethod
    def is_token(cls, address_string: str, *, net=None) -> bool:
        """Returns True if the supplied string parses correctly as a token-aware cash address
        (cash address type 2 or type 3), False otherwise."""
        try:
            _, ca_type = cls.from_cashaddr_string(address_string, net=net, return_ca_type=True)
            return ca_type in (cashaddr.TOKEN_PUBKEY_TYPE, cashaddr.TOKEN_SCRIPT_TYPE)
        except (ValueError, AddressError):
            pass
        return False

    def to_cashaddr(self, *, net=None, ca_type_override=None):
        if net is None: net = networks.net
        self._check_sanity()
        ca_type = ca_type_override if ca_type_override is not None else self.kind
        return cashaddr.encode(net.CASHADDR_PREFIX, ca_type, self.hash)

    def to_string(self, fmt, *, net=None):
        """Converts to a string of the given format."""
        if net is None: net = networks.net
        cacheable = net is networks.net
        cached = None
        if cacheable:
            try:
                cached = self._addr2str_cache[fmt]
                if cached:
                    return cached
            except (IndexError, TypeError):
                raise AddressError('unrecognized format')

        try:
            if fmt in (self.FMT_CASHADDR, self.FMT_TOKEN):
                ca_type = self.kind
                if fmt == self.FMT_TOKEN:
                    if self.kind == self.ADDR_P2PKH:
                        ca_type = cashaddr.TOKEN_PUBKEY_TYPE
                    elif self.kind == self.ADDR_P2SH:
                        ca_type = cashaddr.TOKEN_SCRIPT_TYPE
                cached = self.to_cashaddr(net=net, ca_type_override=ca_type)
                return cached

            if fmt == self.FMT_LEGACY:
                if self.kind == self.ADDR_P2PKH:
                    verbyte = net.ADDRTYPE_P2PKH
                else:  # self.kind == self.ADDR_P2SH
                    verbyte = net.ADDRTYPE_P2SH
            else:
                # This should never be reached due to cache-lookup check above.
                # But leaving it in as it's a harmless sanity check.
                raise AddressError('unrecognized format')

            self._check_sanity()
            cached = Base58.encode_check(bytes([verbyte]) + self.hash)
            return cached
        finally:
            if cached and cacheable:
                self._addr2str_cache[fmt] = cached

    def to_token_string(self, *, net=None):
        """Return a (prefix-less) string that is the "token-aware" representation of this address. These addresses
        are encoded with cashaddr type 2 or 3 (as opposed to 0 or 1 for non-token-aware addresses)."""
        return self.to_string(self.FMT_TOKEN, net=net)

    def to_full_string(self, fmt, *, net=None):
        """Convert to text, with a URI prefix for cashaddr format."""
        if net is None: net = networks.net
        text = self.to_string(fmt, net=net)
        if fmt in (self.FMT_CASHADDR, self.FMT_TOKEN):
            text = ':'.join([net.CASHADDR_PREFIX, text])
        return text

    def to_full_token_string(self, *, net=None):
        """Like to_token_string but always includes the prefix (e.g. "bitcoincash:").."""
        return self.to_full_string(self.FMT_TOKEN, net=net)

    def to_ui_string(self, *, net=None):
        """Convert to text in the current UI format choice."""
        if net is None: net = networks.net
        return self.to_string(self.FMT_UI, net=net)

    def to_full_ui_string(self, *, net=None):
        """Convert to text, with a URI prefix if cashaddr."""
        if net is None: net = networks.net
        return self.to_full_string(self.FMT_UI, net=net)

    def to_URI_components(self, *, net=None, token=False):
        """Returns a (scheme, path) pair for building a URI."""
        if net is None: net = networks.net
        scheme = net.CASHADDR_PREFIX
        path = self.to_token_string(net=net) if token else self.to_ui_string(net=net)
        return scheme, path

    def to_storage_string(self, *, net=None):
        """Convert to text in the storage format."""
        if net is None: net = networks.net
        return self.to_string(self.FMT_LEGACY, net=net)

    def to_script(self):
        """Return a binary script to pay to the address."""
        self._check_sanity()
        if self.kind == self.ADDR_P2PKH:
            return Script.P2PKH_script(self.hash)
        else:
            return Script.P2SH_script(self.hash)

    def to_script_hex(self):
        """Return a script to pay to the address as a hex string."""
        return self.to_script().hex()

    def to_scripthash(self):
        """Returns the hash of the script in binary."""
        return sha256(self.to_script())

    def to_scripthash_hex(self):
        """Like other bitcoin hashes this is reversed when written in hex."""
        return hash_to_hex_str(self.to_scripthash())

    def __str__(self):
        return self.to_ui_string()

    def __repr__(self):
        return '<Address {}>'.format(self.__str__())


def _match_ops(ops, pattern):
    if len(ops) != len(pattern):
        return False
    for op, pop in zip(ops, pattern):
        if pop != op:
            # -1 means 'data push', whose op is an (op, data) tuple
            if pop == -1 and isinstance(op, tuple):
                continue
            return False

    return True


class Script:

    @classmethod
    def P2SH_script(cls, addr_hash):
        assert len(addr_hash) in (20, 32)
        if len(addr_hash) == 20:
            return P2SH_prefix + addr_hash + P2SH_suffix
        else:
            return P2SH32_prefix + addr_hash + P2SH32_suffix

    @classmethod
    def P2PKH_script(cls, hash160):
        assert len(hash160) == 20
        return P2PKH_prefix + hash160 + P2PKH_suffix

    @classmethod
    def P2PK_script(cls, pubkey):
        return cls.push_data(pubkey) + bytes([OpCodes.OP_CHECKSIG])

    @classmethod
    def multisig_script(cls, m, pubkeys):
        """Returns the script for a pay-to-multisig transaction."""
        n = len(pubkeys)
        if not 1 <= m <= n <= 15:
            raise ScriptError('{:d} of {:d} multisig script not possible'
                              .format(m, n))
        for pubkey in pubkeys:
            PublicKey.validate(pubkey)   # Can be compressed or not
        # See https://bitcoin.org/en/developer-guide
        # 2 of 3 is: OP_2 pubkey1 pubkey2 pubkey3 OP_3 OP_CHECKMULTISIG
        return (cls.push_data(bytes([m]))
                + b''.join(cls.push_data(pubkey) for pubkey in pubkeys)
                + cls.push_data(bytes([n])) + bytes([OpCodes.OP_CHECKMULTISIG]))

    @classmethod
    def push_data(cls, data: Union[bytes, bytearray], *, minimal=True) -> bytes:
        """Returns the OpCodes to push the data on the stack, plus the payload."""
        return push_script_bytes(data, minimal=minimal)

    @classmethod
    def get_ops(cls, script, *, synthesize_minimal_data=True):
        ops = []

        # The unpacks or script[n] below throw on truncated scripts
        try:
            n = 0
            while n < len(script):
                op = script[n]
                n += 1

                if op <= OpCodes.OP_PUSHDATA4:
                    if op < OpCodes.OP_PUSHDATA1:
                        # Raw bytes follow
                        dlen = op
                    elif op == OpCodes.OP_PUSHDATA1:
                        # One-byte length, then data
                        dlen = script[n]
                        n += 1
                    elif op == OpCodes.OP_PUSHDATA2:
                        # Two-byte length, then data
                        dlen, = struct.unpack('<H', script[n: n + 2])
                        n += 2
                    else:  # op == OpCodes.OP_PUSHDATA4
                        # Four-byte length, then data
                        dlen, = struct.unpack('<I', script[n: n + 4])
                        n += 4
                    if n + dlen > len(script):
                        raise IndexError
                    data = script[n:n + dlen]
                    n += dlen
                elif synthesize_minimal_data and OpCodes.OP_1 <= op <= OpCodes.OP_16:
                    # BIP62: 1-byte pushes containing just 0x1 to 0x10 are encoded as single op-codes
                    # We synthesize the data that was originally pushed.
                    data = bytes([1 + (op - OpCodes.OP_1)])
                elif synthesize_minimal_data and op == OpCodes.OP_1NEGATE:
                    # BIP62: 1-byte pushes containing just 0x81 are encoded as single op-codes
                    # We synthesize the data that was originally pushed.
                    data = bytes([0x81])
                else:
                    data = None

                ops.append((op, data))
        except Exception:
            # Truncated script; e.g. tx_hash
            # ebc9fa1196a59e192352d76c0f6e73167046b9d37b8302b6bb6968dfd279b767
            raise ScriptError('truncated script')

        return ops


class Base58Error(Exception):
    """Exception used for Base58 errors."""


class Base58:
    """Class providing base 58 functionality."""

    chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    assert len(chars) == 58
    cmap = {c: n for n, c in enumerate(chars)}

    @staticmethod
    def char_value(c):
        val = Base58.cmap.get(c)
        if val is None:
            raise Base58Error('invalid base 58 character "{}"'.format(c))
        return val

    @staticmethod
    def decode(txt):
        """Decodes txt into a big-endian bytearray."""
        if not isinstance(txt, str):
            raise TypeError('a string is required')

        if not txt:
            raise Base58Error('string cannot be empty')

        value = 0
        for c in txt:
            value = value * 58 + Base58.char_value(c)

        result = int_to_bytes(value)

        # Prepend leading zero bytes if necessary
        count = 0
        for c in txt:
            if c != '1':
                break
            count += 1
        if count:
            result = bytes(count) + result

        return result

    @staticmethod
    def encode(be_bytes):
        """Converts a big-endian bytearray into a base58 string."""
        value = bytes_to_int(be_bytes)

        txt = ''
        while value:
            value, mod = divmod(value, 58)
            txt += Base58.chars[mod]

        for byte in be_bytes:
            if byte != 0:
                break
            txt += '1'

        return txt[::-1]

    @staticmethod
    def decode_check(txt):
        """Decodes a Base58Check-encoded string to a payload.  The version
        prefixes it."""
        be_bytes = Base58.decode(txt)
        result, check = be_bytes[:-4], be_bytes[-4:]
        if check != double_sha256(result)[:4]:
            raise Base58Error('invalid base 58 checksum for {}'.format(txt))
        return result

    @staticmethod
    def encode_check(payload):
        """Encodes a payload bytearray (which includes the version byte(s))
        into a Base58Check string."""
        be_bytes = payload + double_sha256(payload)[:4]
        return Base58.encode(be_bytes)
