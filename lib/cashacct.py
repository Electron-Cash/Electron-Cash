##!/usr/bin/env python3
#
# Electron Cash - A Bitcoin Cash SPV Wallet
# This file Copyright (c) 2019 Calin Culianu <calin.culianu@gmail.com>
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

'''
Cash Accounts related classes and functions.

Note that this file also contains a unique class called `ScriptOutput` (which
inherits from address.py's own ScriptOutput), so always import this file
carefully if also importing address.py.
'''

import re
from . import bitcoin
from . import util
from .address import Address, OpCodes, Script, ScriptError
from .address import ScriptOutput as ScriptOutputBase
from .transaction import BCDataStream

# Cash Accounts protocol code prefix is 0x01010101
# See OP_RETURN prefix guideline: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/op_return-prefix-guideline.md
protocol_code = 0x01010101

activation_height = 563720  # all cash acct registrations are invalid if they appear before this block height
height_modification = activation_height - 100  # compute the cashacct.number by subtracting this value from tx block height

# This RE is used to accept/reject names
name_accept_re = re.compile(r'^[a-zA-Z0-9_]{1,99}$')
# Accept/reject collision_hash -- must be a number string of precisely length 10
collision_hash_accept_re = re.compile(r'^[0-9]{10}$')

# mapping of Address.kind -> cash account data types
_addr_kind_data_types = { Address.ADDR_P2PKH : 0x1, Address.ADDR_P2SH : 0x2 }
_data_types_addr_kind = util.inv_dict(_addr_kind_data_types)

def _i2b(val): return bytes((val,))

class ArgumentError(ValueError):
    '''Raised by various CashAcct functions if the supplied args are bad or
    out of spec.'''

class ScriptOutput(ScriptOutputBase):
    '''A class to encapsulate a Cash Accounts script output. Use the __new__ or
    @classmethod factory methods to create instances. Suitable for including in
    a Transaction as an output.

    Note: This class is named ScriptOutput like its base. This is intentional
    and client code should import this file such that referring to this class
    is module-qualified, eg cashacct.ScriptOutput. '''

    _protocol_prefix = _i2b(OpCodes.OP_RETURN) + _i2b(4) + int.to_bytes(protocol_code, 4, byteorder='big')

    @classmethod
    def protocol_match_fast(cls, script_bytes):
        '''Returns true iff the `script_bytes` at least START with the correct
        protocol code. Useful for fast-matching script outputs and testing
        if they are potential CashAcct registrations.

        `script_bytes` should be the full script as a bytes-like-object,
        including the OP_RETURN byte prefix.'''
        script_bytes = cls._ensure_script(script_bytes)
        return script_bytes.startswith(cls._protocol_prefix)

    @classmethod
    def protocol_match(cls, script_bytes):
        '''Returns true iff the `script_bytes` is a valid Cash Accounts
        registration script (has all the requisite fields, etc).

        This check does parsing and thus is a bit slower than
        `protocol_match_fast` which just looks for a prefix and does no
        parsing.'''
        script_bytes = cls._ensure_script(script_bytes)
        try:
            res = cls.parse_script(script_bytes)
            return bool(res)
        except (ValueError, TypeError):
            return False

    @classmethod
    def is_valid(cls, script):
        '''Alias for protocol_match. Returns true if script is a valid CashAcct
        registration script.'''
        return cls.protocol_match(script)

    def __new__(cls, script, *, number=None, collision_hash=None):
        '''Instantiate from a script (or address.ScriptOutput) you wish to parse.
        Use number= and collision_hash= kwargs if you also have that
        information, otherwise the script will be parsed and self.name and
        self.address will be set.  Raises ArgumentError on invalid script.

        Always has the following attributes defined (even if None):

                name, address, number, collision_hash
        '''
        script = cls._ensure_script(script)
        self = super(__class__, cls).__new__(cls, script)
        self.name, self.address = self.parse_script(self.script)  # raises on error
        self.make_complete(number, collision_hash)  # raises if number is not None and is bad and/or if collision_hash is not None and is bad, otherwise just sets attributes
        return self

    @staticmethod
    def _check_name_address(name, address):
        '''Raises ArgumentError if either name or address are somehow invalid.'''
        if not isinstance(name, str) or not name_accept_re.match(name):
            raise ArgumentError('Invalid name specified: must be an alphanumeric ascii string of length 1-99', name)
        if name != name.encode('ascii', errors='ignore').decode('ascii', errors='ignore'):  # <-- ensure ascii.  Note that this test is perhaps superfluous but the mysteries of unicode and how re's deal with it elude me, so it's here just in case.
            raise ArgumentError('Name must be pure ascii', name)
        if not isinstance(address, Address):
            raise ArgumentError('Address of type \'Address\' expected', address)
        if address.kind not in _addr_kind_data_types:
            raise ArgumentError('Invalid or unsupported address type', address)
        return True

    @staticmethod
    def _check_number_collision_hash(number, collision_hash):
        '''Raises ArgumentError if either number or collision_hash aren't to spec.'''
        if number is not None:  # We don't raise on None
            if not isinstance(number, int) or number < 100:
                raise ArgumentError('Number must be an int >= 100')
        if collision_hash is not None:  # We don't raise on None
            if not isinstance(collision_hash, str) or not collision_hash_accept_re.match(collision_hash):
                raise ArgumentError('Collision hash must be a string numbers, right-padded with zeroes, of length 10')
        return number is not None and collision_hash is not None

    def is_complete(self, fast_check=False):
        '''Returns true iff we have the number and collision_hash data for this
        instance, as well as valid name and valid address.'''
        if fast_check:
            return self.name and self.address and self.number and self.collision_hash
        try:
            return self._check_name_address(self.name, self.address) and self._check_number_collision_hash(self.number, self.collision_hash)
        except ArgumentError:
            return False

    def make_complete(self, number, collision_hash):
        '''Make this ScriptOutput instance complete by filling in the number and
        collision_hash info. Raises ArgumentError on bad/out-of-spec args (None
        args are ok though, the cashacct just won't be complete).'''
        ok = self._check_number_collision_hash(number, collision_hash)
        self.number = number
        self.collision_hash = collision_hash
        return ok

    def __repr__(self):
        return ( f'<ScriptOutput (CashAcct) {self.__str__()} '
                 + f' name={self.name} address={self.address}'
                 + f' number={self.number} collision_hash={self.collision_hash}>' )

    @staticmethod
    def _ensure_script(script):
        '''Returns script or script.script if script is a ScriptOutput instance.
        Raises if script is not bytes and/or not ScriptOutput.  Always returns
        a bytes-like-object.'''
        if isinstance(script, ScriptOutputBase):
            script = script.script
        if not isinstance(script, (bytes, bytearray)):
            raise ArgumentError('Script argument must be either a valid ScriptOutput instance or a bytes-like-object')
        return script

    @classmethod
    def parse_script(cls, script):
        '''Parses `script`, which may be either a ScriptOutput class, or raw
        bytes data. Will raise various exceptions if it cannot parse.  Returns
        (name: str, address: Address) as a tuple. '''
        script = cls._ensure_script(script)
        # Check prefix, length, and that the 'type' byte is one we know about
        if not cls.protocol_match_fast(script) or len(script) < 30 or script[-21] not in _data_types_addr_kind:
            raise ArgumentError('Not a valid CashAcct registration script')
        script_short = script
        try:
            script_short = script[len(cls._protocol_prefix):]  # take off the already-validated prefix
            ops = Script.get_ops(script_short)  # unpack ops
        except Exception as e:
            raise ArgumentError('Bad CashAcct script', script_short.hex()) from e
        # Check for extra garbage at the end, too few items and/or other nonsense
        if not ops or not len(ops) == 2 or not all(len(op) == 2 and op[1] for op in ops):
            raise ArgumentError('CashAcct script parse error', ops)
        name_bytes = ops[0][1]
        type_byte = ops[1][1][0]
        hash160_bytes = ops[1][1][1:]
        try:
            name = name_bytes.decode('ascii')
        except UnicodeError as e:
            raise ArgumentError('CashAcct names must be ascii encoded', name_bytes) from e
        try:
            address = Address(hash160_bytes, _data_types_addr_kind[type_byte])
        except Exception as e:
            # Paranoia -- this branch should never be reached at this point
            raise ArgumentError('Bad address or address could not be parsed') from e

        cls._check_name_address(name, address)  # raises if invalid

        return name, address

    ############################################################################
    #                            FACTORY METHODS                               #
    ############################################################################
    @classmethod
    def create_registration(cls, name, address):
        '''Generate a CashAccounts registration script output for a given
        address. Raises ArgumentError (a ValueError subclass) if args are bad,
        otherwise returns an instance of this class.'''
        cls._check_name_address(name, address)
        # prepare payload
        # From: https://gitlab.com/cash-accounts/specification/blob/master/SPECIFICATION.md
        #
        # Sample payload (hex bytes) for registration of 'bv1' -> bitcoincash:qzgvpjawln2l8wfmsg2qwnnytcua02hy45vpdvrqu5
        # (This example is a real tx with txid: 4a2da2a69fba3ac07b7047dd17927a890091f13a9e89440a4cd4cfb4c009de1f)
        #
        # hex bytes:
        # 6a040101010103627631150190c0cbaefcd5f3b93b8214074e645e39d7aae4ad
        # | | |......|| |....|| | |......................................|
        # | | |......|| |....|| | ↳ hash160 of bitcoincash:qzgvpjawln2l8wfmsg2qwnnytcua02hy45vpdvrqu5
        # | | |......|| |....|| |
        # | | |......|| |....|| ↳ type (01 = p2pkh)
        # | | |......|| |....||
        # | | |......|| |....|↳ OP_PUSH(0x15 = 21)
        # | | |......|| |....|
        # | | |......|| ↳'bv1'
        # | | |......||
        # | | |......|↳OP_PUSH(3)
        # | | |......|
        # | | ↳protocol_code = 0x01010101
        # | |
        # | ↳OP_PUSH(4)
        # |
        # ↳OP_RETURN
        class MyBCDataStream(BCDataStream):
            def push_data(self, data):
                self.input = self.input or bytearray()
                self.input += Script.push_data(data)
        bcd = MyBCDataStream()
        bcd.write(cls._protocol_prefix)  # OP_RETURN -> 0x6a + 0x4 (pushdata 4 bytes) + 0x01010101 (protocol code)
        bcd.push_data(name.encode('ascii'))
        bcd.push_data(
            # type byte: 0x1 for ADDR_P2PKH, 0x2 for ADDR_P2SH
            _i2b(_addr_kind_data_types[address.kind])
            # 20 byte haash160
            + address.hash160
        )

        return cls(bytes(bcd.input))

    @classmethod
    def from_script(cls, script):
        '''Create an instance from a `script`, which may be either a
        ScriptOutput class, or raw bytes data. Will raise various exceptions if
        it cannot parse and/or script is invalid.'''
        return cls(script)


# Helper Functions

def _collision_hash(block_hash, txid):
    ''' Returns the full sha256 collision hash as bytes given the hex strings
    and/or raw bytes as input. May raise ValueError or other. '''
    bh = bytes.fromhex(block_hash) if isinstance(block_hash, str) else block_hash
    tx = bytes.fromhex(txid) if isinstance(txid, str) else txid
    if not all( isinstance(x, (bytes, bytearray)) and len(x) == 32 for x in (bh, tx) ):
        raise ArgumentError('Invalid arguments', block_hash, txid)
    return bitcoin.sha256(bh + tx)

def collision_hash(block_hash, txid):
    ''' May raise if block_hash and txid are not valid hex-encoded strings
    and/or raw bytes, otherwise returns the 0-padded collision hash string
    (always a str of length 10).'''
    ch = _collision_hash(block_hash, txid)[:4]
    ch = ''.join(reversed(str(int.from_bytes(ch, byteorder='big'))))  # convert int to string, reverse it
    ch += '0' * (10 - len(ch))  # pad with 0's at the end
    return ch

def emoji_index(block_hash, txid):
    ''' May raise. Otherwise returns an emoji index from 0 to 99. '''
    ch = _collision_hash(block_hash, txid)[-4:]
    return int.from_bytes(ch, byteorder='big') % 100

emoji_list = [ 128123, 128018, 128021, 128008, 128014, 128004, 128022, 128016,
               128042, 128024, 128000, 128007, 128063, 129415, 128019, 128039,
               129414, 129417, 128034, 128013, 128031, 128025, 128012, 129419,
               128029, 128030, 128375, 127803, 127794, 127796, 127797, 127809,
               127808, 127815, 127817, 127819, 127820, 127822, 127826, 127827,
               129373, 129381, 129365, 127805, 127798, 127812, 129472, 129370,
               129408, 127850, 127874, 127853, 127968, 128663, 128690, 9973,
               9992, 128641, 128640, 8986, 9728, 11088, 127752, 9730, 127880,
               127872, 9917, 9824, 9829, 9830, 9827, 128083, 128081, 127913,
               128276, 127925, 127908, 127911, 127928, 127930, 129345, 128269,
               128367, 128161, 128214, 9993, 128230, 9999, 128188, 128203,
               9986, 128273, 128274, 128296, 128295, 9878, 9775, 128681,
               128099, 127838 ]

def emoji(block_hash, txid):
    ''' Returns the emoji character givern a block hash and txid. May raise.'''
    return chr(emoji_list[emoji_index(block_hash, txid)])

def number_from_block_height(block_height):
    ''' Given a block height, returns the cash account 'number' (as int).
    This is simply the block height minus 563620. '''
    return block_height - height_modification
