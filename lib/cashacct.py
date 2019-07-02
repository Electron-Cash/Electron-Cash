##!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
import requests
import threading
import queue
import random
import time
from collections import defaultdict, namedtuple
from typing import List, Tuple
from . import bitcoin
from . import util
from .address import Address, OpCodes, Script, ScriptError
from .address import ScriptOutput as ScriptOutputBase
from .transaction import BCDataStream, Transaction
from . import verifier
from . import blockchain
from . import caches

# Cash Accounts protocol code prefix is 0x01010101
# See OP_RETURN prefix guideline: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/op_return-prefix-guideline.md
protocol_code = bytes.fromhex("01010101")

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
    is module-qualified, eg cashacct.ScriptOutput.

    Note2: that the Transaction class automatically deserializes TYPE_SCRIPT
    outputs to instances of this class if the script contents match the
    CashAccounts protocol (based on boolean result of protocol_match() below).
    See the address.ScriptOutput 'protocol' mechanism (in address.py).'''

    _protocol_prefix = _i2b(OpCodes.OP_RETURN) + _i2b(4) + protocol_code

    # Additional attributes outside of the base class tuple's 1 attribute
    attrs_extra = ( 'name', 'address', 'number', 'collision_hash', 'emoji' )

    @classmethod
    def _protocol_match_fast(cls, script_bytes):
        '''Returns true iff the `script_bytes` at least START with the correct
        protocol code. Useful for fast-matching script outputs and testing
        if they are potential CashAcct registrations.

        `script_bytes` should be the full script as a bytes-like-object,
        including the OP_RETURN byte prefix.'''
        return script_bytes.startswith(cls._protocol_prefix)

    @classmethod
    def protocol_match(cls, script_bytes):
        '''Returns true iff the `script_bytes` is a valid Cash Accounts
        registration script (has all the requisite fields, etc).'''
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

    def __new__(cls, script, *, number=None, collision_hash=None, emoji=None):
        '''Instantiate from a script (or address.ScriptOutput) you wish to parse.
        Use number=, collision_hash=, emoji= kwargs if you also have that
        information and want to store it in this instance.

        The script will be parsed and self.name and self.address will be set
        regardless.  Raises ArgumentError on invalid script.

        Always has the following attributes defined (even if None):

                name, address, number, collision_hash, emoji
        '''
        if isinstance(script, cls) and not any((number, collision_hash, emoji)):
            # copy constructor work-alike
            number, collision_hash, emoji = script.number, script.collision_hash, script.emoji
        script = cls._ensure_script(script)
        self = super(__class__, cls).__new__(cls, script)
        self.name, self.address = self.parse_script(self.script)  # raises on error
        self.number, self.collision_hash, self.emoji = None, None, None  # ensure attributes defined
        self.make_complete2(number, collision_hash, emoji=emoji)  # raises if number  bad and/or if collision_hash is bad, otherwise just sets attributes. None ok for args.
        return self

    def copy(self):
        ''' Creates a copy. '''
        return ScriptOutput(self)

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
            if isinstance(collision_hash, int): collision_hash = str(collision_hash)  # grr.. it was an int
            if not isinstance(collision_hash, str) or not collision_hash_accept_re.match(collision_hash):
                raise ArgumentError('Collision hash must be a number string, right-padded with zeroes, of length 10')
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

    def make_complete2(self, number, collision_hash, *, emoji=None):
        '''Make this ScriptOutput instance complete by filling in the number and
        collision_hash info. Raises ArgumentError on bad/out-of-spec args (None
        args are ok though, the cashacct just won't be complete).'''
        ok = self._check_number_collision_hash(number, collision_hash)
        self.number = number
        self.collision_hash = collision_hash
        self.emoji = emoji or self.emoji
        return ok

    def make_complete(self, block_height=None, block_hash=None, txid=None):
        '''Make this ScriptOutput instance complete by specifying block height,
        block_hash (hex string or bytes), and txid (hex string or bytes)'''
        ch = collision_hash(block_hash, txid) if block_hash and txid else None
        num = bh2num(block_height) if block_height is not None else None
        em = emoji(block_hash, txid) if ch else None
        return self.make_complete2(num, ch, emoji=em)

    def clear_completion(self):
        '''Make this ScriptOutput incomplete again.'''
        self.number = self.collision_hash = self.emoji = None

    def to_ui_string(self, ignored=True):
        ''' Overrides super to add cashaccount data '''
        s = super().to_ui_string(ignored)
        extra = []
        for a in __class__.attrs_extra:
            val = getattr(self, a, None)
            if val is not None:
                extra.append(f'{a}={val}')
        extra = ' '.join(extra)
        return f'{s} [CashAcct: {extra}]' if extra else f'{s} [CashAcct]'

    def block_height(self) -> int:
        ''' Convenience method to returns the block_height.
        Requires that this class have its 'number' attribute not None, otherwise
        returns 0. '''
        return self.number + height_modification if self.number else 0

    def __repr__(self):
        return f'<ScriptOutput (CashAcct) {self.__str__()}>'

    def __eq__(self, other):
        res = super().__eq__(other)
        if res and isinstance(other, __class__) and self is not other:
            # awkward.. we do a deep check if self and other are both this type
            for a in __class__.attrs_extra:
                res = res and getattr(self, a, None) == getattr(other, a, None)
                if not res:
                    break
        return res

    def __ne__(self, other):
        return not self.__eq__(other)

    @staticmethod
    def _ensure_script(script):
        '''Returns script or script.script if script is a ScriptOutput instance.
        Raises if script is not bytes and/or not ScriptOutput.  Always returns
        a bytes-like-object.'''
        if isinstance(script, ScriptOutputBase):
            script = script.script
        script = _ensure_bytes(script, "Script")
        return script

    @classmethod
    def parse_script(cls, script):
        '''Parses `script`, which may be either a ScriptOutput class, or raw
        bytes data. Will raise various exceptions if it cannot parse.  Returns
        (name: str, address: Address) as a tuple. '''
        script = cls._ensure_script(script)
        # Check prefix, length, and that the 'type' byte is one we know about
        if not cls._protocol_match_fast(script) or len(script) < 30 or script[-21] not in _data_types_addr_kind:
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
    def from_script(cls, script, *,
                    # these two optional args, if specified, take precedence
                    number=None, collision_hash=None,
                    # additionally these other args can be specified to
                    # have this class calculate number and collision_hash
                    # for you. Use either set of optional args but not both.
                    block_height=None,  # if set, self.number will be set. Cannot specify this & number
                    # Cannot specify these & collision_hash at the same time
                    block_hash=None, txid=None  # if block_hash and txid are set, .emoji will be set too on returned class (along with .collision_hash)
                    ):
        '''Create an instance from a `script`, which may be either a
        ScriptOutput class, or raw bytes data. Will raise various exceptions if
        it cannot parse and/or script or args are invalid.'''
        if block_height is not None:
            if number is not None:
                raise ArgumentError('Cannot specify both block_height and number')
            number = number_from_block_height(block_height)
        tup = (block_hash, txid)
        myemoji=None
        if any(tup):
            if not all(tup):
                raise ArgumentError('block_hash and txid must both be specified or not specified at all')
            if collision_hash is not None:
                raise ArgumentError('Cannot specify collision_hash, block_hash & txid together')
            collision_hash = chash(block_hash, txid)
            myemoji = emoji(block_hash, txid)
        return cls(script, number=number, collision_hash=collision_hash, emoji=myemoji)

    @classmethod
    def from_dict(cls, d: dict) -> object:
        ''' Create an isntance from a dict created by to_dict. '''
        return cls(d['script'],  # hex -> bytes will get auto-converted in c'tor
                   number=d.get('number'), collision_hash=d.get('collision_hash'),
                   emoji=d.get('emoji'))

    def to_dict(self) -> dict:
        assert self.script
        d = { 'script' : self.script.hex() }
        if self.number is not None: d['number'] = self.number
        if self.collision_hash is not None: d['collision_hash'] = self.collision_hash
        if self.emoji is not None: d['emoji'] = self.emoji
        return d

# register the above class with the ScriptOutput protocol system
ScriptOutputBase.protocol_classes.add(ScriptOutput)

# Helper Functions
def _ensure_bytes(arg, argname='Arg'):
    if isinstance(arg, str):
        try:
            arg = bytes.fromhex(arg)
        except ValueError as e:
            raise ArgumentError(f'{argname} could not be binhex decoded', arg) from e
    if not isinstance(arg, (bytes, bytearray)):
        raise ArgumentError(f'{argname} argument not a bytes-like-object', arg)
    return arg

def _collision_hash(block_hash, txid):
    ''' Returns the full sha256 collision hash as bytes given the hex strings
    and/or raw bytes as input. May raise ValueError or other. '''
    bh = _ensure_bytes(block_hash, 'block_hash')
    tx = _ensure_bytes(txid, 'txid')
    if not all( len(x) == 32 for x in (bh, tx) ):
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

chash = collision_hash  # alias.

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

_emoji = emoji  # alias for internal use if names clash

def number_from_block_height(block_height):
    ''' Given a block height, returns the cash account 'number' (as int).
    This is simply the block height minus 563620. '''
    return int(block_height - height_modification)

def number_to_block_height(number):
    ''' Reciprocal of number_to_block_height '''
    return int(number + height_modification)

bh2num = number_from_block_height  # alias
num2bh = number_to_block_height  # alias

#### Lookup & Verification

class Info(namedtuple("Info", "name, address, number, collision_hash, emoji, txid")):
    @classmethod
    def from_script(cls, script, txid):
        ''' Converts a script to an Info object. Note that ideally the passed-in
        script.is_complete() should be True otherwise most of the fields of the
        returned Info object will be None.'''
        return cls(name=script.name,
                   address=script.address,
                   number=script.number,
                   collision_hash=script.collision_hash,
                   emoji=script.emoji,
                   txid=txid)

    def to_script(self):
        ''' Inverse of from_script, returns a (script, txid) tuple. '''
        script = ScriptOutput.create_registration(name=self.name, address=self.address)
        script.make_complete2(number=self.number, collision_hash=self.collision_hash,
                              emoji=self.emoji)
        return script, self.txid

    @classmethod
    def from_regtx(cls, regtx):
        return cls.from_script(regtx.script, regtx.txid)


servers = [
    "https://cashacct.imaginary.cash",
    "https://api.cashaccount.info"
]

debug = False

def lookup(server, number, name=None, collision_prefix=None, timeout=10.0, exc=[]) -> tuple:
    ''' Synchronous lookup, returns a tuple of:

            block_hash, List[ RegTx(txid, script) namedtuples ]

    or None on error. Note the .script in each returned RegTx will always have
    .is_complete() == True (has all fields filled-in from the lookup server).

    Optionally, pass a list as the `exc` parameter and the exception encountered
    will be returned to caller by appending to the list.

    Use `collision_prefix` and `name` to narrow the search, otherwise all
    results (if any) for a particular block (number) are returned.

    Name matching is case-insensitive.  Additionally, as of the time of this
    writing, collision_prefix without a specified name will always return no
    results from the lookup server. Also, name should be a complete name and not
    a substring.

    Note:
    Results are not verified by this function and further verification is
    necessary before presenting any results to the user for the purposes of
    sending funds.'''
    url = f'{server}/lookup/{number}'
    if name:
        name = name.strip().lower()
        url += f'/{name}'
    if collision_prefix:
        collision_prefix = collision_prefix.strip()
        url += f'/{collision_prefix}'
    try:
        ret = []
        r = requests.get(url, allow_redirects=True, timeout=timeout) # will raise requests.exceptions.Timeout on timeout
        r.raise_for_status()
        d = r.json()
        if not isinstance(d, dict) or not d.get('results') or not isinstance(d.get('block'), int):
            raise RuntimeError('Unexpected response', r.text)
        res, block = d['results'], int(d['block'])
        number = bh2num(block)
        if not isinstance(res, list) or number < 100:
            raise RuntimeError('Bad response')
        block_hash, header_prev = None, None
        for d in res:
            txraw = d['transaction']
            header_hex = d['inclusion_proof'][:blockchain.HEADER_SIZE*2].lower()
            header_prev = header_prev or header_hex
            if len(header_hex)//2 != blockchain.HEADER_SIZE:
                raise AssertionError('Could not get header')
            if not block_hash:
                block_hash = blockchain.hash_header_hex(header_hex)
            elif header_prev != header_hex:
                raise AssertionError('Differing headers in results')
            tx = Transaction(txraw)
            txid = Transaction._txid(txraw)
            op_return_count = 0
            tx_regs = []  # there should be exactly 1 of these per tx, as per cash acount spec.. we reject tx's with more than 1 op_return
            for _typ, script, value in tx.outputs():
                if isinstance(script, ScriptOutputBase):
                    if script.is_opreturn():
                        op_return_count += 1
                    if isinstance(script, ScriptOutput):  # note ScriptOutput here is our subclass defined at the top of this file, not addess.ScriptOutput
                        script.make_complete(block_height=block, block_hash=block_hash, txid=txid)
                        tx_regs.append(CashAcct.RegTx(txid, script))
            if len(tx_regs) == 1 and op_return_count == 1:
                # we only accept tx's with exactly 1 OP_RETURN, as per the spec
                ret.extend(tx_regs)
            else:
                if debug:
                    util.print_error(f"lookup: {txid} had no valid registrations in it using server {server} (len(tx_regs)={len(tx_regs)} op_return_count={op_return_count})")
        if debug:
            util.print_error(f"lookup: found {len(ret)} reg txs at block height {block} (number={number})")
        return block_hash, ret
    except Exception as e:
        if debug:
            util.print_error("lookup:", repr(e))
        if isinstance(exc, list):
            exc.append(e)

def lookup_asynch(server, number, success_cb, error_cb=None,
                  name=None, collision_prefix=None, timeout=10.0):
    ''' Like lookup() above, but spawns a thread and does its lookup
    asynchronously.

    success_cb - will be called on successful completion with a single arg:
                 a tuple of (block_hash, the results list).
    error_cb   - will be called on failure with a single arg: the exception
                 (guaranteed to be an Exception subclass).

    In either case one of the two callbacks will be called. It's ok for
    success_cb and error_cb to be the same function (in which case it should
    inspect the arg passed to it). Note that the callbacks are called in the
    context of the spawned thread, (So e.g. Qt GUI code using this function
    should not modify the GUI directly from the callbacks but instead should
    emit a Qt signal from within the callbacks to be delivered to the main
    thread as usual.) '''

    def thread_func():
        exc = []
        res = lookup(server=server, number=number, name=name, collision_prefix=collision_prefix, timeout=timeout, exc=exc)
        called = False
        if res is None:
            if callable(error_cb) and exc:
                error_cb(exc[-1])
                called = True
        else:
            success_cb(res)
            called = True
        if not called:
            # this should never happen
            util.print_error("WARNING: no callback called for ", threading.current_thread().name)
    t = threading.Thread(name=f"CashAcct lookup_asynch: {server} {number} ({name},{collision_prefix},{timeout})",
                         target=thread_func, daemon=True)
    t.start()

def lookup_asynch_all(number, success_cb, error_cb=None, name=None,
                      collision_prefix=None, timeout=10.0):
    ''' Like lookup_asynch above except it tries *all* the hard-coded servers
    from `servers` and if all fail, then calls the error_cb exactly once.
    If any succeed, calls success_cb exactly once.

    Note: in this function success_cb is called with TWO args:
      - first arg is the tuple of (block_hash, regtx-results-list)
      - the second arg is the 'server' that was successful (server string)

    One of the two callbacks are guaranteed to be called in either case.

    Callbacks are called in another thread context so GUI-facing code should
    be aware of that fact (see nodes for lookup_asynch above).  '''
    assert servers, "No servers hard-coded in cashacct.py. FIXME!"
    my_servers = servers.copy()
    random.shuffle(my_servers)
    N = len(my_servers)
    lock = threading.Lock()
    n_ok, n_err = 0, 0
    def on_succ(res, server):
        nonlocal n_ok
        with lock:
            #util.print_error("success", n_ok+n_err)
            if n_ok:
                return
            n_ok += 1
        success_cb(res, server)
    def on_err(exc):
        nonlocal n_err
        with lock:
            #util.print_error("error", n_ok+n_err)
            if n_ok:
                return
            n_err += 1
            if n_err < N:
                return
        if error_cb:
            #util.print_error("calling err")
            error_cb(exc)
    for server in my_servers:
        #util.print_error("server:", server)
        lookup_asynch(server, number = number,
                      success_cb = lambda res,_server=server: on_succ(res,_server),
                      error_cb = on_err,
                      name = name, collision_prefix = collision_prefix, timeout = timeout)

class ProcessedBlock:
    __slots__ = ( 'hash',  # str binhex block header hash
                  'height',  # int blockchain block height
                  'status_hash',  # str binhex computed value derived from Hash(hash + height + reg_txs..) see compute_status_hash
                  'reg_txs' )  # dict of txid -> RegTx(txid, script) namedtuple

    def __init__(self, *args, **kwargs):
        assert not args, "This class only takes kwargs"
        assert all(k in self.__slots__ for k in kwargs), "Unknown kwarg specified"
        for s in self.__slots__:
            setattr(self, s, kwargs.get(s))
        assert self.reg_txs is None or (isinstance(self.reg_txs, dict) and all(bytes.fromhex(k).hex() == bytes.fromhex(v.txid).hex() for k,v in self.reg_txs.items()))
        assert self.hash is None or (isinstance(self.hash, str) and bytes.fromhex(self.hash).hex())
        assert self.height is None or (isinstance(self.height, int) and self.height >= activation_height)
        self.status_hash or self.set_status_hash()  # tries to recompute if not provided
        assert self.status_hash is None or (isinstance(self.status_hash, str) and bytes.fromhex(self.status_hash))

    def __repr__(self):
        return ( f'<ProcessedBlock at 0x{id(self):x} hash={self.hash} height={self.height} status_hash={self.status_hash}'
                 + f' with {0 if not self.reg_txs else len(self.reg_txs)} registration(s)>')

    def set_status_hash(self) -> str:
        self.status_hash = self.compute_status_hash(self.hash, self.height, self.reg_txs)
        return self.status_hash

    def set_hash_from_raw_header_hex(self, rawhex : str) -> str:
        assert len(rawhex) >= blockchain.HEADER_SIZE * 2
        self.hash = blockchain.hash_header_hex(rawhex[:blockchain.HEADER_SIZE*2])
        return self.hash

    @staticmethod
    def compute_status_hash(hash_hex : str, height : int, reg_txs : dict) -> str:
        if hash_hex and isinstance(height, int) and isinstance(reg_txs, dict):
            ba = bytearray()
            ba.extend(int.to_bytes(height, length=4, byteorder='little'))
            ba.extend(bytes.fromhex(hash_hex))
            for txid in sorted(reg_txs.keys()):
                ba.extend(bytes.fromhex(txid))
            status_hash = bitcoin.hash_encode(bitcoin.Hash(ba))
            return status_hash

    def __eq__(self, other):
        if other is self: return True
        if isinstance(other, ProcessedBlock):
            return bool(self.hash == other.hash and self.height == other.height and (self.status_hash or self.set_status_hash()) == (other.status_hash or other.set_status_hash()))
        return False

    def __neq__(self, other):
        return not self.__eq__(other)


class CashAcct(util.PrintError, verifier.SPVDelegate):
    ''' Class implementing cash account subsystem such as verification, etc. '''

    # info for a registration tx. may or may not be currently verified
    RegTx = namedtuple("RegTx", "txid, script")
    # info for a verified RegTx.  Invariant should be all VerifTx's have a
    # corrseponding RegTx but not necessarily vice-versa.
    VerifTx = namedtuple("VerifTx", "txid, block_height, block_hash")

    def __init__(self, wallet):
        assert wallet, "CashAcct cannot be instantiated without a wallet"
        self.wallet = wallet
        self.network = None
        self.verifier = None
        self.lock = threading.Lock()  # note, this lock is subordinate to wallet.lock and should always be taken AFTER wallet.lock and never before

        self._init_data()

    def _init_data(self):
        self.wallet_reg_tx = dict() # dict of txid -> RegTx
        self.ext_reg_tx = dict() # dict of txid -> RegTx

        self.v_tx = dict() # dict of txid -> VerifTx
        self.v_by_addr = defaultdict(set) # dict of addr -> set of txid
        self.v_by_name = defaultdict(set) # dict of lowercased name -> set of txid

        self.ext_unverif = dict()  # ephemeral (not saved) dict of txid -> block_height. This is however re-computed in load() (TODO: see if this should not be the case)

        self.ext_incomplete_tx = dict() # ephemeral (not saved) dict of txid -> RegTx (all regtx's are incomplete here)

        # minimal collision hash encodings cache. keyed off (name.lower(), number, collision_hash) -> '03' string or '' string
        self.minimal_ch_cache = caches.ExpiringCache(name=f"{self.wallet.diagnostic_name()} - CashAcct minimal collision_hash cache", timeout=3600.0)

        # Dict of block_height -> ProcessedBlock
        self.processed_blocks = caches.ExpiringCache(name=f"{self.wallet.diagnostic_name()} - CashAcct processed block cache", maxlen=5000, timeout=3600.0)

    def diagnostic_name(self):
        return f'{self.wallet.diagnostic_name()}.{__class__.__name__}'

    def start(self, network):
        assert network, "CashAcct start requires a valid network instance"
        if not self.network:
            assert not self.verifier
            self.network = network
            # our own private verifier, we give it work via the delegate methods
            self.verifier = verifier.SPV(self.network, self)
            self.network.add_jobs([self.verifier])
            util.finalization_print_error(self.verifier)
            self.network.register_callback(self._fw_wallet_updated, ['wallet_updated'])

    def stop(self):
        if self.verifier:
            assert self.network
            self.network.unregister_callback(self._fw_wallet_updated)
            self.verifier.release()
            self.verifier = None
            self.network = None

    def fmt_info(self, info : Info, minimal_chash: str = None) -> str:
        ''' Given an Info object, returns a string of the form:

        name#123.1234;
        name2#100;
        name3#101.1234567890;

        (Note that the returned string will always end in a semicolon.)

        Will implicitly go out to network to cache the minimal_chash value
        if minimal_chash==None.. such that subsequent calls may return
        a shortened version once the minimal_chash is computed.'''
        name, number, chash = info.name, info.number, info.collision_hash
        if minimal_chash is None:
            minimal_chash = self.get_minimal_chash(name, number, chash)
        if minimal_chash: minimal_chash = '.' + minimal_chash
        return f"{name}#{number}{minimal_chash};"

    @classmethod
    def parse_string(cls, s : str) -> tuple:
        ''' Returns a (name, number, collision_prefix) tuple on parse success
        of a string of the form: "name#100" or "name#100.12" or "name#100.123;"
        (trailing ; is ignored).

        Returns None on parse failure.

        Note:
            - number must always be >= 100 otherwise None is returned. e.g.
              mark#99 is bad but mark#100 is good.
            - collision_prefix must be empty or length <= 10 otherwise None is
              returned.  e.g. mark#100.01234567899 is too long but mark#100.0123456789 is ok

        Does not raise, merely returns None on all errors.'''
        s = s.strip()
        while s.endswith(';'):
            s = s[:-1]  # strip trailing ;
        parts = s.split('#')
        if len(parts) != 2:
            return None
        name, therest = parts
        if not name_accept_re.match(name):
            return None
        parts = therest.split('.')
        if len(parts) == 1:
            number = parts[0]
            collision_prefix = ''
        elif len(parts) == 2:
            number, collision_prefix = parts
        else:
            return None
        try:
            number = int(number)
            collision_prefix = collision_prefix and str(int(collision_prefix))  # make sure it is all numbers
        except:
            return None
        if number < 100:
            return None
        if len(collision_prefix) > 10:
            return None
        return name, number, collision_prefix


    def get_minimal_chash(self, name, number, collision_hash) -> str:
        ''' Returns a string of the minimal collision hash for a given
        name, number, collision_hash combination. This initially will just
        return collision_hash, but will go out to the network and
        subsequent calls will return the cached results from the asynch. network
        lookup should it complete successfully. Note that cached results get
        saved to wallet storage, so over the course of the life of a wallet
        at least the GUI for the wallet's own addresses should contain correct
        results here. '''
        lname = name.lower()
        key = (lname, number, collision_hash)
        with self.lock:
            found = self.minimal_ch_cache.get(key)
        if found is not None:
            return found
        else:
            def do_lookup():
                t0 = time.time()
                def on_success(pb : ProcessedBlock):
                    i = 0
                    found = None
                    block_hash, res_dict = pb.hash, pb.reg_txs
                    num_res = int(bool(res_dict) and len(res_dict))
                    if num_res > 1:
                        i = 1
                        N = len(collision_hash)
                        for txid, rtx in res_dict.items():
                            if rtx.script.name.lower() != lname:
                                continue
                            ch = rtx.script.collision_hash
                            if ch == collision_hash and number == rtx.script.number:
                                found = rtx
                                continue
                            while i < N and ch.startswith(collision_hash[:i]):
                                i += 1
                    elif num_res:
                        rtx = list(res_dict.values())[0]
                        if rtx.script.collision_hash == collision_hash:
                            found = rtx
                    if not found:
                        # hmm. empty results.. or bad lookup. in either case,
                        # don't cache anything.
                        self.print_error("get_minimal_chash: no results found for", *key, "(server =", server, ")")
                        return
                    minimal_chash = collision_hash[:i]
                    with self.lock:
                        self.minimal_ch_cache.put(key, minimal_chash)
                    self.print_error(f"get_minimal_chash: network lookup completed in {time.time()-t0:1.2f} seconds")
                    network = self.network  # capture network obj to avoid race conditions with self.stop()
                    if network and found and minimal_chash != collision_hash:
                        network.trigger_callback('ca_updated_minimal_chash', self, Info.from_regtx(found), minimal_chash)
                # /on_success
                self.verify_block_asynch(number=number, success_cb=on_success)
            if self.network:  # only do this if not 'offline'
                do_lookup()  # start the asynch lookup
            # Immediately return the long-form chash so we give the caller a
            # result immediately, even if it is not the final result.
            # The caller should subscribe to the ca_updated_minimal_chash
            # network signal to get final minimal_chash when it is ready.
            return collision_hash

    def get_cashaccounts(self, domain=None, inv=False) -> List[Info]:
        ''' Returns a list of Info objects for verified cash accounts in domain.
        Domain must be an iterable of addresses (either wallet or external).
        If domain is None, every verified cash account we know about is returned.

        If inv is True, then domain specifies addresses NOT to include
        in the results (i.e. eevery verified cash account we know about not in
        domain be returned). '''
        if domain is None:
            domain = self.v_by_addr if not inv else set()
        ret = []
        seen = set()
        with self.lock:
            if inv:
                domain = set(self.v_by_addr) - set(domain)
            for addr in domain:
                txids = self.v_by_addr.get(addr, set())
                for txid in txids:
                    script = self._find_script(txid)
                    if script and txid not in seen:
                        seen.add(txid)
                        ret.append(Info.from_script(script, txid))

        return ret

    def get_wallet_cashaccounts(self) -> List[Info]:
        ''' Convenience method, returns all the verified cash accounts we
        know about for wallet addresses only. '''
        return self.get_cashaccounts(domain=self.wallet.get_addresses())

    def get_external_cashaccounts(self) -> List[Info]:
        ''' Convenience method, retruns all the verified cash accounts we
        know about that are not for wallet addresses. '''
        return self.get_cashaccounts(domain=self.wallet.get_addresses(), inv=True)


    def load(self):
        ''' Note: loading should happen before threads are started, so no lock
        is needed.'''
        self._init_data()
        dd = self.wallet.storage.get('cash_accounts_data', {})
        #self.print_error("LOADED:", dd)
        wat_d = dd.get('wallet_reg_tx', {})
        eat_d = dd.get('ext_reg_tx', {})
        vtx_d = dd.get('verified_tx', {})
        min_enc_l = dd.get('minimal_ch_cache', [])

        seen_scripts = {}

        for txid, script_dict in wat_d.items():
            txid = txid.lower()
            script = ScriptOutput.from_dict(script_dict)
            if script.is_complete():
                # sanity check
                seen_scripts[txid] = script
                self.wallet_reg_tx[txid] = self.RegTx(txid, script)
        for txid, script_dict in eat_d.items():
            script = ScriptOutput.from_dict(script_dict)
            if script.is_complete() and txid not in seen_scripts:
                # sanity check
                seen_scripts[txid] = script
                self.ext_reg_tx[txid] = self.RegTx(txid, script)
        for txid, info in vtx_d.items():
            block_height, block_hash = info
            script = seen_scripts.get(txid)
            if script:
                self._add_vtx(self.VerifTx(txid, block_height, block_hash), script)
        for item in min_enc_l:
            value = item[-1]
            key = item[:-1]
            self.minimal_ch_cache.put(tuple(key), value)  # re-populate the cache

        # re-enqueue previously unverified for verification.
        # they may come from either wallet or external source, but we
        # enqueue them with the private verifier here.
        # FIXME: This means that failed/bad verifications will forever retry
        # on wallet restart. TODO: handle this situation.
        # FIXME2: Figure out how to deal with actual chain reorgs and detecting
        # when a cash account no longer belongs to the best chain.  The situation
        # now is we will forever try and verify them each wallet startup...
        d = self.ext_reg_tx.copy()
        d.update(self.wallet_reg_tx)
        for txid, item in d.items():
            if txid not in self.v_tx and item.script.number is not None and item.script.number >= 100:
                self.ext_unverif[txid] = num2bh(item.script.number)

        # Note that 'wallet.load_transactions' will be called after this point
        # in the wallet c'tor and it will take care of removing wallet_reg_tx
        # and v_tx entries from self if it detects unreferenced transactions in
        # history (via the remove_transaction_hook callback).


    def save(self, write=False):
        '''
        FYI, current data model is:

        RegTx = namedtuple("RegTx", "txid, script")
        VerifTx = namedtuple("VerifTx", "txid, block_height, block_hash")

        self.wallet_reg_tx = dict() # dict of txid -> RegTx
        self.ext_reg_tx = dict() # dict of txid -> RegTx

        self.v_tx = dict() # dict of txid -> VerifTx
        self.v_by_addr = defaultdict(set) # dict of addr -> set of txid
        self.v_by_name = defaultdict(set) # dict of lowercased name -> set of txid
        '''

        # This is just scratch code.. TODO: IMPLEMENT
        wat_d, eat_d, vtx_d = dict(), dict(), dict()
        min_enc_l = list()
        with self.lock:
            for txid, rtx in self.wallet_reg_tx.items():
                wat_d[txid] = rtx.script.to_dict()
            for txid, rtx in self.ext_reg_tx.items():
                eat_d[txid] = rtx.script.to_dict()
            for txid, vtx in self.v_tx.items():
                vtx_d[txid] = [vtx.block_height, vtx.block_hash]
            for key, tup in self.minimal_ch_cache.copy_dict().items():
                value = tup[-1]
                if value is None:
                    # we sometimes write 'None' to the cache to invalidate
                    # items but don't delete the entry.  Skip these.
                    continue
                min_enc_l.append([*key, value])

        data =  {
                    'wallet_reg_tx' : wat_d,
                    'ext_reg_tx'    : eat_d,
                    'verified_tx'   : vtx_d,
                    'minimal_ch_cache' : min_enc_l,
                }

        self.wallet.storage.put('cash_accounts_data', data)

        #self.print_error("SAVED:", data)

        if write:
            self.wallet.storage.write()

    def find_verified(self, name: str, number: int = None, collision_prefix: str = None) -> List[Info]:
        ''' Returns a list of Info objects for verified cash accounts matching
        lowercased name.  Optionally you can narrow the search by specifying
        number (int) and a collision_prefix (str of digits) '''
        ret = []
        with self.lock:
            name = name.lower()
            s = self.v_by_name.get(name, set())
            for txid in s:
                script = self._find_script(txid, False)
                if script:
                    if script.name.lower() != name:
                        self.print_error(f"find: FIXME -- v_by_name has inconsistent data for {txid}, name {name} != {script.name}")
                        continue
                    if not script.is_complete():
                        self.print_error(f"find: FIXME -- v_by_name has a script that is not 'complete' for {txid} name='{name}'")
                        continue
                    if number is not None and script.number != number:
                        continue
                    if collision_prefix is not None and not script.collision_hash.startswith(collision_prefix):
                        continue
                    ret.append(Info.from_script(script, txid))
        return ret

    def add_ext_tx(self, txid : str, script : ScriptOutput):
        ''' This will add txid to our ext_tx cache, and kick off verification,
        but only if it's not verified already and/or not in wallet_reg_tx. '''
        if not isinstance(script, ScriptOutput) or not script.is_complete():
            raise ArgumentError("Please pass an 'is_complete' script to add_ext_tx")
        with self.lock:
            if txid not in self.wallet_reg_tx:
                self.ext_reg_tx[txid] = self.RegTx(txid, script)
            if txid not in self.v_tx:
                self.ext_unverif[txid] = num2bh(script.number)

    def has_tx(self, txid: str) -> bool:
        ''' Returns true if we know about a complete tx, whether verified or not. '''
        with self.lock:
            return bool(self._find_script(txid, False))

    def is_verified(self, txid: str) -> bool:
        with self.lock:
            return txid in self.v_tx

    def add_ext_incomplete_tx(self, txid : str, block_height : int, script : ScriptOutput):
        if not isinstance(script, ScriptOutput) or not isinstance(block_height, (int, float)) or not txid or not isinstance(txid, str):
            raise ArgumentError("bad args to add_ext_incomplete_tx")
        script.number = bh2num(block_height)
        if script.number < 100:
            raise ArgumentError("bad block height")
        with self.lock:
            self.ext_incomplete_tx[txid] = self.RegTx(txid, script)
            self.ext_unverif[txid] = block_height


    @staticmethod
    def _do_verify_block_argchecks(network, number, exc=[], server='https://unknown'):
        if not isinstance(number, int) or number < 100:
            raise ArgumentError('number must be >= 100')
        if not isinstance(server, str) or not server:
            raise ArgumentError('bad server arg')
        if not isinstance(exc, list):
            raise ArgumentError('bad exc arg')
        if not network:
            exc.append(RuntimeError('no network'))
            return False
        return True

    def verify_block_asynch(self, number : int, success_cb=None, error_cb=None, timeout=10.0):
        ''' Tries all servers. Calls success_cb with the verified ProcessedBlock
        as the single argument on first successful retrieval of the block.
        Calls error_cb with the exc as the only argument on failure. Guaranteed
        to call 1 of the 2 callbacks in either case.  Callbacks are optional
        and won't be called if specified as None. '''
        network = self.network # capture network object in case it goes away while we are running
        exc = []
        if not self._do_verify_block_argchecks(network=network, number=number, exc=exc):
            if error_cb: error_cb((exc and exc[-1]) or RuntimeError('error'))
            return
        def on_error(exc):
            if error_cb:
                error_cb(exc)
        def on_success(res, server):
            pb = self._verify_block_synch_inner(res, network, server, number, True, timeout, exc)
            if pb:
                if success_cb:
                    success_cb(pb)
            else:
                on_error(exc[-1])
        return lookup_asynch_all(number=number, success_cb=on_success, error_cb=on_error, timeout=timeout)

    def verify_block_synch(self, server : str, number : int, verify_txs=True, timeout=10.0, exc=[]) -> ProcessedBlock:
        ''' Processes a whole block from the lookup server and returns it.
        Returns None on failure, and puts the Exception in the exc parameter.

        Note if this returns successfully, then all the tx's in the returned ProcessedBlock
        are guaranteed to have verified successfully. '''
        network = self.network  # just in case network goes away, capture it
        if not self._do_verify_block_argchecks(network=network, number=number, exc=exc, server=server):
            return
        res = lookup(server=server, number=number, timeout=timeout, exc=exc)
        if not res:
            return
        return self._verify_block_synch_inner(res, network, server, number, verify_txs, timeout, exc)

    def _verify_block_synch_inner(self, res, network, server, number, verify_txs, timeout, exc) -> ProcessedBlock:
        ''' Do not call this from the Network thread, as it actually relies on
        the network thread being another thread (it waits for callbacks from it
        to proceed).  Caller should NOT hold any locks. '''
        pb = ProcessedBlock(hash=res[0], height=num2bh(number), reg_txs={ r.txid : r for r in res[1] })
        with self.lock:
            pb_cached = self.processed_blocks.get(pb.height)
            if pb_cached and pb != pb_cached:
                # Poor man's reorg detection below...
                self.processed_blocks.put(pb.height, None)
                self.print_error(f"Warning, retrieved block info from server {server} is {pb} which differs from cached version {pb_cached}! Reverifying!")
                keys = set()  # (lname, number, collision_hash) tuples
                for txid in set(set(pb_cached.reg_txs or set()) | set(pb.reg_txs or set())):
                    self._rm_vtx(txid, rm_from_verifier=True)
                    script = self._find_script(txid, False)
                    if script:
                        keys.add((script.name.lower(), script.number, script.collision_hash))
                # invalidate minimal_chashes for block
                for k in keys:
                    if self.minimal_ch_cache.get(k):
                        self.print_error("invalidated minimal_chash", k)
                        self.minimal_ch_cache.put(k, None)  # invalidate cache item
                verify_txs = True
        def num_needed():
            with self.lock:
                return len(set(pb.reg_txs) - set(self.v_tx))
        if verify_txs and pb.reg_txs and num_needed():
            q = queue.Queue()
            def on_verified(event, *args):
                if event == 'ca_verified_tx' and args[0] is self:
                    if not num_needed():
                        q.put('done')
            try:
                network.register_callback(on_verified, ['ca_verified_tx'])
                for txid, regtx in pb.reg_txs.items():
                    self.add_ext_tx(txid, regtx.script)  # NB: this is a no-op if already verified and/or in wallet_reg_txs
                if num_needed():
                    q.get(timeout=timeout)
            except queue.Empty as e:
                if num_needed():
                    exc.append(e)
                    return
            finally:
                network.unregister_callback(on_verified)
        with self.lock:
            self.processed_blocks.put(pb.height, pb)
        return pb

    ############################
    # UI / Prefs / Convenience #
    ############################

    def get_address_default(self, infos : List[Info]) -> Info:
        ''' Returns the preferred Info object for a particular address from
        a given list. `infos' is a list of Info objects pertaining to a
        particular address (they should all pertain to said address, but this
        is not checked). '''
        if infos:
            last = infos[-1]
            d = self.wallet.storage.get('cash_accounts_address_defaults')
            if isinstance(d, dict):
                tup = d.get(last.address.to_storage_string())
                if isinstance(tup, (tuple, list)) and len(tup) == 3:
                    name, number, chash = tup
                    if isinstance(name, str) and isinstance(number, (int, float)) and isinstance(chash, str):
                        # find the matching one in the list
                        for info in infos:
                            if (name.lower(), number, chash) == (info.name.lower(), info.number, info.collision_hash):
                                return info
            # just return the latest one if no default specified
            return last

    def set_address_default(self, info : Info):
        ''' Set the default CashAccount for a particular address. Pass the Info
        object pertaining to the Cash Account / Address in question. '''
        d = self.wallet.storage.get('cash_accounts_address_defaults', {})
        d[info.address.to_storage_string()] = [info.name, info.number, info.collision_hash]
        self.wallet.storage.put('cash_accounts_address_defaults', d)


    ###################
    # Private Methods #
    ###################

    def _fw_wallet_updated(self, evt, *args):
        ''' Our private verifier is done. Propagate updated signal to parent
        wallet so that the GUI will refresh. '''
        if evt == 'wallet_updated' and args and args[0] is self:
            self.print_error("forwarding 'wallet_updated' as parent wallet")
            self.network.trigger_callback('wallet_updated', self.wallet)

    def _find_script(self, txid, print_if_missing=True, *, incomplete=False, giveto=None):
        ''' lock should be held by caller '''
        item = self.wallet_reg_tx.get(txid) or self.ext_reg_tx.get(txid)
        if not item and incomplete:
            item = self.ext_incomplete_tx.get(txid)
        if item:
            # Note the giveto with incomplete=True is fragile and requires
            # a call to _add_verified_tx_common right after this
            # _find_script call. We want to maintain the invariant that
            # wallet_reg_tx and ext_reg_tx both contain *complete* scripts.
            # Also note: we intentionally don't pop the ext_incomplete_tx
            # dict here as perhaps client code is maintaining a reference
            # and we want to update that reference later in add_verified_common.
            if giveto == 'e':
                self.wallet_reg_tx.pop(txid, None)
                self.ext_reg_tx[txid] = item
            elif giveto == 'w':
                self.ext_reg_tx.pop(txid, None)
                self.wallet_reg_tx[txid] = item
            return item.script
        if print_if_missing:
            self.print_error("_find_script: could not find script for txid", txid)

    def _add_vtx(self, vtx, script):
        ''' lock should be held by caller '''
        self.v_tx[vtx.txid] = vtx
        self.v_by_addr[script.address].add(vtx.txid)
        self.v_by_name[script.name.lower()].add(vtx.txid)

    def _rm_vtx(self, txid, *, force=False, rm_from_verifier=False):
        ''' lock should be held by caller '''
        vtx = self.v_tx.pop(txid, None)
        if not vtx:
            # was not relevant, abort early
            return
        assert txid == vtx.txid
        script = self._find_script(txid, print_if_missing=not force)  # will print_error if script not found
        if script:
            addr, name = script.address, script.name.lower()
            self.v_by_addr[addr].discard(txid)
            if not self.v_by_addr[addr]: self.v_by_addr.pop(addr, None)
            self.v_by_name[name].discard(txid)
            if not self.v_by_name[name]: self.v_by_name.pop(name, None)
        elif force:
            self.print_error("force remove v_tx", txid)
            empty = set()
            for a, s in self.v_by_addr.items():
                s.discard(txid)
                if not s:
                    empty.add(a)
            for a in empty:
                self.v_by_addr.pop(a, None)
            empty.clear()
            for n, s in self.v_by_name.items():
                s.discard(txid)
                if not s:
                    empty.add(n)
            for n in empty:
                self.v_by_name.pop(n, None)
        if rm_from_verifier:
            verifier = self.verifier
            if verifier:
                verifier.remove_spv_proof_for_tx(txid)

    def _wipe_tx(self, txid):
        ''' called to completely forget a tx from all caches '''
        self._rm_vtx(txid, force=True)
        self.wallet_reg_tx.pop(txid, None)
        self.ext_reg_tx.pop(txid, None)
        self.ext_incomplete_tx.pop(txid, None)
        self.ext_unverif.pop(txid, None)

    def _add_verified_tx_common(self, script, txid, height, header):
        ''' caller must hold locks '''
        if not script or height < activation_height:
            # no-op or not relevant callback
            return

        block_hash = blockchain.hash_header(header)
        v = self.VerifTx(txid=txid, block_height=height, block_hash=block_hash)
        # update/completeify
        script.make_complete(block_height=v.block_height, block_hash=v.block_hash, txid=v.txid)
        rtx = self.ext_incomplete_tx.pop(txid, None)
        if rtx:
            # in case client code somewhere has a copy of this script ..
            # update it to 'complete' so GUI can reflect change.
            # (relevant to TxDialog class)
            rtx.script.make_complete(block_height=v.block_height, block_hash=v.block_hash, txid=v.txid)
            if txid not in self.ext_reg_tx and txid not in self.wallet_reg_tx:
                # save this is_complete RegTx to ext_reg_tx dict which gets saved to disk
                self.ext_reg_tx[txid] = rtx
        # register this tx as verified
        self._add_vtx(v, script)

    def _add_vtx_chk_height(self, txid, height_ts_pos_tup):
        ''' caller must hold locks '''
        height = height_ts_pos_tup[0]
        if not isinstance(height, (int, float)) or height < activation_height:
            self.print_error(f"Warning: Got a tx {txid} with height {height} < activation height {activation_height}!")
            self._wipe_tx(txid)
            return 0
        return int(height)

    #########################
    # Wallet hook callbacks #
    #########################
    def add_verified_tx_hook(self, txid: str, height_ts_pos_tup: tuple, header: dict):
        ''' Called by wallet when it itself got a verified tx from its own
        verifier.  We need to know about tx's that the parent wallet verified
        so we don't do the same work again. '''
        with self.lock:
            # Note: precondition here is that the tx exists in one of our RegTx
            # dicts, otherwise the tx is not relevant to us (contains no cash
            # account registrations). We need this check because we are called
            # a lot for every tx the wallet verifies.
            script = self._find_script(txid, False, giveto='w', incomplete=True)
            if not script:
                return

            self.print_error("verified internal:", txid, height_ts_pos_tup)

            height = self._add_vtx_chk_height(txid, height_ts_pos_tup)  # prints to print_error and wipes tx on error
            if not height:
                return

            self._add_verified_tx_common(script, txid, height, header)

        # this needs to be done without the lock held
        if self.network and script.is_complete():  # paranoia checks
            self.network.trigger_callback('ca_verified_tx', self, Info.from_script(script, txid))


    def undo_verifications_hook(self, txs: set):
        ''' Called by wallet when it itself got called to undo_verifictions by
        its verifier. We need to be told what set of tx_hash was undone. '''
        if not txs: return
        with self.lock:
            for txid in txs:
                self._rm_vtx(txid)  # this is safe as a no-op if txid was not relevant
                self._find_script(txid, False, giveto='w')
            # Since we have a chain reorg, invalidate the processed block and
            # minimal_ch_cache to force revalidation of our collision hashes.
            # FIXME: Do this more elegantly. This casts a pretty wide net.
            # NB: I believe assiging a new {} to .d is safer than d.clear()
            # in this case as the caches._ExpiringCacheMgr doesn't like it
            # when you remove items from the existing dict, but should run ok
            # if you just assign a new dict (it keeps a working reference as
            # it flushes the cache)... so assigning to .d is safer in this case.
            self.minimal_ch_cache.d = {}
            self.processed_blocks.d = {}

    def add_transaction_hook(self, txid: str, tx: object, out_n: int, script: ScriptOutput):
        ''' Called by wallet inside add_transaction (with wallet.lock held) to
        notify us about transactions that were added containing a cashacct
        scriptoutput. Note these tx's aren't yet in the verified set. '''
        assert isinstance(script, ScriptOutput)
        with self.lock:
            self.wallet_reg_tx[txid] = self.RegTx(txid=txid, script=script)
            self._find_script(txid, giveto='w')  # makes sure there is only 1 copy in wallet_reg_tx

    def remove_transaction_hook(self, txid: str):
        ''' Called by wallet inside remove_transaction (with wallet.lock held)
        to tell us about a transaction that was removed. '''
        with self.lock:
            self._rm_vtx(txid)
            self.wallet_reg_tx.pop(txid, None)

    def add_unverified_tx_hook(self, txid: str, block_height: int):
        ''' This is called by wallet when we expect a future subsequent
        verification to happen. So let's pop the vtx from our data structure
        in anticipation of a possible future verification coming in. '''
        with self.lock:
            self._rm_vtx(txid)
            self._find_script(txid, False, giveto='w')

    def on_address_addition(self, address):
        ''' Called by wallet when a new address is added in imported wallet.'''

    def on_address_deletion(self, address):
        ''' Called by wallet when an existing address is deleted in imported wallet.'''

    def on_clear_history(self):
        ''' Called by wallet rebuild history mechanism to clear everything. '''
        with self.lock:
            self._init_data()

    def save_verified_tx_hook(self, write=False):
        self.save(write)

    # /Wallet hook callbacks

    #######################
    # SPVDelegate Methods #
    #######################
    def get_unverified_txs(self) -> dict:
        ''' Return a dict of tx_hash (hex encoded) -> height (int)'''
        with self.lock:
            return self.ext_unverif.copy()

    def add_verified_tx(self, tx_hash : str, height_ts_pos_tup : tuple, header : dict) -> None:
        ''' Called when a verification is successful.
        Params:
            #1 tx_hash - hex string
            #2 tuple of: (tx_height: int, timestamp: int, pos : int)
            #3 the header - dict. This can be subsequently serialized using
               blockchain.serialize_header if so desiered, or it can be ignored.
        '''
        self.print_error('verified external:', tx_hash, height_ts_pos_tup)

        with self.wallet.lock:  # thread safety, even though for 1-liners in CPython it hardly matters.
            # maintain invariant -- this is because pvt verifier can get kicked
            # off on .load() for any missing unverified tx (wallet or external)
            # so we have to determine here where to put the final tx should live
            giveto = 'w' if tx_hash in self.wallet.transactions else 'e'

        with self.lock:
            self.ext_unverif.pop(tx_hash, None)  # pop it off unconditionally

            height = self._add_vtx_chk_height(tx_hash, height_ts_pos_tup)  # prints to print_error and wipes tx on error
            if not height:
                return
            script = self._find_script(tx_hash, incomplete=True, giveto=giveto)
            # call back into the same codepath that registers tx's as verified, and completes them...
            self._add_verified_tx_common(script, tx_hash, height, header)

        # this needs to be done without the lock held
        if self.network and script and script.is_complete():  # paranoia checks
            self.network.trigger_callback('ca_verified_tx', self, Info.from_script(script, tx_hash))

    def is_up_to_date(self) -> bool:
        '''Return True to kick off network wallet_updated callback and
        save_verified_tx callback to us, only when nothing left to verify. '''
        return not self.ext_unverif

    def save_verified_tx(self, write : bool = False):
        ''' Save state. Called by ext verified when it's done. '''
        self.save(write)

    def undo_verifications(self, bchain : object, height : int) -> set:
        ''' Called when the blockchain has changed to tell the wallet to undo
        verifications when a reorg has happened. Returns a set of tx_hash. '''
        txs = set()
        with self.lock:
            for txid, vtx in self.v_tx.copy().items():
                if txid in self.wallet_reg_tx:
                    # wallet verifier will take care of this one
                    continue
                if vtx.block_height >= height:
                    header = bchain.read_header(vtx.block_height)
                    if not header or vtx.block_hash != blockchain.hash_header(header):
                        self._rm_vtx(txid)
                        self.ext_unverif[txid] = vtx.block_height  # re-enqueue for verification with private verifier...? TODO: how to detect tx's dropped out of new chain?
                        txs.add(txid)
        return txs

    def verification_failed(self, tx_hash, reason):
        ''' TODO.. figure out what to do here. Or with wallet verification in
        general in this error case. '''
        self.print_error(f"SPV failed for {tx_hash}, reason: '{reason}'")
        try:
            with self.lock:
                script = self._find_script(tx_hash)
                if self.verifier.failure_reasons.index(reason) < 3 or not script or not script.is_complete():
                    # actual verification failure.. remove this tx
                    self.print_error("removing tx from ext_reg_tx cache")
                    self.ext_unverif.pop(tx_hash, None)
                    self.ext_reg_tx.pop(tx_hash, None)
                else:
                    # Note that the above ^ branch can also be reached due to a
                    # misbehaving server so .. not really sure what to do here.
                    # TODO: Determine best strategy for verification failures.
                    self.print_error("ignoring failure due to misbehaving server.. will try again next session")
        except ValueError:
            self.print_error(f"Cannot find '{reason}' in verifier reason list! FIXME!")

    # /SPVDelegate Methods

    ###############################################
    # Experimental Methods (stuff we may not use) #
    ###############################################

    def scan_servers_for_registrations(self, start=100, stop=None, progress_cb=None, error_cb=None, timeout=10.0,
                                       add_only_mine=True):
        ''' This is slow and not particularly useful.  Will maybe delete this
        code soon. I used it for testing to populate wallet.

        progress_cb is called with (progress : float, num_added : int, number : int) as args!
        error_cb is called with no arguments to indicate failure.

        Upon completion, either progress_cb(1.0 ..) will be called to indicate
        successful completion of the task.  Or, error_cb() will be called to
        indicate error abort (usually due to timeout).

        Returned object can be used to stop the process.  obj.stop() is the
        method.
        '''
        if not self.network:
            return
        cancel_evt = threading.Event()
        stop = num2bh(stop) if stop is not None else stop
        start = num2bh(max(start or 0, 100))
        def stop_height():
            return stop or self.wallet.get_local_height()+1
        def progress(h, added):
            if progress_cb:
                progress_cb(max((h-start)/(stop_height() - start), 0.0), added, bh2num(h))
        def thread_func():
            q = queue.Queue()
            h = start
            added = 0
            while self.network and not cancel_evt.is_set() and h < stop_height():
                num = bh2num(h)
                lookup_asynch_all(number=num,
                                  success_cb = lambda res,server: q.put(res),
                                  error_cb = q.put,
                                  timeout=timeout)
                try:
                    thing = q.get(timeout=timeout)
                    if isinstance(thing, Exception):
                        e = thing
                        if debug:
                            self.print_error(f"Height {h} got exception in lookup: {repr(e)}")
                    elif isinstance(thing, tuple):
                        block_hash, res = thing
                        for rtx in res:
                            if rtx.txid not in self.wallet_reg_tx and rtx.txid not in self.ext_reg_tx and (not add_only_mine or self.wallet.is_mine(rtx.script.address)):
                                self.add_ext_tx(rtx.txid, rtx.script)
                                added += 1
                    progress(h, added)
                except queue.Empty:
                    self.print_error("Could not complete request, timed out!")
                    if error_cb:
                        error_cb()
                    return
                h += 1
            progress(h, added)
        t = threading.Thread(daemon=True, target=thread_func)
        t.start()
        class ScanStopper(namedtuple("ScanStopper", "thread, event")):
            def is_alive(self):
                return self.thread.is_alive()
            def stop(self):
                if self.is_alive():
                    self.event.set()
                    self.thread.join()
        return ScanStopper(t, cancel_evt)
