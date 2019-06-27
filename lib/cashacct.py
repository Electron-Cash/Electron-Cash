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
import requests
import threading
from collections import defaultdict, namedtuple
from . import bitcoin
from . import util
from .address import Address, OpCodes, Script, ScriptError
from .address import ScriptOutput as ScriptOutputBase
from .transaction import BCDataStream, Transaction
from . import verifier
from . import blockchain

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

    # Additional attributes outside of the tuple's 1 attribute
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
        script = cls._ensure_script(script)
        self = super(__class__, cls).__new__(cls, script)
        self.name, self.address = self.parse_script(self.script)  # raises on error
        self.number, self.collision_hash, self.emoji = None, None, None  # ensure attributes defined
        self.make_complete2(number, collision_hash, emoji=emoji)  # raises if number  bad and/or if collision_hash is bad, otherwise just sets attributes. None ok for args.
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


# register ourself with the ScriptOutput protocol system
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
    return block_height - height_modification

def number_to_block_height(number):
    ''' Reciprocal of number_to_block_height '''
    return number + height_modification

bh2num = number_from_block_height  # alias
num2bh = number_to_block_height  # alias

#### Lookup & Verification

CashAcctInfo = namedtuple("CashAcctInfo", "name, address, number, collision_hash, emoji, txid")

servers = [
    "https://cashacct.imaginary.cash",
    "https://api.cashaccount.info"
]

def lookup(server, number, name=None, collision_prefix=None, timeout=10.0, exc=[]) -> list:
    ''' Synchronous lookup, returns a list of (txid, out_n, script) tuples, or
    None on error. (Optionally pass a list as the `exc` parameter and the
    exception encountered will be returned to caller by appending to the list,)
    '''
    url = f'{server}/lookup/{number}'
    if name:
        name = name.lower()
        url += f'/{name}'
    if collision_prefix:
        url += f'/{collision_prefix}'
    try:
        ret = []
        r = requests.get(url, allow_redirects=True, timeout=timeout) # will raise requests.exceptions.Timeout on timeout
        r.raise_for_status()
        d = r.json()
        if not isinstance(d, dict) or not d.get('results') or not isinstance(d.get('block'), int):
            raise RuntimeError('Unexpected response', r.text)
        res, block = d['results'], d['block']
        if not isinstance(res, list) or bh2num(block) < 100:
            raise RuntimeError('Bad response')
        for d in res:
            txraw = d['transaction']
            header_hex = d['inclusion_proof'][:blockchain.HEADER_SIZE*2]
            if len(header_hex)//2 != blockchain.HEADER_SIZE:
                raise AssertionError('Could not get header')
            block_hash = blockchain.hash_header_hex(header_hex)
            tx = Transaction(txraw)
            for out_n, txo in enumerate(tx.outputs()):
                _typ, script, value = txo
                if isinstance(script, ScriptOutput):  # note ScriptOutput here is our subclass defined at the top of this file
                    txid = tx.txid()
                    script.make_complete(block_height=block, block_hash=block_hash, txid=txid)
                    ret.append(CashAcct.AddedTx(txid, out_n, script))
                    break # there will be no more outputs in this tx that are relevant
        return ret
    except Exception as e:
        util.print_error("lookup:", repr(e))
        if isinstance(exc, list):
            exc.append(e)

class CashAcct(util.PrintError, verifier.SPVDelegate):
    ''' Class implementing cash account subsystem such as verification, etc. '''

    AddedTx = namedtuple("AddedTx", "txid, out_n, script")
    VerifTx = namedtuple("VerifTx", "txid, block_height, block_hash")

    def __init__(self, wallet):
        assert wallet, "CashAcct cannot be instantiated without a wallet"
        self.wallet = wallet
        self.network = None
        self.verifier = None
        self.lock = threading.Lock()

        self._init_data()

    def _init_data(self):
        self.wallet_added_tx = dict() # dict of txid -> AddedTx
        self.ext_added_tx = dict() # dict of txid -> AddedTx

        self.v_tx = dict() # dict of txid -> VerifTx
        self.v_by_addr = defaultdict(set) # dict of addr -> set of txid
        self.v_by_name = defaultdict(set) # dict of lowercased name -> set of txid

        # TESTING
        self.test_unverif = dict()


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

    def stop(self):
        if self.verifier:
            assert self.network
            self.verifier.release()
            self.verifier = None
            self.network = None

    def get_cashaccounts(self, domain=None, inv=False) -> list:
        ''' Returns a list of CashAcctInfo for verified cash accounts in domain.
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
                        ret.append(self._info_from_script(script, txid))

        return ret

    def get_wallet_cashaccounts(self) -> list:
        ''' Convenience method, returns all the verified cash accounts we
        know about for wallet addresses only. '''
        return self.get_cashaccounts(domain=self.wallet.get_addresses())

    def get_external_cashaccounts(self) -> list:
        ''' Convenience method, retruns all the verified cash accounts we
        know about that are not for wallet addresses. '''
        return self.get_cashaccounts(domain=self.wallet.get_addresses(), inv=True)


    def load(self):
        ''' Note: loading should happen before threads are started, so no lock
        is needed.'''
        # TODO...

    def save(self, write=False):
        '''
        FYI, current data model is:

        AddedTx = namedtuple("AddedTx", "txid, out_n, script")
        VerifTx = namedtuple("VerifTx", "txid, block_height, block_hash")

        self.wallet_added_tx = dict() # dict of txid -> AddedTx
        self.ext_added_tx = dict() # dict of txid -> AddedTx

        self.v_tx = dict() # dict of txid -> VerifTx
        self.v_by_addr = defaultdict(set) # dict of addr -> set of txid
        self.v_by_name = defaultdict(set) # dict of lowercased name -> set of txid
        '''

        # This is just scratch code.. TODO: IMPLEMENT
        wat_d, eat_d, vtx_d = dict(), dict(), dict()
        with self.lock:
            for txid, atx in self.wallet_added_tx.items():
                wat_d[txid] = [atx.out_n, atx.script.script.hex()]
            for txid, etx in self.ext_added_tx.items():
                eat_d[txid] = [etx.out_n, etx.script.script.hex()]
            for txid, vtx in self.v_tx.items():
                vtx_d[txid] = [vtx.block_height, vtx.block_hash]
        '''
        import json
        self.print_error(f"would have saved:\n"
                         f"wat_d = {json.dumps(wat_d)}\n"
                         f"eat_d = {json.dumps(eat_d)}\n"
                         f"vtx_d = {json.dumps(vtx_d)}\n"
                         )
        '''

    def find(self, name: str, number: int = None, collision_prefix: str = None) -> list:
        ''' Returns a list of CashAcctInfo for verified cash accounts matching
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
                    ret.append(self._info_from_script(script, txid))
        return ret

    ###################
    # Private Methods #
    ###################

    @classmethod
    def _info_from_script(cls, script, txid):
        return CashAcctInfo(name=script.name,
                            address=script.address,
                            number=script.number,
                            collision_hash=script.collision_hash,
                            emoji=script.emoji,
                            txid=txid)

    def _find_script(self, txid, print_if_missing=True):
        ''' lock should be held by caller '''
        item = self.wallet_added_tx.get(txid) or self.ext_added_tx.get(txid)
        if item:
            return item.script
        if print_if_missing:
            self.print_error("_find_script: could not find script for txid", txid)

    def _add_vtx(self, vtx, script):
        ''' lock should be held by caller '''
        self.v_tx[vtx.txid] = vtx
        self.v_by_addr[script.address].add(vtx.txid)
        self.v_by_name[script.name.lower()].add(vtx.txid)

    def _rm_vtx(self, txid):
        ''' lock should be held by caller '''
        vtx = self.v_tx.pop(txid, None)
        if not vtx:
            # was not relevant, abort early
            return
        assert txid == vtx.txid
        script = self._find_script(txid)  # will print_error if script not found
        if script:
            addr, name = script.address, script.name.lower()
            self.v_by_addr[addr].discard(txid)
            if not self.v_by_addr[addr]: self.v_by_addr.pop(addr, None)
            self.v_by_name[name].discard(txid)
            if not self.v_by_name[name]: self.v_by_name.pop(name, None)

    def _add_verified_tx_common(self, script, txid, height, header):
        ''' caller must hold locks '''
        if not script:
            # no-op or not relevant callback
            return

        block_hash = blockchain.hash_header(header)
        v = self.VerifTx(txid=txid, block_height=height, block_hash=block_hash)
        # update/completeify
        script.make_complete(block_height=v.block_height, block_hash=v.block_hash, txid=v.txid)
        # register this tx as verified
        self._add_vtx(v, script)

    #########################
    # Wallet hook callbacks #
    #########################
    def add_verified_tx_hook(self, txid: str, height_ts_pos_tup: tuple, header: dict):
        ''' Called by wallet when it itself got a verified tx from its own
        verifier.  We need to know about tx's that the parent wallet verified
        so we don't do the same work again. '''
        with self.lock:
            # Note: precondition here is that the tx exists in wallet_added_tx,
            # otherwise the tx is not relevant to us (contains no cash account registrations)
            added = self.wallet_added_tx.get(txid)
            if not added:
                return

            self._add_verified_tx_common(added.script, txid, height_ts_pos_tup[0], header)


    def undo_verifications_hook(self, txs: set):
        ''' Called by wallet when it itself got called to undo_verifictions by
        its verifier. We need to be tool what set of tx_hash was undone. '''
        if not txs: return
        with self.lock:
            for txid in txs:
                self._rm_vtx(txid)  # this safe as a no-op if txid was not relevant

    def add_transaction_hook(self, txid: str, tx: object, out_n: int, script: ScriptOutput):
        ''' Called by wallet inside add_transaction (but with lock not held) to
        notify us about transactions that were added containing a cashacct
        scriptoutput. Note these tx's aren't yet in the verified set. '''
        assert isinstance(script, ScriptOutput)
        with self.lock:
            self.wallet_added_tx[txid] = self.AddedTx(txid=txid, out_n=out_n, script=script)

    def remove_transaction_hook(self, txid: str):
        ''' Called by wallet inside remove_transaction (but with lock not held)
        to tell us about a transaction that was removed. '''
        with self.lock:
            self._rm_vtx(txid)
            self.wallet_added_tx.pop(txid, None)

    def add_unverified_tx_hook(self, txid: str, block_height: int):
        with self.lock:
            self._rm_vtx(txid)
            script = self._find_script(txid, False)
            if script:
                script.clear_completion()

    def on_address_addition(self, address):
        ''' Called by wallet when a new address is added in imported wallet.
        TODO: Implement. '''

    def on_address_deletion(self, address):
        ''' Called by wallet when an existing address is deleted in imported wallet
        TODO: Implement. '''

    def on_clear_history(self):
        ''' Called by wallet rebuild history mechanism to clear everything. '''
        with self.lock:
            self._init_data()

    # /Wallet hook callbacks

    #######################
    # SPVDelegate Methods #
    #######################
    def get_unverified_txs(self) -> dict:
        ''' Return a dict of tx_hash (hex encoded) -> height (int)'''
        return self.test_unverif.copy()

    def add_verified_tx(self, tx_hash : str, height_ts_pos_tup : tuple, header : dict) -> None:
        ''' Called when a verification is successful.
        Params:
            #1 tx_hash - hex string
            #2 tuple of: (tx_height: int, timestamp: int, pos : int)
            #3 the header - dict. This can be subsequently serialized using
               blockchain.serialize_header if so desiered, or it can be ignored.
        '''
        self.print_error('verified external:', tx_hash, height_ts_pos_tup, blockchain.hash_header(header))
        with self.lock:
            self.test_unverif.pop(tx_hash, None)
            # call back into the same codepath that registers tx's as verified...
            self._add_verified_tx_common(self._find_script(tx_hash), tx_hash, height_ts_pos_tup[0], header)

    def is_up_to_date(self) -> bool:
        ''' No-op - always return false to prevent network wallet_updated callback '''
        return False

    def save_verified_tx(self, write : bool = False):
        ''' No-op '''

    def undo_verifications(self, blkchain : object, height : int) -> set:
        ''' Called when the blockchain has changed to tell the wallet to undo
        verifications when a reorg has happened. Returns a set of tx_hash. '''
        return set()

    def verification_failed(self, tx_hash, reason):
        ''' TODO '''
        self.print_error(f"SPV failed for {tx_hash}, reason: '{reason}'")

    # /SPVDelegate Methods
