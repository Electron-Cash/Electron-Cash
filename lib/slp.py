from . import bitcoin
from . import address  # for ScriptOutput, OpCodes, ScriptError, Script
from collections import namedtuple
from typing import List, Tuple

lokad_id = b"SLP\x00"  # aka protocol code -- this appears after the 'OP_RETURN + OP_PUSH(4)' bytes in the ScriptOutput

# ---- EXCEPTIONS ----
class Error(Exception):
    ''' Base class for all SLP-related errors '''

class OpreturnError(Error):
    pass


# Exceptions caused by malformed or unexpected data found in parsing.
class ParsingError(Error):
    pass

class UnsupportedSlpTokenType(ParsingError):
    # Cannot parse OP_RETURN due to unrecognized version
    # (may or may not be valid)
    pass

class InvalidOutputMessage(ParsingError):
    # This exception (and subclasses) marks a message as definitely invalid
    # under SLP consensus rules. (either malformed SLP or just not SLP)
    pass


# Exceptions during creation of SLP message.
class SerializingError(Error):
    pass

class OPReturnTooLarge(SerializingError):
    pass

# Other exceptions
class NoMintingBatonFound(Error):
    pass

# /EXCEPTIONS

def _i2b(val): return bytes((val,))

class ScriptOutput(address.ScriptOutput):
    ''' Encapsulates a parsed, valid SLP OP_RETURN output script. '''

    _protocol_prefix = _i2b(address.OpCodes.OP_RETURN) + _i2b(4) + lokad_id

    attrs_extra = ('message',)

    def __new__(cls, script):
        '''Instantiate from a script (or address.ScriptOutput) you wish to parse.'''
        script = script if isinstance(script, (bytes, bytearray)) else script.to_script()
        script = bytes(script) if isinstance(script, bytearray) else script
        self = super(__class__, cls).__new__(cls, script)
        self.message = Message.parseOutputScript(self)
        return self

    def __hash__(self):
        return super().__hash__()

    @classmethod
    def protocol_match(cls, script_bytes):
        ''' Returns True if the passed-in bytes are a valid OP_RETURN script
        for SLP. '''
        # fast test -- most ScriptOutputs that aren't SLP will fail here quickly
        if not script_bytes.startswith(cls._protocol_prefix):
            return False
        # fast test passed -- next try the slow test -- attempt to parse and
        # validate OP_RETURN message
        try:
            slf = cls(script_bytes)
            return slf.message.is_valid
        except Error:
            pass
        except Exception:
            # DEBUG XXX FIXME
            import traceback, sys
            traceback.print_exc(file=sys.stderr)
            pass
        return False
# /ScriptOutput

#address.ScriptOutput.protocol_classes.add(ScriptOutput)  # register self with electron-cash script protocol system

class Chunks:
    ''' SLP OP_RETURN 'fields' object.

    Encapsulates the "chunks" in the SLP OP_RETURN message. self.chunks stores
    the tuple of parsed chunks (bytes objects) in the message.

    This class is intended to be accessed via its .property accessors.

    Accesses are parsed upon access and may raise various Exceptions
    if the OP_RETURN message and/or chunks are malformed.  No real validation
    is done, since this is a low-level class.

    Use the `Message` class which validates the chunks, defined later in this
    file. '''
    def __init__(self, chunks : Tuple[bytes] = None):
        if chunks is not None and (not isinstance(chunks, tuple)
                                   or any(not isinstance(b, bytes) for b in chunks)):
            chunks = tuple(bytes(b) for b in chunks)  # ensure tuple of bytes
        self.chunks = chunks

    def __len__(self):
        return len(self.chunks) if self.chunks is not None else 0

    def __hash__(self):
        return hash(self.chunks)

    def __repr__(self):
        d = {}
        def generic(keys):
            for k in keys:
                if k.startswith('_') or k == 'chunks':
                    continue
                try:
                    v = getattr(self, k, None)
                except:
                    continue
                if v is not None and not callable(v):
                    d[k] = v
        def genesis():
            generic(('token_type', 'transaction_type', 'lokad_id', 'nft_flag',
                     'ticker', 'token_name', 'token_doc_url', 'token_doc_hash',
                     'decimals', 'mint_baton_vout', 'initial_token_mint_quantity',))
        def send():
            generic(('token_type', 'transaction_type', 'lokad_id', 'nft_flag',
                     'token_id_hex', 'token_output', ))
        def mint():
            generic(('token_type', 'transaction_type', 'lokad_id', 'nft_flag',
                     'token_id_hex', 'mint_baton_vout', 'additional_token_quantity'))
        tt = self.transaction_type
        if tt == "GENESIS":
            genesis()
        elif tt == "SEND":
            send()
        elif tt == "MINT":
            mint()
        else:
            generic(dir(self))
        return "<{name} object at 0x{loc:0x} fields: {fields}>".format(
            name = type(self).__qualname__,
            loc = id(self),
            fields = ", ".join([f"{k}={v}" for k,v in d.items()])
        )


    # PROPERTIES -- returns values derived from parsing the bytes in self.chunks
    # Note: ALL properties below are only valid if self.chunks is valid and not
    # None!  Not all properties are 'valid' in all contexts: some depend on
    # transation_type!  No validation is done in the property methods
    # themselves thus they may raise various Exceptions.
    @property
    def lokad_id(self) -> bytes:
        return self.chunks[0]
    @property
    def token_type(self) -> int:
        ''' Returns the SLP token type: one of: 1, 65, 129 '''
        return self._parseChunkToInt(self.chunks[1], 1, 2, True)
    @property
    def transaction_type(self) -> str:
        ''' Returns the transaction type string (chunks[2] as decoded string),
        may rause UnicodeError and/or other Exceptions.

        Will be one of "GENESIS" "SEND" "MINT" "COMMIT"
        '''
        return self.chunks[2].decode('ascii')
    @property
    def nft_flag(self) -> str:
        ''' Returns one of "NFT_PARENT", "NFT_CHILD", or None if non-NFT. '''
        t_type = self.token_type
        if t_type == 65:
            return "NFT_CHILD"
        elif t_type == 129:
            return "NFT_PARENT"
        else:
            return None
    # -- GENESIS PROPERTIES
    @property
    def ticker(self) -> bytes:
        return self.chunks[3]
    @property
    def token_name(self) -> bytes:
        return self.chunks[4]
    @property
    def token_doc_url(self) -> bytes:
        return self.chunks[5]
    @property
    def token_doc_hash(self) -> bytes:
        return self.chunks[6]
    @property
    def decimals(self) -> int:
        ''' decimals -- one byte in range 0-9 -> int '''
        return self._parseChunkToInt(self.chunks[7], 1, 1, True)
    @property
    def mint_baton_vout(self) -> int:
        ''' May return None. '''
        if self.transaction_type == 'GENESIS':
            return self._parseChunkToInt(self.chunks[8], 1, 1)
        else:
            # presumably MINT
            return self._parseChunkToInt(self.chunks[4], 1, 1)
    @property
    def initial_token_mint_quantity(self) -> int:
        return self._parseChunkToInt(self.chunks[9], 8, 8, True)
    # -- SEND properties
    @property
    def token_id(self) -> bytes:
        return self.chunks[3]
    @property
    def token_id_hex(self) -> str:  # this is *ALSO* a MINT property
        ''' Returns the self.ticker bytes as a hex-encoded string. '''
        return self.token_id.hex()
    @property
    def token_output(self) -> Tuple[int]:  # ret[0] is always 0
        ''' Returns the token output as a list of ints.
            Note that we put an explicit 0 for  self.token_output[0] since it
            corresponds to vout=0, which is the OP_RETURN tx output.
            token_output[1] is the first token output given by the SLP
            message, i.e., the number listed as `token_output_quantity1` in the
            spec, which goes to tx output vout=1.'''
        return (0,) + tuple( self._parseChunkToInt(field, 8, 8, True)
                             for field in self.chunks[4:] )
    # -- MINT properties
    # NOTE:
    # - token_id_hex is also MINT property here (as well as a SEND property)
    # - mint_baton_vout is also MINT propety here (as well as a GENESIS property)
    @property
    def additional_token_quantity(self) -> int:
        return self._parseChunkToInt(self.chunks[5], 8, 8, True)
    # -- COMMIT properties
    @property
    def info(self) -> str:
        ''' Not really implemented. Returns the same thing each time. '''
        return 'slp.py not parsing yet \xaf\\_(\u30c4)_/\xaf'
    # /End PROPERTIES

    # --- HELPERS ---
    @staticmethod
    def _parseChunkToInt(intBytes: bytes, minByteLen: int, maxByteLen: int, raise_on_Null: bool = False):
        # Parse data as unsigned-big-endian encoded integer.
        # For empty data different possibilities may occur:
        #      minByteLen <= 0 : return 0
        #      raise_on_Null == False and minByteLen > 0: return None
        #      raise_on_Null == True and minByteLen > 0:  raise InvalidOutputMessage
        if len(intBytes) >= minByteLen and len(intBytes) <= maxByteLen:
            return int.from_bytes(intBytes, 'big', signed=False)
        if len(intBytes) == 0 and not raise_on_Null:
            return None
        raise InvalidOutputMessage('Field has wrong length')

class Message:
    ''' This class represents a parsed and valid op_return message that can be
    used by the validator to examine SLP messages. '''


    __slots__ = ('is_valid',  # bool
                 'chunks',)   # Chunks object

    def __init__(self, chunks: Chunks):
        assert isinstance(chunks, Chunks)
        self.is_valid = self.is_valid_or_raise(chunks)
        self.chunks = chunks

    def __hash__(self):
        return hash((self.is_valid, self.chunks))

    def __repr__(self):
        return "<%s token_type=%d transaction_type=%r %r>"%(type(self).__qualname__, self.chunks.token_type, self.chunks.transaction_type, self.chunks)

    @classmethod
    def parseOutputScript(cls, outputScript) -> object:
        ''' This method attempts to parse a ScriptOutput object as an SLP message.
            Bad scripts will throw a subclass of ParsingError; any other exception indicates a bug in this code.
            - Unrecognized SLP versions will throw UnsupportedSlpTokenType.
            - It is a STRICT parser -- consensus-invalid messages will throw InvalidOutputMessage.
            - Non-SLP scripts will also throw InvalidOutputMessage. '''
        try:
            script_bytes = outputScript if isinstance(outputScript, (bytes, bytearray)) else outputScript.to_script()
            chunks = Chunks( cls._parseOpreturnToChunks(script_bytes, allow_op_0 = False, allow_op_number = False) )
        except OpreturnError as e:
            raise InvalidOutputMessage('Bad OP_RETURN', *e.args) from e

        return cls(chunks)  # implicitly calls is_valid_or_raise

    @staticmethod
    def _parseOpreturnToChunks(script: bytes, *,  allow_op_0: bool, allow_op_number: bool) -> List[bytes]:
        """Extract pushed bytes after opreturn. Returns list of bytes() objects,
        one per push.

        Strict refusal of non-push opcodes; bad scripts throw OpreturnError."""
        try:
            ops = address.Script.get_ops(script)
        except address.ScriptError as e:
            raise OpreturnError('Script error') from e

        if ops[0][0] != address.OpCodes.OP_RETURN:
            raise OpreturnError('No OP_RETURN')

        chunks = []
        for opitem in ops[1:]:
            op, data = opitem if isinstance(opitem, tuple) else (opitem, None)
            if op > address.OpCodes.OP_16:
                raise OpreturnError('Non-push opcode')
            if op > address.OpCodes.OP_PUSHDATA4:
                if op == 80:
                    raise OpreturnError('Non-push opcode')
                if not allow_op_number:
                    raise OpreturnError('OP_1NEGATE to OP_16 not allowed')
                if op == address.OpCodes.OP_1NEGATE:
                    data = [0x81]
                else: # OP_1 - OP_16
                    data = [op-80]
            if op == address.OpCodes.OP_0 and not allow_op_0:
                raise OpreturnError('OP_0 not allowed')
            chunks.append(b'' if data is None else bytes(data))
        return chunks

    @classmethod
    def is_valid_or_raise(cls, chunks : Chunks) -> bool:
        ''' Checks if chunks is a valid SLP OP_RETURN message.

        Returns True or raises if not valid. '''
        if not chunks:
            raise InvalidOutputMessage('Empty OP_RETURN')

        if chunks.lokad_id != lokad_id:
            raise InvalidOutputMessage('Not SLP')

        if len(chunks) <= 1:
            raise InvalidOutputMessage('Missing token_type')

        # check if the token version is supported
        # 1   = type 1
        # 65  = type 1 as NFT child
        # 129 = type 1 as NFT parent
        token_type = chunks.token_type
        if token_type not in (1, 65, 129):
            raise UnsupportedSlpTokenType(token_type)

        if len(chunks) <= 2:
            raise InvalidOutputMessage('Missing SLP command')

        # (the following logic is all for version 1)
        try:
            transaction_type = chunks.transaction_type
        except UnicodeDecodeError:
            # This can occur if non-ascii bytes present (byte > 127)
            raise InvalidOutputMessage('Bad transaction type')

        # switch statement to handle different on transaction type
        if transaction_type == 'GENESIS':
            if len(chunks) != 10:
                raise InvalidOutputMessage('GENESIS with incorrect number of parameters')
            # keep ticker, token name, document url, document hash as bytes
            # (their textual encoding is not relevant for SLP consensus)
            # but do enforce consensus length limits
            dummy = chunks.ticker  # ensure this parses
            dummy = chunks.token_name  # ensure parses
            dummy = chunks.token_doc_url  # ensure parses
            if len(chunks.token_doc_hash) not in (0, 32):
                raise InvalidOutputMessage('Token document hash is incorrect length')

            # decimals -- one byte in range 0-9
            if chunks.decimals > 9:
                raise InvalidOutputMessage('Too many decimals')

            ## handle baton for additional minting, but may be empty
            v = chunks.mint_baton_vout
            if v is not None and v < 2:
                raise InvalidOutputMessage('Mint baton cannot be on vout=0 or 1')
            elif v is not None and chunks.nft_flag == 'NFT_CHILD':
                raise InvalidOutputMessage('Cannot have a minting baton in a NFT_CHILD token.')

            # handle initial token quantity issuance
            dummy = chunks.initial_token_mint_quantity  # ensure parses
        elif transaction_type == 'SEND':
            if len(chunks) < 4:
                raise InvalidOutputMessage('SEND with too few parameters')
            if len(chunks.token_id) != 32:
                raise InvalidOutputMessage('token_id is wrong length')
            #dummy = chunks.token_id_hex  # ensure parses

            # Note that we put an explicit 0 for token_output[0] since it
            # corresponds to vout=0, which is the OP_RETURN tx output.
            # token_output[1] is the first token output given by the SLP
            # message, i.e., the number listed as `token_output_quantity1` in the
            # spec, which goes to tx output vout=1.
            token_output = chunks.token_output  # ensure parses
            # maximum 19 allowed token outputs, plus 1 for the explicit [0] we inserted.
            if len(token_output) < 2:
                raise InvalidOutputMessage('Missing output amounts')
            if len(token_output) > 20:
                raise InvalidOutputMessage('More than 19 output amounts')
        elif transaction_type == 'MINT':
            if chunks.nft_flag == 'NFT_CHILD':
                raise InvalidOutputMessage('Cannot have MINT with NFT_CHILD')
            if len(chunks) != 6:
                raise InvalidOutputMessage('MINT with incorrect number of parameters')
            if len(chunks.token_id) != 32:
                raise InvalidOutputMessage('token_id is wrong length')
            #dummy = chunks.token_id_hex  # ensure parse
            v = chunks.mint_baton_vout
            if v is not None and v < 2:
                raise InvalidOutputMessage('Mint baton cannot be on vout=0 or 1')
            dummy = chunks.additional_token_quantity  # ensure parse
        elif slpMsg.transaction_type == 'COMMIT':
            # We don't know how to handle this right now, just return slpMsg of 'COMMIT' type
            dummy = chunks.info  # ensure parse
        else:
            raise InvalidOutputMessage('Bad transaction type')
        return True

#/Message

class Build:
    ''' Namespace of all static methods involved in SLP OP_RETURN message
    building.

    SLP message creation functions below.
    Various exceptions can occur:
       SerializingError / subclass if bad values.
       UnicodeDecodeError if strings are weird (in GENESIS only).
    '''

    @staticmethod
    def pushChunk(chunk: bytes) -> bytes: # allow_op_0 = False, allow_op_number = False
        '''utility for creation: use smallest push except not any of: op_0, op_1negate, op_1 to op_16'''
        length = len(chunk)
        if length == 0:
            return b'\x4c\x00' + chunk
        elif length < 76:
            return bytes((length,)) + chunk
        elif length < 256:
            return bytes((0x4c,length,)) + chunk
        elif length < 65536: # shouldn't happen but eh
            return b'\x4d' + length.to_bytes(2, 'little') + chunk
        elif length < 4294967296: # shouldn't happen but eh
            return b'\x4e' + length.to_bytes(4, 'little') + chunk
        else:
            raise ValueError()

    @staticmethod
    def chunksToOpreturnOutput(chunks: List[bytes]) -> tuple:
        ''' utility for creation '''
        script = bytearray((address.OpCodes.OP_RETURN,)) # start with OP_RETURN
        for c in chunks:
            script.extend(Build.pushChunk(c))

        if len(script) > 223:
            raise OPReturnTooLarge('OP_RETURN message too large, cannot be larger than 223 bytes')

        # Note 'ScriptOutput' is our subclass in this file, not address.py ScriptOutput!
        return (bitcoin.TYPE_SCRIPT, ScriptOutput(bytes(script)), 0)

    @staticmethod
    def GenesisOpReturnOutput_V1(ticker: str, token_name: str, token_document_url: str, token_document_hash_hex: str, decimals: int, baton_vout: int, initial_token_mint_quantity: int, token_type: int = 1) -> tuple:
        ''' Type 1 Token GENESIS Message '''
        chunks = []

        # lokad id
        chunks.append(lokad_id)

        # token version/type
        if token_type in (1, 'SLP1'):
            chunks.append(b'\x01')
        elif token_type in (65, 'SLP65'):
            chunks.append(b'\x41')
        elif token_type in (129, 'SLP129'):
            chunks.append(b'\x81')
        else:
            raise Error('Unsupported token type')

        # transaction type
        chunks.append(b'GENESIS')

        # ticker (can be None)
        if not ticker:
            tickerb = b''
        else:
            tickerb = ticker.encode('utf-8')
        chunks.append(tickerb)

        # name (can be None)
        if not token_name:
            chunks.append(b'')
        else:
            chunks.append(token_name.encode('utf-8'))

        # doc_url (can be None)
        if not token_document_url:
            chunks.append(b'')
        else:
            chunks.append(token_document_url.encode('ascii'))

        # doc_hash (can be None)
        if not token_document_hash_hex:
            chunks.append(b'')
        else:
            dochash = bytes.fromhex(token_document_hash_hex)
            if len(dochash) not in (0, 32):
                raise SerializingError()
            chunks.append(dochash)

        # decimals
        decimals = int(decimals)
        if decimals > 9 or decimals < 0:
            raise SerializingError()
        chunks.append(bytes((decimals,)))

        # baton vout
        if baton_vout is None:
            chunks.append(b'')
        else:
            if baton_vout < 2:
                raise SerializingError()
            chunks.append(bytes((baton_vout,)))

        # init quantity
        qb = int(initial_token_mint_quantity).to_bytes(8,'big')
        chunks.append(qb)

        return Build.chunksToOpreturnOutput(chunks)

    @staticmethod
    def GenesisOpReturnOutput_V2(ticker: str, token_name: str, token_document_url: str, token_document_hash_hex: str, decimals: int, baton_vout: int, initial_token_mint_quantity: int) -> tuple:
        ''' Type 1 Token GENESIS Message '''
        chunks = []

        # lokad id
        chunks.append(lokad_id)

        # token version/type
        chunks.append(b'\x02')

        # transaction type
        chunks.append(b'GENESIS')

        # ticker (can be None)
        if not ticker:
            tickerb = b''
        else:
            tickerb = ticker.encode('utf-8')
        chunks.append(tickerb)

        # name (can be None)
        if not token_name:
            chunks.append(b'')
        else:
            chunks.append(token_name.encode('utf-8'))

        # doc_url (can be None)
        if not token_document_url:
            chunks.append(b'')
        else:
            chunks.append(token_document_url.encode('ascii'))

        # doc_hash (can be None)
        if not token_document_hash_hex:
            chunks.append(b'')
        else:
            dochash = bytes.fromhex(token_document_hash_hex)
            if len(dochash) not in (0, 32):
                raise SerializingError()
            chunks.append(dochash)

        # decimals
        decimals = int(decimals)
        if decimals > 9 or decimals < 0:
            raise SerializingError()
        chunks.append(bytes((decimals,)))

        # baton vout
        if baton_vout is None:
            chunks.append(b'')
        else:
            if baton_vout < 2:
                raise SerializingError()
            chunks.append(bytes((baton_vout,)))

        # init quantity
        qb = int(initial_token_mint_quantity).to_bytes(8,'big')
        chunks.append(qb)

        return Build.chunksToOpreturnOutput(chunks)

    @staticmethod
    def MintOpReturnOutput_V1(token_id_hex: str, baton_vout: int, token_mint_quantity: int, token_type: int = 1) -> tuple:
        ''' Type 1 Token MINT Message '''
        chunks = []

        # lokad id
        chunks.append(lokad_id)

        # token version/type
        if token_type in (1, 'SLP1'):
            chunks.append(b'\x01')
        elif token_type in (129, 'SLP129'):
            chunks.append(b'\x81')
        else:
            raise Error('Unsupported token type')

        # transaction type
        chunks.append(b'MINT')

        # token id
        tokenId = bytes.fromhex(token_id_hex)
        if len(tokenId) != 32:
            raise SerializingError()
        chunks.append(tokenId)

        # baton vout
        if baton_vout is None:
            chunks.append(b'')
        else:
            if baton_vout < 2:
                raise SerializingError()
            chunks.append(bytes((baton_vout,)))

        # init quantity
        qb = int(token_mint_quantity).to_bytes(8,'big')
        chunks.append(qb)

        return Build.chunksToOpreturnOutput(chunks)

    @staticmethod
    def MintOpReturnOutput_V2(token_id_hex: str, baton_vout: int, token_mint_quantity: int) -> tuple:
        '''  Type 2 Token MINT Message '''
        chunks = []

        # lokad id
        chunks.append(lokad_id)

        # token version/type
        chunks.append(b'\x02')

        # transaction type
        chunks.append(b'MINT')

        # token id
        tokenId = bytes.fromhex(token_id_hex)
        if len(tokenId) != 32:
            raise SerializingError()
        chunks.append(tokenId)

        # baton vout
        if baton_vout is None:
            chunks.append(b'')
        else:
            if baton_vout < 2:
                raise SerializingError()
            chunks.append(bytes((baton_vout,)))

        # init quantity
        qb = int(token_mint_quantity).to_bytes(8,'big')
        chunks.append(qb)

        return Build.chunksToOpreturnOutput(chunks)

    @staticmethod
    def SendOpReturnOutput_V1(token_id_hex: str, output_qty_array: [int], token_type: int = 1) -> tuple:
        ''' Type 1 Token SEND Message '''
        chunks = []

        # lokad id
        chunks.append(lokad_id)

        # token version/type
        if token_type in (1, 'SLP1'):
            chunks.append(b'\x01')
        elif token_type in (65, 'SLP65'):
            chunks.append(b'\x41')
        elif token_type in (129, 'SLP129'):
            chunks.append(b'\x81')
        else:
            raise Error('Unsupported token type')

        # transaction type
        chunks.append(b'SEND')

        # token id
        tokenId = bytes.fromhex(token_id_hex)
        if len(tokenId) != 32:
            raise SerializingError()
        chunks.append(tokenId)

        # output quantities
        if len(output_qty_array) < 1:
            raise SerializingError("Cannot have less than 1 SLP Token output.")
        if len(output_qty_array) > 19:
            raise SerializingError("Cannot have more than 19 SLP Token outputs.")
        for qty in output_qty_array:
            qb = int(qty).to_bytes(8,'big')
            chunks.append(qb)

        return Build.chunksToOpreturnOutput(chunks)

    @staticmethod
    def SendOpReturnOutput_V2(token_id_hex: str, output_qty_array: [int]) -> tuple:
        '''' Type 2 Token SEND Message '''
        chunks = []

        # lokad id
        chunks.append(lokad_id)

        # token version/type
        chunks.append(b'\x02')

        # transaction type
        chunks.append(b'SEND')

        # token id
        tokenId = bytes.fromhex(token_id_hex)
        if len(tokenId) != 32:
            raise SerializingError()
        chunks.append(tokenId)

        # output quantities
        if len(output_qty_array) < 1:
            raise SerializingError("Cannot have less than 1 SLP Token output.")
        if len(output_qty_array) > 19:
            raise SerializingError("Cannot have more than 19 SLP Token outputs.")
        for qty in output_qty_array:
            qb = int(qty).to_bytes(8,'big')
            chunks.append(qb)

        return Build.chunksToOpreturnOutput(chunks)
