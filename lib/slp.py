from .transaction import Transaction
from .address import ScriptOutput
from .bitcoin import TYPE_SCRIPT
from .address import Script, ScriptError, OpCodes
from enum import Enum

lokad_id = b"SLP\x00"

def int_2_bytes_bigendian(number: int, byte_length: int = None):
    number = int(number)
    if byte_length is None: # autosize
        byte_length = (number.bit_length()+7)//8
    # Raises OverflowError if number is too big for this length
    return number.to_bytes(byte_length, 'big')


class OpreturnError(Exception):
    pass

def parseOpreturnToChunks(script: bytes, *,  allow_op_0: bool, allow_op_number: bool):
    """Extract pushed bytes after opreturn. Returns list of bytes() objects,
    one per push.

    Strict refusal of non-push opcodes; bad scripts throw OpreturnError."""
    try:
        ops = Script.get_ops(script)
    except ScriptError as e:
        raise OpreturnError('Script error') from e

    if ops[0][0] != OpCodes.OP_RETURN:
        raise OpreturnError('No OP_RETURN')

    chunks = []
    for opitem in ops[1:]:
        op, data = opitem if isinstance(opitem, tuple) else (opitem, None)
        if op > OpCodes.OP_16:
            raise OpreturnError('Non-push opcode')
        if op > OpCodes.OP_PUSHDATA4:
            if op == 80:
                raise OpreturnError('Non-push opcode')
            if not allow_op_number:
                raise OpreturnError('OP_1NEGATE to OP_16 not allowed')
            if op == OpCodes.OP_1NEGATE:
                data = [0x81]
            else: # OP_1 - OP_16
                data = [op-80]
        if op == OpCodes.OP_0 and not allow_op_0:
            raise OpreturnError('OP_0 not allowed')
        chunks.append(b'' if data is None else bytes(data))
    return chunks


# Exceptions caused by malformed or unexpected data found in parsing.
class SlpParsingError(Exception):
    pass

class SlpUnsupportedSlpTokenType(SlpParsingError):
    # Cannot parse OP_RETURN due to unrecognized version
    # (may or may not be valid)
    pass

class SlpInvalidOutputMessage(SlpParsingError):
    # This exception (and subclasses) marks a message as definitely invalid
    # under SLP consensus rules. (either malformed SLP or just not SLP)
    pass


# Exceptions during creation of SLP message.
class SlpSerializingError(Exception):
    pass

class OPReturnTooLarge(SlpSerializingError):
    pass

# Other exceptions
class SlpNoMintingBatonFound(Exception):
    pass


# This class represents a parsed op_return message that can be used by validator to look at SLP messages
class SlpMessage:
    lokad_id = lokad_id

    def __init__(self):
        self.token_type  = None
        self.transaction_type  = None
        self.op_return_fields = {}

    def __repr__(self,):
        return "<%s token_type=%d %r %r>"%(type(self).__qualname__, self.token_type, self.transaction_type, self.op_return_fields)

    # This method attempts to parse a ScriptOutput object as an SLP message.
    # Bad scripts will throw a subclass of SlpParsingError; any other exception indicates a bug in this code.
    # - Unrecognized SLP versions will throw SlpUnsupportedSlpTokenType.
    # - It is a STRICT parser -- consensus-invalid messages will throw SlpInvalidOutputMessage.
    # - Non-SLP scripts will also throw SlpInvalidOutputMessage.
    @staticmethod
    def parseSlpOutputScript(outputScript: ScriptOutput):
        slpMsg = SlpMessage()
        try:
            chunks = parseOpreturnToChunks(outputScript.to_script(), allow_op_0 = False, allow_op_number = False)
        except OpreturnError as e:
            raise SlpInvalidOutputMessage('Bad OP_RETURN', *e.args) from e

        if len(chunks) == 0:
            raise SlpInvalidOutputMessage('Empty OP_RETURN')

        if chunks[0] != lokad_id:
            raise SlpInvalidOutputMessage('Not SLP')

        if len(chunks) == 1:
            raise SlpInvalidOutputMessage('Missing token_type')

        # check if the token version is supported
        # 1   = type 1
        # 65  = type 1 as NFT child
        # 129 = type 1 as NFT parent
        slpMsg.token_type = SlpMessage.parseChunkToInt(chunks[1], 1, 2, True)
        if slpMsg.token_type not in [1, 65, 129]:
            raise SlpUnsupportedSlpTokenType(slpMsg.token_type)

        if slpMsg.token_type == 65:
            nft_flag = slpMsg.op_return_fields['nft_flag'] = "NFT_CHILD"
        elif slpMsg.token_type == 129:
            nft_flag = slpMsg.op_return_fields['nft_flag'] = "NFT_PARENT"
        else:
            nft_flag = slpMsg.op_return_fields['nft_flag'] = None

        if len(chunks) == 2:
            raise SlpInvalidOutputMessage('Missing SLP command')

        # (the following logic is all for version 1)
        try:
            slpMsg.transaction_type = chunks[2].decode('ascii')
        except UnicodeDecodeError:
            # This can occur if bytes > 127 present.
            raise SlpInvalidOutputMessage('Bad transaction type')

        # switch statement to handle different on transaction type
        if slpMsg.transaction_type == 'GENESIS':
            if len(chunks) != 10:
                raise SlpInvalidOutputMessage('GENESIS with incorrect number of parameters')
            # keep ticker, token name, document url, document hash as bytes
            # (their textual encoding is not relevant for SLP consensus)
            # but do enforce consensus length limits
            slpMsg.op_return_fields['ticker'] = chunks[3]
            slpMsg.op_return_fields['token_name'] = chunks[4]
            slpMsg.op_return_fields['token_doc_url'] = chunks[5]
            slpMsg.op_return_fields['token_doc_hash'] = chunks[6]
            if len(slpMsg.op_return_fields['token_doc_hash']) not in (0, 32):
                raise SlpInvalidOutputMessage('Token document hash is incorrect length')

            # decimals -- one byte in range 0-9
            slpMsg.op_return_fields['decimals'] = SlpMessage.parseChunkToInt(chunks[7], 1, 1, True)
            if slpMsg.op_return_fields['decimals'] > 9:
                raise SlpInvalidOutputMessage('Too many decimals')

            ## handle baton for additional minting, but may be empty
            v = slpMsg.op_return_fields['mint_baton_vout'] = SlpMessage.parseChunkToInt(chunks[8], 1, 1)
            if v is not None and v < 2:
                raise SlpInvalidOutputMessage('Mint baton cannot be on vout=0 or 1')
            elif v is not None and nft_flag == 'NFT_CHILD':
                raise SlpInvalidOutputMessage('Cannot have a minting baton in a NFT_CHILD token.')

            # handle initial token quantity issuance
            slpMsg.op_return_fields['initial_token_mint_quantity'] = SlpMessage.parseChunkToInt(chunks[9], 8, 8, True)
        elif slpMsg.transaction_type == 'SEND':
            if len(chunks) < 4:
                raise SlpInvalidOutputMessage('SEND with too few parameters')
            if len(chunks[3]) != 32:
                raise SlpInvalidOutputMessage('token_id is wrong length')
            slpMsg.op_return_fields['token_id_hex'] = chunks[3].hex()

            # Note that we put an explicit 0 for  ['token_output'][0] since it
            # corresponds to vout=0, which is the OP_RETURN tx output.
            # ['token_output'][1] is the first token output given by the SLP
            # message, i.e., the number listed as `token_output_quantity1` in the
            # spec, which goes to tx output vout=1.
            slpMsg.op_return_fields['token_output'] = (0,) + \
                    tuple( SlpMessage.parseChunkToInt(field, 8, 8, True) for field in chunks[4:] )
            # maximum 19 allowed token outputs, plus 1 for the explicit [0] we inserted.
            if len(slpMsg.op_return_fields['token_output']) < 2:
                raise SlpInvalidOutputMessage('Missing output amounts')
            if len(slpMsg.op_return_fields['token_output']) > 20:
                raise SlpInvalidOutputMessage('More than 19 output amounts')
        elif slpMsg.transaction_type == 'MINT':
            if nft_flag == 'NFT_CHILD':
                raise SlpInvalidOutputMessage('Cannot have MINT with NFT_CHILD')
            if len(chunks) != 6:
                raise SlpInvalidOutputMessage('MINT with incorrect number of parameters')
            if len(chunks[3]) != 32:
                raise SlpInvalidOutputMessage('token_id is wrong length')
            slpMsg.op_return_fields['token_id_hex'] = chunks[3].hex()
            v = slpMsg.op_return_fields['mint_baton_vout'] = SlpMessage.parseChunkToInt(chunks[4], 1, 1)
            if v is not None and v < 2:
                raise SlpInvalidOutputMessage('Mint baton cannot be on vout=0 or 1')
            slpMsg.op_return_fields['additional_token_quantity'] = SlpMessage.parseChunkToInt(chunks[5], 8, 8, True)
        elif slpMsg.transaction_type == 'COMMIT':
            # We don't know how to handle this right now, just return slpMsg of 'COMMIT' type
            slpMsg.op_return_fields['info'] = 'slp.py not parsing yet \xaf\\_(\u30c4)_/\xaf'
        else:
            raise SlpInvalidOutputMessage('Bad transaction type')
        return slpMsg

    @staticmethod
    def parseChunkToInt(intBytes: bytes, minByteLen: int, maxByteLen: int, raise_on_Null: bool = False):
        # Parse data as unsigned-big-endian encoded integer.
        # For empty data different possibilities may occur:
        #      minByteLen <= 0 : return 0
        #      raise_on_Null == False and minByteLen > 0: return None
        #      raise_on_Null == True and minByteLen > 0:  raise SlpInvalidOutputMessage
        if len(intBytes) >= minByteLen and len(intBytes) <= maxByteLen:
            return int.from_bytes(intBytes, 'big', signed=False)
        if len(intBytes) == 0 and not raise_on_Null:
            return None
        raise SlpInvalidOutputMessage('Field has wrong length')






###
# SLP message creation functions below.
# Various exceptions can occur:
#   SlpSerializingError / subclass if bad values.
#   UnicodeDecodeError if strings are weird (in GENESIS only).
###


# utility for creation: use smallest push except not any of: op_0, op_1negate, op_1 to op_16
def pushChunk(chunk: bytes) -> bytes: # allow_op_0 = False, allow_op_number = False
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

# utility for creation
def chunksToOpreturnOutput(chunks: [bytes]) -> tuple:
    script = bytearray([0x6a,]) # start with OP_RETURN
    for c in chunks:
        script.extend(pushChunk(c))

    if len(script) > 223:
        raise OPReturnTooLarge('OP_RETURN message too large, cannot be larger than 223 bytes')

    return (TYPE_SCRIPT, ScriptOutput(bytes(script)), 0)


# Type 1 Token GENESIS Message
def buildGenesisOpReturnOutput_V1(ticker: str, token_name: str, token_document_url: str, token_document_hash_hex: str, decimals: int, baton_vout: int, initial_token_mint_quantity: int, token_type: int = 1) -> tuple:
    chunks = []
    script = bytearray((0x6a,))  # OP_RETURN

    # lokad id
    chunks.append(lokad_id)

    # token version/type
    if token_type in [1, 'SLP1']:
        chunks.append(b'\x01')
    elif token_type in [65, 'SLP65']:
        chunks.append(b'\x41')
    elif token_type in [129, 'SLP129']:
        chunks.append(b'\x81')
    else:
        raise Exception('Unsupported token type')

    # transaction type
    chunks.append(b'GENESIS')

    # ticker (can be None)
    if ticker is None:
        tickerb = b''
    else:
        tickerb = ticker.encode('utf-8')
    chunks.append(tickerb)

    # name (can be None)
    if token_name is None:
        chunks.append(b'')
    else:
        chunks.append(token_name.encode('utf-8'))

    # doc_url (can be None)
    if token_document_url is None:
        chunks.append(b'')
    else:
        chunks.append(token_document_url.encode('ascii'))

    # doc_hash (can be None)
    if token_document_hash_hex is None:
        chunks.append(b'')
    else:
        dochash = bytes.fromhex(token_document_hash_hex)
        if len(dochash) not in (0,32):
            raise SlpSerializingError()
        chunks.append(dochash)

    # decimals
    decimals = int(decimals)
    if decimals > 9 or decimals < 0:
        raise SlpSerializingError()
    chunks.append(bytes((decimals,)))

    # baton vout
    if baton_vout is None:
        chunks.append(b'')
    else:
        if baton_vout < 2:
            raise SlpSerializingError()
        chunks.append(bytes((baton_vout,)))

    # init quantity
    qb = int(initial_token_mint_quantity).to_bytes(8,'big')
    chunks.append(qb)

    return chunksToOpreturnOutput(chunks)

# Type 1 Token GENESIS Message
def buildGenesisOpReturnOutput_V2(ticker: str, token_name: str, token_document_url: str, token_document_hash_hex: str, decimals: int, baton_vout: int, initial_token_mint_quantity: int) -> tuple:
    chunks = []
    script = bytearray((0x6a,))  # OP_RETURN

    # lokad id
    chunks.append(lokad_id)

    # token version/type
    chunks.append(b'\x02')

    # transaction type
    chunks.append(b'GENESIS')

    # ticker (can be None)
    if ticker is None:
        tickerb = b''
    else:
        tickerb = ticker.encode('utf-8')
    chunks.append(tickerb)

    # name (can be None)
    if token_name is None:
        chunks.append(b'')
    else:
        chunks.append(token_name.encode('utf-8'))

    # doc_url (can be None)
    if token_document_url is None:
        chunks.append(b'')
    else:
        chunks.append(token_document_url.encode('ascii'))

    # doc_hash (can be None)
    if token_document_hash_hex is None:
        chunks.append(b'')
    else:
        dochash = bytes.fromhex(token_document_hash_hex)
        if len(dochash) not in (0,32):
            raise SlpSerializingError()
        chunks.append(dochash)

    # decimals
    decimals = int(decimals)
    if decimals > 9 or decimals < 0:
        raise SlpSerializingError()
    chunks.append(bytes((decimals,)))

    # baton vout
    if baton_vout is None:
        chunks.append(b'')
    else:
        if baton_vout < 2:
            raise SlpSerializingError()
        chunks.append(bytes((baton_vout,)))

    # init quantity
    qb = int(initial_token_mint_quantity).to_bytes(8,'big')
    chunks.append(qb)

    return chunksToOpreturnOutput(chunks)

# Type 1 Token MINT Message
def buildMintOpReturnOutput_V1(token_id_hex: str, baton_vout: int, token_mint_quantity: int, token_type: int = 1) -> tuple:
    chunks = []

    # lokad id
    chunks.append(lokad_id)

    # token version/type
    if token_type in [1, 'SLP1']:
        chunks.append(b'\x01')
    elif token_type in [129, 'SLP129']:
        chunks.append(b'\x81')
    else:
        raise Exception('Unsupported token type')

    # transaction type
    chunks.append(b'MINT')

    # token id
    tokenId = bytes.fromhex(token_id_hex)
    if len(tokenId) != 32:
        raise SlpSerializingError()
    chunks.append(tokenId)

    # baton vout
    if baton_vout is None:
        chunks.append(b'')
    else:
        if baton_vout < 2:
            raise SlpSerializingError()
        chunks.append(bytes((baton_vout,)))

    # init quantity
    qb = int(token_mint_quantity).to_bytes(8,'big')
    chunks.append(qb)

    return chunksToOpreturnOutput(chunks)

# Type 2 Token MINT Message
def buildMintOpReturnOutput_V2(token_id_hex: str, baton_vout: int, token_mint_quantity: int) -> tuple:
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
        raise SlpSerializingError()
    chunks.append(tokenId)

    # baton vout
    if baton_vout is None:
        chunks.append(b'')
    else:
        if baton_vout < 2:
            raise SlpSerializingError()
        chunks.append(bytes((baton_vout,)))

    # init quantity
    qb = int(token_mint_quantity).to_bytes(8,'big')
    chunks.append(qb)

    return chunksToOpreturnOutput(chunks)

# Type 1 Token SEND Message
def buildSendOpReturnOutput_V1(token_id_hex: str, output_qty_array: [int], token_type: int = 1) -> tuple:
    chunks = []

    # lokad id
    chunks.append(lokad_id)

    # token version/type
    if token_type in [1, 'SLP1']:
        chunks.append(b'\x01')
    elif token_type in [65, 'SLP65']:
        chunks.append(b'\x41')
    elif token_type in [129, 'SLP129']:
        chunks.append(b'\x81')
    else:
        raise Exception('Unsupported token type')

    # transaction type
    chunks.append(b'SEND')

    # token id
    tokenId = bytes.fromhex(token_id_hex)
    if len(tokenId) != 32:
        raise SlpSerializingError()
    chunks.append(tokenId)

    # output quantities
    if len(output_qty_array) < 1:
        raise SlpSerializingError("Cannot have less than 1 SLP Token output.")
    if len(output_qty_array) > 19:
        raise SlpSerializingError("Cannot have more than 19 SLP Token outputs.")
    for qty in output_qty_array:
        qb = int(qty).to_bytes(8,'big')
        chunks.append(qb)

    return chunksToOpreturnOutput(chunks)

# Type 2 Token SEND Message
def buildSendOpReturnOutput_V2(token_id_hex: str, output_qty_array: [int]) -> tuple:
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
        raise SlpSerializingError()
    chunks.append(tokenId)

    # output quantities
    if len(output_qty_array) < 1:
        raise SlpSerializingError("Cannot have less than 1 SLP Token output.")
    if len(output_qty_array) > 19:
        raise SlpSerializingError("Cannot have more than 19 SLP Token outputs.")
    for qty in output_qty_array:
        qb = int(qty).to_bytes(8,'big')
        chunks.append(qb)

    return chunksToOpreturnOutput(chunks)
