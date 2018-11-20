#!/usr/bin/env python3
from .address import OpCodes, to_bytes, Address, ScriptOutput
from .bitcoin import TYPE_ADDRESS
from binascii import hexlify

def makeZCFscriptV0(inputs, forfeit_pubkey_address):
    """Create a zero conf forfeit P2SH script for the list of inputs, version 0. """
    op = OpCodes

    forfeit_pubkey_address_hash = to_bytes(forfeit_pubkey_address.hash160)

    #print("Creating forfeit script for:", forfeit_pubkey_address)
    #print("And inputs:", inputs)

    # first, add P2PKH equivalent script path for spending forfeit forward the regular way
    # DUP HASH160 <pubkey-hash160> OP_EQUAL
    # IF
    #   CHECKSIG // do P2PKH-like check
    # ELSE
    s = (bytes([op.OP_DUP,
                op.OP_HASH160, 160 // 8]) +
         forfeit_pubkey_address_hash +
         bytes([op.OP_EQUAL, op.OP_IF, op.OP_CHECKSIG, op.OP_ELSE]))

    # now add forfeit case for each input
    for inp in inputs:
        #print("make script, @inp:", inp)
        if inp["type"] != "p2pkh":
            continue

        # check for the given input address
        # DUP HASH160 <address> EQUAL
        s += (bytes([op.OP_DUP, op.OP_HASH160, 160 // 8]) +
              to_bytes(inp["address"].hash160) + bytes([op.OP_EQUAL]))

        # and do the forfeit check:
        # IF
        #   OVER 4 PICK EQUAL NOT VERIFY // check message hashes are not equal
        #   DUP TO_ALTSTACK CHECKDATASIGVERIFY // and verify the two
        #   FROMALTSACK CHECKDATASIG           // signatures
        # ELSE
        s += bytes([op.OP_IF,
                    op.OP_OVER, op.OP_4, op.OP_PICK, op.OP_EQUAL, op.OP_NOT, op.OP_VERIFY,
                    op.OP_DUP, op.OP_TOALTSTACK, op.OP_CHECKDATASIGVERIFY,
                    op.OP_FROMALTSTACK, op.OP_CHECKDATASIG,
                    op.OP_ELSE])
    s+=bytes([op.OP_RETURN]) # fail the script for any other input

    # and close all the else paths
    s += bytes([op.OP_ENDIF] * (1 + len(inputs)))
    #print ("FORFEIT SCRIPT:", hexlify(s))
    return s

def derefForfeitOutput(tx, forfeit_p2sh_address):
    #print("Forfeit check: Checking transaction %s" % tx.txid())
    #print("Forfeit check: Forfeit P2SH address: %s" % repr(forfeit_p2sh_address))
    if not isinstance(forfeit_p2sh_address, Address):
        #print("Forfeit check: Not an address, returning false.")
        return None, None

    for output in tx.outputs():
        if isinstance(output[1], Address):
            script = makeZCFscriptV0(tx.inputs(),
                                     output[1])

            check_addr = Address.from_multisig_script(script)
            #print("Forfeit check: %s == %s ?"  % (check_addr, forfeit_p2sh_address))
            if check_addr == forfeit_p2sh_address:
                print("Forfeit check: return %s for %s" % (repr(output[1]), repr(check_addr)))
                return output[1], script
    #print("Forfeit check: return false")
    return None, None



def makeZCFoutput(inputs, forfeit_pubkey_address, amount):
    """ Create a zero conf forfeit P2SH output for the given inputs and the given amount."""

    forfeit_output_script = makeZCFscriptV0(inputs, forfeit_pubkey_address)

    address = Address.from_multisig_script(forfeit_output_script)

    return (TYPE_ADDRESS, address, amount)
