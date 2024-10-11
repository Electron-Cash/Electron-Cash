#!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 Thomas Voegtlin
#
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2023 The Electron Cash Developers
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


# Note: The deserialization code originally comes from ABE.

from .util import print_error, profiler
from .caches import ExpiringCache

from .bitcoin import *
from .address import (PublicKey, Address, Script, ScriptOutput, hash160,
                      UnknownAddress, OpCodes as opcodes,
                      P2PKH_prefix, P2PKH_suffix, P2SH_prefix, P2SH_suffix, P2SH32_prefix, P2SH32_suffix)
from .serialize import BCDataStream, SerializationError
from . import schnorr
from . import token
from . import util
import warnings

from .keystore import xpubkey_to_address, xpubkey_to_pubkey

NO_SIGNATURE = 'ff'


class InputValueMissing(ValueError):
    """ thrown when the value of an input is needed but not present """


# This function comes from bitcointools, bct-LICENSE.txt.
def long_hex(bytes):
    return bytes.encode('hex_codec')


# This function comes from bitcointools, bct-LICENSE.txt.
def short_hex(bytes):
    t = bytes.encode('hex_codec')
    if len(t) < 11:
        return t
    return t[0:4]+"..."+t[-4:]


def match_decoded(decoded, to_match):
    if len(decoded) != len(to_match):
        return False
    for i in range(len(decoded)):
        op = decoded[i][0]
        if to_match[i] == opcodes.OP_PUSHDATA4 and op <= opcodes.OP_PUSHDATA4 and op > 0:
            # Opcodes below OP_PUSHDATA4 just push data onto stack, and are equivalent.
            # Note we explicitly don't match OP_0, OP_1 through OP_16 and OP1_NEGATE here
            continue
        if to_match[i] != op:
            return False
    return True


def parse_sig(x_sig):
    return [None if x == NO_SIGNATURE else x for x in x_sig]


def safe_parse_pubkey(x):
    try:
        return xpubkey_to_pubkey(x)
    except:
        return x


def parse_scriptSig(d, _bytes):
    try:
        decoded = Script.get_ops(_bytes)
    except Exception as e:
        # coinbase transactions raise an exception
        print_error("cannot find address in input script", bh2u(_bytes))
        return

    match = [ opcodes.OP_PUSHDATA4 ]
    if match_decoded(decoded, match):
        item = decoded[0][1]
        # payto_pubkey
        d['type'] = 'p2pk'
        d['signatures'] = [bh2u(item)]
        d['num_sig'] = 1
        d['x_pubkeys'] = ["(pubkey)"]
        d['pubkeys'] = ["(pubkey)"]
        return

    # non-generated TxIn transactions push a signature
    # (seventy-something bytes) and then their public key
    # (65 bytes) onto the stack:
    match = [ opcodes.OP_PUSHDATA4, opcodes.OP_PUSHDATA4 ]
    if match_decoded(decoded, match):
        sig = bh2u(decoded[0][1])
        x_pubkey = bh2u(decoded[1][1])
        try:
            signatures = parse_sig([sig])
            pubkey, address = xpubkey_to_address(x_pubkey)
        except:
            print_error("cannot find address in input script", bh2u(_bytes))
            return
        d['type'] = 'p2pkh'
        d['signatures'] = signatures
        d['x_pubkeys'] = [x_pubkey]
        d['num_sig'] = 1
        d['pubkeys'] = [pubkey]
        d['address'] = address
        return

    # p2sh transaction, m of n
    match = [ opcodes.OP_0 ] + [ opcodes.OP_PUSHDATA4 ] * (len(decoded) - 1)
    if not match_decoded(decoded, match):
        print_error("cannot find address in input script", bh2u(_bytes))
        return
    x_sig = [bh2u(x[1]) for x in decoded[1:-1]]
    m, n, x_pubkeys, pubkeys, redeemScript = parse_redeemScript(decoded[-1][1])
    # write result in d
    d['type'] = 'p2sh'
    d['num_sig'] = m
    d['signatures'] = parse_sig(x_sig)
    d['x_pubkeys'] = x_pubkeys
    d['pubkeys'] = pubkeys
    d['redeemScript'] = redeemScript
    d['address'] = Address.from_P2SH_hash(hash160(redeemScript))


def parse_redeemScript(s):
    dec2 = Script.get_ops(s)
    # the following throw exception when redeemscript has one or zero opcodes
    m = dec2[0][0] - opcodes.OP_1 + 1
    n = dec2[-2][0] - opcodes.OP_1 + 1
    op_m = opcodes.OP_1 + m - 1
    op_n = opcodes.OP_1 + n - 1
    match_multisig = [ op_m ] + [opcodes.OP_PUSHDATA4]*n + [ op_n, opcodes.OP_CHECKMULTISIG ]
    if not match_decoded(dec2, match_multisig):
        # causes exception in caller when mismatched
        print_error("cannot find address in input script", bh2u(s))
        return
    x_pubkeys = [bh2u(x[1]) for x in dec2[1:-2]]
    pubkeys = [safe_parse_pubkey(x) for x in x_pubkeys]
    redeemScript = Script.multisig_script(m, [bytes.fromhex(p)
                                              for p in pubkeys])
    return m, n, x_pubkeys, pubkeys, redeemScript


def get_address_from_output_script(_bytes):
    scriptlen = len(_bytes)

    if scriptlen == 23 and _bytes.startswith(P2SH_prefix) and _bytes.endswith(P2SH_suffix):
        # Pay-to-script-hash
        return TYPE_ADDRESS, Address.from_P2SH_hash(_bytes[2:22])

    if scriptlen == 35 and _bytes.startswith(P2SH32_prefix) and _bytes.endswith(P2SH32_suffix):
        # P2SH32
        return TYPE_ADDRESS, Address.from_P2SH_hash(_bytes[2:34])

    if scriptlen == 25 and _bytes.startswith(P2PKH_prefix) and _bytes.endswith(P2PKH_suffix):
        # Pay-to-pubkey-hash
        return TYPE_ADDRESS, Address.from_P2PKH_hash(_bytes[3:23])

    if scriptlen == 35 and _bytes[0] == 33 and _bytes[1] in (2,3) and _bytes[34] == opcodes.OP_CHECKSIG:
        # Pay-to-pubkey (compressed)
        return TYPE_PUBKEY, PublicKey.from_pubkey(_bytes[1:34])

    if scriptlen == 67 and _bytes[0] == 65 and _bytes[1] == 4 and _bytes[66] == opcodes.OP_CHECKSIG:
        # Pay-to-pubkey (uncompressed)
        return TYPE_PUBKEY, PublicKey.from_pubkey(_bytes[1:66])

    # note: we don't recognize bare multisigs.

    return TYPE_SCRIPT, ScriptOutput.protocol_factory(bytes(_bytes))


def parse_input(vds):
    d = {}
    prevout_hash = hash_encode(vds.read_bytes(32))
    prevout_n = vds.read_uint32()
    scriptSig = vds.read_bytes(vds.read_compact_size())
    sequence = vds.read_uint32()
    d['prevout_hash'] = prevout_hash
    d['prevout_n'] = prevout_n
    d['sequence'] = sequence
    d['address'] = UnknownAddress()
    if prevout_hash == '00'*32:
        d['type'] = 'coinbase'
        d['scriptSig'] = bh2u(scriptSig)
    else:
        d['x_pubkeys'] = []
        d['pubkeys'] = []
        d['signatures'] = {}
        d['address'] = None
        d['type'] = 'unknown'
        d['num_sig'] = 0
        d['scriptSig'] = bh2u(scriptSig)
        try:
            parse_scriptSig(d, scriptSig)
        except Exception as e:
            print_error('{}: Failed to parse tx input {}:{}, probably a p2sh (non multisig?). Exception was: {}'.format(__name__, prevout_hash, prevout_n, repr(e)))
            # that whole heuristic codepath is fragile; just ignore it when it dies.
            # failing tx examples:
            # 1c671eb25a20aaff28b2fa4254003c201155b54c73ac7cf9c309d835deed85ee
            # 08e1026eaf044127d7103415570afd564dfac3131d7a5e4b645f591cd349bb2c
            # override these once more just to make sure
            d['address'] = UnknownAddress()
            d['type'] = 'unknown'
        if not Transaction.is_txin_complete(d):
            del d['scriptSig']
            val = vds.read_uint64()
            if val >= 0xff_ff_ff_ff_ff_ff_ff_f0:
                # Hack to stuff utxo data into txin (this breaks older clients, however)
                ext_version = val & 0xf  # "extension" version is low-order nybble
                # Future-proof this hack: version 0xf (if extending this, use 0xe, 0xd, 0xc etc..)
                if ext_version == 0xf:
                    val = vds.read_compact_size(strict=True)
                    wspk = vds.read_bytes(strict=True)
                    assert wspk and wspk[0] == token.PREFIX_BYTE[0], "Expected serialized token data"
                    token_data, spk = token.unwrap_spk(wspk)
                    assert not spk  # For now, we never serialize the prevout's spk and it must be empty
                    d['value'] = val  # For being able to sign offline
                    d['token_data'] = token_data  # For being able to sign token inputs offline
                else:
                    raise SerializationError(f"Unknown txn format extension: {ext_version:x}")
            else:
                # Legacy format
                d['value'] = val
                d['token_data'] = None
    return d


def parse_output(vds, i):
    d = {}
    d['value'] = vds.read_int64()
    wrappedScriptPubKey = vds.read_bytes(vds.read_compact_size())
    token_data, scriptPubKey = token.unwrap_spk(wrappedScriptPubKey)
    d['type'], d['address'] = get_address_from_output_script(scriptPubKey)
    d['scriptPubKey'] = bh2u(scriptPubKey)
    d['token_data'] = token_data
    d['prevout_n'] = i
    return d


def deserialize(raw):
    vds = BCDataStream(bfh(raw))
    d = {}
    d['version'] = vds.read_int32()
    n_vin = vds.read_compact_size()
    d['inputs'] = [parse_input(vds) for i in range(n_vin)]
    n_vout = vds.read_compact_size()
    d['outputs'] = [parse_output(vds, i) for i in range(n_vout)]
    d['lockTime'] = vds.read_uint32()
    if vds.can_read_more():
        raise SerializationError('extra junk at the end')
    return d


# pay & redeem scripts
def multisig_script(public_keys, m):
    n = len(public_keys)
    assert n <= 15
    assert m <= n
    op_m = push_script_bytes(bytes([m])).hex()
    op_n = push_script_bytes(bytes([n])).hex()
    keylist = [push_script(k) for k in public_keys]
    return op_m + ''.join(keylist) + op_n + bytes([opcodes.OP_CHECKMULTISIG]).hex()


class Transaction:

    SIGHASH_FORKID = 0x40  # do not use this; deprecated
    FORKID = 0x000000  # do not use this; deprecated

    def __str__(self):
        if self.raw is None:
            self.raw = self.serialize()
        return self.raw

    def __init__(self, raw, sign_schnorr=False):
        if raw is None:
            self.raw = None
        elif isinstance(raw, str):
            self.raw = raw.strip() if raw else None
        elif isinstance(raw, dict):
            self.raw = raw['hex']
        else:
            raise BaseException("cannot initialize transaction", raw)
        self._inputs = None
        self._outputs = None
        self._token_datas = None
        self.locktime = 0
        self.version = 1
        self._sign_schnorr = sign_schnorr

        # attribute used by HW wallets to tell the hw keystore about any outputs
        # in the tx that are to self (change), etc. See wallet.py add_hw_info
        # which writes to this dict and the various hw wallet plugins which
        # read this dict.
        self.output_info = dict()

        # Ephemeral meta-data used internally to keep track of interesting
        # things. This is currently written-to by coinchooser to tell UI code
        # about 'dust_to_fee', which is change that's too small to go to change
        # outputs (below dust threshold) and needed to go to the fee.
        #
        # It is also used to store the 'fetched_inputs' which are asynchronously
        # retrieved inputs (by retrieving prevout_hash tx's), see
        #`fetch_input_data`.
        #
        # Values in this dict are advisory only and may or may not always be
        # there!
        self.ephemeral = dict()

    def is_memory_compact(self):
        """Returns True if the tx is stored in memory only as self.raw (serialized) and has no deserialized data
        structures currently in memory. """
        return (self.raw is not None
                and self._inputs is None and self._outputs is None and self.locktime == 0 and self.version == 1)

    def set_sign_schnorr(self, b):
        self._sign_schnorr = b

    def update(self, raw):
        self.raw = raw
        self._inputs = None
        self.deserialize()

    def inputs(self):
        if self._inputs is None:
            self.deserialize()
        return self._inputs

    def outputs(self, *, tokens=False) -> list:
        if self._outputs is None:
            self.deserialize()
        if tokens:
            assert len(self._outputs) == len(self._token_datas)
            return list(zip(self._outputs, self._token_datas))
        return self._outputs

    def token_datas(self) -> list:
        if self._token_datas is None:
            self.deserialize()
        return self._token_datas

    @classmethod
    def get_sorted_pubkeys(self, txin):
        # sort pubkeys and x_pubkeys, using the order of pubkeys
        # Note: this function is CRITICAL to get the correct order of pubkeys in
        # multisignatures; avoid changing.
        x_pubkeys = txin['x_pubkeys']
        pubkeys = txin.get('pubkeys')
        if pubkeys is None:
            pubkeys = [xpubkey_to_pubkey(x) for x in x_pubkeys]
            pubkeys, x_pubkeys = zip(*sorted(zip(pubkeys, x_pubkeys)))
            txin['pubkeys'] = pubkeys = list(pubkeys)
            txin['x_pubkeys'] = x_pubkeys = list(x_pubkeys)
        return pubkeys, x_pubkeys

    def update_signatures(self, signatures):
        """Add new signatures to a transaction
        `signatures` is expected to be a list of hex encoded sig strings with
        *no* sighash byte at the end (implicitly always 0x41 (SIGHASH_FORKID|SIGHASH_ALL);
        will be added by this function).

        signatures[i] is intended for self._inputs[i].

        The signature will be matched with the appropriate pubkey automatically
        in the case of multisignature wallets.

        This function is used by the Trezor, KeepKey, etc to update the
        transaction with signatures form the device.

        Note this function supports both Schnorr and ECDSA signatures, but as
        yet no hardware wallets are signing Schnorr.
        """
        if self.is_complete():
            return
        if not isinstance(signatures, (tuple, list)):
            raise Exception('API changed: update_signatures expects a list.')
        if len(self.inputs()) != len(signatures):
            raise Exception('expected {} signatures; got {}'.format(len(self.inputs()), len(signatures)))
        for i, txin in enumerate(self.inputs()):
            pubkeys, x_pubkeys = self.get_sorted_pubkeys(txin)
            sig = signatures[i]
            if not isinstance(sig, str):
                raise ValueError("sig was bytes, expected string")
            # sig_final is the signature with the sighashbyte at the end (0x41)
            sig_final = sig + '41'
            if sig_final in txin.get('signatures'):
                # skip if we already have this signature
                continue
            pre_hash = Hash(bfh(self.serialize_preimage(i)))
            sig_bytes = bfh(sig)
            added = False
            reason = []
            for j, pubkey in enumerate(pubkeys):
                # see which pubkey matches this sig (in non-multisig only 1 pubkey, in multisig may be multiple pubkeys)
                if self.verify_signature(bfh(pubkey), sig_bytes, pre_hash, reason):
                    print_error("adding sig", i, j, pubkey, sig_final)
                    self._inputs[i]['signatures'][j] = sig_final
                    added = True
            if not added:
                resn = ', '.join(reversed(reason)) if reason else ''
                print_error("failed to add signature {} for any pubkey for reason(s): '{}' ; pubkey(s) / sig / pre_hash = ".format(i, resn),
                            pubkeys, '/', sig, '/', bh2u(pre_hash))
        # redo raw
        self.raw = self.serialize()

    def is_schnorr_signed(self, input_idx):
        """ Return True IFF any of the signatures for a particular input
        are Schnorr signatures (Schnorr signatures are always 64 bytes + 1) """
        if (isinstance(self._inputs, (list, tuple))
                and input_idx < len(self._inputs)
                and self._inputs[input_idx]):
            # Schnorr sigs are always 64 bytes. However the sig has a hash byte
            # at the end, so that's 65. Plus we are hex encoded, so 65*2=130
            return any(isinstance(sig, (str, bytes)) and len(sig) == 130
                       for sig in self._inputs[input_idx].get('signatures', []))
        return False

    def deserialize(self):
        if self.raw is None:
            return
        if self._inputs is not None:
            return
        d = deserialize(self.raw)
        self.invalidate_common_sighash_cache()
        self._inputs = d['inputs']
        self._outputs = [(x['type'], x['address'], x['value']) for x in d['outputs']]
        self._token_datas = [x['token_data'] for x in d['outputs']]
        assert all(isinstance(output[1], (PublicKey, Address, ScriptOutput))
                   for output in self._outputs)
        assert all(isinstance(td, (token.OutputData, type(None)))
                   for td in self._token_datas)
        self.locktime = d['lockTime']
        self.version = d['version']
        return d

    @classmethod
    def from_io(cls, inputs, outputs, locktime=0, sign_schnorr=False, *, token_datas=None, version=1) -> object:
        assert all(isinstance(output[1], (PublicKey, Address, ScriptOutput))
                   for output in outputs)
        self = cls(None)
        self._inputs = inputs
        self._outputs = outputs.copy()
        self.version = version
        if token_datas is not None:
            assert all(isinstance(td, (token.OutputData, type(None)))
                       for td in token_datas)
            self._token_datas = token_datas.copy()
        else:
            self._token_datas = []
        # Ensure len(self._token_datas) == len(self._outputs)
        lt = len(self._token_datas)
        lo = len(self._outputs)
        if lt < lo:
            # If they specified a short list, pad with None
            self._token_datas += [None] * (lo - lt)
            lt = len(self._token_datas)
        assert lt == lo
        self.locktime = locktime
        self.set_sign_schnorr(sign_schnorr)
        return self

    @classmethod
    def pay_script(cls, output) -> str:
        """Note: we cannot make this based on the bytes version since some code overrides this, so this function
        must be the basis for the data."""
        return output.to_script().hex()

    @classmethod
    def pay_script_bytes(cls, output) -> bytes:
        return bfh(cls.pay_script(output))

    @classmethod
    def estimate_pubkey_size_from_x_pubkey(cls, x_pubkey):
        try:
            if x_pubkey[0:2] in ['02', '03']:  # compressed pubkey
                return 0x21
            elif x_pubkey[0:2] == '04':  # uncompressed pubkey
                return 0x41
            elif x_pubkey[0:2] == 'ff':  # bip32 extended pubkey
                return 0x21
            elif x_pubkey[0:2] == 'fe':  # old electrum extended pubkey
                return 0x41
        except Exception as e:
            pass
        return 0x21  # just guess it is compressed

    @classmethod
    def estimate_pubkey_size_for_txin(cls, txin):
        pubkeys = txin.get('pubkeys', [])
        x_pubkeys = txin.get('x_pubkeys', [])
        if pubkeys and len(pubkeys) > 0:
            return cls.estimate_pubkey_size_from_x_pubkey(pubkeys[0])
        elif x_pubkeys and len(x_pubkeys) > 0:
            return cls.estimate_pubkey_size_from_x_pubkey(x_pubkeys[0])
        else:
            return 0x21  # just guess it is compressed

    @classmethod
    def get_siglist(cls, txin, estimate_size=False, sign_schnorr=False):
        # if we have enough signatures, we use the actual pubkeys
        # otherwise, use extended pubkeys (with bip32 derivation)
        num_sig = txin.get('num_sig', 1)
        if estimate_size:
            pubkey_size = cls.estimate_pubkey_size_for_txin(txin)
            pk_list = ["00" * pubkey_size] * len(txin.get('x_pubkeys', [None]))
            # we assume that signature will be 0x48 bytes long if ECDSA, 0x41 if Schnorr
            if sign_schnorr:
                siglen = 0x41
            else:
                siglen = 0x48
            sig_list = [ "00" * siglen ] * num_sig
        else:
            pubkeys, x_pubkeys = cls.get_sorted_pubkeys(txin)
            x_signatures = txin['signatures']
            signatures = list(filter(None, x_signatures))
            is_complete = len(signatures) == num_sig
            if is_complete:
                pk_list = pubkeys
                sig_list = signatures
            else:
                pk_list = x_pubkeys
                sig_list = [sig if sig else NO_SIGNATURE for sig in x_signatures]
        return pk_list, sig_list

    @classmethod
    def input_script(cls, txin, estimate_size=False, sign_schnorr=False) -> str:
        # For already-complete transactions, scriptSig will be set and we prefer
        # to use it verbatim in order to get an exact reproduction (including
        # malleated push opcodes, etc.).
        scriptSig = txin.get('scriptSig', None)
        if scriptSig is not None:
            return scriptSig

        # For partially-signed inputs, or freshly signed transactions, the
        # scriptSig will be missing and so we construct it from pieces.
        _type = txin['type']
        if _type == 'coinbase':
            raise RuntimeError('Attempted to serialize coinbase with missing scriptSig')
        pubkeys, sig_list = cls.get_siglist(txin, estimate_size, sign_schnorr=sign_schnorr)
        script = ''.join(push_script(x) for x in sig_list)
        if _type == 'p2pk':
            pass
        elif _type == 'p2sh':
            # put op_0 before script
            script = '00' + script
            redeem_script = multisig_script(pubkeys, txin['num_sig'])
            script += push_script(redeem_script)
        elif _type == 'p2pkh':
            script += push_script(pubkeys[0])
        elif _type == 'unknown':
            raise RuntimeError('Cannot serialize unknown input with missing scriptSig')
        return script

    @classmethod
    def is_txin_complete(cls, txin):
        if txin['type'] == 'coinbase':
            return True
        num_sig = txin.get('num_sig', 1)
        if num_sig == 0:
            return True
        x_signatures = txin['signatures']
        signatures = list(filter(None, x_signatures))
        return len(signatures) == num_sig

    @classmethod
    def get_preimage_script(cls, txin):
        _type = txin['type']
        if _type == 'p2pkh':
            return txin['address'].to_script().hex()
        elif _type == 'p2sh':
            pubkeys, x_pubkeys = cls.get_sorted_pubkeys(txin)
            return multisig_script(pubkeys, txin['num_sig'])
        elif _type == 'p2pk':
            pubkey = txin['pubkeys'][0]
            return public_key_to_p2pk_script(pubkey)
        elif _type == 'unknown':
            # this approach enables most P2SH smart contracts (but take care if using OP_CODESEPARATOR)
            return txin['scriptCode']
        else:
            raise RuntimeError('Unknown txin type', _type)

    @classmethod
    def serialize_outpoint(cls, txin) -> str:
        return bh2u(cls.serialize_outpoint_bytes(txin))

    @classmethod
    def serialize_outpoint_bytes(cls, txin) -> bytes:
        return bfh(txin['prevout_hash'])[::-1] + int_to_bytes(txin['prevout_n'], 4)

    @classmethod
    def serialize_input(cls, txin, script, estimate_size=False) -> str:
        return cls.serialize_input_bytes(txin, bytes.fromhex(script), estimate_size).hex()

    @classmethod
    def serialize_input_bytes(cls, txin, script: bytes, estimate_size=False) -> bytes:
        # Prev hash and index
        b = bytearray(cls.serialize_outpoint_bytes(txin))
        # Script length, script, sequence
        b += var_int_bytes(len(script))
        b += script
        b += int_to_bytes(txin.get('sequence', 0xffffffff - 1), 4)
        # offline signing needs to know the input value (and possibly also the token_data)
        if ('value' in txin
                and txin.get('scriptSig') is None
                and not (estimate_size or cls.is_txin_complete(txin))):
            if txin.get('token_data'):
                # New format, encapsulate value + token data (for token signing)
                b += int_to_bytes(0xff_ff_ff_ff_ff_ff_ff_ff, 8)  # Special marker for extended format
                b += var_int_bytes(txin['value'])  # Extended format value is a compactsize to save space
                wspk = token.wrap_spk(txin['token_data'], b'')  # Shortcut to get PREFIX_BYTE + serialized_token_data
                b += var_int_bytes(len(wspk))  # write compact size
                b += wspk
            else:
                # Legacy format, we write the value directly
                b += int_to_bytes(txin['value'], 8)
        return bytes(b)

    def BIP69_sort(self, *, sort_outputs=True, sort_inputs=True):
        """See https://en.bitcoin.it/wiki/BIP_0069 plus https://github.com/bitjson/cashtokens"""
        if sort_inputs:
            self._inputs.sort(key=lambda txin: (txin['prevout_hash'], txin['prevout_n']))
        if sort_outputs:
            zipped_outputs = self.outputs(tokens=True)

            # sort by (nValue, scriptPubKey, token_data)
            def output_as_tup(tup):
                output, token_data = tup
                typ, addr_like, value = output
                if token_data is None:
                    # Ensure "None" sorts before any possible token tuple
                    tok_tup = (-1, -1, -1, b'', b'')
                else:
                    tok_tup = (token_data.amount, int(token_data.has_nft()), token_data.get_capability(),
                               token_data.commitment, token_data.id)
                return value, self.pay_script(addr_like), tok_tup

            zipped_outputs.sort(key=lambda tup: output_as_tup(tup))
            # Unzip sorted outputs
            self._outputs = [output for output, _ in zipped_outputs]
            self._token_datas = [token_data for _, token_data in zipped_outputs]
        self.invalidate_common_sighash_cache()
        assert len(self._outputs) == len(self._token_datas)

    def serialize_output(self, output) -> str:
        """DO NOT USE. Does not know about tokens. Only used by satochip plugin."""
        warnings.warn("warning: deprecated Transaction.serialize_output", FutureWarning, stacklevel=2)
        output_type, addr, amount = output
        s = int_to_hex(amount, 8)
        script = self.pay_script(addr)
        s += var_int(len(script)//2)
        s += script
        return s

    def serialize_output_n_bytes(self, n: int) -> bytes:
        assert 0 <= n < len(self._outputs) 
        assert len(self._token_datas) == len(self._outputs)
        output = self._outputs[n]
        token_data = self._token_datas[n]
        output_type, addr_like_obj, amount = output
        buf = bytearray(int_to_bytes(amount, 8))
        spk = self.pay_script_bytes(addr_like_obj)
        wspk = token.wrap_spk(token_data, spk)
        buf.extend(var_int_bytes(len(wspk)))
        buf.extend(wspk)
        return bytes(buf)

    @classmethod
    def nHashType(cls):
        """Hash type in hex."""
        warnings.warn("warning: deprecated tx.nHashType()", FutureWarning, stacklevel=2)
        return 0x01 | (cls.SIGHASH_FORKID + (cls.FORKID << 8))

    def invalidate_common_sighash_cache(self):
        """Call this to invalidate the cached common sighash (computed by
        `calc_common_sighash` below).

        This is function is for advanced usage of this class where the caller
        has mutated the transaction after computing its signatures and would
        like to explicitly delete the cached common sighash.
        See `calc_common_sighash` below."""
        try: del self._cached_sighash_tup
        except AttributeError: pass

    def calc_common_sighash(self, use_cache=False):
        """ Calculate the common sighash components that are used by
        transaction signatures. If `use_cache` enabled then this will return
        already-computed values from the `._cached_sighash_tup` attribute, or
        compute them if necessary (and then store).

        For transactions with N inputs and M outputs, calculating all sighashes
        takes only O(N + M) with the cache, as opposed to O(N^2 + NM) without
        the cache.

        Returns three 32-long bytes objects: (hashPrevouts, hashSequence, hashOutputs).

        Warning: If you modify non-signature parts of the transaction
        afterwards, this cache will be wrong! """
        inputs = self.inputs()
        n_outputs = len(self.outputs())
        meta = (len(inputs), n_outputs)

        if use_cache:
            try:
                cmeta, res = self._cached_sighash_tup
            except AttributeError:
                pass
            else:
                # minimal heuristic check to detect bad cached value
                if cmeta == meta:
                    # cache hit and heuristic check ok
                    return res
                else:
                    del cmeta, res, self._cached_sighash_tup

        hashPrevouts = Hash(b''.join(self.serialize_outpoint_bytes(txin) for txin in inputs))
        hashSequence = Hash(b''.join(int_to_bytes(txin.get('sequence', 0xffffffff - 1), 4) for txin in inputs))
        hashOutputs = Hash(b''.join(self.serialize_output_n_bytes(n) for n in range(n_outputs)))

        res = hashPrevouts, hashSequence, hashOutputs
        # cach resulting value, along with some minimal metadata to defensively
        # program against cache invalidation (due to class mutation).
        self._cached_sighash_tup = meta, res
        return res

    def serialize_preimage_bytes(self, i, nHashType=0x00000041, use_cache=False) -> bytes:
        """ See `.calc_common_sighash` for explanation of use_cache feature """
        if (nHashType & 0xff) != 0x41:
            raise ValueError("other hashtypes not supported; submit a PR to fix this!")

        nVersion = int_to_bytes(self.version, 4)
        nHashType = int_to_bytes(nHashType, 4)
        nLocktime = int_to_bytes(self.locktime, 4)

        txin = self.inputs()[i]
        outpoint = self.serialize_outpoint_bytes(txin)
        preimage_script = bfh(self.get_preimage_script(txin))
        input_token = txin.get('token_data')
        if input_token is not None:
            serInputToken = token.PREFIX_BYTE + input_token.serialize()
        else:
            serInputToken = b''
        scriptCode = var_int_bytes(len(preimage_script)) + preimage_script
        try:
            amount = int_to_bytes(txin['value'], 8)
        except KeyError:
            raise InputValueMissing
        nSequence = int_to_bytes(txin.get('sequence', 0xffffffff - 1), 4)

        hashPrevouts, hashSequence, hashOutputs = self.calc_common_sighash(use_cache=use_cache)

        preimage = (nVersion + hashPrevouts + hashSequence + outpoint + serInputToken + scriptCode + amount + nSequence
                    + hashOutputs + nLocktime + nHashType)
        return preimage

    def serialize_preimage(self, i, nHashType=0x00000041, use_cache=False) -> str:
        return self.serialize_preimage_bytes(i, nHashType, use_cache).hex()

    def serialize_bytes(self, estimate_size=False) -> bytes:
        nVersion = int_to_bytes(self.version, 4)
        nLocktime = int_to_bytes(self.locktime, 4)
        inputs = self.inputs()
        n_outputs = len(self.outputs())
        txins = var_int_bytes(len(inputs)) + b''.join(
            self.serialize_input_bytes(txin, bfh(self.input_script(txin, estimate_size, self._sign_schnorr)),
                                       estimate_size)
            for txin in inputs)
        txouts = var_int_bytes(n_outputs) + b''.join(self.serialize_output_n_bytes(n) for n in range(n_outputs))
        return nVersion + txins + txouts + nLocktime

    def serialize(self, estimate_size=False) -> str:
        return self.serialize_bytes(estimate_size=estimate_size).hex()

    def hash(self):
        warnings.warn("warning: deprecated tx.hash()", FutureWarning, stacklevel=2)
        return self.txid()

    def txid(self):
        if not self.is_complete():
            return None
        ser = self.serialize_bytes()
        return self._txid_bytes(ser)[::-1].hex()

    def txid_fast(self):
        """ Returns the txid by immediately calculating it from self.raw,
        which is faster than calling txid() which does a full re-serialize
        each time.  Note this should only be used for tx's that you KNOW are
        complete and that don't contain our funny serialization hacks.

        (The is_complete check is also not performed here because that
        potentially can lead to unwanted tx deserialization). """
        if self.raw:
            return self._txid(self.raw)
        return self.txid()

    @classmethod
    def _txid(cls, raw_hex: str) -> str:
        return cls._txid_bytes(bfh(raw_hex))[::-1].hex()

    @staticmethod
    def _txid_bytes(raw: bytes) -> bytes:
        return Hash(raw)

    def add_inputs(self, inputs):
        self._inputs.extend(inputs)
        self.raw = None
        self.invalidate_common_sighash_cache()
 
    def set_inputs(self, inputs):
        self._inputs = inputs
        self.raw = None
        
    def add_outputs(self, outputs, token_datas=None):
        assert all(isinstance(output[1], (PublicKey, Address, ScriptOutput))
                   for output in outputs)
        if token_datas is None:
            token_datas = []
        if len(token_datas) < len(outputs):
            token_datas = [None] * (len(outputs) - len(token_datas))
        self._outputs.extend(outputs)
        self._token_datas.extend(token_datas)
        self.raw = None
        self.invalidate_common_sighash_cache()
   
    def set_outputs(self, outputs):
        assert all(isinstance(output[1], (PublicKey, Address, ScriptOutput))
                   for output in outputs) 
        self._outputs = outputs
        self.raw = None 
        token_datas = []
        self._token_datas=token_datas
        if len(token_datas) < len(outputs):
            token_datas = [None] * (len(outputs) - len(token_datas)) 
        self._token_datas.extend(token_datas)  
   
    def input_value(self):
        """ Will return the sum of all input values, if the input values
        are known (may consult self.fetched_inputs() to get a better idea of
        possible input values).  Will raise InputValueMissing if input values
        are missing. """
        try:
            return sum(x['value'] for x in (self.fetched_inputs() or self.inputs()))
        except (KeyError, TypeError, ValueError) as e:
            raise InputValueMissing from e

    def output_value(self):
        return sum(val for tp, addr, val in self.outputs())

    def get_fee(self):
        """ Try and calculate the fee based on the input data, and returns it as
        satoshis (int). Can raise InputValueMissing on tx's where fee data is
        missing, so client code should catch that. """
        # first, check if coinbase; coinbase tx always has 0 fee
        if self.inputs() and self._inputs[0].get('type') == 'coinbase':
            return 0
        # otherwise just sum up all values - may raise InputValueMissing
        return self.input_value() - self.output_value()

    @profiler
    def estimated_size(self):
        """Return an estimated tx size in bytes."""
        if not self.is_complete() or self.raw is None:
            return len(self.serialize_bytes(True))
        else:
            return len(self.raw) // 2  # ASCII hex string

    @classmethod
    def estimated_input_size(cls, txin, sign_schnorr=False):
        """Return an estimated of serialized input size in bytes."""
        script = bfh(cls.input_script(txin, True, sign_schnorr=sign_schnorr))
        return len(cls.serialize_input_bytes(txin, script, True))

    def signature_count(self):
        r = 0
        s = 0
        for txin in self.inputs():
            if txin['type'] == 'coinbase':
                continue
            signatures = list(filter(None, txin.get('signatures',[])))
            s += len(signatures)
            r += txin.get('num_sig', -1)
        return s, r

    def is_complete(self):
        s, r = self.signature_count()
        return r == s

    @staticmethod
    def verify_signature(pubkey, sig, msghash, reason=None):
        """ Given a pubkey (bytes), signature (bytes -- without sighash byte),
        and a sha256d message digest, returns True iff the signature is good
        for the given public key, False otherwise.  Does not raise normally
        unless given bad or garbage arguments.

        Optional arg 'reason' should be a list which will have a string pushed
        at the front (failure reason) on False return. """
        if (any(not arg or not isinstance(arg, bytes) for arg in (pubkey, sig, msghash))
                or len(msghash) != 32):
            raise ValueError('bad arguments to verify_signature')
        if len(sig) == 64:
            # Schnorr signatures are always exactly 64 bytes
            return schnorr.verify(pubkey, sig, msghash)
        else:
            from ecdsa import BadSignatureError, BadDigestError
            from ecdsa.der import UnexpectedDER
            # ECDSA signature
            try:
                pubkey_point = ser_to_point(pubkey)
                vk = MyVerifyingKey.from_public_point(pubkey_point, curve=SECP256k1)
                if vk.verify_digest(sig, msghash, sigdecode = ecdsa.util.sigdecode_der):
                   return True
            except (AssertionError, ValueError, TypeError,
                    BadSignatureError, BadDigestError, UnexpectedDER) as e:
                # ser_to_point will fail if pubkey is off-curve, infinity, or garbage.
                # verify_digest may also raise BadDigestError and BadSignatureError
                if isinstance(reason, list):
                    reason.insert(0, repr(e))
            except BaseException as e:
                print_error("[Transaction.verify_signature] unexpected exception", repr(e))
                if isinstance(reason, list):
                    reason.insert(0, repr(e))
            return False

    @staticmethod
    def _ecdsa_sign(sec, pre_hash):
        pkey = regenerate_key(sec)
        secexp = pkey.secret
        private_key = MySigningKey.from_secret_exponent(secexp, curve=SECP256k1)
        public_key = private_key.get_verifying_key()
        sig = private_key.sign_digest_deterministic(pre_hash, hashfunc=hashlib.sha256,
                                                    sigencode=ecdsa.util.sigencode_der)
        assert public_key.verify_digest(sig, pre_hash, sigdecode=ecdsa.util.sigdecode_der)
        return sig

    @staticmethod
    def _schnorr_sign(pubkey, sec, pre_hash, *, ndata=None):
        pubkey = bytes.fromhex(pubkey)
        sig = schnorr.sign(sec, pre_hash, ndata=ndata)
        assert schnorr.verify(pubkey, sig, pre_hash)  # verify what we just signed
        return sig

    def sign(self, keypairs, *, use_cache=False, ndata=None):
        for i, txin in enumerate(self.inputs()):
            pubkeys, x_pubkeys = self.get_sorted_pubkeys(txin)
            for j, (pubkey, x_pubkey) in enumerate(zip(pubkeys, x_pubkeys)):
                if self.is_txin_complete(txin):
                    # txin is complete
                    break
                if pubkey in keypairs:
                    _pubkey = pubkey
                    kname = 'pubkey'
                elif x_pubkey in keypairs:
                    _pubkey = x_pubkey
                    kname = 'x_pubkey'
                else:
                    continue
                print_error(f"adding signature for input#{i} sig#{j}; {kname}: {_pubkey} schnorr: {self._sign_schnorr}")
                sec, compressed = keypairs.get(_pubkey)
                self._sign_txin(i, j, sec, compressed, use_cache=use_cache, ndata=ndata)
        print_error("is_complete", self.is_complete())
        self.raw = self.serialize()

    def _sign_txin(self, i, j, sec, compressed, *, use_cache=False, ndata=None):
        """Note: precondition is self._inputs is valid (ie: tx is already deserialized)"""
        pubkey = public_key_from_private_key(sec, compressed)
        # add signature
        nHashType = 0x00000041  # hardcoded, perhaps should be taken from unsigned input dict
        pre_hash = Hash(self.serialize_preimage_bytes(i, nHashType, use_cache=use_cache))
        if self._sign_schnorr:
            sig = self._schnorr_sign(pubkey, sec, pre_hash, ndata=ndata)
        else:
            sig = self._ecdsa_sign(sec, pre_hash)
        reason = []
        if not self.verify_signature(bfh(pubkey), sig, pre_hash, reason=reason):
            print_error(f"Signature verification failed for input#{i} sig#{j}, reason: {str(reason)}")
            return None
        txin = self._inputs[i]
        txin['signatures'][j] = bh2u(sig + bytes((nHashType & 0xff,)))
        txin['pubkeys'][j] = pubkey  # needed for fd keys
        return txin

    def get_outputs(self):
        return [(addr, value) for _, addr, value in self.outputs()]

    def get_output_addresses(self):
        return [addr for addr, value in self.get_outputs()]

    def has_address(self, addr):
        return (addr in self.get_output_addresses()) or (addr in (tx.get("address") for tx in self.inputs()))

    def is_final(self):
        return not any([x.get('sequence', 0xffffffff - 1) < 0xffffffff - 1
                        for x in self.inputs()])

    def as_dict(self):
        if self.raw is None:
            self.raw = self.serialize()
        self.deserialize()
        out = {
            'hex': self.raw,
            'complete': self.is_complete(),
            'final': self.is_final(),
        }
        return out

    # This cache stores foreign (non-wallet) tx's we fetched from the network
    # for the purposes of the "fetch_input_data" mechanism. Its max size has
    # been thoughtfully calibrated to provide a decent tradeoff between
    # memory consumption and UX.
    #
    # In even aggressive/pathological cases this cache won't ever exceed
    # 100MB even when full. [see ExpiringCache.size_bytes() to test it].
    # This is acceptable considering this is Python + Qt and it eats memory
    # anyway.. and also this is 2019 ;). Note that all tx's in this cache
    # are in the non-deserialized state (hex encoded bytes only) as a memory
    # savings optimization.  Please maintain that invariant if you modify this
    # code, otherwise the cache may grow to 10x memory consumption if you
    # put deserialized tx's in here.
    _fetched_tx_cache = ExpiringCache(maxlen=1000, name="TransactionFetchCache")

    def fetch_input_data(self, wallet, done_callback=None, done_args=tuple(),
                         prog_callback=None, *, force=False, use_network=True):
        """
        Fetch all input data and put it in the 'ephemeral' dictionary, under
        'fetched_inputs'. This call potentially initiates fetching of
        prevout_hash transactions from the network for all inputs to this tx.

        The fetched data is basically used for the Transaction dialog to be able
        to display fee, actual address, and amount (value) for tx inputs.

        `wallet` should ideally have a network object, but this function still
        will work and is still useful if it does not.

        `done_callback` is called with `done_args` (only if True was returned),
        upon completion. Note that done_callback won't be called if this function
        returns False. Also note that done_callback runs in a non-main thread
        context and as such, if you want to do GUI work from within it, use
        the appropriate Qt signal/slot mechanism to dispatch work to the GUI.

        `prog_callback`, if specified, is called periodically to indicate
        progress after inputs are retrieved, and it is passed a single arg,
        "percent" (eg: 5.1, 10.3, 26.3, 76.1, etc) to indicate percent progress.

        Note 1: Results (fetched transactions) are cached, so subsequent
        calls to this function for the same transaction are cheap.

        Note 2: Multiple, rapid calls to this function will cause the previous
        asynchronous fetch operation (if active) to be canceled and only the
        latest call will result in the invocation of the done_callback if/when
        it completes.
        """
        if not self._inputs:
            return False
        if force:
            # forced-run -- start with empty list
            inps = []
        else:
            # may be a new list or list that was already in dict
            inps = self.fetched_inputs(require_complete = True)
        if len(self._inputs) == len(inps):
            # we already have results, don't do anything.
            return False
        eph = self.ephemeral
        eph['fetched_inputs'] = inps = inps.copy()  # paranoia: in case another thread is running on this list
        # Lazy imports to keep this functionality very self-contained
        # These modules are always available so no need to globally import them.
        import threading
        import queue
        import time
        from copy import deepcopy
        from collections import defaultdict
        t0 = time.time()
        t = None
        cls = __class__
        self_txid = self.txid()
        def doIt():
            """
            This function is seemingly complex, but it's really conceptually
            simple:
            1. Fetch all prevouts either from cache (wallet or global tx_cache)
            2. Or, if they aren't in either cache, then we will asynchronously
               queue the raw tx gets to the network in parallel, across *all*
               our connected servers. This is very fast, and spreads the load
               around.

            Tested with a huge tx of 600+ inputs all coming from different
            prevout_hashes on mainnet, and it's super fast:
            cd8fcc8ad75267ff9ad314e770a66a9e871be7882b7c05a7e5271c46bfca98bc """
            last_prog = -9999.0
            need_dl_txids = defaultdict(list)  # the dict of txids we will need to download (wasn't in cache)
            def prog(i, prog_total=100):
                """ notify interested code about progress """
                nonlocal last_prog
                if prog_callback:
                    prog = ((i+1)*100.0)/prog_total
                    if prog - last_prog > 5.0:
                        prog_callback(prog)
                        last_prog = prog
            while eph.get('_fetch') == t and len(inps) < len(self._inputs):
                i = len(inps)
                inp = deepcopy(self._inputs[i])
                typ, prevout_hash, n, addr, value = inp.get('type'), inp.get('prevout_hash'), inp.get('prevout_n'), inp.get('address'), inp.get('value')
                if not prevout_hash or n is None:
                    raise RuntimeError('Missing prevout_hash and/or prevout_n')
                if typ != 'coinbase' and (not isinstance(addr, Address) or value is None):
                    tx = cls.tx_cache_get(prevout_hash) or wallet.transactions.get(prevout_hash)
                    if tx:
                        # Tx was in cache or wallet.transactions, proceed
                        # note that the tx here should be in the "not
                        # deserialized" state
                        if tx.raw:
                            # Note we deserialize a *copy* of the tx so as to
                            # save memory.  We do not want to deserialize the
                            # cached tx because if we do so, the cache will
                            # contain a deserialized tx which will take up
                            # several times the memory when deserialized due to
                            # Python's memory use being less efficient than the
                            # binary-only raw bytes.  So if you modify this code
                            # do bear that in mind.
                            tx = Transaction(tx.raw)
                            try:
                                tx.deserialize()
                                # The below txid check is commented-out as
                                # we trust wallet tx's and the network
                                # tx's that fail this check are never
                                # put in cache anyway.
                                #txid = tx._txid(tx.raw)
                                #if txid != prevout_hash: # sanity check
                                #    print_error("fetch_input_data: cached prevout_hash {} != tx.txid() {}, ignoring.".format(prevout_hash, txid))
                            except Exception as e:
                                print_error("fetch_input_data: WARNING failed to deserialize {}: {}".format(prevout_hash, repr(e)))
                                tx = None
                        else:
                            tx = None
                            print_error("fetch_input_data: WARNING cached tx lacked any 'raw' bytes for {}".format(prevout_hash))
                    # now, examine the deserialized tx, if it's still good
                    if tx:
                        if n < len(tx.outputs()):
                            outp = tx.outputs()[n]
                            token_data = tx.token_datas()[n]
                            addr, value = outp[1], outp[2]
                            inp['value'] = value
                            inp['address'] = addr
                            inp['token_data'] = token_data
                            print_error("fetch_input_data: fetched cached", i, addr, value)
                        else:
                            print_error("fetch_input_data: ** FIXME ** should never happen -- n={} >= len(tx.outputs())={} for prevout {}".format(n, len(tx.outputs()), prevout_hash))
                    else:
                        # tx was not in cache or wallet.transactions, mark
                        # it for download below (this branch can also execute
                        # in the unlikely case where there was an error above)
                        need_dl_txids[prevout_hash].append((i, n))  # remember the input# as well as the prevout_n

                inps.append(inp) # append either cached result or as-yet-incomplete copy of _inputs[i]
            # Now, download the tx's we didn't find above if network is available
            # and caller said it's ok to go out ot network.. otherwise just return
            # what we have
            if use_network and eph.get('_fetch') == t and wallet.network:
                callback_funcs_to_cancel = set()
                try:  # the whole point of this try block is the `finally` way below...
                    prog(-1)  # tell interested code that progress is now 0%
                    # Next, queue the transaction.get requests, spreading them
                    # out randomly over the connected interfaces
                    q = queue.Queue()
                    q_ct = 0
                    bad_txids = set()
                    def put_in_queue_and_cache(r):
                        """ we cache the results directly in the network callback
                        as even if the user cancels the operation, we would like
                        to save the returned tx in our cache, since we did the
                        work to retrieve it anyway. """
                        q.put(r)  # put the result in the queue no matter what it is
                        txid = ''
                        try:
                            # Below will raise if response was 'error' or
                            # otherwise invalid. Note: for performance reasons
                            # we don't validate the tx here or deserialize it as
                            # this function runs in the network thread and we
                            # don't want to eat up that thread's CPU time
                            # needlessly. Also note the cache doesn't store
                            # deserializd tx's so as to save memory. We
                            # always deserialize a copy when reading the cache.
                            tx = Transaction(r['result'])
                            txid = r['params'][0]
                            assert txid == cls._txid(tx.raw), "txid-is-sane-check"  # protection against phony responses
                            cls.tx_cache_put(tx=tx, txid=txid)  # save tx to cache here
                        except Exception as e:
                            # response was not valid, ignore (don't cache)
                            if txid:  # txid may be '' if KeyError from r['result'] above
                                bad_txids.add(txid)
                            print_error("fetch_input_data: put_in_queue_and_cache fail for txid:", txid, repr(e))
                    for txid, l in need_dl_txids.items():
                        wallet.network.queue_request('blockchain.transaction.get', [txid],
                                                     interface='random',
                                                     callback=put_in_queue_and_cache)
                        callback_funcs_to_cancel.add(put_in_queue_and_cache)
                        q_ct += 1

                    def get_bh():
                        if eph.get('block_height'):
                            return False
                        lh = wallet.network.get_server_height() or wallet.get_local_height()
                        def got_tx_info(r):
                            q.put('block_height')  # indicate to other thread we got the block_height reply from network
                            try:
                                confs = r.get('result').get('confirmations', 0)  # will raise of error reply
                                if confs and lh:
                                    # the whole point.. was to get this piece of data.. the block_height
                                    eph['block_height'] = bh = lh - confs + 1
                                    print_error('fetch_input_data: got tx block height', bh)
                                else:
                                    print_error('fetch_input_data: tx block height could not be determined')
                            except Exception as e:
                                print_error('fetch_input_data: get_bh fail:', str(e), r)
                        if self_txid:
                            wallet.network.queue_request('blockchain.transaction.get', [self_txid,True],
                                                         interface=None, callback=got_tx_info)
                            callback_funcs_to_cancel.add(got_tx_info)
                            return True
                    if get_bh():
                        q_ct += 1

                    class ErrorResp(Exception):
                        pass
                    for i in range(q_ct):
                        # now, read the q back, with a 10 second timeout, and
                        # populate the inputs
                        try:
                            r = q.get(timeout=10)
                            if eph.get('_fetch') != t:
                                # early abort from func, canceled
                                break
                            if r == 'block_height':
                                # ignore block_height reply from network.. was already processed in other thread in got_tx_info above
                                continue
                            if r.get('error'):
                                msg = r.get('error')
                                if isinstance(msg, dict):
                                    msg = msg.get('message') or 'unknown error'
                                raise ErrorResp(msg)
                            rawhex = r['result']
                            txid = r['params'][0]
                            assert txid not in bad_txids, "txid marked bad"  # skip if was marked bad by our callback code
                            tx = Transaction(rawhex); tx.deserialize()
                            for item in need_dl_txids[txid]:
                                ii, n = item
                                assert n < len(tx.outputs())
                                tup = tx.outputs(tokens=True)[n]
                                outp, token_data = tup
                                addr, value = outp[1], outp[2]
                                inps[ii]['value'] = value
                                inps[ii]['address'] = addr
                                inps[ii]['token_data'] = token_data
                                print_error("fetch_input_data: fetched from network", ii, addr, value, token_data)
                            prog(i, q_ct)  # tell interested code of progress
                        except queue.Empty:
                            print_error("fetch_input_data: timed out after 10.0s fetching from network, giving up.")
                            break
                        except Exception as e:
                            print_error("fetch_input_data:", repr(e))
                finally:
                    # force-cancel any extant requests -- this is especially
                    # crucial on error/timeout/failure.
                    for func in callback_funcs_to_cancel:
                        wallet.network.cancel_requests(func)
            if len(inps) == len(self._inputs) and eph.get('_fetch') == t:  # sanity check
                eph.pop('_fetch', None)  # potential race condition here, popping wrong t -- but in practice w/ CPython threading it won't matter
                print_error(f"fetch_input_data: elapsed {(time.time()-t0):.4f} sec")
                if done_callback:
                    done_callback(*done_args)
        # /doIt
        t = threading.Thread(target=doIt, daemon=True)
        eph['_fetch'] = t
        t.start()
        return True

    def fetched_inputs(self, *, require_complete=False):
        """ Returns the complete list of asynchronously fetched inputs for
        this tx, if they exist. If the list is not yet fully retrieved, and
        require_complete == False, returns what it has so far
        (the returned list will always be exactly equal to len(self._inputs),
        with not-yet downloaded inputs coming from self._inputs and not
        necessarily containing a good 'address' or 'value').

        If the download failed completely or was never started, will return the
        empty list [].

        Note that some inputs may still lack key: 'value' if there was a network
        error in retrieving them or if the download is still in progress."""
        if self._inputs:
            ret = self.ephemeral.get('fetched_inputs') or []
            diff = len(self._inputs) - len(ret)
            if diff > 0 and self.ephemeral.get('_fetch') and not require_complete:
                # in progress.. so return what we have so far
                return ret + self._inputs[len(ret):]
            elif diff == 0 and (not require_complete or not self.ephemeral.get('_fetch')):
                # finished *or* in-progress and require_complete==False
                return ret
        return []

    def fetch_cancel(self) -> bool:
        """ Cancels the currently-active running fetch operation, if any """
        return bool(self.ephemeral.pop('_fetch', None))

    @classmethod
    def tx_cache_get(cls, txid : str) -> object:
        """ Attempts to retrieve txid from the tx cache that this class
        keeps in-memory.  Returns None on failure. The returned tx is
        not deserialized, and is a copy of the one in the cache. """
        tx = cls._fetched_tx_cache.get(txid)
        if tx is not None and tx.raw:
            # make sure to return a copy of the transaction from the cache
            # so that if caller does .deserialize(), *his* instance will
            # use up 10x memory consumption, and not the cached instance which
            # should just be an undeserialized raw tx.
            return Transaction(tx.raw)
        return None

    @classmethod
    def tx_cache_put(cls, tx : object, txid : str = None):
        """ Puts a non-deserialized copy of tx into the tx_cache. """
        if not tx or not tx.raw:
            raise ValueError('Please pass a tx which has a valid .raw attribute!')
        txid = txid or cls._txid(tx.raw)  # optionally, caller can pass-in txid to save CPU time for hashing
        cls._fetched_tx_cache.put(txid, Transaction(tx.raw))


def tx_from_str(txt):
    """json or raw hexadecimal"""
    import json
    txt = txt.strip()
    if not txt:
        raise ValueError("empty string")
    try:
        bfh(txt)
        is_hex = True
    except:
        is_hex = False
    if is_hex:
        return txt
    tx_dict = json.loads(str(txt))
    assert "hex" in tx_dict.keys()
    return tx_dict["hex"]


# ---
class OPReturn:
    """ OPReturn helper namespace. Used by GUI main_window.py and also
    electroncash/commands.py """
    class Error(Exception):
        """ thrown when the OP_RETURN for a tx not of the right format """

    class TooLarge(Error):
        """ thrown when the OP_RETURN for a tx is >220 bytes """

    no_length_check = False

    @staticmethod
    def output_for_stringdata(op_return):
        from .i18n import _
        if not isinstance(op_return, str):
            raise OPReturn.Error('OP_RETURN parameter needs to be of type str!')
        op_return_code = "OP_RETURN "
        op_return_encoded = op_return.encode('utf-8')
        if not OPReturn.no_length_check and len(op_return_encoded) > 220:
            raise OPReturn.TooLarge(_("OP_RETURN message too large, needs to be no longer than 220 bytes"))
        op_return_payload = op_return_encoded.hex()
        script = op_return_code + op_return_payload
        amount = 0
        return (TYPE_SCRIPT, ScriptOutput.from_string(script), amount)

    @staticmethod
    def output_for_rawhex(op_return):
        from .i18n import _
        if not isinstance(op_return, str):
            raise OPReturn.Error('OP_RETURN parameter needs to be of type str!')
        if op_return == 'empty':
            op_return = ''
        try:
            op_return_script = b'\x6a' + bytes.fromhex(op_return.strip())
        except ValueError:
            raise OPReturn.Error(_('OP_RETURN script expected to be hexadecimal bytes'))
        if len(op_return_script) > 223:
            raise OPReturn.TooLarge(_("OP_RETURN script too large, needs to be no longer than 223 bytes"))
        amount = 0
        return (TYPE_SCRIPT, ScriptOutput.protocol_factory(op_return_script), amount)
# /OPReturn
