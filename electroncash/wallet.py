# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Electron Cash - Bitcoin Cash thin client
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

# Wallet classes:
#   - ImportedAddressWallet: imported address, no keystore
#   - ImportedPrivkeyWallet: imported private keys, keystore
#   - Standard_Wallet: one keystore, P2PKH
#   - Multisig_Wallet: several keystores, P2SH
#   - MultiXPubWallet: several keystores, P2PKH

import copy
import errno
import json
import hashlib
import itertools
import math
import os
import queue
import random
import threading
import time
from collections import defaultdict, namedtuple, OrderedDict
from enum import Enum, auto
from functools import partial
from typing import Any, DefaultDict, Dict, ItemsView, Iterable, List, Optional, Set, Tuple, Union, ValuesView
from typing import OrderedDict as OrderedDictType

from .i18n import ngettext
from .util import (NotEnoughFunds, ExcessiveFee, PrintError, UserCancelled, profiler, format_satoshis, format_time,
                   finalization_print_error, to_string, TimeoutException)
from . import util

from .address import Address, Script, ScriptOutput, PublicKey, OpCodes
from .bitcoin import *
from .version import *
from .keystore import load_keystore, Hardware_KeyStore, Imported_KeyStore, BIP32_KeyStore, xpubkey_to_address
from . import networks
from . import keystore
from .storage import multisig_type, WalletStorage

from . import transaction
from .transaction import Transaction, InputValueMissing
from .plugins import run_hook
from . import bitcoin
from . import coinchooser
from .synchronizer import Synchronizer
from .verifier import SPV, SPVDelegate
from .rpa.rpa_manager import RpaManager
from . import schnorr
from . import ecc_fast
from .blockchain import NULL_HASH_HEX
from . import token


from . import paymentrequest
from .paymentrequest import InvoiceStore, PR_PAID, PR_UNCONFIRMED, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED
from .contacts import Contacts
from . import cashacct
from . import slp
from .rpa import paycode as rpa


def _(message):
    return message


TX_STATUS = [
    _('Unconfirmed parent'),
    _('Low fee'),
    _('Unconfirmed'),
    _('Not Verified'),
]

class DSPStatus(Enum):
    UNKNOWN = 1
    NOT_APPLICABLE = 2
    PROCESSING = 3
    UNDETECTED = 4
    DETECTED = 5

del _
from .i18n import _

DEFAULT_CONFIRMED_ONLY = False


def relayfee(network):
    RELAY_FEE = 1000
    MAX_RELAY_FEE = 50000
    f = network.relay_fee if network and network.relay_fee else RELAY_FEE
    return min(f, MAX_RELAY_FEE)


def dust_threshold(network):
    # Change < dust threshold is added to the tx fee
    #return 182 * 3 * relayfee(network) / 1000 # original Electrum logic
    #return 1 # <-- was this value until late Sept. 2018
    return 546  # hard-coded Bitcoin Cash dust threshold. Was changed to this as of Sept. 2018


def sweep_preparations(privkeys, network, imax=100):
    class InputsMaxxed(Exception):
        pass

    def append_utxos_to_inputs(inputs, pubkey, txin_type):
        if txin_type == 'p2pkh':
            address = Address.from_pubkey(pubkey)
        else:
            address = PublicKey.from_pubkey(pubkey)
        sh = address.to_scripthash_hex()
        try:
            # First try the protocol 1.5 version to explicitly ask for no tokens
            u = network.synchronous_get(('blockchain.scripthash.listunspent', [sh, "exclude_tokens"]))
        except util.ServerError as e:
            # Failure; server likely doesn't know anything about tokens, fallback to 1.4 API
            util.print_error(f"sweep_preparations got exception from listunspent: \"{e}\""
                             " (falling-back to 1.4-compatible call)")
            u = network.synchronous_get(('blockchain.scripthash.listunspent', [sh]))
        for item in u:
            if len(inputs) >= imax:
                raise InputsMaxxed()
            item['address'] = address
            item['type'] = txin_type
            item['prevout_hash'] = item['tx_hash']
            item['prevout_n'] = item['tx_pos']
            item['pubkeys'] = [pubkey]
            item['x_pubkeys'] = [pubkey]
            item['signatures'] = [None]
            item['num_sig'] = 1
            inputs.append(item)

    def find_utxos_for_privkey(txin_type, privkey, compressed):
        pubkey = bitcoin.public_key_from_private_key(privkey, compressed)
        append_utxos_to_inputs(inputs, pubkey, txin_type)
        keypairs[pubkey] = privkey, compressed

    inputs = []
    keypairs = {}
    try:
        for sec in privkeys:
            txin_type, privkey, compressed = bitcoin.deserialize_privkey(sec)
            find_utxos_for_privkey(txin_type, privkey, compressed)
            # do other lookups to increase support coverage
            if is_minikey(sec):
                # minikeys don't have a compressed byte
                # we lookup both compressed and uncompressed pubkeys
                find_utxos_for_privkey(txin_type, privkey, not compressed)
            elif txin_type == 'p2pkh':
                # WIF serialization does not distinguish p2pkh and p2pk
                # we also search for pay-to-pubkey outputs
                find_utxos_for_privkey('p2pk', privkey, compressed)
            elif txin_type == 'p2sh':
                raise ValueError(_("The specified WIF key '{}' is a p2sh WIF key. These key types cannot be swept.").format(sec))
    except InputsMaxxed:
        pass
    if not inputs:
        raise ValueError(_('No inputs found. (Note that inputs need to be confirmed)'))
    return inputs, keypairs


def sweep(privkeys, network, config, recipient, fee=None, imax=100, sign_schnorr=False):
    inputs, keypairs = sweep_preparations(privkeys, network, imax)
    total = sum(i.get('value') for i in inputs)
    if fee is None:
        outputs = [(TYPE_ADDRESS, recipient, total)]
        tx = Transaction.from_io(inputs, outputs, sign_schnorr=sign_schnorr)
        fee = config.estimate_fee(tx.estimated_size())
    if total - fee < 0:
        raise NotEnoughFunds(_('Not enough funds on address.') + '\nTotal: %d satoshis\nFee: %d'%(total, fee))
    if total - fee < dust_threshold(network):
        raise NotEnoughFunds(_('Not enough funds on address.') + '\nTotal: %d satoshis\nFee: %d\nDust Threshold: %d'%(total, fee, dust_threshold(network)))

    outputs = [(TYPE_ADDRESS, recipient, total - fee)]
    locktime = network.get_local_height()

    tx = Transaction.from_io(inputs, outputs, locktime=locktime, sign_schnorr=sign_schnorr)
    tx.BIP69_sort()
    tx.sign(keypairs)
    return tx


class TokenSendSpec:
    """Class used by Abstract_Wallet.make_token_send_tx to communicate to it what is required."""
    __slots__ = ('payto_addr', 'change_addr', 'feerate', 'non_token_utxos', 'token_utxos',
                 'send_satoshis', 'send_fungible_amounts', 'send_nfts', 'edit_nfts', 'mint_nfts')
    # The payee -- they will receive all fungibles specified as well as nfts marked for sending. Can be a local wallet
    # addresss in the case of minting or editing NFTs.
    payto_addr: Address
    # Where to send all change back to wallet (both tokens and BCH)
    change_addr: Address

    # In sats/KB
    feerate: int

    # Where we are spending from for BCH to cover the txn and fees, and also the satoshis we are sending along
    # with the tokens. Can be populated from data coming in from make_token_utxos_dict(Abstract_Wallet.get_utxos())
    # All utxos here must *not* have 'token_data'.
    non_token_utxos: Dict[str, Dict[str, Any]]  # Dict of: utxo-name ("prevout_hash:prevout_n") -> utxo dict

    # We spend send_fundible_amount and send_nfts from this set of utxos. All utxos here must have 'token_data'.
    # Note that a utxo won't get picked up for sending necessarily if it appears in this dict. It's just the "pool"
    # of token-bearing utxos to use for the send_fungible_amount, send_nfts, edit_nfts, and mint_nfts fields below.
    token_utxos: Dict[str, Dict[str, Any]]  # utxo-name ("prevout_hash:n") -> utxo

    send_satoshis: int  # BCH to attach, can be 0
    send_fungible_amounts: Dict[str, int]  # token-id (hex) -> fungible amount to send. Can be empty.
    # Set of utxo-names (which must exist in token_utxos above) that contain NFTs which are marked for sending
    send_nfts: Set[str]  # Can be empty

    # Dict of utxo-name -> new commitment that are mutable or minting NFTs which should have their commitment modified
    # All utxo-name keys in this dict must appear in token_utxos and also be marked for sending in send_nfts
    edit_nfts: Dict[str, bytes]  # Can be empty

    # Dict of utxo-name -> newly minted NFTs to send to the payto_addr.  All utxo-name keys appearing here must
    # appear in token_utxos and also have been marked for "sending" in send_nfts.  The utxo-name's UTXO should contain
    # a minting NFT.  The newly-generated NFTs will inherit category-id of the utxo-name that is referenced, but with
    # the specified Capability and commitment (commitment can be zero-length bytes).
    mint_nfts: Dict[str, List[Tuple[token.Capability, bytes]]]  # Can be empty

    def __init__(self):
        (self.non_token_utxos, self.token_utxos, self.send_fungible_amounts, self.send_nfts, self.edit_nfts,
         self.mint_nfts) = dict(), dict(), dict(), set(), dict(), dict()
        self.feerate, self.send_satoshis = 0, 0

    def get_utxo(self, utxoname: str) -> Optional[Dict[str, Any]]:
        return self.token_utxos.get(utxoname) or self.non_token_utxos.get(utxoname)

    @staticmethod
    def utxo_name(utxo: Dict[str, Any]) -> str:
        return f"{utxo['prevout_hash']}:{utxo['prevout_n']}"

    @classmethod
    def make_token_utxos_dict(cls, utxo_list: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        ret: Dict[str, Dict[str, Any]] = dict()
        for utxo in utxo_list:
            ret[cls.utxo_name(utxo)] = utxo
        return ret


class TokensBurnedError(RuntimeError):
    """Raised by Abstract_Wallet.make_token_send_tx if there is some internal logic error and tokens are being
     burned by the txn in question.  In practice this should never actually be raised unless there are bugs
     in that method."""


class Abstract_Wallet(PrintError, SPVDelegate):
    """
    Wallet classes are created to handle various address generation methods.
    Completion states (watching-only, single account, no seed, etc) are handled inside classes.
    """

    max_change_outputs = 3

    def __init__(self, storage):
        self.electrum_version = PACKAGE_VERSION
        self.storage = storage
        self.thread = None  # this is used by the qt main_window to store a QThread. We just make sure it's always defined as an attribute here.
        self.network = None
        # verifier (SPV) and synchronizer are started in start_threads
        self.verifier: Optional[SPV] = None
        self.synchronizer: Optional[Synchronizer] = None
        self.rpa_manager: Optional[RpaManager] = None
        self.weak_window = None  # Some of the GUI classes, such as the Qt ElectrumWindow, use this to refer back to themselves.  This should always be a weakref.ref (Weak.ref), or None
        # CashAccounts subsystem. Its network-dependent layer is started in
        # start_threads. Note: object instantiation should be lightweight here.
        # self.cashacct.load() is called later in this function to load data.
        self.cashacct = cashacct.CashAcct(self)
        self.slp = slp.WalletData(self)
        finalization_print_error(self.cashacct)  # debug object lifecycle
        finalization_print_error(self.slp)  # debug object lifecycle

        # Removes defunct entries from self.pruned_txo asynchronously
        self.pruned_txo_cleaner_thread = None

        # Cache of Address -> (c,u,x) balance. This cache is used by
        # get_addr_balance to significantly speed it up (it is called a lot).
        # Cache entries are invalidated when tx's are seen involving this
        # address (address history chages). Entries to this cache are added
        # only inside get_addr_balance.
        # Note that this data structure is touched by the network and GUI
        # thread concurrently without the use of locks, because Python GIL
        # allows us to get away with such things. As such do not iterate over
        # this dict, but simply add/remove items to/from it in 1-liners (which
        # Python's GIL makes thread-safe implicitly).
        self._addr_bal_cache = {}

        # We keep a set of the wallet and receiving addresses so that is_mine()
        # checks are O(logN) rather than O(N). This creates/resets that cache.
        self.invalidate_address_set_cache()

        # This cache is used by self.try_to_get_tx(), and saves us from having to
        # do repeated network lookups in the case where we are looking up the
        # same txn multiple times from the network, and also allows us to avoid
        # returning in-wallet txns to callers of get_input_tx() and get_wallet_tx().
        self._tx_cache: OrderedDictType[str, Transaction] = OrderedDict()

        self.gap_limit_for_change = 20  # constant
        # saved fields
        self.use_change            = storage.get('use_change', True)
        self.multiple_change       = storage.get('multiple_change', False)
        self.labels                = storage.get('labels', {})
        # Frozen addresses
        frozen_addresses = storage.get('frozen_addresses',[])
        self.frozen_addresses = set(Address.from_string(addr)
                                    for addr in frozen_addresses)
        # Frozen coins (UTXOs) -- note that we have 2 independent levels of "freezing": address-level and coin-level.
        # The two types of freezing are flagged independently of each other and 'spendable' is defined as a coin that satisfies
        # BOTH levels of freezing.
        self.frozen_coins = set(storage.get('frozen_coins', []))
        self.frozen_coins_tmp = set()  # in-memory only

        self.change_reserved = set(Address.from_string(a) for a in storage.get('change_reserved', ()))
        self.change_reserved_default = [Address.from_string(a) for a in storage.get('change_reserved_default', ())]
        self.change_unreserved = [Address.from_string(a) for a in storage.get('change_unreserved', ())]
        self.change_reserved_tmp = set() # in-memory only

        # address -> list(txid, height)
        history = storage.get('addr_history',{})
        self._history = self.to_Address_dict(history)

        # there is a difference between wallet.up_to_date and interface.is_up_to_date()
        # interface.is_up_to_date() returns true when all requests have been answered and processed
        # wallet.up_to_date is true when the wallet is synchronized (stronger requirement)
        self.up_to_date = False

        # The only lock. We used to have two here. That was more technical debt
        # without much purpose. 1 lock is sufficient. In particular data
        # structures that are touched by the network thread as well as the GUI
        # (such as self.transactions, history, etc) need to be synchronized
        # using this mutex.
        self.lock = threading.RLock()

        # load requests
        requests = self.storage.get('payment_requests', {})
        for key, req in requests.items():
            req['address'] = Address.from_string(key)
        self.receive_requests = {req['address']: req
                                 for req in requests.values()}

        # Transactions pending verification.  A map from tx hash to transaction
        # height.  Access is contended so a lock is needed. Client code should
        # use get_unverified_tx to get a thread-safe copy of this dict.
        self.unverified_tx = defaultdict(int)

        # Verified transactions.  Each value is a (height, timestamp, block_pos) tuple.  Access with self.lock.
        self.verified_tx = storage.get('verified_tx3', {})

        # save wallet type the first time
        if self.storage.get('wallet_type') is None:
            self.storage.put('wallet_type', self.wallet_type)

        # invoices and contacts
        self.invoices = InvoiceStore(self.storage)
        self.contacts = Contacts(self.storage)

        # txid's with network-triggered double spend proofs
        self._dsp_statuses = {}

        # cashacct is started in start_threads, but it needs to have relevant
        # data here, before the below calls happen
        self.cashacct.load()
        self.slp.load()  # try to load first so we can pick up the remove_transaction hook from load_transactions if need be

        # Now, finally, after object is constructed -- we can do this
        self.load_keystore_wrapper()
        self.load_addresses()
        self.load_transactions()
        self.build_reverse_history()

        self.check_history()

        if self.slp.need_rebuild:
            # load failed, must rebuild from self.transactions
            self.slp.rebuild()
            self.slp.save()  # commit changes to self.storage

        # Print debug message on finalization
        finalization_print_error(self, "[{}/{}] finalized".format(type(self).__name__, self.diagnostic_name()))

    @classmethod
    def to_Address_dict(cls, d):
        '''Convert a dict of strings to a dict of Adddress objects.'''
        return {Address.from_string(text): value for text, value in d.items()}

    @classmethod
    def from_Address_dict(cls, d):
        '''Convert a dict of Address objects to a dict of strings.'''
        return {addr.to_storage_string(): value
                for addr, value in d.items()}

    def diagnostic_name(self):
        return self.basename()

    def __str__(self):
        return self.basename()

    def get_master_public_key(self):
        """Subclasses that use master pubkeys should reimplement this"""
        return None

    def get_master_public_keys(self):
        """Subclasses that use master pubkeys should reimplement this"""
        return []

    def load_keystore_wrapper(self):
        """ Loads the keystore, but also tries to preserve derivation(s). Older
        Electron Cash versions would not save the derivation for all keystore
        types. So this function ensures:

        1. That on first run, we store the keystore_derivations to top-level
           storage (which is preserved always).
        2. On subsequent runs we try and load the keystore_derivations from
           storage and restore them if the individual keystore.derivation data
           items were lost (because user loaded wallet with older Electron
           Cash).

        This function is provided to allow users to switch between old and new
        EC versions.  In the future if we deprecate the wallet format, or if
        enough time has passed, this function may be removed and the simple
        self.load_keystore() may be used instead. """
        self.load_keystore()
        if not hasattr(self, 'get_keystores'):
            return
        from .keystore import Deterministic_KeyStore, Old_KeyStore
        keystores = self.get_keystores()
        keystore_derivations = self.storage.get('keystore_derivations', [])
        if len(keystore_derivations) != len(keystores):
            keystore_derivations = [None] * len(keystores)
        updated, updated_ks, updated_st = False, False, False
        for i, keystore in enumerate(keystores):
            if i == 0 and isinstance(keystore, Deterministic_KeyStore) and not keystore.seed_type:
                # Attempt to update keystore.seed_type
                if isinstance(keystore, Old_KeyStore):
                    keystore.seed_type = 'old'
                    updated_st = True
                else:
                    # attempt to restore the seed_type based on wallet saved "seed_type"
                    typ = self.storage.get('seed_type')
                    if typ in ('standard', 'electrum'):
                        keystore.seed_type = 'electrum'
                        updated_st = True
                    elif typ == 'bip39':
                        keystore.seed_type = 'bip39'
                        updated_st = True
            saved_der = keystore_derivations[i]
            der = (keystore.has_derivation() and keystore.derivation) or None
            if der != saved_der:
                if der:
                    # keystore had a derivation, but top-level storage did not
                    # (this branch is typically taken on first run after
                    # restoring from seed or creating a new wallet)
                    keystore_derivations[i] = saved_der = der
                    updated = True
                elif saved_der:
                    # we had a derivation but keystore did not. This branch is
                    # taken if the user has loaded this wallet with an older
                    # version of Electron Cash. Attempt to restore their
                    # derivation item in keystore.
                    keystore.derivation = der  # write to keystore
                    updated_ks = True  # tell it to re-save
        if updated:
            self.print_error("Updated keystore_derivations")
            self.storage.put('keystore_derivations', keystore_derivations)
        if updated_ks or updated_st:
            if updated_ks:
                self.print_error("Updated keystore (lost derivations restored)")
            if updated_st:
                self.print_error("Updated keystore (lost seed_type restored)")
            self.save_keystore()
        if any((updated, updated_ks, updated_st)):
            self.storage.write()

    @profiler
    def load_transactions(self):
        txi = self.storage.get('txi', {})
        self.txi = {tx_hash: self.to_Address_dict(value)
                    for tx_hash, value in txi.items()
                    # skip empty entries to save memory and disk space
                    if value}
        # Map of tx_hash -> map of address -> list of tuple(prevout_n, value, iscoinbase)
        txo = self.storage.get('txo', {})
        self.txo = {tx_hash: self.to_Address_dict(value)
                    for tx_hash, value in txo.items()
                    # skip empty entries to save memory and disk space
                    if value}
        # Populates self.ct_txi: Map of tx_hash -> map of address -> map of "prevout_hash" -> map of n -> token_data
        bad_ct_entry_ctr = self.load_ct_txi()
        # Populates self.ct_txo: Map of tx_hash -> map of address -> map of prevout_n -> token.OutputData
        bad_ct_entry_ctr += self.load_ct_txo()
        # Detect if user opened wallet in older EC and we need to rebuild ct_txi and ct_txo
        ct_txid_hash = self.storage.get('ct_txid_hash', None) if not bad_ct_entry_ctr else None
        self.tx_fees = self.storage.get('tx_fees', {})
        self.pruned_txo = self.storage.get('pruned_txo', {})
        self.pruned_txo_values = set(self.pruned_txo.values())
        tx_list = self.storage.get('transactions', {})
        self.transactions = {}
        txid_hasher = hashlib.sha256() if not bad_ct_entry_ctr else None
        for tx_hash, raw in sorted(tx_list.items(), key=lambda x: x[0]):
            if txid_hasher:
                txid_hasher.update(bytes.fromhex(tx_hash))
            tx = Transaction(raw)
            self.transactions[tx_hash] = tx
            if (not self.txi.get(tx_hash) and not self.txo.get(tx_hash) and (tx_hash not in self.pruned_txo_values)
                    and not self.ct_txi.get(tx_hash) and not self.ct_txo.get(tx_hash)):
                self.print_error("removing unreferenced tx", tx_hash)
                self.transactions.pop(tx_hash)
                self.cashacct.remove_transaction_hook(tx_hash)
                self.slp.rm_tx(tx_hash)
        if txid_hasher is None or txid_hasher.digest().hex() != ct_txid_hash:
            # Need to rebuild ct_txi and ct_txo
            # This code is here to detect case where user opened same wallet in an older version of
            # electron cash which does not track CashTokens
            self.rebuild_ct_txi_txo()

    @profiler
    def load_ct_txo(self) -> int:
        """Populates self.ct_txo from storage key 'ct_txo'. """
        ct_txo = self.storage.get('ct_txo', {})
        self.ct_txo = {tx_hash: self.to_Address_dict(value)
                       for tx_hash, value in ct_txo.items()
                       # skip empty entries to save memory and disk space
                       if value}
        # Convert hex data values to token.OutputData
        bad_ct_entry_ctr = 0
        for tx_hash, addrmap in self.ct_txo.items():
            for addr, outputmap in addrmap.items():
                for n, hexdata in outputmap.copy().items():
                    token_data = token.OutputData.fromhex(hexdata)
                    if not token_data:
                        bad_ct_entry_ctr += 1
                        del outputmap[n]
                        self.print_error(f"load_ct_txo: cannot deserialize token for {tx_hash}:{n} hexdata: {hexdata},"
                                         f" skipping")
                        continue
                    del outputmap[n]
                    n = int(n)  # JSON doesn't support non-string keys, so convert this key back to int
                    outputmap[n] = token_data
        return bad_ct_entry_ctr

    @profiler
    def save_ct_txo(self):
        ct_txo = {tx_hash: self.from_Address_dict(value)
                  for tx_hash, value in self.ct_txo.items()
                  # skip empty entries to save memory and disk space
                  if value}
        ct_txo = copy.deepcopy(ct_txo)  # Take a deep copy since we mutate this below
        # Convert token.OutputData values to hexdata
        for tx_hash, addrmap in ct_txo.items():
            for addr_txt, outputmap in addrmap.items():
                for n, token_data in outputmap.copy().items():
                    if not token_data:
                        continue
                    hexdata = token_data.hex()
                    outputmap[n] = hexdata
        self.storage.put('ct_txo', ct_txo)

    @profiler
    def load_ct_txi(self) -> int:
        """Populates self.ct_txi:
           Map of tx_hash -> map of address -> map of "prevout_hash" -> map of prevout_n -> token_data"""
        ct_txi = self.storage.get('ct_txi', {})
        self.ct_txi = {tx_hash: self.to_Address_dict(value)
                       for tx_hash, value in ct_txi.items()
                       # skip empty entries to save memory and disk space
                       if value}
        # Convert hex data values to token.OutputData
        bad_ct_entry_ctr = 0
        for tx_hash, addrmap in self.ct_txi.items():
            for addr, prevout_hash_map in addrmap.items():
                for prevout_hash, token_data_map in prevout_hash_map.items():
                    for prevout_n, hexdata in token_data_map.copy().items():
                        token_data = token.OutputData.fromhex(hexdata)
                        if not token_data:
                            bad_ct_entry_ctr += 1
                            del token_data_map[prevout_n]
                            self.print_error(f"load_ct_txi: cannot deserialize token for {tx_hash}:{prevout_n}"
                                             f" hexdata: {hexdata}, skipping")
                            continue
                        del token_data_map[prevout_n]
                        # JSON doesn't support non-string keys, so convert this key back to int
                        prevout_n = int(prevout_n)
                        token_data_map[prevout_n] = token_data  # Convert hexdata to token.OutputData for usage
        return bad_ct_entry_ctr

    @profiler
    def save_ct_txi(self):
        ct_txi = {tx_hash: self.from_Address_dict(value)
                  for tx_hash, value in self.ct_txi.items()
                  # skip empty entries to save memory and disk space
                  if value}
        ct_txi = copy.deepcopy(ct_txi)  # Take a deep copy since we mutate this below
        # Convert token.outputData values to hexdata
        for tx_hash, addrmap in ct_txi.items():
            for addr, prevout_hash_map in addrmap.items():
                for prevout_hash, token_data_map in prevout_hash_map.items():
                    for prevout_n, token_data in token_data_map.copy().items():
                        if not token_data:
                            continue
                        hexdata = token_data.hex()
                        token_data_map[prevout_n] = hexdata  # Overwrite token_data with hex for storage
        self.storage.put('ct_txi', ct_txi)

    @profiler
    def rebuild_ct_txi_txo(self):
        self.print_error("Rebuilding CashTokens-specific txi and txo maps ...")
        self.ct_txo.clear()
        self.ct_txi.clear()
        txn_cache = {}
        # First, do txo
        # Populates self.ct_txo: Map of tx_hash -> map of address -> map of prevout_n -> token.OutputData
        for tx_hash, addrmap in self.txo.items():
            if not addrmap:
                self.print_error(f"ct_txo: no addrmap for {tx_hash}")
                continue
            tx = txn_cache.get(tx_hash) or self.transactions.get(tx_hash)
            if not tx:
                self.print_error(f"rebuild_ct_txi_txo: Unknown transaction in self.txo: {tx_hash}")
                continue
            if tx is self.transactions.get(tx_hash):
                # Take a deep copy to avoid deserializing txn from map and wasting memory, temporarily cache the result
                txn_cache[tx_hash] = tx = copy.deepcopy(tx)
            # Next, walk through every entry in self.txo and figure out if it has token_data, and if so, put token_data
            # into self.ct_txo
            tx_outputs = tx.outputs(tokens=True)
            ct_addr_map = self.ct_txo.get(tx_hash, {})
            ct_addr_map_was_empty = not ct_addr_map
            for addr, outputlist in addrmap.items():
                ct_output_map = ct_addr_map.get(addr, {})
                ct_output_map_was_empty = not ct_output_map
                for ll in outputlist:
                    n, value, is_coinbase = ll
                    token_data = tx_outputs[n][1]
                    if token_data is not None:
                        self.print_error(f"ct_txo: Adding {tx_hash} -> {addr} -> {n} -> {token_data!r}")
                        ct_output_map[n] = token_data
                if ct_output_map_was_empty and ct_output_map:
                    ct_addr_map[addr] = ct_output_map
            if ct_addr_map_was_empty and ct_addr_map:
                self.ct_txo[tx_hash] = ct_addr_map
        # Next, do txi
        # Populates self.ct_txi: Map of tx_hash -> map of address -> map of "prevout_hash" -> map of n -> token_data
        for tx_hash, addrmap in self.txi.items():
            if not addrmap:
                self.print_error(f"ct_txi: no addrmap for {tx_hash}")
                continue
            ct_addr_map = self.ct_txi.get(tx_hash, {})
            ct_addr_map_was_empty = not ct_addr_map
            for addr, ll in addrmap.items():
                if not ll:
                    self.print_error(f"ct_txi: no ll for {tx_hash} -> {addr}")
                ct_prevout_hash_map = ct_addr_map.get(addr, {})
                ct_prevout_hash_map_was_empty = not ct_prevout_hash_map
                for tup in ll:
                    ser, _ = tup
                    try:
                        prevout_hash, prevout_n = ser.split(':', 1)
                        prevout_n = int(prevout_n)
                    except ValueError:
                        self.print_error(f"rebuild_ct_txi_txo: Bad output point serialization in self.txi: {ser}")
                        continue
                    token_data = self.ct_txo.get(prevout_hash, {}).get(addr, {}).get(prevout_n, None)
                    # The below is commented-out for now since it should not be necessary to deserialize the same
                    # txns again that we already processed for self.ct_txo
                    # if not token_data:
                    #     # Fall-back to trying to deser a known txn
                    #     tx = self.transactions.get(prevout_hash)
                    #     if not tx:
                    #         self.print_error(f"rebuild_ct_txi_txo: Unknown transaction in self.txi: {prevout_hash}")
                    #         continue
                    #     tx = copy.deepcopy(tx)  # Take a deep copy to save memory
                    #     _, token_data = tx.outputs(tokens=True)[prevout_n]
                    if token_data is not None:
                        self.print_error(f"ct_txi: Adding {tx_hash} -> {addr} -> {prevout_hash} -> {prevout_n} -> {token_data!r}")
                        ct_prevout_n_map = ct_prevout_hash_map.get(prevout_hash, {})
                        ct_prevout_n_map_was_empty = not ct_prevout_n_map
                        ct_prevout_n_map[prevout_n] = token_data
                        if ct_prevout_n_map_was_empty:
                            ct_prevout_hash_map[prevout_hash] = ct_prevout_n_map
                if ct_prevout_hash_map_was_empty and ct_prevout_hash_map:
                    ct_addr_map[addr] = ct_prevout_hash_map
            if ct_addr_map_was_empty and ct_addr_map:
                self.ct_txi[tx_hash] = ct_addr_map
        self.print_error(f"rebuild_ct_txi_txo: ct_txi: {len(self.ct_txi)}, ct_txo: {len(self.ct_txo)}")

    @profiler
    def save_transactions(self, write=False):
        with self.lock:
            txid_hasher = hashlib.sha256()
            tx = {}
            for tx_hash, txn in sorted(self.transactions.items(), key=lambda x: x[0]):
                txid_hasher.update(bytes.fromhex(tx_hash))
                tx[tx_hash] = str(txn)
            self.storage.put('transactions', tx)
            txi = {tx_hash: self.from_Address_dict(value)
                   for tx_hash, value in self.txi.items()
                   # skip empty entries to save memory and disk space
                   if value}
            txo = {tx_hash: self.from_Address_dict(value)
                   for tx_hash, value in self.txo.items()
                   # skip empty entries to save memory and disk space
                   if value}
            self.storage.put('txi', txi)
            self.storage.put('txo', txo)
            self.storage.put('tx_fees', self.tx_fees)
            self.storage.put('pruned_txo', self.pruned_txo)
            history = self.from_Address_dict(self._history)
            self.storage.put('addr_history', history)
            self.slp.save()
            self.save_ct_txi()
            self.save_ct_txo()
            ct_txid_hash = txid_hasher.digest().hex()
            self.storage.put('ct_txid_hash', ct_txid_hash)
            if write:
                self.storage.write()

    def save_verified_tx(self, write=False):
        with self.lock:
            self.storage.put('verified_tx3', self.verified_tx)
            self.cashacct.save()
            if write:
                self.storage.write()

    def save_change_reservations(self):
        with self.lock:
            self.storage.put('change_reserved_default', [a.to_storage_string() for a in self.change_reserved_default])
            self.storage.put('change_reserved', [a.to_storage_string() for a in self.change_reserved])
            unreserved = self.change_unreserved + list(self.change_reserved_tmp)
            self.storage.put('change_unreserved', [a.to_storage_string() for a in unreserved])

    def clear_history(self):
        with self.lock:
            self.txi = {}
            self.txo = {}
            self.ct_txi = {}
            self.ct_txo = {}
            self.tx_fees = {}
            self.pruned_txo = {}
            self.pruned_txo_values = set()
            self.slp.clear()
            self.save_transactions()
            self._addr_bal_cache = {}
            self._history = {}
            self.tx_addr_hist = defaultdict(set)
            self.cashacct.on_clear_history()

    @profiler
    def build_reverse_history(self):
        self.tx_addr_hist = defaultdict(set)
        for addr, hist in self._history.items():
            for tx_hash, h in hist:
                self.tx_addr_hist[tx_hash].add(addr)

    @profiler
    def check_history(self):
        save = False
        my_addrs = [addr for addr in self._history if self.is_mine(addr)]

        for addr in set(self._history) - set(my_addrs):
            self._history.pop(addr)
            save = True

        for addr in my_addrs:
            hist = self._history[addr]

            for tx_hash, tx_height in hist:
                if tx_hash in self.pruned_txo_values or self.txi.get(tx_hash) or self.txo.get(tx_hash):
                    continue
                tx = self.transactions.get(tx_hash)
                if tx is not None:
                    self.add_transaction(tx_hash, tx)
                    save = True
        if save:
            self.save_transactions()
            self.cashacct.save()

    def basename(self):
        return os.path.basename(self.storage.path) if self.storage.path else f"memory:{id(self.storage)}"

    def save_addresses(self):
        addr_dict = {
            'receiving': [addr.to_storage_string()
                          for addr in self.receiving_addresses],
            'change': [addr.to_storage_string()
                       for addr in self.change_addresses],
        }
        self.storage.put('addresses', addr_dict)

    def load_addresses(self):
        d = self.storage.get('addresses', {})
        if not isinstance(d, dict):
            d = {}
        self.receiving_addresses = Address.from_strings(d.get('receiving', []))
        self.change_addresses = Address.from_strings(d.get('change', []))

    def synchronize(self):
        pass

    def is_deterministic(self):
        return self.keystore.is_deterministic()

    def set_up_to_date(self, up_to_date):
        with self.lock:
            self.up_to_date = up_to_date
            if up_to_date:
                self.save_addresses()
                self.save_transactions()
                # if the verifier is also up to date, persist that too;
                # otherwise it will persist its results when it finishes
                if self.verifier and self.verifier.is_up_to_date():
                    self.save_verified_tx()
                self.storage.write()

    def is_up_to_date(self):
        with self.lock: return self.up_to_date

    def is_fully_settled_down(self):
        ''' Returns True iff the wallet is up to date and its synchronizer
        and verifier aren't busy doing work, and its pruned_txo_values list
        is currently empty.  This is used as a final check by the Qt GUI
        to decide if it should do a final refresh of all tabs in some cases.'''
        with self.lock:
            ret = self.up_to_date
            if ret and self.verifier:
                ret = self.verifier.is_up_to_date()
            if ret and self.synchronizer:
                ret = self.synchronizer.is_up_to_date()
            ret = ret and not self.pruned_txo_values
            return bool(ret)

    def set_label(self, name, text=None, save=True):
        with self.lock:
            if isinstance(name, Address):
                name = name.to_storage_string()
            changed = False
            old_text = self.labels.get(name)
            if text:
                text = text.replace("\n", " ")
                if old_text != text:
                    self.labels[name] = text
                    changed = True
            else:
                if old_text:
                    self.labels.pop(name)
                    changed = True

            if changed:
                run_hook('set_label', self, name, text)
                if save:
                    self.save_labels()

            return changed

    def save_labels(self):
        self.storage.put('labels', self.labels)

    def invalidate_address_set_cache(self):
        """This should be called from functions that add/remove addresses
        from the wallet to ensure the address set caches are empty, in
        particular from ImportedWallets which may add/delete addresses
        thus the length check in is_mine() may not be accurate.
        Deterministic wallets can neglect to call this function since their
        address sets only grow and never shrink and thus the length check
        of is_mine below is sufficient."""
        self._recv_address_set_cached, self._change_address_set_cached = frozenset(), frozenset()

    def is_mine(self, address):
        """Note this method assumes that the entire address set is
        composed of self.get_change_addresses() + self.get_receiving_addresses().
        In subclasses, if that is not the case -- REIMPLEMENT this method!"""
        assert not isinstance(address, str)
        # assumption here is get_receiving_addresses and get_change_addresses
        # are cheap constant-time operations returning a list reference.
        # If that is not the case -- reimplement this function.
        ra, ca = self.get_receiving_addresses(), self.get_change_addresses()
        # Detect if sets changed (addresses added/removed).
        # Note the functions that add/remove addresses should invalidate this
        # cache using invalidate_address_set_cache() above.
        if len(ra) != len(self._recv_address_set_cached):
            # re-create cache if lengths don't match
            self._recv_address_set_cached = frozenset(ra)
        if len(ca) != len(self._change_address_set_cached):
            # re-create cache if lengths don't match
            self._change_address_set_cached = frozenset(ca)
        # Do a 2 x O(logN) lookup using sets rather than 2 x O(N) lookups
        # if we were to use the address lists (this was the previous way).
        # For small wallets it doesn't matter -- but for wallets with 5k or 10k
        # addresses, it starts to add up siince is_mine() is called frequently
        # especially while downloading address history.
        return (address in self._recv_address_set_cached
                or address in self._change_address_set_cached)

    def is_change(self, address):
        assert not isinstance(address, str)
        ca = self.get_change_addresses()
        if len(ca) != len(self._change_address_set_cached):
            # re-create cache if lengths don't match
            self._change_address_set_cached = frozenset(ca)
        return address in self._change_address_set_cached

    def get_address_index(self, address):
        try:
            return False, self.receiving_addresses.index(address)
        except ValueError:
            pass
        try:
            return True, self.change_addresses.index(address)
        except ValueError:
            pass
        assert not isinstance(address, str)
        raise Exception("Address {} not found".format(address))

    def export_private_key(self, address, password):
        """ extended WIF format """
        if self.is_watching_only():
            return []
        index = self.get_address_index(address)
        pk, compressed = self.keystore.get_private_key(index, password)
        return bitcoin.serialize_privkey(pk, compressed, self.txin_type)

    def get_public_keys(self, address):
        sequence = self.get_address_index(address)
        return self.get_pubkeys(*sequence)

    def add_unverified_tx(self, tx_hash, tx_height):
        with self.lock:
            if tx_height <= 0 and tx_hash in self.verified_tx:
                self.verified_tx.pop(tx_hash)
                if self.verifier:
                    self.verifier.merkle_roots.pop(tx_hash, None)

            # tx will be verified only if height > 0
            if tx_hash not in self.verified_tx:
                self.unverified_tx[tx_hash] = tx_height
                self.cashacct.add_unverified_tx_hook(tx_hash, tx_height)

    def add_verified_tx(self, tx_hash, info, header):
        # Remove from the unverified map and add to the verified map and
        with self.lock:
            self.unverified_tx.pop(tx_hash, None)
            self.verified_tx[tx_hash] = info  # (tx_height, timestamp, pos)
            height, conf, timestamp = self.get_tx_height(tx_hash)
            self.cashacct.add_verified_tx_hook(tx_hash, info, header)
        self.network.trigger_callback('verified2', self, tx_hash, height, conf, timestamp)
        self._update_request_statuses_touched_by_tx(tx_hash)

    def verification_failed(self, tx_hash, reason):
        ''' TODO: Notify gui of this if it keeps happening, try a different
        server, rate-limited retries, etc '''
        self.cashacct.verification_failed_hook(tx_hash, reason)

    def get_unverified_txs(self):
        '''Returns a map from tx hash to transaction height'''
        with self.lock:
            return self.unverified_tx.copy()

    def get_unverified_tx_pending_count(self):
        ''' Returns the number of unverified tx's that are confirmed and are
        still in process and should be verified soon.'''
        with self.lock:
            return len([1 for height in self.unverified_tx.values() if height > 0])

    def undo_verifications(self, blockchain, height):
        '''Used by the verifier when a reorg has happened'''
        txs = set()
        with self.lock:
            for tx_hash, item in list(self.verified_tx.items()):
                tx_height, timestamp, pos = item
                if tx_height >= height:
                    header = blockchain.read_header(tx_height)
                    # fixme: use block hash, not timestamp
                    if not header or header.get('timestamp') != timestamp:
                        self.verified_tx.pop(tx_hash, None)
                        txs.add(tx_hash)
            if txs: self.cashacct.undo_verifications_hook(txs)
        if txs:
            self._addr_bal_cache = {}  # this is probably not necessary -- as the receive_history_callback will invalidate bad cache items -- but just to be paranoid we clear the whole balance cache on reorg anyway as a safety measure
        for tx_hash in txs:
            self._update_request_statuses_touched_by_tx(tx_hash)
        return txs

    def get_local_height(self):
        """ return last known height if we are offline """
        return self.network.get_local_height() if self.network else self.storage.get('stored_height', 0)

    def get_tx_height(self, tx_hash):
        """ return the height and timestamp of a verified transaction. """
        with self.lock:
            if tx_hash in self.verified_tx:
                height, timestamp, pos = self.verified_tx[tx_hash]
                conf = max(self.get_local_height() - height + 1, 0)
                return height, conf, timestamp
            elif tx_hash in self.unverified_tx:
                height = self.unverified_tx[tx_hash]
                return height, 0, 0
            else:
                return 0, 0, 0

    def get_tx_block_hash(self, tx_hash):
        ''' Only works for tx's in wallet, for which we know the height. '''
        height, ign, ign2 = self.get_tx_height(tx_hash)
        return self.get_block_hash(height)

    def get_block_hash(self, height):
        '''Convenience method equivalent to Blockchain.get_height(), except our
        version returns None instead of NULL_HASH_HEX on 'not found' header. '''
        ret = None
        if self.network and height is not None and height >= 0 and height <= self.get_local_height():
            bchain = self.network.blockchain()
            if bchain:
                ret = bchain.get_hash(height)
                if ret == NULL_HASH_HEX:
                    # if hash was NULL (all zeroes), prefer to return None
                    ret = None
        return ret


    def get_txpos(self, tx_hash):
        "return position, even if the tx is unverified"
        with self.lock:
            if tx_hash in self.verified_tx:
                height, timestamp, pos = self.verified_tx[tx_hash]
                return height, pos
            elif tx_hash in self.unverified_tx:
                height = self.unverified_tx[tx_hash]
                return (height, 0) if height > 0 else ((1e9 - height), 0)
            else:
                return (1e9+1, 0)

    def is_found(self):
        return any(value for value in self._history.values())

    def get_num_tx(self, address):
        """ return number of transactions where address is involved """
        return len(self.get_address_history(address))

    def get_tx_delta(self, tx_hash, address):
        assert isinstance(address, Address)
        "effect of tx on address"
        # pruned
        if tx_hash in self.pruned_txo_values:
            return None
        delta = 0
        # substract the value of coins sent from address
        d = self.txi.get(tx_hash, {}).get(address, [])
        for n, v in d:
            delta -= v
        # add the value of the coins received at address
        d = self.txo.get(tx_hash, {}).get(address, [])
        for n, v, cb in d:
            delta += v
        return delta

    @staticmethod
    def _token_delta_dict_factory():
        return {"fungibles": 0, "nfts_in": [], "nfts_out": []}

    def get_tx_tokens_delta(self, tx_hash, address) -> Optional[Dict[str, Dict[str, Any]]]:
        """Returns the effect of tx on per-address token balance(s), if any

        returns dict: {"token_id_hex" : {"fungibles": nnn,
                                         "nfts_in": [(out_n, token_data)],
                                         "nfts_out":[(prevout_hash, prevout_n, token_data)]}}

        May return None if `tx_hash` is pruned, otherwise will always return (a possibly-empty) dict.
        """
        assert isinstance(address, Address)
        if tx_hash in self.pruned_txo_values:
            return None

        # Nota bene: self.ct_txi is a nested dict of dicts keyed by:
        # tx_hash -> dict key: address -> dict key: prevout_hash -> dict key: prevout_n -> token_data (token.OutputData)
        d = self.ct_txi.get(tx_hash, {}).get(address, {})
        ret = defaultdict(self._token_delta_dict_factory)
        # "substract" the fungibles and ntfs of tokens sent from address
        for prevout_hash, inp_dict in d.items():
            for prevout_n, token_data in inp_dict.items():
                if token_data:
                    id_hex = token_data.id_hex
                    ret[id_hex]["fungibles"] -= token_data.amount
                    if token_data.has_nft():
                        ret[id_hex]["nfts_out"].append((prevout_hash, prevout_n, token_data))
        # Nota bene: self.ct_txo is a nested dict of dicts keyed by:
        # tx_hash -> dict key: address -> dict key: address -> dict key: n -> token_data (token.OutputData)
        d = self.ct_txo.get(tx_hash, {}).get(address, {})
        # "add" the fungibles and ntfs received at address
        for output_n, token_data in d.items():
            if token_data:
                id_hex = token_data.id_hex
                ret[id_hex]["fungibles"] += token_data.amount
                if token_data.has_nft():
                    ret[id_hex]["nfts_in"].append((output_n, token_data))

        # demote to regular dict for safety, and return
        return dict(ret)

    WalletDelta = namedtuple("WalletDelta", "is_relevant, is_mine, v, fee")
    WalletDelta2 = namedtuple("WalletDelta2", WalletDelta._fields + ("spends_coins_mine",))

    def get_wallet_delta(self, tx) -> WalletDelta:
        return self._get_wallet_delta(tx, ver=1)

    def _get_wallet_delta(self, tx, *, ver=1) -> Union[WalletDelta, WalletDelta2]:
        """ Effect of tx on wallet """
        assert ver in (1, 2)
        is_relevant = False
        is_mine = False
        is_pruned = False
        is_partial = False
        v_in = v_out = v_out_mine = n_out = 0
        spends_coins_mine = list()

        for item in tx.inputs():
            addr = item['address']
            if self.is_mine(addr):
                is_mine = True
                is_relevant = True
                prevout_hash = item['prevout_hash']
                prevout_n = item['prevout_n']
                d = self.txo.get(prevout_hash, {}).get(addr, [])
                for n, v, cb in d:
                    if n == prevout_n:
                        value = v
                        if ver >= 2:
                            spends_coins_mine.append(f'{prevout_hash}:{prevout_n}')
                        break
                else:
                    value = None
                if value is None:
                    is_pruned = True
                else:
                    v_in += value
            else:
                is_partial = True
        if not is_mine:
            is_partial = False
        for (_type, addr, value), token_data in tx.outputs(tokens=True):
            v_out += value
            if self.is_mine(addr):
                v_out_mine += value
                is_relevant = True
            n_out += 1

        if is_pruned:
            # some inputs are mine:
            fee = None
            if is_mine:
                v = v_out_mine - v_out
            else:
                # no input is mine
                v = v_out_mine
        else:
            v = v_out_mine - v_in
            if is_partial:
                # some inputs are mine, but not all
                fee = None
            else:
                # all inputs are mine
                fee = v_in - v_out
        if not is_mine:
            fee = None
        if ver == 1:
            return self.WalletDelta(is_relevant, is_mine, v, fee)
        return self.WalletDelta2(is_relevant, is_mine, v, fee, spends_coins_mine)

    TxInfo = namedtuple("TxInfo", "tx_hash, status, label, can_broadcast, amount, fee, height, conf, timestamp, exp_n")

    class StatusEnum(Enum):
        Unconfirmed = auto()
        NotVerified = auto()
        Confirmed = auto()
        Signed = auto()
        Unsigned = auto()
        PartiallySigned = auto()

    TxInfo2 = namedtuple("TxInfo2", TxInfo._fields + ("status_enum",))
    TxInfo3 = namedtuple("TxInfo3", TxInfo._fields + ("status_enum", "token_data",))

    def get_tx_info(self, tx) -> TxInfo:
        """ Return information for a transaction """
        return self._get_tx_info(tx, self.get_wallet_delta(tx), ver=1)

    def get_tx_extended_info(self, tx, ver=2) -> Tuple[Union[WalletDelta, WalletDelta2],
                                                       Union[TxInfo, TxInfo2, TxInfo3]]:
        """ Get extended information for a transaction, combined into 1 call (for performance) """
        delta_x = self._get_wallet_delta(tx, ver=min(ver, 2))
        info_x = self._get_tx_info(tx, delta_x, ver=ver)
        return delta_x, info_x

    def _get_tx_info(self, tx, delta, *, ver=1) -> Union[TxInfo, TxInfo2, TxInfo3]:
        """ get_tx_info implementation """
        assert ver in (1, 2, 3)
        if isinstance(delta, self.WalletDelta):
            is_relevant, is_mine, v, fee = delta
        else:
            is_relevant, is_mine, v, fee, __ = delta
        exp_n = None
        can_broadcast = False
        label = ''
        height = conf = timestamp = None
        status_enum = None
        tx_hash = tx.txid()
        input_token_data = []
        if tx.is_complete():
            if tx_hash in self.transactions:
                label = self.get_label(tx_hash)
                height, conf, timestamp = self.get_tx_height(tx_hash)
                if height > 0:
                    if conf:
                        status = ngettext("{conf} confirmation", "{conf} confirmations", conf).format(conf=conf)
                        status_enum = self.StatusEnum.Confirmed
                    else:
                        status = _('Not verified')
                        status_enum = self.StatusEnum.NotVerified
                else:
                    status = _('Unconfirmed')
                    status_enum = self.StatusEnum.Unconfirmed
                    if fee is None:
                        fee = self.tx_fees.get(tx_hash)
                    if fee and self.network and self.network.config.has_fee_estimates():
                        # NB: this branch will not be taken as has_fee_estimates()
                        # will always return false since we disabled querying
                        # the fee histogram as it's useless for BCH anyway.
                        size = tx.estimated_size()
                        fee_per_kb = fee * 1000 / size
                        exp_n = self.network.config.reverse_dynfee(fee_per_kb)
            else:
                status = _("Signed")
                status_enum = self.StatusEnum.Signed
                can_broadcast = self.network is not None
        else:
            s, r = tx.signature_count()
            if s == 0:
                status = _("Unsigned")
                status_enum = self.StatusEnum.Unsigned
            else:
                status =_('Partially signed') + ' (%d/%d)'%(s,r)
                status_enum = self.StatusEnum.PartiallySigned

        if ver >= 3:
            # For version 3 or above, we return a list of token_data as well for all the inputs to a txn
            for i, txin in enumerate(tx.inputs()):
                if 'token_data' not in txin:
                    address = txin.get('address')
                    if address:
                        prevout_hash = txin.get('prevout_hash')
                        prevout_n = txin.get('prevout_n')
                        token_data = self.ct_txi.get(tx_hash, {}).get(address, {}).get(prevout_hash, {}).get(prevout_n)
                    else:
                        token_data = None
                else:
                    token_data = txin['token_data']
                input_token_data.append(token_data)

        if is_relevant:
            if is_mine:
                if fee is not None:
                    amount = v + fee
                else:
                    amount = v
            else:
                amount = v
        else:
            amount = None

        if ver == 1:
            return self.TxInfo(tx_hash, status, label, can_broadcast, amount, fee, height, conf, timestamp, exp_n)
        assert status_enum is not None
        if ver == 2:
            return self.TxInfo2(tx_hash, status, label, can_broadcast, amount, fee, height, conf, timestamp, exp_n,
                                status_enum)
        return self.TxInfo3(tx_hash, status, label, can_broadcast, amount, fee, height, conf, timestamp, exp_n,
                            status_enum, input_token_data)

    def get_addr_io(self, address):
        h = self.get_address_history(address)
        received = {}
        sent = {}
        for tx_hash, height in h:
            l = self.txo.get(tx_hash, {}).get(address, [])
            ct_txo_tx_hash_addr_dict = self.ct_txo.get(tx_hash, {}).get(address, {})
            for n, v, is_cb in l:
                token_data = ct_txo_tx_hash_addr_dict.get(n)
                received[tx_hash + ':%d'%n] = (height, v, is_cb, token_data)
        for tx_hash, height in h:
            l = self.txi.get(tx_hash, {}).get(address, [])
            for txi, v in l:
                sent[txi] = height
        return received, sent

    def get_addr_utxo(self, address):
        coins, spent = self.get_addr_io(address)
        for txi in spent:
            coins.pop(txi)
            # cleanup/detect if the 'frozen coin' was spent and remove it from the frozen coin set
            self.frozen_coins.discard(txi)
            self.frozen_coins_tmp.discard(txi)
        out = {}
        for txo, v in coins.items():
            tx_height, value, is_cb, token_data = v
            prevout_hash, prevout_n = txo.split(':', 1)
            prevout_n = int(prevout_n)
            x = {
                'address': address,
                'value': value,
                'prevout_n': prevout_n,
                'prevout_hash': prevout_hash,
                'height': tx_height,
                'coinbase': is_cb,
                'is_frozen_coin': txo in self.frozen_coins or txo in self.frozen_coins_tmp,
                'slp_token': self.slp.token_info_for_txo(txo),  # (token_id_hex, qty) tuple or None
                'token_data': token_data,  # token.OutputData instance or None
            }
            out[txo] = x
        return out

    # return the total amount ever received by an address
    def get_addr_received(self, address):
        received, sent = self.get_addr_io(address)
        return sum([v for height, v, is_cb, token_data in received.values()])

    def get_addr_balance(self, address, exclude_frozen_coins=False, *, tokens=False):
        """ Returns the balance of a bitcoin address as a tuple of:
            (confirmed_matured, unconfirmed, unmatured) if tokens == False or
            (confirmed_matured, unconfirmed, unmatured, cashtoken_utxo_balance) if tokens == True
            Note that 'exclude_frozen_coins = True' only checks for coin-level
            freezing, not address-level. """
        assert isinstance(address, Address)
        mempoolHeight = self.get_local_height() + 1
        return_arity = 3 + int(tokens)
        if not exclude_frozen_coins:
            # Note: We do not use the cache when excluding frozen coins as frozen status is
            # a dynamic quantity that can change at any time in the UI
            cached = self._addr_bal_cache.get(address)
            if cached is not None:
                # Account for the possible variation in tokens arg, leading to cached 3-tuple vs 4-tuple...
                # Ensure the cached value has the arity we need for this invocation
                if len(cached) >= return_arity:
                    return cached[:return_arity]
        received, sent = self.get_addr_io(address)
        c = u = x = 0
        tok_locked = 0
        had_cb = False
        for txo, (tx_height, v, is_cb, token_data) in received.items():
            if exclude_frozen_coins and (txo in self.frozen_coins or txo in self.frozen_coins_tmp):
                continue
            had_cb = had_cb or is_cb  # remember if this address has ever seen a coinbase txo
            if is_cb and tx_height + COINBASE_MATURITY > mempoolHeight:
                x += v
            elif tx_height > 0:
                c += v
            else:
                u += v
            if txo in sent:
                if sent[txo] > 0:
                    c -= v
                else:
                    u -= v
            elif token_data:
                # This received output has a token on it and has not been spent.
                # We can say its BCH amount is "locked" onto a CashToken
                tok_locked += v

        result = (c, u, x, tok_locked)[:return_arity]
        if not exclude_frozen_coins and not had_cb:
            # Cache the results.
            # Cache needs to be invalidated if a transaction is added to/
            # removed from addr history.  (See self._addr_bal_cache calls
            # related to this littered throughout this file).
            #
            # Note that as a performance tweak we don't ever cache balances for
            # addresses involving coinbase coins. The rationale being as
            # follows: Caching of balances of the coinbase addresses involves
            # a dynamic quantity: maturity of the coin (which considers the
            # ever-changing block height).
            #
            # There wasn't a good place in this codebase to signal the maturity
            # happening (and thus invalidate the cache entry for the exact
            # address that holds the coinbase coin in question when a new
            # block is found that matures a coinbase coin).
            #
            # In light of that fact, a possible approach would be to invalidate
            # this entire cache when a new block arrives (this is what Electrum
            # does). However, for Electron Cash with its focus on many addresses
            # for privacy features such as integrated CashFusion --
            # being notified in the wallet and invalidating the *entire* cache
            # whenever a new block arrives (which is the exact time you do
            # the most GUI refreshing and calling of this function) seems a bit
            # heavy-handed, just for sake of the (relatively rare, for the
            # average user) coinbase-carrying addresses.
            #
            # It's not a huge performance hit for the coinbase addresses to
            # simply not cache their results, and have this function recompute
            # their balance on each call, when you consider that as a
            # consequence of this policy, all the other addresses that are
            # non-coinbase can benefit from a cache that stays valid for longer
            # than 1 block (so long as their balances haven't changed).
            self._addr_bal_cache[address] = result  # Note that the arity of `result` may be 3 or 4 here
        return result

    def get_spendable_coins(self, domain, config, isInvoice=False):
        confirmed_only = config.get('confirmed_only', DEFAULT_CONFIRMED_ONLY)
        if isInvoice:
            confirmed_only = True
        return self.get_utxos(domain, exclude_frozen=True, mature=True, confirmed_only=confirmed_only, exclude_slp=True,
                              # For now, we will prohibit spending cash tokens implicitly (must be explicit)
                              exclude_tokens=True)

    def get_utxos(self, domain=None, exclude_frozen=False, mature=False, confirmed_only=False,
                  *, addr_set_out=None, exclude_slp=True, exclude_tokens=True, tokens_only=False):
        """Note that exclude_frozen = True checks for BOTH address-level and
        coin-level frozen status.

        exclude_slp skips coins that also have SLP tokens on them.  This defaults
        to True in EC 4.0.10+ in order to prevent inadvertently burning tokens.

        Optional kw-only arg `addr_set_out` specifies a set in which to add all
        addresses encountered in the utxos returned. """
        if tokens_only:
            exclude_tokens = False
        with self.lock:
            mempoolHeight = self.get_local_height() + 1
            coins = []
            if domain is None:
                domain = self.get_addresses()
            if exclude_frozen:
                domain = set(domain) - self.frozen_addresses
            for addr in domain:
                utxos = self.get_addr_utxo(addr)
                len_before = len(coins)
                for x in utxos.values():
                    if exclude_tokens and x['token_data']:
                        continue
                    if tokens_only and not x['token_data']:
                        continue
                    if exclude_slp and x['slp_token']:
                        continue
                    if exclude_frozen and x['is_frozen_coin']:
                        continue
                    if confirmed_only and x['height'] <= 0:
                        continue
                    # A note about maturity: Previous versions of Electrum
                    # and Electron Cash were off by one. Maturity is
                    # calculated based off mempool height (chain tip height + 1).
                    # See bitcoind consensus/tx_verify.cpp Consensus::CheckTxInputs
                    # and also txmempool.cpp  CTxMemPool::removeForReorg.
                    if mature and x['coinbase'] and mempoolHeight - x['height'] < COINBASE_MATURITY:
                        continue
                    coins.append(x)
                if addr_set_out is not None and len(coins) > len_before:
                    # add this address to the address set if it has results
                    addr_set_out.add(addr)
            return coins

    def dummy_address(self):
        return self.get_receiving_addresses()[0]

    def get_addresses(self):
        return self.get_receiving_addresses() + self.get_change_addresses()

    def get_change_addresses(self):
        """ Reimplemented in subclasses for wallets that have a change address set/derivation path. """
        return []

    def get_receiving_addresses(self):
        """ Must be reimplemented in subclasses """
        raise RuntimeError("'get_receiving_addresses' is not implemented in this class: " + str(type(self)))

    def get_preferred_change_addresses(self):
        """ In most subclasses this is just self.get_change_addresses(), but in the MultiXPubWallet, it is
        the addresses from one of the XPubs we have the private keys for (if any), otherwise it's just
        the regular change addresses."""
        return self.get_change_addresses()

    def get_preferred_receiving_addresses(self):
        """Reimplemented in MultiXPubWallet"""
        return self.get_receiving_addresses()

    def get_preferred_addresses(self):
        return self.get_preferred_receiving_addresses() + self.get_preferred_change_addresses()

    def get_frozen_balance(self):
        if not self.frozen_coins and not self.frozen_coins_tmp:
            # performance short-cut -- get the balance of the frozen address set only IFF we don't have any frozen coins
            return self.get_balance(self.frozen_addresses)
        # otherwise, do this more costly calculation...
        cc_no_f, uu_no_f, xx_no_f = self.get_balance(None, exclude_frozen_coins = True, exclude_frozen_addresses = True)
        cc_all, uu_all, xx_all = self.get_balance(None, exclude_frozen_coins = False, exclude_frozen_addresses = False)
        return (cc_all-cc_no_f), (uu_all-uu_no_f), (xx_all-xx_no_f)

    def get_balance(self, domain=None, exclude_frozen_coins=False, exclude_frozen_addresses=False, *,
                    tokens=False):
        """If tokens=True, returns a 4-tuple: (confirmed, unconfirmed, unmatured, tokens), otherwise returns a
           3-tuple of just (confirmed, unconfirmed, unmatured) """
        if domain is None:
            domain = self.get_addresses()
        if exclude_frozen_addresses:
            domain = set(domain) - self.frozen_addresses
        cc = uu = xx = toks = 0
        for addr in domain:
            tup = self.get_addr_balance(addr, exclude_frozen_coins, tokens=tokens)
            c, u, x = tup[:3]
            tok = tup[3] if tokens else 0
            cc += c
            uu += u
            xx += x
            toks += tok
        return (cc, uu, xx, toks)[:3 + int(tokens)]

    def get_address_history(self, address):
        assert isinstance(address, Address)
        return self._history.get(address, [])

    def _clean_pruned_txo_thread(self):
        """ Runs in the thread self.pruned_txo_cleaner_thread which is only
        active if self.network. Cleans the self.pruned_txo dict and the
        self.pruned_txo_values set of spends that are not relevant to the
        wallet. The processing below is needed because as of 9/16/2019, Electron
        Cash temporarily puts all spends that pass through add_transaction and
        have an unparseable address (txi['address'] is None) into the dict
        self.pruned_txo. This is necessary for handling tx's with esoteric p2sh
        scriptSigs and detecting balance changes properly for txins
        containing such scriptSigs. See #895. """
        me = threading.current_thread()
        fname = "clean_pruned_txo"
        def deser(ser):
            prevout_hash, prevout_n = ser.split(':')
            prevout_n = int(prevout_n)
            return prevout_hash, prevout_n
        def mkser(prevout_hash, prevout_n):
            return f'{prevout_hash}:{prevout_n}'
        def rm(ser, pruned_too=True, *, tup = None):
            h, n = tup or deser(ser)  # tup arg is for performance when caller already knows the info (avoid a redundant .split on ':')
            s = txid_n[h]
            s.discard(n)
            if not s:
                txid_n.pop(h, None)
            if pruned_too:
                with self.lock:
                    tx_hash = self.pruned_txo.pop(ser, None)
                    self.pruned_txo_values.discard(tx_hash)
        def add(ser):
            prevout_hash, prevout_n = deser(ser)
            txid_n[prevout_hash].add(prevout_n)
        def keep_running():
            return bool(self.network and self.pruned_txo_cleaner_thread is me)
        def can_do_work():
            return bool(txid_n and self.is_up_to_date())
        debug = False  # set this to true here to get more verbose output
        q = me.q
        me.txid_n = txid_n = defaultdict(set)  # dict of prevout_hash -> set of prevout_n (int)
        last = time.time()
        try:
            self.print_error(f"{fname}: thread started")
            with self.lock:
                # Setup -- grab whatever was already in pruned_txo at thread
                # start
                for ser in self.pruned_txo:
                    h, n = deser(ser)
                    txid_n[h].add(n)
            while keep_running():
                try:
                    ser = q.get(timeout=5.0 if can_do_work() else 20.0)
                    if ser is None:
                        # quit thread
                        return
                    if ser.startswith('r_'):
                        # remove requested
                        rm(ser[2:], False)
                    else:
                        # ser was added
                        add(ser)
                    del ser
                except queue.Empty:
                    pass
                if not can_do_work():
                    continue
                t0 = time.time()
                if t0 - last < 1.0:  # run no more often than once per second
                    continue
                last = t0
                defunct_ct = 0
                for prevout_hash, s in txid_n.copy().items():
                    for prevout_n in s.copy():
                        ser = mkser(prevout_hash, prevout_n)
                        with self.lock:
                            defunct = ser not in self.pruned_txo
                        if defunct:
                            #self.print_error(f"{fname}: skipping already-cleaned", ser)
                            rm(ser, False, tup=(prevout_hash, prevout_n))
                            defunct_ct += 1
                            continue
                if defunct_ct and debug:
                    self.print_error(f"{fname}: DEBUG", defunct_ct, "defunct txos removed in", time.time()-t0, "secs")
                ct = 0
                for prevout_hash, s in txid_n.copy().items():
                    try:
                        with self.lock:
                            tx = self.transactions.get(prevout_hash)
                        if tx is None:
                            tx = Transaction.tx_cache_get(prevout_hash)
                        if isinstance(tx, Transaction):
                            tx = Transaction(tx.raw)  # take a copy
                        else:
                            if debug: self.print_error(f"{fname}: DEBUG retrieving txid", prevout_hash, "...")
                            t1 = time.time()
                            tx = Transaction(self.network.synchronous_get(('blockchain.transaction.get', [prevout_hash])))
                            if debug: self.print_error(f"{fname}: DEBUG network retrieve took", time.time()-t1, "secs")
                            # Paranoia; intended side effect of the below assert
                            # is to also deserialize the tx (by calling the slow
                            # .txid()) which ensures the tx from the server
                            # is not junk.
                            assert prevout_hash == tx.txid(), "txid mismatch"
                            Transaction.tx_cache_put(tx, prevout_hash)  # will cache a copy
                    except Exception as e:
                        self.print_error(f"{fname}: Error retrieving txid", prevout_hash, ":", repr(e))
                        if not keep_running():  # in case we got a network timeout *and* the wallet was closed
                            return
                        continue
                    if not keep_running():
                        return
                    for prevout_n in s.copy():
                        ser = mkser(prevout_hash, prevout_n)
                        try:
                            txo = tx.outputs()[prevout_n]
                        except IndexError:
                            self.print_error(f"{fname}: ERROR -- could not find output", ser)
                            rm(ser, True, tup=(prevout_hash, prevout_n))
                            continue
                        _typ, addr, v = txo
                        rm_pruned_too = False
                        with self.lock:
                            mine = self.is_mine(addr)
                            if not mine and ser in self.pruned_txo:
                                ct += 1
                                rm_pruned_too = True
                        rm(ser, rm_pruned_too, tup=(prevout_hash, prevout_n))
                        if rm_pruned_too and debug:
                            self.print_error(f"{fname}: DEBUG removed", ser)
                if ct:
                    with self.lock:
                        # Save changes to storage -- this is cheap and doesn't
                        # actually write to file yet, just flags storage as
                        # 'dirty' for when wallet.storage.write() is called
                        # later.
                        self.storage.put('pruned_txo', self.pruned_txo)
                    self.print_error(f"{fname}: removed", ct,
                                     "(non-relevant) pruned_txo's in",
                                     f'{time.time()-t0:3.2f}', "seconds")
        except:
            import traceback
            self.print_error(f"{fname}:", traceback.format_exc())
            raise
        finally:
            self.print_error(f"{fname}: thread exiting")

    def add_transaction(self, tx_hash, tx):
        if not tx.inputs():
            # bad tx came in off the wire -- all 0's or something, see #987
            self.print_error("add_transaction: WARNING a tx came in from the network with 0 inputs!"
                             " Bad server? Ignoring tx:", tx_hash)
            return
        is_coinbase = tx.inputs()[0]['type'] == 'coinbase'
        with self.lock:
            # HELPER FUNCTIONS
            def add_to_self_txi(tx_hash, addr, ser, v, token_data):
                """ addr must be 'is_mine' """
                d = self.txi.get(tx_hash)
                if d is None:
                    self.txi[tx_hash] = d = {}
                l = d.get(addr)
                if l is None:
                    d[addr] = l = []
                l.append((ser, v))
                # Next, update self.ct_txi
                if token_data is not None:
                    d = self.ct_txi.get(tx_hash)
                    if d is None:
                        self.ct_txi[tx_hash] = d = {}
                    dd = d.get(addr)
                    if dd is None:
                        d[addr] = dd = {}
                    prevout_hash, prevout_n = ser.split(':', 1)
                    prevout_n = int(prevout_n)
                    ddd = dd.get(prevout_hash)
                    if ddd is None:
                        dd[prevout_hash] = ddd = {}
                    ddd[prevout_n] = token_data
                    self.print_error(f"Adding CashTokens txi: {tx_hash} -> {addr} -> {prevout_hash} -> {prevout_n} -> {token_data!r}")

            def find_in_self_txo(prevout_hash: str, prevout_n: int) -> tuple:
                """Returns a tuple of the (Address, value, tokenData) for a given
                prevout_hash:prevout_n, or (None, None, None) if not found. If valid
                return, the Address object is found by scanning self.txo. The
                lookup below is relatively fast in practice even on pathological
                wallets."""
                dd = self.txo.get(prevout_hash, {})
                for addr2, item in dd.items():
                    for n, v, is_cb in item:
                        if n == prevout_n:
                            token_data = self.ct_txo.get(prevout_hash, {}).get(addr2, {}).get(prevout_n)
                            return addr2, v, token_data
                return None, None, None
            def txin_get_info(txi):
                prevout_hash = txi['prevout_hash']
                prevout_n = txi['prevout_n']
                ser = f'{prevout_hash}:{prevout_n}'
                return prevout_hash, prevout_n, ser
            def put_pruned_txo(ser, tx_hash):
                self.pruned_txo[ser] = tx_hash
                self.pruned_txo_values.add(tx_hash)
                t = self.pruned_txo_cleaner_thread
                if t and t.q: t.q.put(ser)
            def pop_pruned_txo(ser):
                next_tx = self.pruned_txo.pop(ser, None)
                if next_tx:
                    self.pruned_txo_values.discard(next_tx)
                    t = self.pruned_txo_cleaner_thread
                    if t and t.q: t.q.put('r_' + ser)  # notify of removal
                return next_tx
            # /HELPER FUNCTIONS

            # add inputs
            self.txi[tx_hash] = d = {}
            self.ct_txi[tx_hash] = ct_d = {}
            for txi in tx.inputs():
                if txi['type'] == 'coinbase':
                    continue
                addr = txi.get('address')
                # find value from prev output
                if self.is_mine(addr):
                    prevout_hash, prevout_n, ser = txin_get_info(txi)
                    dd = self.txo.get(prevout_hash, {})
                    for n, v, is_cb in dd.get(addr, []):
                        if n == prevout_n:
                            token_data = self.ct_txo.get(prevout_hash, {}).get(addr, {}).get(prevout_n, None)
                            add_to_self_txi(tx_hash, addr, ser, v, token_data)
                            break
                    else:
                        # Coin's spend tx came in before its receive tx: flag
                        # the spend for when the receive tx will arrive into
                        # this function later.
                        put_pruned_txo(ser, tx_hash)
                    self._addr_bal_cache.pop(addr, None)  # invalidate cache entry
                    del dd, prevout_hash, prevout_n, ser
                elif addr is None:
                    # Unknown/unparsed address.. may be a strange p2sh scriptSig
                    # Try and find it in txout's if it's one of ours.
                    # See issue #895.
                    prevout_hash, prevout_n, ser = txin_get_info(txi)
                    # Find address in self.txo for this prevout_hash:prevout_n
                    addr2, v, token_data = find_in_self_txo(prevout_hash, prevout_n)
                    if addr2 is not None and self.is_mine(addr2):
                        add_to_self_txi(tx_hash, addr2, ser, v, token_data)
                        self._addr_bal_cache.pop(addr2, None)  # invalidate cache entry
                    else:
                        # Not found in self.txo. It may still be one of ours
                        # however since tx's can come in out of order due to
                        # CTOR, etc, and self.txo may not have it yet. So we
                        # flag the spend now, and when the out-of-order prevout
                        # tx comes in later for this input (if it's indeed one
                        # of ours), the real address for this input will get
                        # picked up then in the "add outputs" section below in
                        # this function. At that point, self.txi will be
                        # properly updated to indicate the coin in question was
                        # spent via an add_to_self_txi call.
                        #
                        # If it's *not* one of ours, however, the below will
                        # grow pruned_txo with an irrelevant entry. However, the
                        # irrelevant entry will eventually be reaped and removed
                        # by the self.pruned_txo_cleaner_thread which runs
                        # periodically in the background.
                        put_pruned_txo(ser, tx_hash)
                    del addr2, v, prevout_hash, prevout_n, ser
            # don't keep empty entries in self.txi
            if not d:
                self.txi.pop(tx_hash, None)
            if not ct_d:
                self.ct_txi.pop(tx_hash, None)

            # add outputs
            self.txo[tx_hash] = d = {}
            self.ct_txo[tx_hash] = ct_d = {}
            op_return_ct = 0
            deferred_cashacct_add = None
            for n, (txo, token_data) in enumerate(tx.outputs(tokens=True)):
                ser = tx_hash + ':%d'%n
                _type, addr, v = txo
                mine = False
                if isinstance(addr, ScriptOutput):
                    if addr.is_opreturn():
                        op_return_ct += 1
                    if isinstance(addr, cashacct.ScriptOutput):
                        # auto-detect CashAccount registrations we see,
                        # and notify cashacct subsystem of that fact. But we
                        # can only do it after making sure it's the *only*
                        # OP_RETURN in the tx.
                        deferred_cashacct_add = (
                            lambda _tx_hash=tx_hash, _tx=tx, _n=n, _addr=addr:
                                self.cashacct.add_transaction_hook(_tx_hash, _tx, _n, _addr)
                        )
                elif self.is_mine(addr):
                    # add coin to self.txo since it's mine.
                    mine = True
                    l = d.get(addr)
                    if l is None:
                        d[addr] = l = []
                    l.append((n, v, is_coinbase))
                    if token_data is not None:
                        ct_dd = ct_d.get(addr)
                        if ct_dd is None:
                            ct_d[addr] = ct_dd = {}
                        ct_dd[n] = token_data
                        self.print_error(f"Adding CashTokens txo: {tx_hash} -> {addr} -> {n} -> {token_data!r}")
                    self._addr_bal_cache.pop(addr, None)  # invalidate cache entry
                # give v to txi that spends me
                next_tx = pop_pruned_txo(ser)
                if next_tx is not None and mine:
                    add_to_self_txi(next_tx, addr, ser, v, token_data)
            # don't keep empty entries in self.txo
            if not d:
                self.txo.pop(tx_hash, None)
            if not ct_d:
                self.ct_txo.pop(tx_hash, None)


            # save
            self.transactions[tx_hash] = tx


            # Invoke the cashacct add hook (if defined) here at the end, with
            # the lock held. We accept the cashacct.ScriptOutput only iff
            # op_return_ct == 1 as per the Cash Accounts spec.
            # See: https://gitlab.com/cash-accounts/lookup-server/blob/master/routes/parser.js#L253
            if op_return_ct == 1 and deferred_cashacct_add:
                deferred_cashacct_add()

            # Unconditionally invoke the SLP handler. Note that it is a fast &
            # cheap no-op if this tx's outputs[0] is not an SLP script.
            self.slp.add_tx(tx_hash, tx)

    def remove_transaction(self, tx_hash):
        with self.lock:
            self.print_error("removing tx from history", tx_hash)
            # Note that we don't actually remove the tx_hash from
            # self.transactions, but instead rely on the unreferenced tx being
            # removed the next time the wallet is loaded in self.load_transactions()

            to_pop = []
            for ser, hh in self.pruned_txo.items():  # "prevout_hash:n" (ser) -> tx_hash
                if hh == tx_hash:
                    to_pop.append(ser)
                    self.pruned_txo_values.discard(hh)
            for ser in to_pop:
                self.pruned_txo.pop(ser, None)
            # add tx to pruned_txo, and undo the txi addition
            empties = []
            for next_tx, dd in self.txi.items():  # "next_tx_hash" -> Address > List[Tuple[ser, value]]
                to_pop = []
                for addr, l in dd.items():
                    del_idx = []
                    for idx, (ser, v) in enumerate(l):
                        prev_hash, prev_n = ser.split(':')
                        if prev_hash == tx_hash:
                            self._addr_bal_cache.pop(addr, None)  # invalidate cache entry
                            del_idx.append(idx)
                            self.pruned_txo[ser] = next_tx
                            self.pruned_txo_values.add(next_tx)
                    for ctr, idx in enumerate(del_idx):
                        del l[idx - ctr]
                    if len(l) == 0:
                        to_pop.append(addr)
                for addr in to_pop:
                    dd.pop(addr, None)
                if not dd:
                    empties.append(next_tx)
            for next_tx in empties:
                self.txi.pop(next_tx, None)
            # undo the self.ct_txi addition
            empties = []
            for next_tx, addrmap in self.ct_txi.items():  # next_tx_hash -> Address -> tx_hash -> n -> tokenOutput
                addrmap.pop(tx_hash, None)
                if not addrmap:
                    empties.append(next_tx)
            for next_tx in empties:
                self.ct_txi.pop(next_tx, None)

            # invalidate addr_bal_cache for outputs involving this tx
            d = self.txo.get(tx_hash, {})  # tx_hash -> Address -> List[Tuple[N, value, is_cb]]
            for addr in d:
                self._addr_bal_cache.pop(addr, None)  # invalidate cache entry

            try: self.txi.pop(tx_hash)
            except KeyError: self.print_error("tx was not in input history", tx_hash)
            try: self.txo.pop(tx_hash)
            except KeyError: self.print_error("tx was not in output history", tx_hash)
            self.ct_txi.pop(tx_hash, None)
            self.ct_txo.pop(tx_hash, None)

            # do this with the lock held
            self.cashacct.remove_transaction_hook(tx_hash)
            # inform slp subsystem as well
            self.slp.rm_tx(tx_hash)

    def receive_tx_callback(self, tx_hash, tx, tx_height):
        self.add_transaction(tx_hash, tx)
        self.add_unverified_tx(tx_hash, tx_height)
        self._update_request_statuses_touched_by_tx(tx_hash)

    def _update_request_statuses_touched_by_tx(self, tx_hash):
        tx = self.transactions.get(tx_hash)
        if tx is None:
            return
        if self.network and self.network.callback_listener_count("payment_received") > 0:
            for _, addr, _ in tx.outputs():
                status = self.get_request_status(addr)  # returns PR_UNKNOWN quickly if addr has no requests, otherwise returns tuple
                if status != PR_UNKNOWN:
                    status = status[0]  # unpack status from tuple
                    self.network.trigger_callback('payment_received', self, addr, status)

    @profiler
    def receive_history_callback(self, addr, hist, tx_fees):
        hist_set = frozenset((tx_hash, height) for tx_hash, height in hist)
        hist_dict: Optional[Dict[str, int]] = None
        newly_confirmed_ct = 0
        no_longer_has_unconf_ancestors_status_ct = 0
        removed_ct = 0
        with self.lock:
            # First, find txns that are in the old history but no longer in the current history
            old_hist = self.get_address_history(addr)
            old_hist_set = frozenset((tx_hash, height) for tx_hash, height in old_hist)
            for tx_hash, height in old_hist_set - hist_set:
                if hist_dict is None:
                    # Lazily init the hist_dict only if we need it
                    hist_dict = {tx_hash: height for tx_hash, height in hist}
                new_height = hist_dict.get(tx_hash)
                if new_height is not None and height <= 0 <= new_height:
                    if new_height > 0:
                        # This was a previously-known mempool txn that confirmed
                        newly_confirmed_ct += 1
                    else:
                        # This was a previously-known txn that had height -1 and now has height 0;
                        # in other words: ancestor unconfirmed status for this txn has been upgraded
                        # to "no unconf. ancestors".
                        no_longer_has_unconf_ancestors_status_ct += 1
                    # In either case, skip removal if confirmed or if unconf parent status changes
                    continue
                # If we get here the txn in question either disappeared we reorged in some way
                # such that height associated with the txn has changed. Best thing to do is remove
                # (and add it again if need be later).
                s = self.tx_addr_hist.get(tx_hash)  # tx_hash -> Set[Address]
                if s:
                    s.discard(addr)
                if not s:
                    # if no address references this tx anymore, kill it
                    # from txi/txo dicts.
                    if s is not None:
                        # We won't keep empty sets around.
                        self.tx_addr_hist.pop(tx_hash)
                    # note this call doesn't actually remove the tx from
                    # storage, it merely removes it from the self.txi
                    # and self.txo dicts
                    self.remove_transaction(tx_hash)
                    removed_ct += 1
            self._addr_bal_cache.pop(addr, None)  # unconditionally invalidate cache entry
            self._history[addr] = hist

            for tx_hash, tx_height in hist:
                # add it in case it was previously unconfirmed
                self.add_unverified_tx(tx_hash, tx_height)
                # add reference in tx_addr_hist
                self.tx_addr_hist[tx_hash].add(addr)
                # if addr is new, we have to recompute txi and txo
                tx = self.transactions.get(tx_hash)
                if tx is not None and self.txi.get(tx_hash, {}).get(addr) is None and self.txo.get(tx_hash, {}).get(addr) is None:
                    self.add_transaction(tx_hash, tx)

            # Store fees
            self.tx_fees.update(tx_fees)

        if newly_confirmed_ct + removed_ct > 0:
            self.print_error(f"tx history for {addr}, size: {len(hist)}, newly confirmed: {newly_confirmed_ct}, "
                             f"unconf parent status upgraded: {no_longer_has_unconf_ancestors_status_ct}, "
                             f"removed: {removed_ct}")

        if self.network:
            self.network.trigger_callback('on_history', self)

    def add_tx_to_history(self, txid):
        with self.lock:
            for addr in itertools.chain(list(self.txi.get(txid, {}).keys()), list(self.txo.get(txid, {}).keys())):
                cur_hist = self._history.get(addr, list())
                if not any(True for x in cur_hist if x[0] == txid):
                    cur_hist.append((txid, 0))
                    self._history[addr] = cur_hist

    # Returned by get_history iff include_tokens arg is False
    TxHistory = namedtuple("TxHistory", "tx_hash, height, conf, timestamp, amount, balance")
    # Returned by get_history iff include_tokens arg is True
    TxHistory2 = namedtuple("TxHistory", TxHistory._fields + ("tokens_deltas", "tokens_balances"))

    @profiler
    def get_history(self, domain=None, *, reverse=False, receives_before_sends=False,
                    include_tokens=False, include_tokens_balances=False) -> List[Union[TxHistory, TxHistory2]]:
        """Iff include_tokens=True, returns a list of TxHistory2, otherwise returns a list of TxHistory
           If include_tokens_balances is False, the TxHistory2.tokens_balances dict will be empty (perf. optimization)
        """
        # get domain
        if domain is None:
            domain = self.get_addresses()
        # 1. Get the history of each address in the domain, maintain the
        #    delta of a tx as the sum of its deltas on domain addresses
        tx_deltas = defaultdict(int)
        # key: tx_hash -> "category_id" -> merged token_delta dict for all addresses
        tx_tokens_deltas = defaultdict(lambda: defaultdict(self._token_delta_dict_factory))

        def accumulate_tokens_deltas(dest, tdelta):
            for token_id, per_tok_delta in tdelta.items():
                dest[token_id]["fungibles"] += per_tok_delta.get("fungibles", 0)
                dest[token_id]["nfts_in"] += per_tok_delta.get("nfts_in", [])
                dest[token_id]["nfts_out"] += per_tok_delta.get("nfts_out", [])

        for addr in domain:
            h = self.get_address_history(addr)
            for tx_hash, height in h:
                delta = self.get_tx_delta(tx_hash, addr)
                if delta is None or tx_deltas[tx_hash] is None:
                    tx_deltas[tx_hash] = None
                else:
                    tx_deltas[tx_hash] += delta
                if include_tokens:
                    tdelta = self.get_tx_tokens_delta(tx_hash, addr)
                    if tdelta:
                        accumulate_tokens_deltas(tx_tokens_deltas[tx_hash], tdelta)

        # 2. create sorted history
        history = []
        for tx_hash in tx_deltas:
            delta = tx_deltas[tx_hash]
            tokens_deltas = tx_tokens_deltas.get(tx_hash, {}) if include_tokens else None
            height, conf, timestamp = self.get_tx_height(tx_hash)
            history.append((tx_hash, height, conf, timestamp, delta, tokens_deltas))

        def sort_func_simple(h_item):
            """Here we naively sort just by tx_pos in the block (CTOR ordering), per block"""
            return self.get_txpos(h_item[0])

        def sort_func_receives_before_sends(h_item):
            """Here we sort in a way such that receives are always ordered before sends, per block"""
            height, pos = self.get_txpos(h_item[0])
            delta = h_item[4] or 0  # Guard against delta == None by forcing None -> 0
            return height, -delta, pos

        sort_func = sort_func_receives_before_sends if receives_before_sends else sort_func_simple
        history.sort(key=sort_func, reverse=True)

        # 3. add balance
        c, u, x, toks_ignored = self.get_balance(domain, tokens=True)
        balance = c + u + x
        h2 = []
        tokens_balances = defaultdict(lambda: {"fungibles": 0, "nfts": 0})

        def tally_token_balance(tokens_deltas, add: bool, cleanup_zeroes=False):
            for token_id, tdelta in tokens_deltas.items():
                ft_amt = tdelta.get("fungibles", 0)
                nft_amt = len(tdelta.get("nfts_in", [])) - len(tdelta.get("nfts_out", []))
                if add:
                    tokens_balances[token_id]["fungibles"] += ft_amt
                    tokens_balances[token_id]["nfts"] += nft_amt
                else:
                    tokens_balances[token_id]["fungibles"] -= ft_amt
                    tokens_balances[token_id]["nfts"] -= nft_amt
                if cleanup_zeroes:
                    # After tallying, clean up zero balances
                    if not tokens_balances[token_id]["fungibles"] and not tokens_balances[token_id]["nfts"]:
                        del tokens_balances[token_id]

        if include_tokens and include_tokens_balances:
            for h_item in history:
                tally_token_balance(h_item[5] or {}, True)

        for tx_hash, height, conf, timestamp, delta, tokens_deltas in history:
            tup_base = tx_hash, height, conf, timestamp, delta, balance
            if include_tokens:
                tup = tup_base + (tokens_deltas, copy.deepcopy(tokens_balances))
                # Add to history
                h2.append(self.TxHistory2(*tup))

                if tokens_deltas and include_tokens_balances:
                    # maintain  balance
                    tally_token_balance(tokens_deltas, False, True)
            else:
                h2.append(self.TxHistory(*tup_base))

            if balance is None or delta is None:
                balance = None
            else:
                balance -= delta
        if not reverse:
            h2.reverse()

        return h2

    def export_history(self, domain=None, from_timestamp=None, to_timestamp=None, fx=None,
                       show_addresses=False, decimal_point=8,
                       *, fee_calc_timeout=10.0, download_inputs=False,
                       progress_callback=None, receives_before_sends=False):
        ''' Export history. Used by RPC & GUI.

        Arg notes:
        - `fee_calc_timeout` is used when computing the fee (which is done
          asynchronously in another thread) to limit the total amount of time in
          seconds spent waiting for fee calculation. The timeout is a total time
          allotment for this function call. (The reason the fee calc can take a
          long time is for some pathological tx's, it is very slow to calculate
          fee as it involves deserializing prevout_tx from the wallet, for each
          input).
        - `download_inputs`, if True, will allow for more accurate fee data to
          be exported with the history by using the Transaction class input
          fetcher to download *all* prevout_hash tx's for inputs (even for
          inputs not in wallet). This feature requires self.network (ie, we need
          to be online) otherwise it will behave as if download_inputs=False.
        - `progress_callback`, if specified, is a callback which receives a
          single float argument in the range [0.0,1.0] indicating how far along
          the history export is going. This is intended for interop with GUI
          code. Node the progress callback is not guaranteed to be called in the
          context of the main thread, therefore GUI code should use appropriate
          signals/slots to update the GUI with progress info.

        Note on side effects: This function may update self.tx_fees. Rationale:
        it will spend some time trying very hard to calculate accurate fees by
        examining prevout_tx's (leveraging the fetch_input_data code in the
        Transaction class). As such, it is worthwhile to cache the results in
        self.tx_fees, which gets saved to wallet storage. This is not very
        demanding on storage as even for very large wallets with huge histories,
        tx_fees does not use more than a few hundred kb of space. '''
        from .util import timestamp_to_datetime
        # we save copies of tx's we deserialize to this temp dict because we do
        # *not* want to deserialize tx's in wallet.transactoins since that
        # wastes memory
        local_tx_cache = {}
        # some helpers for this function
        t0 = time.time()
        def time_remaining(): return max(fee_calc_timeout - (time.time()-t0), 0)
        class MissingTx(RuntimeError):
            ''' Can happen in rare circumstances if wallet history is being
            radically reorged by network thread while we are in this code. '''
        def get_tx(tx_hash):
            ''' Try to get a tx from wallet, then from the Transaction class
            cache if that fails. In either case it deserializes the copy and
            puts the deserialized tx in local stack dict local_tx_cache. The
            reason we don't deserialize the tx's from self.transactions is that
            we do not want to keep deserialized tx's in memory. The
            self.transactions dict should contain just raw tx's (not
            deserialized). Deserialized tx's eat on the order of 10x the memory
            because because of the Python lists, dict, etc they contain, per
            instance. '''
            tx = local_tx_cache.get(tx_hash)
            if tx:
                return tx
            tx = Transaction.tx_cache_get(tx_hash)
            if not tx:
                tx = copy.deepcopy(self.transactions.get(tx_hash))
            if tx:
                tx.deserialize()
                local_tx_cache[tx_hash] = tx
            else:
                raise MissingTx(f'txid {tx_hash} dropped out of wallet history while exporting')
            return tx
        def try_calc_fee(tx_hash):
            ''' Try to calc fee from cheapest to most expensive calculation.
            Ultimately asks the transaction class to look at prevouts in wallet and uses
            that scheme as a last (more CPU intensive) resort. '''
            fee = self.tx_fees.get(tx_hash)
            if fee is not None:
                return fee
            def do_get_fee(tx_hash):
                tx = get_tx(tx_hash)
                def try_get_fee(tx):
                    try: return tx.get_fee()
                    except InputValueMissing: pass
                fee = try_get_fee(tx)
                t_remain = time_remaining()
                if fee is None and t_remain:
                    q = queue.Queue()
                    def done():
                        q.put(1)
                    tx.fetch_input_data(self, use_network=bool(download_inputs), done_callback=done)
                    try: q.get(timeout=t_remain)
                    except queue.Empty: pass
                    fee = try_get_fee(tx)
                return fee
            fee = do_get_fee(tx_hash)
            if fee is not None:
                self.tx_fees[tx_hash] = fee  # save fee to wallet if we bothered to dl/calculate it.
            return fee
        def fmt_amt(v, is_diff):
            if v is None:
                return '--'
            return format_satoshis(v, decimal_point=decimal_point,
                                   is_diff=is_diff)

        # grab history
        h = self.get_history(domain, reverse=True, receives_before_sends=receives_before_sends)
        out = []

        n, l = 0, max(1, float(len(h)))
        for tx_hash, height, conf, timestamp, value, balance in h:
            if progress_callback:
                progress_callback(n/l)
            n += 1
            timestamp_safe = timestamp
            if timestamp is None:
                timestamp_safe = time.time()  # set it to "now" so below code doesn't explode.
            if from_timestamp and timestamp_safe < from_timestamp:
                continue
            if to_timestamp and timestamp_safe >= to_timestamp:
                continue
            try:
                fee = try_calc_fee(tx_hash)
            except MissingTx as e:
                self.print_error(str(e))
                continue
            item = {
                'txid'          : tx_hash,
                'height'        : height,
                'confirmations' : conf,
                'timestamp'     : timestamp_safe,
                'value'         : fmt_amt(value, is_diff=True),
                'fee'           : fmt_amt(fee, is_diff=False),
                'balance'       : fmt_amt(balance, is_diff=False),
            }
            if item['height'] > 0:
                date_str = format_time(timestamp) if timestamp is not None else _("unverified")
            else:
                date_str = _("unconfirmed")
            item['date'] = date_str
            try:
                # Defensive programming.. sanitize label.
                # The below ensures strings are utf8-encodable. We do this
                # as a paranoia measure.
                item['label'] = self.get_label(tx_hash).encode(encoding='utf-8', errors='replace').decode(encoding='utf-8', errors='replace')
            except UnicodeError:
                self.print_error(f"Warning: could not export label for {tx_hash}, defaulting to ???")
                item['label'] = "???"
            if show_addresses:
                tx = get_tx(tx_hash)
                input_addresses = []
                output_addresses = []
                for x in tx.inputs():
                    if x['type'] == 'coinbase': continue
                    addr = x.get('address')
                    if addr == None: continue
                    input_addresses.append(addr.to_ui_string())
                for _type, addr, v in tx.outputs():
                    output_addresses.append(addr.to_ui_string())
                item['input_addresses'] = input_addresses
                item['output_addresses'] = output_addresses
            if fx is not None:
                date = timestamp_to_datetime(timestamp_safe)
                item['fiat_value'] = fx.historical_value_str(value, date)
                item['fiat_balance'] = fx.historical_value_str(balance, date)
                item['fiat_fee'] = fx.historical_value_str(fee, date)
            out.append(item)
        if progress_callback:
            progress_callback(1.0)  # indicate done, just in case client code expects a 1.0 in order to detect completion
        return out

    def get_label(self, tx_hash):
        label = self.labels.get(tx_hash, '')
        if not label:
            label = self.get_default_label(tx_hash)
        return label

    def get_default_label(self, tx_hash):
        if not self.txi.get(tx_hash):
            d = self.txo.get(tx_hash, {})
            labels = []
            for addr in list(d.keys()):  # use a copy to avoid possibility of dict changing during iteration, see #1328
                label = self.labels.get(addr.to_storage_string())
                if label:
                    labels.append(label)
            return ', '.join(labels)
        return ''

    def get_tx_status(self, tx_hash, height, conf, timestamp):
        if conf == 0:
            tx = self.transactions.get(tx_hash)
            if not tx:
                return 3, 'unknown'
            fee = self.tx_fees.get(tx_hash)
            # we disable fee estimates in BCH for now.
            #if fee and self.network and self.network.config.has_fee_estimates():
            #    size = len(tx.raw)/2
            #    low_fee = int(self.network.config.dynfee(0)*size/1000)
            #    is_lowfee = fee < low_fee * 0.5
            #else:
            #    is_lowfee = False
            # and instead if it's less than 1.0 sats/B we flag it as low_fee
            try:
                # NB len(tx.raw) is 2x the byte size as it's hex encoded.
                is_lowfee = int(fee) / (int(len(tx.raw)) / 2.0) < 1.0  # if less than 1.0 sats/B, complain. otherwise don't.
            except (TypeError, ValueError):  # If for some reason fee was None or invalid, just pass on through.
                is_lowfee = False
            # /
            if height < 0:
                status = 0
            elif height == 0 and is_lowfee:
                status = 1
            elif height == 0:
                status = 2
            else:
                status = 3
        else:
            status = 3 + min(conf, 6)
        if status >= 4:
            status_str = format_time(timestamp) if timestamp else _("unknown")
        else:
            status_str = TX_STATUS[status]
        return status, status_str

    def relayfee(self):
        return relayfee(self.network)

    def dust_threshold(self):
        return dust_threshold(self.network)

    def reserve_change_addresses(self, count, temporary=False):
        """ Reserve and return `count` change addresses. In order
        of preference, this will return from:

        1. addresses 'freed' by `.unreserve_change_address`,
        2. addresses in the last 20 (gap limit) of the change list,
        3. newly-created addresses.

        Of these, only unlabeled, unreserved addresses with no usage history
        will be returned. If you pass temporary=False (default), this will
        persist upon wallet saving, otherwise with temporary=True the address
        will be made available again once the wallet is re-opened.

        On non-deterministic wallets, this returns an empty list.
        """
        if count <= 0 or not hasattr(self, 'create_new_preferred_address'):
            return []

        with self.lock:
            last_change_addrs = self.get_preferred_change_addresses()[-self.gap_limit_for_change:]
            if not last_change_addrs:
                # this happens in non-deterministic wallets but the above
                # hasattr check should have caught those.
                return []

            def gen_change():
                try:
                    while True:
                        yield self.change_unreserved.pop(0)
                except IndexError:
                    pass
                for addr in last_change_addrs:
                    yield addr
                while True:
                    yield self.create_new_preferred_address(for_change=True)

            result = []
            for addr in gen_change():
                if (   addr in self.change_reserved
                    or addr in self.change_reserved_tmp
                    or self.get_num_tx(addr) != 0
                    or addr in result):
                    continue

                addr_str = addr.to_storage_string()
                if self.labels.get(addr_str):
                    continue

                result.append(addr)
                if temporary:
                    self.change_reserved_tmp.add(addr)
                else:
                    self.change_reserved.add(addr)
                if len(result) >= count:
                    return result

            raise RuntimeError("Unable to generate new addresses") # should not happen

    def unreserve_change_address(self, addr):
        """ Unreserve an addr that was set by reserve_change_addresses, and
        also explicitly reschedule this address to be usable by a future
        reservation. Unreserving is appropriate when the address was never
        actually shared or used in a transaction, and reduces empty gaps in
        the change list.
        """
        assert addr in self.get_change_addresses()
        with self.lock:
            self.change_reserved.discard(addr)
            self.change_reserved_tmp.discard(addr)
            self.change_unreserved.append(addr)

    def get_default_change_addresses(self, count):
        """ Return `count` change addresses from the default reserved list,
        ignoring and removing used addresses. Reserves more as needed.

        The same default change addresses keep getting repeated until they are
        actually seen as used in a transaction from the network. Theoretically
        this could hurt privacy if the user has multiple unsigned transactions
        open at the same time, but practically this avoids address gaps for
        normal usage. If you need non-repeated addresses, see
        `reserve_change_addresses`.

        On non-deterministic wallets, this returns an empty list.
        """
        result = []
        with self.lock:
            for addr in list(self.change_reserved_default):
                if len(result) >= count:
                    break
                if self.get_num_tx(addr) != 0:
                    self.change_reserved_default.remove(addr)
                    continue
                result.append(addr)
            need_more = count - len(result)
            if need_more > 0:
                new_addrs = self.reserve_change_addresses(need_more)
                self.change_reserved_default.extend(new_addrs)
                result.extend(new_addrs)
            return result

    def make_unsigned_transaction(self, inputs, outputs, config, fixed_fee=None, change_addr=None, sign_schnorr=None,
                                  *, token_datas=None, bip69_sort=True):
        ''' sign_schnorr flag controls whether to mark the tx as signing with
        schnorr or not. Specify either a bool, or set the flag to 'None' to use
        whatever the wallet is configured to use from the GUI '''
        sign_schnorr = self.is_schnorr_enabled() if sign_schnorr is None else bool(sign_schnorr)
        # check outputs
        i_max = None
        for i, o in enumerate(outputs):
            _type, data, value = o
            if value == '!':
                if i_max is not None:
                    raise BaseException("More than one output set to spend max")
                i_max = i

        # Avoid index-out-of-range with inputs[0] below
        if not inputs:
            raise NotEnoughFunds()

        if fixed_fee is None and config.fee_per_kb() is None:
            raise BaseException('Dynamic fee estimates not available')

        for item in inputs:
            self.add_input_info(item)

        # Fee estimator
        if fixed_fee is None:
            fee_estimator = config.estimate_fee
        elif callable(fixed_fee):
            fee_estimator = fixed_fee
        else:
            fee_estimator = lambda size: fixed_fee

        if i_max is None:
            # Let the coin chooser select the coins to spend

            change_addrs = []
            if change_addr:
                change_addrs = [change_addr]
            else:
                # Currently the only code that uses this hook is the deprecated
                # Cash Shuffle plugin
                change_addrs = run_hook("get_change_addrs", self) or []

            if not change_addrs:
                # hook gave us nothing, so find a change addr from the change
                # reservation subsystem
                max_change = self.max_change_outputs if self.multiple_change else 1
                if self.use_change:
                    change_addrs = self.get_default_change_addresses(max_change)
                else:
                    change_addrs = []

                if not change_addrs:
                    # For some reason we couldn't get any autogenerated change
                    # address (non-deterministic wallet?). So, try to find an
                    # input address that belongs to us.
                    for inp in inputs:
                        backup_addr = inp['address']
                        if self.is_mine(backup_addr):
                            change_addrs = [backup_addr]
                            break
                    else:
                        # ok, none of the inputs are "mine" (why?!) -- fall back
                        # to picking first max_change change_addresses that have
                        # no history
                        change_addrs = []
                        for addr in self.get_preferred_change_addresses()[-self.gap_limit_for_change:]:
                            if self.get_num_tx(addr) == 0:
                                change_addrs.append(addr)
                                if len(change_addrs) >= max_change:
                                    break
                        if not change_addrs:
                            # No unused wallet addresses or no change addresses.
                            # Fall back to picking ANY wallet address
                            try:
                                # Pick a random address
                                change_addrs = [random.choice(self.get_preferred_addresses())]
                            except IndexError:
                                change_addrs = []  # Address-free wallet?!
                        # This should never happen
                        if not change_addrs:
                            raise RuntimeError("Can't find a change address!")

            assert all(isinstance(addr, Address) for addr in change_addrs)

            coin_chooser = coinchooser.CoinChooserPrivacy()
            tx = coin_chooser.make_tx(inputs, outputs, change_addrs,
                                      fee_estimator, self.dust_threshold(), sign_schnorr=sign_schnorr,
                                      token_datas=token_datas)
        else:
            sendable = sum(map(lambda x:x['value'], inputs))
            _type, data, value = outputs[i_max]
            outputs[i_max] = (_type, data, 0)
            tx = Transaction.from_io(inputs, outputs, sign_schnorr=sign_schnorr, token_datas=token_datas)
            fee = fee_estimator(tx.estimated_size())
            amount = max(0, sendable - tx.output_value() - fee)
            outputs[i_max] = (_type, data, amount)
            tx = Transaction.from_io(inputs, outputs, sign_schnorr=sign_schnorr, token_datas=token_datas)

        # If user tries to send too big of a fee (more than 50 sat/byte), stop them from shooting themselves in the foot
        tx_in_bytes=tx.estimated_size()
        fee_in_satoshis=tx.get_fee()
        sats_per_byte=fee_in_satoshis/tx_in_bytes
        if (sats_per_byte > 50):
            raise ExcessiveFee()

        if bip69_sort:
            # Sort the inputs and outputs deterministically
            tx.BIP69_sort()
        # Timelock tx to current height.
        locktime = self.get_local_height()
        if locktime == -1: # We have no local height data (no headers synced).
            locktime = 0
        tx.locktime = locktime
        run_hook('make_unsigned_transaction', self, tx)

        return tx

    def mktx(self, outputs, password, config, fee=None, change_addr=None, domain=None, sign_schnorr=None):
        coins = self.get_spendable_coins(domain, config)
        tx = self.make_unsigned_transaction(coins, outputs, config, fee, change_addr, sign_schnorr=sign_schnorr)
        self.sign_transaction(tx, password)
        return tx

    def make_token_send_tx(self, config, spec: TokenSendSpec, *, sign_schnorr=None,
                           bip69_sort=True) -> Transaction:
        assert all(x['token_data'] for x in spec.token_utxos.values())
        assert not any(x['token_data'] for x in spec.non_token_utxos.values())
        assert isinstance(spec.payto_addr, Address) and isinstance(spec.change_addr, Address)
        assert isinstance(spec.feerate, int) and spec.feerate >= 0
        assert all(utxoname in spec.token_utxos for utxoname in spec.send_nfts)
        assert all(utxoname in spec.token_utxos and utxoname in spec.send_nfts and isinstance(commitment, bytes)
                   for utxoname, commitment in spec.edit_nfts.items())
        assert all(utxoname in spec.token_utxos and utxoname in spec.send_nfts and isinstance(l, (list, tuple))
                   and len(l) > 0 and spec.get_utxo(utxoname)['token_data'].is_minting_nft()
                   for utxoname, l in spec.mint_nfts.items())

        def get_utxo(name) -> Dict[str, Any]:
            ret = spec.get_utxo(name)
            assert ret
            return ret

        def clone_and_set_amt(td: token.OutputData, amt: int, clear_nft=False,
                              edit_commitment: Optional[bytes] = None) -> token.OutputData:
            """Returns a clone of td with amount force-set to amt"""
            assert amt >= 0 and (not clear_nft or edit_commitment is None)
            bf = td.bitfield
            if amt > 0:
                bf |= token.Structure.HasAmount
            else:  # amt == 0
                bf &= (0xff & ~token.Structure.HasAmount)
            commitment = td.commitment
            if clear_nft and td.has_nft():
                commitment = b''
                bf &= (0xff & ~(token.Structure.HasNFT | token.Structure.HasCommitmentLength))
                bf &= (0xff & ~(token.Capability.Minting | token.Capability.Mutable))  # clear capability nybble
            elif edit_commitment is not None:
                assert td.has_nft()
                commitment = edit_commitment
                if not len(commitment):
                    bf &= 0xff & ~token.Structure.HasCommitmentLength
                else:
                    bf |= token.Structure.HasCommitmentLength
            ret = token.OutputData(id=td.id, amount=amt, commitment=commitment, bitfield=bf)
            return ret

        ft_in: DefaultDict[str, int] = defaultdict(int)  # token-id -> amount

        class TDList(list):
            """This always is a list of token.OutputData"""

            seen_tids = set()

            def find_first_fungible_only(self, tid: str) -> Optional[Tuple[int, token.OutputData]]:
                for i, td in enumerate(self):
                    if td.id_hex == tid and not td.has_nft():
                        return i, td

            def find_first_any(self, tid: str) -> Optional[Tuple[int, token.OutputData]]:
                for i, td in enumerate(self):
                    if td.id_hex == tid:
                        return i, td

            def clear_all_amts(self, tid: str) -> int:
                ret = 0
                for idx, td in enumerate(self.copy()):
                    if td.id_hex == tid:
                        ret += td.amount
                        self[idx] = clone_and_set_amt(td, amt=0)
                return ret

            def copy(self):
                ret = TDList(self)
                ret.seen_tids = self.seen_tids.copy()
                return ret

            def append(self, item):
                if isinstance(item, token.OutputData):
                    self.seen_tids.add(item.id_hex)
                return super().append(item)

        tds_out = TDList()  # token outputs to payee
        tds_change_out = TDList()  # for NFT or FT "change" (to wallet)

        inputs: List[Dict[str, Any]] = []  # list of utxos as inputs
        input_names: Set[str] = set()  # set of utxonames in inputs above

        def add_token_change_out(td_change: token.OutputData):
            id_hex = td_change.id_hex
            assert td_change.has_nft() or td_change.amount > 0

            if td_change.has_nft():
                tup = tds_change_out.find_first_fungible_only(id_hex)
            else:
                tup = tds_change_out.find_first_any(id_hex)
            if tup:
                # Since we have an existing change output for this token-id, we can try to merge
                idx, td_existing = tup
                merged_amt = td_existing.amount + td_change.amount
                if not td_change.has_nft():
                    # Take this FT-only amount and merge with any existing
                    tds_change_out[idx] = clone_and_set_amt(td_existing, amt=merged_amt)
                    return
                elif td_change.has_nft() and not td_existing.has_nft():
                    # Take this NFT and merge with the fungible-only that already exists
                    tds_change_out[idx] = clone_and_set_amt(td_change, amt=merged_amt)
                    return
            tds_change_out.append(td_change)

        def add_token_input(utxo_name: str, utxo: dict, td_out: Optional[token.OutputData]):
            assert utxo_name not in input_names
            td_in = utxo['token_data']
            id_hex = td_in.id_hex
            assert td_out is None or id_hex == td_out.id_hex
            if td_out is not None:
                tds_out.append(td_out)
            inputs.append(copy.deepcopy(utxo))  # add to inputs now
            input_names.add(utxo_name)  # remember that it was consumed
            ft_in[id_hex] += td_in.amount  # tally the ft amounts we are consuming

        def have_ft(tid): return ft_in.get(tid, 0)

        # First, figure out which inputs must exist because they are specified as nfts
        for utxo_name in spec.send_nfts:
            utxo = get_utxo(utxo_name)
            td: token.OutputData = utxo['token_data']
            assert td.has_nft()
            ft_needed = max(0, spec.send_fungible_amounts.get(td.id_hex, 0) - have_ft(td.id_hex))
            target_amt = min(td.amount, ft_needed)
            # add to tds_out; strip excess fungibles out that aren't requested
            td_out = clone_and_set_amt(td, amt=target_amt, edit_commitment=spec.edit_nfts.get(utxo_name))
            assert td_out.amount == target_amt
            add_token_input(utxo_name, utxo, td_out)
            change_amt = td.amount - target_amt
            if change_amt > 0:
                td_ft_change = clone_and_set_amt(td, amt=change_amt, clear_nft=True)
                add_token_change_out(td_ft_change)
            # Lastly, append newly-minted NFTs specified in spec.mint_nfts, if any
            if spec.mint_nfts and td.is_minting_nft():
                tuplist = spec.mint_nfts.get(utxo_name)
                if tuplist:
                    for capability, commitment in tuplist:
                        # Ensure sanity
                        assert (isinstance(capability, int) and isinstance(commitment, bytes)
                                and len(commitment) <= token.MAX_CONSENSUS_COMMITMENT_LENGTH
                                and capability in (token.Capability.NoCapability, token.Capability.Mutable,
                                                   token.Capability.Minting))
                        bitfield = 0xff & (token.Structure.HasNFT | capability)
                        if len(commitment):
                            bitfield |= 0xff & token.Structure.HasCommitmentLength
                        new_nft = token.OutputData(id=td.id, amount=0, bitfield=bitfield, commitment=commitment)
                        # Finally, append to end of "token datas out" list..
                        tds_out.append(new_nft)

        # Find fungibles to spend, prefer pure ft-only, but fall-back to nft
        for tid, amt in spec.send_fungible_amounts.items():
            def have(): return have_ft(tid)
            def have_enough(): return amt <= 0 or have() >= amt
            if have_enough():
                continue
            for allow_nft in range(2):  # loop twice, first time seeking-out fungibles-only
                if have_enough():
                    break
                for utxo_name, utxo in spec.token_utxos.items():
                    if have_enough():
                        break
                    if utxo_name in input_names:
                        continue
                    td = utxo['token_data']
                    # is this token and has fungibles and prefer ft-only tokens first time thru
                    if td.id_hex == tid and td.has_amount() and (allow_nft or not td.has_nft()):
                        tup = tds_out.find_first_fungible_only(tid) or tds_out.find_first_any(tid)
                        additional_amount = min(amt - have(), td.amount)
                        change_amount = td.amount - additional_amount
                        if tup is None:  # no existing token output for this tid, create a pure-ft output
                            td_ft_only = clone_and_set_amt(td, amt=additional_amount, clear_nft=True)
                            add_token_input(utxo_name, utxo, td_ft_only)
                        else:
                            add_token_input(utxo_name, utxo, None)  # consume input, no new outputs
                            # have existing output for this token-id, update fungible amount
                            idx, td_existing = tup
                            td_updated = clone_and_set_amt(td_existing,
                                                           amt=td_existing.amount + additional_amount)
                            tds_out[idx] = td_updated
                        # if input has nft (output doesn't), then preserve the NFT: tally this as a
                        # "change" output
                        if td.has_nft() or change_amount > 0:
                            # If any NFT or FT is leftover, clone what remains and add to change
                            add_token_change_out(clone_and_set_amt(td, amt=change_amount))
            if not have_enough():
                # Ideally the UI prevents this situation. But we raise in case the TokenSendSpec is wrong
                raise NotEnoughFunds()

        # Next, consolidate fungible amounts so that they all go to the same output
        for which, l in enumerate((tds_out, tds_change_out)):
            list_name = ('tds_out', 'tds_change_out')[which]
            for tid in l.seen_tids:
                tup = l.find_first_fungible_only(tid) or l.find_first_any(tid)
                if tup:
                    total = l.clear_all_amts(tid)
                    idx, td = tup
                    self.print_error(f"Consolidating {total} fungibles for tid={tid} to list={list_name} pos={idx}")
                    l[idx] = clone_and_set_amt(td, amt=total)  # update 1 output to have the consolidated amt
            # Finally, delete any fungible-only amount=0 outputs
            ctr = 0
            for i, td in enumerate(l):
                if not td.has_nft() and not td.amount:
                    self.print_error(f"Consolidation: WARNING - Deleting fungible-only token output with amount=0"
                                     f" tid={td.id_hex} list={list_name} pos={i}")
                    del l[i - ctr]
                    ctr += 1
            for td in l:
                assert td.is_valid_bitfield(), list_name

        # Setup outputs
        token_dust = token.heuristic_dust_limit_for_token_bearing_output()  # 800 sats
        outputs: List[Tuple[int, Address, Union[int, str]]]
        outputs = [(TYPE_ADDRESS, spec.payto_addr, token_dust)] * len(tds_out)
        tds_satoshis = []
        if spec.send_satoshis > 0:
            outputs += [(TYPE_ADDRESS, spec.payto_addr, spec.send_satoshis)]
            tds_satoshis += [None]  # Non-token output for pure BCH
        outputs += [(TYPE_ADDRESS, spec.change_addr, token_dust)] * len(tds_change_out)

        token_datas = tds_out + tds_satoshis + tds_change_out

        # Add change output
        i_change = len(outputs)
        outputs.append((TYPE_ADDRESS, spec.change_addr, '!'))
        token_datas.append(None)
        assert len(outputs) == len(token_datas)

        sign_schnorr = self.is_schnorr_enabled() if sign_schnorr is None else sign_schnorr
        addrs_seen: Set[Address] = {spec.change_addr, spec.payto_addr}
        # This is needed so that Transaction.from_io below works
        for inp in inputs:
            self.add_input_info(inp)
            addrs_seen.add(inp['address'])

        def value_out(): return sum(o[2] for o in outputs if isinstance(o[2], int))
        def value_in(): return sum(ux['value'] for ux in inputs)
        def get_fee(tx_size): return int(math.ceil((tx_size / 1000) * max(spec.feerate, config.fee_rates[0])))

        def est_tx_size():
            outs = outputs.copy()
            # mogrify since Transaction.from_io doesn't know about '!' notation
            outs[i_change] = (outs[i_change][0], outs[i_change][1], 0)
            tx = Transaction.from_io(inputs, outs, sign_schnorr=sign_schnorr, token_datas=token_datas)
            return tx.estimated_size()

        # Next, try and satisfy the BCH requirement
        while value_in() < value_out() + get_fee(est_tx_size()):
            def sorter(tup):
                name, utxo = tup
                addr = utxo['address']
                return int(addr not in addrs_seen), -utxo['value'], utxo['height'], name
            sorted_utxo_tups = sorted(spec.non_token_utxos.items(), key=sorter)
            for utxo_name, utxo in sorted_utxo_tups:
                if utxo_name in input_names:
                    continue
                inputs.append(copy.deepcopy(utxo))
                addrs_seen.add(inputs[-1]['address'])
                input_names.add(utxo_name)
                self.add_input_info(inputs[-1])
                break
            else:
                raise NotEnoughFunds()

        tx: Transaction
        tx = self.make_unsigned_transaction(inputs, outputs, config, token_datas=token_datas, fixed_fee=get_fee,
                                            sign_schnorr=sign_schnorr, bip69_sort=False)
        if tx._outputs:
            # Corner case: delete the change output if it contains dust
            t, addr, value = tx._outputs[i_change]
            if addr == spec.change_addr and value < dust_threshold(self.network):
                self.print_error(f"Deleting change output at position {i_change} with value: {value}")
                del tx._outputs[i_change]
                assert tx._token_datas[i_change] is None
                del tx._token_datas[i_change]
                tx.invalidate_common_sighash_cache()

        if bip69_sort:
            # Sort the inputs and outputs deterministically
            tx.BIP69_sort()

        def raise_if_tokens_burned():
            """If tokens are burned, raises TokensBurnedError. Tokens burned involves just counts for each
            NFT out being less than NFT in, and FT amount counts mismatching. We don't enforce the consensus
            rules regarding prevention of ex-nihilo-tokens (out of thin air) -- that's up to the full node to
            prevent. We also don't correctly handle mutable or minting NFTs "dropping privileges" since for
            the purposes of this function's pre/post conditions, that's not supported and would indicate a
            programming error above if it were to occur.

            In short: This function is just defensive programming to detect bugs in the above code that may
            lead to tokens being destroyed."""
            non_mint_in, non_mint_out = defaultdict(int), defaultdict(int)
            ft_amts_in, ft_amts_out = defaultdict(int), defaultdict(int)
            mint_in, mint_out = defaultdict(int), defaultdict(int)

            for utxo in tx.inputs():
                td: Optional[token.OutputData] = utxo['token_data']
                if td:
                    tid = td.id_hex
                    ft_amts_in[tid] += td.amount
                    if td.has_nft():
                        if td.is_minting_nft():
                            mint_in[tid] += 1
                        else:
                            non_mint_in[tid] += 1
            for _, td in tx.outputs(tokens=True):
                if td:
                    tid = td.id_hex
                    ft_amts_out[tid] += td.amount
                    if td.has_nft():
                        if td.is_minting_nft():
                            mint_out[tid] += 1
                        else:
                            non_mint_out[tid] += 1

            if ft_amts_in != ft_amts_out:
                raise TokensBurnedError()
            for tid, ct in mint_in.items():
                if mint_out[tid] < ct:
                    raise TokensBurnedError()
            for tid, ct in non_mint_in.items():
                out_ct = non_mint_out[tid]
                if out_ct < ct:
                    raise TokensBurnedError()

        raise_if_tokens_burned()

        return tx

    def is_frozen(self, addr):
        """ Address-level frozen query. Note: this is set/unset independent of
        'coin' level freezing. """
        assert isinstance(addr, Address)
        return addr in self.frozen_addresses

    def is_frozen_coin(self, utxo: Union[str, dict, Set[str]]) -> Union[bool, Set[str]]:
        """ 'coin' level frozen query. Note: this is set/unset independent of
        address-level freezing.

        `utxo` is a prevout:n string, or a dict as returned from get_utxos(),
        in which case a bool is returned.

        `utxo` may also be a set of prevout:n strings in which case a set is
        returned which is the intersection of the internal frozen coin sets
        and the `utxo` set. """
        assert isinstance(utxo, (str, dict, set))
        if isinstance(utxo, dict):
            name = ("{}:{}".format(utxo['prevout_hash'], utxo['prevout_n']))
            ret = name in self.frozen_coins or name in self.frozen_coins_tmp
            if ret != utxo['is_frozen_coin']:
                self.print_error("*** WARNING: utxo has stale is_frozen_coin flag", name)
                utxo['is_frozen_coin'] = ret  # update stale flag
            return ret
        elif isinstance(utxo, set):
            # set is returned
            return (self.frozen_coins | self.frozen_coins_tmp) & utxo
        else:
            return utxo in self.frozen_coins or utxo in self.frozen_coins_tmp

    def set_frozen_state(self, addrs, freeze):
        """Set frozen state of the addresses to `freeze`, True or False. Note
        that address-level freezing is set/unset independent of coin-level
        freezing, however both must be satisfied for a coin to be defined as
        spendable."""
        if all(self.is_mine(addr) for addr in addrs):
            if freeze:
                self.frozen_addresses |= set(addrs)
            else:
                self.frozen_addresses -= set(addrs)
            frozen_addresses = [addr.to_storage_string()
                                for addr in self.frozen_addresses]
            self.storage.put('frozen_addresses', frozen_addresses)
            return True
        return False

    def set_frozen_coin_state(self, utxos, freeze, *, temporary=False):
        """Set frozen state of the `utxos` to `freeze`, True or False. `utxos`
        is a (possibly mixed) list of either "prevout:n" strings and/or
        coin-dicts as returned from get_utxos(). Note that if passing prevout:n
        strings as input, 'is_mine()' status is not checked for the specified
        coin. Also note that coin-level freezing is set/unset independent of
        address-level freezing, however both must be satisfied for a coin to be
        defined as spendable.

        The `temporary` flag only applies if `freeze = True`. In that case,
        freezing coins will only affect the in-memory-only frozen set, which
        doesn't get saved to storage. This mechanism was added so that plugins
        (such as CashFusion) have a mechanism for ephemeral coin freezing that
        doesn't persist across sessions.

        Note that setting `freeze = False` effectively unfreezes both the
        temporary and the permanent frozen coin sets all in 1 call. Thus after a
        call to `set_frozen_coin_state(utxos, False), both the temporary and the
        persistent frozen sets are cleared of all coins in `utxos`."""
        add_set = self.frozen_coins if not temporary else self.frozen_coins_tmp
        def add(utxo):
            add_set.add(utxo)
        def discard(utxo):
            self.frozen_coins.discard(utxo)
            self.frozen_coins_tmp.discard(utxo)
        apply_operation = add if freeze else discard
        original_size = len(self.frozen_coins)
        with self.lock:
            ok = 0
            for utxo in utxos:
                if isinstance(utxo, str):
                    apply_operation(utxo)
                    ok += 1
                elif isinstance(utxo, dict):
                    # Note: we could do an is_mine check here for each coin dict here,
                    # but since all code paths leading to this branch always pass valid
                    # coins that are "mine", we removed the check to save CPU cycles.
                    #
                    # So an O(M logN) algorithm becomes O(M) without the is_mine check,
                    # where M = number of coins and N = number of addresses.
                    txo = "{}:{}".format(utxo['prevout_hash'], utxo['prevout_n'])
                    apply_operation(txo)
                    utxo['is_frozen_coin'] = bool(freeze)
                    ok += 1
            if original_size != len(self.frozen_coins):
                # Performance optimization: only set storage if the perma-set
                # changed.
                self.storage.put('frozen_coins', list(self.frozen_coins))
            return ok

    @profiler
    def prepare_for_verifier(self):
        # review transactions that are in the history
        for addr, hist in self._history.items():
            for tx_hash, tx_height in hist:
                # add it in case it was previously unconfirmed
                self.add_unverified_tx(tx_hash, tx_height)

        # if we are on a pruning server, remove unverified transactions
        with self.lock:
            vr = set(self.verified_tx.keys()) | set(self.unverified_tx.keys())
        to_pop = []
        for tx_hash in self.transactions.keys():
            if tx_hash not in vr:
                to_pop.append(tx_hash)
        for tx_hash in to_pop:
            self.print_error("removing transaction", tx_hash)
            self.transactions.pop(tx_hash)

    def start_threads(self, network):
        self.network = network
        if self.network:
            self.start_pruned_txo_cleaner_thread()
            self.prepare_for_verifier()
            self.verifier = SPV(self.network, self)
            self.synchronizer = Synchronizer(self, network)
            finalization_print_error(self.verifier)
            finalization_print_error(self.synchronizer)
            my_jobs = [self.verifier, self.synchronizer]
            if self.wallet_type == 'rpa':
                self.rpa_manager = RpaManager(self, network)
                my_jobs.append(self.rpa_manager)
            else:
                self.rpa_manager = None
            network.add_jobs(my_jobs)
            self.cashacct.start(self.network)  # start cashacct network-dependent subsystem, nework.add_jobs, etc
        else:
            self.verifier = None
            self.synchronizer = None
            self.rpa_manager = None

    def stop_threads(self):
        if self.network:
            # Note: syncrhonizer and verifier will remove themselves from the
            # network thread the next time they run, as a result of the below
            # release() calls.
            # It is done this way (as opposed to an immediate clean-up here)
            # because these objects need to do thier clean-up actions in a
            # thread-safe fashion from within the thread where they normally
            # operate on their data structures.
            self.cashacct.stop()
            if self.synchronizer:
                self.synchronizer.save()
                self.synchronizer.release()
            if self.verifier:
                self.verifier.release()
            self.synchronizer = None
            self.verifier = None
            if self.rpa_manager:
                self.network.remove_jobs([self.rpa_manager])
            self.rpa_manager = None
            self.stop_pruned_txo_cleaner_thread()
            # Now no references to the syncronizer or verifier
            # remain so they will be GC-ed
            self.storage.put('stored_height', self.get_local_height())
        self.save_network_state()

    def save_network_state(self):
        """Save all the objects which are updated by the network thread. This is called
        periodically by the Android app during long synchronizations.
        """
        with self.lock:
            self.save_addresses()
            self.save_transactions()
            self.save_verified_tx()  # implicit cashacct.save
            self.storage.put('frozen_coins', list(self.frozen_coins))
            self.save_change_reservations()
            self.storage.write()

    def start_pruned_txo_cleaner_thread(self):
        self.pruned_txo_cleaner_thread = threading.Thread(target=self._clean_pruned_txo_thread, daemon=True)
        self.pruned_txo_cleaner_thread.q = queue.Queue()
        self.pruned_txo_cleaner_thread.start()

    def stop_pruned_txo_cleaner_thread(self):
        t = self.pruned_txo_cleaner_thread
        self.pruned_txo_cleaner_thread = None  # this also signals a stop
        if t and t.is_alive():
            t.q.put(None)  # signal stop
            # if the join times out, it's ok. it means the thread was stuck in
            # a network call and it will eventually exit.
            t.join(timeout=3.0)

    def wait_until_synchronized(self, callback=None, *, timeout=None):
        tstart = time.time()
        def check_timed_out():
            if timeout is not None and time.time() - tstart > timeout:
                raise TimeoutException()
        def wait_for_wallet():
            self.set_up_to_date(False)
            while not self.is_up_to_date():
                if callback:
                    msg = "%s\n%s %d"%(
                        _("Please wait..."),
                        _("Addresses generated:"),
                        len(self.addresses(True)))
                    callback(msg)
                time.sleep(0.1)
                check_timed_out()
        def wait_for_network():
            while not self.network.is_connected():
                if callback:
                    msg = "%s \n" % (_("Connecting..."))
                    callback(msg)
                time.sleep(0.1)
                check_timed_out()
        # wait until we are connected, because the user
        # might have selected another server
        if self.network:
            wait_for_network()
            wait_for_wallet()
        else:
            self.synchronize()

    def can_export(self):
        return not self.is_watching_only() and hasattr(self.keystore, 'get_private_key')

    def is_used(self, address):
        return self.get_address_history(address) and self.is_empty(address)

    def is_empty(self, address):
        assert isinstance(address, Address)
        return not any(self.get_addr_balance(address))

    def address_is_old(self, address, age_limit=2):
        age = -1
        local_height = self.get_local_height()
        for tx_hash, tx_height in self.get_address_history(address):
            if tx_height == 0:
                tx_age = 0
            else:
                tx_age = local_height - tx_height + 1
            if tx_age > age:
                age = tx_age
            if age > age_limit:
                break # ok, it's old. not need to keep looping
        return age > age_limit

    def add_input_info(self, txin):
        address = txin['address']
        if self.is_mine(address):
            txin['type'] = self.get_txin_type(address)
            # Bitcoin Cash needs value to sign
            received, spent = self.get_addr_io(address)
            item = received.get(txin['prevout_hash']+':%d'%txin['prevout_n'])
            tx_height, value, is_cb, token_data = item
            txin['value'] = value
            txin['token_data'] = token_data
            self.add_input_sig_info(txin, address)

    def add_input_sig_info(self, txin, address):
        """ Must be reimplemented in subclasses """
        raise RuntimeError("'add_input_sig_info' is not implemented in this class: " + str(type(self)))

    def get_keystores(self):
        """ Must be reimplemented in subclasses """
        raise RuntimeError("'get_keystores' is not implemented in this class: " + str(type(self)))

    def can_sign(self, tx):
        if tx.is_complete():
            return False
        for k in self.get_keystores():
            # setup "wallet advice" so Xpub wallets know how to sign 'fd' type tx inputs
            # by giving them the sequence number ahead of time
            if isinstance(k, BIP32_KeyStore):
                for txin in tx.inputs():
                    for x_pubkey in txin['x_pubkeys']:
                        _, addr = xpubkey_to_address(x_pubkey)
                        try:
                            c, index = self.get_address_index(addr)
                        except:
                            continue
                        if index is not None:
                            k.set_wallet_advice(addr, [c,index])
            if k.can_sign(tx):
                return True
        return False

    def _get_tx_from_cache(self, tx_hash: str) -> Optional[Transaction]:
        ret = self._tx_cache.get(tx_hash)
        if ret is not None:
            # cache hit, rotate to end to indicate it was recently used and thus should not be evicted
            # from cache soon (enforces LRU cache eviction strategy)
            self._tx_cache.move_to_end(tx_hash, last=True)
        return ret

    _tx_cache_max = 250

    def _put_tx_in_cache(self, tx_hash: str, tx: Transaction):
        if not tx or not tx_hash:
            return
        if tx_hash in self._tx_cache:
            self._tx_cache.move_to_end(tx_hash, last=True)
        else:
            self._tx_cache[tx_hash] = tx
        # Limit cache size, evict oldest entries
        while len(self._tx_cache) > self._tx_cache_max:
            self._tx_cache.popitem(last=False)

    def try_to_get_tx(self, tx_hash, *, allow_network_lookup=True, timeout=30) -> Optional[Transaction]:
        # Try and find it in the wallet cache
        tx = self._get_tx_from_cache(tx_hash)
        if tx:
            return tx
        # Next look up an input transaction in the wallet where it
        # will likely be.  If co-signing a transaction it may not have
        # all the input txs, in which case we ask the network.
        tx = self.transactions.get(tx_hash)
        if tx:
            # Take a deep-copy of the txn if it came from the wallet to avoid in-wallet txs from being
            # stored in deserialized form, to save memory. In-wallet txs are stored serialized, but
            # they get deserialized if the caller calls tx.outputs(), tx.inputs(), etc, and this
            # may waste memory... so give the caller a copy of this tx instead.
            tx = Transaction(tx.raw) if tx.raw else copy.deepcopy(tx)
        else:
            # Next, try to get it from the Transaction "fetched input" cache (who knows, it might be there!)
            tx = Transaction.tx_cache_get(tx_hash)
            if not tx and self.network and allow_network_lookup:
                # Not cached. Resort to network lookup.
                request = ('blockchain.transaction.get', [tx_hash])
                try:
                    raw = self.network.synchronous_get(request, timeout=timeout)
                    tx = Transaction(raw) if raw else None
                except util.ServerError:
                    return None
        if tx:
            # It's ok to cache (this tx may be: a copy of an in-wallet tx or a network-derived tx)
            self._put_tx_in_cache(tx_hash, tx)
        return tx

    def get_wallet_tx(self, tx_hash):
        return self.try_to_get_tx(tx_hash, allow_network_lookup=False)

    def get_input_tx(self, tx_hash):
        return self.try_to_get_tx(tx_hash, allow_network_lookup=True)

    def add_input_values_to_tx(self, tx):
        """ add input values to the tx, for signing"""
        for txin in tx.inputs():
            if 'value' not in txin or 'token_data' not in txin:
                inputtx = self.get_input_tx(txin['prevout_hash'])
                if inputtx is not None:
                    (out_zero, out_addr, out_val), token_data = inputtx.outputs(tokens=True)[txin['prevout_n']]
                    txin['value'] = out_val
                    txin['prev_tx'] = inputtx   # may be needed by hardware wallets
                    txin['token_data'] = token_data

    def add_hw_info(self, tx):
        # add previous tx for hw wallets, if needed and not already there
        if any([(isinstance(k, Hardware_KeyStore) and k.can_sign(tx) and k.needs_prevtx()) for k in self.get_keystores()]):
            for txin in tx.inputs():
                if 'prev_tx' not in txin:
                    txin['prev_tx'] = self.get_input_tx(txin['prevout_hash'])
        # add output info for hw wallets
        info = {}
        xpubs = self.get_master_public_keys()
        for txout in tx.outputs():
            _type, addr, amount = txout
            if self.is_change(addr):
                index = self.get_address_index(addr)
                pubkeys = self.get_public_keys(addr)
                # sort xpubs using the order of pubkeys
                sorted_pubkeys, sorted_xpubs = zip(*sorted(zip(pubkeys, xpubs)))
                info[addr] = index, sorted_xpubs, self.m if isinstance(self, Multisig_Wallet) else None, self.txin_type
        tx.output_info = info

    def sign_transaction(self, tx, password, *, use_cache=False):
        """ Sign a transaction, requires password (may be None for password-less
        wallets). If `use_cache` is enabled then signing will be much faster.

        For transactions with N inputs and M outputs, calculating all sighashes
        takes only O(N + M) with the cache, as opposed to O(N^2 + NM) without
        the cache.

        Warning: If you modify non-signature parts of the transaction
        afterwards, do not use `use_cache`! """

        if self.is_watching_only():
            return
        # add input values for signing
        self.add_input_values_to_tx(tx)
        # hardware wallets require extra info
        if any([(isinstance(k, Hardware_KeyStore) and k.can_sign(tx)) for k in self.get_keystores()]):
            self.add_hw_info(tx)
        # sign
        for k in self.get_keystores():
            try:
                if k.can_sign(tx):
                    k.sign_transaction(tx, password, use_cache=use_cache)
            except UserCancelled:
                continue

    def get_unused_addresses(self, *, for_change=False, frozen_ok=True, preferred=False):
        # fixme: use slots from expired requests
        with self.lock:
            if preferred:
                domain = (self.get_preferred_receiving_addresses() if not for_change
                          else (self.get_preferred_change_addresses() or self.get_preferred_receiving_addresses()))
            else:
                domain = (self.get_receiving_addresses() if not for_change
                          else (self.get_change_addresses() or self.get_receiving_addresses()))
            return [addr for addr in domain
                    if not self.get_address_history(addr)
                    and addr not in self.receive_requests
                    and (frozen_ok or addr not in self.frozen_addresses)
                    and (not for_change or not self.is_retired_change_addr(addr))]

    def get_unused_address(self, *, for_change=False, frozen_ok=True, preferred=False):
        addrs = self.get_unused_addresses(for_change=for_change, frozen_ok=frozen_ok, preferred=preferred)
        if addrs:
            return addrs[0]

    def get_receiving_address(self, *, frozen_ok=True, preferred=True):
        """Returns a receiving address or None."""
        domain = self.get_unused_addresses(for_change=False, frozen_ok=frozen_ok, preferred=preferred)
        if not domain:
                addr_list = self.get_preferred_receiving_addresses() if preferred else self.get_receiving_addresses()
                domain = [a for a in addr_list
                          if frozen_ok or a not in self.frozen_addresses]
        if domain:
            return domain[0]

    def get_payment_status(self, address, amount):
        local_height = self.get_local_height()
        received, sent = self.get_addr_io(address)
        l = []
        for txo, x in received.items():
            h, v, is_cb, token_data = x
            txid, n = txo.split(':')
            info = self.verified_tx.get(txid)
            if info:
                tx_height, timestamp, pos = info
                conf = max(local_height - tx_height + 1, 0)
            else:
                conf = 0
            l.append((conf, v, txid))
        tx_hashes = []
        vsum = 0
        amount = amount or 0
        for conf, v, tx_hash in reversed(sorted(l)):
            vsum += v
            tx_hashes.append(tx_hash)
            if vsum >= amount:
                return True, conf, tx_hashes
        return False, None, tx_hashes

    def has_payment_request(self, addr):
        ''' Returns True iff Address addr has any extant payment requests
        (even if expired), False otherwise. '''
        assert isinstance(addr, Address)
        return bool(self.receive_requests.get(addr))

    def get_payment_request(self, addr, config):
        assert isinstance(addr, Address)
        r = self.receive_requests.get(addr)
        if not r:
            return
        out = copy.copy(r)
        addr_text = addr.to_ui_string()
        amount_text = format_satoshis(r['amount'])
        out['URI'] = '{}:{}'.format(networks.net.CASHADDR_PREFIX, addr_text)
        if r['amount']:
            out['URI'] += '?amount={}'.format(amount_text)
        status, conf, tx_hashes = self.get_request_status(addr)
        out['status'] = status
        out['tx_hashes'] = tx_hashes
        if conf is not None:
            out['confirmations'] = conf
        # check if bip70 file exists
        rdir = config.get('requests_dir')
        if rdir:
            key = out.get('id', addr.to_storage_string())
            path = os.path.join(rdir, 'req', key[0], key[1], key)
            if os.path.exists(path):
                baseurl = 'file://' + rdir
                rewrite = config.get('url_rewrite')
                if rewrite:
                    baseurl = baseurl.replace(*rewrite)
                out['request_url'] = os.path.join(baseurl, 'req', key[0], key[1], key, key)
                out['URI'] += ('&r=' if r['amount'] else '?r=') + out['request_url']
                if not 'index_url' in out:
                    out['index_url'] = os.path.join(baseurl, 'index.html') + '?id=' + key
                websocket_server_announce = config.get('websocket_server_announce')
                if websocket_server_announce:
                    out['websocket_server'] = websocket_server_announce
                else:
                    out['websocket_server'] = config.get('websocket_server', 'localhost')
                websocket_port_announce = config.get('websocket_port_announce')
                if websocket_port_announce:
                    out['websocket_port'] = websocket_port_announce
                else:
                    out['websocket_port'] = config.get('websocket_port', 9999)
        return out

    def get_request_status(self, key):
        r = self.receive_requests.get(key)
        if r is None:
            return PR_UNKNOWN
        address = r['address']
        amount = r.get('amount')
        timestamp = r.get('time', 0)
        if timestamp and type(timestamp) != int:
            timestamp = 0
        expiration = r.get('exp')
        if expiration and type(expiration) != int:
            expiration = 0
        conf = None
        tx_hashes = []
        paid, conf, tx_hashes = self.get_payment_status(address, amount)
        if not paid:
            status = PR_UNPAID
        elif conf == 0:
            status = PR_UNCONFIRMED
        else:
            status = PR_PAID
        if status == PR_UNPAID and expiration is not None and time.time() > timestamp + expiration:
            status = PR_EXPIRED
        return status, conf, tx_hashes

    def make_payment_request(self, addr, amount, message, expiration=None, *,
                             op_return=None, op_return_raw=None, payment_url=None, index_url=None, token_request=False):
        assert isinstance(addr, Address)
        if op_return and op_return_raw:
            raise ValueError("both op_return and op_return_raw cannot be specified as arguments to make_payment_request")
        timestamp = int(time.time())
        _id = bh2u(Hash(addr.to_storage_string() + "%d" % timestamp))[0:10]
        d = {
            'time': timestamp,
            'amount': amount,
            'exp': expiration,
            'address': addr,
            'memo': message,
            'id': _id,
            'tokenreq': token_request
        }
        if payment_url:
            d['payment_url'] = payment_url + "/" + _id
        if index_url:
            d['index_url'] = index_url + "/" + _id
        if op_return:
            d['op_return'] = op_return
        if op_return_raw:
            d['op_return_raw'] = op_return_raw
        return d

    def serialize_request(self, r):
        result = r.copy()
        result['address'] = r['address'].to_storage_string()
        return result

    def save_payment_requests(self, write=True):
        def delete_address(value):
            del value['address']
            return value

        requests = {addr.to_storage_string() : delete_address(value.copy())
                    for addr, value in self.receive_requests.items()}
        self.storage.put('payment_requests', requests)
        self.save_labels()  # In case address labels were set or cleared.
        if write:
            self.storage.write()

    def sign_payment_request(self, key, alias, alias_addr, password):
        req = self.receive_requests.get(key)
        alias_privkey = self.export_private_key(alias_addr, password)
        pr = paymentrequest.make_unsigned_request(req)
        paymentrequest.sign_request_with_alias(pr, alias, alias_privkey)
        req['name'] = to_string(pr.pki_data)
        req['sig'] = bh2u(pr.signature)
        self.receive_requests[key] = req
        self.save_payment_requests()

    def add_payment_request(self, req, config, set_address_label=True, save=True):
        addr = req['address']
        addr_text = addr.to_storage_string()
        amount = req['amount']
        message = req['memo']
        self.receive_requests[addr] = req
        if save:
            self.save_payment_requests()
        if set_address_label:
            self.set_label(addr_text, message, save=save) # should be a default label

        rdir = config.get('requests_dir')
        if rdir and amount is not None:
            key = req.get('id', addr_text)
            pr = paymentrequest.make_request(config, req)
            path = os.path.join(rdir, 'req', key[0], key[1], key)
            if not os.path.exists(path):
                try:
                    os.makedirs(path)
                except OSError as exc:
                    if exc.errno != errno.EEXIST:
                        raise
            with open(os.path.join(path, key), 'wb') as f:
                f.write(pr.SerializeToString())
            # reload
            req = self.get_payment_request(addr, config)
            req['address'] = req['address'].to_ui_string()
            with open(os.path.join(path, key + '.json'), 'w', encoding='utf-8') as f:
                f.write(json.dumps(req))

    def remove_payment_request(self, addr, config, clear_address_label_if_no_tx=True,
                               save=True):
        if isinstance(addr, str):
            addr = Address.from_string(addr)
        if addr not in self.receive_requests:
            return False
        r = self.receive_requests.pop(addr)
        if clear_address_label_if_no_tx and not self.get_address_history(addr):
            memo = r.get('memo')
            # clear it only if the user didn't overwrite it with something else
            if memo and memo == self.labels.get(addr.to_storage_string()):
                self.set_label(addr, None, save=save)

        rdir = config.get('requests_dir')
        if rdir:
            key = r.get('id', addr.to_storage_string())
            for s in ['.json', '']:
                n = os.path.join(rdir, 'req', key[0], key[1], key, key + s)
                if os.path.exists(n):
                    os.unlink(n)
        if save:
            self.save_payment_requests()
        return True

    def get_sorted_requests(self, config, *, filter_asset: Optional[str] = None):
        # `filter_asset` may be either None to indicate no filter, 'token' to return only
        # token requests, and any other value to return only BCH requests
        m = map(lambda x: self.get_payment_request(x, config), self.receive_requests.keys())
        if filter_asset is not None:
            def is_request_for_asset(req, asset):
                return (asset == 'token') == req.get('tokenreq', False)
            m = filter(lambda x: is_request_for_asset(x, filter_asset), m)
        try:
            def f(x):
                try:
                    addr = x['address']
                    return self.get_address_index(addr) or addr
                except:
                    return addr
            return sorted(m, key=f)
        except TypeError:
            # See issue #1231 -- can get inhomogenous results in the above
            # sorting function due to the 'or addr' possible return.
            # This can happen if addresses for some reason drop out of wallet
            # while, say, the history rescan is running and it can't yet find
            # an address index for an address.  In that case we will
            # return an unsorted list to the caller.
            return list(m)

    def get_fingerprint(self):
        raise NotImplementedError()

    def is_watching_only(self):
        """Reimplemented in subclasses"""
        raise NotImplementedError()

    def can_fully_sign_for_all_addresses(self):
        """Checks that all keystores are able to sign. Relevant for MultiXPubWallet hybrid wallets which have
        multiple keystores, not all of which have the private keys for their associated addresses."""
        return not self.is_watching_only() and all(not ks.is_watching_only() for ks in self.get_keystores())

    def can_import_privkey(self):
        return False

    def can_import_address(self):
        return False

    def can_delete_address(self):
        return False

    def is_multisig(self):
        # Subclass Multisig_Wallet overrides this
        return False

    def is_hardware(self):
        return any([isinstance(k, Hardware_KeyStore) for k in self.get_keystores()])

    def add_address(self, address, *, for_change=False):
        assert isinstance(address, Address)
        # paranoia, not really necessary -- just want to maintain the invariant that when we modify address history
        # below we invalidate cache.
        self._addr_bal_cache.pop(address, None)
        self.invalidate_address_set_cache()
        if address not in self._history:
            self._history[address] = []
        if self.synchronizer:
            self.synchronizer.add(address, for_change=for_change)
        self.cashacct.on_address_addition(address)

    def has_password(self):
        return self.storage.get('use_encryption', False)

    def check_password(self, password):
        self.keystore.check_password(password)

    def sign_message(self, address, message, password):
        index = self.get_address_index(address)
        return self.keystore.sign_message(index, message, password)

    def decrypt_message(self, pubkey, message, password):
        addr = self.pubkeys_to_address(pubkey)
        index = self.get_address_index(addr)
        return self.keystore.decrypt_message(index, message, password)

    def rebuild_history(self):
        """ This is an advanced function for use in the GUI when the user
        wants to resynch the whole wallet from scratch, preserving labels
        and contacts. """
        if not self.network or not self.network.is_connected():
            raise RuntimeError('Refusing to rebuild wallet without a valid server connection!')
        if not self.synchronizer or not self.verifier:
            raise RuntimeError('Refusing to rebuild a stopped wallet!')
        network = self.network
        self.synchronizer.clear_retired_change_addrs()
        self.stop_threads()
        do_addr_save = False
        with self.lock:
            self.transactions.clear(); self.unverified_tx.clear(); self.verified_tx.clear()
            self.clear_history()
            if isinstance(self, (Standard_Wallet, MultiXPubWallet)):
                # reset the address list to default too, just in case. New synchronizer will pick up the addresses again.
                self.receiving_addresses, self.change_addresses = self.receiving_addresses[:self.gap_limit], self.change_addresses[:self.gap_limit_for_change]
                do_addr_save = True
            self.change_reserved.clear()
            self.change_reserved_default.clear()
            self.change_unreserved.clear()
            self.change_reserved_tmp.clear()
            self.invalidate_address_set_cache()
        if do_addr_save:
            self.save_addresses()
        self.save_transactions()
        self.save_change_reservations()
        self.save_verified_tx()  # implicit cashacct.save
        self.storage.write()
        self.start_threads(network)
        self.network.trigger_callback('wallet_updated', self)

    def is_schnorr_possible(self, reason: list = None) -> bool:
        ''' Returns True if this wallet type is compatible.
        `reason` is an optional list where you would like a translated string
        of why Schnorr isn't possible placed (on False return). '''
        ok = bool(not self.is_multisig() and not self.is_hardware())
        if not ok and isinstance(reason, list):
            reason.insert(0, _('Schnorr signatures are disabled for this wallet type.'))
        return ok

    def is_schnorr_enabled(self) -> bool:
        ''' Returns whether schnorr is enabled AND possible for this wallet.
        Schnorr is enabled per-wallet. '''
        if not self.is_schnorr_possible():
            # Short-circuit out of here -- it's not even possible with this
            # wallet type.
            return False
        ss_cfg = self.storage.get('sign_schnorr', None)
        if ss_cfg is None:
            # Schnorr was not set in config; figure out intelligent defaults,
            # preferring Schnorr if it's at least as fast as ECDSA (based on
            # which libs user has installed). Note for watching-only we default
            # to off if unspecified regardless, to not break compatibility
            # with air-gapped signing systems that have older EC installed
            # on the signing system. This is to avoid underpaying fees if
            # signing system doesn't use Schnorr.  We can turn on default
            # Schnorr on watching-only sometime in the future after enough
            # time has passed that air-gapped systems are unlikely to not
            # have Schnorr enabled by default.
            # TO DO: Finish refactor of txn serialized format to handle this
            # case better!
            if (not self.is_watching_only()
                    and (schnorr.has_fast_sign()
                         or not ecc_fast.is_using_fast_ecc())):
                # Prefer Schnorr, all things being equal.
                # - If not watching-only & schnorr possible AND
                # - Either Schnorr is fast sign (native, ABC's secp256k1),
                #   so use it by default
                # - Or both ECDSA & Schnorr are slow (non-native);
                #   so use Schnorr in that case as well
                ss_cfg = 2
            else:
                # This branch is reached if Schnorr is slow but ECDSA is fast
                # (core's secp256k1 lib was found which lacks Schnorr) -- so we
                # default it to off. Also if watching only we default off.
                ss_cfg = 0
        return bool(ss_cfg)

    def set_schnorr_enabled(self, b: bool):
        ''' Enable schnorr for this wallet. Note that if Schnorr is not possible,
        (due to missing libs or invalid wallet type) is_schnorr_enabled() will
        still return False after calling this function with a True argument. '''
        # Note: we will have '1' at some point in the future which will mean:
        # 'ask me per tx', so for now True -> 2.
        self.storage.put('sign_schnorr', 2 if b else 0)

    def is_dsp_detected(self, txid) -> bool:
        with self.lock:
            if txid not in self._dsp_statuses:
                return False
            return True if self._dsp_statuses[txid] == DSPStatus.DETECTED else False

    def get_dsp_status(self, txid) -> DSPStatus:
        with self.lock:
            if not self.network.force_dsproof:
                return DSPStatus.UNKNOWN
            if txid in self._dsp_statuses:
                return self._dsp_statuses[txid]
            else:
                return DSPStatus.NOT_APPLICABLE

    def set_dsp_status(self, txid, status: DSPStatus):
        with self.lock:
            self._dsp_statuses[txid] = status

    def add_detected_dsproofs(self, txids):
        with self.lock:
            for t in txids:
                if t in self._dsp_statuses:
                    self._dsp_statuses[t] = DSPStatus.DETECTED

    def remove_detected_dsproof(self, txid):
        with self.lock:
            if txid in self._dsp_statuses:
                del(self._dsp_statuses[txid])
        
    def get_history_values(self) -> ValuesView[Tuple[str, int]]:
        """ Returns the an iterable (view) of all the List[tx_hash, height] pairs for each address in the wallet."""
        return self._history.values()

    def get_history_items(self) -> ItemsView[Address, List[Tuple[str, int]]]:
        return self._history.items()

    DEFAULT_CHANGE_ADDR_SUBS_LIMIT = 1000

    @property
    def limit_change_addr_subs(self) -> int:
        """Returns positive nonzero if old change subs limiting is set in wallet storage, otherwise returns 0"""
        val = int(self.storage.get('limit_change_addr_subs', self.DEFAULT_CHANGE_ADDR_SUBS_LIMIT))
        if val >= 0:
            return val
        return self.DEFAULT_CHANGE_ADDR_SUBS_LIMIT

    @limit_change_addr_subs.setter
    def limit_change_addr_subs(self, val: int):
        val = max(val or 0, 0)  # Guard against bool, None, or negative
        self.storage.put('limit_change_addr_subs', int(val))

    def is_retired_change_addr(self, addr: Address) -> bool:
        """ Returns True if the address in question is in the "retired change address" set (set maintained by
        the synchronizer).  If the network is not started (offline mode), will always return False. """
        assert isinstance(addr, Address)
        if not self.synchronizer:
            return False
        sh = addr.to_scripthash_hex()
        return sh in self.synchronizer.change_scripthashes_that_are_retired

    def is_hw_without_cashtoken_support(self):
        """If true, the UI should take steps to warn or otherwise guide the user away from receiving
        CashTokens.  This is True for hardware wallets that cannot sign txns that send CashTokens, which
        are all of them other than the satochip-based HW wallets."""
        return any(k.is_hw_without_cashtoken_support() for k in self.get_keystores())

    @profiler
    def _process_dsp_viability(self, tx_hash, callback):

        total_parents = 0
        verified_proofs = {}
        
        # This function can and should be replaced by an Electrum API that functions
        # the same way as the bitcoind RPC getdsproofscore
        def validate_dsp_eligibility(txid, input, depth = 0) -> bool:
            nonlocal total_parents
            nonlocal verified_proofs

            def _valid_tx_input_type(input) -> bool:
                if input['type'] != "p2pkh":
                    return False
                for sig in input['signatures']:
                    if sig[-2:] != "41":
                        return False
                return True

            def _valid_tx_proof(txid, merkel) -> bool:
                if self.verifier:
                    return self.verifier.verify_merkel_txid(merkel, txid)
                return False

            if depth > 6 or total_parents > 20:
                return False

            if input is not None and not _valid_tx_input_type(input):
                return False

            block_height = 0
            if txid in verified_proofs:
                return True
            else:
                try:
                    merkel = self.network.synchronous_get(('blockchain.transaction.get_merkle',[txid]), timeout=5)
                    if 'block_height' in merkel:
                        block_height = merkel['block_height']
                except Exception as e:
                    # The network call will throw if the tx isn't confirmed.
                    # Done this way to save on an extra call to get_height.
                    # Just assume that any problems is treated as an unconfirmed tx
                    pass

                if block_height > 0 and _valid_tx_proof(txid, merkel):
                    verified_proofs[txid] = True
                    return True

            tx = self.try_to_get_tx(txid)
            inputs = tx.inputs()
            total_parents = total_parents + len(inputs)
            for inp in inputs:
                if not validate_dsp_eligibility(inp['prevout_hash'], inp, depth+1):
                    return False
            return True
        
        if validate_dsp_eligibility(tx_hash, None):
            if self.get_dsp_status(tx_hash) != DSPStatus.DETECTED:
                self.set_dsp_status(tx_hash, DSPStatus.UNDETECTED)
                self.network.subscribe_to_dsproof(tx_hash, callback)
        else:
            self.set_dsp_status(tx_hash, DSPStatus.NOT_APPLICABLE)

    def subscribe_to_dsp(self, history):
        for tx_hash, tx_height in history:
            subscribed = self.network.is_dsp_subscribed(tx_hash, self.synchronizer.dsproof_callback)
            if tx_height > 0:
                self.remove_detected_dsproof(tx_hash)
                if subscribed:
                    self.network.unsubscribe_to_dsproof(tx_hash, self.synchronizer.dsproof_callback)
            else:
                if self.network.force_dsproof and not subscribed:
                    self.set_dsp_status(tx_hash, DSPStatus.PROCESSING)
                    dsp_validation_thread = threading.Thread(target=self._process_dsp_viability, args=[tx_hash, self.synchronizer.dsproof_callback])
                    dsp_validation_thread.start()

    def toggle_dsp_on_history(self, enable: bool):
        if enable:
            h = self.get_history(domain=None, reverse=True, receives_before_sends=True, include_tokens=True, include_tokens_balances=False)
            for h_item in h:
                tx_hash, height, _, _, _, _, _, _ = h_item
                if height < 1:
                    self.subscribe_to_dsp([(tx_hash, height)])
        else:
            self.network.unsubscribe_to_dsproof_for_callback(self.synchronizer.dsproof_callback)
            with self.lock:
                self._dsp_statuses = {}
        self.network.trigger_callback('wallet_updated', self)


class Simple_Wallet(Abstract_Wallet):
    """ wallet with a single keystore """

    def get_keystore(self):
        return self.keystore

    def get_keystores(self):
        return [self.keystore]

    def is_watching_only(self):
        return self.keystore.is_watching_only()

    def can_change_password(self):
        return self.keystore.can_change_password()

    def update_password(self, old_pw, new_pw, encrypt=False):
        if old_pw is None and self.has_password():
            raise InvalidPassword()
        if self.keystore is not None and self.keystore.can_change_password():
            self.keystore.update_password(old_pw, new_pw)
            self.save_keystore()
        self.storage.set_password(new_pw, encrypt)
        self.storage.write()

    def save_keystore(self):
        self.storage.put('keystore', self.keystore.dump())


class ImportedWalletBase(Simple_Wallet):

    txin_type = 'p2pkh'

    def get_txin_type(self, address):
        return self.txin_type

    def can_delete_address(self):
        return len(self.get_addresses()) > 1  # Cannot delete the last address

    def has_seed(self):
        return False

    def is_deterministic(self):
        return False

    def is_change(self, address):
        return False

    def get_master_public_keys(self):
        return []

    def is_beyond_limit(self, address, is_change):
        return False

    def get_fingerprint(self):
        return ''

    def get_receiving_addresses(self):
        return self.get_addresses()

    def delete_address(self, address):
        assert isinstance(address, Address)
        all_addrs = self.get_addresses()
        if len(all_addrs) <= 1 or address not in all_addrs:
            return
        del all_addrs

        transactions_to_remove = set()  # only referred to by this address
        transactions_new = set()  # txs that are not only referred to by address
        with self.lock:
            for addr, details in self._history.items():
                if addr == address:
                    for tx_hash, height in details:
                        transactions_to_remove.add(tx_hash)
                        self.tx_addr_hist[tx_hash].discard(address)
                        if not self.tx_addr_hist.get(tx_hash):
                            self.tx_addr_hist.pop(tx_hash, None)
                else:
                    for tx_hash, height in details:
                        transactions_new.add(tx_hash)
            transactions_to_remove -= transactions_new
            self._history.pop(address, None)

            for tx_hash in transactions_to_remove:
                self.remove_transaction(tx_hash)
                self.tx_fees.pop(tx_hash, None)
                self.verified_tx.pop(tx_hash, None)
                self.unverified_tx.pop(tx_hash, None)
                self.transactions.pop(tx_hash, None)
                self.ct_txi.pop(tx_hash, None)
                self.ct_txo.pop(tx_hash, None)
                self._addr_bal_cache.pop(address, None)  # not strictly necessary, above calls also have this side-effect. but here to be safe. :)
                if self.verifier:
                    # TX is now gone. Toss its SPV proof in case we have it
                    # in memory. This allows user to re-add PK again and it
                    # will avoid the situation where the UI says "not verified"
                    # erroneously!
                    self.verifier.remove_spv_proof_for_tx(tx_hash)
                # Remove also from pruned_txo
                if tx_hash in self.pruned_txo_values:
                    self.pruned_txo_values.discard(tx_hash)
                    to_pop = []
                    for key, th in self.pruned_txo.items():
                        if tx_hash == th:
                            to_pop.append(key)
                    for key in to_pop:
                        self.pruned_txo.pop(key, None)

            self.storage.put('verified_tx3', self.verified_tx)

        self.save_transactions()

        self.set_label(address, None)
        self.remove_payment_request(address, {})
        self.set_frozen_state([address], False)
        self.delete_address_derived(address)  # Assumption: derived class implements this
        self.invalidate_address_set_cache()

        self.cashacct.on_address_deletion(address)
        self.cashacct.save()

        self.save_addresses()
        self.storage.write()  # no-op if above already wrote


class ImportedAddressWallet(ImportedWalletBase):
    """ Watch-only wallet of imported addresses """

    wallet_type = 'imported_addr'

    def __init__(self, storage):
        self._sorted = None
        super().__init__(storage)

    @classmethod
    def from_text(cls, storage, text):
        wallet = cls(storage)
        for address in text.split():
            wallet.import_address(Address.from_string(address))
        return wallet

    def is_watching_only(self):
        return True

    def get_keystores(self):
        return []

    def can_import_privkey(self):
        return False

    def load_keystore(self):
        self.keystore = None

    def save_keystore(self):
        pass

    def load_addresses(self):
        addresses = self.storage.get('addresses', [])
        self.addresses = [Address.from_string(addr) for addr in addresses]

    def save_addresses(self):
        self.storage.put('addresses', [addr.to_storage_string()
                                       for addr in self.addresses])
        self.storage.write()

    def can_change_password(self):
        return False

    def can_import_address(self):
        return True

    def get_addresses(self):
        if not self._sorted:
            self._sorted = sorted(self.addresses,
                                  key=lambda addr: addr.to_ui_string())
        return self._sorted

    def import_address(self, address):
        assert isinstance(address, Address)
        if address in self.addresses:
            return False
        self.addresses.append(address)
        self.add_address(address)
        self.cashacct.save()
        self.save_addresses()
        self.storage.write()  # no-op if already wrote in previous call
        self._sorted = None
        return True

    def delete_address_derived(self, address):
        self.addresses.remove(address)
        self._sorted.remove(address)

    def add_input_sig_info(self, txin, address):
        x_pubkey = 'fd' + address.to_script_hex()
        txin['x_pubkeys'] = [x_pubkey]
        txin['signatures'] = [None]


class ImportedPrivkeyWallet(ImportedWalletBase):
    """ wallet made of imported private keys """

    wallet_type = 'imported_privkey'

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)

    @classmethod
    def from_text(cls, storage, text, password=None):
        wallet = cls(storage)
        storage.put('use_encryption', bool(password))
        for privkey in text.split():
            wallet.import_private_key(privkey, password)
        return wallet

    def is_watching_only(self):
        return False

    def get_keystores(self):
        return [self.keystore]

    def can_import_privkey(self):
        return True

    def load_keystore(self):
        if self.storage.get('keystore'):
            self.keystore = load_keystore(self.storage, 'keystore')
        else:
            self.keystore = Imported_KeyStore({})

    def save_keystore(self):
        self.storage.put('keystore', self.keystore.dump())

    def load_addresses(self):
        pass

    def save_addresses(self):
        pass

    def can_change_password(self):
        return True

    def can_import_address(self):
        return False

    def get_addresses(self):
        return self.keystore.get_addresses()

    def delete_address_derived(self, address):
        self.keystore.remove_address(address)
        self.save_keystore()

    def get_address_index(self, address):
        return self.get_public_key(address)

    def get_public_key(self, address):
        return self.keystore.address_to_pubkey(address)

    def import_private_key(self, sec, pw):
        pubkey = self.keystore.import_privkey(sec, pw)
        self.save_keystore()
        self.add_address(pubkey.address)
        self.cashacct.save()
        self.save_addresses()
        self.storage.write()  # no-op if above already wrote
        return pubkey.address.to_ui_string()

    def export_private_key(self, address, password):
        """Returned in WIF format."""
        pubkey = self.keystore.address_to_pubkey(address)
        return self.keystore.export_private_key(pubkey, password)

    def add_input_sig_info(self, txin, address):
        assert txin['type'] == 'p2pkh'
        pubkey = self.keystore.address_to_pubkey(address)
        txin['num_sig'] = 1
        txin['x_pubkeys'] = [pubkey.to_ui_string()]
        txin['signatures'] = [None]

    def pubkeys_to_address(self, pubkey):
        pubkey = PublicKey.from_string(pubkey)
        if pubkey in self.keystore.keypairs:
            return pubkey.address


class RpaWallet(ImportedWalletBase):
    """ RPA wallet made of imported private keys  """

    wallet_type = 'rpa'
    txin_type = 'p2pkh'
    rpa_pwd = None

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)
        self.seed_ts = storage.get('seed_ts')  # The timestamp the seed was created, if known (for default rpa_height)
        self.keystore_rpa_aux = None
        self.rpa_payload = None

    @property
    def rpa_height(self) -> int:
        height = self.storage.get('rpa_height')
        if height is not None:
            # we had a stored height to resume from
            return height
        else:
            # we lack a stored height, use the seed_ts, if known, as a heuristic to start off from
            if self.seed_ts is not None:
                args = self.seed_ts,
            else:
                args = ()  # just use default which ends up being some height circa Dec 2023
            return rpa.determine_best_rpa_start_height(*args)

    @rpa_height.setter
    def rpa_height(self, value: int):
        self.storage.put('rpa_height', value)

    @classmethod
    def from_text(cls, storage, text, password=None):
        wallet = cls(storage)
        storage.put('use_encryption', bool(password))
        for privkey in text.split():
            wallet.import_private_key(privkey, password)
        return wallet

    def is_watching_only(self):
        return False

    def get_keystores(self):
        return [self.keystore]

    def get_keystore_rpa_aux(self):
        return self.keystore_rpa_aux

    def can_import_privkey(self):
        return True

    def has_seed(self):
        return self.keystore_rpa_aux.has_seed()

    def get_seed(self, password):
        return self.keystore_rpa_aux.get_seed(password)

    def load_keystore_rpa_aux(self):
        if self.storage.get('keystore_rpa_aux'):
            self.keystore_rpa_aux = load_keystore(
                self.storage, 'keystore_rpa_aux')

    def load_keystore(self):
        self.load_keystore_rpa_aux()
        if self.storage.get('keystore'):
            self.keystore = load_keystore(self.storage, 'keystore')
        else:
            self.keystore = Imported_KeyStore({})

    def save_keystore(self):
        self.storage.put('keystore', self.keystore.dump())

    def check_password(self, password):
        self.keystore_rpa_aux.check_password(password)

    def save_keystore_rpa_aux(self):
        self.storage.put('keystore_rpa_aux', self.keystore_rpa_aux.dump())

    def load_addresses(self):
        pass

    def save_addresses(self):
        pass

    def update_password(self, old_pw, new_pw, encrypt=False):
        if old_pw is None and self.has_password():
            raise InvalidPassword()

        if self.keystore is not None and len(self.keystore.keypairs) > 0 and self.keystore.can_change_password():
            self.keystore.update_password(old_pw,new_pw)
            self.save_keystore()
        if self.keystore_rpa_aux is not None and self.keystore_rpa_aux.can_change_password():
            self.keystore_rpa_aux.update_password(old_pw, new_pw)
            self.save_keystore_rpa_aux()
        self.storage.set_password(new_pw, encrypt)
        self.storage.write()
        self.rpa_pwd = new_pw

    def can_change_password(self):
        return True

    def can_import_address(self):
        return False

    def get_addresses(self):
        return self.keystore.get_addresses()

    def delete_address_derived(self, address):
        self.keystore.remove_address(address)
        self.save_keystore()

    def get_address_index(self, address):
        return self.get_public_key(address)

    def get_public_key(self, address):
        return self.keystore.address_to_pubkey(address)

    def import_private_key(self, sec, pw):
        pubkey = self.keystore.import_privkey(sec, pw)
        self.save_keystore()
        self.add_address(pubkey.address)
        self.cashacct.save()
        self.save_addresses()
        self.storage.write()  # no-op if above already wrote
        return pubkey.address.to_ui_string()

    def export_private_key(self, address, password):
        '''Returned in WIF format.'''
        pubkey = self.keystore.address_to_pubkey(address)
        return self.keystore.export_private_key(pubkey, password)

    def export_private_key_from_index(self, index, password):
        # returns a private from the HD (rpa auxilliary) keystore based on the index
        # The index is a tuple consisting of Change (boolean) and Address number.
        # for example (False,0) is the first receiving address.
        pk, compressed = self.keystore_rpa_aux.get_private_key(index, password)
        return bitcoin.serialize_privkey(pk, compressed, self.txin_type)

    def add_input_sig_info(self, txin, address):
        assert txin['type'] == 'p2pkh'
        pubkey = self.keystore.address_to_pubkey(address)
        txin['num_sig'] = 1
        txin['x_pubkeys'] = [pubkey.to_ui_string()]
        txin['signatures'] = [None]

    def pubkeys_to_address(self, pubkey):
        pubkey = PublicKey.from_string(pubkey)
        if pubkey in self.keystore.keypairs:
            return pubkey.address

    def derive_pubkeys(self, c, i):
        if not self.keystore_rpa_aux:
            self.load_keystore_rpa_aux()
        k = self.get_keystore_rpa_aux()
        return k.derive_pubkey(c, i)

    def dummy_address(self):
        pubkey = self.derive_pubkeys(0, 0)
        dummy_address = Address.from_pubkey(pubkey)
        return dummy_address

    def get_grind_string(self):
        rpa_grind_string = rpa.get_grind_string(self)
        return rpa_grind_string

    def get_receiving_paycode(self):
        return rpa.generate_paycode(self, prefix_size="10")

    def extract_private_keys_from_transaction(self, rawtx, password):
        return rpa.extract_private_keys_from_transaction(self, rawtx, password)

    def rebuild_history(self):
        self.storage.put('rpa_height', rpa.determine_best_rpa_start_height())
        super(RpaWallet, self).rebuild_history()


class Deterministic_Wallet(Abstract_Wallet):

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)
        self.gap_limit = storage.get('gap_limit', 20)

    def has_seed(self):
        return self.keystore.has_seed()

    def get_receiving_addresses(self):
        return self.receiving_addresses

    def get_change_addresses(self):
        return self.change_addresses

    def get_seed(self, password):
        return self.keystore.get_seed(password)

    def add_seed(self, seed, pw):
        self.keystore.add_seed(seed, pw)

    def can_delete_keystore(self):
        """Reimplemented in MultiXPubWallet"""
        return False

    def can_add_keystore(self):
        """Reimplemented in MultiXPubWallet"""
        return False

    def change_gap_limit(self, value):
        '''This method is not called in the code, it is kept for console use'''
        with self.lock:
            if value >= self.gap_limit:
                self.gap_limit = value
                self.storage.put('gap_limit', self.gap_limit)
                return True
            elif value >= self.min_acceptable_gap():
                addresses = self.get_receiving_addresses()
                k = self.num_unused_trailing_addresses(addresses)
                n = len(addresses) - k + value
                self.receiving_addresses = self.receiving_addresses[0:n]
                self.gap_limit = value
                self.storage.put('gap_limit', self.gap_limit)
                self.save_addresses()
                return True
            else:
                return False

    def num_unused_trailing_addresses(self, addresses):
        '''This method isn't called anywhere. Perhaps it is here for console use.
        Can't be sure. -Calin '''
        with self.lock:
            k = 0
            for addr in reversed(addresses):
                if addr in self._history:
                    break
                k = k + 1
            return k

    def min_acceptable_gap(self):
        ''' Caller needs to hold self.lock otherwise bad things may happen. '''
        # fixme: this assumes wallet is synchronized
        n = 0
        nmax = 0
        addresses = self.get_receiving_addresses()
        k = self.num_unused_trailing_addresses(addresses)
        for a in addresses[0:-k]:
            if a in self._history:
                n = 0
            else:
                n += 1
                if n > nmax: nmax = n
        return nmax + 1

    def create_new_address(self, for_change=False, save=True):
        for_change = bool(for_change)
        with self.lock:
            addr_list = self.change_addresses if for_change else self.receiving_addresses
            n = len(addr_list)
            x = self.derive_pubkeys(for_change, n)
            address = self.pubkeys_to_address(x)
            addr_list.append(address)
            if save:
                self.save_addresses()
            self.add_address(address, for_change=for_change)
            return address

    def create_new_preferred_address(self, for_change=False, save=True):
        """Default just calls create_new_address(). MultiXPubWallet reimplements this to keep generating
        until it gets a preferred address."""
        return self.create_new_address(for_change=for_change, save=save)

    def synchronize_sequence(self, for_change):
        limit = self.gap_limit_for_change if for_change else self.gap_limit
        while True:
            addresses = self.get_change_addresses() if for_change else self.get_receiving_addresses()
            if len(addresses) < limit:
                self.create_new_address(for_change, save=False)
                continue
            if all(map(lambda a: not self.address_is_old(a), addresses[-limit:] )):
                break
            else:
                self.create_new_address(for_change, save=False)

    def synchronize(self):
        with self.lock:
            self.synchronize_sequence(False)
            self.synchronize_sequence(True)

    def is_beyond_limit(self, address, is_change):
        with self.lock:
            if is_change:
                addr_list = self.get_change_addresses()
                limit = self.gap_limit_for_change
            else:
                addr_list = self.get_receiving_addresses()
                limit = self.gap_limit
            idx = addr_list.index(address)
            if idx < limit:
                return False
            for addr in addr_list[-limit:]:
                if addr in self._history:
                    return False
            return True

    def get_master_public_keys(self):
        return [self.get_master_public_key()]

    def get_fingerprint(self):
        return self.get_master_public_key()

    def get_txin_type(self, address):
        return self.txin_type


class Simple_Deterministic_Wallet(Simple_Wallet, Deterministic_Wallet):

    """ Deterministic Wallet with a single pubkey per address """

    def __init__(self, storage):
        Deterministic_Wallet.__init__(self, storage)

    def get_public_key(self, address):
        sequence = self.get_address_index(address)
        pubkey = self.get_pubkey(*sequence)
        return pubkey

    def load_keystore(self):
        self.keystore = load_keystore(self.storage, 'keystore')
        try:
            xtype = bitcoin.xpub_type(self.keystore.xpub)
        except:
            xtype = 'standard'
        self.txin_type = 'p2pkh' if xtype == 'standard' else xtype

    def get_pubkey(self, c, i):
        return self.derive_pubkeys(c, i)

    def get_public_keys(self, address):
        return [self.get_public_key(address)]

    def add_input_sig_info(self, txin, address):
        derivation = self.get_address_index(address)
        x_pubkey = self.keystore.get_xpubkey(*derivation)
        txin['x_pubkeys'] = [x_pubkey]
        txin['signatures'] = [None]
        txin['num_sig'] = 1

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def derive_pubkeys(self, c, i):
        return self.keystore.derive_pubkey(c, i)


class Standard_Wallet(Simple_Deterministic_Wallet):
    wallet_type = 'standard'

    def pubkeys_to_address(self, pubkey):
        return Address.from_pubkey(pubkey)


class Multisig_Wallet(Deterministic_Wallet):
    """ generic m of n """
    gap_limit = 20

    def __init__(self, storage):
        self.wallet_type = storage.get('wallet_type')
        self.m, self.n = multisig_type(self.wallet_type)
        Deterministic_Wallet.__init__(self, storage)

    def get_pubkeys(self, c, i):
        return self.derive_pubkeys(c, i)

    def pubkeys_to_address(self, pubkeys):
        pubkeys = [bytes.fromhex(pubkey) for pubkey in pubkeys]
        redeem_script = self.pubkeys_to_redeem_script(pubkeys)
        return Address.from_multisig_script(redeem_script)

    def pubkeys_to_redeem_script(self, pubkeys):
        return Script.multisig_script(self.m, sorted(pubkeys))

    def derive_pubkeys(self, c, i):
        return [k.derive_pubkey(c, i) for k in self.get_keystores()]

    def load_keystore(self):
        self.keystores = {}
        for i in range(self.n):
            name = 'x%d/'%(i+1)
            self.keystores[name] = load_keystore(self.storage, name)
        self.keystore = self.keystores['x1/']
        xtype = bitcoin.xpub_type(self.keystore.xpub)
        self.txin_type = 'p2sh' if xtype == 'standard' else xtype

    def save_keystore(self):
        for name, k in self.keystores.items():
            self.storage.put(name, k.dump())

    def get_keystore(self):
        return self.keystores.get('x1/')

    def get_keystores(self):
        return [self.keystores[i] for i in sorted(self.keystores.keys())]

    def update_password(self, old_pw, new_pw, encrypt=False):
        if old_pw is None and self.has_password():
            raise InvalidPassword()
        for name, keystore in self.keystores.items():
            if keystore.can_change_password():
                keystore.update_password(old_pw, new_pw)
                self.storage.put(name, keystore.dump())
        self.storage.set_password(new_pw, encrypt)
        self.storage.write()

    def has_seed(self):
        return self.keystore.has_seed()

    def can_change_password(self):
        return self.keystore.can_change_password()

    def is_watching_only(self):
        return not any([not k.is_watching_only() for k in self.get_keystores()])

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def get_master_public_keys(self):
        return [k.get_master_public_key() for k in self.get_keystores()]

    def get_fingerprint(self):
        return ''.join(sorted(self.get_master_public_keys()))

    def add_input_sig_info(self, txin, address):
        # x_pubkeys are not sorted here because it would be too slow
        # they are sorted in transaction.get_sorted_pubkeys
        derivation = self.get_address_index(address)
        txin['x_pubkeys'] = [k.get_xpubkey(*derivation) for k in self.get_keystores()]
        txin['pubkeys'] = None
        # we need n place holders
        txin['signatures'] = [None] * self.n
        txin['num_sig'] = self.m

    def is_multisig(self):
        return True


class PrivateKeyMissing(RuntimeError):
    """Only ever raised by MultiXPubWallet below if calling code attempts to retrieve a private key
    for an address for which the wallet lacks the xprv."""


class MultiXPubWallet(Deterministic_Wallet):
    """ P2PKH "aggregate" wallet. A deterministic wallet which combines multiple xpubs into one view.
    The addresses are interleaved modulo len(self.keystores). """

    txin_type = 'p2pkh'
    wallet_type = 'multi_xpub'

    def __init__(self, storage):
        Deterministic_Wallet.__init__(self, storage)
        # Scale gap limit to catch everything from all sub-xpubs
        prev_gap_limit = self.gap_limit
        self.gap_limit = max(self.gap_limit, 20 * len(self.keystores))
        self.gap_limit_for_change = max(self.gap_limit_for_change, self.gap_limit)
        if self.gap_limit != prev_gap_limit:
            self.storage.put("gap_limit", self.gap_limit)

    class _KeyStoreFacade:
        """This class is used as a facade to catch calls to wallet.keystore by code in the app
        and forward and/or translate the call appropriately so that things work as expected."""
        def __init__(self, parent):
            self.parent = parent

        def is_deterministic(self):
            return self.parent.is_deterministic()

        def get_private_key(self, sequence, password):
            for_change, index = sequence
            ks, real_index = self.parent._map_address_index(index)
            if ks.is_watching_only():
                raise PrivateKeyMissing(_("This address is watching-only"))
            return ks.get_private_key((for_change, real_index), password)

        def check_password(self, password):
            for ks in self.parent.get_keystores():
                if ks.may_have_password():
                    ks.check_password(password)

        def sign_message(self, sequence, message, password):
            for_change, index = sequence
            ks, real_index = self.parent._map_address_index(index)
            if ks.is_watching_only():
                raise PrivateKeyMissing(_("This address is watching-only"))
            return ks.sign_message((for_change, real_index), message, password)

        def decrypt_message(self, sequence, message, password):
            for_change, index = sequence
            ks, real_index = self.parent._map_address_index(index)
            return ks.decrypt_message((for_change, real_index), message, password)

        def get_pubkey_derivation(self, x_pubkey):
            for which_ks, ks in enumerate(self.parent.get_keystores()):
                derivation = ks.get_pubkey_derivation(x_pubkey)
                if derivation:
                    for_change, real_index = derivation
                    index = self.parent._unmap_address_index(which_ks, real_index)
                    return for_change, index

    def get_keystore(self):
        return self._KeyStoreFacade(self)

    @property
    def keystore(self):
        return self.get_keystore()

    def get_keystores(self):
        return self.keystores

    def _delete_add_keystore_common(self):
        # Assumption: self.lock is held by caller
        saved_gap_limit = self.gap_limit
        saved_gap_limit_for_change = self.gap_limit_for_change
        self.gap_limit = max(self.gap_limit, 20 * len(self.keystores))
        self.gap_limit_for_change = max(self.gap_limit_for_change, self.gap_limit)
        self.storage.put("gap_limit", self.gap_limit)
        self.save_keystore()
        self.change_reserved.clear()
        self.change_reserved_default.clear()
        self.change_unreserved.clear()
        self.change_reserved_tmp.clear()
        # delete every address and regen
        del self.receiving_addresses[:]
        del self.change_addresses[:]
        while len(self.receiving_addresses) < saved_gap_limit:
            self.create_new_address(for_change=False, save=False)
        while len(self.change_addresses) < saved_gap_limit_for_change:
            self.create_new_address(for_change=True, save=False)
        self.invalidate_address_set_cache()
        self.save_addresses()

    def can_delete_keystore(self):
        return len(self.keystores) > 1

    def can_add_keystore(self):
        return True

    def delete_keystore(self, index, rebuild_history=True):
        """Note that removing a keystore really should involve full wallet history rebuild via self.rebuild_history()
        due to all the invariants that are now potentially violated by this operation."""
        n_ks = len(self.keystores)
        if index < 0 or index >= n_ks or n_ks == 1:
            raise ValueError(_('Cannot delete keystore at index {index}').format(index=index))
        with self.lock:
            del self.keystores[index]
            self._delete_add_keystore_common()
        if rebuild_history:
            self.rebuild_history()

    def add_keystore(self, master_key, rebuild_history=True):
        """Note that adding a keystore really should involve full wallet history rebuild via self.rebuild_history()
        due to all the invariants that are now potentially violated by this operation."""
        assert keystore.is_master_key(master_key)
        ks = keystore.from_master_key(master_key)
        if any(ks.get_master_public_key() == k.get_master_public_key() for k in self.keystores):
            raise ValueError(_('XPub already exists in wallet') + f":\n{str(master_key)}")
        with self.lock:
            self.keystores.append(ks)
            self._delete_add_keystore_common()
        if rebuild_history:
            self.rebuild_history()

    def is_watching_only(self):
        return all(k.is_watching_only() for k in self.get_keystores())

    def get_preferred_receiving_addresses(self):
        return self._get_preferred_addresses(False)

    def get_preferred_change_addresses(self):
        return self._get_preferred_addresses(True)

    @property
    def _signing_xpubs(self) -> Set[str]:
        return {k.get_master_public_key() for k in self.get_keystores() if not k.is_watching_only()}

    def _get_preferred_addresses(self, for_change):
        signing_xpubs = self._signing_xpubs
        domain = self.get_change_addresses() if for_change else self.get_receiving_addresses()
        if not signing_xpubs or len(signing_xpubs) >= len(self.get_keystores()):
            # We can't sign, or we can sign all, so we prefer nothing in particular, return all addresses
            return domain
        # Remove addresses we can't sign for and return the rest, since we "prefer" those
        ret = []
        for i, addr in enumerate(domain):
            ks, _ = self._map_address_index(i)
            if ks.get_master_public_key() in signing_xpubs:
                ret.append(addr)
        return ret or domain  # If ret empty, fallback to full set of addresses

    def create_new_preferred_address(self, for_change=False, save=True):
        signing_xpubs = self._signing_xpubs
        if not signing_xpubs or len(signing_xpubs) >= len(self.get_keystores()):
            # Can't sign, or all xpubs can sign, so just take normal path
            return self.create_new_address(for_change=for_change, save=save)
        # Keep looping until we get a new address we can sign for
        while True:
            address = self.create_new_address(for_change=for_change, save=save)
            c, index = self.get_address_index(address)
            assert bool(c) == bool(for_change)
            ks, _ = self._map_address_index(index)
            if ks.get_master_public_key() in signing_xpubs:
                return address

    def can_change_password(self):
        return any(k.can_change_password() for k in self.get_keystores())

    def update_password(self, old_pw, new_pw, encrypt=False):
        if old_pw is None and self.has_password():
            raise InvalidPassword()
        for k in self.get_keystores():
            if k is not None and k.can_change_password():
                k.update_password(old_pw, new_pw)
        self.save_keystore()
        self.storage.set_password(new_pw, encrypt)
        self.storage.write()

    def load_keystore(self):
        l = self.storage.get("keystores")
        assert l and isinstance(l, list)
        self.keystores = []
        for d in l:
            assert isinstance(d, dict)
            k = load_keystore({"dummy": d}, "dummy")
            assert k.is_deterministic(), "This class only supports deterministic wallets"
            self.keystores.append(k)

    def save_keystore(self):
        self.storage.put('keystores', [k.dump() for k in self.get_keystores()])

    def has_seed(self):
        return False

    def get_seed(self, password):
        return None

    def add_seed(self, seed, pw):
        pass

    def is_deterministic(self):
        return all(k.is_deterministic() for k in self.keystores)

    def get_public_key(self, address):
        sequence = self.get_address_index(address)
        pubkey = self.get_pubkey(*sequence)
        return pubkey

    def get_pubkey(self, c, i):
        return self.derive_pubkeys(c, i)

    def get_public_keys(self, address):
        return [self.get_public_key(address)]

    def _map_address_index(self, index):
        n_ks = len(self.keystores)
        which_ks = index % n_ks
        real_index = index // n_ks
        return self.keystores[which_ks], real_index

    def _unmap_address_index(self, ks: Union[object, int], real_index):
        n_ks = len(self.keystores)
        which_ks = ks if isinstance(ks, int) else self.keystores.index(ks)
        index = real_index * n_ks + which_ks
        return index

    def add_input_sig_info(self, txin, address):
        is_change, index = self.get_address_index(address)
        keystore, real_index = self._map_address_index(index)
        x_pubkey = keystore.get_xpubkey(is_change, real_index)
        txin['x_pubkeys'] = [x_pubkey]
        txin['signatures'] = [None]
        txin['num_sig'] = 1

    def get_master_public_keys(self):
        return [k.get_master_public_key() for k in self.keystores]

    def get_fingerprint(self):
        return ''.join(sorted(self.get_master_public_keys()))

    def derive_pubkeys(self, c, i):
        keystore, real_index = self._map_address_index(i)
        return keystore.derive_pubkey(c, real_index)

    @staticmethod
    def pubkeys_to_address(pubkey):
        return Address.from_pubkey(pubkey)


wallet_types = ['standard', 'multisig', 'imported', 'rpa', 'multi_xpub']


def register_wallet_type(category):
    wallet_types.append(category)


wallet_constructors = {
    'standard': Standard_Wallet,
    'old': Standard_Wallet,
    'xpub': Standard_Wallet,
    'imported_privkey': ImportedPrivkeyWallet,
    'imported_addr': ImportedAddressWallet,
    'rpa': RpaWallet,
    'multi_xpub': MultiXPubWallet,
}


def register_constructor(wallet_type, constructor):
    wallet_constructors[wallet_type] = constructor


class UnknownWalletType(RuntimeError):
    """ Raised if encountering an unknown wallet type """
    pass


class Wallet:
    """The main wallet "entry point".
    This class is actually a factory that will return a wallet of the correct
    type when passed a WalletStorage instance."""

    def __new__(self, storage):
        wallet_type = storage.get('wallet_type')
        WalletClass = Wallet.wallet_class(wallet_type)
        wallet = WalletClass(storage)
        # Convert hardware wallets restored with older versions of
        # Electrum to BIP44 wallets.  A hardware wallet does not have
        # a seed and plugins do not need to handle having one.
        rwc = getattr(wallet, 'restore_wallet_class', None)
        if rwc and storage.get('seed', ''):
            storage.print_error("converting wallet type to " + rwc.wallet_type)
            storage.put('wallet_type', rwc.wallet_type)
            wallet = rwc(storage)
        return wallet

    @staticmethod
    def wallet_class(wallet_type):
        if multisig_type(wallet_type):
            return Multisig_Wallet
        if wallet_type in wallet_constructors:
            return wallet_constructors[wallet_type]
        raise UnknownWalletType("Unknown wallet type: " + str(wallet_type))


def create_new_wallet(*, path, config, passphrase=None, password=None,
                      encrypt_file=True, seed_type=None, gap_limit=None) -> dict:
    """Create a new wallet"""
    storage = WalletStorage(path, in_memory_only=path is None)
    if path is not None and storage.file_exists():
        raise Exception("Remove the existing wallet first!")

    from .mnemonic import Mnemonic_Electrum, Mnemonic
    if seed_type == 'electrum':
        seed = Mnemonic_Electrum('en').make_seed()
    else:
        seed = Mnemonic('en').make_seed()
    k = keystore.from_seed(seed, passphrase, seed_type = seed_type)
    storage.put('keystore', k.dump())
    storage.put('wallet_type', 'standard')
    storage.put('seed_type', seed_type)
    if gap_limit is not None:
        storage.put('gap_limit', gap_limit)
    wallet = Wallet(storage)
    wallet.update_password(old_pw=None, new_pw=password, encrypt=encrypt_file)
    wallet.synchronize()
    msg = "Please keep your seed in a safe place; if you lose it, you will not be able to restore your wallet."

    wallet.storage.write()
    return {'seed': seed, 'wallet': wallet, 'msg': msg}


def restore_wallet_from_text(text, *, path, config,
                             passphrase=None, password=None, encrypt_file=True,
                             gap_limit=None) -> dict:
    """Restore a wallet from text. Text can be a seed phrase, a master
    public key, a master private key, a list of bitcoin addresses
    or bitcoin private keys."""
    storage = WalletStorage(path, in_memory_only=path is None)
    if path is not None and storage.file_exists():
        raise Exception("Remove the existing wallet first!")

    text = text.strip()
    if keystore.is_address_list(text):
        wallet = ImportedAddressWallet.from_text(storage, text)
        wallet.save_addresses()
    elif keystore.is_private_key_list(text,):
        k = keystore.Imported_KeyStore({})
        storage.put('keystore', k.dump())
        wallet = ImportedPrivkeyWallet.from_text(storage, text, password)
    else:
        if keystore.is_master_key(text):
            k = keystore.from_master_key(text)
        elif keystore.is_seed(text):
            k = keystore.from_seed(text, passphrase)  # auto-detects seed type, preference order: old, electrum, bip39
        else:
            raise Exception("Seed or key not recognized")
        storage.put('keystore', k.dump())
        storage.put('wallet_type', 'standard')
        seed_type = getattr(k, 'seed_type', None)
        if seed_type:
            storage.put('seed_type', seed_type)  # Save, just in case
        if gap_limit is not None:
            storage.put('gap_limit', gap_limit)
        wallet = Wallet(storage)

    wallet.update_password(old_pw=None, new_pw=password, encrypt=encrypt_file)
    wallet.synchronize()
    msg = ("This wallet was restored offline. It may contain more addresses than displayed. "
           "Start a daemon and use load_wallet to sync its history.")

    wallet.storage.write()
    return {'wallet': wallet, 'msg': msg}

