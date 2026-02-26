#!/usr/bin/env python3
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


import copy
import math
from collections import defaultdict
from itertools import count
from typing import DefaultDict, List, Dict
from enum import IntEnum

from PyQt5 import QtCore
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from .util import PrintError
from electroncash import wallet, address, token
from electroncash.i18n import _


# This class is inspired by SendTokenForm.
# Consider moving relevant methods from TokenSendUtil and SendTokenForm to wallet.py as they
# align with wallet functionality.
class TokenSendUtil(PrintError):

    def __init__(self, wallet, token_meta, config):
        self.wallet = wallet
        self.token_meta = token_meta
        self.config = config

    def get_wallet_tokens(self, exclude_frozen=True):
        tokens: DefaultDict[List[Dict]] = defaultdict(list)
        tokens_grouped: DefaultDict[DefaultDict[List[Dict]]] = defaultdict(lambda: defaultdict(list))

        token_utxos = self.wallet.get_utxos(exclude_frozen=exclude_frozen, tokens_only=True)

        # Setup data source; iterate over a sorted list of utxos
        def sort_func(u):
            td: token.OutputData = u['token_data']
            return td.id, td.commitment, td.bitfield & 0x0f, self.get_outpoint_longname(u)
        sorted_utxos = sorted(token_utxos, key=sort_func)

        for utxo in sorted_utxos:
            td = utxo['token_data']
            token_id = td.id_hex
            tokens[token_id].append(utxo)
            if not td.has_nft():
                tokens_grouped[token_id]['ft_only'].append(utxo)
            else:
                tokens_grouped[token_id][td.commitment.hex()].append(utxo)

        return tokens, tokens_grouped

    def get_wallet_fungible_only_tokens(self, exclude_frozen=True):
        tokens, tokens_grouped = self.get_wallet_tokens(exclude_frozen)

        for token_id in copy.deepcopy(tokens):
            if self.get_max_ft_token_amount_available(tokens, token_id) == 0:
                del tokens[token_id]
                del tokens_grouped[token_id]
        return tokens, tokens_grouped

    @staticmethod
    def get_max_ft_token_amount_available(tokens: DefaultDict[str, List[Dict]], category_id):
        token_utxos = tokens[category_id]
        total_amount = 0
        for utxo in token_utxos:
            total_amount += utxo['token_data'].amount
        return total_amount

    def get_ft_send_spec(self, addr, category_id, amount, tokens, send_satoshis=0, dummy=False):
        token_utxos = tokens[category_id]
        feerate = self.config.fee_per_kb()

        # Setup data source; iterate over a sorted list of utxos
        def sort_func(u):
            td: token.OutputData = u['token_data']
            return td.id, td.commitment, td.bitfield & 0x0f, self.get_outpoint_longname(u)

        sorted_utxos = sorted(token_utxos, key=sort_func)

        utxos_by_name = dict()
        for utxo in sorted_utxos:
            td: token.OutputData = utxo['token_data']
            assert isinstance(td, token.OutputData)
            tid = td.id_hex
            name = self.get_outpoint_longname(utxo)
            if name in utxos_by_name:
                # skip dupes
                assert utxos_by_name[name] == utxo
                continue
            utxos_by_name[name] = utxo

        spec = wallet.TokenSendSpec()
        if dummy:
            spec.payto_addr = self.wallet.dummy_address()
        else:
            spec.payto_addr = addr

        spec.change_addr = (self.wallet.get_unused_address(for_change=True, frozen_ok=False)
                            or self.wallet.dummy_address())
        spec.feerate = feerate
        if dummy:
            spec.send_satoshis = wallet.dust_threshold(self.wallet.network)
        else:
            spec.send_satoshis = send_satoshis
        spec.token_utxos = copy.deepcopy(utxos_by_name)
        spec.non_token_utxos = {self.get_outpoint_longname(x): x
                                for x in self.wallet.get_spendable_coins(None, self.config)}
        spec.send_fungible_amounts = {category_id: amount}

        # No NFTs!
        # Gather tx inputs
        # spec.send_nfts = set()
        # for tid, utxo_name_set in self.token_nfts_selected.items():
        #     spec.send_nfts |= utxo_name_set

        return spec

    @staticmethod
    def get_outpoint_longname(utxo) -> str:
        return f"{utxo['prevout_hash']}:{utxo['prevout_n']}"

    def estimate_max_bch_amount(self):
        # make a dummy token spec
        tokens, _ = self.get_wallet_fungible_only_tokens()
        dummy_tid = next(iter(tokens))
        dummy_amount = tokens[dummy_tid][0]['token_data'].amount
        spec = self.get_ft_send_spec(None, dummy_tid, dummy_amount, tokens, dummy=True)

        try:
            tx = self.wallet.make_token_send_tx(self.config, spec)
        except Exception as e:
            self.print_error("_estimate_max_bch_amount:", repr(e))
            raise e
        dust_regular = wallet.dust_threshold(self.wallet.network)
        dust_token = token.heuristic_dust_limit_for_token_bearing_output()
        # Consider all non-token non-dust utxos as potentially contributing to max_amount
        max_in = sum(x['value'] for x in spec.non_token_utxos.values() if x['value'] >= dust_regular)
        # Quirk: We don't choose token utxos for contributing to BCH amount unless the token was selected for
        # sending by the user in the UI. So only consider BCH amounts > 800 sats for tokens chosen for this tx
        # by the user's NFT/FT selections in the UI.
        max_in += sum(x['value'] - dust_token for x in tx.inputs() if x['token_data'] and x['value'] > dust_token)

        val_out_minus_change = 0
        for (_, addr, val), td in tx.outputs(tokens=True):
            if td or addr != spec.change_addr:
                val_out_minus_change += val
        bytes = tx.serialize_bytes(estimate_size=True)
        max_amount = max(0, max_in - val_out_minus_change - int(math.ceil(len(bytes)/1000 * spec.feerate)))
        return max_amount

    def check_sanity(self) -> bool:
        sane = True
        ft_total = sum(amt for amt in self.token_fungible_to_spend.values())
        num_nfts = sum(len(s) for s in self.token_nfts_selected.values())
        if max(ft_total, 0) + num_nfts + len(self.nfts_to_mint) <= 0:
            # No tokens specified!
            sane = False
        elif not address.Address.is_valid(self.te_payto.toPlainText().strip()):
            # Bad address
            sane = False
        if sane and self.form_mode == self.FormMode.edit:
            # Checks for edit mode only
            if any(c is None for c in self.nfts_to_edit.values()):
                # Bad NFT commitment specified
                sane = False
            else:
                # Ensure that at least one modified selection exists
                modct = 0
                for s in self.token_nfts_selected.values():
                    if modct:
                        break
                    for name in s:
                        if modct:
                            break
                        utxo = self.get_utxo(name)
                        td = utxo['token_data']
                        new_commitment = self.nfts_to_edit.get(name)
                        modct += new_commitment is not None and td.commitment != new_commitment
                if not modct:
                    # No modified selections exist, bail
                    sane = False
        if sane and self.form_mode == self.FormMode.mint:
            # Checks for mint mode only
            # Must have specified minting of at least 1 thing, and no NFT commitments that are malformed can exist
            sane = len(self.nfts_to_mint) and all(d.get("commitment") is not None for d in self.nfts_to_mint)
        return sane

    def on_preview_tx(self):
        # First, we must make sure that any amount line-edits have lost focus, so we can be 100% sure
        # "textEdited" signals propagate and what the user sees on-screen is what ends-up in the txn
        w = self.focusWidget()
        if w:
            w.clearFocus()
        # Check sanity just in case the above caused us to no longer be "sane"
        if not self.check_sanity():
            self.print_error("Spurious click of 'preview tx', returning early")
            return
        spec = self.make_token_send_spec()
        try:
            tx = self.wallet.make_token_send_tx(self.config, spec)
            if tx:
                self.parent.show_transaction(tx, tx_desc=self.te_desc.toPlainText().strip() or None,
                                             broadcast_callback=self.broadcast_callback)
            else:
                self.show_error("Unimplemented")
        except wallet.NotEnoughFunds as e:
            self.show_error(str(e) or _("Not enough funds"))
        except wallet.ExcessiveFee as e:
            self.show_error(str(e) or _("Excessive fee"))
        except wallet.TokensBurnedError as e:
            self.show_error(str(e) or _("Internal Error: Transaction generation yielded a transaction in which"
                                        " some tokens are being burned;  refusing to proceed. Please report this"
                                        " situation to the developers."))


class TokenSendComboBox(QComboBox):

    class DataRoles(IntEnum):
        token_id = QtCore.Qt.UserRole
        max_formated_token_amount_available = QtCore.Qt.UserRole + 1

    def __init__(self):
        QComboBox.__init__(self)

        self.add_empty_item()

    def add_empty_item(self):
        cashTokensIcon = QIcon(':icons/tab_token.svg')
        self.addItem(cashTokensIcon, _("None"), None)

    def fill_token_items(self, tokens: DefaultDict[str, List[Dict]],
                        tokens_grouped: DefaultDict[str, DefaultDict[str, List[Dict]]], token_meta):

        self.clear()

        self.add_empty_item()

        for token_id in tokens.keys():
            token_icon = token_meta.get_icon(token_id)
            token_display_name = token_meta.get_token_display_name(token_id) or token_id
            self.addItem(token_icon, token_display_name)

            max_token_amt = TokenSendUtil.get_max_ft_token_amount_available(tokens, token_id)
            max_token_amt_formated = token_meta.format_amount(token_id, max_token_amt)

            # Add item data
            index = self.count() - 1
            self.setItemData(index, token_id, self.DataRoles.token_id)
            self.setItemData(index, max_token_amt_formated, self.DataRoles.max_formated_token_amount_available)
