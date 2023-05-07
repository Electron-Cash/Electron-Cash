#!/usr/bin/env python3
#
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2022 The Electron Cash Developers
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

from enum import IntEnum
from typing import Optional

from PyQt5 import QtCore
from PyQt5.QtGui import QBrush, QColor, QIcon, QFont
from PyQt5.QtWidgets import QMenu, QHeaderView

from electroncash import token
from electroncash.i18n import _
from electroncash.util import profiler

from .util import MONOSPACE_FONT, MyTreeWidget, rate_limited, SortableTreeWidgetItem


class TokenHistoryList(MyTreeWidget):

    class Col(IntEnum):
        """Column numbers. This is to make code in on_update easier to read.
        If you modify these, make sure to modify the column header names in
        the MyTreeWidget constructor."""
        status = 1
        date = 2
        description = 3
        category_id = 4
        fungible_amount = 5
        nft_amount = 6

    class DataRoles(IntEnum):
        """Data roles. Again, to make code in on_update easier to read."""
        status = QtCore.Qt.UserRole + 1
        tx_hash = QtCore.Qt.UserRole + 2
        category = QtCore.Qt.UserRole + 3
        commitment = QtCore.Qt.UserRole + 4
        capability = QtCore.Qt.UserRole + 5

    statusIcons = {}

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [], self.Col.description, deferred_updates=True)

        headers = ['', '', _('Date'), _('Description'), _('Category ID'), _('Fungible Amount'), _('NFT Amount')]
        self.update_headers(headers)
        self.setColumnHidden(1, True)
        self.setSortingEnabled(True)
        self.sortByColumn(0, QtCore.Qt.AscendingOrder)
        self.wallet = self.parent.wallet
        self.cleaned_up = False
        self.monospaceFont = QFont(MONOSPACE_FONT)
        self.withdrawalBrush = QBrush(QColor("#BC1E1E"))
        self.batonIcon = QIcon(":icons/seal")
        self.setTextElideMode(QtCore.Qt.ElideMiddle)
        self.header().setSectionResizeMode(self.Col.category_id, QHeaderView.Interactive)
        self.header().resizeSection(self.Col.category_id, 120)

    def clean_up(self):
        self.cleaned_up = True

    @rate_limited(1.0, classlevel=True, ts_after=True)
    def update(self):
        if self.cleaned_up:
            # short-cut return if window was closed and wallet is stopped
            return
        super().update()

    @profiler
    def on_update(self):
        self.clear()
        h = self.wallet.get_history(self.wallet.get_addresses(), reverse=True, receives_before_sends=True)

        for h_item in h:
            tx_hash, height, conf, timestamp, value, balance = h_item
            label = self.wallet.get_label(tx_hash)
            status, status_str = self.wallet.get_tx_status(tx_hash, height, conf, timestamp)
            icon = self.parent.history_list.get_icon_for_status(status)

            tokens_delta = self.wallet.get_wallet_tokens_delta(self.wallet.transactions.get(tx_hash))
            for category_id, category_delta in tokens_delta.items():
                fungible_amount = category_delta["fungibles"]
                nft_amount = len(category_delta["nfts_in"]) - len(category_delta["nfts_out"])
                entry = ['', tx_hash, status_str, label, category_id, str(fungible_amount), str(nft_amount)]
                item = SortableTreeWidgetItem(entry)
                item.setData(0, self.DataRoles.status, (status, conf))
                item.setData(0, self.DataRoles.tx_hash, tx_hash)
                item.setData(0, self.DataRoles.category, category_id)
                item.setToolTip(self.Col.category_id, category_id)
                if icon:
                    item.setIcon(0, icon)
                item.setToolTip(0, str(conf) + " confirmation" + ("s" if conf != 1 else ""))
                for col in (self.Col.category_id, self.Col.fungible_amount, self.Col.nft_amount):
                    item.setTextAlignment(col, QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
                    item.setFont(col, self.monospaceFont)
                item.setFont(self.Col.date, self.monospaceFont)
                if fungible_amount < 0 or nft_amount < 0:
                    item.setForeground(self.Col.description, self.withdrawalBrush)
                    item.setForeground(self.Col.fungible_amount if fungible_amount < 0 else self.Col.nft_amount,
                                       self.withdrawalBrush)

                def get_nft_flag(td: token.OutputData) -> Optional[str]:
                    if td.is_minting_nft():
                        return _('Minting')
                    elif td.is_mutable_nft():
                        return _('Mutable')
                    elif td.is_immutable_nft():
                        return _('Immutable')

                def add_nft(nft, out=False):
                    commitment = nft.commitment.hex()
                    capability = get_nft_flag(nft)
                    direction = "-" if out else "+"
                    commitment_str = f": {commitment}" if commitment else ""
                    name = f"{direction} {capability} NFT{commitment_str}"
                    nft_item = SortableTreeWidgetItem(['', tx_hash, '', name, '', '', '', ''])
                    nft_item.setFont(self.Col.description, self.monospaceFont)
                    nft_item.setData(0, self.DataRoles.commitment, commitment)
                    nft_item.setData(0, self.DataRoles.capability, capability)
                    if out:
                        nft_item.setForeground(self.Col.description, self.withdrawalBrush)
                    if nft.is_minting_nft() or nft.is_mutable_nft():
                        item.setIcon(self.Col.description, self.batonIcon)
                        item.setToolTip(self.Col.description, _("Transaction involves a Minting or Mutable NFT"))
                    item.addChild(nft_item)

                for nft_in in category_delta["nfts_in"]:
                    add_nft(nft_in, False)
                for nft_out in category_delta["nfts_out"]:
                    add_nft(nft_out, True)

                self.addChild(item)

    def on_doubleclick(self, item, column):
        tx_id = item.data(0, self.DataRoles.tx_hash)
        tx = self.wallet.transactions.get(tx_id)
        if tx:
            self.parent.show_transaction(tx)

    def create_menu(self, position):
        menu = QMenu()

        selected = self.selectedItems()
        num_selected = len(selected)

        def do_copy(txt):
            txt = txt.strip()
            self.parent.copy_to_clipboard(txt)

        col = self.currentColumn()
        column_title = self.headerItem().text(col)

        if num_selected > 0:
            if num_selected == 1:
                item = self.itemAt(position)
                if item:
                    copy_text = item.text(col).strip()
                    capability = item.data(0, self.DataRoles.capability)
                    if capability:  # This is an NFT row
                        description = item.text(self.Col.description).strip()
                        commitment = item.data(0, self.DataRoles.commitment)
                        if description:
                            menu.addAction(_("Copy {}").format(_("NFT Description")), lambda: do_copy(description[2:]))
                        if commitment:
                            menu.addAction(_("Copy {}").format(_("NFT Commitment")), lambda: do_copy(commitment))
                    elif copy_text:
                        menu.addAction(_("Copy {}").format(column_title), lambda: do_copy(copy_text))

                    tx_hash = item.data(0, self.DataRoles.tx_hash)
                    tx = self.wallet.transactions.get(tx_hash, None)
                    if tx:
                        menu.addAction(_("Details"), lambda: self.parent.show_transaction(tx))

        menu.addSeparator()
        menu.addAction(QIcon(":icons/tab_token.svg"), _("Create Token..."), self.parent.show_create_new_token_dialog)
        menu.exec_(self.viewport().mapToGlobal(position))
