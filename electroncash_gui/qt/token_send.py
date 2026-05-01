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
from enum import IntEnum
from typing import Any, Callable, DefaultDict, Dict, List, Optional, Set

from PyQt5 import QtCore, QtGui, QtWidgets

from electroncash import address, networks, token, util, wallet
from electroncash.i18n import _
from .amountedit import BTCAmountEdit
from .fee_slider import FeeSlider
from .main_window import ElectrumWindow
from .qrtextedit import ScanQRTextEdit
from .token_meta import TokenMetaQt
from .util import ColorScheme, HelpLabel, OnDestroyedMixin, PrintError, WindowModalDialog


class SendTokenForm(WindowModalDialog, PrintError, OnDestroyedMixin):

    class ColsTok(IntEnum):
        category = 0
        nfts = 1
        amount = 2
        amount_send = 3

    class ColsNFT(IntEnum):
        selected = 0
        category = 1
        commitment = 2
        flags = 3

    class ColsBaton(IntEnum):
        icon = 0
        category = 1
        buttons = 2

    class ColsMint(IntEnum):
        category = 0
        commitment = 1
        capability = 2
        multiplier = 3

    class DataRoles(IntEnum):
        token_id = QtCore.Qt.UserRole
        output_point = QtCore.Qt.UserRole + 1
        receives_nft_count_updates = QtCore.Qt.UserRole + 2
        receives_nft_flag_updates = QtCore.Qt.UserRole + 3

    class FormMode(IntEnum):
        send = 0
        edit = 1
        mint = 2

    headers_tok = [_("Category"), _("NFTs to Send"), _("Fungible Amount"), _("Fungible Amount to Send")]
    headers_nft = [_("Send"), _("Category"), _("Commitment"), _("Capability")]
    headers_baton = ["", _("Category"), ""]
    headers_mint = [_("Category"), _("Commitment"), _("Capability"), _("Multiplier")]

    def __init__(self, parent: ElectrumWindow, token_utxos: List[dict],
                 *, broadcast_callback: Optional[Callable[[bool], Any]] = None, form_mode=FormMode.send):
        assert isinstance(parent, ElectrumWindow)
        if form_mode == self.FormMode.send:
            title = _("Send Tokens")
        elif form_mode == self.FormMode.edit:
            title = _("Edit Tokens")
        else:
            title = _("Mint NFTs")
        title += " - " + parent.wallet.basename()
        super().__init__(parent=parent, title=title)
        PrintError.__init__(self)
        OnDestroyedMixin.__init__(self)
        self.fully_constructed = False
        self._rebuilding_treewidget = False
        util.finalization_print_error(self)
        self.setWindowIcon(QtGui.QIcon(":icons/tab_send.png"))
        self.parent = parent
        self.token_meta: TokenMetaQt = parent.token_meta
        self.wallet: wallet.Abstract_Wallet = self.parent.wallet
        self.utxos_by_name: Dict[str, dict] = dict()
        self.token_utxos: DefaultDict[str, List[str]] = defaultdict(list)  # tokenid -> unique sorted list of utxonames
        self.token_nfts: DefaultDict[str, List[str]] = defaultdict(list)  # tokenid -> list of utxonames
        self.token_fungible_only: DefaultDict[str, List[str]] = defaultdict(list)
        self.token_fungible_totals: DefaultDict[str, int] = defaultdict(int)  # tokenid -> fungible total
        self.token_nfts_selected: DefaultDict[str, Set[str]] = defaultdict(set)  # tokenid -> set of selected utxonames
        self.token_fungible_to_spend: DefaultDict[str, int] = defaultdict(int)  # tokenid -> amount
        self.nfts_to_edit: DefaultDict[str, Optional[bytes]] = defaultdict(bytes)  # utxoname -> new commitment bytes
        self.nfts_to_mint: List[Dict] = list()  # Inner Dict keys: category_id, commitment, capability, copies, baton_name
        self.broadcast_callback = broadcast_callback
        self.icon_baton = QtGui.QIcon(":icons/baton.png")
        self.icon_mutable = QtGui.QIcon(":icons/mutable.png")
        self.icon_trash = QtGui.QIcon(":icons/trash-10-24.png")
        self.form_mode = form_mode

        # Setup data source; iterate over a sorted list of utxos
        def sort_func(u):
            td: token.OutputData = u['token_data']
            return td.id, td.commitment, td.bitfield & 0x0f, self.get_outpoint_longname(u)
        sorted_utxos = sorted(token_utxos, key=sort_func)

        for utxo in sorted_utxos:
            td: token.OutputData = utxo['token_data']
            assert isinstance(td, token.OutputData)
            tid = td.id_hex
            name = self.get_outpoint_longname(utxo)
            if name in self.utxos_by_name:
                # skip dupes
                assert self.utxos_by_name[name] == utxo
                continue
            self.utxos_by_name[name] = utxo
            self.token_utxos[tid].append(name)
            if td.has_nft():
                self.token_nfts[tid].append(name)
                # Start out with nothing selected
                self.token_nfts_selected[tid].clear()
            else:
                assert td.has_amount()
                self.token_fungible_only[tid].append(name)
            self.token_fungible_totals[tid] += td.amount

        # Build UI
        vbox = QtWidgets.QVBoxLayout(self)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.setContentsMargins(0, 0, 0, 0)  # contains the two top groupboxess (each containing a treewidget)

        # Top panel
        if self.form_mode == self.FormMode.mint:
            gb_tok_title = _("Available Minting Tokens")
        else:
            gb_tok_title = _("Tokens to Send")

        self.gb_ft = gb = QtWidgets.QGroupBox(gb_tok_title)
        vbox_gb = QtWidgets.QVBoxLayout(gb)
        self.tw_tok = tw = QtWidgets.QTreeWidget()
        tw.setAlternatingRowColors(True)
        tw.setSortingEnabled(False)
        tw.setTextElideMode(QtCore.Qt.ElideMiddle)
        if self.form_mode == self.FormMode.mint:
            tw.setHeaderLabels(self.headers_baton)
            tw.header().setSectionResizeMode(self.ColsBaton.category, QtWidgets.QHeaderView.Stretch)
            tw.header().setSectionResizeMode(self.ColsBaton.buttons, QtWidgets.QHeaderView.ResizeToContents)
            tw.header().setStretchLastSection(False)
            tw.header().resizeSection(self.ColsBaton.icon, 21)
            tw.itemDoubleClicked.connect(self.on_mint_mode_top_tree_dbl_click)
            tw.setMinimumHeight(100)
        else:
            tw.setHeaderLabels(self.headers_tok)
            tw.header().setSectionResizeMode(self.ColsTok.amount_send, QtWidgets.QHeaderView.Stretch)
        tw.setRootIsDecorated(False)  # Saves space in col0
        tw.setItemsExpandable(False)  # ditto
        vbox_gb.addWidget(tw)
        splitter.addWidget(gb)
        if self.form_mode == self.FormMode.mint:
            splitter.setStretchFactor(splitter.count()-1, 38)
        else:
            splitter.setStretchFactor(splitter.count()-1, 100)

        # Middle panel
        if self.form_mode == self.FormMode.send:
            gb_nft_title = _("NFTs to Send")
        elif self.form_mode == self.FormMode.edit:
            gb_nft_title = _("NFTs to Edit")
        else:
            gb_nft_title = _("NFTs to Mint")
        self.gb_nft = gb_nft = QtWidgets.QGroupBox(gb_nft_title)
        gb_nft_vbox = QtWidgets.QVBoxLayout(gb_nft)

        self.tw_nft = tw = QtWidgets.QTreeWidget()
        tw.setAlternatingRowColors(True)
        tw.setSortingEnabled(False)
        tw.setTextElideMode(QtCore.Qt.ElideMiddle)
        if self.form_mode == self.FormMode.send:
            tw.setHeaderLabels(self.headers_nft)
            tw.header().setSectionResizeMode(self.ColsNFT.flags, QtWidgets.QHeaderView.Stretch)
        elif self.form_mode == self.FormMode.edit:
            self.headers_nft = [_("Selected")] + self.headers_nft[1:]
            tw.setHeaderLabels(self.headers_nft)
            tw.header().setSectionResizeMode(self.ColsNFT.commitment, QtWidgets.QHeaderView.Stretch)
        elif self.form_mode == self.FormMode.mint:
            tw.setRootIsDecorated(False)
            tw.setItemsExpandable(False)
            tw.setHeaderLabels(self.headers_mint)
            tw.header().setSectionResizeMode(self.ColsMint.commitment, QtWidgets.QHeaderView.Stretch)
            tw.header().setSectionResizeMode(self.ColsMint.capability, QtWidgets.QHeaderView.Fixed)
        gb_nft_vbox.addWidget(tw)

        self.rebuild_output_tokens_treewidget()
        self.rebuild_input_tokens_treewidget()

        # Receive notification and update nft selected sets when user clicks the NFT widget
        self.tw_nft.itemChanged.connect(self.on_nft_item_changed)

        splitter.addWidget(gb_nft)
        splitter.setStretchFactor(splitter.count()-1, 100)

        # Pay To
        vbox_bottom = QtWidgets.QVBoxLayout()
        vbox_bottom.setContentsMargins(0, 0, 0, 0)  # No inset
        gb_payto = self.gb_payto = QtWidgets.QGroupBox(_("Pay To"))
        vbox_payto = QtWidgets.QVBoxLayout(gb_payto)
        self.te_payto = te = ScanQRTextEdit()

        vbox_payto.addWidget(te)
        te.setPlaceholderText(networks.net.CASHADDR_PREFIX + ":" + "...")
        te.textChanged.connect(self.on_ui_state_changed)

        self._adjust_te_payto_size()
        if self.form_mode in (self.FormMode.edit, self.FormMode.mint):
            gb_payto.setHidden(True)
            an_addr = self.wallet.get_unused_address(for_change=True) or self.wallet.dummy_address()
            self.te_payto.setText(an_addr.to_token_string())

        vbox_bottom.addWidget(gb_payto)
        vbox_bottom.setStretch(vbox_bottom.count()-1, 1)

        # BCH to send plus description
        hbox = QtWidgets.QHBoxLayout()
        vbox_bottom.setStretch(vbox.count()-1, 100)
        hbox.setContentsMargins(0, 0, 0, 0)  # No inset
        # Additional BCH to Send
        self._setup_additional_bch_gbox(hbox)
        # Description
        gb_desc = QtWidgets.QGroupBox(_("Description"))
        gb_desc.setToolTip(_("Enter an optional label for the transaction"))
        vbox_gb_desc = QtWidgets.QVBoxLayout(gb_desc)
        self.te_desc = QtWidgets.QPlainTextEdit()
        vbox_gb_desc.addWidget(self.te_desc)
        self.te_desc.setWordWrapMode(QtGui.QTextOption.WrapAnywhere)
        self.te_desc.setPlaceholderText(_("Memo") + "...")
        hbox.addWidget(gb_desc)

        vbox_bottom.addLayout(hbox)
        vbox_bottom.setStretch(vbox_bottom.count()-1, 100)
        w_bottom = QtWidgets.QWidget()
        w_bottom.setContentsMargins(0, 0, 0, 0)  # No inset
        w_bottom.setLayout(vbox_bottom)
        splitter.addWidget(w_bottom)
        if self.form_mode == self.FormMode.mint:
            splitter.setStretchFactor(splitter.count()-1, 38)
        else:
            splitter.setStretchFactor(splitter.count()-1, 26)
        vbox.addWidget(splitter)
        vbox.setStretch(vbox.count()-1, 100)

        # Bottom buttons
        hbox = QtWidgets.QHBoxLayout()
        but_clear = QtWidgets.QPushButton(_("Clear"))
        but_clear.clicked.connect(self.clear_form)
        hbox.addWidget(but_clear)
        self.lbl_status_msg = l = QtWidgets.QLabel()
        hbox.addWidget(l, 1, QtCore.Qt.AlignCenter | QtCore.Qt.AlignVCenter)
        spacer = QtWidgets.QSpacerItem(0, 0, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        hbox.addItem(spacer)
        but_cancel = QtWidgets.QPushButton(_("Cancel"))
        but_cancel.clicked.connect(self.close)
        hbox.addWidget(but_cancel)
        self.but_preview_tx = QtWidgets.QPushButton(_("Preview Tx..."))
        self.but_preview_tx.setDefault(True)
        self.but_preview_tx.clicked.connect(self.on_preview_tx)
        hbox.addWidget(self.but_preview_tx)

        vbox.addLayout(hbox)

        self.fully_constructed = True
        self.on_ui_state_changed()

        self.resize(640, 480)

    def showEvent(self, evt: QtGui.QShowEvent):
        super().showEvent(evt)
        if evt.isAccepted():
            # Subscribe to signals when metadata is updated in another window to redraw UI with proper metadata
            self.parent.gui_object.token_metadata_updated_signal.connect(self._on_token_metadata_updated)

    def hideEvent(self, evt: QtGui.QHideEvent):
        super().hideEvent(evt)
        if evt.isAccepted():
            try:
                self.parent.gui_object.token_metadata_updated_signal.disconnect(self._on_token_metadata_updated)
            except TypeError:
                pass

    def _on_token_metadata_updated(self, tid):
        if self.fully_constructed and tid in self.token_utxos:
            self.rebuild_output_tokens_treewidget()
            self.rebuild_input_tokens_treewidget()
            self.on_ui_state_changed()

    def _adjust_te_payto_size(self):
        te = self.te_payto
        gb = self.gb_payto
        font_spacing = QtGui.QFontMetrics(te.document().defaultFont()).lineSpacing()
        margins = te.contentsMargins()
        document_margin = te.document().documentMargin()
        vertical_margins = margins.top() + margins.bottom()
        vertical_margins += te.frameWidth() * 2
        vertical_margins += int(document_margin * 2)

        height_min = font_spacing + vertical_margins
        te.setMinimumHeight(height_min)
        sp = gb.sizePolicy()
        sp.setVerticalPolicy(sp.Maximum)
        gb.setSizePolicy(sp)
        te.setSizePolicy(sp)

    def _setup_additional_bch_gbox(self, parent_layout: QtWidgets.QLayout):
        gb = QtWidgets.QGroupBox(_("Additional BCH to Send"))
        grid = QtWidgets.QGridLayout(gb)
        row, col, n_cols = 0, 0, 5
        msg = (_('Additional amount to be sent along with the tokens.') + '\n\n'
               # The below text comes from the main_window.
               + _('The amount will be displayed in red if you do not have enough funds in your wallet.') + ' '
               + _('Note that if you have frozen some of your addresses, the available funds will be lower than your'
                   ' total balance.'))
        l = HelpLabel(_("Amount"), msg)
        grid.addWidget(l, row, col)
        col += 1
        self.amount_e = BTCAmountEdit(self.parent.get_decimal_point)
        self.amount_e.setFixedWidth(150)
        grid.addWidget(self.amount_e, row, col)
        l.setBuddy(self.amount_e)
        col += 1

        def spend_max(checked):
            if checked:
                self.on_ui_state_changed()
        self.cb_max = QtWidgets.QCheckBox(_("&Max"))
        grid.addWidget(self.cb_max, row, col)
        self.cb_max.clicked.connect(spend_max)
        col += 1

        def on_text_edited():
            if self.cb_max.isChecked():
                self.cb_max.setChecked(False)  # will call on_ui_state_changed
            else:
                self.on_ui_state_changed()
        self.amount_e.textEdited.connect(on_text_edited)

        spacer = QtWidgets.QSpacerItem(0, 0, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        grid.addItem(spacer, row, col)

        row += 1
        col = 0
        msg = (_('Bitcoin Cash transactions are in general not free. A transaction fee is paid by the sender of the'
                 ' funds.') + '\n\n'
               + _('Generally, a fee of 1.0 sats/B is a good minimal rate to ensure your transaction will make it into'
                   ' the next block.'))
        fee_e_label = HelpLabel(_('F&ee'), msg)
        grid.addWidget(fee_e_label)
        col += 1

        self.fee_rate = 1000  # this gets quickly overwritten below

        def fee_cb(dyn, pos, fee_rate):
            self.fee_rate = fee_rate
            self.on_ui_state_changed()

        self.fee_slider = FeeSlider(self.parent, self.parent.config, fee_cb)
        self.fee_slider.setFixedWidth(140)
        grid.addWidget(self.fee_slider, row, col)
        fee_e_label.setBuddy(self.fee_slider)
        self.fee_slider.moved(self.fee_slider.value())  # Ensure callback fires at least once

        parent_layout.addWidget(gb)
        if self.form_mode in (self.FormMode.edit, self.FormMode.mint):
            gb.setHidden(True)

    def have_fts(self) -> bool:
        return sum(amt for amt in self.token_fungible_totals.values()) > 0

    def have_nfts(self) -> bool:
        return sum(len(u) for u in self.token_nfts.values()) > 0

    def get_nfts_selected_str(self, tid: str) -> str:
        nft_total = len(self.token_nfts.get(tid, []))
        nfts_selected = len(self.token_nfts_selected.get(tid, set()))
        return f"{nfts_selected}/{nft_total}"

    def on_nft_item_changed(self, item: QtWidgets.QTreeWidgetItem, column: int):
        if self._rebuilding_treewidget:
            return
        tid = item.data(0, self.DataRoles.token_id)
        name = item.data(0, self.DataRoles.output_point)
        # Update NFTs selected set and counts in UI
        if tid and name and column == self.ColsNFT.selected:
            checked = item.checkState(column) == QtCore.Qt.Checked
            if checked:
                self.token_nfts_selected[tid].add(name)
            else:
                self.token_nfts_selected[tid].discard(name)
            self.update_tokens_to_send_nft_count(tid)
            self.on_ui_state_changed()

    def update_tokens_to_send_nft_flags(self, tid: str):
        """Intended to be a callback for a specific token id -- updates the NFTs x/y column"""
        tw = self.tw_nft
        for i in range(tw.topLevelItemCount()):
            item = tw.topLevelItem(i)
            if (item.data(0, self.DataRoles.token_id) == tid
                    and item.data(0, self.DataRoles.receives_nft_flag_updates)):
                flags = set()
                for index in range(item.childCount()):
                    child = item.child(index)
                    name = child.data(0, self.DataRoles.output_point)
                    if name and name in self.token_nfts_selected.get(tid, set()):
                        flags.add(child.text(self.ColsNFT.flags))
                flags = ', '.join(flags)
                if flags:
                    flags = _("Selected") + ": " + flags
                item.setText(self.ColsNFT.flags, flags)
                return

    def update_tokens_to_send_nft_count(self, tid: str):
        """Intended to be a callback for a specific token id -- updates the NFTs x/y column"""
        tws = [(self.tw_tok, self.ColsTok.nfts), (self.tw_nft, self.ColsNFT.selected)]
        for tw, col in tws:
            if tw is None:
                continue
            for i in range(tw.topLevelItemCount()):
                item = tw.topLevelItem(i)
                if (item.data(0, self.DataRoles.token_id) == tid
                        and item.data(0, self.DataRoles.receives_nft_count_updates)):
                    item.setText(col, self.get_nfts_selected_str(tid))
                    break

    def add_nft_to_mint(self, category_id: str, baton_name: str):
        self.nfts_to_mint.append(
            {"category_id": category_id,
             "commitment": b'',
             "capability": token.Capability.NoCapability,
             "copies": 1,
             "baton_name": baton_name})
        self.rebuild_output_tokens_treewidget()
        self.on_ui_state_changed()
        # Scroll to bottom so user understands where the new NFT ended up (otherwise he/she might have impression
        # that the Mint button had no effect on UI)
        self.tw_nft.scrollToBottom()

    def remove_nft_to_mint(self, row_number):
        scroll_pos_val = self.tw_nft.verticalScrollBar().value()
        del self.nfts_to_mint[row_number]
        self.rebuild_output_tokens_treewidget()
        self.tw_nft.verticalScrollBar().setValue(scroll_pos_val)
        self.on_ui_state_changed()

    def on_mint_mode_top_tree_dbl_click(self, item, column):
        """Slot to make double-clicks do the same things as clicking the "Mint..." button"""
        if self.form_mode != self.FormMode.mint:
            return
        baton_name = item.data(0, self.DataRoles.output_point)
        w = self.tw_tok.itemWidget(item, self.ColsBaton.buttons)
        if w and baton_name:
            but = w.findChild(QtWidgets.QToolButton, "mint_" + baton_name, QtCore.Qt.FindChildrenRecursively)
            if but:
                but.clicked.emit()

    @staticmethod
    def _set_field_margins(hbox, first_row=False, first_column=False, last_column=False):
        normal = 2
        left = 0 if first_column else normal
        right = normal * 2 if last_column else normal
        top = normal * 2 if first_row else normal
        hbox.setContentsMargins(left, top, right, normal)

    @staticmethod
    def allow_transparent_background(widget: QtWidgets.QWidget):
        """QWidgets added to QTreeWidgets by default have fully opaque backgrounds which disrupt the alternate-row
        styling and row-hover effects.  This function gives the appropriate QWidget a transparent background."""
        widget.parentWidget().setStyleSheet(
            'QTreeWidget::item > QWidget > QWidget { background-color: transparent; }')

    def _set_category_col(self, item, tid: str, category_col: int):
        # Params: tid: token_id (category id), category_col: the column that corresponds to the category column
        assert category_col in {self.ColsNFT.category, self.ColsTok.category, self.ColsMint.category,
                                self.ColsBaton.category}
        item.setIcon(category_col, self.token_meta.get_icon(tid))
        formatted_category = self.token_meta.format_token_display_name(tid)
        item.setText(category_col, formatted_category)
        tt = formatted_category
        if formatted_category != tid:
            tt += " " + _("Category ID") + ": " + tid
        item.setToolTip(category_col, tt)
        f = item.font(category_col)
        f.setStretch(f.SemiCondensed)
        item.setFont(category_col, f)

    def rebuild_input_tokens_treewidget(self):
        try:
            self._rebuilding_treewidget = True
            self._rebuild_input_tokens_treewidget()
        finally:
            self._rebuilding_treewidget = False

    def _rebuild_input_tokens_treewidget(self):
        tw = self.tw_tok
        tw.clear()
        first_row = True
        if self.form_mode == self.FormMode.send:
            for tid, amt in self.token_fungible_totals.items():
                try:
                    if amt <= 0:
                        # Skip displaying rows in this table for tokens that have no fungibles
                        continue
                    formatted_amt = self.token_meta.format_amount(tid, amt)
                    item = QtWidgets.QTreeWidgetItem(["", "", formatted_amt, ""])
                    item.setData(0, self.DataRoles.token_id, tid)
                    item.setData(0, self.DataRoles.receives_nft_count_updates, True)
                    self._set_category_col(item, tid, self.ColsTok.category)
                    item.setToolTip(self.ColsTok.amount, item.text(self.ColsTok.amount))
                    item.setFlags(item.flags() & ~QtCore.Qt.ItemIsSelectable)
                    tw.addTopLevelItem(item)
                finally:
                    # Update NFTs M/N column (must be done after add, and even if we didn't add anything)
                    self.update_tokens_to_send_nft_count(tid)
                w = QtWidgets.QWidget()
                w.setToolTip(_("Specify fungible token amount to be sent in the transaction"))
                hbox = QtWidgets.QHBoxLayout(w)
                self._set_field_margins(hbox, first_row, last_column=True)
                le = QtWidgets.QLineEdit()
                le.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
                le.setObjectName("le")  # so we can find it later
                formatted_saved_amt = self.token_meta.format_amount(tid, self.token_fungible_to_spend.get(tid, 0))
                le.setText(formatted_saved_amt)

                def on_edit(amt=amt, tid=tid, le=le):
                    try:
                        val = self.token_meta.parse_amount(tid, le.text())
                        if val < 0:
                            val = 0
                        elif val > amt:
                            val = amt
                        self.token_fungible_to_spend[tid] = val
                    except ValueError:
                        pass
                    le.setText(self.token_meta.format_amount(tid, self.token_fungible_to_spend[tid]))
                    self.on_ui_state_changed()
                le.editingFinished.connect(on_edit)
                hbox.addWidget(le)

                def on_max(b, amt=amt, tid=tid, le=le):
                    le.setText(self.token_meta.format_amount(tid, amt))
                    on_edit(amt=amt, tid=tid, le=le)

                def on_clear(b, amt=amt, tid=tid, le=le):
                    le.setText("0")
                    on_edit(amt=amt, tid=tid, le=le)
                but = QtWidgets.QToolButton()
                but.clicked.connect(on_max)
                but.setText(_("Max"))
                but.setObjectName("max")
                but.setToolTip("Set to full amount available")
                hbox.addWidget(but)
                but2 = QtWidgets.QToolButton()
                but2.clicked.connect(on_clear)
                but2.setText(_("Clear"))
                but2.setObjectName("clear")
                but2.setToolTip("Set to 0")
                hbox.addWidget(but2)
                tw.setItemWidget(item, self.ColsTok.amount_send, w)
                self.allow_transparent_background(w)
                first_row = False
        elif self.form_mode == self.FormMode.mint:
            for tid, baton_names in self.token_nfts.items():
                for baton_name in baton_names:
                    utxo = self.get_utxo(baton_name)
                    td = utxo['token_data']
                    assert isinstance(td, token.OutputData)
                    category_id = td.id_hex
                    assert category_id == tid
                    item = QtWidgets.QTreeWidgetItem(["", "", ""])
                    item.setData(0, self.DataRoles.token_id, tid)
                    item.setData(0, self.DataRoles.output_point, baton_name)
                    self._set_category_col(item, category_id, self.ColsBaton.category)
                    item.setToolTip(self.ColsBaton.icon, _("Minting NFT"))
                    item.setFlags(item.flags() & ~QtCore.Qt.ItemIsSelectable)
                    item.setIcon(self.ColsBaton.icon, self.icon_baton)
                    tw.addTopLevelItem(item)
                    w = QtWidgets.QWidget()
                    w.setToolTip(item.toolTip(self.ColsNFT.commitment))
                    hbox = QtWidgets.QHBoxLayout(w)
                    self._set_field_margins(hbox, first_row, last_column=True)
                    but = QtWidgets.QToolButton()

                    def on_clicked(_, _category_id=category_id, _baton_name=baton_name):
                        self.add_nft_to_mint(_category_id, _baton_name)
                        self.on_ui_state_changed()
                    but.clicked.connect(on_clicked)
                    but.setText(_("Mint..."))
                    but.setObjectName("mint_" + baton_name)
                    but.setToolTip("Use this Minting token to mint new NFTs")
                    hbox.addWidget(but)
                    tw.setItemWidget(item, self.ColsBaton.buttons, w)
                    self.allow_transparent_background(w)
                    first_row = False

        if self.form_mode == self.FormMode.edit or (self.form_mode == self.FormMode.send and not self.have_fts()):
            # Hide the input tokens box in edit mode or if no fungibles in send mode
            self.gb_ft.setHidden(True)

    @staticmethod
    def is_commitment_valid(commitment_hex):
        if len(commitment_hex) > token.MAX_CONSENSUS_COMMITMENT_LENGTH * 2:
            return False, b''
        try:
            return True, bytes.fromhex(commitment_hex)
        except ValueError:
            return False, b''

    def rebuild_output_tokens_treewidget(self):
        try:
            self._rebuilding_treewidget = True
            self._rebuild_output_tokens_treewidget()
        finally:
            self._rebuilding_treewidget = False

    def _rebuild_output_tokens_treewidget(self):
        tw = self.tw_nft
        tw.clear()
        row_num = 0
        first_row = True

        if self.form_mode == self.FormMode.mint:
            for row_data in self.nfts_to_mint:
                category_id = row_data["category_id"]
                commitment = row_data["commitment"] or b''
                capability = row_data["capability"]
                copies = row_data["copies"]
                item = QtWidgets.QTreeWidgetItem(["", "", "", ""])
                self._set_category_col(item, category_id, self.ColsMint.category)
                max_chars = token.MAX_CONSENSUS_COMMITMENT_LENGTH * 2
                item.setToolTip(self.ColsNFT.commitment,
                                _("Enter an even number of up to {max_chars} hexadecimal characters")
                                .format(max_chars=max_chars))
                item.setFlags(item.flags() & ~QtCore.Qt.ItemIsSelectable)
                tw.addTopLevelItem(item)

                # Commitment field
                w = QtWidgets.QWidget()
                w.setToolTip(item.toolTip(self.ColsMint.commitment))
                hbox = QtWidgets.QHBoxLayout(w)
                self._set_field_margins(hbox, first_row)
                commitment_le = QtWidgets.QLineEdit()
                commitment_le.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
                commitment_le.setText(row_data.get("last_text_seen") or commitment.hex())

                def on_text_changed(text, no_updaate_ui=False, le=commitment_le, _row_num=row_num):
                    self.nfts_to_mint[_row_num]["last_text_seen"] = text
                    color = ColorScheme.DEFAULT
                    valid, new_commitment = self.is_commitment_valid(text)
                    if valid:
                        self.nfts_to_mint[_row_num]["commitment"] = new_commitment
                    else:
                        color = ColorScheme.RED
                        self.nfts_to_mint[_row_num]["commitment"] = None  # Indicate that we have an error
                    le.setStyleSheet(color.as_stylesheet())
                    if not no_updaate_ui:
                        self.on_ui_state_changed()

                on_text_changed(commitment_le.text(), False)  # Call once to properly set color

                commitment_le.textChanged.connect(on_text_changed)
                hbox.addWidget(commitment_le)
                tw.setItemWidget(item, self.ColsMint.commitment, w)
                self.allow_transparent_background(w)

                # Capability field
                w = QtWidgets.QWidget()
                w.setToolTip(item.toolTip(self.ColsMint.capability))
                hbox = QtWidgets.QHBoxLayout(w)
                self._set_field_margins(hbox, first_row)
                capability_cb = QtWidgets.QComboBox()
                capability_cb.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
                capability_cb.addItems([_('Immutable'), _('Mutable'), _('Minting')])
                capability_cb.setItemIcon(1, self.icon_mutable)
                capability_cb.setItemIcon(2, self.icon_baton)
                capability_cb.setToolTip(_("Capability of the newly-minted NFT"))
                if capability == token.Capability.Minting:
                    capability_cb.setCurrentIndex(2)
                elif capability == token.Capability.Mutable:
                    capability_cb.setCurrentIndex(1)
                else:
                    capability_cb.setCurrentIndex(0)

                def on_capability_change(index, _row_num=row_num):
                    assert index in (0, 1, 2)
                    if index == 0:
                        cap = token.Capability.NoCapability
                    elif index == 1:
                        cap = token.Capability.Mutable
                    else:
                        cap = token.Capability.Minting
                    self.nfts_to_mint[_row_num]["capability"] = cap
                capability_cb.currentIndexChanged.connect(on_capability_change)
                hbox.addWidget(capability_cb)
                tw.setItemWidget(item, self.ColsMint.capability, w)
                self.allow_transparent_background(w)

                # Multiplier field
                w = QtWidgets.QWidget()
                w.setToolTip(item.toolTip(self.ColsMint.multiplier))
                hbox = QtWidgets.QHBoxLayout(w)
                self._set_field_margins(hbox, first_row, last_column=True)
                multiplier_sb = QtWidgets.QSpinBox()
                multiplier_sb.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
                multiplier_sb.setMinimum(1)
                multiplier_sb.setMaximum(1000)
                multiplier_sb.setSuffix(" " + _("copies"))
                multiplier_sb.setSpecialValueText(_("Single"))
                multiplier_sb.setValue(copies)
                multiplier_sb.setToolTip(_("Number of identical copies of this NFT to mint"))

                def on_multiplier_change(value, _row_num=row_num):
                    self.nfts_to_mint[_row_num]["copies"] = value
                multiplier_sb.valueChanged.connect(on_multiplier_change)
                hbox.addWidget(multiplier_sb)
                delete_button = QtWidgets.QToolButton()
                delete_button.setIcon(self.icon_trash)
                delete_button.setToolTip(_("Remove this NFT from the list"))

                def on_button_click(_, _row_num=row_num):
                    self.remove_nft_to_mint(_row_num)
                delete_button.clicked.connect(on_button_click)
                hbox.addWidget(delete_button)

                hbox.addStretch(10)

                tw.setItemWidget(item, self.ColsMint.multiplier, w)
                self.allow_transparent_background(w)
                first_row = False
                row_num += 1
        else:  # form_mode edit or send
            def add_leaf_item(parent: QtWidgets.QTreeWidgetItem, tid, name, first=False) -> QtWidgets.QTreeWidgetItem:
                utxo = self.get_utxo(name)
                td = utxo['token_data']
                assert isinstance(td, token.OutputData)
                commitment = td.commitment
                commitment_display_str = commitment.hex() if self.form_mode != self.FormMode.edit else ""
                item = QtWidgets.QTreeWidgetItem(["", "", commitment_display_str, token.get_nft_flag_text(td)])
                item.setData(0, self.DataRoles.token_id, tid)
                item.setData(0, self.DataRoles.output_point, name)
                self._set_category_col(item, tid, self.ColsNFT.category)
                if self.form_mode == self.FormMode.send:
                    item.setToolTip(self.ColsNFT.selected, _("Check to send this NFT"))
                    item.setToolTip(self.ColsNFT.commitment, commitment.hex()
                    if commitment.hex() else _("zero-length commitment"))
                elif self.form_mode == self.FormMode.edit:
                    item.setToolTip(self.ColsNFT.selected, _("Check to edit this NFT"))
                    max_chars = token.MAX_CONSENSUS_COMMITMENT_LENGTH * 2
                    item.setToolTip(self.ColsNFT.commitment,
                                    _("Enter an even number of up to {max_chars} hexadecimal characters")
                                    .format(max_chars=max_chars))
                item.setFlags((item.flags() | QtCore.Qt.ItemIsUserCheckable) & ~QtCore.Qt.ItemIsSelectable)
                if td.is_minting_nft():
                    item.setIcon(self.ColsNFT.flags, self.icon_baton)
                elif td.is_mutable_nft():
                    item.setIcon(self.ColsNFT.flags, self.icon_mutable)
                parent.addChild(item)
                item.setCheckState(self.ColsNFT.selected,
                                   QtCore.Qt.Checked)  # Need to call this at least once to make checkbox appear
                if name not in self.token_nfts_selected.get(tid, set()):
                    item.setCheckState(self.ColsNFT.selected, QtCore.Qt.Unchecked)

                if self.form_mode == self.FormMode.edit:
                    w = QtWidgets.QWidget()
                    w.setToolTip(item.toolTip(self.ColsNFT.commitment))
                    hbox = QtWidgets.QHBoxLayout(w)
                    self._set_field_margins(hbox, first)
                    le = QtWidgets.QLineEdit()
                    le.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
                    le.setObjectName("le_" + name)  # so we can find it later
                    le.setText(commitment.hex())

                    def on_commitment_changed(text, _item=item, _le=le, _commitment=commitment, _name=name):
                        color = ColorScheme.DEFAULT
                        valid, new_commitment = self.is_commitment_valid(text)
                        if valid:
                            if text == _commitment.hex():
                                _item.setCheckState(self.ColsNFT.selected, QtCore.Qt.Unchecked)
                                self.nfts_to_edit.pop(_name, None)
                            else:
                                color = ColorScheme.BLUE
                                _item.setCheckState(self.ColsNFT.selected, QtCore.Qt.Checked)
                                self.nfts_to_edit[_name] = new_commitment
                        else:
                            color = ColorScheme.RED
                            _item.setCheckState(self.ColsNFT.selected, QtCore.Qt.Unchecked)
                            self.nfts_to_edit[_name] = None  # Indicate that we have an error
                        _le.setStyleSheet(color.as_stylesheet())
                        self.on_ui_state_changed()

                    le.textChanged.connect(on_commitment_changed)
                    hbox.addWidget(le)

                    def on_reset(b, commitment_hex=commitment.hex(), _le=le):
                        is_same = _le.text() == commitment_hex
                        if is_same:
                            # If same, above slot won't fire when calling setText(), so we force it to fire
                            on_commitment_changed(commitment_hex)
                        else:
                            # Otherwise modify text and slot fires
                            _le.setText(commitment_hex)

                    but = QtWidgets.QToolButton()
                    but.clicked.connect(on_reset)
                    but.setText(_("Reset"))
                    but.setObjectName("reset_" + name)
                    but.setToolTip("Reset to original commitment")
                    hbox.addWidget(but)
                    tw.setItemWidget(item, self.ColsNFT.commitment, w)
                    self.allow_transparent_background(w)

                return item

            for tid, names in self.token_nfts.items():
                if not names:
                    # Defensive programming: should never happen
                    continue
                if len(names) == 1:
                    # This group has only 1 item, push to top-level and don't build a sub-item
                    item = add_leaf_item(tw.invisibleRootItem(), tid, names[0], first_row)
                    # Subscribe to counts label updates
                    item.setData(0, self.DataRoles.receives_nft_count_updates, True)
                    continue
                # This group has more than 1 item, build a subgrouping
                parent = QtWidgets.QTreeWidgetItem(["", "", "", ""])
                self._set_category_col(parent, tid, self.ColsNFT.category)
                parent.setFlags((parent.flags() | QtCore.Qt.ItemIsAutoTristate | QtCore.Qt.ItemIsUserCheckable)
                                & ~QtCore.Qt.ItemIsSelectable)
                parent.setData(0, self.DataRoles.token_id, tid)
                # Subscribe to update of counts label
                parent.setData(0, self.DataRoles.receives_nft_count_updates, True)
                # Subscribe to updates of Flags label
                parent.setData(0, self.DataRoles.receives_nft_flag_updates, True)
                parent.setCheckState(0, QtCore.Qt.Checked)  # Needs to be called once to make checkbox appear
                nfts_selected = self.token_nfts_selected.get(tid, set())
                nchkd = len(nfts_selected)
                ntot = len(names)
                if nchkd == 0:
                    parent.setCheckState(0, QtCore.Qt.Unchecked)
                elif nchkd < ntot:
                    parent.setCheckState(0, QtCore.Qt.PartiallyChecked)
                tw.addTopLevelItem(parent)
                for name in names:
                    add_leaf_item(parent, tid, name, first_row)
                    first_row = False

            if self.form_mode == self.FormMode.edit:
                # After above is built, do a 1-pass to re-set the counts for items receiving count updates,
                # so that the UI starts off with the right counts. This is necessary in "edit" mode only;
                # "send" mode has the "fungibles" box firing a re-count as it builds itself, thereby implicitly
                # causing the below update_tokens_to_send_nft_count(tid) to run for each `tid`.
                for tid in self.token_nfts.keys():
                    self.update_tokens_to_send_nft_count(tid)

            if tw.topLevelItemCount() == 1:
                # Auto-expand if only 1 item
                item = tw.topLevelItem(0)
                if item.childCount() > 0:
                    item.setExpanded(True)

        # In send mode, if we have no NFTs, hide this widget completely
        if self.form_mode == self.FormMode.send:
            self.gb_nft.setHidden(not self.have_nfts())

    def diagnostic_name(self):
        dn = super().diagnostic_name()
        w = getattr(self, 'wallet', None)
        wn = ("/" + w.diagnostic_name()) if w else ""
        return f'{dn}{wn}'

    @staticmethod
    def get_outpoint_longname(utxo) -> str:
        return f"{utxo['prevout_hash']}:{utxo['prevout_n']}"

    def get_utxo(self, name: str) -> Optional[dict]:
        return self.utxos_by_name.get(name)

    def clear_form(self):
        """Bring this form back to the initial state, clear text fields, etc"""
        self.tw_nft.itemChanged.disconnect(self.on_nft_item_changed)  # Need to disable this signal temporarily
        for tid in list(self.token_fungible_to_spend):
            self.token_fungible_to_spend[tid] = 0
        for tid in list(self.token_nfts_selected):
            self.token_nfts_selected[tid].clear()
        self.nfts_to_mint.clear()
        self.rebuild_output_tokens_treewidget()
        self.rebuild_input_tokens_treewidget()
        self.cb_max.setChecked(False)
        self.fee_slider.setValue(0)
        self.amount_e.clear()
        if self.form_mode == self.FormMode.send:
            self.te_payto.clear()
        self.te_desc.clear()
        self.tw_nft.itemChanged.connect(self.on_nft_item_changed)
        self.on_ui_state_changed()

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

    def _estimate_max_amount(self):
        spec = self.make_token_send_spec(dummy=True)
        try:
            tx = self.wallet.make_token_send_tx(self.parent.config, spec)
        except Exception as e:
            self.print_error("_estimate_max_amount:", repr(e))
            return None
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

    def on_ui_state_changed(self):
        if not self.fully_constructed:
            return
        sane = self.check_sanity()
        self.but_preview_tx.setEnabled(sane)

        # Manage amt color state
        amt_color = ColorScheme.DEFAULT
        if self.cb_max.isChecked():
            amt = self._estimate_max_amount()
            self.amount_e.setAmount(amt or 0)
        else:
            amt = self.amount_e.get_amount()
            if amt is not None:
                max_amt = self._estimate_max_amount()
                if max_amt is not None and amt > max_amt:
                    amt_color = ColorScheme.RED
        self.amount_e.setStyleSheet(amt_color.as_stylesheet())

        # Manage address color state
        addr_color = ColorScheme.DEFAULT
        msg = ""
        if sane:
            addr_str = self.te_payto.toPlainText().strip()
            if address.Address.is_token(addr_str):
                addr_color = ColorScheme.GREEN
            else:
                addr_color = ColorScheme.YELLOW
                msg = _("Not a CashToken-aware address")
        self.te_payto.setStyleSheet(addr_color.as_stylesheet())
        self.lbl_status_msg.setText(msg)
        self.lbl_status_msg.setStyleSheet(addr_color.as_stylesheet() if msg else ColorScheme.DEFAULT.as_stylesheet())

    def make_token_send_spec(self, dummy=False) -> wallet.TokenSendSpec:
        spec = wallet.TokenSendSpec()
        if dummy:
            spec.payto_addr = self.wallet.dummy_address()
        else:
            spec.payto_addr = address.Address.from_string(self.te_payto.text().strip())
        spec.change_addr = (self.wallet.get_unused_address(for_change=True, frozen_ok=False)
                            or self.wallet.dummy_address())
        spec.feerate = self.fee_rate
        if dummy:
            spec.send_satoshis = wallet.dust_threshold(self.wallet.network)
        else:
            spec.send_satoshis = self.amount_e.get_amount() or 0
        spec.token_utxos = copy.deepcopy(self.utxos_by_name)
        spec.non_token_utxos = {self.get_outpoint_longname(x): x
                                for x in self.wallet.get_spendable_coins(None, self.parent.config)}
        spec.send_fungible_amounts = {tid: amt for tid, amt in self.token_fungible_to_spend.items()}

        # Gather tx inputs
        spec.send_nfts = set()
        if self.form_mode == self.FormMode.mint:
            for i, nft_mint_row in enumerate(self.nfts_to_mint):
                if nft_mint_row["commitment"] is None:
                    # Defensive programming: This should never happen
                    self.print_error(f"BUG: commitment for nft_mint_row {i} was None")
                    continue
                spec.send_nfts.add(nft_mint_row["baton_name"])
        else:
            for tid, utxo_name_set in self.token_nfts_selected.items():
                if self.form_mode == self.FormMode.send:
                    spec.send_nfts |= utxo_name_set
                else:
                    # In edit mode, only pick up NFTs that changed
                    for utxo_name in utxo_name_set:
                        new_commitment = self.nfts_to_edit.get(utxo_name)
                        commitment = self.utxos_by_name[utxo_name]['token_data'].commitment
                        if new_commitment is not None and new_commitment != commitment:
                            spec.send_nfts.add(utxo_name)
                            spec.edit_nfts[utxo_name] = new_commitment

        # In edit or mint mode, avoid splitting NFTs with amounts on them when editing/minting them, by specifying
        # that the fungible amount should be "sent"
        if self.form_mode in (self.FormMode.edit, self.FormMode.mint):
            iterable = spec.edit_nfts if self.form_mode == self.FormMode.edit else spec.send_nfts
            for utxo_name in iterable:
                utxo = spec.get_utxo(utxo_name)
                td = utxo['token_data']
                spec.send_fungible_amounts[td.id_hex] = td.amount + spec.send_fungible_amounts.get(td.id_hex, 0)

        # 'dummy' mode only: Try and fill in at least 1 nft or fungible amount
        if dummy and not spec.send_nfts and sum(spec.send_fungible_amounts.values()) <= 0:
            for name, utxo in spec.token_utxos.items():
                td = utxo['token_data']
                if td.has_nft():
                    spec.send_nfts.add(name)
                    break
                elif td.amount:
                    spec.send_fungible_amounts[td.id_hex] = td.amount
                    break

        # Determine outputs for minting tx
        if self.form_mode == self.FormMode.mint:
            for i, nft_mint_row in enumerate(self.nfts_to_mint):
                copies = nft_mint_row["copies"]
                baton_name = nft_mint_row["baton_name"]
                capability = nft_mint_row["capability"]
                commitment = nft_mint_row["commitment"]
                if baton_name not in spec.send_nfts:
                    # Defensive programming: This should never happen
                    self.print_error(f"BUG: commitment for nft_mint_row {i} not in spec.send_nfts")
                    continue
                for _ in range(copies):
                    l = spec.mint_nfts.get(baton_name, list())
                    l.append((capability, commitment))
                    if len(l) == 1:
                        # Was missing, ensure exists in dict
                        spec.mint_nfts[baton_name] = l

        return spec

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
            tx = self.wallet.make_token_send_tx(self.parent.config, spec)
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
