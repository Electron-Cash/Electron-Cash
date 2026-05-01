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

import hashlib
import math
import re
import requests
import threading
import urllib.parse
import weakref
from typing import Optional, Tuple

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QFont

from electroncash.i18n import _
from electroncash import address, bitcoin, networks, token, util, wallet

from .main_window import ElectrumWindow
from .util import HelpLabel, MessageBoxMixin, MONOSPACE_FONT, OnDestroyedMixin, PrintError, WaitingDialog

BCMR_URL_REQUIRED_PREFIX = "https://"


class CreateTokenForm(QtWidgets.QWidget, MessageBoxMixin, PrintError, OnDestroyedMixin):

    def __init__(self, parent: ElectrumWindow):
        assert isinstance(parent, ElectrumWindow)
        super().__init__(parent=parent, flags=QtCore.Qt.Window)
        MessageBoxMixin.__init__(self)
        PrintError.__init__(self)
        OnDestroyedMixin.__init__(self)
        util.finalization_print_error(self)
        self.parent = parent
        self.wallet = self.parent.wallet
        self.network = self.parent.network
        self.eligible_utxos = []
        self.other_non_dust_utxos = []
        self.did_warn_wallet_empty = False
        self.token_meta = self.parent.token_meta
        self.setWindowTitle(_("Create Token") + " - " + self.wallet.basename())
        self.setWindowIcon(QtGui.QIcon(":icons/tab_token.svg"))

        self.last_size = None

        grid = QtWidgets.QGridLayout()
        l = QtWidgets.QLabel(_("Create Token"))
        f = l.font()
        f.setPointSize(f.pointSize() + 1)
        f.setBold(True)
        l.setFont(f)
        row, col = 0, 0
        n_cols = 3
        grid.addWidget(l, row, col)
        row += 1

        help_text = _("In order to create a new token, you must spend a coin (UTXO) that has output number 0, e.g."
                      " \"xxxx:0\". Up to ~{tx_fee} satoshis from this coin will be used in fees, and the rest will"
                      " go back to your wallet. If your wallet lacks any \"xxx:0\" coins, click the"
                      " \"New...\" button to send some funds to yourself to create an eligible coin with tx output"
                      " number 0.").format(
            tx_fee=self.est_tx_fee())
        tt = _("Select a coin from your wallet to use for token creation")
        l = HelpLabel(_("Select Coin"), help_text)
        l.setToolTip(tt)
        grid.addWidget(l, row, col, 1, n_cols)
        col += 1
        self.cb_utxos = QtWidgets.QComboBox()
        f = QtGui.QFont(MONOSPACE_FONT)
        f.setPointSize(f.pointSize() - 1)
        smaller_mono_font = f
        self.cb_utxos.setFont(f)
        self.cb_utxos.setToolTip(tt)
        grid.addWidget(self.cb_utxos, row, col)

        col += 1
        self.create_coin_button = b = QtWidgets.QPushButton(_("New..."))
        self.create_coin_button_tooltip_on = _("Create a UTXO with output number 0 from a non-0 wallet UTXO")
        self.create_coin_button_tooltip_off = _("No eligible non-zero UTXOs left in the wallet")
        b.setToolTip(self.create_coin_button_tooltip_on)
        b.clicked.connect(self.create_new_coin)
        grid.addWidget(b, row, col)

        col = 0
        row += 1
        help_text = _("The newly created token derives its Category ID (also known as a Token ID) from the tx hash"
                      " of the \"xxx:0\" coin that was used to create it.")
        tt = _("Category ID of the newly created token")
        l = HelpLabel(_("Category ID"), help_text)
        l.setToolTip(tt)
        grid.addWidget(l, row, col)
        col += 1
        self.token_id_label = l = QtWidgets.QLabel("")
        l.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard)
        f = QFont(smaller_mono_font)
        f.setPointSize(f.pointSize() + 1)
        f.setStretch(QtGui.QFont.SemiCondensed)
        l.setFont(f)
        l.setToolTip(tt)
        self.cb_utxos.currentIndexChanged.connect(self.on_cb_utxo_index_change)
        grid.addWidget(l, row, col)

        # Embed icon
        col += 1
        vbox = QtWidgets.QVBoxLayout()
        vbox.setContentsMargins(6, 12, 0, 0)
        vbox.setSpacing(0)
        tt = _("The icon is generated from the Category ID and is for display purposes only")
        self.icon_lbl = l = QtWidgets.QLabel()
        l.setToolTip(tt)
        l.setScaledContents(True)
        l.setFixedSize(64, 64)
        l.setAlignment(QtCore.Qt.AlignBottom | QtCore.Qt.AlignCenter)
        l.setFrameStyle(QtWidgets.QFrame.Box)
        vbox.addWidget(l)
        l = QtWidgets.QLabel(_("Icon"))
        l.setToolTip(tt)
        l.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignCenter)
        f = l.font()
        f.setPointSize(f.pointSize() - 1)
        l.setFont(f)
        vbox.addWidget(l)
        vbox.addSpacerItem(QtWidgets.QSpacerItem(0, 0, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding))
        vbox.setStretch(2, 1)

        grid.addLayout(vbox, row, col, 2, 1)

        col = 0
        row += 1
        help_text = _("Specify the token properties, such as fungible amount, whether to also create an NFT, and the"
                      " properties of the optional NFT.")
        tt = _("Specify token details")
        l = HelpLabel(_("Specify"), help_text)
        l.setToolTip(tt)
        grid.addWidget(l, row, col)
        grid.setAlignment(l, QtCore.Qt.AlignTop)

        # Embed a sub-grid here for the token details
        col += 1
        grid2 = QtWidgets.QGridLayout()
        row2, col2, n_cols2 = 0, 0, 2
        grid2.setHorizontalSpacing(max(grid2.horizontalSpacing(), 6))
        help_text = _("The fungible amount is specified at token creation time and is fixed for the token once it has"
                      " been created.  In other words, one may not mint new fungible tokens after token genesis. "
                      " Valid values are in the range [0, 9223372036854775807].  Note that fungible amounts of 0 are"
                      " only allowed if the token generates an NFT, otherwise the amount must be greater than 0.")
        tt = _("Specify the fungible amount for this token")
        l = HelpLabel(_("Fungible Amount") + ":", help_text)
        l.setToolTip(tt)
        grid2.addWidget(l, row2, col2)

        col2 += 1
        self.le_fungible = le = QtWidgets.QLineEdit()
        le.textChanged.connect(self.check_sanity)
        le.setToolTip(tt)
        le.setPlaceholderText("1234…")
        grid2.addWidget(le, row2, col2)

        col2 = 0
        row2 += 1
        self.gb_nft = gb = QtWidgets.QGroupBox(_("Has NFT"))
        gb.setCheckable(True)
        gb.setChecked(False)
        row3, col3, n_cols3 = 0, 0, 2
        grid3 = QtWidgets.QGridLayout()
        grid3.setHorizontalSpacing(max(grid3.horizontalSpacing(), 6))
        help_text = _("The NFT commitment is a 0-40 byte value that uniquely identifies this specific non-fungible"
                      " token.  Enter up to 40 bytes worth of an even number of hexadecimal characters here to"
                      " specify the commitment, or leave this field blank for an empty commitment.")
        tt = _("Specify the NFT commitment data as hex")
        l = HelpLabel(_("NFT Commitment"), help_text)
        l.setToolTip(tt)
        grid3.addWidget(l, row3, col3)
        col3 += 1
        self.le_commitment = le = QtWidgets.QLineEdit()
        le.textChanged.connect(self.check_sanity)
        le.setToolTip(tt)
        le.setPlaceholderText(_("Hexadecimal"))
        grid3.addWidget(le, row3, col3)
        col3 = 0
        row3 += 1
        help_text = _("NFT capabilities are \"permissions\" that the NFT has.<br>"
                      "<ul>"
                      "<li><i>None</i> - Sets the NFT to be immutable and thus the only thing one can do is"
                      " send the NFT or burn it.</li>"
                      "<li><i>Mutable</i> - Allows users to modify the commitment for the NFT to any value"
                      " when sending it.</li>"
                      "<li><i>Minting</i> - Allows holders of this NFT to create an unlimited number of new"
                      " NFTs of the same token category.</li>"
                      "</ul>")
        tt = _("Specify the NFT's capability")
        l = HelpLabel(_("NFT Capability"), help_text)
        l.setToolTip(tt)
        grid3.addWidget(l, row3, col3)
        col3 += 1
        hbox = QtWidgets.QHBoxLayout()
        self.rb_none = rb = QtWidgets.QRadioButton(_("None"))
        rb.setToolTip(_("No Capability (Immutable NFT)"))
        hbox.addWidget(rb)
        self.rb_mutable = rb = QtWidgets.QRadioButton(_("Mutable"))
        rb.setToolTip(_("Mutable Capability (Editable NFT)"))
        hbox.addWidget(rb)
        self.rb_minting = rb = QtWidgets.QRadioButton(_("Minting"))
        rb.setToolTip(_("Minting Capability (Minting Baton)"))
        hbox.addWidget(rb)
        self.rb_default = self.rb_minting
        self.rb_default.setChecked(True)  # Default to minting
        grid3.addLayout(hbox, row3, col3)

        gb.setLayout(grid3)
        grid2.addWidget(gb, row2, col2, 1, n_cols2)

        grid.addLayout(grid2, row, col, 1, n_cols - col - 1)

        def maybe_auto_set_fungible_to_0(b):
            if b and self.le_fungible.text().strip() == "":
                self.le_fungible.setText("0")

        gb.toggled.connect(maybe_auto_set_fungible_to_0)
        gb.toggled.connect(self.check_sanity)
        # /Embed

        col = 0
        row += 1
        help_text = _("The destination address to which the newly created token should be sent."
                      " {coin_amt} satoshis will accompany the token on the same UTXO. You can either send this new"
                      " token to a new receiving address in your wallet, or you can send it to any Bitcoin Cash"
                      " address outside this wallet.").format(
            coin_amt=token.heuristic_dust_limit_for_token_bearing_output())
        tt = _("Address to which to send the newly created token")
        l = HelpLabel(_("Send To"), help_text)
        l.setToolTip(tt)
        grid.addWidget(l, row, col)
        col += 1
        hbox = QtWidgets.QHBoxLayout()
        self.bg_addr_radios = QtWidgets.QButtonGroup(self)
        self.rb_me = QtWidgets.QRadioButton(_("This wallet"))
        self.rb_me.setToolTip(_("Send to a fresh address in this wallet"))
        self.bg_addr_radios.addButton(self.rb_me)
        hbox.addWidget(self.rb_me)
        tt = _("Send to any external address")
        self.rb_ext = QtWidgets.QRadioButton("")
        self.rb_ext.setToolTip(tt)
        self.bg_addr_radios.addButton(self.rb_ext)
        hbox.addWidget(self.rb_ext)

        class ClickableLE(QtWidgets.QLineEdit):
            """A line-edit that emits a "mouse_clicked" signal even if it is disabled."""

            mouse_clicked = QtCore.pyqtSignal(bool)

            def event(self, evt: QtCore.QEvent):
                if evt.type() == QtCore.QEvent.MouseButtonPress:
                    self.mouse_clicked.emit(True)
                return super().event(evt)

        self.le_address = ClickableLE()
        self.le_address.setToolTip(tt)
        hbox.addWidget(self.le_address)
        grid.addLayout(hbox, row, col, 1, n_cols - col - 1)
        self.rb_me.toggled.connect(self.le_address.setDisabled)
        self.rb_ext.toggled.connect(self.le_address.setEnabled)
        self.rb_ext.toggled.connect(self.check_sanity)
        self.le_address.setPlaceholderText(networks.net.CASHADDR_PREFIX + ":…")
        self.le_address.textChanged.connect(self.check_sanity)
        self.rb_me.setChecked(True)
        # Ensure that clicking the address line-edit is like selecting the radio button
        self.le_address.mouse_clicked.connect(self.rb_ext.setChecked)
        self.le_address.mouse_clicked.connect(self.le_address.setFocus)

        # BCMR Url
        col = 0
        row += 1
        tt = _("Optional URL to embed as an OP_RETURN in the token genesis txn")
        help_text = _("This field is optional, but if specified, Electron Cash will embed an OP_RETURN in the"
                      " genesis tx for this token which contains the URL and a hash of the URL's contents. This"
                      " would make the token conform to the BCMR token meta-data standard for Bitcoin Cash. The"
                      " URL must begin with {bcmr_prefix} and should serve up a BCMR-conforming JSON document.\n\n"
                      "See: https://github.com/bitjson/chip-bcmr\n\n"
                      "Electron Cash will fetch this document once before creating the token and calculate"
                      " the SHA-256 hash of this document which gets embedded into the genesis tx along with"
                      " the URL.\n\n"
                      "Therefore, before you create the token, be sure that the URL points to the final"
                      " BCMR-conforming JSON document describing this token's metadata.\n\n"
                      "Feel free to leave this field blank to not associate this token with any BCMR metadata.").format(
            bcmr_prefix=BCMR_URL_REQUIRED_PREFIX
        )
        l = HelpLabel(_("BCMR URL"), help_text)
        grid.addWidget(l, row, col)
        col += 1
        self.le_url = QtWidgets.QLineEdit()
        self.le_url.setPlaceholderText(BCMR_URL_REQUIRED_PREFIX + "server.com/mytoken.json" + " " + _("(Optional)"))
        grid.addWidget(l, row, col)
        self.le_url.textChanged.connect(self.check_sanity)
        grid.addWidget(self.le_url, row, col)
        col += 1

        # Bottom buttons
        col = 0
        row += 1
        hbox = QtWidgets.QHBoxLayout()
        hbox.setContentsMargins(0, 0, 0, 0)
        self.clear_button = QtWidgets.QPushButton(_("Clear"))
        self.clear_button.clicked.connect(self.clear_form)
        hbox.addWidget(self.clear_button)
        hbox.addStretch(2)

        self.dlg_buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        self.create_button = self.dlg_buttons.button(QtWidgets.QDialogButtonBox.Ok)
        self.cancel_button = self.dlg_buttons.button(QtWidgets.QDialogButtonBox.Cancel)
        self.create_button.setText(_("Create..."))
        assert self.create_button and self.cancel_button
        self.dlg_buttons.accepted.connect(self.do_create)
        self.dlg_buttons.rejected.connect(self.close)
        hbox.addWidget(self.dlg_buttons)
        grid.addLayout(hbox, row, col, 1, n_cols)

        self.setLayout(grid)

    def diagnostic_name(self):
        dn = super().diagnostic_name()
        w = getattr(self, 'wallet', None)
        wn = ("/" + w.diagnostic_name()) if w else ""
        return f'{dn}{wn}'

    def get_fungible_amount(self) -> Optional[int]:
        """ Only returns a real int if our line-edit is in the 0 - 2^63-1 range"""
        txt = self.le_fungible.text().strip()
        if re.match("^[0-9]+$", txt):
            try:
                val = int(txt)
            except (ValueError, TypeError):
                return None
            if val < 0 or val > 2 ** 63 - 1:
                return None
            return val
        return None

    def clear_form(self):
        """Bring this form back to the initial state, clear text fields, etc"""
        self.rb_default.setChecked(True)
        self.gb_nft.setChecked(False)
        self.le_commitment.clear()
        self.le_address.clear()
        self.rb_me.setChecked(True)
        self.le_fungible.clear()
        if self.cb_utxos.count():
            self.cb_utxos.setCurrentIndex(0)
        self.le_url.clear()

    def check_sanity(self) -> bool:
        sane = True
        if not self.cb_utxos.count() or self.cb_utxos.currentIndex() < 0:
            # No input token selected
            sane = False
        elif self.rb_ext.isChecked():
            addr_text = self.le_address.text().strip()
            try:
                address.Address.from_string(addr_text)
            except address.AddressError:
                # Free-form address line-edit selected but address entered is invalid
                sane = False
        if sane:
            famt = self.get_fungible_amount()
            if famt is None:
                sane = False
            elif famt == 0 and not self.gb_nft.isChecked():
                # Disallow fungible 0 if no NFT enabled
                sane = False
        if sane and self.gb_nft.isChecked():
            try:
                data = bytes.fromhex(self.le_commitment.text().strip())
                if len(data) > token.MAX_CONSENSUS_COMMITMENT_LENGTH:
                    sane = False
            except ValueError:
                sane = False
        if sane:
            url = self.le_url.text().strip()
            len_prefix = len(BCMR_URL_REQUIRED_PREFIX)
            if url and (not url.startswith(BCMR_URL_REQUIRED_PREFIX) or len(url) <= len_prefix):
                sane = False
        self.create_button.setEnabled(sane)
        return sane

    def read_form(self) -> Optional[Tuple[dict, address.Address, token.OutputData, str]]:
        if not self.check_sanity():
            return None
        utxo = self.tup2u(self.cb_utxos.currentData())
        if utxo is None:
            return None
        if self.rb_ext.isChecked():
            addr = address.Address.from_string(self.le_address.text().strip())
        else:
            # Send back to a new address
            addr = self.wallet.get_unused_address(for_change=False, frozen_ok=False) or utxo["address"]

        fungible_amt = self.get_fungible_amount()
        if fungible_amt is None:
            return None
        token_id_hex = utxo['prevout_hash']
        assert len(token_id_hex) == 64
        bitfield = 0
        bitfield |= token.Structure.HasAmount if fungible_amt else 0
        commitment = b''
        if self.gb_nft.isChecked():
            bitfield |= token.Structure.HasNFT
            commitment = bytes.fromhex(self.le_commitment.text().strip())
            bitfield |= token.Structure.HasCommitmentLength if len(commitment) else 0
            if self.rb_mutable.isChecked():
                bitfield |= token.Capability.Mutable
            elif self.rb_minting.isChecked():
                bitfield |= token.Capability.Minting
            else:
                assert self.rb_none.isChecked()
                bitfield |= token.Capability.NoCapability
        tok = token.OutputData(id=token_id_hex, amount=fungible_amt, commitment=commitment, bitfield=bitfield)
        url = self.le_url.text().strip()
        return utxo, addr, tok, url

    def _do_validate_url_and_get_hash(self, url: str) -> Optional[Tuple[bytes, bytes]]:
        """Returns a tuple of hash_bytes, url_bytes (url-encoded to ascii) after retrieving the data from
        url, or None if there was an error or user canceled."""

        assert url.startswith(BCMR_URL_REQUIRED_PREFIX)
        len_prefix = len(BCMR_URL_REQUIRED_PREFIX)
        try:
            url_encoded_sans_prefix = urllib.parse.quote(url[len_prefix:],
                                                         safe="/~", encoding="ascii", errors="strict").encode("ascii")
        except UnicodeError as e:
            self.show_error(_("Unable to url-encode URL: {error}").format(error=repr(e)))
            return None

        full_url_as_bytes = BCMR_URL_REQUIRED_PREFIX.encode('ascii') + url_encoded_sans_prefix

        def retrieve_document_in_thread_and_calculate_hash() -> bytes:
            r = requests.get(full_url_as_bytes, timeout=20.0)
            if r.status_code != 200:
                raise RuntimeError(f"{r.status_code} {r.reason}")
            h = hashlib.sha256()
            h.update(r.content)
            the_hash = h.digest()
            self.print_error(f"Got hash from \"{full_url_as_bytes.decode('ascii')}\" -> {the_hash.hex()}")
            return the_hash

        def on_error(exc_info: tuple):
            self.show_error(_("Unable to retrieve document from \"{url}\", error: {errmsg}")
                            .format(url=full_url_as_bytes.decode('ascii'), errmsg=str(exc_info[1])))

        hash_bytes: Optional[bytes] = None

        def on_success(result):
            nonlocal hash_bytes
            assert isinstance(result, (bytes, bytearray))
            hash_bytes = bytes(result)

        WaitingDialog(self, _("Retrieving document from specified URL, please wait..."),
                      task=retrieve_document_in_thread_and_calculate_hash, on_success=on_success, on_error=on_error,
                      auto_cleanup=True, auto_exec=True, title=_("Checking URL"))

        if not hash_bytes:
            return None

        assert len(hash_bytes) == 32

        return hash_bytes, url_encoded_sans_prefix

    def do_create(self):
        tup = self.read_form()
        if tup is None:
            self.show_error("Error: Form is not sane; unexpected return value from read_form()")
            return
        utxo, addr, tok, url = tup
        if url:
            tup = self._do_validate_url_and_get_hash(url)
            if not tup:
                return
            hash_bytes, url_bytes = tup
        else:
            hash_bytes, url_bytes = None, None
        # We intentionally order things so that the change goes to output 0, so that the wallet doesn't run out of
        # genesis-capable UTXOs.
        change_addr = self.wallet.get_unused_address(for_change=True, frozen_ok=False) or utxo["address"]
        outputs = [(bitcoin.TYPE_ADDRESS, change_addr, '!'),
                   (bitcoin.TYPE_ADDRESS, addr, token.heuristic_dust_limit_for_token_bearing_output())]
        if hash_bytes and url_bytes:
            script = address.ScriptOutput.from_string("OP_RETURN {BCMR} {hash} {url}"
                                                      .format(BCMR=b'BCMR'.hex(),
                                                              hash=hash_bytes.hex(),
                                                              url=url_bytes.hex()))
            # Check that OP_RETURN size is sane according to current relay policy
            if len(script.script) > 223:
                self.show_error(_("OP_RETURN script too large, needs to be no longer than 223 bytes")
                                + ".\n\n" + _("To fix this, please ensure the URL is shorter."))
                return
            outputs += [(bitcoin.TYPE_SCRIPT, script, 0)]
        token_datas = [None, tok]
        tx = self.wallet.make_unsigned_transaction(inputs=[utxo], outputs=outputs, config=self.parent.config,
                                                   token_datas=token_datas, bip69_sort=False)

        tx_desc = _("Token genesis: {token_id}").format(token_id=tok.id_hex)
        self.parent.show_transaction(tx, tx_desc=tx_desc)

    def get_utxos(self):
        return self.wallet.get_utxos(exclude_frozen=True, mature=True, confirmed_only=False, exclude_slp=True,
                                     exclude_tokens=True)

    def create_new_coin(self):
        # Sort by highest prevout_n, highest value first, so we prefer non-0 output nums first
        self.refresh_utxos()
        utxos = sorted(self.other_non_dust_utxos, key=lambda x: (-x['prevout_n'], -x['value']))
        if not utxos:
            self.show_error(_("Not enough funds"))
            return
        utxo = utxos[0]
        addr = self.wallet.get_unused_address(for_change=True, frozen_ok=False) or utxo['address']
        try:
            tx = self.wallet.make_unsigned_transaction(config=self.parent.config, inputs=[utxo],
                                                       outputs=[(bitcoin.TYPE_ADDRESS, addr, '!')])
        except util.NotEnoughFunds:
            self.show_error(_("Not enough funds"))
            return
        except util.ExcessiveFee:
            self.show_error(_("Excessive fee"))
            return
        self.parent.show_transaction(tx, tx_desc=_("Create a new genesis-capable UTXO; spend {coin_name} back to"
                                                   " wallet").format(coin_name=self.utxo_short_name(utxo)))

    def on_cb_utxo_index_change(self, ignored: int):
        data = self.cb_utxos.currentData()
        if data and data[0]:
            self.token_id_label.setText(data[0])
            icon: QtGui.QIcon = self.token_meta.get_icon(data[0])
            self.icon_lbl.setPixmap(icon.pixmap(64, 64))
        else:
            self.token_id_label.setText("-")
            self.icon_lbl.setPixmap(QtGui.QPixmap())
        is_sane = self.check_sanity()
        if is_sane:
            # Ensure that if the index changed, we clear the URL to avoid problems for users
            self.le_url.clear()

    @staticmethod
    def utxo_short_name(utxo: dict) -> str:
        h = utxo["prevout_hash"]
        short_hash = f'{h[:6]}…{h[-6:]}'
        return f'{short_hash}:{utxo["prevout_n"]}'

    def refresh(self) -> None:
        select_index = None
        if self.refresh_utxos():
            selected = self.cb_utxos.currentData()
            self.cb_utxos.clear()
            amts = []
            cut_pos = 2**64  # Just a huge out-of-range value to start
            for utxo in self.eligible_utxos:
                # Grab amounts, figure out how much of the leading spaces to trim
                amt = self.parent.format_amount(utxo['value'], whitespaces=True)
                ctr = 0
                for ch in amt:
                    if ch != ' ':
                        break
                    ctr += 1
                cut_pos = min(cut_pos, ctr)
                amts.append(amt)
            for i, amt in enumerate(amts):
                # Trim leading spaces
                amts[i] = amt[cut_pos:]
            for i, utxo in enumerate(self.eligible_utxos):
                data = self.u2tup(utxo)
                amt = amts[i]
                unit = self.parent.base_unit()
                addr = utxo["address"].to_ui_string()
                text = f'{self.utxo_short_name(utxo)} | {amt} {unit} | {addr}'
                self.cb_utxos.addItem(text, data)
                if selected == data:
                    select_index = i
        if select_index is not None:
            self.cb_utxos.setCurrentIndex(select_index)
        elif self.cb_utxos.currentIndex() < 0:
            # Called to set the Category ID label to "-" on empty / no selection
            self.on_cb_utxo_index_change(-1)
        # Only enable the "New..." button if it makes sense ot do so, and set the tooltip accordingly
        b = bool(len(self.other_non_dust_utxos))
        self.create_coin_button.setEnabled(b)
        tt = self.create_coin_button_tooltip_on if b else self.create_coin_button_tooltip_off
        self.create_coin_button.setToolTip(tt)

        self.maybe_warn_wallet_empty()  # Pop up warning on empty wallet
        self.check_sanity()

    def maybe_warn_wallet_empty(self):
        if not self.eligible_utxos and not self.other_non_dust_utxos and not self.did_warn_wallet_empty:
            self.did_warn_wallet_empty = True
            weak_self = weakref.ref(self)

            def called_later():
                me = weak_self()
                if not me or me.isHidden():
                    return
                me.show_error(_("There are no eligible genesis-capable \"output 0\" coins in the wallet and there"
                                " are not enough free funds to create any new such coins.  Fund the wallet or"
                                " unfreeze any frozen coins to proceed."), parent=me)

            QtCore.QTimer.singleShot(250, called_later)

    @staticmethod
    def u2tup(utxo: dict) -> Tuple[str, int]:
        return utxo['prevout_hash'], utxo['prevout_n']

    def tup2u(self, tup: Optional[Tuple[str, int]]) -> Optional[dict]:
        if tup is not None:
            for utxo in self.eligible_utxos:
                if utxo['prevout_hash'] == tup[0] and utxo['prevout_n'] == tup[1]:
                    return utxo

    def est_tx_fee(self, tx_size=310) -> int:
        return int(math.ceil(tx_size * wallet.relayfee(self.parent.network) / 1000.0))

    def refresh_utxos(self) -> bool:
        """Populates self.eligible_utxos and self.other_non_dust_utxos with fresh data from self.wallet.
        Returns True if there was a change, False otherwise."""

        # Try and guess the worst-case value we need on a single utxo for creating a new token.
        # min_val: roughly 800 + 310 byte txn -> 1310 sats.
        min_val = token.heuristic_dust_limit_for_token_bearing_output() + self.est_tx_fee()
        min_val_other = token.heuristic_dust_limit_for_token_bearing_output() + self.est_tx_fee(200) * 2
        utxos = []
        utxos_other = []
        for utxo in self.get_utxos():
            # NB: Only prevout_n == 0 UTXOs can create new tokens.
            if utxo['prevout_n'] == 0 and utxo['value'] >= min_val:
                utxos.append(utxo)
            elif utxo['prevout_n'] != 0 and utxo['value'] >= min_val_other:
                utxos_other.append(utxo)
        set_old1 = {self.u2tup(utxo) for utxo in self.eligible_utxos}
        set_old2 = {self.u2tup(utxo) for utxo in self.other_non_dust_utxos}
        self.eligible_utxos = sorted(utxos, key=lambda x: -x['value'])  # sort results descending
        self.other_non_dust_utxos = sorted(utxos_other, key=lambda x: -x['value'])  # sort results descending
        set_new1 = {self.u2tup(utxo) for utxo in self.eligible_utxos}
        set_new2 = {self.u2tup(utxo) for utxo in self.other_non_dust_utxos}
        return set_old1 != set_new1 or set_old2 != set_new2 # Return True if there actually was an update

    # This decorator makes this callback always run in main thread (as opposed to the network thread)
    @util.in_main_thread
    def on_network_callback(self, event, *args):
        assert threading.current_thread() == threading.main_thread()
        if event == "wallet_updated" and args and args[0] == self.wallet:
            self.refresh()

    def register_network_callbacks(self):
        if self.network:
            # So we can get refresh our utxo lists as soon as the wallet is updated
            self.network.register_callback(self.on_network_callback, ["wallet_updated"])

    def unregister_network_callbacks(self):
        if self.network:
            # Undo the effects of registering the callback when it is no longer needed, in case this wallet is closed
            # later and this object dies (avoids dangling refs)
            self.network.unregister_callback(self.on_network_callback)

    def showEvent(self, event: QtGui.QShowEvent) -> None:
        super().showEvent(event)
        if event.isAccepted():
            self.did_warn_wallet_empty = False
            self.register_network_callbacks()
            self.refresh()
            if self.last_size:
                self.resize(self.last_size)

    def hideEvent(self, event: QtGui.QCloseEvent) -> None:
        super().hideEvent(event)
        if event.isAccepted():
            self.last_size = self.size()
            self.unregister_network_callbacks()
