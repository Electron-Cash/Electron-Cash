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

import os
import threading
import weakref

from collections import namedtuple
from typing import Optional

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QFont

from electroncash import token, util
from electroncash.i18n import _
from electroncash.token_meta import DownloadedMetaData, try_to_download_metadata
from .main_window import ElectrumWindow
from .util import HelpLabel, MessageBoxMixin, MONOSPACE_FONT, OnDestroyedMixin, PrintError
from .token_meta import TokenMetaQt

MAX_UI_DECIMALS = len(str(2**63 - 1))
ICON_BUT_SIZE = 64


class TokenMetaEditorForm(QtWidgets.QWidget, MessageBoxMixin, PrintError, OnDestroyedMixin):
    sig_got_bcmr = QtCore.pyqtSignal(object)
    sig_error_bcmr = QtCore.pyqtSignal()

    def __init__(self, parent: QtWidgets.QWidget, token_id: str, *,
                 flags=None, window: Optional[ElectrumWindow] = None):
        window = window or parent
        assert isinstance(window, ElectrumWindow)
        if flags:
            super().__init__(parent=parent, flags=flags)
        else:
            super().__init__(parent=parent)
        MessageBoxMixin.__init__(self)
        PrintError.__init__(self)
        OnDestroyedMixin.__init__(self)
        util.finalization_print_error(self)
        self.window: ElectrumWindow = window
        self.token_meta: TokenMetaQt = self.window.token_meta
        self.token_id = token_id
        self.bcmr_downloaded: Optional[DownloadedMetaData] = None

        self.setWindowTitle(_("Edit Token Properties") + f" - {self.token_id}")
        self.setWindowIcon(self.token_meta.get_icon(self.token_id))

        # Remember what the state of things was when this form was created
        RV = namedtuple("reset", "name, ticker, decimals, icon")
        self.reset_vals = RV(
            name=self.token_meta.get_token_display_name(self.token_id) or "",
            ticker=self.token_meta.get_token_ticker_symbol(self.token_id) or "",
            decimals=self.token_meta.get_token_decimals(self.token_id) or 0,
            icon=self.token_meta.get_icon(self.token_id) or QtGui.QIcon(),
        )
        self.selected_icon = self.reset_vals.icon

        layout = QtWidgets.QFormLayout(self)
        layout.setFieldGrowthPolicy(layout.ExpandingFieldsGrow)

        tt = _("Category ID (Token ID)")
        help_text = _("This token derived its Category ID (aka Token ID) from the tx hash"
                      " of the \"xxx:0\" coin that was used to create it.  Once set at token genesis, this ID is"
                      " fixed forever and cannot be edited.")
        l = HelpLabel(_("Category ID") + ":", help_text)
        l.setToolTip(tt)
        self.lbl_category_id = l2 = QtWidgets.QLabel(self.token_id)
        l2.setToolTip(tt)
        f = QFont(MONOSPACE_FONT)
        f.setBold(True)
        l2.setFont(f)
        l2.setTextInteractionFlags(l2.textInteractionFlags() | QtCore.Qt.TextSelectableByMouse)
        a = QtWidgets.QAction(_("Copy Category ID"), self)
        a.triggered.connect(lambda: self.window.copy_to_clipboard(self.token_id))
        l.addAction(a)
        l2.addAction(a)
        l.setContextMenuPolicy(QtCore.Qt.ActionsContextMenu)
        l2.setContextMenuPolicy(QtCore.Qt.ActionsContextMenu)
        layout.addRow(l, l2)

        help_text = _("The token icon is used in the UI to decorate all tokens sharing this Category ID."
                      "  This field is local to this installation of Electron Cash and is for UI convenience only.")
        tt = _("The icon to assign to this token")
        l = HelpLabel(_("Token Icon") + ":", help_text)
        l.setToolTip(tt)
        hbox = QtWidgets.QHBoxLayout()
        hbox.setContentsMargins(0, 0, 0, 0)
        self.but_icon = QtWidgets.QPushButton()
        self.but_icon.setFixedSize(ICON_BUT_SIZE, ICON_BUT_SIZE)
        self.but_icon.setIconSize(QtCore.QSize(ICON_BUT_SIZE, ICON_BUT_SIZE))
        self.but_icon.setToolTip(tt + ";  " + _("Click to change"))
        self.but_icon.setFlat(True)
        self.but_icon.resize(ICON_BUT_SIZE, ICON_BUT_SIZE)
        self.but_icon.clicked.connect(self.on_but_icon)
        hbox.setAlignment(self.but_icon, QtCore.Qt.AlignTop | QtCore.Qt.AlignCenter)
        hbox.addWidget(self.but_icon)
        vbox = QtWidgets.QVBoxLayout()
        vbox.setSpacing(1)
        vbox.setContentsMargins(0, 0, 0, 0)
        but_chg = QtWidgets.QPushButton(_("Change Icon..."))
        but_chg.clicked.connect(self.on_but_icon)
        vbox.addWidget(but_chg)
        but_def = QtWidgets.QPushButton(_("Set to Auto-Gen"))
        but_def.setToolTip(_("Click to clear the icon and assign it an auto-generated deterministic value"))
        f = but_def.font()
        f.setStretch(f.SemiCondensed)
        f.setPointSize(f.pointSize() - 1)
        but_def.setFont(f)
        but_chg.setFont(f)

        def reset_to_autogen():
            self.selected_icon = self.token_meta.gen_default_icon(self.token_id)
            self.but_icon.setIcon(self.selected_icon)
        but_def.clicked.connect(reset_to_autogen)
        vbox.addWidget(but_def)
        hbox.addLayout(vbox)
        hbox.setAlignment(vbox, QtCore.Qt.AlignBottom | QtCore.Qt.AlignCenter)
        layout.addRow(l, hbox)
        layout.setAlignment(l, QtCore.Qt.AlignTop | QtCore.Qt.AlignRight)

        help_text = _("The token name is the display name that will be used in Electron Cash to refer to this token."
                      "  It is local to this installation of Electron Cash and is for UI convenience only.")
        tt = _("Token name used for UI display within Electron Cash")
        l = HelpLabel(_("Token Name") + ":", help_text)
        l.setToolTip(tt)
        self.le_token_name = QtWidgets.QLineEdit()
        self.le_token_name.setToolTip(tt)
        self.le_token_name.setPlaceholderText(_("Satoshi's Token"))
        self.le_token_name.textChanged.connect(self.on_edit_token_name)
        layout.addRow(l, self.le_token_name)

        help_text = _("The token symbol should be a short acronym for the token, as would appear on an exchange."
                      "  This field is local to this installation of Electron Cash and is for UI convenience only.")
        tt = _("Token symbol used for UI display within Electron Cash")
        l = HelpLabel(_("Token Symbol") + ":", help_text)
        l.setToolTip(tt)
        self.le_token_sym = QtWidgets.QLineEdit()
        self.le_token_sym.setToolTip(tt)
        self.le_token_sym.setPlaceholderText(_("ST"))
        layout.addRow(l, self.le_token_sym)

        help_text = (_("The token decimals is an integer from 0 to {max}.  It controls how the token's fungible amount"
                       " is formatted within Electron Cash."
                       "  This field is local to this installation of Electron Cash and is for UI convenience only.")
                     .format(max=MAX_UI_DECIMALS))
        tt = _("Controls how to format token fungible amounts in the UI")
        l = HelpLabel(_("Token Decimals") + ":", help_text)
        l.setToolTip(tt)
        self.sb_token_dec = QtWidgets.QSpinBox()
        self.sb_token_dec.setToolTip(tt)
        self.sb_token_dec.setMinimum(0)
        self.sb_token_dec.setMaximum(MAX_UI_DECIMALS)
        hbox = QtWidgets.QHBoxLayout()
        hbox.setContentsMargins(0, 0, 0, 0)
        self.l_token_sym_dec_example = QtWidgets.QLabel()
        self.l_token_sym_dec_example.setToolTip(_("Sample of how this setting will look in the UI"))
        hbox.addWidget(self.sb_token_dec)
        hbox.addWidget(self.l_token_sym_dec_example)
        self.sb_token_dec.valueChanged.connect(self.update_token_dec_example)
        self.update_token_dec_example(self.sb_token_dec.value())
        # Formats label with whatever is in settings
        layout.addRow(l, hbox)

        # BCMR auto-downloder
        help_text = _("BCMR Metadata comes from the OP_RETURN of the token's genesis tx. If found, Electron Cash"
                      " will download this data, and you can apply it as metadata for this category ID"
                      " in this window.")
        tt = _("Metadata from the network")
        l = HelpLabel(_("BCMR Metadata") + ":", help_text)
        self.lbl_dl_bcmr = l2 = QtWidgets.QLabel()
        l2.linkActivated.connect(self.on_apply_bcmr)
        layout.addRow(l, l2)

        # Bottom buttons
        layout.addItem(QtWidgets.QSpacerItem(0, 12, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding))
        hbox = QtWidgets.QHBoxLayout()
        hbox.setContentsMargins(0, 0, 0, 0)
        clear_but = QtWidgets.QPushButton(_("Reset"))
        clear_but.setToolTip(_("Reset this form to its initial state"))
        clear_but.clicked.connect(self.reset_form)
        hbox.addWidget(clear_but)
        hbox.addStretch(2)
        clz = QtWidgets.QDialogButtonBox
        buttons = QtWidgets.QDialogButtonBox(clz.Cancel | clz.Ok)
        buttons.accepted.connect(self.on_ok_button)
        buttons.rejected.connect(self.on_close_button)
        hbox.addWidget(buttons, 1, QtCore.Qt.AlignRight)
        layout.addRow(hbox)

        self.sig_got_bcmr.connect(self.on_bcmr)
        self.sig_error_bcmr.connect(self.on_bcmr_error)

        self.reset_form()

    def on_bcmr(self, bcmr: DownloadedMetaData):
        self.lbl_dl_bcmr.setText(_("Downloaded BCMR data for this token from the network."
                                   "  <a href='apply'>Click here to apply it...</a>"))
        self.bcmr_downloaded = bcmr

    def on_apply_bcmr(self):
        assert threading.current_thread() is threading.main_thread()
        if self.bcmr_downloaded:
            self.lbl_category_id.setFocus()
            self.le_token_name.setText(self.bcmr_downloaded.name)
            self.le_token_sym.setText(self.bcmr_downloaded.symbol)
            self.sb_token_dec.setValue(min(self.sb_token_dec.maximum(),
                                           max(self.sb_token_dec.minimum(), self.bcmr_downloaded.decimals)))
            if self.bcmr_downloaded.icon:

                # TODO: if svgs won't load on meta edit, try loading from icon directly 
                # if(self.bcmr_downloaded.icon_ext == ".svg"):
                #     icon = QtGui.QIcon(QtGui.QPixmap.fromImage(QtGui.QImage.fromData(self.bcmr_downloaded.icon)))    
                #     self.but_icon.setIcon(icon)
                #     self.selected_icon = icon
                # else:                

                # e.g.: /path/to/tmp/XXXXXX.svg
                f = QtCore.QTemporaryFile(os.path.join(QtCore.QDir.tempPath(), "XXXXXX") 
                                        + (self.bcmr_downloaded.icon_ext or ''))
                if f.open():
                    f.writeData(self.bcmr_downloaded.icon)
                    f.flush()
                    icon = QtGui.QIcon(f.fileName())
                    self.but_icon.setIcon(icon)
                    self.selected_icon = icon

    def on_bcmr_error(self):
        assert threading.current_thread() is threading.main_thread()
        self.lbl_dl_bcmr.setText(_("BCMR data not available for this category ID."))

    def do_bcmr_data_download(self):
        self.lbl_dl_bcmr.setText(_("Checking for BCMR data from the network ..."))
        weak_self = weakref.ref(self)

        def threadfunc(wallet, token_id):
            try:
                bcmr = try_to_download_metadata(wallet, token_id)
            except Exception as e:
                util.print_error(repr(e))
                bcmr = None
            slf = weak_self and weak_self()
            if slf and slf.isVisible():
                if bcmr:
                    slf.sig_got_bcmr.emit(bcmr)
                else:
                    slf.sig_error_bcmr.emit()

        t = threading.Thread(target=threadfunc, daemon=True, args=(self.window.wallet, self.token_id,))
        t.start()

    def showEvent(self, evt: QtGui.QShowEvent):
        super().showEvent(evt)
        if evt.isAccepted():
            self.do_bcmr_data_download()

    def on_ok_button(self):
        tid = self.token_id
        self.token_meta.set_icon(tid, self.selected_icon if not self.selected_icon.isNull() else None)
        self.token_meta.set_token_display_name(tid, self.le_token_name.text().strip() or None)
        self.token_meta.set_token_ticker_symbol(tid, self.le_token_sym.text().strip() or None)
        self.token_meta.set_token_decimals(tid, self.sb_token_dec.value() or None)
        self.token_meta.save()
        self.close()
        self.window.gui_object.token_metadata_updated_signal.emit(tid)

    def on_close_button(self):
        self.close()

    def on_but_icon(self):
        fn, filt = QtWidgets.QFileDialog.getOpenFileName(self, _("Open icon file"), "",
                                                         "Images (*.png *.svg *.jpg *.jpeg *.ico)")
        if not fn:
            return
        icon = QtGui.QIcon(fn)
        if icon.isNull():
            return
        # Scale it for this button
        self.but_icon.setIcon(icon)
        self.selected_icon = icon

    def update_token_dec_example(self, num_decimals):
        val = 2**63 - 1
        fmt = token.format_fungible_amount(val, decimal_point=num_decimals, precision=num_decimals)
        if fmt.endswith('.'):
            fmt = fmt[:-1]
        example = _("Example") + "<font face='" + MONOSPACE_FONT + "'>:&nbsp;" + fmt + "</font>"
        self.l_token_sym_dec_example.setText(example)

    def on_edit_token_name(self):
        """Automagically sets the token symbol for a user if they never edited the token symbol field,
        and they begin typing in the token name field"""
        if self.le_token_sym.isModified():
            return
        auto_acronym = ''
        for word in self.le_token_name.text().strip().split():
            if word:
                ch = word[0].upper()
                if ch >= 'A' and ch <= 'Z':
                    auto_acronym += ch
        self.le_token_sym.setText(auto_acronym)

    def reset_form(self):
        rv = self.reset_vals
        self.le_token_sym.setText(rv.ticker)
        self.le_token_sym.setModified(len(self.le_token_sym.text().strip()) > 0)
        self.le_token_name.setText(rv.name)
        self.sb_token_dec.setValue(rv.decimals)
        self.selected_icon = rv.icon
        self.but_icon.setIcon(self.selected_icon)
