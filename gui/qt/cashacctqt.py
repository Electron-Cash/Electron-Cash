##!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Electron Cash - A Bitcoin Cash SPV Wallet
# This file Copyright (c) 2019 Calin Culianu <calin.culianu@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

'''
Cash Accounts related classes and functions - Qt UI related.
'''

# TODO: whittle these * imports down to what we actually use
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from .util import *

from typing import Tuple
from electroncash import cashacct
from electroncash import util
from electroncash.address import Address, UnknownAddress
from electroncash.i18n import _


class VerifyingDialog(WaitingDialog):

    def __init__(self, parent, message, task, on_success=None, on_error=None, auto_cleanup=True,
                 *, auto_show=True, auto_exec=False, title=None, disable_escape_key=False):
        super().__init__(parent, message, task, on_success=on_success,
                         on_error=on_error, auto_cleanup=auto_cleanup,
                         auto_show=False, auto_exec=False,
                         title=title or _('Verifying Cash Account'),
                         disable_escape_key=disable_escape_key)
        hbox = QHBoxLayout()
        self._vbox.removeWidget(self._label)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(QIcon(":icons/cashacct-logo.png").pixmap(50))
        hbox.addWidget(icon_lbl)
        hbox.addWidget(self._label)
        self._vbox.addLayout(hbox)
        prog = QProgressBar()
        prog.setRange(0,0)
        self._vbox.addWidget(prog)
        if auto_show and not auto_exec:
            self.open()
        elif auto_exec:
            self.exec_()


def resolve_cashacct(parent : MessageBoxMixin, name : str, wallet=None) -> Tuple[cashacct.Info, str]:
    ''' Throws up a WaitingDialog while it resolves a Cash Account.

    Goes out to network, verifies all tx's.

    Returns: a tuple of: (Info, Minimally_Encoded_Formatted_AccountName)

    Argument `name` should be a Cash Account name string of the form:

      name#number.123
      name#number
      name#number.;  etc

    If the result would be ambigious, that is considered an error, so enough
    of the account name#number.collision_hash needs to be specified to
    unambiguously resolve the Cash Account.

    On failure throws up an error window and returns None.'''
    from .main_window import ElectrumWindow
    if isinstance(parent, ElectrumWindow) and not wallet:
        wallet = parent.wallet
    assert wallet
    class Bad(Exception): pass
    try:
        if not wallet.network or not wallet.network.interface:
            raise Bad(_("Cannot verify Cash Account as the network appears to be offline."))
        ca_tup = wallet.cashacct.parse_string(name)
        if not ca_tup:
            raise Bad(_("Invalid Cash Account name specified: {name}").format(name=name))
        info_min = None
        def resolve_verify():
            nonlocal info_min
            info_min = wallet.cashacct.resolve_verify(name, skip_caches=True)
        code = VerifyingDialog(parent.top_level_window(),
                               _("Verifying Cash Account {name}, please wait ...").format(name=name),
                               resolve_verify, auto_show=False).exec_()
        if code == QDialog.Rejected:
            # user cancel operation
            return
        if not info_min:
            raise Bad(_("Cash Account not found or ambiguous: {name}").format(name=name) + "\n\n"
                      + _("Could not find the Cash Account name specified. "
                          "It either does not exist or requires more collision hash characters to be resolved. "
                          "Please double-check it and try again."))
        info, mch = info_min
        name = wallet.cashacct.fmt_info(info, mch)
        if not isinstance(info.address, Address):
            raise Bad(_("Unsupported payment data type.") + "\n\n"
                      + _("The Cash Account {name} uses an account type that "
                          "is not supported by Electron Cash.").format(name=name))
        return info, name
    except Bad as e:
        parent.show_error(str(e))
    return None
