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
        results = None
        def resolve_verify():
            nonlocal results
            results = wallet.cashacct.resolve_verify(name)
        code = VerifyingDialog(parent.top_level_window(),
                               _("Verifying Cash Account {name}, please wait ...").format(name=name),
                               resolve_verify, auto_show=False).exec_()
        if code == QDialog.Rejected:
            # user cancel operation
            return
        if not results:
            raise Bad(_("Cash Account not found: {name}").format(name=name) + "\n\n"
                      + _("Could not find the Cash Account name specified. "
                          "It either does not exist or there may have been a network connectivity error. "
                          "Please double-check it and try again."))
        if len(results) > 1:
            tup = multiple_result_picker(parent=parent, wallet=wallet, results=results)
            if not tup:
                # user cancel
                return
            results = [tup]
        info, mch = results[0]
        name = wallet.cashacct.fmt_info(info, mch)
        if not isinstance(info.address, Address):
            raise Bad(_("Unsupported payment data type.") + "\n\n"
                      + _("The Cash Account {name} uses an account type that "
                          "is not supported by Electron Cash.").format(name=name))
        return info, name
    except Bad as e:
        parent.show_error(str(e))
    return None

def multiple_result_picker(parent, results, wallet=None, msg=None, title=None, gbtext=None):
    assert parent
    from .main_window import ElectrumWindow
    if isinstance(parent, ElectrumWindow) and not wallet:
        wallet = parent.wallet
    assert wallet

    # sort results by formatted cash account string, also adding the string to
    # the results tuples; tuples now are modified to 3 elements:
    # (info, min_chash, formatted_ca_string)
    formatter = lambda x: (x[0], x[1], wallet.cashacct.fmt_info(x[0], x[1]))
    results = sorted((formatter(x) for x in results), key=lambda tup:tup[2])
    msg = msg or _('Multiple results were found, please select an option from the items below:')
    title = title or _("Select Cash Account")
    gbtext = gbtext or _("{number} Cash Account(s)").format(number=len(results))

    d = WindowModalDialog(parent, title)
    util.finalization_print_error(d)  # track object lifecycle
    destroyed_print_error(d)

    vbox = QVBoxLayout(d)
    lbl = WWLabel(msg)
    vbox.addWidget(lbl)

    gb = QGroupBox(gbtext)
    vbox.addWidget(gb)

    grid = QGridLayout(gb)
    but_grp = QButtonGroup(gb)
    row, col = -1, 0
    cols = 2


    class AssociatedLabel(QLabel):

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.but = None
            self.setTextInteractionFlags(self.textInteractionFlags() | Qt.TextSelectableByMouse)

        def setBut(self, b): self.but = b

        def mouseReleaseEvent(self, e):
            super().mouseReleaseEvent(e)
            if self.but:
                if self.but.isEnabled():
                    self.but.click()
                elif self.but.toolTip() and not self.hasSelectedText():
                    QToolTip.showText(QCursor.pos(), self.but.toolTip(), self)


    def view_tx_link_activated(txid):
        if isinstance(parent, ElectrumWindow):
            parent.do_process_from_txid(txid=txid, tx_desc=wallet.get_label(txid))

    grid.setVerticalSpacing(4)

    for i, item in enumerate(results):
        col = col % cols
        if not col:
            row += 1
        info, min_chash, ca_string = item
        # Radio button (by itself in colum 0)
        rb = QRadioButton()
        is_valid = True
        if not isinstance(info.address, Address):
            rb.setDisabled(True)
            is_valid = False
            rb.setToolTip(_('Electron Cash currently only supports Cash Account types 1 & 2'))
        but_grp.addButton(rb, i)
        grid.addWidget(rb, row*3, col*4, 1, 1)
        pretty_string = info.emoji + " " + ca_string[:-1]
        chash_extra = info.collision_hash[len(min_chash):]
        if not min_chash:
            chash_extra = "." + chash_extra

        # Cash Account name
        ca_lbl = AssociatedLabel(f'<b>{pretty_string}</b><font size=-1><i>{chash_extra}</i></font><b>;</b>')
        ca_lbl.setBut(rb)
        grid.addWidget(ca_lbl, row*3, col*4+1, 1, 1)

        # View tx ...
        viewtx = _("View tx")
        view_tx_lbl = WWLabel(f'<font size=-1><a href="{info.txid}">{viewtx}...</a></font>')
        grid.addWidget(view_tx_lbl, row*3, col*4+2, 1, 1)

        # copy button
        copy_but = QPushButton(QIcon(":icons/copy.png"), "")
        copy_but.setFlat(True)
        grid.addWidget(copy_but, row*3, col*4+3, 1, 1)

        if isinstance(parent, ElectrumWindow):
            view_tx_lbl.linkActivated.connect(view_tx_link_activated)
            copy_but.clicked.connect(lambda ignored=None, ca_string=ca_string, copy_but=copy_but:
                                         parent.copy_to_clipboard(text=ca_string, tooltip=_('Cash Account copied to clipboard'), widget=copy_but) )
        else:
            view_tx_lbl.setHidden(True)
            copy_but.setHidden(True)

        addr_lbl = AssociatedLabel('')
        addr_lbl.setBut(rb)
        if is_valid:
            addr_lbl.setText(f'{info.address.to_ui_string()}')
        else:
            addr_lbl.setText('<i>' + _('Unsupported Account Type') + '</i>')
            addr_lbl.setToolTip(rb.toolTip())
        grid.addWidget(addr_lbl, row*3+1, col*4+1, 1, 3)

        spacer = QSpacerItem(1, 8)
        grid.addItem(spacer, row*3+2, col*4, 1, 4)

        col += 1

    ok_but = OkButton(d)
    buts = Buttons(CancelButton(d), ok_but)
    vbox.addLayout(buts)
    ok_but.setEnabled(False)

    but_grp.buttonClicked.connect(lambda x: ok_but.setEnabled(True))

    code = d.exec_()

    if code == QDialog.Accepted:
        which = but_grp.checkedId()
        if which > -1 and which < len(results):
            return results[which][:-1]
