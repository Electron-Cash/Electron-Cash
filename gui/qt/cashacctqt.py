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

from typing import Tuple, List
from enum import IntEnum
from electroncash import cashacct
from electroncash import util
from electroncash.address import Address, UnknownAddress
from electroncash.i18n import _
from electroncash.wallet import Abstract_Wallet


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


def resolve_cashacct(parent : MessageBoxMixin, name : str, wallet : Abstract_Wallet = None) -> Tuple[cashacct.Info, str]:
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
    assert isinstance(wallet, Abstract_Wallet)
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


class ButtonAssociatedLabel(QLabel):
    ''' A QLabel, that if clicked on, sends a 'click()' call to an associated
    QAbstractButton. '''

    def __init__(self, *args, **kwargs):
        but = kwargs.pop('button', None)
        super().__init__(*args, **kwargs)
        self.but = but
        self.setTextInteractionFlags(self.textInteractionFlags() | Qt.TextSelectableByMouse)

    def setButton(self, b : QAbstractButton): self.but = b
    def button(self) -> QAbstractButton: return self.but

    def mouseReleaseEvent(self, e):
        super().mouseReleaseEvent(e)
        if self.but:
            if self.but.isEnabled():
                self.but.click()
            elif self.but.toolTip() and not self.hasSelectedText():
                QToolTip.showText(QCursor.pos(), self.but.toolTip(), self)


class InfoGroupBox(PrintError, QGroupBox):

    class ButtonType(IntEnum):
        NoButton = 0  # If this is specified to button_type, then the buttons will be hidden. selectedItem and selectedItems will have undefined results.
        Radio    = 1  # If specified, the on-screen buttons will be QRadioButtons and selectedItems() will always have 0 or 1 item.
        CheckBox = 2  # If specified, the on-screen buttons will be QCheckBox and selectedItems() may be a list of more than 1 result

    def __init__(self,
                 parent : QWidget,  # widget parent for layout/embedding/etc
                 main_window : MessageBoxMixin,  # may be same as 'parent'; will raise if not an ElectrumWindow instance
                 items: List[Tuple[cashacct.Info, str, str]] = [], # list of 2 or 3 tuple : Info, minimal_chash[, formatted_string]
                 title : str = None,
                 button_type : ButtonType = ButtonType.Radio,  # Note that if CheckBox, the buttonGroup will be made non-exclusive and selectedItems() may return more than 1 item.
                 ):
        from .main_window import ElectrumWindow
        assert isinstance(main_window, ElectrumWindow)
        super().__init__(parent)
        self.main_window = main_window
        self.wallet = self.main_window.wallet
        assert isinstance(self.wallet, Abstract_Wallet)
        self._setup()
        self.setItems(items=items, title=title, auto_resize_parent=False, button_type=button_type)

    def _setup(self):
        self.grid = QGridLayout(self)  # client code shouldn't use this
        self._but_grp = QButtonGroup(self)  # client code shouldn't use this but instead use selectedItems(), etc
        self.cols = 2  # client code may set this but needs to call refresh()
        self.no_items_text = _('No Cash Accounts')  # client code may set this directly

    def setItems(self,
                 items : List[Tuple[cashacct.Info, str, str]],  # list of 2 or 3 tuple : Info, minimal_chash[, formatted_string]
                 title = None, auto_resize_parent = True, sort=True,
                 button_type : ButtonType = ButtonType.Radio):
        items = items or []
        title = title or _("{number} Cash Account(s)").format(number=len(items))
        wallet = self.wallet
        if items and (sort or len(items[0]) != 3):
            # sort items by formatted cash account string, also adding the string to
            # the items tuples; tuples now are modified to 3 elements:
            # (info, min_chash, formatted_ca_string)
            formatter = lambda x: (x[0], x[1], wallet.cashacct.fmt_info(x[0], x[1]))
            if sort:
                items = sorted((formatter(x) for x in items), key=lambda tup:tup[2])
            else:
                items = [formatter(x) for x in items]
        self._items = items
        self.button_type = button_type
        self.setTitle(title)
        self.refresh()
        if auto_resize_parent and self.parent():
            weakParent = util.Weak.ref(self.parent())
            QTimer.singleShot(0, lambda: weakParent() and weakParent().resize(weakParent().sizeHint()))

    def buttonGroup(self) -> QButtonGroup:
        ''' The button group id's will point to indices in self.items() '''
        return self._but_grp

    def checkItemWithInfo(self, info : cashacct.Info):
        ''' Pass an info object and the item that corresponds to that
        Info object will be checked. Pass None to uncheck all items. '''
        for i, item in enumerate(self._items):
            if info is None:
                self._but_grp.button(i).setChecked(False)
            elif item[0] == info:
                self._but_grp.button(i).setChecked(True)

    def items(self) -> List[Tuple[cashacct.Info, str, str]]:
        ''' The list of items on-screen. self.buttonGroup()'s ids will point
        to indices in this list.

        Returned list items are 3-tuples of:
           (Info, min_chash: str, fmtd_acct_name: str) '''
        return self._items

    def selectedItem(self) -> Tuple[cashacct.Info, str, str]:
        ''' Returns the currently selected item tuple or None if none is selected '''
        items = self.selectedItems()
        if items:
            return items[0]

    def selectedItems(self) -> List[Tuple[cashacct.Info, str, str]]:
        ''' In multi-select mode (CheckBox mode), returns the currently selected
        items as a list of 3-tuple. '''
        ret = []
        buts = self._but_grp.buttons()
        for but in buts:
            if but.isChecked():
                which = self._but_grp.id(but)
                if which > -1 and which < len(self._items):
                    ret.append(self._items[which])
        return ret

    def refresh(self):
        from .main_window import ElectrumWindow
        parent = self.main_window
        wallet = self.wallet
        items = self._items
        button_type = self.button_type
        assert all(len(x) == 3 for x in items)
        but_grp = self._but_grp
        cols, col, row = self.cols, 0, -1
        grid = self.grid

        # save selection
        saved_selection = [tup[0] for tup in self.selectedItems()]

        # clear existing subwidges on refresh
        for c in self.children():
            if isinstance(c, QWidget):
                if isinstance(c, QAbstractButton):
                    but_grp.removeButton(c)
                grid.removeWidget(c)
                c.setParent(None)

        def view_tx_link_activated(txid):
            if isinstance(parent, ElectrumWindow):
                parent.do_process_from_txid(txid=txid, tx_desc=wallet.get_label(txid))

        def view_addr_link_activated(addr):
            if isinstance(parent, ElectrumWindow):
                try:
                    address = Address.from_string(addr)
                    parent.show_address(address, parent=parent.top_level_window())
                except Exception as e:
                    parent.print_error(repr(e))



        if button_type == __class__.ButtonType.CheckBox:
            BUTTON_CLASS = QCheckBox
            but_grp.setExclusive(False)
        else:
            BUTTON_CLASS = QRadioButton
            but_grp.setExclusive(True)
        hide_but = button_type == __class__.ButtonType.NoButton

        grid.setVerticalSpacing(4)

        if not items:
            label = WWLabel("<i>" + self.no_items_text + "</i>")
            label.setAlignment(Qt.AlignCenter)
            grid.addWidget(label, 0, 0, -1, -1)


        for i, item in enumerate(items):
            col = col % cols
            if not col:
                row += 1
            info, min_chash, ca_string = item
            # Radio button (by itself in colum 0)
            rb = BUTTON_CLASS()
            rb.setHidden(hide_but)
            rb.setDisabled(hide_but)  # hidden buttons also disabled to prevent user clicking their labels to select them
            is_valid = True
            is_mine = False
            is_change = False
            if not isinstance(info.address, Address):
                rb.setDisabled(True)
                is_valid = False
                rb.setToolTip(_('Electron Cash currently only supports Cash Account types 1 & 2'))
            elif wallet.is_mine(info.address):
                is_mine = True
                is_change = wallet.is_change(info.address)
            but_grp.addButton(rb, i)
            grid.addWidget(rb, row*3, col*4, 1, 1)
            pretty_string = info.emoji + " " + ca_string[:-1]
            chash_extra = info.collision_hash[len(min_chash):]
            if not min_chash:
                chash_extra = "." + chash_extra

            # Cash Account name
            ca_lbl = ButtonAssociatedLabel(f'<b>{pretty_string}</b><font size=-1><i>{chash_extra}</i></font><b>;</b>', button=rb)
            grid.addWidget(ca_lbl, row*3, col*4+1, 1, 1)

            # View tx ...
            viewtx = _("View tx")
            view_tx_lbl = WWLabel(f'<font size=-1><a href="{info.txid}">{viewtx}...</a></font>')
            grid.addWidget(view_tx_lbl, row*3, col*4+2, 1, 1)
            view_tx_lbl.setToolTip(_("View Registration Transaction"))

            # copy button
            copy_but = QPushButton(QIcon(":icons/copy.png"), "")
            copy_but.setFlat(True)
            grid.addWidget(copy_but, row*3, col*4+3, 1, 1)

            if isinstance(parent, ElectrumWindow):
                view_tx_lbl.linkActivated.connect(view_tx_link_activated)
                copy_but.clicked.connect(lambda ignored=None, ca_string=ca_string, copy_but=copy_but:
                                             parent.copy_to_clipboard(text=ca_string, tooltip=_('Cash Account copied to clipboard'), widget=copy_but) )
                copy_but.setToolTip(_("Copy Cash Account"))
            else:
                view_tx_lbl.setHidden(True)
                copy_but.setHidden(True)

            addr_lbl = ButtonAssociatedLabel('', button=rb)
            if is_valid:
                if is_mine:
                    addr_lbl.setText(f'<a href="{info.address.to_ui_string()}">{info.address.to_ui_string()}</a>')
                    addr_lbl.linkActivated.connect(view_addr_link_activated)
                    addr_lbl.setToolTip(_('Wallet') + ' - ' + (_('Change Address') if is_change else _('Receiving Address')))
                    addr_lbl.setButton(None)  # disable click to select
                else:
                    addr_lbl.setText(f'{info.address.to_ui_string()}')
            else:
                addr_lbl.setText('<i>' + _('Unsupported Account Type') + '</i>')
                addr_lbl.setToolTip(rb.toolTip())
            grid.addWidget(addr_lbl, row*3+1, col*4+1, 1, 3)

            spacer = QSpacerItem(1, 8)
            grid.addItem(spacer, row*3+2, col*4, 1, 4)

            col += 1

        if saved_selection and self.button_type != self.ButtonType.NoButton:
            for info in saved_selection:
                self.checkItemWithInfo(info)
        else:
            self.checkItemWithInfo(None)

def multiple_result_picker(parent, results, wallet=None, msg=None, title=None, gbtext=None):
    ''' Pops up a modal dialog telling you to pick a results. Used by the
    Contacts tab edit function, etc. '''
    assert parent
    from .main_window import ElectrumWindow
    if isinstance(parent, ElectrumWindow) and not wallet:
        wallet = parent.wallet
    assert isinstance(wallet, Abstract_Wallet)

    msg = msg or _('Multiple results were found, please select an option from the items below:')
    title = title or _("Select Cash Account")

    d = WindowModalDialog(parent, title)
    util.finalization_print_error(d)  # track object lifecycle
    destroyed_print_error(d)

    vbox = QVBoxLayout(d)
    lbl = WWLabel(msg)
    vbox.addWidget(lbl)

    gb = InfoGroupBox(d, parent, results)
    vbox.addWidget(gb)

    ok_but = OkButton(d)
    buts = Buttons(CancelButton(d), ok_but)
    vbox.addLayout(buts)
    ok_but.setEnabled(False)

    but_grp = gb.buttonGroup()
    but_grp.buttonClicked.connect(lambda x=None: ok_but.setEnabled(gb.selectedItem() is not None))

    code = d.exec_()

    if code == QDialog.Accepted:
        item = gb.selectedItem()
        if item:
            return item[:-1]
