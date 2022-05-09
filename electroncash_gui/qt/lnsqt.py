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
LNS related classes and functions - Qt UI related.
'''

# TODO: whittle these * imports down to what we actually use
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from .util import *
from .qrcodewidget import QRCodeWidget

import queue
import time
import requests
from typing import Callable, List, Optional, Tuple
from enum import IntEnum
from electroncash import lns
from electroncash import util
from electroncash import web
from electroncash.address import Address
from electroncash.i18n import _, ngettext
from electroncash.wallet import Abstract_Wallet

available = lns.available


class VerifyingDialog(WaitingDialog):

    def __init__(self, parent, message, task, on_success=None, on_error=None, auto_cleanup=True,
                 *, auto_show=True, auto_exec=False, title=None, disable_escape_key=False):
        main_thread_success_cb = lambda x: util.do_in_main_thread(on_success, x) if on_success else None
        main_thread_error_cb = lambda x: util.do_in_main_thread(on_error, x) if on_error else None
        super().__init__(parent, message, task, on_success=main_thread_success_cb,
                         on_error=main_thread_error_cb, auto_cleanup=auto_cleanup,
                         auto_show=False, auto_exec=False,
                         title=title or _('Verifying LNS Name'),
                         disable_escape_key=disable_escape_key)
        hbox = QHBoxLayout()
        self._vbox.removeWidget(self._label)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(QIcon(":icons/lns.png").pixmap(50))
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
        destroyed_print_error(self)


def verify_multiple_names(names : List[str], parent : MessageBoxMixin, wallet : Abstract_Wallet, timeout=10.0) -> int:
    ''' Pass a list of names and will attempt to verify them all in 1 pass.
    This is used by the Contacts tab to verify unverified LNS Names that
    may have been imported. Returns the number of successfully verified names
    or None on user cancel. '''
    if not len(names):
        return 0
    names = set(names)
    nnames = len(names)
    q = queue.Queue()
    def done_cb(thing):
        if isinstance(thing, (Exception, list)):
            q.put(thing)
        else:
            q.put(None)
    ctr = 0
    def thread_func():
        nonlocal ctr
        wallet.lns.verify_name_asynch(name=names, success_cb=done_cb, error_cb=done_cb, timeout=timeout)
        errs = 0
        while ctr + errs < nnames:
            try:
                thing = q.get(timeout=timeout)
                if thing is None:
                    errs += 1
                elif isinstance(thing, Exception):
                    raise thing
                else:
                    ctr += len(thing)
            except queue.Empty:
                return
    code = VerifyingDialog(parent.top_level_window(),
                           ngettext("Verifying {count} name please wait ...",
                                    "Verifying {count} names please wait ...", nnames).format(count=nnames),
                                    thread_func, auto_show=False, on_error=lambda e: parent.show_error(str(e))).exec_()
    if code != QDialog.Accepted:
        return None
    return ctr


def resolve_lns(parent: MessageBoxMixin, name: str, wallet: Abstract_Wallet = None) -> Optional[Tuple[lns.Info, str]]:
    ''' Throws up a WaitingDialog while it resolves an LNS Name.

    Goes out to network, verifies the name.

    Returns: a tuple of: (Info, lns_name)

    Argument `name` should be an LNS Name string of the form:

      satoshi.bch

    On failure throws up an error window and returns None.'''
    from .main_window import ElectrumWindow
    if isinstance(parent, ElectrumWindow) and not wallet:
        wallet = parent.wallet
    assert isinstance(wallet, Abstract_Wallet)
    class Bad(Exception): pass
    try:
        lns_tup = wallet.lns.parse_string(name)
        if not lns_tup:
            raise Bad(_("Invalid LNS Name specified: {name}").format(name=name))
        results = None
        def resolve_verify():
            nonlocal results
            results = wallet.lns.resolve_verify(name)
            if results:
                results = [(item, item.name) for item in results]
        code = VerifyingDialog(parent.top_level_window(),
                               _("Verifying LNS Name {name} please wait ...").format(name=name),
                               resolve_verify, on_error=lambda e: parent.show_error(str(e)), auto_show=False).exec_()
        if code == QDialog.Rejected:
            # user cancel operation
            return
        if not results:
            raise Bad(_("LNS Name not found: {name}").format(name=name) + "\n\n"
                      + _("Could not find the LNS Name specified. "
                          "It either does not exist or there may have been a network connectivity error. "
                          "Please double-check it and try again."))
        if len(results) > 1:
            tup = multiple_result_picker(parent=parent.top_level_window(), wallet=wallet, results=results)
            if not tup:
                # user cancel
                return
            results = [tup]
        info, _name = results[0]
        name = wallet.lns.fmt_info(info)
        if not isinstance(info.address, Address):
            raise Bad(_("Unsupported payment data type.") + "\n\n"
                      + _("The LNS Name {name} uses an account type that "
                          "is not supported by Electron Cash.").format(name=name))
        return info, info.name
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


def naked_button_style() -> str:
    ''' Returns a stylesheet for a small 'naked' (flat) QPushButton button which
    is used in the lookup results and other associated widgets in this file '''
    but_style_sheet = 'QPushButton { border-width: 1px; padding: 0px; margin: 0px; }'
    if not ColorScheme.dark_scheme:
        but_style_sheet += ''' QPushButton { border: 1px solid transparent; }
        QPushButton:hover { border: 1px solid #3daee9; }'''
    return but_style_sheet

def button_make_naked(but: QAbstractButton) -> QAbstractButton:
    ''' Just applied a bunch of things to a button to "make it naked"
    which is the look we use for the lookup results and various other odds and
    ends. Returns the button passed to it. '''
    but.setStyleSheet(naked_button_style())
    but.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    return but

class InfoGroupBox(PrintError, QGroupBox):

    class ButtonType(IntEnum):
        NoButton = 0  # If this is specified to button_type, then the buttons will be hidden. selectedItem and selectedItems will have undefined results.
        Radio    = 1  # If specified, the on-screen buttons will be QRadioButtons and selectedItems() will always have 0 or 1 item.
        CheckBox = 2  # If specified, the on-screen buttons will be QCheckBox and selectedItems() may be a list of more than 1 result

    def __init__(self,
                 parent : QWidget,  # widget parent for layout/embedding/etc
                 main_window : MessageBoxMixin,  # may be same as 'parent'; will raise if not an ElectrumWindow instance
                 items: List[Tuple[lns.Info, str]] = [], # list of 1 or 2 tuple : Info[, formatted_string]
                 title : str = None,
                 button_type : ButtonType = ButtonType.Radio,  # Note that if CheckBox, the buttonGroup will be made non-exclusive and selectedItems() may return more than 1 item.
                 extra_buttons : List[Callable[[Tuple[lns.Info, str]], QAbstractButton]] = [],  # pass a list of callables that take a 2-tuple for each item and return a button
                 show_addresses : bool = True,  # if False, the address label remains hidden
                 custom_contents_margins : Tuple[int] = None,  # if specified, use this as the contents margins for the internal layout widget
                 ):
        from .main_window import ElectrumWindow
        assert isinstance(main_window, ElectrumWindow)
        super().__init__(parent)
        self.main_window = main_window
        self.wallet = self.main_window.wallet
        self.extra_buttons = extra_buttons or []
        self.show_addresses = bool(show_addresses)
        if isinstance(custom_contents_margins, (tuple, list)) and len(custom_contents_margins) == 4 and all(isinstance(x, (int, float)) for x in custom_contents_margins):
            self.custom_contents_margins = custom_contents_margins
        else:
            self.custom_contents_margins = None
        assert isinstance(self.wallet, Abstract_Wallet)
        self._setup()
        self.setItems(items=items, title=title, auto_resize_parent=False, button_type=button_type)

    def _setup(self):
        self.w = QWidget(self)
        self.vbox = QVBoxLayout(self)
        self.vbox.setContentsMargins(0,0,0,0)
        self.vbox.addWidget(self.w)
        self._but_grp = QButtonGroup(self)  # client code shouldn't use this but instead use selectedItems(), etc
        self.no_items_text = _('No LNS Names')  # client code may set this directly

    def setItems(self,
                 items : List[Tuple[lns.Info, str]],  # list of 1 or 2 tuple : Info[, formatted_string]
                 title = None, auto_resize_parent = True, sort=True,
                 button_type : ButtonType = ButtonType.Radio):
        items = items or []
        nitems = len(items)
        title = ngettext("{number} LNS Name", "{number} LNS Names", nitems).format(number=nitems) if title is None else title
        wallet = self.wallet
        if items and (sort): #or len(items[0]) != 3):
            # sort items by formatted LNS Name string, also adding the string to
            # the items tuples; tuples now are modified to 2 elements:
            # (info, formatted_ca_string)
            formatter = lambda x: (x[0], wallet.lns.fmt_info(x[0]))
            if sort:
                items = sorted((formatter(x) for x in items), key=lambda tup:tup[1])
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

    def checkItemWithInfo(self, info : lns.Info):
        ''' Pass an info object and the item that corresponds to that
        Info object will be checked. Pass None to uncheck all items. '''
        for i, item in enumerate(self._items):
            if info is None:
                self._but_grp.button(i).setChecked(False)
            elif item[0] == info:
                self._but_grp.button(i).setChecked(True)

    def items(self) -> List[Tuple[lns.Info, str]]:
        ''' The list of items on-screen. self.buttonGroup()'s ids will point
        to indices in this list.

        Returned list items are 2-tuples of:
           (Info, fmtd_lns_name: str) '''
        return self._items

    def selectedItem(self) -> Tuple[lns.Info, str]:
        ''' Returns the currently selected item tuple or None if none is selected '''
        items = self.selectedItems()
        if items:
            return items[0]

    def selectedItems(self) -> List[Tuple[lns.Info, str]]:
        ''' In multi-select mode (CheckBox mode), returns the currently selected
        items as a list of 2-tuple. '''
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
        assert all(len(x) == 2 for x in items)
        but_grp = self._but_grp
        cols, col, row = 2, 0, -1

        if self.w:
            # save selection
            saved_selection = [tup[0] for tup in self.selectedItems()]
            # tear down the dummy container widget from before and everything
            # in it
            for c in self.findChildren(QAbstractButton, "InfoGroupBoxButton"):
                if isinstance(c, QAbstractButton):
                    but_grp.removeButton(c)
            self.w.hide()
            self.vbox.removeWidget(self.w)
            self.w.setParent(None)
            self.w.deleteLater()
            self.w = None
        self.w = w = QWidget(self)
        self.vbox.addWidget(w)

        grid = QGridLayout(w)

        if self.custom_contents_margins:
            grid.setContentsMargins(*self.custom_contents_margins)

        def details_link_activated(lnsstr):
            if isinstance(parent, ElectrumWindow):
                lns_detail_dialog(parent, lnsstr)

        def view_addr_link_activated(addr):
            if isinstance(parent, ElectrumWindow):
                try:
                    address = Address.from_string(addr)
                    parent.show_address(address, parent=parent.top_level_window())
                except Exception as e:
                    parent.print_error(repr(e))


        # We do it this way with BUTTON_FACTORY in case we want to expand
        # this facility later to generate even more dynamic buttons.
        if button_type == __class__.ButtonType.CheckBox:
            BUTTON_FACTORY = lambda *args: QCheckBox()
            but_grp.setExclusive(False)
        else:
            BUTTON_FACTORY = lambda *args: QRadioButton()
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
            info, lns_string = item
            lns_string_em = info.name
            # Radio button (by itself in colum 0)
            rb = BUTTON_FACTORY(info, "", lns_string, lns_string_em)
            rb.setObjectName("InfoGroupBoxButton")
            rb.setHidden(hide_but)
            rb.setDisabled(hide_but)  # hidden buttons also disabled to prevent user clicking their labels to select them
            is_valid = True
            is_mine = False
            is_change = False
            assert isinstance(info.address, Address)
            if wallet.is_mine(info.address):
                is_mine = True
                is_change = wallet.is_change(info.address)
            but_grp.addButton(rb, i)
            grid.addWidget(rb, row*3, col*5, 1, 1)
            pretty_string = lns_string

            # LNS Name
            lns_lbl = ButtonAssociatedLabel(f'<b>{pretty_string}</b>', button=rb)
            grid.addWidget(lns_lbl, row*3, col*5+1, 1, 1)

            # Details
            details = _("Details")
            details_lbl = WWLabel(f'<font size=-1><a href="{lns_string}">{details}...</a></font>')
            details_lbl.setToolTip(_("View Details"))
            grid.addWidget(details_lbl, row*3, col*5+2, 1, 1)

            # misc buttons
            hbox = QHBoxLayout()
            hbox.setContentsMargins(0,0,0,0)
            hbox.setSpacing(4)
            for func in self.extra_buttons:
                if callable(func):
                    ab = func(item)
                    if isinstance(ab, QAbstractButton):
                        button_make_naked(ab)
                        hbox.addWidget(ab)
            # copy button
            copy_but = QPushButton(QIcon(":icons/copy.png"), "")
            button_make_naked(copy_but)
            hbox.addWidget(copy_but)
            grid.addLayout(hbox, row*3, col*5+3, 1, 1)
            # end button bar

            if isinstance(parent, ElectrumWindow):
                details_lbl.linkActivated.connect(details_link_activated)
                copy_but.clicked.connect(lambda ignored=None, name=lns_string_em, copy_but=copy_but:
                                             parent.copy_to_clipboard(text=name, tooltip=_('LNS Name copied to clipboard'), widget=copy_but) )
                copy_but.setToolTip('<span style="white-space:nowrap">'
                                    + _("Copy <b>{text}</b>").format(text=lns_string_em)
                                    + '</span>')
            else:
                details_lbl.setHidden(True)
                copy_but.setHidden(True)

            if self.show_addresses:
                addr_lbl = ButtonAssociatedLabel('', button=rb)
                if is_valid:
                    if is_mine:
                        addr_lbl.setText(f'<a href="{info.address.to_ui_string()}"><pre>{info.address.to_ui_string()}</pre></a>')
                        addr_lbl.linkActivated.connect(view_addr_link_activated)
                        addr_lbl.setToolTip(_('Wallet') + ' - ' + (_('Change Address') if is_change else _('Receiving Address')))
                        addr_lbl.setButton(None)  # disable click to select
                    else:
                        addr_lbl.setText(f'<pre>{info.address.to_ui_string()}</pre>')
                else:
                    addr_lbl.setText('<i>' + _('Unsupported Account Type') + '</i>')
                    addr_lbl.setToolTip(rb.toolTip())
                grid.addWidget(addr_lbl, row*3+1, col*5+1, 1, 3)

            if (col % cols) == 0:
                # insert stretch in between the two columns
                spacer = QSpacerItem(1,0)
                grid.addItem(spacer, row, col*5+4, 1, 1)
                grid.setColumnStretch(col*5+4, 10)

            if self.show_addresses:
                # in-between row spaer. Only added if showing addresses
                # to make the address line visually closer to the line above it
                spacer = QSpacerItem(1, 8)
                grid.addItem(spacer, row*3+2, col*5, 1, 4)

            col += 1


        if len(items) == 1:
            # just 1 item, put it on the left
            grid.addItem(QSpacerItem(2,1), 0, 5)
            grid.setColumnStretch(5, 100)
        if len(items) <= 2:
            # just 1 row, push it up to the top
            grid.addItem(QSpacerItem(1,2), 3, 0, -1, -1)
            grid.setRowStretch(3, 100)


        if saved_selection and self.button_type != self.ButtonType.NoButton:
            for info in saved_selection:
                self.checkItemWithInfo(info)
        else:
            self.checkItemWithInfo(None)


def multiple_result_picker(parent, results, wallet=None, msg=None, title=None,
                           gbtext=None) -> Optional[Tuple[lns.Info, str]]:
    ''' Pops up a modal dialog telling you to pick a results. Used by the
    Contacts tab edit function, etc. '''
    assert parent
    from .main_window import ElectrumWindow
    if isinstance(parent, ElectrumWindow) and not wallet:
        wallet = parent.wallet
    assert isinstance(wallet, Abstract_Wallet)

    msg = msg or _('Multiple results were found, please select an option from the items below:')
    title = title or _("Select LNS Name")

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
        return gb.selectedItem()


def lookup_lns_dialog(
    parent, wallet, *,  # parent and wallet are required and parent must be an ElectrumWindow instance.
        title: str = None,  # the title to use, defaults to "Lookup LNS Name" (translated) and is bold and larger. Can be rich text.
        blurb: str = None,  # will appear in the same label, can be rich text, will get concatenated to title.
        title_label_link_activated_slot: Callable[[str], None] = None,  # if you embed links in the blub, pass a callback to handle them
        button_type: InfoGroupBox.ButtonType = InfoGroupBox.ButtonType.NoButton,  #  see InfoGroupBox
        add_to_contacts_button: bool = False,  # if true, the button bar will include an add to contacts button
        pay_to_button: bool = False  # if true, the button bar will include a "pay to" button
) -> List[Tuple[lns.Info, str, str]]:  # Returns a list of tuples
    ''' Shows the generic LNS Name lookup interface. '''
    from .main_window import ElectrumWindow
    ok_disables = button_type != InfoGroupBox.ButtonType.NoButton
    title = title or _("Lookup LNS Name")
    blurb = blurb or ''
    assert isinstance(parent, ElectrumWindow) and isinstance(wallet, Abstract_Wallet)
    if parent.gui_object.warn_if_no_network(parent):
        return None
    d = WindowModalDialog(parent.top_level_window(), title)
    d.setObjectName("WindowModalDialog - " + title)
    finalization_print_error(d)
    destroyed_print_error(d)
    all_lns_contacts = set(contact.name for contact in wallet.contacts.get_all(nocopy=True) if contact.type == 'lns')

    vbox = QVBoxLayout(d)
    hbox = QHBoxLayout()
    label = QLabel()
    label.setPixmap(QIcon(":icons/lns.png").pixmap(50))
    hbox.addWidget(label)
    hbox.addItem(QSpacerItem(10, 1))
    label = QLabel("<font size=+1><b>" + title + "</b></font>" + blurb)
    if callable(title_label_link_activated_slot):
        label.linkActivated.connect(title_label_link_activated_slot)
    label.setAlignment(Qt.AlignVCenter|Qt.AlignLeft)
    hbox.addWidget(label)
    hbox.addStretch(2)
    vbox.addLayout(hbox)
    grid = QGridLayout()
    grid.setContentsMargins(62, 32, 12, 12)
    acct = QLineEdit()
    acct.setPlaceholderText(_("LNS Name e.g.  satoshi.bch"))
    acct.setMinimumWidth(280)
    label2 = WWLabel('<a href="https://app.bch.domains">' + _("Search online...") + "</a>")
    label2.linkActivated.connect(webopen)


    #acct.setFixedWidth(280)
    label = HelpLabel(_("&LNS Name"), _("Enter an LNS Name of the form satoshi.bch, and Electron Cash will search for the contact and present you with its resolved address."))
    label.setBuddy(acct)
    search = QPushButton(_("Lookup"))
    search.setEnabled(False)
    grid.addWidget(label, 0, 0, 1, 1, Qt.AlignRight)
    grid.addWidget(acct, 0, 1, 1, 1, Qt.AlignLeft)
    grid.addWidget(search, 0, 2, 1, 1, Qt.AlignLeft)
    grid.addWidget(label2, 0, 3, 1, 1, Qt.AlignLeft)
    grid.setColumnStretch(3, 5)
    vbox.addLayout(grid)
    vbox.addItem(QSpacerItem(20,10))
    frame = QScrollArea()
    tit_lbl = QLabel()
    vbox.addWidget(tit_lbl)
    extra_buttons = []
    # Extra Buttons
    if add_to_contacts_button:
        def create_add_to_contacts_button_callback(item: tuple) -> QPushButton:
            info, lns_string = item
            lns_string_em = wallet.lns.fmt_info(info)
            but = QPushButton(QIcon(":icons/tab_contacts.png"), "")
            if isinstance(info.address, Address):
                if lns_string not in all_lns_contacts and wallet.is_mine(info.address):
                    # We got a result for an LNS that happens to be ours. Remember it.
                    parent.set_contact(label=lns_string, address=info.address, typ='lns')
                    all_lns_contacts.add(lns_string)
                if lns_string in all_lns_contacts:
                    but.setDisabled(True)
                    but.setToolTip(_('<span style="white-space:nowrap"><b>{lns_name}</b> already in Contacts</span>').format(lns_name=lns_string_em))
                else:
                    add_str = _("Add to Contacts")
                    but.setToolTip(f'<span style="white-space:nowrap">{add_str}<br>&nbsp;&nbsp;&nbsp;<b>{lns_string_em}</b></span>')
                    del add_str
                    def add_contact_slot(ign=None, but=but, item=item):
                        # label, address, typ='address') -> str:
                        new_contact = parent.set_contact(label=lns_string, address=info.address, typ='lns')
                        if new_contact:
                            msg = _('<span style="white-space:nowrap"><b>{lns_name}</b> added to Contacts</span>').format(lns_name=lns_string_em)
                            but.setDisabled(True)
                            but.setToolTip(msg)
                            all_lns_contacts.add(new_contact.name)
                        else:
                            msg = _("Error occurred adding to Contacts")
                        QToolTip.showText(QCursor.pos(), msg, frame, QRect(), 5000)
                    # /add_contact
                    but.clicked.connect(add_contact_slot)
            else:
                but.setDisabled(True)
                but.setToolTip("<i>" + _("Unsupported Account Type") + "</i>")
            return but
        extra_buttons.append(create_add_to_contacts_button_callback)
    if pay_to_button:
        def create_payto_but(item):
            info, _name = item
            lns_string_em = wallet.lns.fmt_info(info)
            icon_file = ":icons/paper-plane.svg" if not ColorScheme.dark_scheme else ":icons/paper-plane_dark_theme.svg"
            but = QPushButton(QIcon(icon_file), "")
            if isinstance(info.address, Address):
                payto_str = _("Pay to")
                but.setToolTip(f'<span style="white-space:nowrap">{payto_str}<br>&nbsp;&nbsp;&nbsp;<b>{lns_string_em}</b></span>')
                but.clicked.connect(lambda: parent.is_alive() and parent.payto_payees([lns_string_em]))
                but.clicked.connect(d.reject)
            else:
                but.setDisabled(True)
                but.setToolTip("<i>" + _("Unsupported Account Type") + "</i>")
            return but
        extra_buttons.append(create_payto_but)
    # /Extra Buttons
    ca = InfoGroupBox(frame, parent, button_type = button_type, title = '', extra_buttons=extra_buttons)
    ca.refresh()
    frame.setMinimumWidth(765)
    frame.setMinimumHeight(250)
    frame.setWidget(ca)
    frame.setWidgetResizable(True)
    vbox.addWidget(frame)
    search.setDefault(True)
    if ok_disables:
        need_to_fwd_return = True
        ok = OkButton(d)
        ok.setDisabled(ok_disables)
        vbox.addLayout(Buttons(CancelButton(d), ok))
    else:
        need_to_fwd_return = False
        ok = CloseButton(d)
        ok.setDefault(False)
        vbox.addLayout(Buttons(ok))

    def ca_msg(m, clear=False):
        ca.no_items_text = m
        if clear:
            ca.setItems([], auto_resize_parent=False, title = '')
        else:
            ca.refresh()
        tit_lbl.setText('')

    def on_return_pressed():
        if need_to_fwd_return and search.isEnabled():
            search.click()

    def on_text_changed(txt):
        txt = txt.strip() if txt else ''
        search.setEnabled(bool(wallet.lns.parse_string(txt)))
        if not txt and not ca.items():
            ca_msg(" ")

    def on_search():
        ok.setDisabled(ok_disables)
        name = acct.text().strip()
        tup = wallet.lns.parse_string(name)
        if tup:
            ca_msg(_("Searching for <b>{lns_name}</b> please wait ...").format(lns_name=name), True)
            results = None
            exc = []
            t0 = time.time()
            def resolve_verify():
                nonlocal results
                results = wallet.lns.resolve_verify(name, exc=exc)
                results = [(item,item.name) for item in results]
            code = VerifyingDialog(parent.top_level_window(),
                                   _("Verifying LNS Name {name} please wait ...").format(name=name),
                                   resolve_verify, auto_show=False).exec_()
            if code == QDialog.Rejected:
                # user cancel -- the waiting dialog thread will continue to run in the background but that's ok.. it will be a no-op
                d.reject()
                return
            if results:
                ca.setItems(results, auto_resize_parent=False, title='', button_type = button_type)  # suppress groupbox title
            else:
                ca_msg(_("The specified LNS Name does not appear to be associated with any BCH address"), True)
                if time.time()-t0 >= lns.timeout:
                    if (wallet.verifier and wallet.synchronizer and  # check these are still alive: these could potentially go away from under us if wallet is stopped when we get here.
                            (not wallet.verifier.is_up_to_date() or not wallet.synchronizer.is_up_to_date())):
                        parent.show_message(_("No results found. However, your wallet is busy updating."
                                              " This can interfere with LNS lookups."
                                              " You may want to try again when it is done."))
                    else:
                        parent.show_message(_("A network timeout occurred while looking up this LNS Name. "
                                              "You may want to check that your internet connection is up and "
                                              "not saturated processing other requests."))
                elif exc and isinstance(exc[-1], requests.ConnectionError):
                    parent.show_error(_("A network connectivity error occured. Please check your internet connection and try again."))
            nres = len(results or [])
            title =  "<b>" + name + "</b> - " + ngettext("{number} LNS Name", "{number} LNS Names", nres).format(number=nres)
            tit_lbl.setText(title)
        else:
            ca_msg(_("Invalid LNS Name, please try again"), True)

    acct.textChanged.connect(on_text_changed)
    search.clicked.connect(on_search)
    acct.returnPressed.connect(on_return_pressed)
    ca.buttonGroup().buttonClicked.connect(lambda x=None: ok.setEnabled(ok_disables and ca.selectedItem() is not None))

    ca_msg(" ")

    if d.exec_() == QDialog.Accepted:
        return ca.selectedItems()
    parent.contact_list.do_update_signal.emit()  # In case they added some contacts, etc
    return None


def lns_detail_dialog(parent : MessageBoxMixin,  # Should be an ElectrumWindow instance
                               lns_string : str,  # Cash acount string eg: "satoshi.bch"
                               *, title : str = None  # The modal dialog window title
    ) -> bool:  # returns True on success, False on failure
    ''' Shows the LNS Name details for any LNS Name.
    Note that parent should be a ElectrumWindow instance.
    `lns_string` is just an LNS Name string of the form:
        satoshi.bch
    Returns False on failure or True on success. User is presented with an error
    message box on False return.'''
    from .main_window import ElectrumWindow
    assert isinstance(parent, ElectrumWindow)
    wallet = parent.wallet
    assert isinstance(wallet, Abstract_Wallet)

    if not wallet.lns.parse_string(lns_string):
        parent.show_error(_("Invalid LNS Name:") + f" {lns_string}")
        return False

    # validate lns_string arg & resolve if need be
    info = wallet.lns.get_verified(lns_string)
    if not info:
        # need to look it up
        tup = resolve_lns(parent, lns_string, wallet)
        if not tup:
            # Error window was provided by resolve_lns, just return
            return False
        info, lns_string = tup

    # . <-- at this point we have a verified LNS name to display

    # Make sure it's not an unsupported type as the code at the end of this
    # file assumes info.address is an Address.
    if not isinstance(info.address, Address):
        parent.show_error(_("Unsupported payment data type.") + "\n\n"
                          + _("The LNS Name {name} uses an account type that "
                              "is not supported by Electron Cash.").format(name=lns_string))
        return False

    title = title or _("LNS Name Details")
    # create dialog window
    d = WindowModalDialog(parent.top_level_window(), title)
    d.setObjectName("WindowModalDialog - " + title)
    finalization_print_error(d)
    destroyed_print_error(d)

    grid = QGridLayout(d)
    avatar_lbl = QLabel()
    def success_cb(data):
        try:
            avatar_lbl.setText('')
            pix = QPixmap()
            pix.loadFromData(data)
            avatar_lbl.setPixmap(pix.scaled(75, 75, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        except:
            pass

    def thread_func():
        url = f'https://metadata.bch.domains/smartbch/avatar/{lns_string}'
        r = requests.get(url,  allow_redirects=True)
        if r.ok:
            success_cb(r.content)

    t = threading.Thread(name=f"LNS avatar download",
                         target=thread_func, daemon=True)
    t.start()

    avatar_lbl.setToolTip(f'<span style="white-space:nowrap;">{info.name}</span>')
    grid.addWidget(avatar_lbl, 0, 0, 3, 1)
    fsize = 26
    if len(info.name) > 20:
        fsize = 15
    if len(info.name) > 30:
        fsize = 12
    if len(info.name) > 50:
        fsize = 10
    if len(info.name) > 90:
        fsize = 8
    name_txt = f'<span style="white-space:nowrap; font-size:{fsize}pt; font-weight:bold;">{info.name}'
    name_txt += '</span></span>'

    def open_link(link):
        if Address.is_valid(link):
            addr = Address.from_string(link)
            if wallet.is_mine(addr):
                parent.show_address(addr)
            else:
                addr_URL = web.BE_URL(parent.config, 'addr', addr)
                if addr_URL:
                    webopen(addr_URL)
            return
        if link.startswith('http'):
            webopen(link)

    # name
    name_lbl = QLabel(name_txt)
    grid.addWidget(name_lbl, 0, 1, 1, 1)
    # copy name
    copy_name_but = QPushButton()
    copy_name_but.setIcon(QIcon(":icons/copy.png"))
    button_make_naked(copy_name_but)
    copy_name_but.setToolTip('<span style="white-space:nowrap">'
                                + _("Copy <b>{lns_name}</b>").format(lns_name=info.name)
                                + '</span>')
    copy_name_but.clicked.connect(lambda ignored=None, ca_string_em=info.name, copy_but=copy_name_but:
                                    parent.copy_to_clipboard(text=ca_string_em, tooltip=_('Cash Account copied to clipboard'), widget=copy_but) )
    grid.addWidget(copy_name_but, 0, 2, 1, 1)
    # address label
    addr_lbl = QLabel(f'<span style="white-space:nowrap; font-size:15pt;"><a href="{info.address.to_ui_string()}"><pre>{info.address.to_ui_string()}</pre></a></span>')
    addr_lbl.linkActivated.connect(open_link)
    grid.addWidget(addr_lbl, 1, 1, 1, 1)
    # copy address label
    copy_addr_but = QPushButton()
    copy_addr_but.setIcon(QIcon(":icons/copy.png"))
    button_make_naked(copy_addr_but)
    copy_addr_but.setToolTip(_("Copy {}").format(_("Address")))
    copy_addr_but.clicked.connect(lambda ignored=None, text=info.address.to_ui_string(), copy_but=copy_addr_but:
                                    parent.copy_to_clipboard(text=text, tooltip=_('Address copied to clipboard'), widget=copy_but) )
    grid.addWidget(copy_addr_but, 1, 2, 1, 1)

    # registration date label
    reg_date_lbl = QLabel(f'<span style="white-space:nowrap; font-size:15pt;">Registration date:&nbsp;{util.format_time(info.registrationDate)}</span>')
    grid.addWidget(reg_date_lbl, 2, 1, 1, 1)

    # expiry date label
    exp_date_lbl = QLabel(f'<span style="white-space:nowrap; font-size:15pt;">Expiry date:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{util.format_time(info.expiryDate)}</span>')
    grid.addWidget(exp_date_lbl, 3, 1, 1, 1)

    if not wallet.is_mine(info.address):
        ismine_txt = _("External Address") + ', '
    else:
        ismine_txt = _("My LNS Name") + ', '

    # Mined in block
    viewname_txt = _("View in LNS app")
    url = f'https://app.bch.domains/name/{info.name}'
    view_tx_lbl = QLabel(f'<span style="white-space:nowrap; font-size:11pt;">{ismine_txt} <a href="{url}">{viewname_txt}</a></span>')
    view_tx_lbl.setToolTip(_("View in LNS app"))
    view_tx_lbl.linkActivated.connect(open_link)
    grid.addWidget(view_tx_lbl, 4, 1, 1, 1, Qt.AlignTop | Qt.AlignRight)

    grid.setRowStretch(4, 1)

    # QR
    tabs = QTabWidget()
    full_addr_str = info.address.to_full_ui_string()
    qr_address = QRCodeWidget(full_addr_str, fixedSize=True)
    qr_address.setToolTip(full_addr_str)
    tabs.addTab(qr_address, _("Address"))
    qr_ca_string = QRCodeWidget(lns_string, fixedSize=True)
    qr_ca_string.setToolTip(lns_string)
    tabs.addTab(qr_ca_string, _("LNS Name"))
    qr_address.setMinimumSize(300, 300)
    qr_ca_string.setMinimumSize(300, 300)

    grid.addWidget(tabs, 5, 0, 1, -1, Qt.AlignTop | Qt.AlignHCenter)

    # Bottom buttons
    buttons = Buttons(OkButton(d))
    grid.addLayout(buttons, 6, 0, -1, -1)

    # make all labels allow select text & click links
    for c in d.children():
        if isinstance(c, QLabel):
            c.setTextInteractionFlags(c.textInteractionFlags() | Qt.TextSelectableByMouse | Qt.LinksAccessibleByMouse)

    try:
        d.exec_()
    except:
        pass

    return True
