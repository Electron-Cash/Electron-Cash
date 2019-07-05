#!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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

from electroncash.i18n import _
import electroncash.web as web
from electroncash.address import Address
from electroncash.plugins import run_hook
from electroncash.util import FileImportFailed, PrintError, finalization_print_error
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from .util import MyTreeWidget, webopen, WindowModalDialog, Buttons, CancelButton, OkButton, HelpLabel, WWLabel, destroyed_print_error, webopen
from enum import IntEnum
from collections import defaultdict
from . import cashacctqt

class ContactList(PrintError, MyTreeWidget):
    filter_columns = [1, 2]  # Name, Address
    default_sort = MyTreeWidget.SortSpec(1, Qt.AscendingOrder)

    class DataRoles(IntEnum):
        Key         = Qt.UserRole + 0
        Name        = Qt.UserRole + 1
        Type        = Qt.UserRole + 2

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu,
                              ["", _('Name'), _('Address'), _('Type') ], 1, [1],  # headers, stretch_column, editable_columns
                              deferred_updates=True, save_sort_settings=True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.wallet = parent.wallet
        self.setIndentation(0)
        self._edited_item_cur_sel = (None,) * 3

    def on_permit_edit(self, item, column):
        # openalias items shouldn't be editable
        return item.data(0, self.DataRoles.Type) != "openalias"

    def on_edited(self, item, column, prior_value):
        typ = item.data(0, self.DataRoles.Type)
        was_cur, was_sel = bool(self.currentItem()), item.isSelected()
        name, value = item.text(1), item.text(2)
        del item  # paranoia

        # On success, parent.set_contact returns the new key (address text)
        # if 'cashacct'.. or always the same key for all other types.
        key = self.parent.set_contact(name, value, typ=typ)

        if key:
            # Due to deferred updates, on_update will actually be called later.
            # So, we have to save the edited item's "current" and "selected"
            # status here. 'on_update' will look at this tuple and clear it
            # after updating.
            self._edited_item_cur_sel = (key, was_cur, was_sel)

    def import_contacts(self):
        wallet_folder = self.parent.get_wallet_folder()
        filename, __ = QFileDialog.getOpenFileName(self.parent, "Select your wallet file", wallet_folder)
        if not filename:
            return
        try:
            num = self.parent.contacts.import_file(filename)
            self.parent.show_message(_("{} contacts successfully imported.").format(num))
        except BaseException as e:
            self.parent.show_error(_("Electron Cash was unable to import your contacts.") + "\n" + repr(e))
        self.on_update()

    def export_contacts(self):
        if not len(self.parent.contacts):
            self.parent.show_error(_("Your contact list is empty."))
            return
        try:
            fileName = self.parent.getSaveFileName(_("Select file to save your contacts"), 'electron-cash_contacts.json', "*.json")
            if fileName:
                num = self.parent.contacts.export_file(fileName)
                self.parent.show_message(_("{} contacts exported to '{}'").format(num, fileName))
        except BaseException as e:
            self.parent.show_error(_("Electron Cash was unable to export your contacts.") + "\n" + repr(e))

    def find_item(self, key: str, data_role = DataRoles.Key) -> QTreeWidgetItem:
        ''' Rather than store the item reference in a lambda, we store its key.
        Storing the item reference can lead to C++ Runtime Errors if the
        underlying QTreeWidgetItem is deleted on .update() while the right-click
        menu is still up. This function returns a currently alive item given a
        key. '''
        for item in self.get_leaves():
            if item.data(0, data_role) == key:
                return item

    def _on_edit_item(self, key : str, column : int):
        ''' Callback from context menu, private method. '''
        item = self.find_item(key)
        if item:
            self.editItem(item, column)

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selectedItems()
        if selected:
            names = [item.text(1) for item in selected]
            keys = [item.data(0, self.DataRoles.Key) for item in selected]
            column = self.currentColumn()
            column_title = self.headerItem().text(column)
            column_data = '\n'.join([item.text(column) for item in selected])
            item = self.currentItem()
            typ = item.data(0, self.DataRoles.Type) if item else 'unknown'
            if item and typ in ('cashacct',) and column == 1 and len(selected) == 1:
                # hack .. for non-addresses say "Copy OpenAlias" or "Copy Cash Account", etc
                column_title = item.text(3)
            menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
            if item and column in self.editable_columns and self.on_permit_edit(item, column):
                key = item.data(0, self.DataRoles.Key)
                # this key & find_item business is so we don't hold a reference
                # to the ephemeral item, which may be deleted while the
                # context menu is up.  Accessing the item after on_update runs
                # means the item is deleted and you get a C++ object deleted
                # runtime error.
                menu.addAction(_("Edit {}").format(column_title), lambda: self._on_edit_item(key, column))
            menu.addAction(_("Pay to"), lambda: self.parent.payto_contacts(keys))
            menu.addAction(_("Delete"), lambda: self.parent.delete_contacts(keys))
            URLs = [web.BE_URL(self.config, 'addr', Address.from_string(key))
                    for key in keys if Address.is_valid(key)]
            if any(URLs):
                menu.addAction(_("View on block explorer"), lambda: [URL and webopen(URL) for URL in URLs])
            menu.addSeparator()

        menu.addAction(QIcon(":icons/cashacct-logo.png"), _("New Cash Account Contact"), self.new_cash_account_contact_dialog)
        menu.addAction(QIcon(":icons/tab_contacts.png"), _("New Contact"), self.parent.new_contact_dialog)
        menu.addAction(QIcon(":icons/import.svg"), _("Import file"), self.import_contacts)
        if len(self.parent.contacts):
            menu.addAction(QIcon(":icons/save.svg"), _("Export file"), self.export_contacts)

        run_hook('create_contact_menu', menu, selected)
        menu.exec_(self.viewport().mapToGlobal(position))

    def on_update(self):
        item = self.currentItem()
        current_key = item.data(0, self.DataRoles.Key) if item else None
        selected = self.selectedItems() or []
        selected_keys = set(item.data(0, self.DataRoles.Key) for item in selected)
        del item, selected  # must not hold a reference to a C++ object that will soon be deleted in self.clear()..
        self.clear()
        type_names = defaultdict(lambda: _("Unknown"))
        type_names.update({
            'openalias' : _('OpenAlias'),
            'cashacct'  : _('Cash Account'),
            'address'   : _('Address'),
        })
        selected_items, current_item = [], None
        edited = self._edited_item_cur_sel
        for key in sorted(self.parent.contacts.keys()):
            _type, name = self.parent.contacts[key]
            item = QTreeWidgetItem(["", name, key, type_names[_type]])
            item.setData(0, self.DataRoles.Key, key)
            item.setData(0, self.DataRoles.Type, _type)
            item.setData(0, self.DataRoles.Name, name)
            item.DataRole = self.DataRoles.Name
            if _type == 'cashacct':
                ca_info = self.wallet.cashacct.get_verified(name)
                if ca_info:
                    item.setText(0, ca_info.emoji)
                    tt = _('Validated Cash Account: <b><pre>{emoji} {account_string}</pre></b>').format(
                        emoji = ca_info.emoji,
                        account_string = f'{ca_info.name}#{ca_info.number}.{ca_info.collision_hash};'
                    )
                else:
                    item.setIcon(0, QIcon(":icons/unconfirmed.svg"))
                    tt = _('Warning: This Cash Account is not validated')
                item.setToolTip(0, tt)
            self.addTopLevelItem(item)
            if key == current_key or (key == edited[0] and edited[1]):
                current_item = item  # this key was the current item before and it hasn't gone away
            if key in selected_keys or (key == edited[0] and edited[2]):
                selected_items.append(item)  # this key was selected before and it hasn't gone away

        if selected_items:  # sometimes currentItem is set even if nothing actually selected. grr..
            # restore current item & selections
            if current_item:
                # set the current item. this may also implicitly select it
                self.setCurrentItem(current_item)
            for item in selected_items:
                # restore the previous selection
                item.setSelected(True)
        self._edited_item_cur_sel = (None,) * 3
        run_hook('update_contacts_tab', self)

    def new_cash_account_contact_dialog(self):
        ''' Context menu callback. Shows the "New Cash Account Contact"
        interface. '''
        wallet = self.wallet
        d = WindowModalDialog(self.parent.top_level_window(), _("New Cash Account Contact"))
        d.setObjectName("WindowModalDialog - New Cash Account")
        finalization_print_error(d)
        destroyed_print_error(d)

        vbox = QVBoxLayout(d)
        hbox = QHBoxLayout()
        label = QLabel()
        label.setPixmap(QIcon(":icons/cashacct-logo.png").pixmap(50))
        hbox.addWidget(label)
        hbox.addItem(QSpacerItem(10, 1))
        label = QLabel("<font size=+1><b>" + _('New Cash Account Contact') + "</b></font>")
        label.setAlignment(Qt.AlignVCenter|Qt.AlignLeft)
        hbox.addWidget(label)
        hbox.addStretch(2)
        vbox.addLayout(hbox)
        grid = QGridLayout()
        grid.setContentsMargins(62, 32, 12, 12)
        acct = QLineEdit()
        acct.setPlaceholderText(_("Cash Account e.g. satoshi#123.45"))
        acct.setMinimumWidth(280)
        label2 = WWLabel('<a href="https://www.cashaccount.info/">' + _("Search online...") + "</a>")
        label2.linkActivated.connect(webopen)


        #acct.setFixedWidth(280)
        label = HelpLabel(_("&Cash Account Name"), _("Enter a Cash Account name of the form Name#123.45, and Electron Cash will search for the contact and present you with its resolved address."))
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
        frame = QFrame()
        vbox2 = QVBoxLayout(frame)
        ca = cashacctqt.InfoGroupBox(frame, self.parent)
        ca.refresh()
        frame.setMinimumWidth(760)
        vbox2.addWidget(ca)
        vbox.addWidget(frame)
        ok = OkButton(d)
        ok.setDisabled(True)
        vbox.addLayout(Buttons(CancelButton(d), ok))

        def ca_msg(m, clear=False):
            ca.no_items_text = m
            if clear:
                ca.setItems([], auto_resize_parent=False)
            else:
                ca.refresh()

        def on_return_pressed():
            if search.isEnabled():
                search.click()

        def on_text_changed(txt):
            ''' '''
            search.setEnabled(bool(self.wallet.cashacct.parse_string(txt)))
            if not txt and not ca.items():
                ca_msg(" ")

        def on_search():
            name = acct.text()
            tup = self.wallet.cashacct.parse_string(name)
            if tup:
                ca_msg(_("Searching, for <b>{name}</b> please wait ...").format(name=name), True)
                qApp.processEvents(QEventLoop.ExcludeUserInputEvents)
                results = wallet.cashacct.resolve_verify(name)
                if results:
                    title =  name + " - " + _("{number} Cash Account(s)").format(number=len(results))
                    ca.setItems(results, auto_resize_parent=False, title=title)
                else:
                    ca_msg(_("The specified Cash Account does not appear to be associated with any address"), True)
            else:
                ca_msg(_("Invalid Cash Account name, please try again"), True)

        acct.textChanged.connect(on_text_changed)
        search.clicked.connect(on_search)
        acct.returnPressed.connect(on_return_pressed)

        #ca_msg(_("No Results"))
        ca_msg(" ")

        if d.exec_():
            pass
            #self.set_contact(line2.text(), line1.text())
