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
from electroncash.util import FileImportFailed, PrintError
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import (
    QAbstractItemView, QFileDialog, QMenu, QTreeWidgetItem)
from .util import MyTreeWidget, webopen
from enum import IntEnum
from collections import defaultdict

class ContactList(PrintError, MyTreeWidget):
    filter_columns = [1, 2]  # Name, Address

    class DataRoles(IntEnum):
        Key         = Qt.UserRole + 0
        Name        = Qt.UserRole + 1
        Type        = Qt.UserRole + 2

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu, ["", _('Name'), _('Address'), _('Type') ], 1, [1], deferred_updates=True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.wallet = parent.wallet
        self.sortItems(1, Qt.AscendingOrder)
        self.setIndentation(0)

    def on_permit_edit(self, item, column):
        # openalias items shouldn't be editable
        return item.data(0, self.DataRoles.Type) != "openalias"

    def on_edited(self, item, column, prior_value):
        typ = item.data(0, self.DataRoles.Type)
        name, value = item.text(1), item.text(2)
        self.parent.set_contact(name, value, typ=typ)

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

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selectedItems()
        if not selected:
            menu.addAction(_("New contact"), lambda: self.parent.new_contact_dialog())
            menu.addAction(_("Import file"), lambda: self.import_contacts())
            if len(self.parent.contacts):
                menu.addAction(_("Export file"), lambda: self.export_contacts())
        else:
            names = [item.text(1) for item in selected]
            keys = [item.data(0, self.DataRoles.Key) for item in selected]
            column = self.currentColumn()
            column_title = self.headerItem().text(column)
            column_data = '\n'.join([item.text(column) for item in selected])
            menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
            item = self.currentItem()
            if item and column in self.editable_columns and self.on_permit_edit(item, column):
                menu.addAction(_("Edit {}").format(column_title), lambda: self.editItem(item, column))
            menu.addAction(_("Pay to"), lambda: self.parent.payto_contacts(keys))
            menu.addAction(_("Delete"), lambda: self.parent.delete_contacts(keys))
            URLs = [web.BE_URL(self.config, 'addr', Address.from_string(key))
                    for key in keys if Address.is_valid(key)]
            if any(URLs):
                menu.addAction(_("View on block explorer"), lambda: [URL and webopen(URL) for URL in URLs])

        run_hook('create_contact_menu', menu, selected)
        menu.exec_(self.viewport().mapToGlobal(position))

    def on_update(self):
        item = self.currentItem()
        current_key = item.data(0, self.DataRoles.Key) if item else None
        self.clear()
        type_names = defaultdict(lambda: _("Unknown"))
        type_names.update({
            'openalias' : _('OpenAlias'),
            'cashacct'  : _('Cash Account'),
            'address'   : _('Address'),
        })
        for key in sorted(self.parent.contacts.keys()):
            _type, name = self.parent.contacts[key]
            item = QTreeWidgetItem(["", name, key, type_names[_type]])
            item.setData(0, self.DataRoles.Key, key)
            item.setData(0, self.DataRoles.Type, _type)
            item.setData(0, self.DataRoles.Name, name)
            item.DataRole = self.DataRoles.Name
            if _type == 'cashacct':
                nvc = self.wallet.cashacct.parse_string(name)
                if nvc:
                    nam, num, ch = nvc
                    ca_list = self.wallet.cashacct.find_verified(nam, num, ch)
                    ca_info = len(ca_list) == 1 and ca_list[0] or None
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
            if key == current_key:
                self.setCurrentItem(item)
        run_hook('update_contacts_tab', self)
