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

from electroncash.i18n import _, ngettext
import electroncash.web as web
from electroncash.address import Address
from electroncash.contacts import Contact, contact_types
from electroncash.plugins import run_hook
from electroncash.util import FileImportFailed, PrintError, finalization_print_error
# TODO: whittle down these * imports to what we actually use when done with
# our changes to this class -Calin
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from .util import (MyTreeWidget, webopen, WindowModalDialog, Buttons,
                   CancelButton, OkButton, HelpLabel, WWLabel,
                   destroyed_print_error, webopen, ColorScheme, MONOSPACE_FONT)
from enum import IntEnum
from collections import defaultdict
from typing import List
from . import cashacctqt

class ContactList(PrintError, MyTreeWidget):
    filter_columns = [1, 2]  # Name, Address
    default_sort = MyTreeWidget.SortSpec(1, Qt.AscendingOrder)

    do_update_signal = pyqtSignal()

    class DataRoles(IntEnum):
        Contact     = Qt.UserRole + 0

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu,
                              ["", _('Name'), _('Address'), _('Type') ], 1, [1],  # headers, stretch_column, editable_columns
                              deferred_updates=True, save_sort_settings=True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.wallet = parent.wallet
        self.setIndentation(0)
        self._edited_item_cur_sel = (None,) * 3
        self.monospace_font = QFont(MONOSPACE_FONT)
        self.cleaned_up = False
        self.do_update_signal.connect(self.update)
        self.icon_cashacct = QIcon(":icons/cashacct-logo.png" if not ColorScheme.dark_scheme else ":icons/cashacct-button-darkmode.png")
        self.icon_contacts = QIcon(":icons/tab_contacts.png")
        if self.wallet.network:
            self.wallet.network.register_callback(self._ca_callback, ['ca_verified_tx'])

    def clean_up(self):
        self.cleaned_up = True
        if self.wallet.network:
            self.wallet.network.unregister_callback(self._ca_callback)

    def _ca_callback(self, e, *args):
        if e == 'ca_verified_tx' and len(args) >= 2 and args[0] == self.wallet.cashacct:
            # it's relevant to us when a verification comes in, so we need to
            # schedule an update then
            self.do_update_signal.emit()

    def on_permit_edit(self, item, column):
        # openalias items shouldn't be editable
        return item.data(0, self.DataRoles.Contact).type in ('address', 'cashacct')

    def on_edited(self, item, column, prior_value):
        contact = item.data(0, self.DataRoles.Contact)
        typ = contact.type
        was_cur, was_sel = bool(self.currentItem()), item.isSelected()
        name, value = item.text(1), item.text(2)
        del item  # paranoia

        # On success, parent.set_contact returns the new key (address text)
        # if 'cashacct'.. or always the same key for all other types.
        key = self.parent.set_contact(name, value, typ=typ, replace=contact)

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
        except Exception as e:
            self.parent.show_error(_("Electron Cash was unable to import your contacts.") + "\n" + repr(e))
        self.on_update()

    def export_contacts(self):
        if self.parent.contacts.empty:
            self.parent.show_error(_("Your contact list is empty."))
            return
        try:
            fileName = self.parent.getSaveFileName(_("Select file to save your contacts"), 'electron-cash-contacts.json', "*.json")
            if fileName:
                num = self.parent.contacts.export_file(fileName)
                self.parent.show_message(_("{} contacts exported to '{}'").format(num, fileName))
        except Exception as e:
            self.parent.show_error(_("Electron Cash was unable to export your contacts.") + "\n" + repr(e))

    def find_item(self, key: Contact) -> QTreeWidgetItem:
        ''' Rather than store the item reference in a lambda, we store its key.
        Storing the item reference can lead to C++ Runtime Errors if the
        underlying QTreeWidgetItem is deleted on .update() while the right-click
        menu is still up. This function returns a currently alive item given a
        key. '''
        for item in self.get_leaves():
            if item.data(0, self.DataRoles.Contact) == key:
                return item

    def _on_edit_item(self, key : Contact, column : int):
        ''' Callback from context menu, private method. '''
        item = self.find_item(key)
        if item:
            self.editItem(item, column)

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selectedItems()
        if selected:
            names = [item.text(1) for item in selected]
            keys = [item.data(0, self.DataRoles.Contact) for item in selected]
            deletable_keys = [k for k in keys if k.type in contact_types]
            column = self.currentColumn()
            column_title = self.headerItem().text(column)
            column_data = '\n'.join([item.text(column) for item in selected])
            item = self.currentItem()
            typ = item.data(0, self.DataRoles.Contact).type if item else 'unknown'
            if item and typ in ('cashacct', 'cashacct_W') and column == 1 and len(selected) == 1:
                # hack .. for non-addresses say "Copy OpenAlias" or "Copy Cash Account", etc
                column_title = _('Cash Account')
            menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
            if item and column in self.editable_columns and self.on_permit_edit(item, column):
                key = item.data(0, self.DataRoles.Contact)
                # this key & find_item business is so we don't hold a reference
                # to the ephemeral item, which may be deleted while the
                # context menu is up.  Accessing the item after on_update runs
                # means the item is deleted and you get a C++ object deleted
                # runtime error.
                menu.addAction(_("Edit {}").format(column_title), lambda: self._on_edit_item(key, column))
            menu.addAction(_("Pay to"), lambda: self.parent.payto_contacts(keys))
            a = menu.addAction(_("Delete"), lambda: self.parent.delete_contacts(deletable_keys))
            if not deletable_keys:
                a.setEnabled(False)
            URLs = [web.BE_URL(self.config, 'addr', Address.from_string(key))
                    for key in keys if Address.is_valid(key)]
            if any(URLs):
                menu.addAction(_("View on block explorer"), lambda: [URL and webopen(URL) for URL in URLs])
            menu.addSeparator()

        menu.addAction(self.icon_cashacct,
                       _("New Contact") + " - " + _("Cash Account"), self.new_cash_account_contact_dialog)
        menu.addAction(self.icon_contacts, _("New Contact") + " - " + _("Address"), self.parent.new_contact_dialog)
        menu.addSeparator()
        menu.addAction(self.icon_cashacct,
                       _("Register Cash Account..."), self.parent.register_new_cash_account)
        menu.addSeparator()
        menu.addAction(QIcon(":icons/import.svg" if not ColorScheme.dark_scheme else ":icons/import_dark_theme.svg"),
                       _("Import file"), self.import_contacts)
        if not self.parent.contacts.empty:
            menu.addAction(QIcon(":icons/save.svg" if not ColorScheme.dark_scheme else ":icons/save_dark_theme.svg"),
                           _("Export file"), self.export_contacts)

        run_hook('create_contact_menu', menu, selected)
        menu.exec_(self.viewport().mapToGlobal(position))

    def _make_wallet_cashacct_fake_contacts(self, real_contacts) -> List[Contact]:
        ''' Returns a list of 'fake' contacts that come from the wallet's
        own registered Cash Accounts.  These contacts do not exist in the
        wallet.contacts object but are created on-the-fly from the
        wallet.cashacct list of registered & verified Cash Accounts.

        This is a convenience so that the Contacts tab shows "my" cash accounts
        after registration as well as external Cash Accounts. Note that the
        "mine" entries won't be shown if the user explicitly added his own as
        "external"... '''
        try:
            dupe_chk = set((c.name, Address.from_string(c.address)) for c in real_contacts if c.type == 'cashacct')
        except:
            # Hmm.. invalid address?
            dupe_chk = set()
        wallet_cashaccts = []
        for ca_info in self.wallet.cashacct.get_wallet_cashaccounts():
            name = self.wallet.cashacct.fmt_info(ca_info, emoji=False)
            if (name, ca_info.address) in dupe_chk:
                # if they happened to manually add the same contact that is
                # also a wallet contact, don't display the same contact twice.
                continue
            wallet_cashaccts.append(Contact(
                name = name,
                address = ca_info.address.to_ui_string(),
                type = 'cashacct_W'
            ))
        return wallet_cashaccts

    def on_update(self):
        if self.cleaned_up:
            return
        item = self.currentItem()
        current_contact = item.data(0, self.DataRoles.Contact) if item else None
        selected = self.selectedItems() or []
        selected_contacts = set(item.data(0, self.DataRoles.Contact) for item in selected)
        del item, selected  # must not hold a reference to a C++ object that will soon be deleted in self.clear()..
        self.clear()
        type_names = defaultdict(lambda: _("Unknown"))
        type_names.update({
            'openalias'  : _('OpenAlias'),
            'cashacct'   : _('Cash Account'),
            'cashacct_W' : _('Cash Account [Mine]'),
            'address'    : _('Address'),
        })
        type_icons = {
            'cashacct'   : self.icon_cashacct,
            'cashacct_W' : self.icon_cashacct,
            'address'    : self.icon_contacts,
        }
        selected_items, current_item = [], None
        edited = self._edited_item_cur_sel
        real_contacts = self.parent.contacts.get_all(nocopy=True)
        wallet_cashaccts = self._make_wallet_cashacct_fake_contacts(real_contacts)
        for contact in real_contacts + wallet_cashaccts:
            _type, name, address = contact.type, contact.name, contact.address
            item = QTreeWidgetItem(["", name, address, type_names[_type]])
            item.setData(0, self.DataRoles.Contact, contact)
            item.DataRole = self.DataRoles.Contact
            if _type in ('cashacct', 'cashacct_W'):
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
                item.setFont(2, self.monospace_font)
            if _type in type_icons:
                item.setIcon(3, type_icons[_type])
            self.addTopLevelItem(item)
            if contact == current_contact or (contact == edited[0] and edited[1]):
                current_item = item  # this key was the current item before and it hasn't gone away
            if contact in selected_contacts or (contact == edited[0] and edited[2]):
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

        items = cashacctqt.lookup_cash_account_dialog(
            self.parent, self.wallet, title=_("New Cash Account Contact"),
            blurb = _("<br>Add anyone's Cash Account to your Contacts"),
            button_type=cashacctqt.InfoGroupBox.ButtonType.Radio
        )
        if items:
            info, min_chash, name = items[0]
            self.parent.set_contact(name, info.address.to_ui_string(), typ='cashacct')
            run_hook('update_contacts_tab', self)
