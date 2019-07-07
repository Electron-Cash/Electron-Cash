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

from collections import namedtuple
from typing import List, Dict
from . import util
from .storage import WalletStorage
from .address import Address

class Contact(namedtuple("Contact", "name address type")):
    ''' Your basic contacts entry. '''

contact_types = {'address', 'cashacct', 'openalias'}

class Contacts(util.PrintError):
    '''Electron Cash Contacts subsystem 2.0. Lightweight class for saving/laoding
    contacts to/from storage. This system replaces the old system which was
    a dict keyed off address, and which was limited to 1 contact per address
    and thus unusable for Cash Accounts and other features.

    Instead we model the contact list as a list, keyed off index. Multiple
    entries with the same name or address in the list are ok now. '''

    def __init__(self, storage: WalletStorage):
        assert isinstance(storage, WalletStorage)
        self.storage = storage
        self.load()  # NB: sets up self.data


    ##########################################
    # Load / Save plus their private methods #
    ##########################################

    def load(self):
        self.data = self._load_from_dict_like_object(self.storage)

    @staticmethod
    def _load_from_dict_like_object(storage) -> List[Contact]:
        assert callable(getattr(storage, 'get', None))
        l = storage.get('contacts2')
        # Check if v2 available and and if v1 available. If v1 but no v2,
        # load v1. Otherwise prefer v2.  This allows users to switch EC
        # versions back and forth.
        if (not l or not isinstance(l, list)) and isinstance(storage.get('contacts'), dict):
            return Contacts._loadv1(storage)

        return Contacts._load_v2_list(l)

    @staticmethod
    def _load_v2_list(in_list):
        out = []
        for d in in_list:
            if not isinstance(d, dict):
                continue  # skip obviously bad entries
            name, address, typ = d.get('name', ''), d.get('address', ''), d.get('type', '')
            if not all(isinstance(a, str) for a in (name, address, typ)):
                continue # skip invalid-looking data
            if typ in ('address', 'cashacct') and not Address.is_valid(address):
                continue # skip if address is not valid for these types
            out.append( Contact(name, address, typ) )
        return out

    @staticmethod
    def _loadv1(storage) -> List[Contact]:
        ''' loads v1 'contacts' key from `storage`, which should be either a
        dict or WalletStorage; it must simply support the dict-like method
        'get'. Note this also supports the pre-v1 format, as the old Contacts
        class did. '''
        assert callable(getattr(storage, 'get', None))
        d = dict()
        d2 = storage.get('contacts')
        try:
            d.update(d2)  # catch type errors, etc by doing this
        except:
            return []
        data = []
        # backward compatibility
        for k, v in d.copy().items():
            try:
                _type, n = v
            except:
                continue
            # Previous to 1.0 the format was { name : (type, address) }
            #          -> current 1.0 format { address : (type, name) }
            if _type == 'address' and Address.is_valid(n) and not Address.is_valid(k):
                d.pop(k)
                d[n] = ('address', k)
        # At this point d is the v1 style contacts dict, just put it in data
        for address, tup in d.items():
            _type, name = tup
            if _type == 'address' and not Address.is_valid(address):
                # skip invalid v1 entries, for sanity.
                continue
            if _type not in contact_types:
                # not a known type we care about
                continue
            data.append(
                Contact(str(name), str(address), str(_type))
            )
        return data

    @staticmethod
    def _save(data : List[Contact], v1_too : bool = False) -> dict:
        ''' Re-usable save methods. Saves keys to a dict, which can then
        be saved to wallet storage or saved to json. '''
        out_v2, out_v1, ret = [], {}, {}
        for contact in data:
            out_v2.append({
                'name': contact.name,
                'address': contact.address,
                'type': contact.type
            })
            if v1_too:
                # NOTE: v1 doesn't preserve dupe addresses
                out_v1[contact.address] = (contact.type, contact.name)

        ret['contacts2'] = out_v2

        if v1_too:
            ret['contacts'] = out_v1

        return ret

    def save(self):
        d = self._save(self.data, v1_too = False)  # Note: set v1_too = True if you want to save to v1 so older EC wallets can also see the updated contacts
        for k,v in d.items():
            self.storage.put(k, v)  # "contacts2", "contacts" are the two expected keys

    ###############
    # Plublic API #
    ###############

    def get_all(self) -> List[Contact]:
        ''' Returns a copy of the internal Contact list. '''
        return self.data.copy()

    def replace(self, old : Contact, new : Contact):
        ''' Replaces existing contact old with a new one. Will not add if old
        is not found. Returns True on success or False on error. '''
        assert isinstance(new, Contact)
        try:
            index = self.data.index(old)
            self.data[index] = new
            return True
        except ValueError:
            pass
        return False

    def add(self, contact : Contact, replace_old : Contact = None):
        ''' Puts a contact in the contact list, appending it at the end.
        Optionally, if replace_old is specified, will replace the entry
        where replace_old resides.  If replace_old cannot be found, will simply
        put the contact at the end. '''
        assert isinstance(contact, Contact) and isinstance(replace_old, (Contact, type(None)))
        if replace_old:
            if self.replace(replace_old, contact):
                return
            else:
                ''' replace_old not found, proceed to just add to end '''
                self.print_error(f"add: replace_old={replace_old} not found in contacts")
        self.data.append(contact)

    def remove(self, contact : Contact):
        ''' Removes a contact from the contact list. Returns True if it was
        removed or False otherwise. Note that if multiple entries for the same
        contact exist, only the first one found is removed. '''
        try:
            self.data.remove(contact)
            return True
        except ValueError:
            return False

    def remove_all(self, contact : Contact) -> int:
        ''' Removes all entries matching contact from the internal contact list.
        Returns the number of entries removed successfully. '''
        ct = 0
        while self.remove(contact):
            ct += 1
        return ct
