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

from collections import defaultdict
from enum import IntEnum
from functools import wraps
from typing import Any, DefaultDict, Dict, List, Optional, Set

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QAbstractItemView, QMenu

from electroncash import token, util
from electroncash.i18n import _, ngettext
from .main_window import ElectrumWindow
from .util import ColorScheme, MONOSPACE_FONT, MyTreeWidget, rate_limited, SortableTreeWidgetItem
from .token_meta import TokenMetaQt, do_update_token_meta


class TokenList(MyTreeWidget, util.PrintError):

    class Col(IntEnum):
        """Column numbers. This is to make code in on_update easier to read.
        If you modify these, make sure to modify the column header names in
        the MyTreeWidget constructor."""
        category = 0
        quantity = 1
        nfts = 2
        cap_icon_extra = 3
        cap_icon_main = 4
        nft_flags = 5
        num_utxos = 6
        bch_amount = 7
        output_pt = 8

    class DataRoles(IntEnum):
        """Data roles. Again, to make code in on_update easier to read."""
        item_key = QtCore.Qt.UserRole  # This is also the wallet label key
        token_id = QtCore.Qt.UserRole + 1
        utxos = QtCore.Qt.UserRole + 2
        nft_utxo = QtCore.Qt.UserRole + 3
        frozen_flags = QtCore.Qt.UserRole + 4  # Flags address/coin-level freeze: None or "" or "a" or "c" or "ac"

    filter_columns = [Col.category]
    default_sort = MyTreeWidget.SortSpec(Col.category, QtCore.Qt.AscendingOrder)  # sort by token_id, ascending

    amount_heading = _('Amount ({unit})')

    def __init__(self, parent: ElectrumWindow):
        assert isinstance(parent, ElectrumWindow)
        columns = [_('Category'), _('Fungible Amount'), _('NFTs'), '', '', _('Capability'), _('Num UTXOs'),
                   self.amount_heading.format(unit=parent.base_unit()), _('Output Point')]
        super().__init__(parent=parent, create_menu=self.create_menu, headers=columns,
                         stretch_column=None, deferred_updates=True,
                         save_sort_settings=True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.setAlternatingRowColors(True)
        self.wallet = self.parent.wallet
        self.cleaned_up = False
        self.fixed_width = QFont(MONOSPACE_FONT, QFont().pointSize() - 1)
        self.fixed_width.setFixedPitch(True)
        self.fixed_width.setStretch(QFont.SemiCondensed)
        self.fixed_width_smaller = QFont(MONOSPACE_FONT, QFont().pointSize() - 1)
        self.fixed_width_smaller.setFixedPitch(True)
        self.fixed_width_smaller.setStretch(QFont.Condensed)
        self.fixed_width_larger = QFont(MONOSPACE_FONT, QFont().pointSize())
        self.fixed_width_larger.setFixedPitch(True)
        self.smaller_font = QFont()
        self.smaller_font.setPointSize(self.smaller_font.pointSize() - 1)
        self.smaller_font.setLetterSpacing(QFont.PercentageSpacing, 90)
        self.light_blue = QtGui.QColor('lightblue') if not ColorScheme.dark_scheme else QtGui.QColor('blue')
        self.blue = ColorScheme.BLUE.as_color(True)
        self.cyan_blue = QtGui.QColor('#3399ff')
        self.icon_baton = QtGui.QIcon(":icons/baton.png")
        self.icon_mutable = QtGui.QIcon(":icons/mutable.png")
        self.token_meta: TokenMetaQt = self.parent.token_meta
        self.header().setMinimumSectionSize(21)
        for col in (self.Col.cap_icon_main, self.Col.cap_icon_extra):
            self.header().setSectionResizeMode(col, QtWidgets.QHeaderView.Interactive)
            self.header().resizeSection(col, 21)
        for col in (self.Col.nft_flags,):
            self.header().setSectionResizeMode(col, QtWidgets.QHeaderView.Interactive)
        self.setTextElideMode(QtCore.Qt.ElideRight)

    def diagnostic_name(self):
        return f"{super().diagnostic_name()}/{self.wallet.diagnostic_name()}"

    def clean_up(self):
        self.cleaned_up = True

    def if_not_dead(func):
        """Boilerplate: Check if cleaned up, and if so, don't execute method"""
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if self.cleaned_up or not self.wallet or not self.parent:
                return
            else:
                func(self, *args, **kwargs)
        return wrapper

    @rate_limited(1.0, ts_after=True)  # performance tweak -- limit updates to no more than once per second
    def update(self):
        if self.cleaned_up:
            # short-cut return if window was closed and wallet is stopped
            return
        super().update()

    @classmethod
    def get_outpoint_shortname(cls, utxo):
        return cls.elide(utxo['prevout_hash'], 12) + ':' + str(utxo['prevout_n'])

    @staticmethod
    def get_outpoint_longname(utxo):
        return f"{utxo['prevout_hash']}:{utxo['prevout_n']}"

    @staticmethod
    def elide(s: str, elide_threshold=32) -> str:
        if len(s) > elide_threshold:
            n = max(elide_threshold // 2, 0)
            return s[:n] + '…' + s[-n:]
        return s

    @if_not_dead
    @util.profiler
    def on_update(self):
        def item_path(item: SortableTreeWidgetItem) -> str:
            """ Recursively builds the path for an item eg 'parent_name/item_name' """
            item_key = item.data(0, self.DataRoles.item_key)
            return item_key if not item.parent() else item_path(item.parent()) + "/" + item_key

        def remember_expanded_items(root: QtWidgets.QTreeWidgetItem) -> Set[str]:
            """ Save the set of expanded items... so that token list updates don't annoyingly collapse our tree list
                widget due to the update. This function recurses. Pass self.invisibleRootItem(). """
            ret: Set[str] = set()
            for i in range(0, root.childCount()):
                it = root.child(i)
                if it and it.childCount():
                    if it.isExpanded():
                        ret.add(item_path(it))
                    ret |= remember_expanded_items(it)  # recurse
            return ret

        def restore_expanded_items(root, item_names: Set[str]):
            """ Recursively restore the expanded state saved previously. Pass self.invisibleRootItem(). """
            for i in range(0, root.childCount()):
                it = root.child(i)
                if it and it.childCount():
                    restore_expanded_items(it, item_names)  # recurse, do leaves first
                    old = bool(it.isExpanded())
                    new = bool(item_path(it) in item_names)
                    if old != new:
                        it.setExpanded(new)

        # Remember selections and previously-expanded items, if any (keeps UI state consistent across refreshes)
        sels = self.selectedItems()
        item_keys_to_re_select = {item.data(0, self.DataRoles.item_key) for item in sels}
        expanded_item_names = remember_expanded_items(self.invisibleRootItem())
        del sels  # avoid keeping reference to about-to-be deleted C++ objects

        self.clear()

        # Pick up changes to the configured base_unit and update the amount column
        self.headerItem().setText(self.Col.bch_amount, self.amount_heading.format(unit=self.parent.base_unit()))

        tok_utxos = self.wallet.get_utxos(tokens_only=True)

        tokens: DefaultDict[List[Dict]] = defaultdict(list)  # key: token_id, value: List of utxo dicts
        items_to_re_select: List[SortableTreeWidgetItem] = []
        # token_id_hex -> <commitment_hex>|"ft_only" -> list of utxos
        tokens_grouped: DefaultDict[DefaultDict[List[Dict]]] = defaultdict(lambda: defaultdict(list))

        for utxo in tok_utxos:
            td = utxo['token_data']
            assert isinstance(td, token.OutputData)
            token_id = td.id_hex
            tokens[token_id].append(utxo)
            if not td.has_nft():
                # Special group -- fungible-only utxos
                tokens_grouped[token_id]["ft_only"].append(utxo)
            else:
                # Otherwise group each token_id by the commitment bytes
                tokens_grouped[token_id][td.commitment.hex()].append(utxo)

        def set_fonts(item: SortableTreeWidgetItem):
            for col in (self.Col.category, self.Col.quantity, self.Col.bch_amount):
                txt = item.text(col)
                token_id = item.data(0, self.DataRoles.token_id)
                if col == self.Col.category and txt != token_id and not txt.startswith("NFT: "):
                    continue  # Don't set the font for the "Fungible-Only" entries, or ones with user-edited names
                if len(txt) > 64:
                    item.setFont(col, self.fixed_width_smaller)
                elif len(txt) > 32:
                    item.setFont(col, self.fixed_width)
                else:
                    item.setFont(col, self.fixed_width_larger)
            item.setFont(self.Col.nft_flags, self.smaller_font)
            item.setFont(self.Col.output_pt, self.fixed_width)
            # Lastly, realign the quantity, num_nfts, and num_utxos columns
            for col, align in ((self.Col.quantity, QtCore.Qt.AlignRight),
                               (self.Col.nfts, QtCore.Qt.AlignCenter),
                               (self.Col.num_utxos, QtCore.Qt.AlignCenter)):
                item.setTextAlignment(col, align)

        def set_icons_inner(item: SortableTreeWidgetItem, num_minting, num_mutable, toplevel=False, leaf=False):
            assert not (toplevel and leaf)

            def get_tip_text(number, nft_capability):
                if leaf:
                    prefix = ""
                elif toplevel:
                    prefix = _("Category contains {number} ").format(number=number)
                else:
                    prefix = _("Group contains {number} ").format(number=number)
                return ngettext("{prefix}{nft_capability} NFT",
                                "{prefix}{nft_capability} NFTs",
                                number).format(prefix=prefix, nft_capability=nft_capability)
            if num_minting > 0:
                item.setIcon(self.Col.cap_icon_main, self.icon_baton)
                item.setToolTip(self.Col.cap_icon_main, get_tip_text(num_minting, "Minting"))
                if num_mutable > 0:
                    item.setIcon(self.Col.cap_icon_extra, self.icon_mutable)
                item.setToolTip(self.Col.cap_icon_extra, get_tip_text(num_mutable, "Mutable"))
            elif num_mutable > 0:
                item.setIcon(self.Col.cap_icon_main, self.icon_mutable)
                item.setToolTip(self.Col.cap_icon_main, get_tip_text(num_mutable, "Mutable"))

        def set_icons(item: SortableTreeWidgetItem, td: Optional[token.OutputData], toplevel=False, leaf=False):
            if not td:
                return
            if td.has_nft():
                num_minting = 1 if td.is_minting_nft() else 0
                num_mutable = 1 if td.is_mutable_nft() else 0
                set_icons_inner(item, num_minting, num_mutable, toplevel, leaf)

        def add_utxo_item(parent: Optional[SortableTreeWidgetItem], utxo, name, item_key):
            td = utxo['token_data']
            tid = td.id_hex
            amt = self.token_meta.format_amount(tid, td.amount)
            nft_flags = token.get_nft_flag_text(td) or ""
            num_nfts = str(int(td.has_nft()))
            num_utxos = "1"
            outpt_shortname = self.get_outpoint_shortname(utxo)
            bch_amt = self.parent.format_amount(utxo['value'], is_diff=False, whitespaces=True)
            stwi = SortableTreeWidgetItem([name, amt, num_nfts, "", "", nft_flags, num_utxos, bch_amt, outpt_shortname])
            stwi.setData(0, self.DataRoles.item_key, item_key)
            stwi.setData(0, self.DataRoles.token_id, tid)
            stwi.setData(0, self.DataRoles.utxos, [utxo])
            set_fonts(stwi)
            set_icons(stwi, td, toplevel=False, leaf=True)
            tt = self.get_outpoint_longname(utxo) + "\n"
            if utxo['height'] > 0:
                tt += _("Confirmed in block {height}").format(height=utxo['height'])
            else:
                tt += _("Unconfirmed")
            stwi.setToolTip(self.Col.output_pt, tt)

            stwi.setData(0, self.DataRoles.nft_utxo, utxo if td.has_nft() else None)
            a_frozen = 'a' if self.wallet.is_frozen(utxo['address']) else ''
            c_frozen = 'c' if utxo.get('is_frozen_coin') else ''
            stwi.setData(0, self.DataRoles.frozen_flags, a_frozen + c_frozen)
            if a_frozen and not c_frozen:
                # address is frozen, coin is not frozen
                # emulate the "Look" off the address_list .py's frozen entry
                stwi.setBackground(0, self.light_blue)
                tool_tip_misc = _("Address is frozen")
            elif c_frozen and not a_frozen:
                # coin is frozen, address is not frozen
                stwi.setBackground(0, self.blue)
                tool_tip_misc = _("Coin is frozen")
            elif c_frozen and a_frozen:
                # both coin and address are frozen so color-code it to indicate that.
                stwi.setBackground(0, self.light_blue)
                stwi.setForeground(0, self.cyan_blue)
                tool_tip_misc = _("Coin & Address are frozen")
            else:
                tool_tip_misc = ""

            if tool_tip_misc:
                stwi.setToolTip(self.Col.category, tool_tip_misc)
            if parent is not None:
                parent.addChild(stwi)
            if item_key in item_keys_to_re_select:
                items_to_re_select.append(stwi)
            return stwi

        for token_id, dd in tokens_grouped.items():
            utxo_list = tokens[token_id]
            key_prefix = f'token_{token_id}'
            item_key = key_prefix
            quantity = self.token_meta.format_amount(token_id, sum(u['token_data'].amount for u in utxo_list))
            num_nfts = sum(1 for u in utxo_list if u['token_data'].has_nft())
            nfts = str(num_nfts)
            flags = {token.get_nft_flag_text(u['token_data']) for u in utxo_list}
            num_minting = sum(1 for u in utxo_list if u['token_data'] and u['token_data'].is_minting_nft())
            num_mutable = sum(1 for u in utxo_list if u['token_data'] and u['token_data'].is_mutable_nft())
            flags.discard(None)  # Non-nft's add "None" to this set. discard
            nft_flags = ', '.join(sorted(flags, key=token.nft_flag_text_sorter))
            n_utxos = sum(len(ul) for ul in dd.values())
            num_utxos = str(n_utxos)
            bch_amt = self.parent.format_amount(sum(x['value'] for x in utxo_list), is_diff=False, whitespaces=True)

            token_display_name = self.token_meta.format_token_display_name(token_id)
            item = SortableTreeWidgetItem([token_display_name, quantity, nfts, "", "", nft_flags, num_utxos, bch_amt, ""])
            item.setData(0, self.DataRoles.item_key, item_key)
            item.setData(0, self.DataRoles.token_id, token_id)
            item.setData(0, self.DataRoles.utxos, utxo_list)
            item.setData(0, self.DataRoles.nft_utxo, None)
            set_fonts(item)
            set_icons_inner(item, num_minting, num_mutable, toplevel=True)
            if token_id != token_display_name:
                item.setToolTip(self.Col.category, _("Category ID") + ": " + token_id)
            if item_key in item_keys_to_re_select:
                items_to_re_select.append(item)

            # Do fungibles first
            dd = dd.copy()
            ft_only_utxo_list = dd.pop("ft_only", [])
            ft_only_utxo_list = sorted(ft_only_utxo_list, key=lambda u: -u['token_data'].amount)  # Sort by amount, desc

            name = _("Fungible-Only")
            if len(ft_only_utxo_list) == 1:
                utxo = ft_only_utxo_list[0]
                item_key = key_prefix + "_" + self.get_outpoint_longname(utxo)
                put_on_top_level = num_nfts == 0 and n_utxos == 1 and not dd
                if put_on_top_level:
                    # Special case -- have 1 fungible only and no NFTs for this token-id, just push this to top level
                    parent_item = None
                else:
                    parent_item = item
                sub_item = add_utxo_item(parent_item, utxo, name, item_key)
                if put_on_top_level:
                    # Overwrite the "item" with this sub-item in the special case
                    sub_item.setText(self.Col.category, item.text(self.Col.category))
                    item = sub_item
                    set_fonts(item)
            elif ft_only_utxo_list:
                item_key = key_prefix + "_ft_only"
                create_subgroup = num_nfts > 0 or dd
                if create_subgroup:
                    # Create a subgroup called "Fungible-Only" because we have NFTs
                    ft_amt = self.token_meta.format_amount(token_id,
                                                           sum(u['token_data'].amount for u in ft_only_utxo_list))
                    bch_amt = self.parent.format_amount(sum(x['value'] for x in ft_only_utxo_list), is_diff=False,
                                                        whitespaces=True)
                    ft_parent = SortableTreeWidgetItem([name, ft_amt, "0", "", "", "", str(len(ft_only_utxo_list)),
                                                        bch_amt, ""])
                    ft_parent.setData(0, self.DataRoles.item_key, item_key)
                    ft_parent.setData(0, self.DataRoles.token_id, token_id)
                    ft_parent.setData(0, self.DataRoles.utxos, ft_only_utxo_list)
                    ft_parent.setData(0, self.DataRoles.nft_utxo, None)
                    set_fonts(ft_parent)
                    if item_key in item_keys_to_re_select:
                        items_to_re_select.append(ft_parent)
                else:
                    # Don't create a subgroup: put all fungible UTXOs up right under the item level
                    ft_parent = item

                for utxo in ft_only_utxo_list:
                    item_key2 = key_prefix + "_" + self.get_outpoint_longname(utxo)
                    add_utxo_item(ft_parent, utxo, name, item_key2)

                if ft_parent is not item:
                    item.addChild(ft_parent)

            # Do NFTs next; iterate sorted by commitment, asc
            for commitment_hex, utxo_list in sorted(dd.items(), key=lambda tup: tup[0]):
                utxo_list = sorted(utxo_list, key=lambda u: -u['token_data'].amount)  # Sort by amount, desc
                if not utxo_list:
                    continue

                if commitment_hex:
                    name = f"NFT: {commitment_hex}"
                else:
                    name = "NFT: " + _("zero-length commitment")

                nft_name = self.token_meta.get_nft_display_name(token_id, commitment_hex)
                if nft_name:
                    # Prepend the NFT-specific display-name
                    name = f"{nft_name} {name}"

                nft_icon: Optional[QtGui.QIcon] = self.token_meta.get_icon(token_id, nft_hex=commitment_hex,
                                                                           autogen_if_missing=False)

                if len(utxo_list) == 1:
                    utxo = utxo_list[0]
                    item_key = key_prefix + "_" + self.get_outpoint_longname(utxo)
                    new_item = add_utxo_item(item, utxo, name, item_key)
                    if nft_icon:
                        # Has NFT-specific icon known in metadata, set it to appear next to category name for this NFT
                        new_item.setIcon(self.Col.category, nft_icon)
                else:
                    item_key = key_prefix + "_nft_" + commitment_hex
                    ft_amt = self.token_meta.format_amount(token_id, sum(u['token_data'].amount for u in utxo_list))
                    nfts = str(sum(1 for u in utxo_list if u['token_data'].has_nft()))
                    nft_flags = ', '.join(sorted({token.get_nft_flag_text(u['token_data']) for u in utxo_list},
                                                 key=token.nft_flag_text_sorter))
                    num_minting = sum(1 for u in utxo_list if u['token_data'] and u['token_data'].is_minting_nft())
                    num_mutable = sum(1 for u in utxo_list if u['token_data'] and u['token_data'].is_mutable_nft())
                    num_utxos = str(len(utxo_list))
                    bch_amt = self.parent.format_amount(sum(x['value'] for x in utxo_list), is_diff=False,
                                                        whitespaces=True)
                    nft_parent = SortableTreeWidgetItem([name, ft_amt, nfts, "", "", nft_flags, num_utxos,bch_amt, ""])
                    nft_parent.setData(0, self.DataRoles.item_key, item_key)
                    nft_parent.setData(0, self.DataRoles.token_id, token_id)
                    nft_parent.setData(0, self.DataRoles.utxos, utxo_list)
                    nft_parent.setData(0, self.DataRoles.nft_utxo, None)
                    if nft_icon:
                        # Has NFT-specific icon known in metadata, set it to appear next to category name for this NFT
                        nft_parent.setIcon(self.Col.category, nft_icon)
                    set_fonts(nft_parent)
                    set_icons_inner(nft_parent, num_minting, num_mutable)
                    if item_key in item_keys_to_re_select:
                        items_to_re_select.append(nft_parent)

                    for utxo in utxo_list:
                        item_key2 = key_prefix + "_" + self.get_outpoint_longname(utxo)
                        new_item = add_utxo_item(nft_parent, utxo, name, item_key2)
                        if nft_icon:
                            # Has NFT-specific icon, set it to appear next to category name for this NFT
                            new_item.setIcon(self.Col.category, nft_icon)

                    item.addChild(nft_parent)

            # Lastly, grab the token icon. We set it last because above code may have
            # replaced `item` with another instance.
            item.setIcon(self.Col.category, self.token_meta.get_icon(token_id))
            self.addChild(item)

        # Now, at the very end, enforce previous UI state with respect to what was expanded or not. See #1042
        restore_expanded_items(self.invisibleRootItem(), expanded_item_names)

        # restore selections
        for item in items_to_re_select:
            # NB: Need to select the item at the end because otherwise weird bugs. See #1042.
            item.setSelected(True)

    @if_not_dead
    def create_menu(self, position):
        menu = QMenu()

        selected = self.selectedItems()
        num_selected = len(selected)

        nft_utxos = [item.data(0, self.DataRoles.nft_utxo)
                     for item in selected if item.data(0, self.DataRoles.nft_utxo)]
        non_frozen_utxos = []
        non_frozen_utxos_that_are_editable = []
        non_frozen_utxos_that_are_minting = []
        frozen_utxos = []
        frozen_addresses = set()
        unique_token_ids_selected_that_may_be_frozen_or_unfrozen = set()
        unique_commitments_selected_that_may_be_frozen_or_unfrozen = set()
        fungible_ct = 0

        def recurse_find_non_frozen_leaves(item):
            nonlocal fungible_ct

            if item.childCount() == 0:
                uxs = item.data(0, self.DataRoles.utxos)
                if len(uxs) == 1:
                    utxo = uxs[0]
                    td = utxo['token_data']
                    if td:
                        unique_token_ids_selected_that_may_be_frozen_or_unfrozen.add(td.id_hex)
                        if td.has_nft():
                            unique_commitments_selected_that_may_be_frozen_or_unfrozen.add(td.commitment.hex())
                        else:
                            fungible_ct += 1
                    flags = item.data(0, self.DataRoles.frozen_flags)
                    if 'a' in flags:
                        frozen_addresses.add(utxo['address'])
                    elif 'c' in flags:
                        frozen_utxos.append(utxo)
                    elif not flags:
                        non_frozen_utxos.append(utxo)
                        if td and (td.is_mutable_nft() or td.is_minting_nft()):
                            non_frozen_utxos_that_are_editable.append(utxo)
                            if td.is_minting_nft():
                                non_frozen_utxos_that_are_minting.append(utxo)
                else:
                    self.print_error("WARNING: Unexpected state -- childCount is 0 but we have more than 1 utxo for a"
                                     "QTreeWidgetItem in token_list.py")
            else:
                for i in range(item.childCount()):
                    recurse_find_non_frozen_leaves(item.child(i))

        for item in selected:
            recurse_find_non_frozen_leaves(item)

        non_frozen_utxos = self.dedupe_utxos(non_frozen_utxos)
        frozen_utxos = self.dedupe_utxos(frozen_utxos)
        non_frozen_utxos_that_are_editable = self.dedupe_utxos(non_frozen_utxos_that_are_editable)
        non_frozen_utxos_that_are_minting = self.dedupe_utxos(non_frozen_utxos_that_are_minting,
                                                              # For mint, we only care to grab at most 1 of each token
                                                              # category.
                                                              enforce_unique_token_ids=True)

        def do_copy(txt):
            txt = txt.strip()
            self.parent.copy_to_clipboard(txt)

        col = self.currentColumn()
        column_title = self.headerItem().text(col)
        # Hack to override Category -> CategoryID
        if col == self.Col.category:
            column_title = _("Category ID")

        if num_selected > 0:

            if len(unique_token_ids_selected_that_may_be_frozen_or_unfrozen) == 1:
                token_id_hex = list(unique_token_ids_selected_that_may_be_frozen_or_unfrozen)[0]
                if len(unique_commitments_selected_that_may_be_frozen_or_unfrozen) == 1 and not fungible_ct:
                    # Has 1 or more selected, but it's all the same NFT commitment, so show NFT-level fetch action
                    nft_hex = list(unique_commitments_selected_that_may_be_frozen_or_unfrozen)[0]
                    if self.parent.network and nft_hex:
                        menu.addAction(_("Fetch NFT Metadata"),
                                       lambda: do_update_token_meta(self.parent, token_id_hex, nft_hex=nft_hex))
                else:
                    # If they have a heterogenous set of items selected (NFTs + FTs, etc), but they are all in the
                    # same category, show category-level properties action and fetch action
                    menu.addAction(self.token_meta.get_icon(token_id_hex),
                                   _("Category Properties") + "...", lambda: self.on_edit_metadata(token_id_hex))
                    if self.parent.network:
                        menu.addAction(_("Fetch Category Metadata"),
                                       lambda: do_update_token_meta(self.parent, token_id_hex))

            if num_selected == 1:
                # Single selection
                item = self.itemAt(position)
                if item:
                    nft_utxo = item.data(0, self.DataRoles.nft_utxo)
                    alt_column_title, alt_copy_text = None, None
                    insert_cat_title, insert_cat_text = None, None
                    utxos = item.data(0, self.DataRoles.utxos)
                    is_leaf_utxo = len(utxos) == 1 and item.childCount() == 0
                    if col == self.Col.category:
                        copy_text = item.data(0, self.DataRoles.token_id)
                        if copy_text != item.text(self.Col.category):
                            # Prepend "Copy Token Name" right above "Copy Category ID" in cases where user specified
                            # a token name
                            insert_cat_title = _("Token Name")
                            insert_cat_text = item.text(self.Col.category)
                    elif col == self.Col.output_pt and is_leaf_utxo:
                        copy_text = self.get_outpoint_longname(utxos[0])
                    else:
                        copy_text = item.text(col).strip()
                    if nft_utxo:
                        # NFT child item
                        if col == self.Col.category:
                            alt_column_title = _("NFT Commitment")
                            alt_copy_text = nft_utxo['token_data'].commitment.hex()
                            copy_text = nft_utxo['token_data'].id_hex
                        if copy_text == '-':
                            copy_text = None
                    else:
                        # Top-level item
                        pass

                    if insert_cat_title and insert_cat_text:
                        menu.addAction(_("Copy {}").format(insert_cat_title), lambda: do_copy(insert_cat_text))
                    if copy_text:
                        menu.addAction(_("Copy {}").format(column_title), lambda: do_copy(copy_text))
                    if alt_column_title and alt_copy_text:
                        menu.addAction(_("Copy {}").format(alt_column_title), lambda: do_copy(alt_copy_text))
                    if is_leaf_utxo:
                        txid = utxos[0]['prevout_hash']
                        tx = self.wallet.transactions.get(txid, None)

                        def do_show_tx():
                            self.parent.show_transaction(tx, tx_desc=self.wallet.get_label(txid) or None)
                        if tx:
                            menu.addAction(_("View Tx") + "...", do_show_tx)
            else:
                # Multi-selection
                if col > -1:
                    texts, alt_copy, alt_copy_text = None, None, None
                    if col == self.Col.category:  # token-id or name column
                        texts, seen_token_ids = list(), set()
                        # We do it this way to preserve order, but also to de-duplicate
                        for item in selected:
                            tid = item.data(0, self.DataRoles.token_id)
                            if tid not in seen_token_ids:
                                seen_token_ids.add(tid)
                                texts.append(tid)
                        if nft_utxos:
                            alt_copy = _("Copy {}").format(_("NFT Commitment")) + f" ({len(nft_utxos)})"
                            alt_copy_text = '\n'.join([u['token_data'].commitment.hex() for u in nft_utxos])
                    else:
                        def get_text(item):
                            if col == self.Col.output_pt and item.childCount() == 0:
                                ul = item.data(0, self.DataRoles.utxos)
                                if len(ul) == 1:
                                    return self.get_outpoint_longname(ul[0])
                            return item.text(col).strip()
                        texts = [get_text(i) for i in selected if get_text(i) and get_text(i) != '-']
                        alt_copy_texts = [i.data(0, self.DataRoles.token_id) + ", " + get_text(i)
                                          for i in selected if get_text(i) and get_text(i) != '-']
                        alt_copy_text = "\n".join(alt_copy_texts)
                        primary_col_text = _("Category ID")
                        alt_copy = (_("Copy {}").format(primary_col_text)
                                    + ", " + column_title + f" ({len(alt_copy_texts)})")
                    if texts:
                        copy_text = '\n'.join(texts)
                        menu.addAction(_("Copy {}").format(column_title) + f" ({len(texts)})",
                                       lambda: do_copy(copy_text))
                    if alt_copy and alt_copy_text:
                        menu.addAction(alt_copy, lambda: do_copy(alt_copy_text))
            if frozen_utxos:
                menu.addAction(ngettext(_("Unfreeze Coin"), _("Unfreeze Coins"), len(frozen_utxos)),
                               lambda: self.parent.set_frozen_coin_state(frozen_utxos, False))
            if frozen_addresses:
                menu.addAction(ngettext(_("Unfreeze Address"), _("Unfreeze Addresses"), len(frozen_addresses)),
                               lambda: self.parent.set_frozen_state(frozen_addresses, False))

            menu.addSeparator()
            num_utxos = len(non_frozen_utxos)
            if num_utxos:
                menu.addAction(QtGui.QIcon(":icons/tab_send.svg"),
                               ngettext("Send Token", "Send Tokens", num_utxos)
                               + (f" ({num_utxos})" if num_utxos > 1 else "") + "...",
                               lambda: self.send_tokens(non_frozen_utxos))
            num_editable_utxos = len(non_frozen_utxos_that_are_editable)
            if num_editable_utxos:
                menu.addAction(QtGui.QIcon(":icons/edit_nft.png"),
                               ngettext("Edit NFT Commitment", "Edit NFT Commitments", num_editable_utxos)
                               + (f" ({num_editable_utxos})" if num_editable_utxos > 1 else "") + "...",
                               lambda: self.edit_tokens(non_frozen_utxos_that_are_editable))
            num_minting_utxos = len(non_frozen_utxos_that_are_minting)
            if num_minting_utxos:
                menu.addAction(QtGui.QIcon(":icons/baton.png"), _("Mint NFTs..."),
                               lambda: self.mint_tokens(non_frozen_utxos_that_are_minting))

        menu.addAction(QtGui.QIcon(":icons/tab_token.svg"), _("Create Token") + "...", self.create_new_token)

        menu.exec_(self.viewport().mapToGlobal(position))

    @if_not_dead
    def create_new_token(self):
        self.parent.show_create_new_token_dialog()

    @if_not_dead
    def on_edit_metadata(self, token_id_hex: str):
        self.parent.show_edit_token_metadata_dialog(token_id_hex)

    @classmethod
    def dedupe_utxos(cls, utxos: List[Dict], enforce_unique_token_ids=False) -> List[Dict]:
        deduped_utxos = []
        seen = set()
        seen_token_ids = set()
        for utxo in utxos:
            key = cls.get_outpoint_longname(utxo)
            td = utxo['token_data']
            tid = td and td.id
            if key not in seen and (not enforce_unique_token_ids or not tid or tid not in seen_token_ids):
                seen.add(key)
                if tid:
                    seen_token_ids.add(tid)
                deduped_utxos.append(utxo)
        return deduped_utxos

    @if_not_dead
    def send_tokens(self, utxos: List[Dict[str, Any]]):
        utxos = self.dedupe_utxos(utxos)
        self.parent.send_tokens(utxos)

    @if_not_dead
    def edit_tokens(self, utxos: List[Dict[str, Any]]):
        utxos = self.dedupe_utxos(utxos)
        self.parent.edit_tokens(utxos)

    @if_not_dead
    def mint_tokens(self, utxos: List[Dict[str, Any]]):
        utxos = self.dedupe_utxos(utxos, enforce_unique_token_ids=True)
        self.parent.mint_tokens(utxos)

    @if_not_dead
    def update_labels(self):
        self.update()

    def on_doubleclick(self, item, column):
        if self.permit_edit(item, column):
            super().on_doubleclick(item, column)
        else:
            utxos = item.data(0, self.DataRoles.utxos)
            if len(utxos) == 1 and item.childCount() == 0:  # Leaf utxo item, show transaction
                tx_hash = utxos[0]['prevout_hash']
                tx = self.wallet.transactions.get(tx_hash)
                if tx:
                    label = self.wallet.get_label(tx_hash) or None
                    self.parent.show_transaction(tx, label)

    def showEvent(self, e):
        super().showEvent(e)
        if e.isAccepted():
            self.parent.warn_about_cashtokens_if_hw_wallet()
