#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
# This file (c) 2023-2026 Calin Culianu <calin.culianu@gmail.com>
# Part of the Electron Cash SPV Wallet
# License: MIT
""" Encapsulation and handling of token metadata -- Qt-specific functions """

import os

from typing import Optional, Tuple

from electroncash.i18n import _
from electroncash.token_meta import DownloadedMetaData, TokenMeta, try_to_download_metadata
from .util import WaitingDialog
from .utils import qblockies

from PyQt5.QtCore import QBuffer, QByteArray, QDir, QIODevice, QTemporaryFile
from PyQt5.QtGui import QColor, QIcon, QPixmap


class TokenMetaQt(TokenMeta):

    def _icon_to_bytes(self, icon: QIcon) -> bytes:
        ba = QByteArray()
        buffer = QBuffer(ba)
        buffer.open(QIODevice.WriteOnly)
        pm = icon.pixmap(32, 32)
        pm.save(buffer, "PNG")
        return bytes(ba)

    def _bytes_to_icon(self, buf: bytes) -> QIcon:
        ba = QByteArray(buf)
        pm = QPixmap()
        pm.loadFromData(ba, "PNG")
        icon = QIcon(pm)
        return icon

    def gen_default_icon(self, token_id_hex: str) -> QIcon:
        img = qblockies.create(token_id_hex, size=12, scale=4, spotcolor=QColor(0, 0, 0))
        return QIcon(QPixmap.fromImage(img))

    @property
    def _icon_ext(self) -> str:
        """Override"""
        return "png"

    def convert_downloaded_icon(self, icon_data: bytes, icon_ext: str) -> Optional[QIcon]:
        """Reimplemented from super"""
        if icon_ext and not icon_ext.startswith('.'):
            icon_ext = f".{icon_ext}"
        # e.g.: /path/to/tmp/XXXXXX.svg
        f = QTemporaryFile(os.path.join(QDir.tempPath(), "XXXXXX") + (icon_ext or ''))
        if f.open():
            f.write(icon_data)
            f.flush()
            return QIcon(f.fileName())


def do_update_token_meta(window, token_id_hex: str, nft_hex: Optional[str] = None) -> bool:
    from .main_window import ElectrumWindow
    assert isinstance(window, ElectrumWindow)
    meta: Optional[TokenMetaQt] = window.token_meta
    if not meta or not window.wallet:  # Paranoia, should never happen
        return False
    dlg = None  # this will be set at the bottom of this function

    update_item = _("token category") if not nft_hex else _("token category + NFT")
    item_text = _("this item")

    def task():
        return (try_to_download_metadata(window.wallet, token_id_hex),
                try_to_download_metadata(window.wallet, token_id_hex, nft_hex=nft_hex) if nft_hex else None)

    success = False

    def on_success(tup: Tuple[Optional[DownloadedMetaData], Optional[DownloadedMetaData]]):
        nonlocal success, item_text

        parent, nft = tup

        if parent:
            if parent.name:
                meta.set_token_display_name(token_id_hex, parent.name)
            if parent.symbol:
                meta.set_token_ticker_symbol(token_id_hex, parent.symbol)
            item_text = meta.format_token_display_name(token_id_hex)
            if parent.icon:
                meta.set_icon(token_id_hex, meta.convert_downloaded_icon(parent.icon, parent.icon_ext))
            meta.set_token_decimals(token_id_hex, parent.decimals)

        if nft_hex and nft:
            if nft.name and nft.name != parent.name:
                meta.set_nft_display_name(token_id_hex, nft_hex, nft.name)
                item_text = meta.format_token_display_name(token_id_hex, nft=nft_hex)
            if nft.icon and nft.icon != parent.icon:
                meta.set_icon(token_id_hex, meta.convert_downloaded_icon(nft.icon, nft.icon_ext), nft_hex=nft_hex)

        success = bool(parent and (not nft_hex or nft is not None))

    # kick off the waiting dialog to do all of the above
    dlg = WaitingDialog(window.top_level_window(),
                        _("Fetching metadata for this {update_item}, please wait ...").format(update_item=update_item),
                        task, on_success, window.on_error, disable_escape_key=True,
                        auto_exec=False, auto_show=False, progress_bar=False)
    dlg.exec_()  # this will block here in the WaitingDialog event loop... and set success to True if success

    window.update_tabs()
    if success:
        window.statusBar().showMessage(_('Successfully fetched and applied metadata for "{item_text}"')
                                       .format(item_text=item_text), 5000)
    else:
        trailing_text = _("Category") + ": " + token_id_hex
        if nft_hex:
            trailing_text += f", NFT: {nft_hex}"
        window.statusBar().showMessage(_("Failed to fetch metadata for {trailing_text}")
                                       .format(trailing_text=trailing_text), 5000)
