#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
# This file (c) 2023 Calin Culianu <calin.culianu@gmail.com>
# Part of the Electron Cash SPV Wallet
# License: MIT
""" Encapsulation and handling of token metadata """

import hashlib
import json
import os
import requests
import threading

from abc import ABCMeta, abstractmethod
from typing import Any, Dict, List, Optional, Union

from electroncash import address, token, util
from electroncash.simple_config import SimpleConfig
from electroncash.transaction import Transaction
from electroncash.token_meta_fbch import try_to_get_fbch_metadata

class TokenMeta(util.PrintError, metaclass=ABCMeta):

    def __init__(self, config: SimpleConfig):
        util.PrintError.__init__(self)
        self.config = config
        self.lock = threading.RLock()
        self.path = os.path.join(config.electrum_path(), "cashtoken_meta")
        self.make_dir(self.path)
        self.icons_path = os.path.join(self.path, "icons")
        self.make_dir(self.icons_path)
        self._icon_cache: Dict[str, Any] = dict()
        self.d: Dict[str, Any] = dict()
        self.dirty = False  # True if we wrote some keys to self.d, but they are not yet saved to disk
        self.load()

    def load(self):
        with self.lock:
            metafile = os.path.join(self.path, "metadata.json")
            if os.path.exists(metafile):
                try:
                    with open(metafile, "rt", encoding='utf-8') as f:
                        jdata = f.read()
                        self.d = json.loads(jdata)
                except (OSError, json.JSONDecodeError, TypeError, ValueError) as e:
                    self.print_error(f"Error loading {metafile}: {e!r}")

    def save(self, force=False):
        if not force and not self.dirty:
            return
        with self.lock:
            metafile = os.path.join(self.path, "metadata.json")
            metafile_tmp = metafile + ".tmp"
            try:
                jdata = json.dumps(self.d)
                with open(metafile_tmp, "wt", encoding='utf-8') as f:
                    f.write(jdata)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(metafile_tmp, metafile)
            except (TypeError, ValueError, json.JSONDecodeError, OSError) as e:
                self.print_error(f"Unable to save data to {metafile}: {e!r}")
            self.dirty = False

    @staticmethod
    def make_dir(path):
        util.make_dir(path)
        assert os.path.exists(path) and os.path.isdir(path)

    def get_icon(self, token_id_hex: str) -> Any:
        """ Gets the actual icon. On Qt for example this will return a QImage. Intended to be overridden """
        icon = self._icon_cache.get(token_id_hex)
        if icon:
            return icon
        buf = self._read_icon_file(self._icon_filepath(token_id_hex))
        if buf:
            icon = self._bytes_to_icon(buf)
        if not icon:
            icon = self.gen_default_icon(token_id_hex)
        assert icon is not None
        self._icon_cache[token_id_hex] = icon
        return icon

    def _icon_filepath(self, token_id_hex: str) -> str:
        return os.path.join(self.icons_path, token_id_hex) + "." + self._icon_ext

    def set_icon(self, token_id_hex: str, icon: Any):
        fname = self._icon_filepath(token_id_hex)
        buf = (icon is not None and self._icon_to_bytes(icon)) or None
        self._write_icon_file(fname, buf)
        if icon is not None:
            self._icon_cache[token_id_hex] = icon

    @property
    def _icon_ext(self) -> str:
        """Reimplement in subclasses to define the icon file extension. Default is "png" """
        return "png"

    def _read_icon_file(self, filepath: str) -> Optional[bytes]:
        with self.lock:
            if not os.path.exists(filepath):
                return None
            with open(filepath, "rb") as f:
                return f.read(1_000_000)  # Read up to 1MB

    @abstractmethod
    def _icon_to_bytes(self, icon: Any) -> bytes:
        """Reimplement in subclasses to take whatever icon format the platform expects and spit out bytes"""
        pass

    @abstractmethod
    def _bytes_to_icon(self, buf: bytes) -> Any:
        """Reimplement in subclasses to take whatever icon format the platform expects and spit out bytes"""
        pass

    @abstractmethod
    def gen_default_icon(self, token_id_hex: str) -> Any:
        """Reimplement in subclasses to generate a default icon for a token_id if the icon file is missing"""
        pass

    def _write_icon_file(self, filepath: str, buf: Optional[bytes]):
        with self.lock:
            try:
                os.remove(filepath)
            except OSError:
                pass
            if buf is None:
                return
            with open(filepath, "wb") as f:
                f.write(buf)

    def get_token_display_name(self, token_id_hex: str) -> Optional[str]:
        """Returns None if not found or if empty, otherwise returns the display name if found and not empty"""
        ret = self.d.get("display_names", {}).get(token_id_hex)
        if isinstance(ret, str):
            return ret

    def get_token_ticker_symbol(self, token_id_hex: str) -> Optional[str]:
        ret = self.d.get("tickers", {}).get(token_id_hex)
        if isinstance(ret, str):
            return ret

    def get_token_decimals(self, token_id_hex: str) -> Optional[int]:
        """Returns None if unknown or undefined decimals for token"""
        ret = self.d.get("decimals", {}).get(token_id_hex)
        if isinstance(ret, int):
            return ret
        return ret

    def set_token_display_name(self, token_id_hex: str, name: Optional[str]):
        dd = self.d.get("display_names", {})
        if name is None:
            dd.pop(token_id_hex, None)
        elif isinstance(name, str):
            was_empty = not dd
            dd[token_id_hex] = str(name)
            if was_empty:
                self.d["display_names"] = dd
        self.dirty = True

    def set_token_ticker_symbol(self, token_id_hex: str, ticker: Optional[str]):
        dd = self.d.get("tickers", {})
        if ticker is None:
            dd.pop(token_id_hex, None)
        elif isinstance(ticker, str):
            was_empty = not dd
            dd[token_id_hex] = str(ticker)
            if was_empty:
                self.d["tickers"] = dd
        self.dirty = True

    def set_token_decimals(self, token_id_hex: str, decimals: Optional[int]):
        dd = self.d.get("decimals", {})
        if decimals is None:
            dd.pop(token_id_hex, None)
        elif isinstance(decimals, int):
            was_empty = not dd
            dd[token_id_hex] = int(decimals)
            if was_empty:
                self.d["decimals"] = dd
        self.dirty = True

    @staticmethod
    def _normalize_to_token_id_hex(token_or_id: Union[str, token.OutputData, bytes]) -> str:
        assert isinstance(token_or_id, (str, bytes, bytearray, token.OutputData))
        if isinstance(token_or_id, str):
            return token_or_id
        elif isinstance(token_or_id (bytes, bytearray)):
            return token_or_id.hex()
        else:
            return token_or_id.id_hex

    def format_amount(self, token_or_id: Union[str, token.OutputData, bytes], fungible_amount: int,
                      num_zeros=0, is_diff=False, whitespace=False, precision=None,
                      append_tokentoshis=False) -> str:
        """Formats a particular token's amount string, according to that token's metadata spec for decimals.
        If the token is unknown we tread the 'decimals' for that token as '0'."""
        token_id_hex = self._normalize_to_token_id_hex(token_or_id)
        decimals = self.get_token_decimals(token_id_hex)
        if not isinstance(decimals, int):
            decimals = 0
        return token.format_fungible_amount(fungible_amount, decimal_point=decimals, num_zeros=num_zeros,
                                            precision=precision, is_diff=is_diff, whitespaces=whitespace,
                                            append_tokentoshis=append_tokentoshis)

    def parse_amount(self, token_or_id: Union[str, token.OutputData, bytes], val: str) -> int:
        """Inverse of above"""
        token_id_hex = self._normalize_to_token_id_hex(token_or_id)
        decimals = self.get_token_decimals(token_id_hex)
        if not isinstance(decimals, int):
            decimals = 0
        return token.parse_fungible_amount(val, decimal_point=decimals)

    def format_token_display_name(self, token_or_id: Union[str, token.OutputData, bytes],
                                  format_str="{token_name} ({token_symbol})"):
        token_id_hex = self._normalize_to_token_id_hex(token_or_id)
        tn = self.get_token_display_name(token_id_hex)
        if tn:
            tn = tn.strip()
        tn = tn or token_id_hex
        tsym = self.get_token_ticker_symbol(token_id_hex)
        if tsym:
            tsym = tsym.strip()
        if not tsym:
            return tn
        return format_str.format(token_name=tn, token_symbol=tsym)


def try_to_find_genesis_tx(wallet, token_id_hex, timeout=30) -> Optional[Transaction]:
    """This is potentially slow because it does go out to the network and may end up retrieving quite a few
    transactions to determine what spent token_id_hex:0."""
    assert isinstance(token_id_hex, str) and len(token_id_hex) == 64
    # First, see if it's a wallet tx, find the pre-genesis
    try:
        tx = wallet.try_to_get_tx(token_id_hex, allow_network_lookup=True, timeout=timeout)
    except util.TimeoutException as e:
        util.print_error(f"Failed to get pre-genesis tx for {token_id_hex}; got exception: {e!r}")
        return None
    if not tx:
        util.print_error(f"Failed to get pre-genesis tx for {token_id_hex}; not found")
        return None

    # Next, see what address spends output 0
    addr_or_script = tx.outputs()[0][1] if tx.outputs() else None
    if not addr_or_script:
        util.print_error(f"Failed to get pre-genesis tx for {token_id_hex}; no outputs!")
        return None
    # Maybe it's one of ours?
    h = wallet.get_address_history(addr_or_script)
    if not h:
        # Nope, get a full address history from the network for this address
        if not wallet.network:
            util.print_error(f"Failed to get pre-genesis tx for {token_id_hex}; no network!")
            return None
        try:
            request = ("blockchain.scripthash.get_history", [addr_or_script.to_scripthash_hex()])
            h2 = wallet.network.synchronous_get(request)
        except Exception as e:
            util.print_error(f"Failed to get pre-genesis tx for {token_id_hex};"
                             f" failed to retrieve history for {addr_or_script}; got exception: {e!r}")
            return None
        h = [(x.get('tx_hash', ''), x.get('height', 0)) for x in h2]

    # Next, find the height for the pre-genesis tx
    for tx_hash, height in h:
        if tx_hash == token_id_hex:
            confirmed_height = height
            break
    else:
        util.print_error(f"Failed to get pre-genesis tx for {token_id_hex};"
                         f" could not find tx in history for {addr_or_script}")
        return None

    # Examine all txns that are >= the height of the pre-genesis
    for tx_hash, height in h:
        is_candidate = height <= 0 or height >= confirmed_height  # Pick up mempool + anything >= confirmed_height
        if is_candidate and tx_hash != token_id_hex:
            try:
                tx2 = wallet.try_to_get_tx(tx_hash, allow_network_lookup=True, timeout=timeout)
            except util.TimeoutException as e:
                util.print_error(f"Failed to get pre-genesis tx for {token_id_hex}; could not get potential child tx"
                                 f" {tx_hash}; got exception: {e!r}")
                return None
            if not tx2:
                util.print_error(f"Failed to get pre-genesis tx for {token_id_hex}; could not get potential"
                                 f" child tx {tx_hash}")
                return None
            for inp in tx2.inputs():
                if inp['prevout_n'] == 0 and inp['prevout_hash'] == token_id_hex:
                    # Found it!
                    return tx2
    else:
        util.print_error(f"Failed to get pre-genesis tx for {token_id_hex};"
                         f" found the tx but could not find its child tx in history!")
    return None


def try_to_get_bcmr_op_return_pushes(wallet, token_id_hex, timeout=30) -> Optional[List[bytes]]:
    """Synchronously finds the genesis tx by calling try_to_find_genesis_tx(), and attempts to parse it."""
    tx = try_to_find_genesis_tx(wallet, token_id_hex, timeout)
    if not tx:
        return None
    for i, (_, script, _) in enumerate(tx.outputs()):
        if isinstance(script, address.ScriptOutput) and script.is_opreturn():
            try:
                pushes = address.Script.get_ops(script.to_script()[1:])
            except address.ScriptError as e:
                util.print_error(f"Tx: {token_id_hex} Output: {i}, could not parse OP_RETURN"
                                 f" {script.to_script().hex()}: {e!r}")
                continue
            if (all(isinstance(t, tuple) and len(t) == 2 and isinstance(t[0], int)
                    and isinstance(t[1], (bytes, bytearray)) for t in pushes)
                and len(pushes) >= 2 and pushes[0] == (4, b'BCMR') and pushes[1][0] == 32):
                return [p[1] for p in pushes[1:]]
            else:
                util.print_error(f"Tx: {token_id_hex} Output: {i}, malformed BCMR OP_RETURN:"
                                 f" {script.to_script().hex()}, pushes: {pushes!r}")


class DownloadedMetaData:
    """Encapsulates downloaded metadata"""
    __slots__ = ('name', 'description', 'decimals', 'symbol', 'icon', 'icon_ext')

    name: str
    description: str
    decimals: int
    symbol: str
    icon: Optional[bytes]
    icon_ext: Optional[str]

    def __init__(self):
        self.name = self.description = self.symbol = ''
        self.decimals = 0
        self.icon = self.icon_ext = None

    def __repr__(self):
        icon_thing = len(self.icon) if self.icon is not None else None
        return f"<DownloadedMetaData name={self.name} description={self.description} decimals={self.decimals}" \
               f" symbol={self.symbol}, icon_ext={self.icon_ext} icon={icon_thing} bytes>"


def try_to_download_metadata(wallet, token_id_hex, timeout=30) -> Optional[DownloadedMetaData]:
    """Synchronously find the genesis tx, download metadata if it has properly formed BCMR, and return
    an object describing what was found. May return None on timeout or other error."""
    pushes = try_to_get_bcmr_op_return_pushes(wallet, token_id_hex, timeout=timeout)
    if not pushes or len(pushes) < 2:
        # If bcmr failed, see if the token category is FBCH
        fbch_md = try_to_get_fbch_metadata(wallet, token_id_hex)
        if fbch_md:
            return fbch_md
        return None

    shasum = pushes[0]
    for url in pushes[1:]:
        try:
            url = url.decode("utf-8")
        except UnicodeError as e:
            util.print_error(f"Failed to decode url: {url!r} as utf-8, skipping...")

        def rewrite_if_ipfs(u: str) -> str:
            if u.lower().startswith("ipfs://"):
                parts = u[7:].split('/', 1)
                last_part = '/' + '/'.join(parts[1:]) if len(parts) >= 2 else ''
                cid = parts[0]
                ret = f"https://dweb.link/ipfs/{cid}{last_part}"
                util.print_error(f"Rewrote \"{u}\" -> \"{ret}\"")
                return ret
            else:
                return u

        url = rewrite_if_ipfs(url)
        if not url.lower().startswith("https://"):
            url = "https://" + url
        r = requests.get(url, timeout=timeout)
        if r.ok:
            util.print_error(f"Downloaded {len(r.content)} bytes from {url}")
            sha = hashlib.sha256()
            sha.update(bytes(r.content))
            digest = sha.digest()
            if digest != shasum and digest[::-1] != shasum:
                util.print_error(f"Warning: hash mismatch for json document at {url}, proceeding anyway...")
            try:
                jdoc = json.loads(r.content.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeError) as e:
                util.print_error(f"Got exception decoding from {url}: {e!r}")
                continue
            identities = jdoc.get("identities", {})
            if not identities and not isinstance(identities, dict):
                util.print_error(f"Bad identity found from {url}")
                continue
            for identity, d in identities.items():
                if isinstance(d, list):
                    # Support broken spec
                    d = {-i:val for i, val in enumerate(d)}
                if not isinstance(d, dict) or not d:
                    util.print_error(f"Expected dict in identity {identity} from {url}")
                    break
                times = sorted(d.keys(), reverse=True)
                for t in times:
                    dd = d[t]
                    tok = dd.get("token", {})
                    if not tok or not isinstance(tok, dict):
                        util.print_error(f"Expected a 'token' dict in identity {identity}:{t}  from {url}")
                        continue
                    cat = tok.get("category", "")
                    if cat != token_id_hex:
                        util.print_error(f"Skipping category {cat}")
                        continue
                    decimals = tok.get("decimals", 0)
                    try:
                        decimals = int(decimals)
                    except (ValueError, TypeError):
                        pass
                    decimals = min(max(0, decimals), 19) if isinstance(decimals, int) else 0
                    name = dd.get("name", "")
                    name = name[:30] if isinstance(name, str) else ""
                    description = dd.get("description", "")
                    description = description[:80] if isinstance(description, str) else ""
                    symbol = tok.get("symbol", "")
                    symbol = symbol[:4] if isinstance(symbol, str) else ""

                    md = DownloadedMetaData()
                    md.decimals = decimals
                    md.symbol = symbol
                    md.name = name
                    md.description = description

                    uris = dd.get("uris", {})
                    if uris and isinstance(uris, dict):
                        icon_url = uris.get("icon")
                        if icon_url and isinstance(icon_url, str):

                            icon_url = rewrite_if_ipfs(icon_url)
                            r2 = requests.get(icon_url, timeout=timeout)
                            if r2.ok:
                                util.print_error(f"Downloaded {len(r2.content)} bytes from {icon_url}")
                                md.icon = r2.content
                                md.icon_ext = os.path.splitext(icon_url)[-1]
                            else:
                                util.print_error(f"Got error downloading icon from {icon_url}: {r2.status_code}"
                                                 f" {r2.reason}")
                    return md
        else:
            util.print_error(f"Got error requesting url {url}: {r.status_code} {r.reason}")
