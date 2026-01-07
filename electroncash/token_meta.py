#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
# This file (c) 2023-2026 Calin Culianu <calin.culianu@gmail.com>
# Part of the Electron Cash SPV Wallet
# License: MIT
""" Encapsulation and handling of token metadata """

import hashlib
import json
import os
import requests
import threading

from abc import ABCMeta, abstractmethod
from typing import Any, Dict, List, Optional, Tuple, Union

from electroncash import address, token, util
from electroncash.simple_config import SimpleConfig
from electroncash.transaction import Transaction


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

    @staticmethod
    def _mk_icon_key(token_id_hex, nft_hex):
        return token_id_hex if not nft_hex else f"{token_id_hex}_{nft_hex}"

    def get_icon(self, token_id_hex: str, *, nft_hex: Optional[str] = None, autogen_if_missing=True) -> Optional[Any]:
        """Gets the token-specific (or NFT-specific) icon object. On Qt for example this will return a QIcon.
        If no real icon is known for this token and/or NFT, returns the default "generated" icon, unless
        autogen_if_missing=False in which case it returns None."""
        key = self._mk_icon_key(token_id_hex, nft_hex)
        icon = self._icon_cache.get(key)
        if icon:
            return icon
        buf = self._read_icon_file(self._icon_filepath(key))
        if buf:
            icon = self._bytes_to_icon(buf)
        if not icon:
            if not autogen_if_missing:
                # Special case: Return None to indicate there is no icon known
                return None
            icon = self.gen_default_icon(token_id_hex)
        assert icon is not None
        self._icon_cache[key] = icon
        return icon

    def _icon_filepath(self, token_id_hex: str, *, nft_hex: Optional[str] = None) -> str:
        key = self._mk_icon_key(token_id_hex, nft_hex)
        return os.path.join(self.icons_path, key) + "." + self._icon_ext

    def set_icon(self, token_id_hex: str, icon: Any, *, nft_hex: Optional[str] = None):
        fname = self._icon_filepath(token_id_hex, nft_hex=nft_hex)
        buf = (icon is not None and self._icon_to_bytes(icon)) or None
        self._write_icon_file(fname, buf)
        if icon is not None:
            self._icon_cache[self._mk_icon_key(token_id_hex, nft_hex)] = icon

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
        """Reimplement in subclasses to take bytes and spit out whatever icon format the platform expects"""
        pass

    @abstractmethod
    def gen_default_icon(self, token_id_hex: str) -> Any:
        """Reimplement in subclasses to generate a default icon for a token_id if the icon file is missing"""
        pass

    def convert_downloaded_icon(self, icon_data: bytes, icon_ext: str) -> Any:
        """Reimplement in subclasses to convert the downloaded icon byte buffer into a platform-specific format"""
        return self._bytes_to_icon(icon_data)

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

    def _get_nft_meta(self, token_id_hex: str, nft_hex: str, create_if_missing=False) -> dict:
        empty = {}
        if nft_hex and isinstance(nft_hex, str):
            ret = self.d.get("nfts", empty).get(token_id_hex, empty).get(nft_hex, empty)
            if ret is empty and create_if_missing:
                dict_by_token_id = self.d.get("nfts")
                if dict_by_token_id is None:
                    self.d["nfts"] = dict_by_token_id = {}
                dict_by_nft_id = dict_by_token_id.get(token_id_hex)
                if dict_by_nft_id is None:
                    dict_by_nft_id = dict_by_token_id[token_id_hex] = {}
                ret = dict_by_nft_id[nft_hex] = {}
            if isinstance(ret, dict):
                return ret
        return empty

    def get_token_display_name(self, token_id_hex: str) -> Optional[str]:
        """Returns None if not found or if empty, otherwise returns the display name if found and not empty."""
        ret = self.d.get("display_names", {}).get(token_id_hex)
        if isinstance(ret, str):
            return ret

    def get_nft_display_name(self, token_id_hex: str, nft_hex: str):
        ret = self._get_nft_meta(token_id_hex, nft_hex).get("display_name")
        if ret and isinstance(ret, str):
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

    def has_any_metadata_for(self, token_id_hex: str, nft_hex: Optional[str] = None) -> bool:
        if nft_hex:
            return (self.get_nft_display_name(token_id_hex, nft_hex) is not None
                    or self.get_icon(token_id_hex, nft_hex=nft_hex, autogen_if_missing=False) is not None)
        return (self.get_token_display_name(token_id_hex) is not None
                or self.get_token_ticker_symbol(token_id_hex) is not None
                or self.get_token_decimals(token_id_hex) is not None
                or self.get_icon(token_id_hex, autogen_if_missing=False) is not None)

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

    def set_nft_display_name(self, token_id_hex: str, nft_hex: str, name: Optional[str]):
        dd = self._get_nft_meta(token_id_hex, nft_hex, create_if_missing=True)
        if name is None:
            dd.pop("display_name", None)
        elif isinstance(name, str):
            dd["display_name"] = str(name)
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
    def _normalize_to_token_id_hex(token_or_id: Union[str, token.OutputData, bytes, bytearray]) -> str:
        assert isinstance(token_or_id, (str, bytes, bytearray, token.OutputData))
        if isinstance(token_or_id, str):
            return token_or_id
        elif isinstance(token_or_id, (bytes, bytearray)):
            return token_or_id[::-1].hex()  # reverse
        else:
            return token_or_id.id_hex

    @staticmethod
    def _normalize_to_nft_hex(nft: Union[str, token.OutputData, bytes, bytearray]) -> str:
        assert isinstance(nft, (str, token.OutputData, bytes, bytearray))
        if isinstance(nft, str):
            return nft
        elif isinstance(nft, (bytes, bytearray)):
            return nft.hex()  # don't reverse
        else:
            return nft.commitment.hex()  # don't reverse

    def format_amount(self, token_or_id: Union[str, token.OutputData, bytes, bytearray], fungible_amount: int,
                      num_zeros=0, is_diff=False, whitespace=False, precision=None,
                      append_tokentoshis=False, decimals=None) -> str:
        """Formats a particular token's amount string, according to that token's metadata spec for decimals.
        If the token is unknown we tread the 'decimals' for that token as '0'."""
        if decimals is None:
            token_id_hex = self._normalize_to_token_id_hex(token_or_id)
            decimals = self.get_token_decimals(token_id_hex)
        if not isinstance(decimals, int):
            decimals = 0
        return token.format_fungible_amount(fungible_amount, decimal_point=decimals, num_zeros=num_zeros,
                                            precision=precision, is_diff=is_diff, whitespaces=whitespace,
                                            append_tokentoshis=append_tokentoshis)

    def parse_amount(self, token_or_id: Union[str, token.OutputData, bytes, bytearray], val: str) -> int:
        """Inverse of above"""
        token_id_hex = self._normalize_to_token_id_hex(token_or_id)
        decimals = self.get_token_decimals(token_id_hex)
        if not isinstance(decimals, int):
            decimals = 0
        return token.parse_fungible_amount(val, decimal_point=decimals)

    def format_token_display_name(self, token_or_id: Union[str, token.OutputData, bytes, bytearray],
                                  format_str="{token_name} ({token_symbol})",
                                  *, nft: Optional[Union[str, token.OutputData, bytes, bytearray]] = None) -> str:
        token_id_hex = self._normalize_to_token_id_hex(token_or_id)
        nft_hex: Optional[str] = self._normalize_to_nft_hex(nft) if nft else None
        tn = None
        if nft_hex:
            tn = self.get_nft_display_name(token_id_hex, nft_hex)
        if not tn:
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

    def sanitize(self):
        """Cleans up some fields for this object to enforce invariants"""
        try:
            self.decimals = int(self.decimals)
        except (ValueError, TypeError):
            pass
        self.decimals = min(max(0, self.decimals), 19) if isinstance(self.decimals, int) else 0
        self.name = self.name[:30] if isinstance(self.name, str) else ""
        self.description = self.description[:80] if isinstance(self.description, str) else ""
        self.symbol = self.symbol[:4] if isinstance(self.symbol, str) else ""


def _rewrite_if_ipfs(u: str) -> str:
    """Rewrites any ipfs-style URLs to https using a proxy site that serves such things"""
    if u.lower().startswith("ipfs://"):
        parts = u[7:].split('/', 1)
        last_part = '/' + '/'.join(parts[1:]) if len(parts) >= 2 else ''
        cid = parts[0]
        ret = f"https://dweb.link/ipfs/{cid}{last_part}"
        util.print_error(f"Rewrote \"{u}\" -> \"{ret}\"")
        return ret
    else:
        return u


def _try_to_dl_icon(icon_url: str, *, timeout=30) -> Optional[Tuple[bytes, str]]:
    """Given an icon url, download the icon and return a tuple of (icon_bytes, filename_extension) or None on error"""
    if not icon_url or not isinstance(icon_url, str):
        return
    icon_url = _rewrite_if_ipfs(icon_url)
    r2 = requests.get(icon_url, timeout=timeout, allow_redirects=True)
    if not r2.ok:
        util.print_error(f"Got error downloading icon from {icon_url}: {r2.status_code} {r2.reason}")
        return
    util.print_error(f"Downloaded {len(r2.content)} bytes from {icon_url}")
    icon = r2.content
    # Figure out the icon extension from the content-type header if present, otherwise fall-back to filename-based ext.
    if r2.headers.get("Content-Type", "").startswith("image/"):
        icon_ext = "." + r2.headers["Content-Type"][6:]
        util.print_error(f"Image type from header: {icon_ext}")
    else:
        icon_ext = os.path.splitext(icon_url)[-1]
        util.print_error(f"Image type from filename: {icon_ext}")
    return icon, icon_ext


PAYTACA_HOST = "bcmr.paytaca.com"


def _try_to_dl_from_paytaca_indexer(token_id_hex, timeout=30, *, skip_icon=False,
                                    nft_hex=None) -> Optional[DownloadedMetaData]:
    """Download metadata from the paytaca indexer"""
    if not nft_hex:
        url = f"https://{PAYTACA_HOST}/api/tokens/{token_id_hex}/"
    else:
        url = f"https://{PAYTACA_HOST}/api/tokens/{token_id_hex}/{nft_hex}"
    r = requests.get(url, timeout=timeout, allow_redirects=True)
    if not r.ok:
        util.print_error(f"Got error requesting url {url}: {r.status_code} {r.reason}")
        return
    try:
        jdoc = json.loads(r.content.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeError) as e:
        util.print_error(f"Got exception decoding from {url}: {e!r}")
        return
    if not isinstance(jdoc, dict):
        util.print_error(f"Invalid format for JSON content downloaded from {url}, not a dict: {jdoc}")
        return
    if "error" in jdoc:
        util.print_error(f"Got error reply from {url}: {jdoc.get('error')}")
        return
    md = DownloadedMetaData()
    md.name = jdoc.get("name")
    if not md.name:
        util.print_error(f'Required key "name" missing or empty in JSON downloaded from {url}')
        return
    md.description = jdoc.get("description", "")

    # Handle NFT-specific metadata
    nft_icon_override = None
    if nft_hex and "type_metadata" in jdoc:
        ndict = jdoc["type_metadata"]
        if isinstance(ndict, dict):
            nft_name = ndict.get("name")
            if isinstance(nft_name, str):
                md.name = nft_name
            nft_desc = ndict.get("description")
            if isinstance(nft_desc, str):
                md.description = nft_desc
            nft_uris = ndict.get("uris")
            if isinstance(nft_uris, dict):
                nft_icon = nft_uris.get("icon")
                if nft_icon and isinstance(nft_icon, str):
                    nft_icon_override = nft_icon

    tdict = jdoc.get("token")
    if not isinstance(tdict, dict) or tdict.get("category") != token_id_hex:
        util.print_error(f'Invalid "token" dict downloaded from {url}: {tdict}')
        return
    md.symbol = tdict.get("symbol", "")
    md.decimals = tdict.get("decimals", 0)
    if nft_hex and "decimals" not in tdict:
        # Hack to get the "decimals" from the NFT parent if missing in child NFT results
        util.print_error(f'Missing "decimals" for NFT, downloading parent info for: {token_id_hex} ...')
        md2 = _try_to_dl_from_paytaca_indexer(token_id_hex, timeout=timeout, skip_icon=True, nft_hex=None)
        if md2:
            md.decimals = md2.decimals

    # Next, try and download the icon
    if not skip_icon:
        icon_url = nft_icon_override or None
        if not icon_url:
            udict = jdoc.get("uris")
            if isinstance(udict, dict) and "icon" in udict:
                icon_url = udict["icon"]
        res = _try_to_dl_icon(icon_url, timeout=timeout)
        if res:
            md.icon, md.icon_ext = res
    md.sanitize()
    return md


def _try_to_dl_from_blockchain(wallet, token_id_hex, *, timeout=30, skip_icon=False) -> Optional[DownloadedMetaData]:
    """Synchronously find the genesis tx, download metadata if it has properly formed BCMR, and return
    an object describing what was found. May return None on timeout or other error."""
    pushes = try_to_get_bcmr_op_return_pushes(wallet, token_id_hex, timeout=timeout)
    if not pushes or len(pushes) < 2:
        return None

    shasum = pushes[0]
    for url in pushes[1:]:
        try:
            url = url.decode("utf-8")
        except UnicodeError as e:
            util.print_error(f"Failed to decode url: {url!r} as utf-8, skipping...")

        url = _rewrite_if_ipfs(url)
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
                        util.print_error(f'Expected a "token" dict in identity {identity}:{t} from {url}')
                        continue
                    cat = tok.get("category", "")
                    if cat != token_id_hex:
                        util.print_error(f"Skipping category {cat}")
                        continue
                    decimals = tok.get("decimals", 0)
                    name = dd.get("name", "")
                    description = dd.get("description", "")
                    symbol = tok.get("symbol", "")

                    md = DownloadedMetaData()
                    md.decimals = decimals
                    md.symbol = symbol
                    md.name = name
                    md.description = description

                    uris = dd.get("uris", {})
                    if not skip_icon and uris and isinstance(uris, dict):
                        icon_url = uris.get("icon")
                        res = _try_to_dl_icon(icon_url, timeout=timeout)
                        if res:
                            md.icon, md.icon_ext = res
                    md.sanitize()
                    return md
        else:
            util.print_error(f"Got error requesting url {url}: {r.status_code} {r.reason}")


def try_to_download_metadata(wallet, token_id_hex, timeout=30, *, skip_icon=False,
                             use_indexers=True, use_blockchain=True,
                             nft_hex: Optional[str] = None) -> Optional[DownloadedMetaData]:
    """Tries to get BCMR metadata given a token_id_hex (category id). First, tries the paytaca indexer (faster),
    then if that fails, falls-back to blockchain-based BCMR metadata resolution. Will return None on failure.
    Be sure to catch exceptions as this may raise an exception from the `requests` module."""
    assert use_indexers or use_blockchain, "Must specify at least one of: use_indexers, use_blockchain"
    assert not nft_hex or use_indexers, "Must specify use_indexers=True if trying to get metadata for an nft"

    # First, try paytaca indexer (faster)
    if use_indexers:
        md = _try_to_dl_from_paytaca_indexer(token_id_hex, timeout=timeout, skip_icon=skip_icon,
                                             nft_hex=nft_hex)
        if md is not None:
            util.print_error(f"Success in downloading token metadata from {PAYTACA_HOST} for:"
                             f" {token_id_hex} ({md.name})")
            return md

    # If indexer fails, try the blockchain (slower)
    if use_blockchain and not nft_hex:
        util.print_error(f"Falling-back to slower blockchain method to retrieve BCMR data for: {token_id_hex} ...")
        md = _try_to_dl_from_blockchain(wallet, token_id_hex, timeout=timeout, skip_icon=skip_icon)
        if md is not None:
            util.print_error(f"Success in downloading token metadata from blockchain for: {token_id_hex} ({md.name})")
            return md

    util.print_error(f"Failed to retrieve metadata for: {token_id_hex}")
