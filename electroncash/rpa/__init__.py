#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
# This file (c) 2020 Calin Culianu
# Part of the Electron Cash SPV Wallet
# License: MIT

from . import paycode

from ..i18n import _
from ..util import InvalidPassword


def acquire_rpa_password(wallet, request_password, show_error, *, cached_password=None) -> bool:
    """Ensure wallet.rpa_pwd is available for background RPA scanning.

    GUI-toolkit-agnostic prompt policy: request_password() returns the
    password string, or None if the user declined; show_error(msg) displays a
    message. cached_password, if given, is tried silently first (e.g. the
    password the user already entered to unlock the wallet at startup) so they
    are not prompted twice -- mirrors how CashFusion reuses the startup
    password. Returns True if scanning can proceed (password stored or not
    needed), False if scanning stays paused for this session. A wrong password
    re-prompts; declining or any unexpected error pauses -- never raises.
    """
    if not wallet.is_rpa_enabled() or wallet.rpa_pwd or not wallet.has_password():
        return True
    if cached_password is not None:
        try:
            wallet.check_password(cached_password)
            wallet.rpa_pwd = cached_password
            return True
        except Exception:
            pass  # stale/invalid (shouldn't happen): fall back to prompting
    while True:
        password = request_password()
        if password is None:
            # User declined: paycode scanning stays paused for this session.
            return False
        try:
            wallet.check_password(password)
        except InvalidPassword:
            show_error(_('Incorrect password, please try again.'))
            continue
        except Exception as e:
            show_error(str(e))
            return False
        wallet.rpa_pwd = password
        return True
