##!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Electron Cash - lightweight Bitcoin Cash Client
# Copyright (C) 2019 The Electron Cash Developers
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
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtNetwork import *
from PyQt5.QtWidgets import *

from electroncash.util import PrintError, print_error
from electroncash.i18n import _
from electroncash import version, bitcoin, address
from electroncash.networks import MainNet
from .util import *
import base64, sys, json

class UpdateChecker(QWidget, PrintError):
    ''' A window that checks for updates.

    If ok, and a new version is detected, will present the hard-coded download
    URL in the GUI.

    If ok, and we are on the latest version, will present a message to that
    effect.

    If it can't verify the response or can't talk on network, will present a
    generic error message.

    Update data is expected to be JSON with a bunch of signed version strings.
    see self._process_server_reply below for an example.
    '''
    # Note: it's guaranteed that every call to do_check() will either result
    # in a 'checked' signal or a 'failed' signal to be emitted.
    # got_new_version is only emitted if the new version is actually newer than
    # our version.
    checked = pyqtSignal(object) # emitted whenever the server gave us a (properly signed) version string. may or may not mean it's a new version.
    got_new_version = pyqtSignal(object) # emitted in tandem with 'checked' above ONLY if the server gave us a (properly signed) version string we recognize as *newer*
    failed = pyqtSignal() # emitted when there is an exception, network error, or verify error on version check.

    url = "https://www.c3-soft.com/downloads/BitcoinCash/Electron-Cash/update_check"
    download_url = "https://electroncash.org/#download"

    VERSION_ANNOUNCEMENT_SIGNING_ADDRESSES = (
        address.Address.from_string("bitcoincash:qphax4cg8sxuc0qnzk6sx25939ma7y877uz04s2z82", net=MainNet), # Calin's key
    )

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Electron Cash - ' + _('Update Checker'))
        self.content = QVBoxLayout()
        self.content.setContentsMargins(*([10]*4))

        self.heading_label = QLabel()
        self.content.addWidget(self.heading_label)

        self.detail_label = QLabel()
        self.detail_label.setTextInteractionFlags(Qt.LinksAccessibleByMouse)
        self.detail_label.setOpenExternalLinks(True)
        self.detail_label.setWordWrap(True)
        self.content.addWidget(self.detail_label)

        self.pb = QProgressBar()
        self.pb.setMaximum(100)
        self.pb.setMinimum(0)
        self.content.addWidget(self.pb)

        versions = QHBoxLayout()
        versions.addWidget(QLabel(_("Current version: {}".format(version.PACKAGE_VERSION))))
        self.latest_version_label = QLabel(_("Latest version: {}".format(" ")))
        versions.addWidget(self.latest_version_label)
        self.content.addLayout(versions)

        close_button = QPushButton(_("Close"))
        close_button.clicked.connect(self.close)
        self.cancel_or_check_button = QPushButton(_("Cancel"))
        self.cancel_or_check_button.clicked.connect(self.cancel_or_check)
        self.content.addLayout(Buttons(self.cancel_or_check_button, close_button))
        grid = QGridLayout()
        grid.addLayout(self.content, 0, 0)
        self.setLayout(grid)

        self.network_access_manager = QNetworkAccessManager(self)
        net_config = self.network_access_manager.configuration()
        net_config.setConnectTimeout(int(5.0 * 1e3)) # timeout in msecs
        self.network_access_manager.setConfiguration(net_config)
        self.network_access_manager.authenticationRequired.connect(self.qam_authentication_required)
        self.network_access_manager.encrypted.connect(self.qam_encrypted)
        self.network_access_manager.finished.connect(self.qam_finished)
        self.active_reply = None
        self.resize(450, 200)

    def qam_authentication_required(self, reply, authenticator):
        self.print_error("Authentication required for", reply.url().toString())
        # doing nothing will result in connection fail and a finished() signal emitted

    def qam_encrypted(self, reply):
        self.print_error("Encrypted connecton to", reply.url().toString())

    def qam_finished(self, reply):
        self.print_error("Finished", reply.url().toString(), "with error code:", reply.errorString() if reply.error() else '(No Error)')
        if reply is self.active_reply:
            self.on_reply_finished(reply)
            self.active_reply = None
            self.print_error("was the active reply, set to None")
        else:
            self.print_error("was NOT the active reply")
        reply.deleteLater()

    def on_reply_downloading(self, reply, bytesReceived, bytesTotal):
        if reply is self.active_reply:
            self.print_error("Downloading bytes received", bytesReceived, "/", bytesTotal, "from", reply.url().toString())
            prog = abs((bytesReceived*100.0) / bytesTotal) if bytesTotal else 1
            self.pb.setValue(max(0, min(int(prog), 100)))
        else:
            self.print_error("Warning: on_reply_downloading called with a reply that is not 'active'!")

    def on_reply_finished(self, reply):
        self.print_error("Reply finished", reply.url().toString())
        data, newver = None, None
        if not reply.error():
            try:
                data = bytes(reply.readAll()).decode('utf-8')
                self.print_error("got data\n" + str(data)) # comment this out for release
                data = json.loads(data)
                newver = self._process_server_reply(data)
            except:
                data, newver = None, None
                import traceback
                self.print_error(traceback.format_exc())
        if newver is None:
            self.on_retrieval_failed()
            self.failed.emit()
        else:
            # NB: below 'newver' may actually just be our version or a version
            # before our version (in case we are on a develpment build).
            # Client code should check with this class.is_newer if the emitted
            # version is actually newer.
            self.on_version_retrieved(newver)
            self.checked.emit(newver)
            if self.is_newer(newver):
                self.got_new_version.emit(newver)

    def _process_server_reply(self, signed_version_dict):
        ''' Returns:
                - the new package version string if new version found from
                  server, e.g. '3.3.5', '3.3.5CS', etc
                - or the current version (version.PACKAGE_VERSION) if no new
                  version found.
                - None on failure (such as bad signature).

            May also raise on error. '''
        # example signed_version_dict:
        # {
        #     "3.9.9": {
        #         "bitcoincash:qphax4cg8sxuc0qnzk6sx25939ma7y877uz04s2z82": "IA+2QG3xPRn4HAIFdpu9eeaCYC7S5wS/sDxn54LJx6BdUTBpse3ibtfq8C43M7M1VfpGkD5tsdwl5C6IfpZD/gQ="
        #     },
        #     "3.9.9CS": {
        #         "bitcoincash:qphax4cg8sxuc0qnzk6sx25939ma7y877uz04s2z82": "IA+2QG3xPRn4HAIFdpu9eeaCYC7S5wS/sDxn54LJx6BdUTBpse3ibtfq8C43M7M1VfpGkD5tsdwl5C6IfpZD/gQ="
        #     },
        #     "3.9.9SLP": {
        #         "bitcoincash:qphax4cg8sxuc0qnzk6sx25939ma7y877uz04s2z82": "IA+2QG3xPRn4HAIFdpu9eeaCYC7S5wS/sDxn54LJx6BdUTBpse3ibtfq8C43M7M1VfpGkD5tsdwl5C6IfpZD/gQ="
        #     },
        # }
        # All signed messages above are signed with the address in the dict, and the message is the "3.9.9" or "3.9.9CS" etc string
        ct_matching = 0
        for version_msg, sigdict in signed_version_dict.items():
            # This looks quadratic, and it is. But the expected results are small.
            # We needed to do it this way to detect when there was no matching variant and/or no known-key match.
            if self.is_matching_variant(version_msg):
                for adr, sig in sigdict.items():
                    adr = address.Address.from_string(adr, net=MainNet) # may raise
                    if adr in self.VERSION_ANNOUNCEMENT_SIGNING_ADDRESSES:
                        ct_matching += 1
                        if self.is_newer(version_msg): # may raise
                            try:
                                is_verified = bitcoin.verify_message(adr, base64.b64decode(sig), version_msg.encode('utf-8'), net=MainNet)
                            except:
                                self.print_error("Exception when verifying version signature for", version_msg, ":", repr(sys.exc_info()[1]))
                                return None
                            if is_verified:
                                self.print_error("Got new version", version_msg)
                                return version_msg.strip()
                            else:
                                self.print_error("Got new version", version_msg, "but sigcheck failed!")
                                return None
        if 0 == ct_matching:
            # Hmm. None of the versions we saw matched our variant.
            # And/Or, none of the keys we saw matched keys we knew about.
            # This is an error condition, so return None
            self.print_error("Error: Got a valid reply from server but none of the variants match us and/or none of the signing keys are known!")
            return None
        return version.PACKAGE_VERSION


    def on_version_retrieved(self, version):
        self._update_view(version)

    _error_val = 0xdeadb33f
    def on_retrieval_failed(self):
        self._update_view(self._error_val)

    @staticmethod
    def _ver2int(vtup):
        ''' param vtup is a tuple of ints: (major, minor, revision) as would be
        returned by version.parse_package_version. Returns version encoded
        in an int suitable for numerical comparisons (>, <, >=, ==, etc). '''
        return ((vtup[0]&0xff) << 16) | ((vtup[1]&0xff) << 8) | ((vtup[2]&0xff) << 0)

    @classmethod
    def _my_version(cls):
        if getattr(cls, '_my_version_parsed', None) is None:
            cls._my_version_parsed = version.parse_package_version(version.PACKAGE_VERSION)
        return cls._my_version_parsed

    @classmethod
    def _parse_version(cls, version_msg):
        try:
            return version.parse_package_version(version_msg)
        except:
            print_error("[{}] Error parsing version '{}': {}".format(cls.__name__, version_msg, repr(sys.exc_info()[1])))
            raise

    @classmethod
    def is_matching_variant(cls, version_msg):
        parsed_version = cls._parse_version(version_msg)
        me = cls._my_version()
        return me[3] == parsed_version[3]

    @classmethod
    def is_newer(cls, version_msg):
        if cls.is_matching_variant(version_msg): # make sure it's the same variant as us eg SLP, CS, '' regular, etc..
            v_me = cls._ver2int(cls._my_version())
            v_server = cls._ver2int(cls._parse_version(version_msg))
            return v_server > v_me
        return False

    def _update_view(self, latest_version):
        if latest_version == self._error_val:
            self.heading_label.setText('<h2>' + _("Update check failed") + '</h2>')
            self.detail_label.setText(_("Sorry, but we were unable to check for updates. Please try again later."))
            self.cancel_or_check_button.setText(_("Check Again"))
            self.cancel_or_check_button.setEnabled(True)

            self.pb.hide()
        elif latest_version:
            self.pb.hide()
            self.cancel_or_check_button.setText(_("Check Again"))
            self.latest_version_label.setText(_("Latest version: {}".format("<b>" + latest_version + "</b>")))
            if self.is_newer(latest_version):
                self.heading_label.setText('<h2>' + _("There is a new update available") + '</h2>')
                url = '<a href="{u}">{u}</a>'.format(u=UpdateChecker.download_url)
                self.detail_label.setText(_("You can download the new version from:<br>{}").format(url))
                self.cancel_or_check_button.setEnabled(False)
            else:
                self.heading_label.setText('<h2>' + _("Already up to date") + '</h2>')
                self.detail_label.setText(_("You are already on the latest version of Electron Cash."))
                self.cancel_or_check_button.setEnabled(True)
        else:
            self.pb.show()
            self.pb.setValue(0)
            self.cancel_or_check_button.setText(_("Cancel"))
            self.cancel_or_check_button.setEnabled(True)
            self.latest_version_label.setText("")
            self.heading_label.setText('<h2>' + _("Checking for updates...") + '</h2>')
            self.detail_label.setText(_("Please wait while Electron Cash checks for available updates."))

    def cancel_active(self):
        if self.active_reply:
            self.active_reply.abort()
            self.active_reply = None

    def cancel_or_check(self):
        if self.active_reply:
            self.cancel_active()
        else:
            self.do_check(force=True)

    # Note: calls to do_check() will either result in a 'checked' signal or
    # a 'failed' signal to be emitted (and possibly also 'got_new_version')
    def do_check(self, force=False):
        if force:
            self.cancel_active() # no-op if none active
        if not self.active_reply:
            self._update_view(None)
            req = QNetworkRequest(QUrl(self.url))
            req.setMaximumRedirectsAllowed(2)
            req.setAttribute(QNetworkRequest.EmitAllUploadProgressSignalsAttribute, QVariant(True))
            req.setAttribute(QNetworkRequest.CacheLoadControlAttribute, QVariant(QNetworkRequest.AlwaysNetwork))
            req.setAttribute(QNetworkRequest.RedirectPolicyAttribute, QVariant(QNetworkRequest.NoLessSafeRedirectPolicy))
            self.active_reply = reply = self.network_access_manager.get(req)
            self.active_reply.downloadProgress.connect(lambda bytes_read, bytes_total: self.on_reply_downloading(reply, bytes_read, bytes_total))

