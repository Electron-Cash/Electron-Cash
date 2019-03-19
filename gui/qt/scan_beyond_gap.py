#!/usr/bin/env python3
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2019 calin.culianu@gmail.com
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
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

from .util import *
from electroncash.util import PrintError
from electroncash.i18n import _

class ScanBeyondGap(WindowModalDialog, PrintError):

    def __init__(self, main_window):
        super().__init__(parent=main_window, title=_("Scan Beyond Gap"))
        self.resize(450, 400)
        self.main_window = main_window
        vbox = QVBoxLayout(self)
        l = QLabel(
            "<p><font size=+1><b><i>" + _("Scan Beyond Gap") + "</i></b></font></p><p>"
            + _("Normally, when you (re)generate a wallet from seed, your addresses are added to the wallet until a block of addresses are found without a history.")
            + "</p><p>" + _("Addresses beyond this gap are not scanned for a balance.")
            + "</p><p>"
            + _("Use this tool to scan for an address history past your current address gap, and if any history is found, those addresses will be added to your wallet.")
            + "</p>")
        l.setWordWrap(True)
        vbox.addWidget(l)
        vbox.addStretch(1)
        hbox = QHBoxLayout()
        l = QLabel(_("Number of addresses to scan:"))
        hbox.addWidget(l)
        self.num_sb = QSpinBox(); self.num_sb.setMinimum(1); self.num_sb.setMaximum(1000000);
        self.num_sb.setValue(100)
        hbox.addWidget(self.num_sb)
        self.which_cb = QComboBox()
        self.which_cb.addItem(_("Scan Both Change & Receiving"))
        self.which_cb.addItem(_("Change Addresses Only"))
        self.which_cb.addItem(_("Receiving Addresses Only"))
        self.which_cb.setCurrentIndex(0)
        hbox.addWidget(self.which_cb)
        hbox.addStretch(1)
        vbox.addLayout(hbox)
        self.prog = QProgressBar(); self.prog.setMinimum(0); self.prog.setMaximum(100);
        vbox.addWidget(self.prog)
        self.prog_label = QLabel()
        vbox.addWidget(self.prog_label)
        self.found_label = QLabel()
        vbox.addWidget(self.found_label)
        vbox.addStretch(1)
        self.cancel_but = QPushButton(_("Cancel"))
        self.scan_but = QPushButton(_("Start Scan"))
        vbox.addLayout(Buttons(self.cancel_but, self.scan_but))

        self.cancel_but.clicked.connect(self.cancel)
        self.scan_but.clicked.connect(self.scan)

    def cancel(self):
        self.prog_label.setText(_("Canceled"))
        self.reject()

    def scan(self):
        self.scan_but.setDisabled(True)
        self.prog_label.setVisible(True)
        self.found_label.setVisible(False)
        total = self.num_sb.value()
        self.prog_label.setText(_("Scanning {} of {} addresses ...").format(0, total))
        self.found_label.setText('')
