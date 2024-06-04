#!/usr/bin/env python3
#
# Electrum - Lightweight Bitcoin Client
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

import time
from datetime import datetime
import threading
import queue
import base64
from functools import partial
import re
import io

import smtplib
import imaplib
import email
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.encoders import encode_base64

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from electroncash.plugins import BasePlugin, hook
from electroncash.paymentrequest import PaymentRequest,PR_UNKNOWN,pr_tooltips
from electroncash.i18n import _
from electroncash_gui.qt.util import EnterButton,Buttons,CloseButton,OkButton,WindowModalDialog,pr_icons
from electroncash.util import Weak, PrintError
from electroncash_gui.qt.qrcodewidget import QRCodeWidget
from electroncash.address import Address


class Processor(threading.Thread, PrintError):
    polling_interval = 5*60

    instance = None

    def __init__(self, imap_server, username, password, callback, error_callback):
        threading.Thread.__init__(self)
        Processor.instance = self
        self.daemon = True
        self.username = username
        self.password = password
        self.imap_server = imap_server
        self.on_receive = callback
        self.on_error = error_callback
        self.q = queue.Queue()

    def diagnostic_name(self): return "Email.Processor"

    def poll(self):
        try:
            self.M.select()
        except:
            return
        typ, data = self.M.search(None, 'ALL')
        for num in data[0].split():
            typ, msg_data = self.M.fetch(num, '(RFC822)')
            if type(msg_data[0][1]) is bytes:
                msg = email.message_from_bytes(msg_data[0][1])
            else:
                msg = email.message_from_string(msg_data[0][1])
            p = msg.get_payload()
            if not msg.is_multipart():
                p = [p]
                continue
            for item in p:
                if item.get_content_type() == "application/bitcoin-paymentrequest":
                    pr_str = item.get_payload()
                    pr_str = base64.b64decode(pr_str)
                    self.on_receive(pr_str)

    def run(self):
        try:
            self.M = imaplib.IMAP4_SSL(self.imap_server)
            self.M.login(self.username, self.password)
        except Exception as e:
            self.print_error("Exception encountered, stopping plugin thread:", repr(e))
            self.on_error(_("Email plugin could not connect to {server} as {username}, IMAP receive thread stopped.").format(server=self.imap_server, username=self.username))
            return
        try:
            while Processor.instance is self:
                self.poll()
                try:
                    self.q.get(timeout=self.polling_interval)  # sleep for polling_interval seconds
                    return # if we get here, we were stopped
                except queue.Empty:
                    ''' If we get here, we slept for polling_interval seconds '''
            self.M.close()
            self.M.logout()
        except Exception as e:
            self.print_error("Exception encountered, stopping plugin thread:", repr(e))
            self.on_error(_("Email plugin encountered an error, plugin stopped."))

    def send(self,recipient,sender,subject,message, payment_request,qrcode,uri,receive_addr,amount,date_created,description):
        subject = subject if subject else "Payment Request"
        message = f"<pre class='align-left msg'>{message}</pre>" if message else ""
        bch_png = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPCEtLSBHZW5lcmF0b3I6IEFkb2JlIElsbHVzdHJhdG9yIDI0LjAuMCwgU1ZHIEV4cG9ydCBQbHVnLUluIC4gU1ZHIFZlcnNpb246IDYuMDAgQnVpbGQgMCkgIC0tPgo8c3ZnIHZlcnNpb249IjEuMSIgaWQ9IkxheWVyXzEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHg9IjBweCIgeT0iMHB4IgoJIHZpZXdCb3g9IjAgMCA3ODggNzg4IiBzdHlsZT0iZW5hYmxlLWJhY2tncm91bmQ6bmV3IDAgMCA3ODggNzg4OyIgeG1sOnNwYWNlPSJwcmVzZXJ2ZSI+CjxzdHlsZSB0eXBlPSJ0ZXh0L2NzcyI+Cgkuc3Qwe2ZpbGw6IzBBQzE4RTt9Cgkuc3Qxe2ZpbGw6I0ZGRkZGRjt9Cjwvc3R5bGU+CjxjaXJjbGUgY2xhc3M9InN0MCIgY3g9IjM5NCIgY3k9IjM5NCIgcj0iMzk0Ii8+CjxwYXRoIGlkPSJzeW1ib2xfMV8iIGNsYXNzPSJzdDEiIGQ9Ik01MTYuOSwyNjEuN2MtMTkuOC00NC45LTY1LjMtNTQuNS0xMjEtNDUuMkwzNzgsMTQ3LjFMMzM1LjgsMTU4bDE3LjYsNjkuMgoJYy0xMS4xLDIuOC0yMi41LDUuMi0zMy44LDguNEwzMDIsMTY2LjhsLTQyLjIsMTAuOWwxNy45LDY5LjRjLTkuMSwyLjYtODUuMiwyMi4xLTg1LjIsMjIuMWwxMS42LDQ1LjJjMCwwLDMxLTguNywzMC43LTgKCWMxNy4yLTQuNSwyNS4zLDQuMSwyOS4xLDEyLjJsNDkuMiwxOTAuMmMwLjYsNS41LTAuNCwxNC45LTEyLjIsMTguMWMwLjcsMC40LTMwLjcsNy45LTMwLjcsNy45bDQuNiw1Mi43YzAsMCw3NS40LTE5LjMsODUuMy0yMS44CglsMTguMSw3MC4ybDQyLjItMTAuOWwtMTguMS03MC43YzExLjYtMi43LDIyLjktNS41LDMzLjktOC40bDE4LDcwLjNsNDIuMi0xMC45bC0xOC4xLTcwLjFjNjUtMTUuOCwxMTAuOS01Ni44LDEwMS41LTExOS41CgljLTYtMzcuOC00Ny4zLTY4LjgtODEuNi03Mi4zQzUxOS4zLDMyNC43LDUzMCwyOTcuNCw1MTYuOSwyNjEuN0w1MTYuOSwyNjEuN3ogTTQ5Ni42LDQyNy4yYzguNCw2Mi4xLTc3LjksNjkuNy0xMDYuNCw3Ny4yCglsLTI0LjgtOTIuOUMzOTQsNDA0LDQ4Mi40LDM3Mi41LDQ5Ni42LDQyNy4yeiBNNDQ0LjYsMzAwLjdjOC45LDU1LjItNjQuOSw2MS42LTg4LjcsNjcuN2wtMjIuNi04NC4zCglDMzU3LjIsMjc4LjIsNDI2LjUsMjQ5LjYsNDQ0LjYsMzAwLjd6Ii8+Cjwvc3ZnPgo="
        electroncash_png = "iVBORw0KGgoAAAANSUhEUgAAABkAAAATCAYAAABlcqYFAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAi9JREFUeNq8VT1LA0EQnYQUooIBFQULI1qZIgdqZZGrbRIbLXP5BZ6gWNuKxVXaSVIKgkljfSmsVEgKBQsxAQuJihFUUkTOmc1cstm7nNo4sCTs7ry38+bjQo7jQJCF1ksx/DFx6bgS0lEFl43Lco6T1UCMfiQIHiUAXBn42fL0ECRr+GLBmq3LG3jRRgIN/+bkl0eHImAkJ6Fw8QzVp6YfFkVmoH8Z/XWVRA6lSBdZBkGgz0ehsB0H4+AWTrfisJm/A+vsoV9EFZaVHphyNyPKJZMl6kRArx4ZjAiyt88WmCtTIioyiqpcfZf9E+xvyiRyJEU+vHflIWBaGwjsZzV8gLZzBY2Plno0w2QpNZICkwjTpoeFPLJlD2+hWm+CoU9CJjkB0+MD4p5948m3yXiCJCwdlFlPYeS4un8Nuye17gWUhvZlUB8CYJyyRy6sihBWhaeeSbbXo+W2npfPKM2XiIKMckQkVBSqZDJe+KcGIOdKrZ3c1OIYpJdGoYTAtEcFQXtWZi4QI/KLRsMqeoEEai8iy5535dtbEPtabCjQPyx1uMZ17jH7uqs7VRtZemkMYph4t8zVfmE8TySa3IQ9JFJyLWO23RAcGUln5u48LoznIUlz6W2oHiRLp9sY3C3pnP3oF7zFC9TEp6Rh12METC8ucURU2kKmerPfsISgsWLx7NJk2VDfTh6SnBPqdne8KLPL5Nn19yns9gwR0czyGSX9p/C/fE/+48v4LcAAyHn2UhS/mxsAAAAASUVORK5CYII="
        p = qrcode and qrcode.grab()
        if p and not p.isNull():
            image = p.toImage()
            ba = QByteArray()
            buffer = QBuffer(ba)
            buffer.open(QIODevice.WriteOnly)
            image.save(buffer, 'PNG')
            base64_data = ba.toBase64().data().decode()
            buffer.close()

        plain = f'''
Bitcoin Cash Payment Request \n
{description}\n
{date_created}\n
{amount} Bitcoin Cash (BCH) \n
Pay to: {receive_addr} \n
URI: {uri}\n
{message}
        '''        
        html = f'''
<html>
<head>
<style>
body{{

   background-color:#19232d;
   color:#FFFFFF;
}}

.main{{
    max-width: 500px;
    width: 500px;
    margin: 0 auto;
    text-align: center;
    padding: 10px;
}}
.flex{{

    width:100%;
}}
.align-right{{
    display:block;
    text-align:right;
}}
.align-left{{
    display:block;
    text-align:left;
}}
.v-center{{
    vertical-align:middle
}}
.msg{{

    padding:10px 15px;
    border:1px solid #444444;
    border-radius:4px;
    font-size:14px;
    word-break: break-all;

}}
.footer{{
    font-size:12px;
}}
</style>
</head>
    <body>
        <table class='main'>
            <tbody>
                <tr><td>
                    <table class='flex'>
                        <tbody>
                            <tr>
                                <td><img class='v-center' width='100' src="data:image/svg+xml;base64,{bch_png}"></td>
                                <td class='align-right'>                
                                    <h1> Bitcoin Cash </h1>
                                    <p> Payment Request </p>
                                    <p><b>{amount} Bitcoin Cash (BCH)</b></p>                        
                                </td>
                            </tr>                    
                        </tbody>
                    </table>
                </td></tr>
                <tr><td>
                    <table class='align-left'>
                        <tbody>
                            <tr><td>{description}</td>
                            <tr><td>{date_created}</td>
                        </tbody>
                    </table>
                </td></tr>
                <tr><td>                                    
                    {message}
                </td></tr>
                <tr><td>                
                <p> Bitcoin Cash (BCH)</p>
                <p><b>{amount}</b></p>
                <p>Pay to:</p>
                <p><b>{receive_addr}</b></p>
                <a href="{uri}"> 
                <img src="data:image/png;base64,{base64_data}"><br>
                </a>
                
                </td></tr>
                <tr>
                 <td><a href='https://electroncash.org/'><img width='25' src="data:image/png;base64,{electroncash_png}"></a></td>
                </tr>
                        
            </tbody>
        </table>
    </body>
</html>
        '''

        body = MIMEMultipart('alternative')

        plain = MIMEText(plain.encode('utf-8'), 'plain','utf-8')
        html = MIMEText(html.encode('utf-8'), 'html','utf-8')

        body.attach(plain)
        body.attach(html)

        msg = MIMEMultipart()
        msg.preamble = 'This is a multi-part message in MIME format.\n'
        msg.epilogue = ''     
        
        msg.attach(body)

        attachment = MIMEBase('application', "bitcoincash-paymentrequest")
        attachment.set_payload(payment_request)
        encode_base64(attachment)
        attachment.add_header('Content-Disposition', 'attachment; filename="payme.bch"')
        
        msg.attach(attachment)  

        msg.add_header('From', sender)
        msg.add_header('To', recipient)
        msg.add_header('Subject', subject)

        s = smtplib.SMTP_SSL(self.imap_server, timeout=2)
        s.login(self.username, self.password)
        s.sendmail(sender, [recipient], msg.as_string())
        s.quit()


class EmailSignalObject(QObject):
    email_new_invoice_signal = pyqtSignal()
    email_error = pyqtSignal(str)


class EmailDialog(QDialog):
    def __init__(self,sender,subject,amount, receiving_addr, uri, qrcode, status, parent = None):
        super().__init__(parent)

        self.setMinimumSize(500, 200)
        self.setWindowTitle("Send Via Email")
        vbox = QVBoxLayout(self)

        grid = QGridLayout()
        vbox.addLayout(grid)
        grid.addWidget(QLabel(_("Email Payment Request")), 0, 1)


        label = QLabel(_(subject))
        label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        grid.addWidget(label, 0, 2)

        grid.addWidget(QLabel(_(f"{amount} BCH")), 1, 1)

        if status is not PR_UNKNOWN:
            label = QLabel(_(pr_tooltips.get(status,'')))
            label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            grid.addWidget(label, 1, 2)

        grid = QGridLayout()
        vbox.addLayout(grid)
        grid.addWidget(QLabel('From'), 0, 0)
        self.send_from = QLineEdit()
        self.send_from.setText(sender)
        grid.addWidget(self.send_from, 0, 1)
        grid.addWidget(QLabel('To'), 1, 0)
        self.send_to = QLineEdit()
        grid.addWidget(self.send_to, 1, 1)      
        self.send_to.setFocusPolicy(Qt.StrongFocus)  
        grid.addWidget(QLabel('Subject'), 2, 0)
        self.subject = QLineEdit()
        self.subject.setText(subject)
        grid.addWidget(self.subject, 2, 1)
        grid.addWidget(QLabel('Message'), 3, 0)
        self.msg = QTextEdit()
        self.msg.setPlaceholderText('Add a message...')
        vbox.addWidget(self.msg)
        self.sendButton = OkButton(self, "&Send")
        self.sendButton.setEnabled(False)
        self.cancel = CloseButton(self)
        self.send_to.textChanged.connect(self.check_email_validity)
        self.send_from.textChanged.connect(self.check_email_validity)
        vbox.addStretch()
        vbox.addLayout(Buttons(self.cancel, self.sendButton))
        self.orginal = self.send_to.styleSheet() 
    def check_email_validity(self):
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        if re.fullmatch(regex, self.send_to.text()) and re.fullmatch(regex, self.send_from.text()):
            self.sendButton.setEnabled(True)
            self.send_to.setStyleSheet(self.orginal)
            self.send_from.setStyleSheet(self.orginal)
            return
        else:
            red= QPalette()
            red.setColor(QPalette.Text, Qt.red)    

            if not re.fullmatch(regex, self.send_to.text()):
                self.send_to.setStyleSheet("border: 1px solid red;")
            else:
                 self.send_to.setStyleSheet(self.orginal)

            if not re.fullmatch(regex, self.send_from.text()):
                self.send_from.setStyleSheet("border: 1px solid red;")
                self.send_from.setPalette(red)
            else:
                 self.send_from.setStyleSheet(self.orginal)                
            self.sendButton.setEnabled(False)

class Plugin(BasePlugin):

    def fullname(self):
        return 'Email'

    def description(self):
        return _("Send payment requests via email")

    def is_available(self):
        return True

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.imap_server = self.config.get('email_server', '')
        self.username = self.config.get('email_username', '')
        self.password = self.config.get('email_password', '')
        self.send_from = self.config.get('email_send_from', '')
        if self.imap_server and self.username and self.password:
            self.processor = Processor(self.imap_server, self.username, self.password, self.on_receive, self.on_error)
            self.processor.start()
        else:
            self.processor = None
        self.obj = EmailSignalObject()
        self.obj.email_new_invoice_signal.connect(self.new_invoice)
        self.obj.email_error.connect(self.on_error_qt)

    def on_close(self):
        ''' called on plugin close '''
        Processor.instance = None  # tells thread that it is defunct
        if self.processor and self.processor.is_alive():
            self.processor.q.put(None)  # signal stop
            self.processor.join(timeout=1.0)

    def on_receive(self, pr_str):
        self.print_error('received payment request')
        self.pr = PaymentRequest(pr_str)
        self.obj.email_new_invoice_signal.emit()

    def on_error(self, err):
        self.obj.email_error.emit(err)

    def on_error_qt(self, err):
        QMessageBox.warning(None, _("Email Error"), err)

    def new_invoice(self):
        self.parent.invoices.add(self.pr)
        #window.update_invoices_list()

    @hook
    def receive_list_menu_for_email_plugin(self, window, menu, addr, uri, qrcode, status):
        menu.addAction(_("Send via e-mail"), lambda: self.open_email_dialog(window, addr, uri, qrcode, status))      

    def open_email_dialog(self, window, addr, uri ,qrcode, status):
        if not self.processor:
            window.show_warning(_('The email plugin is enabled but not configured. Please go to its settings and configure it, or disable it if you do not wish to use it.'))
            return
        from electroncash import paymentrequest
        r = window.wallet.receive_requests.get(addr)
        description = r.get('memo', '')
        timestamp = r.get('time', '')
        date_created = datetime.fromtimestamp(timestamp).strftime("%d %b, %Y")
        amount = r.get('amount', '') / 100000000
        amount = "{:.8f}".format(amount)
        try:
            if r.get('signature'):
                pr = paymentrequest.serialize_request(r)
            else:
                pr = paymentrequest.make_request(self.config, r)
        except ValueError as e:
            ''' Bad data such as out-of-range amount, see #1738 '''
            self.print_error('Error serializing request:', repr(e))
            window.show_error(str(e))
            return
        if not pr:
            return

        payload = pr.SerializeToString()

        sender = self.send_from if self.send_from else self.username;
        dialog = EmailDialog(sender, description, amount, addr, uri, qrcode, status, window)
        dialog.send_to.setFocus()

        result = dialog.exec_()
   
        if not result == QDialog.Accepted:
            return

        recipient = dialog.send_to.text()
        sender = dialog.send_from.text()
        subject = dialog.subject.text()
        msg = dialog.msg.toPlainText()
        
        self.print_error('sending mail to', recipient)
         
        try:
            self.processor.send(recipient,sender, subject, msg, payload, qrcode, uri, addr, amount, date_created, description)
        except Exception as e:
            self.print_error("Exception sending:", repr(e))
            # NB; we don't want to actually display the exception message here
            # because it may contain text from the server, which could be a
            # potential phishing attack surface.  So instead we show the user
            # the exception name which is something like ConnectionRefusedError.
            window.show_error(_("Could not send email to {recipient}: {reason}").format(recipient=recipient, reason=type(e).__name__))
            return

        window.show_message(_('Request sent.'))

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        windowRef = Weak.ref(window)
        return EnterButton(_('Settings'), partial(self.settings_dialog, windowRef))

    def settings_dialog(self, windowRef):
        window = windowRef()
        if not window: return
        d = WindowModalDialog(window.top_level_window(), _("Email settings"))
        d.setMinimumSize(500, 200)

        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(_('Server hosting your email account')))
        grid = QGridLayout()
        vbox.addLayout(grid)
        grid.addWidget(QLabel('Server (IMAP)'), 0, 0)
        server_e = QLineEdit()
        server_e.setText(self.imap_server)
        grid.addWidget(server_e, 0, 1)

        grid.addWidget(QLabel('Username'), 1, 0)
        username_e = QLineEdit()
        username_e.setText(self.username)
        grid.addWidget(username_e, 1, 1)

        grid.addWidget(QLabel('Password'), 2, 0)
        password_e = QLineEdit()
        password_e.setText(self.password)
        password_e.setEchoMode(QLineEdit.Password)

        grid.addWidget(password_e, 2, 1)

        grid.addWidget(QLabel('Send from'), 3, 0)
        send_from = QLineEdit()
        send_from.setText(self.send_from)
        grid.addWidget(send_from, 3, 1)

        vbox.addStretch()
        vbox.addLayout(Buttons(CloseButton(d), OkButton(d)))

        if not d.exec_():
            return

        server = str(server_e.text())
        self.config.set_key('email_server', server)

        username = str(username_e.text())
        self.config.set_key('email_username', username)

        send_from = str(send_from.text())
        self.config.set_key('email_send_from', send_from)

        password = str(password_e.text())
        self.config.set_key('email_password', password)
        window.show_message(_('Please restart the plugin to activate the new settings'))
