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

import base64
from functools import partial
import re
import io

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.encoders import encode_base64

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from electroncash.plugins import BasePlugin, hook
from electroncash.paymentrequest import PR_UNKNOWN,pr_tooltips
from electroncash.i18n import _
from electroncash_gui.qt.util import EnterButton,Buttons,CloseButton,OkButton,WindowModalDialog,pr_icons
from electroncash.util import Weak


class EmailWorker(QObject):
    status = pyqtSignal(str, QDialog)
    result = pyqtSignal(int, str, QDialog, bool)
    show_error_on_parent = pyqtSignal(str, QMainWindow)
    closed_before_finished =  pyqtSignal(int, QMainWindow)
    canceled = False #flag that user canceled the email
    dialog_closed = False #flag that user closed the dialog
    smtp_error_prefix ='''
Sending of the message failed.\n
An error occurred while sending mail. The mail server responded:\n
    '''
    generic_error_prefix ='''
Sending of the message failed.\n
The following error occured while creating mail:\n    
    '''
    def send(self, thread, config, dialog,username, password, server, auth_method, conn_sec,port, recipient,sender,
            subject,message, payment_request,qrcode,uri,receive_addr,amount,date_created,date_due, overdue, 
            description, parent):

        try:
            self.status.emit(_("Creating email..."), dialog)
            subject = subject if subject else "Payment Request"
            message = f"<pre class='align-left msg'>{message}</pre>" if message else ""
            bch_png = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPCEtLSBHZW5lcmF0b3I6IEFkb2JlIElsbHVzdHJhdG9yIDI0LjAuMCwgU1ZHIEV4cG9ydCBQbHVnLUluIC4gU1ZHIFZlcnNpb246IDYuMDAgQnVpbGQgMCkgIC0tPgo8c3ZnIHZlcnNpb249IjEuMSIgaWQ9IkxheWVyXzEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHg9IjBweCIgeT0iMHB4IgoJIHZpZXdCb3g9IjAgMCA3ODggNzg4IiBzdHlsZT0iZW5hYmxlLWJhY2tncm91bmQ6bmV3IDAgMCA3ODggNzg4OyIgeG1sOnNwYWNlPSJwcmVzZXJ2ZSI+CjxzdHlsZSB0eXBlPSJ0ZXh0L2NzcyI+Cgkuc3Qwe2ZpbGw6IzBBQzE4RTt9Cgkuc3Qxe2ZpbGw6I0ZGRkZGRjt9Cjwvc3R5bGU+CjxjaXJjbGUgY2xhc3M9InN0MCIgY3g9IjM5NCIgY3k9IjM5NCIgcj0iMzk0Ii8+CjxwYXRoIGlkPSJzeW1ib2xfMV8iIGNsYXNzPSJzdDEiIGQ9Ik01MTYuOSwyNjEuN2MtMTkuOC00NC45LTY1LjMtNTQuNS0xMjEtNDUuMkwzNzgsMTQ3LjFMMzM1LjgsMTU4bDE3LjYsNjkuMgoJYy0xMS4xLDIuOC0yMi41LDUuMi0zMy44LDguNEwzMDIsMTY2LjhsLTQyLjIsMTAuOWwxNy45LDY5LjRjLTkuMSwyLjYtODUuMiwyMi4xLTg1LjIsMjIuMWwxMS42LDQ1LjJjMCwwLDMxLTguNywzMC43LTgKCWMxNy4yLTQuNSwyNS4zLDQuMSwyOS4xLDEyLjJsNDkuMiwxOTAuMmMwLjYsNS41LTAuNCwxNC45LTEyLjIsMTguMWMwLjcsMC40LTMwLjcsNy45LTMwLjcsNy45bDQuNiw1Mi43YzAsMCw3NS40LTE5LjMsODUuMy0yMS44CglsMTguMSw3MC4ybDQyLjItMTAuOWwtMTguMS03MC43YzExLjYtMi43LDIyLjktNS41LDMzLjktOC40bDE4LDcwLjNsNDIuMi0xMC45bC0xOC4xLTcwLjFjNjUtMTUuOCwxMTAuOS01Ni44LDEwMS41LTExOS41CgljLTYtMzcuOC00Ny4zLTY4LjgtODEuNi03Mi4zQzUxOS4zLDMyNC43LDUzMCwyOTcuNCw1MTYuOSwyNjEuN0w1MTYuOSwyNjEuN3ogTTQ5Ni42LDQyNy4yYzguNCw2Mi4xLTc3LjksNjkuNy0xMDYuNCw3Ny4yCglsLTI0LjgtOTIuOUMzOTQsNDA0LDQ4Mi40LDM3Mi41LDQ5Ni42LDQyNy4yeiBNNDQ0LjYsMzAwLjdjOC45LDU1LjItNjQuOSw2MS42LTg4LjcsNjcuN2wtMjIuNi04NC4zCglDMzU3LjIsMjc4LjIsNDI2LjUsMjQ5LjYsNDQ0LjYsMzAwLjd6Ii8+Cjwvc3ZnPgo="
            ec_svg = "iVBORw0KGgoAAAANSUhEUgAAABkAAAATCAYAAABlcqYFAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAi9JREFUeNq8VT1LA0EQnYQUooIBFQULI1qZIgdqZZGrbRIbLXP5BZ6gWNuKxVXaSVIKgkljfSmsVEgKBQsxAQuJihFUUkTOmc1cstm7nNo4sCTs7ry38+bjQo7jQJCF1ksx/DFx6bgS0lEFl43Lco6T1UCMfiQIHiUAXBn42fL0ECRr+GLBmq3LG3jRRgIN/+bkl0eHImAkJ6Fw8QzVp6YfFkVmoH8Z/XWVRA6lSBdZBkGgz0ehsB0H4+AWTrfisJm/A+vsoV9EFZaVHphyNyPKJZMl6kRArx4ZjAiyt88WmCtTIioyiqpcfZf9E+xvyiRyJEU+vHflIWBaGwjsZzV8gLZzBY2Plno0w2QpNZICkwjTpoeFPLJlD2+hWm+CoU9CJjkB0+MD4p5948m3yXiCJCwdlFlPYeS4un8Nuye17gWUhvZlUB8CYJyyRy6sihBWhaeeSbbXo+W2npfPKM2XiIKMckQkVBSqZDJe+KcGIOdKrZ3c1OIYpJdGoYTAtEcFQXtWZi4QI/KLRsMqeoEEai8iy5535dtbEPtabCjQPyx1uMZ17jH7uqs7VRtZemkMYph4t8zVfmE8TySa3IQ9JFJyLWO23RAcGUln5u48LoznIUlz6W2oHiRLp9sY3C3pnP3oF7zFC9TEp6Rh12METC8ucURU2kKmerPfsISgsWLx7NJk2VDfTh6SnBPqdne8KLPL5Nn19yns9gwR0czyGSX9p/C/fE/+48v4LcAAyHn2UhS/mxsAAAAASUVORK5CYII="
            date_due = f"<td class='align-right flex'><b>Due by </b>{date_due}</td>" if date_due else ""       
            overdue = f"<td class='align-right flex'><span class='overdue'><b>OVERDUE</b></span></td>" if overdue else ""
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
.table{{
    display:table;
}}
.flex{{

    width:100%;
}}
.align-right{{
    
    text-align:right;
}}
.align-left{{
    
    text-align:left;
}}
.dont-break{{
    white-space: nowrap;
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
.overdue{{
    color:#cc0000;
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
                    <table class='flex table'>
                        <tbody class='flex'>
                            <tr><td class='align-left'>{description}</td> {overdue}
                            <tr><td class='align-left dont-break'>{date_created}</td>{date_due}
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
                <img src="data:image/png;base64,{qrcode}"><br>
                </a>
                
                </td></tr>
                <tr>
                 <td><a href='https://electroncash.org/'><img width='25' src="data:image/png;base64,{ec_svg}"></a></td>
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
   
            if self.canceled and not self.dialog_closed:
                self.result.emit(2, "", dialog, self.canceled)
                thread.quit()        
                return
            if self.dialog_closed:
                self.closed_before_finished.emit(0, parent)
                thread.quit()  
                return                
            if not self.dialog_closed:
                self.status.emit(_("Connecting to server..."), dialog)
            # connect
            s = smtplib.SMTP_SSL(server,port, timeout=2)
            if not self.is_open(s):
                raise Exception(_("Failed to connect to server"))                    
            if not self.dialog_closed:
                self.status.emit(_("Authenticating user..."), dialog)
            if self.canceled and not self.dialog_closed:
                s.quit()
                self.result.emit(2, "", dialog, self.canceled)
                thread.quit()                      
                return        
            if self.dialog_closed:
                s.quit()
                self.closed_before_finished.emit(0, parent)
                thread.quit() 
                return
            # authenticate    
            s.login(username, password)
            if not self.dialog_closed:
                self.status.emit(_("Sending email..."), dialog)

            if self.canceled and not self.dialog_closed:
                if self.is_open(s):
                    s.quit()  
                self.result.emit(2, "", dialog, self.canceled)
                thread.quit()                      
                return   
            if self.dialog_closed:
                if self.is_open(s):
                    s.quit()  
                self.closed_before_finished.emit(0, parent)
                thread.quit()   
                return                                     
            # send     
            s.sendmail(sender, [recipient], msg.as_string())
            if self.canceled and not self.dialog_closed:
                if self.is_open(s):
                    s.quit()           
                self.result.emit(1, "", dialog, self.canceled)
                thread.quit()                  
                return   
            elif not self.canceled  and not self.dialog_closed:      
                if self.is_open(s):
                    s.quit()  
                self.status.emit(_("Sent successfully"), dialog)
                self.result.emit(1, _("Request sent."),  dialog, self.canceled)
                thread.quit()   

                return
            
            else:
                self.closed_before_finished.emit(1, parent)
                return
 
        except smtplib.SMTPException as e:
            if thread.isRunning():
                thread.quit()              
            if self.is_open(s):
                s.quit()              
            errmsg = getattr(e, 'smtp_error', repr(e))
            if not self.dialog_closed:
                self.result.emit(0, self.smtp_error_prefix+str(errmsg),  dialog, self.canceled)
            else:
                self.show_error_on_parent.emit(repr(e), parent)
            
        except Exception as e:
            if thread.isRunning():
                thread.quit()              
            if self.is_open(s):
                s.quit()   
            if not self.dialog_closed:
                self.result.emit(0, (self.generic_error_prefix+repr(e)), dialog, self.canceled)
            else:
                 self.show_error_on_parent.emit(repr(e), parent)                
  
    def is_open(self, conn):
        try:
            status = conn.noop()[0]
        except:  # smtplib.SMTPServerDisconnected
            status = -1
        return True if status == 250 else False 

class EmailDialog(QDialog):

    send = pyqtSignal()
    dialogIsClosing = pyqtSignal()
    closed = False
    def closeEvent(self, event):
        self.dialogIsClosing.emit()
        event.accept()
        
    def __init__(self,name, sender,subject,amount, receiving_addr, status, parent):
        super().__init__(parent)
        self.initUI(name, sender,subject,amount, receiving_addr, status)
    def initUI(self, name, sender,subject,amount, receiving_addr, status ):
        self.setMinimumSize(500, 350)
        self.setWindowTitle("Email Payment Request - Electron Cash")
        self.setWindowFlag(Qt.ForeignWindow) # Can also be Qt.SubWindow
        self.setWindowModality(Qt.NonModal)

        self.setAttribute(Qt.WA_DeleteOnClose)
        vbox = QVBoxLayout(self)

        grid = QGridLayout()
        vbox.addLayout(grid) 
        title = QLabel(_("Email Payment Request"))
        title.setStyleSheet("font-weight:900")
        grid.addWidget(title, 0, 1)

        label = QLabel(_(subject))
        label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        grid.addWidget(label, 0, 2)

        grid.addWidget(QLabel(_(f"{amount} BCH")), 1, 1)

        if status is not PR_UNKNOWN:

            hbox = QHBoxLayout()
            hbox.addStretch()
            label = QLabel(_(pr_tooltips.get(status,'')))

            if status > 0:
                icon_label = QLabel()
                icon = self.style().standardIcon(QStyle.SP_MessageBoxWarning)
                icon_label.setPixmap(icon.pixmap(20,20))
                hbox.addWidget(icon_label, 0, Qt.AlignRight)
            hbox.addWidget(label,  0, Qt.AlignRight)
            grid.addLayout(hbox, 1, 2)

        grid = QGridLayout()
        vbox.addLayout(grid)
        grid.addWidget(QLabel(_('From')), 0, 0)

        self.send_from  = QComboBox()
        self.send_from.addItems([f'{name} <{sender}>', _("Customize From Address")])     
        grid.addWidget(self.send_from , 0, 1)
        grid.addWidget(QLabel(_('To')), 1, 0)

        self.send_to = QLineEdit()
        grid.addWidget(self.send_to, 1, 1)    
        self.send_to.setFocusPolicy(Qt.StrongFocus)  
        grid.addWidget(QLabel(_('Subject')), 2, 0)
        self.subject = QLineEdit()
        self.subject.setText(subject)
        grid.addWidget(self.subject, 2, 1)
        grid.addWidget(QLabel(_('Message')), 3, 0)
        self.msg = QTextEdit()
        self.msg.setPlaceholderText(_('Add a message...'))
        vbox.addWidget(self.msg)
        self.sendButton = QPushButton( _("&Send"))
        self.sendButton.setDefault(True)
        self.sendButton.clicked.connect(lambda: self.send.emit())
        self.sendButton.setEnabled(False)
        self.cancel = CloseButton(self)
        self.send_to.textChanged.connect(self.check_email_validity)
        self.send_from.currentTextChanged.connect(self.check_email_validity)

        self.send_from.currentIndexChanged.connect(self.send_from_index_changed)
        vbox.addStretch()
        self.status_label = QLabel();
        grid = QGridLayout()
        grid.addWidget(self.status_label, 0 ,0)
        buttons = Buttons(self.cancel, self.sendButton);
        buttons.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        grid.addLayout(buttons, 0, 1)
        vbox.addLayout(grid)
        self.orginal = self.send_to.styleSheet() 
        self.progress = QProgressDialog("Sending email...", "C&ancel",  0 , 0, self)
        self.progress.cancel()
        self.progress.setWindowModality(Qt.NonModal)
        self.progress.setWindowTitle("Sending Email - Electron Cash")

        self.error_msg = QMessageBox( QMessageBox.Critical,
                        _("Error sending mail - Electron Cash"),
                        "",
                        buttons=QMessageBox.Close,
                        parent=self)
        self.error_msg.setWindowModality(Qt.NonModal)  
           

    def send_from_index_changed(self, index):
        if index == 1:
            self.send_from.setEditable(True) 
            self.send_from.lineEdit().setPlaceholderText("Custom From address to be used instead of server username login ")
            self.send_from.setCurrentIndex(0)
            self.send_from.model().item(1).setEnabled(False)

    def show_error(self, msg): 
        self.error_msg.setText(msg)
        self.error_msg.show()       

    def show_info(self, msg) -> QMessageBox: 

        alert = QMessageBox( QMessageBox.Information,
                        "Sent - Electron Cash",
                        msg,
                        buttons=QMessageBox.Ok,
                        parent=self)
        alert.setWindowModality(Qt.NonModal)   
        alert.show()       
                                   
        return alert
     
    def disable_form(self):
        self.progress.setVisible(True)
        self.setEnabled(False)
        self.progress.setEnabled(True)
   
    def enable_form(self):
        self.progress.close()
        self.setEnabled(True)

    def check_email_validity(self):
        regex = r'.*[\<]?\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b[\>]?$'
        if re.match(regex, self.send_to.text()):
            self.sendButton.setEnabled(True)
            self.send_to.setStyleSheet(self.orginal)
            return
        else:
            self.send_to.setStyleSheet("border: 1px solid red;")
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
        self.config = config
        
    @hook
    def receive_list_menu_for_email_plugin(self, window, menu, addr,description, timestamp, expiration, amount, uri, qrcode, status):
        menu.addAction(_("Send via e-mail"), lambda: self.open_email_dialog(window, addr,description, timestamp, expiration, amount,uri, qrcode, status))      

    def open_email_dialog(self, window, addr,description, timestamp, expiration, amount, uri ,qrcode, status):
        self.hostname = self.config.get('hostname', '')
        self.username = self.config.get('email_username', '')
        self.password = self.config.get('email_password', '')
        self.full_name = self.config.get('full_name', '')
        self.send_from = self.config.get('email_send_from', '')
        self.conn_sec = self.config.get('conn_sec', '')
        self.auth_method = self.config.get('auth_method', '')
        self.port = self.config.get('port', '')            
        if not self.username or not self.password or not self.hostname or not self.port:
            window.show_warning(_('The email plugin is enabled but not configured. Please go to its settings and configure it, or disable it if you do not wish to use it.'))
            return

        date_created = datetime.fromtimestamp(timestamp).strftime("%d %b, %Y")
        amount = "{:.8f}".format(amount / 100000000)
        overdue = False
        if expiration:
            due_timestamp = expiration + timestamp
            if due_timestamp < time.time():
                overdue = True
            
            date_due = datetime.fromtimestamp(due_timestamp).strftime("%d %b, %Y")
        else:
            date_due = None

        ''' old file: '''
        # try:
        #     if r.get('signature'):
        #         pr = paymentrequest.serialize_request(r)
        #     else:
        #         pr = paymentrequest.make_request(self.config, r)
        # except ValueError as e:
        #     ''' Bad data such as out-of-range amount, see #1738 '''
        #     self.print_error('Error serializing request:', repr(e))
        #     window.show_error(str(e))
        #     return
        # if not pr:
        #     return
        # payload = pr.SerializeToString()

        payload = uri

        # Convert QRcode to base64 string
        p = qrcode and qrcode.grab()
        if p and not p.isNull():
            image = p.toImage()
            ba = QByteArray()
            buffer = QBuffer(ba)
            buffer.open(QIODevice.WriteOnly)
            image.save(buffer, 'PNG')
            base64_qrcode = ba.toBase64().data().decode()
            buffer.close()

        sender = self.send_from if self.send_from else self.username
        dialog = EmailDialog(self.full_name, sender, description, amount, addr, status, window)
        dialog.show()        
        dialog.send_to.setFocus() 
        dialog.send.connect(lambda: self.start_email_thread(window, dialog, payload, base64_qrcode, uri, addr,
                        amount, date_created, date_due,overdue, description))
        
    def start_email_thread(self, window, dialog, payload, base64_qrcode, uri, addr,
                     amount, date_created,date_due, overdue, description):
        # reload the config variables just incase settings were changed
        # while the dialog was open.
        self.hostname = self.config.get('hostname', '')
        self.username = self.config.get('email_username', '')
        self.password = self.config.get('email_password', '')
        self.full_name = self.config.get('full_name', '')
        self.send_from = self.config.get('email_send_from', '')
        self.conn_sec = self.config.get('conn_sec', '')
        self.auth_method = self.config.get('auth_method', '')
        self.port = self.config.get('port', '')  
        if not self.username or not self.password or not self.hostname or not self.port:
                window.show_warning(_('The email plugin is enabled but not configured. Please go to its settings and configure it, or disable it if you do not wish to use it.'))
                return        
        dialog.disable_form()
        dialog.error_msg.close()
        if dialog.send_from.isEditable() == True:
            sender = dialog.send_from.lineEdit().text().strip() if dialog.send_from.lineEdit().text().strip() != "" else self.username
        else:
            sender = dialog.send_from.currentText().strip() if dialog.send_from.currentText().strip() != "" else self.username
        try:

            thread = QThread(window)
            email_worker = EmailWorker()
            email_worker.canceled = False
            email_worker.moveToThread(thread)
            thread.started.connect( partial(email_worker.send,  thread,self.config, dialog, self.username, self.password, 
                    self.hostname,self.auth_method, self.conn_sec, self.port, dialog.send_to.text(),sender, 
                    dialog.subject.text().strip(),dialog.msg.toPlainText().strip(), 
                    payload, base64_qrcode, uri, addr, amount, date_created, date_due, overdue, description, window))            

            email_worker.result.connect(self.proccess_email_result)
            dialog.progress.canceled.connect( lambda: self.cancel_sending(email_worker))
            dialog.dialogIsClosing.connect(lambda: self.set_dialog_closed_flag(email_worker))
            email_worker.status.connect(self.proccess_status)
            email_worker.closed_before_finished.connect(self.dialog_closed_before_finished)
            email_worker.show_error_on_parent.connect(self.show_error_on_parent)

            thread.start()

            thread.finished.connect(lambda: self.delete_thread( thread, email_worker))

        except Exception as e:
            
            if thread.isRunning():
                thread.quit()
            self.delete_thread()
            dialog.enable_form()
            self.print_error("Exception sending:", repr(e))
            error = type(e).__name__
            dialog.show_error(f'An error occured while sending mail:\n{error}')
            return
    def set_dialog_closed_flag(self, email_worker):
         email_worker.dialog_closed = True
    def dialog_closed_before_finished(self, result, parent):
        if result:
            msg = "Mail sent before it could cancel."
            alert = QMessageBox( QMessageBox.Information,
                            "Sent - Electron Cash",
                            msg,
                            buttons=QMessageBox.Ok,
                            parent=parent)
            alert.setWindowModality(Qt.NonModal)   
            alert.show()       
                                   
    def cancel_sending(self, email_worker):
        email_worker.canceled = True

    def close_after_send(self, dialog):
        dialog.close()

    def delete_thread(self, thread, worker):
        thread.deleteLater()
        worker.deleteLater()

    def show_error_on_parent(self, msg, parent):
        parent.show_error(msg)

    def proccess_status(self, status, dialog):
        if dialog.isVisible():
            dialog.status_label.setText(status)
            dialog.progress.setLabelText(status)

    def proccess_email_result(self, result, msg, dialog, canceled):
        dialog.progress.close()
        if result == 1: #Sent
            dialog.status_label.setText("Sent")
            if not canceled:
                dialog.close()
            else:
                alert = dialog.show_info("Mail was sent before it could cancel.")
                alert.accepted.connect(lambda: self.close_after_send(dialog))
                alert.rejected.connect(lambda: self.close_after_send(dialog))                

        elif result == 0: #Failed
            dialog.enable_form()
            dialog.show_error(msg)
            dialog.status_label.setText(None)

        else: #Canceled 
            dialog.enable_form()        
            dialog.status_label.setText(None)
    def requires_settings(self):
        return True

    def settings_widget(self, window):
        windowRef = Weak.ref(window)
        return EnterButton(_('Settings'), partial(self.settings_dialog, windowRef))

    def settings_dialog(self, windowRef):
        self.hostname = self.config.get('hostname', '')
        self.username = self.config.get('email_username', '')
        self.password = self.config.get('email_password', '')
        self.full_name = self.config.get('full_name', '')
        self.send_from = self.config.get('email_send_from', '')
        self.conn_sec = self.config.get('conn_sec', '')
        self.auth_method = self.config.get('auth_method', '')
        self.port = self.config.get('port', '')          
        window = windowRef()
        if not window: return
        d = WindowModalDialog(window.top_level_window(), _("Email settings"))
        d.setFixedSize(500, 350)


        vbox = QVBoxLayout(d)
        grid = QGridLayout()
        vbox.addLayout(grid)

        grid.addWidget(QLabel('Full name'), 1, 0)
        full_name = QLineEdit()
        full_name.setText(self.full_name)
        grid.addWidget(full_name, 1, 1)        

        grid.addWidget(QLabel('Email address'), 2, 0)
        send_from = QLineEdit()
        send_from.setText(self.send_from)
        grid.addWidget(send_from, 2, 1)

        label = QLabel("SMTP SERVER")
        label.setStyleSheet("font-weight: 900;")
        grid.addWidget(label, 3, 0)

        grid.addWidget(QLabel('Hostname'), 4, 0)
        hostname = QLineEdit()
        hostname.setText(self.hostname)
        grid.addWidget(hostname, 4, 1)

        grid.addWidget(QLabel('Port'),5, 0)
        port = QLineEdit()
        port.setText(self.port)
        onlyInt = QIntValidator()
        port.setValidator(onlyInt)        
        grid.addWidget(port, 5, 1)

        grid.addWidget(QLabel('Connection security'), 6, 0)
        consec = QComboBox()
        consec.addItems(['SSL/TLS'])           
        grid.addWidget(consec, 6, 1)

        grid.addWidget(QLabel('Authentication method'), 7, 0)
        authmeth = QComboBox()
        authmeth.addItems(['Normal password'])       
        authmeth.setCurrentText(self.auth_method)    
        grid.addWidget(authmeth, 7, 1)

        grid.addWidget(QLabel('Username'), 8, 0)
        username = QLineEdit()
        username.setText(self.username)
        grid.addWidget(username, 8, 1)

        grid.addWidget(QLabel('Password'), 9, 0)
        password_e = QLineEdit()
        password_e.setText(self.password)
        password_e.setEchoMode(QLineEdit.Password)
        grid.addWidget(password_e, 9, 1)        

        vbox.addStretch()
        vbox.addLayout(Buttons(CloseButton(d), OkButton(d)))

        if not d.exec_():
            return

        full_name = str(full_name.text())
        self.config.set_key('full_name', full_name)

        hostname = str(hostname.text())
        self.config.set_key('hostname', hostname)

        username = str(username.text())
        self.config.set_key('email_username', username)

        send_from = str(send_from.text())
        self.config.set_key('email_send_from', send_from)

        password = str(password_e.text())
        self.config.set_key('email_password', password)

        password = str(port.text())
        self.config.set_key('port', password)

        consec = str(consec.currentText())
        self.config.set_key('conn_sec', consec)

        authmeth = str(authmeth.currentText())
        self.config.set_key('auth_method', authmeth)

