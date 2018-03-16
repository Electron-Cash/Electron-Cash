from . import utils
from . import gui
from electroncash import WalletStorage, Wallet
from electroncash.util import timestamp_to_datetime, NotEnoughFunds, ExcessiveFee
from electroncash.i18n import _
from .custom_objc import *
import time
import html
from .uikit_bindings import *
from electroncash.networks import NetworkConstants
from electroncash.address import Address, ScriptOutput
from electroncash import bitcoin
import re
from decimal import Decimal
from .feeslider import FeeSlider
from .amountedit import BTCAmountEdit
import traceback
from electroncash.plugins import run_hook

RE_ALIAS = '^(.*?)\s*\<([1-9A-Za-z]{26,})\>$'
        
def parent():
    return gui.ElectrumGui.gui

def config():
    return parent().config

def wallet():
    return parent().wallet
  
class SendVC(UIViewController):
    stuff = objc_property() # an NSArray of stuff to display
    qr = objc_property()
    qrvc = objc_property()
    qrScanErr = objc_property()
    amountSats = objc_property()
    feeSats = objc_property()
    isMax = objc_property()
    notEnoughFunds = objc_property()
    excessiveFee = objc_property()
    timer = objc_property()
    
    @objc_method
    def init(self):
        self = ObjCInstance(send_super(__class__, self, 'init'))
        self.stuff = []
        self.title = _("Send")
        self.qrScanErr = False
        self.amountSats = None # None ok on this one       
        self.feeSats = None  # None ok on this one too
        self.isMax = False # should always be defined
        self.notEnoughFunds = False
        self.excessiveFee = False
        self.timer = None
        return self
    
    @objc_method
    def dealloc(self) -> None:
        self.stuff = None
        self.view = None
        self.qrScanErr = None
        self.amountSats = None
        self.feeSats = None
        self.isMax = None
        self.notEnoughFunds = None
        if self.timer: self.timer.invalidate()  # kill a timer if it hasn't fired yet
        self.timer = None
        self.excessiveFee = None
        send_super(__class__, self, 'dealloc')

    @objc_method
    def didRotateFromInterfaceOrientation_(self, o : int) -> None:
        pass
    
    @objc_method
    def reader_didScanResult_(self, reader, result) -> None:
        utils.NSLog("Reader data = '%s'",str(result))
        self.checkQRData_(result)
        if self.qrScanErr:
            if type(self.qrScanErr) is int and self.qrScanErr == 2:
                title = _("Unsupported QR Code")
                message = _("The QR code contains multiple outputs. At this time only a single output is supported.\nPlease try again.")
            else:
                title = _("Invalid QR Code")
                message = _("The QR code does not appear to be a valid BCH address or payment request.\nPlease try again.")
            reader.stopScanning()
            parent().show_error(
                title = title,
                message = message,
                onOk = lambda: reader.startScanning()
            )
            self.qrScanErr = False
        else:
            self.readerDidCancel_(reader)
             
    @objc_method
    def readerDidCancel_(self, reader) -> None:
        if reader is not None: reader.stopScanning()
        self.dismissViewControllerAnimated_completion_(True, None)
        self.qr = None
        self.qrvc = None    
        
    @objc_method
    def loadView(self) -> None:
        objs = NSBundle.mainBundle.loadNibNamed_owner_options_("Send",self,None)
        assert objs is not None and len(objs)
        self.view = objs[0]
        contentView = self.view.viewWithTag_(100)
        
        # Apply translations and other stuff to UI text...
        parent = gui.ElectrumGui.gui

        lbl = self.view.viewWithTag_(110)
        lbl.text = _("Pay to")
        
        # Pay To text edit
        tedit = self.view.viewWithTag_(115)
        tedit.delegate = self

        # Amount (BCH) label
        lbl = self.view.viewWithTag_(200)
        
        # Input amount text field
        tedit = self.view.viewWithTag_(210)
        tedit.delegate = self # Amount
        def onAmount(t : ObjCInstance) -> None:
            #print("On Amount %s, %s satoshis"%(str(t.text),str(t.getAmount())))
            self.amountSats = t.getAmount()
            if t.isModified():  self.updateFee()
            else: self.chkOk()
        utils.add_callback(tedit, 'textChanged', onAmount)
        def onEdit(t : ObjCInstance) -> None:
            self.isMax = False
        utils.add_callback(tedit, 'edited', onEdit)
        
        lbl = self.view.viewWithTag_(220)
        lbl.text = _("Description")
        
        # Description text field
        tedit = self.view.viewWithTag_(230)
        tedit.delegate = self
        
        but = self.view.viewWithTag_(1090)
        but.setTitle_forState_(_("Max"), UIControlStateNormal)
        but.addTarget_action_forControlEvents_(self, SEL(b'spendMax'), UIControlEventPrimaryActionTriggered)
        
        but = self.view.viewWithTag_(1100)
        but.setTitle_forState_(_("Clear"), UIControlStateNormal)
        but.addTarget_action_forControlEvents_(self, SEL(b'clear'), UIControlEventPrimaryActionTriggered)
        
        but = self.view.viewWithTag_(1110)
        but.setTitle_forState_(_("Preview"), UIControlStateNormal)
        but.addTarget_action_forControlEvents_(self, SEL(b'onPreviewSendBut:'), UIControlEventPrimaryActionTriggered)
        
        but = self.view.viewWithTag_(1120)
        but.setTitle_forState_(_("Send"), UIControlStateNormal)
        but.addTarget_action_forControlEvents_(self, SEL(b'onPreviewSendBut:'), UIControlEventPrimaryActionTriggered)

        # Fee Label
        lbl = self.view.viewWithTag_(300)
        lbl.text = _("Fee")

        tedit = self.view.viewWithTag_(330)
        fee_e = tedit
        tedit.placeholder = _("Fee manual edit")
        tedit.delegate = self
        def onManualFee(t : ObjCInstance) -> None:
            #print("On Manual fee %s, %s satoshis"%(str(t.text),str(t.getAmount())))
            self.feeSats = t.getAmount()
            if t.isModified(): self.updateFee()
            else: self.chkOk()
        utils.add_callback(tedit, 'textChanged', onManualFee)

        # Error Label
        lbl = self.view.viewWithTag_(404)
        lbl.text = _("")

        tedit = self.view.viewWithTag_(230)
        tedit.placeholder = _("Description of the transaction (not mandatory).")
        
        # Check for QRCode availability and if not available, destroy the button
        but = self.view.viewWithTag_(150)
        but.addTarget_action_forControlEvents_(self, SEL(b'onQRBut:'), UIControlEventPrimaryActionTriggered)
   
        feelbl = self.view.viewWithTag_(320)  
        slider = self.view.viewWithTag_(310)
        def sliderCB(dyn : bool, pos : int, fee_rate : int) -> None:
            txt = " ".join(str(slider.getToolTip(pos,fee_rate)).split("\n"))
            feelbl.text = txt
            fee_e.modified = False # force unfreeze fee
            if dyn:
                config().set_key('fee_level', pos, False)
            else:
                config().set_key('fee_per_kb', fee_rate, False)
            self.spendMax() if self.isMax else self.updateFee()
            #print("testcb: %d %d %d.. tt='%s'"%(int(dyn), pos, fee_rate,txt))
        utils.add_callback(slider, 'callback', sliderCB)
        
    @objc_method
    def viewDidLoad(self) -> None:
        self.clear()

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        parent = gui.ElectrumGui.gui

        # redo amount label if prefs changed
        lbl = self.view.viewWithTag_(200)
        tedit = self.view.viewWithTag_(210)
        lbl.text = (_("Amount") + (" ({})")).format(tedit.baseUnit())
        # Placeholder for amount
        tedit = self.view.viewWithTag_(210)
        tedit.placeholder = (_("Input amount") + " ({})").format(tedit.baseUnit())
        wasModified = tedit.isModified()
        tedit.setAmount_(self.amountSats) # in case unit changed in prefs
        tedit.modified = wasModified
        # fee amount label
        lbl = self.view.viewWithTag_(320)
        lbl.text = self.view.viewWithTag_(310).getToolTip(-1,-1)
        # Manual edit .. re-set the amount in satoshis from our cached value, in case they changed units in the prefs screen
        tedit = self.view.viewWithTag_(330)
        wasModified = tedit.isModified()
        tedit.setAmount_(self.feeSats)
        tedit.modified = wasModified
        # fee manual edit unit
        lbl = self.view.viewWithTag_(340)
        lbl.text = (parent.base_unit())
        # set manual fee edit to be enabled/disabled based on prefs settings
        if parent.prefs_get_show_fee():
            tedit.userInteractionEnabled = True
            tedit.alpha = 1.0
            lbl.alpha = 1.0
        else:
            tedit.userInteractionEnabled = False
            tedit.alpha = .5
            lbl.alpha = .5

        #lbl.text = "{} {}".format(parent.format_amount(self.feeSats),parent.base_unit())
        self.chkOk()
        #self.onPayTo_message_amount_(None,None,None) # does some validation
        
    @objc_method
    def viewWillDisappear_(self, animated: bool) -> None:
        send_super(__class__, self, 'viewWillDisappear:', animated, argtypes=[c_bool])
        parent = gui.ElectrumGui.gui
        # Manual edit .. cache the feeSats in case they change stuff in prefs affecting this
        tedit = self.view.viewWithTag_(330)
        self.feeSats = tedit.getAmount()
        # Amount edit --  cache the amountSats in case they change stuff in the prefs affecting this 
        tedit = self.view.viewWithTag_(210)
        self.amountSats = tedit.getAmount()
        

    @objc_method
    def onQRBut_(self, but):
        if not QRCodeReader.isAvailable:
            utils.show_alert(self, _("QR Not Avilable"), _("The camera is not available for reading QR codes"))
        else:
            self.qr = QRCodeReader.new().autorelease()
            self.qrvc = QRCodeReaderViewController.readerWithCancelButtonTitle_codeReader_startScanningAtLoad_showSwitchCameraButton_showTorchButton_("Cancel",self.qr,True,True,True)
            self.qrvc.modalPresentationStyle = UIModalPresentationFormSheet
            self.qrvc.delegate = self
            self.presentViewController_animated_completion_(self.qrvc, True, None)
            self.qrScanErr = False
            pass

    @objc_method
    def textFieldDidBeginEditing_(self, tf) -> None:
        self.view.viewWithTag_(404).text = ""

    @objc_method
    def textFieldShouldEndEditing_(self, tf : ObjCInstance) -> bool:
        #print('textFieldShouldEndEditing %d'%tf.tag)
        if tf.tag in [115,230]:
            tf.text = tf.text.strip() # strip leading/training spaces in description and address text fields
        if tf.tag in [115]: # the other ones auto-call chkOk anyway.. todo: make addr line edit be a special validating class
            self.chkOk()
        return True
        
    @objc_method
    def textFieldShouldReturn_(self, tf : ObjCInstance) -> bool:
        #print('textFieldShouldReturn %d'%tf.tag)
        tf.resignFirstResponder()
        return True
    
    @objc_method
    def onPayTo_message_amount_(self, address, message, amount) -> None:
        # address
        tf = self.view.viewWithTag_(115)
        tf.text = str(address) if address is not None else tf.text
        tf.resignFirstResponder() # just in case
        # label
        tf = self.view.viewWithTag_(230)
        tf.text = str(message) if message is not None else tf.text
        tf.resignFirstResponder()
        # amount
        if amount == "!":
            self.spendMax()
        tf = self.view.viewWithTag_(210)
        self.amountSats = int(amount) if type(amount) in [int,float] else self.amountSats
        tf.setAmount_(self.amountSats)
        tf.resignFirstResponder()
        self.qrScanErr = False
        self.chkOk()
        utils.NSLog("OnPayTo %s %s %s",str(address), str(message), str(amount))
    
    @objc_method
    def chkOk(self) -> bool:
        retVal = False
        errLbl = self.view.viewWithTag_(404)
        addrTf = self.view.viewWithTag_(115)
        sendBut = self.view.viewWithTag_(1120)
        previewBut = self.view.viewWithTag_(1110)
        amountTf = self.view.viewWithTag_(210)
        
        sendBut.enabled = False
        previewBut.enabled = False
        errLbl.text = ""
        
        #c, u, x = wallet().get_balance()        
        #a = self.amountSats if self.amountSats is not None else 0
        #f = self.feeSats if self.feeSats is not None else 0
        
        try:
            #print("wallet balance: %f  amountSats: %f"%(float(c+u),float(self.amountSats)))
            if self.notEnoughFunds:
                errLbl.text = _("Insufficient funds")
                raise Exception("InsufficientFunds")
            if self.excessiveFee:
                errLbl.text = _("Max fee exceeded")
                raise Exception("ExcessiveFee")
            try:
                if len(addrTf.text): Parser().parse_address(addrTf.text) # raises exception on parse error
            except:
                errLbl.text = _("Invalid Address")
                raise Exception("InvalidAddress")
            if self.amountSats is None or self.feeSats is None or not len(addrTf.text): # or self.feeSats <= 0:
                errLbl.text = ""
                raise Exception("SilentException") # silent error when amount or fee isn't yet specified
            
            previewBut.enabled = False # for now, unimplemented.. #True
            sendBut.enabled = True
            retVal = True
        except Exception as e:
            #print("Exception :" + str(e))
            pass
        
        return retVal
    
        
    @objc_method
    def spendMax(self) -> None:
        self.isMax = True
        self.updateFee()  # schedule update
        
    @objc_method
    def clear(self) -> None:
        self.isMax = False
        self.notEnoughFunds = False
        self.excessiveFee = False
        # address
        tf = self.view.viewWithTag_(115)
        tf.text = ""
        # Amount
        tf = self.view.viewWithTag_(210)
        tf.setAmount_(None)
        # label
        tf = self.view.viewWithTag_(230)
        tf.text = ""
        # slider
        slider = self.view.viewWithTag_(310)
        slider.setValue_animated_(slider.minimumValue,True)
        slider.onMoved()
        # manual edit fee
        tf = self.view.viewWithTag_(330)
        tf.setAmount_(None)
        # self.amountSats set below..
        self.amountSats = None
        self.feeSats = None
        self.view.viewWithTag_(404).text = ""  # clear errors
        self.chkOk()
        
    @objc_method
    def checkQRData_(self, text) -> None:
        self.qrScanErr = False
        scan_f =  parent().pay_to_URI
        parser = Parser()

        errors = []
        #if self.is_pr:
        #    return
        # filter out empty lines
        lines = text.split("\n")
        lines = [i for i in lines if i]
        outputs = []
        total = 0
        #self.payto_address = None
        payto_address = None
        
        if len(lines) == 1:
            data = lines[0]
            if data.lower().startswith(NetworkConstants.CASHADDR_PREFIX + ":"):
                def errFunc(): self.qrScanErr = True
                self.isMax = False
                scan_f(data, errFunc)
                self.updateFee() # schedule a fee update later after qr decode completes
                return
            try:
                #self.payto_address = self.parse_output(data)
                payto_address = parser.parse_output(data)
            except:
                pass
            #if self.payto_address:
            if payto_address and len(payto_address) and isinstance(payto_address[1], Address):
                #self.win.lock_amount(False)
                #print("LOCK AMOUNT = False")
                
                try:
                    #self.onPayTo_message_amount_(payto_address[1].to_ui_string(), None, None)
                    self.onPayTo_message_amount_(data, None, None)
                    return
                except Exception as e:
                    utils.NSLog("EXCEPTION -- %s",str(e))
                    pass

        is_max = False
        for i, line in enumerate(lines):
            try:
                _type, to_address, amount = parser.parse_address_and_amount(line)
            except:
                #self.errors.append((i, line.strip()))
                errors.append((i, line.strip()))
                continue

            outputs.append((_type, to_address, amount))
            if amount == '!':
                is_max = True
            else:
                total += amount

        #self.win.is_max = is_max
        #self.outputs = outputs
        #self.payto_address = None

        #if self.win.is_max:
        #    self.win.do_update_fee()
        #else:
        #    self.amount_edit.setAmount(total if outputs else None)
        #    self.win.lock_amount(total or len(lines)>1)
        if len(errors):
            self.qrScanErr = True
        elif len(outputs) != 1:
            self.qrScanErr = 2
        else:
            #print("onCheckPayToText.. last clause")
            self.isMax = is_max
            self.onPayTo_message_amount_(outputs[0][1].to_ui_string(),"",outputs[0][2])
            self.updateFee()  #schedule a fee update later
        utils.NSLog("onCheckPayToText_ result: is_max=%s outputs=%s total=%s errors=%s",str(is_max),str(outputs),str(total),str(errors))

    @objc_method
    def updateFee(self):
        # Enqueus a doUpdateFee() call for later -- this facility is provided for the fee slider so that it doesn't behave too slowly.
        def onTimer() -> None:
            self.timer = None
            self.doUpdateFee()
        if self.timer: self.timer.invalidate()
        self.timer = utils.call_later(0.1,onTimer)

    @objc_method
    def doUpdateFee(self) -> None:
        '''Recalculate the fee.  If the fee was manually input, retain it, but
        still build the TX to see if there are enough funds.
        '''
        fee_e = self.view.viewWithTag_(330)
        amount_e = self.view.viewWithTag_(210)
        addr_e = self.view.viewWithTag_(115)
        self.notEnoughFunds = False
        self.excessiveFee = False
       
        def get_outputs(is_max):
            outputs = []
            if addr_e.text:
                if is_max:
                    amount = '!'
                else:
                    amount = amount_e.getAmount()
                
                try:
                    _type, addr = Parser().parse_output(addr_e.text)
                    outputs = [(_type, addr, amount)]
                except Exception as e:
                    #print("Testing get_outputs Exception: %s"%str(e))
                    pass
            return outputs[:]
        def get_dummy():
            return (bitcoin.TYPE_ADDRESS, wallet().dummy_address())
        
        freeze_fee = (fee_e.isModified()
                      and (fee_e.text or fee_e.isFirstResponder))
        #print("freeze_fee=%s"%str(freeze_fee))
        amount = '!' if self.isMax else amount_e.getAmount()
        if amount is None:
            if not freeze_fee:
                fee_e.setAmount(None)
            # TODO
            #self.statusBar().showMessage('')
        else:
            fee = fee_e.getAmount() if freeze_fee else None
            outputs = get_outputs(self.isMax)
            if not outputs:
                _type, addr = get_dummy()
                outputs = [(_type, addr, amount)]
            try:
                tx = wallet().make_unsigned_transaction(get_coins(), outputs, config(), fee)
            except NotEnoughFunds:
                self.notEnoughFunds = True
                if not freeze_fee:
                    fee_e.setAmount_(None)
                self.chkOk()
                return
            except ExcessiveFee:
                self.excessiveFee = True
                self.chkOk()
                return
            except BaseException as e:
                print("BASE EXCEPTION %s"%str(e))
                self.chkOk()
                return

            if not freeze_fee:
                fee = None if self.notEnoughFunds else tx.get_fee()
                fee_e.setAmount_(fee)

            if self.isMax:
                amount = tx.output_value()
                amount_e.setAmount_(amount)
        self.chkOk()

    @objc_method
    def onPreviewSendBut_(self, but) -> None:
        isPreview = but.tag == 1110
        print ("Clicked %s"%("Preview" if isPreview else "Send"))
        self.doSend(isPreview)
        
    @objc_method
    def showTransaction_desc_(self, txraw, desc) -> None:
        print("showTransaction unimplemented. desc=%s, raw=%s"%(str(desc),str(txraw)))
            
    @objc_method
    def doSend(self, preview : bool) -> None:
        #if run_hook('abort_send', self):
        #    return
        r = read_send_form(self)
        if not r:
            return
        outputs, fee, tx_desc, coins = r
        try:
            tx = wallet().make_unsigned_transaction(coins, outputs, config(), fee)
        except NotEnoughFunds:
            parent().show_error(_("Insufficient funds"))
            return
        except ExcessiveFee:
            parent().show_error(_("Your fee is too high.  Max is 50 sat/byte."))
            return
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            parent().show_error(str(e))
            return

        amount = tx.output_value() if self.isMax else sum(map(lambda x:x[2], outputs))
        fee = tx.get_fee()

        #if fee < self.wallet.relayfee() * tx.estimated_size() / 1000 and tx.requires_fee(self.wallet):
            #parent().show_error(_("This transaction requires a higher fee, or it will not be propagated by the network"))
            #return

        if preview:
            self.showTransaction_desc_(tx.serialize(), tx_desc)
            return

        # confirmation dialog
        msg = [
            _("Amount to be sent") + ": " + parent().format_amount_and_units(amount),
            _("Mining fee") + ": " + parent().format_amount_and_units(fee),
        ]

        x_fee = run_hook('get_tx_extra_fee', wallet(), tx)
        if x_fee:
            x_fee_address, x_fee_amount = x_fee
            msg.append( _("Additional fees") + ": " + parent().format_amount_and_units(x_fee_amount) )

        confirm_rate = 2 * config().max_fee_rate()

        # IN THE FUTURE IF WE WANT TO APPEND SOMETHING IN THE MSG ABOUT THE FEE, CODE IS COMMENTED OUT:
        #if fee > confirm_rate * tx.estimated_size() / 1000:
        #    msg.append(_('Warning') + ': ' + _("The fee for this transaction seems unusually high."))

        if wallet().has_password():
            msg.append("")
            msg.append(_("Enter your password to proceed"))
            password = parent().password_dialog('\n'.join(msg))
            if not password:
                return
        else:
            #msg.append(_('Proceed?'))
            #password = None
            #if not self.question('\n'.join(msg)):
            #    return
            pass

        def sign_done(success) -> None:
            if success:
                if not tx.is_complete():
                    self.showTransaction_desc_(tx.serialize(), tx_desc)
                    self.clear()
                else:
                    parent().broadcast_transaction(tx, tx_desc)
            #else:
            #    parent().show_error(_("An Unknown Error Occurred"))
        parent().sign_tx_with_password(tx, sign_done, password)


def get_coins():
    # TODO: Implement pay_from
    #if self.pay_from:
    #    return self.pay_from
    #else:
    return wallet().get_spendable_coins(None, config())
           
def read_send_form(send : ObjCInstance) -> tuple:
    #if self.payment_request and self.payment_request.has_expired():
    #    parent().show_error(_('Payment request has expired'))
    #    return
    label = send.view.viewWithTag_(230).text
    addr_e = send.view.viewWithTag_(115)
    fee_e = send.view.viewWithTag_(330)
    outputs = []

    if False: #self.payment_request:
        #outputs = self.payment_request.get_outputs()
        pass
    else:
        errors = False #self.payto_e.get_errors()
        if errors:
            #self.show_warning(_("Invalid lines found:") + "\n\n" + '\n'.join([ _("Line #") + str(x[0]+1) + ": " + x[1] for x in errors]))
            #return
            pass
        amt_e = send.view.viewWithTag_(210)
        try:
            typ, addr = Parser().parse_output(addr_e.text)
        except:
            utils.show_alert(parent().get_presented_viewcontroller(), _("Error"), _("Invalid Address"))
            return None
        outputs = [(typ, addr, "!" if send.isMax else amt_e.getAmount())]

        #if self.payto_e.is_alias and self.payto_e.validated is False:
        #    alias = self.payto_e.toPlainText()
        #    msg = _('WARNING: the alias "{}" could not be validated via an additional '
        #            'security check, DNSSEC, and thus may not be correct.').format(alias) + '\n'
        #    msg += _('Do you wish to continue?')
        #    if not self.question(msg):
        #        return

    if not outputs:
        utils.show_alert(parent().get_presented_viewcontroller(), _("Error"), _('No outputs'))
        return None

    for _type, addr, amount in outputs:
        if amount is None:
            utils.show_alert(parent().get_presented_viewcontroller(), _("Error"), _('Invalid Amount'))
            return None

    freeze_fee = fee_e.isModified() and fee_e.getAmount()#self.fee_e.isVisible() and self.fee_e.isModified() and (self.fee_e.text() or self.fee_e.hasFocus())
    fee = fee_e.getAmount() if freeze_fee else None
    coins = get_coins()
    return outputs, fee, label, coins


class Parser:
    def parse_address_and_amount(self, line):
        x, y = line.split(',')
        out_type, out = self.parse_output(x)
        amount = self.parse_amount(y)
        return out_type, out, amount

    def parse_output(self, x):
        try:
            address = self.parse_address(x)
            return bitcoin.TYPE_ADDRESS, address
        except:
            return bitcoin.TYPE_SCRIPT, ScriptOutput.from_string(x)

    def parse_address(self, line):
        r = line.strip()
        m = re.match(RE_ALIAS, r)
        address = m.group(2) if m else r
        return Address.from_string(address)

    def parse_amount(self, x):
        if x.strip() == '!':
            return '!'
        p = pow(10, parent().get_decimal_point())
        return int(p * Decimal(x.strip()))
