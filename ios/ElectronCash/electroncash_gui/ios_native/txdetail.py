from electroncash.i18n import _, language
from . import utils
from . import gui
from .uikit_bindings import *
from electroncash.transaction import Transaction
from electroncash.address import Address, PublicKey

# ViewController used for the TxDetail view's "Inputs" and "Outputs" tables.. not exposed.. managed internally
class TxInputsOutputsTVC(NSObject):
    
    txraw = objc_property()
    tagin = objc_property()
    tagout = objc_property()
    
    @objc_method
    def initWithTxRaw_inputTV_outputTV_(self, txraw : ObjCInstance, inputTV : ObjCInstance, outputTV : ObjCInstance) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self is not None:
            self.txraw = txraw
            if inputTV.tag == 0:
                inputTV.tag = 9001
            self.tagin = inputTV.tag
            if outputTV.tag == 0:
                outputTV.tag = self.tagin + 1
            self.tagout = outputTV.tag
            
            if self.tagin == self.tagout or inputTV.ptr.value == outputTV.ptr.value:
                raise ValueError("The input and output table views must be different and have different tags!")
            
            inputTV.delegate = self
            outputTV.delegate = self
            inputTV.dataSource = self
            outputTV.dataSource = self
            
            from rubicon.objc.runtime import libobjc            
            libobjc.objc_setAssociatedObject(inputTV.ptr, self.ptr, self.ptr, 0x301)
            libobjc.objc_setAssociatedObject(outputTV.ptr, self.ptr, self.ptr, 0x301)
        return self
    
    @objc_method
    def dealloc(self) -> None:
        print("TxInputsOutputsTVC dealloc")
        self.txraw = None
        self.tagin = None
        self.tagout = None
        send_super(__class__, self, 'dealloc')
        
    @objc_classmethod
    def tvcWithTxRaw_inputTV_outputTV_(cls, txraw, itv, otv) -> ObjCInstance:
        return __class__.alloc().initWithTxRaw_inputTV_outputTV_(txraw,itv,otv).autorelease()
    
    @objc_method
    def numberOfSectionsInTableView_(self, tv) -> int:
        return 1
    
    @objc_method
    def tableView_titleForHeaderInSection_(self, tv : ObjCInstance,section : int) -> ObjCInstance:
        tx = Transaction(self.txraw)
        tx.deserialize()
        if tv.tag == self.tagin: return _("Inputs") + " (%d) "%len(tx.inputs())
        elif tv.tag == self.tagout: return _("Outputs") + " (%d) "%len(tx.outputs())
        return "*ERROR*"
            
    @objc_method
    def tableView_numberOfRowsInSection_(self, tv : ObjCInstance, section : int) -> int:
        tx = Transaction(self.txraw)
        tx.deserialize()
        
        if tv.tag == self.tagin:
            return len(tx.inputs())
        elif tv.tag == self.tagout:
            return len(tx.outputs())

    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tv, indexPath):
        #todo: - allow for label editing (popup menu?)
        identifier = "%s_%s"%(str(__class__) , str(indexPath.section))
        cell = tv.dequeueReusableCellWithIdentifier_(identifier)
        parent = gui.ElectrumGui.gui
        wallet = parent.wallet
        
        def format_amount(amt):
            return parent.format_amount(amt, whitespaces = True)

        if cell is None:
            cell = UITableViewCell.alloc().initWithStyle_reuseIdentifier_(UITableViewCellStyleSubtitle, identifier).autorelease()
        try:
            tx = Transaction(self.txraw)
            tx.deserialize()
        
            isInput = None
            x = None
            if tv.tag == self.tagin:
                isInput = True
                x = tx.inputs()[indexPath.row]
            elif tv.tag == self.tagout:
                isInput = False
                x = tx.get_outputs()[indexPath.row]
            else:
                raise ValueError("tv tag %d is neither input (%d) or output (%d) tag!"%(int(tv.tag),int(self.tagin),int(self.tagout)))
            
            colorExt = UIColor.colorWithRed_green_blue_alpha_(1.0,1.0,1.0,0.0)
            colorChg = UIColor.colorWithRed_green_blue_alpha_(1.0,0.9,0.3,0.3)
            colorMine = UIColor.colorWithRed_green_blue_alpha_(0.0,1.0,0.0,0.1)

            cell.backgroundColor = colorExt
            addr = None
            
            if isInput:
                if x['type'] == 'coinbase':
                    cell.textLabel.text = "coinbase"
                    cell.detailTextLabel.text = ""
                else:
                    prevout_hash = x.get('prevout_hash')
                    prevout_n = x.get('prevout_n')
                    mytxt = ""
                    mytxt += prevout_hash[0:8] + '...'
                    mytxt += prevout_hash[-8:] + ":%-4d " % prevout_n
                    addr = x['address']
                    if isinstance(addr, PublicKey):
                        addr = addr.toAddress()
                    if addr is None:
                        addr_text = _('unknown')
                    else:
                        addr_text = addr.to_ui_string()
                    cell.textLabel.text = addr_text
                    if x.get('value'):
                        mytxt += format_amount(x['value'])
                    cell.detailTextLabel.text = mytxt
            else:
                colorMine = UIColor.colorWithRed_green_blue_alpha_(1.0,0.0,1.0,0.1)
                addr, v = x
                #cursor.insertText(addr.to_ui_string(), text_format(addr))
                cell.textLabel.text = addr.to_ui_string()
                cell.detailTextLabel.text = ""
                if v is not None:
                    cell.detailTextLabel.text = format_amount(v)

            if isinstance(addr, Address) and wallet.is_mine(addr):
                if wallet.is_change(addr):
                    cell.backgroundColor = colorChg
                else:
                    cell.backgroundColor = colorMine
                
            cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator#UITableViewCellAccessoryDetailDisclosureButton#UITableViewCellAccessoryDetailButton #
        except Exception as e:
            print("exception in %s: %s"%(__class__.name,str(e)))
            cell.textLabel.attributedText = None
            cell.textLabel.text = "*Error*"
            cell.detailTextLabel.attributedText = None
            cell.detailTextLabel.text = None
            cell.accessoryType = None
        return cell
    
    # Below 2 methods conform to UITableViewDelegate protocol
    @objc_method
    def tableView_accessoryButtonTappedForRowWithIndexPath_(self, tv, indexPath):
        print("ACCESSORY TAPPED CALLED")
        pass
    
    @objc_method
    def tableView_didSelectRowAtIndexPath_(self, tv, indexPath):
        print("DID SELECT ROW CALLED FOR SECTION %s, ROW %s"%(str(indexPath.section),str(indexPath.row)))
        parent = gui.ElectrumGui.gui
        tv.deselectRowAtIndexPath_animated_(indexPath, True)
        tx = Transaction(self.txraw)
        tx.deserialize()
        isInput = tv.tag == self.tagin
        x = tx.inputs()[indexPath.row] if isInput else tx.get_outputs()[indexPath.row]
        vc = parent.get_presented_viewcontroller()
        title = _("Options")
        message = _("Transaction Input {}").format(indexPath.row) if isInput else _("Transaction Output {}").format(indexPath.row)
        
        def getData(x, isAddr, isInput) -> str:
            data = ""
            if isAddr:
                if isInput:
                    addr = x['address']
                    if isinstance(addr, PublicKey):
                        addr = addr.toAddress()
                    if addr is None:
                        addr_text = _('unknown')
                    else:
                        addr_text = addr.to_ui_string()
                else:
                    addr, v = x
                    addr_text = addr.to_ui_string()
                data = addr_text
            elif isInput:
                prevout_hash = x.get('prevout_hash')
                prevout_n = x.get('prevout_n')
                data = prevout_hash[:] #+ ":%-4d" % prevout_n
            print("Data=%s"%str(data))
            return data
        
        def onCpy(isAddr : bool) -> None:
            print ("onCpy %s"%str(isAddr))
            UIPasteboard.generalPasteboard.string = getData(x,isAddr,isInput)
            utils.show_notification(message=_("Text copied to clipboard"))
        def onQR(isAddr : bool) -> None:
            print ("onQR %s"%str(isAddr))
            data = getData(x, isAddr, isInput)
            qrvc = utils.present_qrcode_vc_for_data(parent.get_current_nav_controller(), data)
            parent.add_navigation_bar_close_to_modal_vc(qrvc)

        def onBlkXplo() -> None:
            print ("onBlkXplo")
            if isInput:
                data = getData(x, False, True)
            else:
                data = getData(x, True, False)
                data = Address.from_string(data)
            parent.view_on_block_explorer(data, "tx" if isInput else "addr")
        
        actions = [
            [ _("Copy address to clipboard"), onCpy, True ],
            [ _("Show address as QR code"), onQR, True ],
            [ _("Copy input hash to clipboard"), onCpy, False ],
            [ _("Show input hash as QR code"), onQR, False ],
            [ _("View on block explorer"), onBlkXplo ],
            [ _("Cancel") ],
        ]
        if not isInput:
            actions.pop(2)
            actions.pop(2)
        
        utils.show_alert(vc = vc,
                         title = title,
                         message = message,
                         actions = actions,
                         cancel = _("Cancel"),
                         style = UIAlertControllerStyleActionSheet)
    

# returns the view itself, plus the copy button and the qrcode button, plus the (sometimes nil!!) UITextField for the editable description
#  the copy and the qrcode buttons are so that caller may attach event handing to them
def create_transaction_detail_view(txDetailViewController : ObjCInstance) -> (ObjCInstance, ObjCInstance, ObjCInstance, ObjCInstance):
    entry = txDetailViewController.entry
    dummy, tx_hash, status_str, label, v_str, balance_str, date, conf, status, value, img, *dummy2 = entry
    parent = gui.ElectrumGui.gui
    wallet = parent.wallet
    base_unit = parent.base_unit()
    format_amount = parent.format_amount
    tx = None
    if txDetailViewController.rawtx:
        try:
            tx = Transaction(txDetailViewController.rawtx)
            tx.deserialize()
        except Exception as e:
            tx = None
            utils.NSLog("Got exception finding & deserializing tx with hash %s: %s",tx_hash,str(e))
    if tx is None:
        tx = wallet.transactions.get(tx_hash, None)
        if tx is not None: tx.deserialize()
    if tx is None: raise ValueError("Cannot find tx for hash: %s"%tx_hash)
    tx_hash, status_, label_, can_broadcast, amount, fee, height, conf, timestamp, exp_n = wallet.get_tx_info(tx)
    size = tx.estimated_size()
    # todo: broadcast button based on 'can_broadcast'
    can_sign = not tx.is_complete() and wallet.can_sign(tx) #and (wallet.can_sign(tx) # or bool(self.main_window.tx_external_keypairs))
    # todo: something akin to this: self.sign_button.setEnabled(can_sign)

    objs = NSBundle.mainBundle.loadNibNamed_owner_options_("TxDetail",None,None)
    view = objs[0]
    
    # grab all the views
    # Transaction ID:
    txTit = view.viewWithTag_(100)
    txHash = view.viewWithTag_(110)
    copyBut = view.viewWithTag_(120)
    qrBut = view.viewWithTag_(130)
    # Description:
    descTit = view.viewWithTag_(200)
    descTf = view.viewWithTag_(210)
    # Status:
    statusTit = view.viewWithTag_(300)
    statusIV = view.viewWithTag_(310)
    statusLbl = view.viewWithTag_(320)
    # Date:
    dateTit = view.viewWithTag_(400)
    dateLbl = view.viewWithTag_(410)
    # Amount received/sent:
    amtTit = view.viewWithTag_(500)
    amtLbl = view.viewWithTag_(510)
    # Size:
    sizeTit = view.viewWithTag_(600)
    sizeLbl = view.viewWithTag_(610)
    # Fee:
    feeTit = view.viewWithTag_(700)
    feeLbl = view.viewWithTag_(710)
    # Locktime:
    lockTit = view.viewWithTag_(800)
    lockLbl = view.viewWithTag_(810)
    # Inputs
    inputsTV = view.viewWithTag_(1000)
    # Outputs
    outputsTV = view.viewWithTag_(1100)
    
    # Setup data for all the stuff
    txTit.text = _("Transaction ID:")
    tx_hash_str = tx_hash if tx_hash is not None and tx_hash != "None" and tx_hash != "Unknown" and tx_hash != _("Unknown") else _('Unknown')
    if tx_hash == _("Unknown"):
        txHash.text = tx_hash_str
    else:
        linkAttributes = {
            NSForegroundColorAttributeName : UIColor.colorWithRed_green_blue_alpha_(0.05,0.4,0.65,1.0),
            NSUnderlineStyleAttributeName : NSUnderlineStyleSingle              
        }
        txHash.attributedText = NSAttributedString.alloc().initWithString_attributes_(tx_hash_str, linkAttributes).autorelease()
        txHash.userInteractionEnabled = True
        txHash.addGestureRecognizer_(UITapGestureRecognizer.alloc().initWithTarget_action_(txDetailViewController,SEL(b'onTxLink:')).autorelease())

    descTit.text = _("Description") + ":"
    descTf.text = label
    descTf.placeholder = _("Tap to add a description")
    if amount < 0:
        descTf.backgroundColor = UIColor.colorWithRed_green_blue_alpha_(1.0,0.2,0.2,0.040)
    else:
        descTf.backgroundColor = UIColor.colorWithRed_green_blue_alpha_(0.0,0.0,1.0,0.040)
    descTf.adjustsFontSizeToFitWidth = True
    descTf.minimumFontSize = 8.0
    descTf.clearButtonMode = UITextFieldViewModeWhileEditing

    statusTit.text = _("Status:")
    #statusIV.autoresizingMask = UIViewAutoresizingNone
    statusIV.image = img
    ff = status_str
    try:
        if int(conf) > 0:
           ff = "%s %s"%(conf, _('confirmations'))
    except:
        pass        
    statusLbl.text = _(ff)
    
    if timestamp or exp_n:
        if timestamp:
            dateTit.text = _("Date") + ":"
            dateLbl.text = date
        elif exp_n:
            dateTit.text = _("Expected confirmation time") + ':'
            dateLbl.text = '%d blocks'%(exp_n) if exp_n > 0 else _('unknown (low fee)')
    else:
        # wtf? what to do here? 
        dateTit.text = _("Date") + ":"
        dateLbl.text = ""
        dateTit.alpha = 0.5
        dateLbl.alpha = 0.5
 
    if amount is None:
        amtTit.text = _("Amount") + ":"
        amtLbl.text = _("Transaction unrelated to your wallet")
    elif amount > 0:
        amtTit.text = _("Amount received:")
        amtLbl.text = ('%s'%(format_amount(amount))) + ' ' + base_unit
    else:
        amtTit.text = _("Amount sent:") 
        amtLbl.text = ('%s'%(format_amount(-amount))) + ' ' + base_unit

    sizeTit.text = _("Size:")
    if size:
        sizeLbl.text = ('%d bytes' % (size))
    else:
        sizeLbl.text = _("Unknown")

    feeTit.text = _("Fee") + ':'
    fee_str = '%s' % (format_amount(fee) + ' ' + base_unit if fee is not None else _('unknown'))
    if fee is not None:
        fee_str += '  ( %s ) '%  parent.format_fee_rate(fee/size*1000)
    feeLbl.text = fee_str
    
    if tx.locktime > 0:
        lockLbl.text = str(tx.locktime)
        
    # refreshes the tableview with data    
    tvc = TxInputsOutputsTVC.tvcWithTxRaw_inputTV_outputTV_(tx.raw, inputsTV, outputsTV)
    
    #view.translatesAutoresizingMaskIntoConstraints = False
    #view.viewWithTag_(1).translatesAutoresizingMaskIntoConstraints = True
    
    return (view, copyBut, qrBut, descTf)

class TxDetail(UIViewController):
    # entry = ('', tx_hash, status_str, label, v_str, balance_str, date_str, conf, status, val, status_uiimage)
    entry = objc_property()  # an NSArray of basically the history entry
    rawtx = objc_property()  # string of the raw tx data suitable for building a Transaction instance using deserialize.  May be None

    @objc_method
    def initWithEntry_rawTx_(self, entry : ObjCInstance, rawtx : ObjCInstance) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self:
            self.entry = entry
            self.rawtx = rawtx
            self.title = _("Transaction") + " " + _("Details")
        return self
    
    @objc_method
    def dealloc(self) -> None:
        print("TxDetail dealloc")
        self.entry = None
        self.rawtx = None
        self.title = None
        self.view = None
        send_super(__class__, self, 'dealloc')
    
    @objc_method
    def loadView(self) -> None:
        self.view, butCopy, butQR, descrTF = create_transaction_detail_view(self)
        butCopy.addTarget_action_forControlEvents_(self, SEL(b'onCopyBut:'), UIControlEventPrimaryActionTriggered)
        butQR.addTarget_action_forControlEvents_(self, SEL(b'onQRBut:'), UIControlEventPrimaryActionTriggered)
        if descrTF is not None:
            descrTF.delegate = self

    @objc_method
    def textFieldShouldReturn_(self, tf) -> bool:
        #print("hit return, value is {}".format(tf.text))
        tx_hash = self.entry[1]
        tf.text = tf.text.strip()
        new_label = tf.text
        gui.ElectrumGui.gui.on_label_edited(tx_hash, new_label)
        tf.resignFirstResponder()
        return True

    @objc_method
    def onCopyBut_(self, but) -> None:
        UIPasteboard.generalPasteboard.string = self.entry[1]
        utils.show_notification(message=_("Text copied to clipboard"))

    @objc_method
    def onQRBut_(self, but) -> None:
        #utils.show_notification(message="QR button unimplemented -- coming soon!", duration=2.0, color=(.9,0,0,1.0))
        
        qrvc = utils.present_qrcode_vc_for_data(vc=self.tabBarController,
                                                data=self.entry[1],
                                                title = _('QR code'))
        gui.ElectrumGui.gui.add_navigation_bar_close_to_modal_vc(qrvc)

        
    @objc_method
    def onTxLink_(self, gestureRecognizer : ObjCInstance) -> None:
        def on_block_explorer() -> None:
            parent = gui.ElectrumGui.gui
            parent.view_on_block_explorer(self.entry[1], 'tx')
            
        utils.show_alert(
            vc = self,
            title = _("Options"),
            message = _("Transaction ID:") + " " + self.entry[1][:12] + "...",
            actions = [
                [ 'Cancel' ],
                [ _('Copy to clipboard'), self.onCopyBut_, None ],
                [ _('Show as QR code'), self.onQRBut_, None ],
                [ _("View on block explorer"), on_block_explorer ],
            ],
            cancel = 'Cancel',
            style = UIAlertControllerStyleActionSheet
        )
