from . import utils
from . import gui
from .txdetail import TxDetail
from electroncash import WalletStorage, Wallet
from electroncash.util import timestamp_to_datetime
from electroncash.i18n import _, language
import time
import html
from .uikit_bindings import *
 
# History Tab -- shows tx's, etc
class HistoryTableVC(UITableViewController):
    needsRefresh = objc_property()
    statusImages = objc_property()

    @objc_method
    def initWithStyle_(self, style : int):
        self = ObjCInstance(send_super(__class__, self, 'initWithStyle:', style, argtypes=[c_int]))
        self.needsRefresh = False
        self.title = _("History")
        # setup the status icons array.. cache the images basically
        tx_icons = [
            "warning.png",
            "warning.png",
            "unconfirmed.png",
            "unconfirmed.png",
            "clock1.png",
            "clock2.png",
            "clock3.png",
            "clock4.png",
            "clock5.png",
            "confirmed.png",
        ]
        self.statusImages = NSMutableArray.arrayWithCapacity_(len(tx_icons))
        for icon in tx_icons:
            img = UIImage.imageNamed_(icon)
            assert img is not None
            self.statusImages.addObject_(img)
        
        self.refreshControl = UIRefreshControl.alloc().init().autorelease()

        return self

    @objc_method
    def dealloc(self) -> None:
        self.needsRefresh = None
        self.statusImages = None
        send_super(__class__, self, 'dealloc')

    @objc_method
    def numberOfSectionsInTableView_(self, tableView) -> int:
        return 1

    @objc_method
    def tableView_numberOfRowsInSection_(self, tableView, section : int) -> int:
        try:
            parent = gui.ElectrumGui.gui
            return len(parent.history)
        except:
            print("Error, no history")
            return 0

    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tableView, indexPath):
        identifier = "%s_%s"%(str(__class__) , str(indexPath.section))
        cell = tableView.dequeueReusableCellWithIdentifier_(identifier)
        if cell is None:
            cell = UITableViewCell.alloc().initWithStyle_reuseIdentifier_(UITableViewCellStyleSubtitle, identifier).autorelease()
        try:
            parent = gui.ElectrumGui.gui
            entry = parent.history[indexPath.row]
            _, tx_hash, status_str, label, v_str, balance_str, date, conf, status, val, *_ = entry

            ff = str(date)
            if conf > 0:
                ff = "%s %s"%(conf, language.gettext('confirmations'))
            if label is None:
                label = ''
            lblColor = "#000000" if val >= 0 else "#993333"
            lblSep = ' - ' if len(label) else ''
            title = utils.nsattributedstring_from_html(('<font face="system font,arial,helvetica,verdana" size=2>%s</font>'
                                                       + '<font face="system font,arial,helvetica,verdana" size=4>%s<font color="%s"><b>%s</b></font></font>')
                                                       %(html.escape(status_str),
                                                         lblSep,
                                                         lblColor,
                                                         ''+html.escape(label)+'' if len(label)>0 else ''
                                                         ))
            pstyle = NSMutableParagraphStyle.alloc().init().autorelease()
            pstyle.lineBreakMode = NSLineBreakByTruncatingTail
            title.addAttribute_value_range_(NSParagraphStyleAttributeName, pstyle, NSRange(0,title.length()))
            detail = utils.nsattributedstring_from_html(('<p align="justify" style="font-family:system font,arial,helvetica,verdana">'
                                                        + 'Amt: <font face="monaco, menlo, courier" color="%s"><strong>%s</strong></font>'
                                                        + ' - Bal: <font face="monaco, menlo, courier"><strong>%s</strong></font>'
                                                        + ' - <font size=-1 color="#666666"><i>(%s)</i></font>'
                                                        + '</p>')
                                                        %(lblColor,html.escape(v_str),html.escape(balance_str),html.escape(ff)))
            detail.addAttribute_value_range_(NSParagraphStyleAttributeName, pstyle, NSRange(0,detail.length()))
            if status >= 0 and status < len(self.statusImages):
                cell.imageView.image = self.statusImages[status]
            else:
                cell.imageView.image = None
            cell.textLabel.text = None
            cell.textLabel.adjustsFontSizeToFitWidth = False if len(label) > 0 else True
            cell.textLabel.lineBreakMode = NSLineBreakByTruncatingTail# if len(label) > 0 else NSLineBreakByClipping
            cell.textLabel.numberOfLines = 1 #if len(label) <= 0 else 2
            cell.textLabel.attributedText = title
            cell.textLabel.updateConstraintsIfNeeded()
            cell.detailTextLabel.text = None
            cell.detailTextLabel.adjustsFontSizeToFitWidth = False
            cell.detailTextLabel.lineBreakMode = NSLineBreakByTruncatingTail
            cell.detailTextLabel.numberOfLines = 1
            cell.detailTextLabel.attributedText = detail
            cell.detailTextLabel.updateConstraintsIfNeeded()
            cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator
        except Exception as e:
            print("exception in tableView_cellForRowAtIndexPath_: %s"%str(e))
            cell.textLabel.attributedText = None
            cell.textLabel.text = "*Error*"
            cell.detailTextLabel.attributedText = None
            cell.detailTextLabel.text = None
            cell.accessoryType = None
        return cell
    
    # Below 2 methods conform to UITableViewDelegate protocol
    @objc_method
    def tableView_accessoryButtonTappedForRowWithIndexPath_(self, tv, indexPath):
        #print("ACCESSORY TAPPED CALLED")
        pass
    
    @objc_method
    def tableView_didSelectRowAtIndexPath_(self, tv, indexPath):
        #print("DID SELECT ROW CALLED FOR ROW %d"%indexPath.row)
        parent = gui.ElectrumGui.gui
        hentry = parent.history[indexPath.row]
        entry = [str(it) for it in hentry]
        entry.append(self.statusImages[hentry[8]])
        tx = parent.wallet.transactions.get(hentry[1], None)
        rawtx = None
        if tx is not None: rawtx = tx.raw
        parent.historyNav.pushViewController_animated_(TxDetail.alloc().initWithEntry_rawTx_(entry, rawtx).autorelease(), True)
    
    @objc_method
    def updateHistoryFromWallet(self):
        parent = gui.ElectrumGui.gui
        wallet = parent.wallet
        h = wallet.get_history()
        #item = self.currentItem()
        #current_tx = item.data(0, Qt.UserRole) if item else None
        #self.clear()
        #fx = parent.fx
        #if fx: fx.history_used_spot = False
        parent.history = []
        for h_item in h:
            tx_hash, height, conf, timestamp, value, balance = h_item
            status, status_str = wallet.get_tx_status(tx_hash, height, conf, timestamp)
            has_invoice = wallet.invoices.paid.get(tx_hash)
            #icon = QIcon(":icons/" + TX_ICONS[status])
            v_str = parent.format_amount(value, True, whitespaces=True)
            balance_str = parent.format_amount(balance, whitespaces=True)
            label = wallet.get_label(tx_hash)
            date = timestamp_to_datetime(time.time() if conf <= 0 else timestamp)
            entry = ('', tx_hash, status_str, label, v_str, balance_str, date, conf, status, value)
            parent.history.insert(0,entry) # reverse order
            #if fx and fx.show_history():
            #    date = timestamp_to_datetime(time.time() if conf <= 0 else timestamp)
            #    for amount in [value, balance]:
            #        text = fx.historical_value_str(amount, date)
            #        entry.append(text)
            #item = SortableTreeWidgetItem(entry)
            #item.setIcon(0, icon)
            #item.setToolTip(0, str(conf) + " confirmation" + ("s" if conf != 1 else ""))
            #item.setData(0, SortableTreeWidgetItem.DataRole, (status, conf))
            #if has_invoice:
            #    item.setIcon(3, QIcon(":icons/seal"))
            #for i in range(len(entry)):
            #    if i>3:
            #        item.setTextAlignment(i, Qt.AlignRight)
            #    if i!=2:
            #        item.setFont(i, QFont(MONOSPACE_FONT))
            #if value and value < 0:
            #    item.setForeground(3, QBrush(QColor("#BC1E1E")))
            #    item.setForeground(4, QBrush(QColor("#BC1E1E")))
            #if tx_hash:
            #    item.setData(0, Qt.UserRole, tx_hash)
            #self.insertTopLevelItem(0, item)
            #if current_tx == tx_hash:
            #    self.setCurrentItem(item)
        print ("fetched %d entries from history"%len(parent.history))


    @objc_method
    def refresh(self):
        self.updateHistoryFromWallet()
        if self.refreshControl: self.refreshControl.endRefreshing()
        if self.tableView:
            self.tableView.reloadData()
        self.needsRefresh = False

    @objc_method
    def needUpdate(self):
        if self.needsRefresh: return
        self.needsRefresh = True
        self.retain()
        def inMain() -> None:
            self.doRefreshIfNeeded()
            self.autorelease()
        utils.do_in_main_thread(inMain)

    # This method runs in the main thread as it's enqueue using our hacky "Heartbeat" mechanism/workaround for iOS
    @objc_method
    def doRefreshIfNeeded(self):
        if self.needsRefresh:
            self.refresh()
            #print ("HISTORY REFRESHED")

    @objc_method
    def showRefreshControl(self):
        if self.refreshControl is not None and not self.refreshControl.isRefreshing():
            # the below starts up the table view in the "refreshing" state..
            self.refreshControl.beginRefreshing()
            self.tableView.setContentOffset_animated_(CGPointMake(0, self.tableView.contentOffset.y-self.refreshControl.frame.size.height), True)
