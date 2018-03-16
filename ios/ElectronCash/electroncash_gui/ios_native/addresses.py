from . import utils
from . import gui
from electroncash import WalletStorage, Wallet
from electroncash.util import timestamp_to_datetime
import electroncash.exchange_rate
from electroncash.i18n import _, language
from electroncash.address import Address

import time
import html

try:
    from .uikit_bindings import *
except Exception as e:
    sys.exit("Error: Could not import iOS libs: %s"%str(e))

class AddressDetail(UIViewController):
    addrInfo = objc_property() # an NSArray of stuff to display
    
    @objc_method
    def initWithAddrInfo_(self, addrInfo):
        self = ObjCInstance(send_super(__class__, self, 'init'))
        self.addrInfo = addrInfo
        self.title = "Address Information"
        return self
    
    @objc_method
    def dealloc(self) -> None:
        #print("AddressDetail dealloc")
        self.addrInfo = None
        self.title = None
        self.view = None
        send_super(__class__, self, 'dealloc')
    
    @objc_method
    def loadView(self) -> None:
        self.view = UIView.alloc().init().autorelease()
        lbl = UILabel.alloc().init().autorelease()
        lbl.text = "Address Detail: " + str(self.addrInfo[0])
        lbl.adjustsFontSizeForWidth = True
        lbl.numberOfLines = 2
        w = UIScreen.mainScreen.bounds.size.width
        rect = CGRectMake(0,100,w,80)
        lbl.frame = rect
        self.view.addSubview_(lbl)

 
# Addresses Tab -- shows addresses, etc
class AddressesTableVC(UITableViewController):
    needsRefresh = objc_property()

    @objc_method
    def initWithStyle_(self, style : int):
        self = ObjCInstance(send_super(__class__, self, 'initWithStyle:', style, argtypes=[c_int]))
        self.needsRefresh = False
        self.title = _("&Addresses").split('&')[1]
                
        self.refreshControl = UIRefreshControl.alloc().init().autorelease()
        self.updateAddressesFromWallet()
        
        return self

    @objc_method
    def dealloc(self) -> None:
        self.needsRefresh = None
        send_super(__class__, self, 'dealloc')

    @objc_method
    def numberOfSectionsInTableView_(self, tableView) -> int:
        parent = gui.ElectrumGui.gui
        addrData = parent.addrData
        return len(addrData.getSections())
    
    @objc_method
    def tableView_titleForHeaderInSection_(self, tv : ObjCInstance,section : int) -> ObjCInstance:
        try:
            parent = gui.ElectrumGui.gui
            addrData = parent.addrData
            return addrData.getSections().get(section, '')
        except Exception as e:
            print("Error in addresses 1: %s"%str(e))
            return '*Error*'
            
    @objc_method
    def tableView_numberOfRowsInSection_(self, tableView : ObjCInstance, section : int) -> int:
        try:
            parent = gui.ElectrumGui.gui
            addrData = parent.addrData
            d = addrData.getListsBySection()
            return len(d.get(section,[]))
        except Exception as e:
            print("Error in addresses 2: %s"%str(e))
            return 0

    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tableView, indexPath):
        #todo: - allow for label editing (popup menu?)
        identifier = "%s_%s"%(str(__class__) , str(indexPath.section))
        cell = tableView.dequeueReusableCellWithIdentifier_(identifier)
        if cell is None:
            cell = UITableViewCell.alloc().initWithStyle_reuseIdentifier_(UITableViewCellStyleSubtitle, identifier).autorelease()
        try:
            parent = gui.ElectrumGui.gui
            addrData = parent.addrData
            entries = addrData.getListsBySection().get(indexPath.section,[])
            assert indexPath.row < len(entries)
            entry = entries[indexPath.row]
            for i,e in enumerate(entry):
                if type(e) is str:
                    entry[i] = html.escape(e)
            # columns are: (address_text, addr_idx_text, label, balance_text, fiat_balance_text, num_tx_text, is_frozen_bool) 
            address_text, addr_idx_text, label, balance_text, fiat_balance_text, num_tx_text, is_frozen_bool, num, bal, *_ = entry
            titleColorSpec = '#000000' if not is_frozen_bool else '#99333'
            detailColorSpec = '#555566' if not is_frozen_bool else '#99333'
            labelColorSpec = '#000000' if not is_frozen_bool else '#993333'
            balColorSpec = 'color="#000000"' if bal > 0.0 else ''
            fiat_html = (' (<font face="monaco, menlo, courier" %s>%s</font>) '%(balColorSpec,fiat_balance_text)) if addrData.show_fx else ''
            title = utils.nsattributedstring_from_html('<font face="system font,arial,helvetica,verdana" color="%s"><b>%s</b></font>'
                                                       % (titleColorSpec,address_text) )
            detail = utils.nsattributedstring_from_html(('<font face="system font,arial,helvetica,verdana" color="%s" size="-1">'
                                                         + 'bal: <font face="monaco, menlo, courier" % size=+1s>%s</font>%snumtx: %s label: <font color="%s">%s</font>'
                                                         + '</font>')
                                                        % (detailColorSpec, balColorSpec, balance_text, fiat_html, num_tx_text, labelColorSpec, label) 
                                                        )
            pstyle = NSMutableParagraphStyle.alloc().init().autorelease()
            pstyle.lineBreakMode = NSLineBreakByTruncatingTail
            title.addAttribute_value_range_(NSParagraphStyleAttributeName, pstyle, NSRange(0,title.length()))
            detail.addAttribute_value_range_(NSParagraphStyleAttributeName, pstyle, NSRange(0,detail.length()))
            cell.imageView.image = None
            cell.textLabel.text = None
            cell.textLabel.adjustsFontSizeToFitWidth = False
            cell.textLabel.lineBreakMode = NSLineBreakByTruncatingTail
            cell.textLabel.numberOfLines = 1
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
            print("exception in addresses tableView_cellForRowAtIndexPath_: %s"%str(e))
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
        #print("DID SELECT ROW CALLED FOR SECTION %s, ROW %s"%(str(indexPath.section),str(indexPath.row)))
        parent = gui.ElectrumGui.gui
        parent.addressesNav.pushViewController_animated_(AddressDetail.alloc().initWithAddrInfo_(['Some Info for addr %d'%(indexPath.section*4+indexPath.row)]).autorelease(), True)
 
    
    @objc_method
    def updateAddressesFromWallet(self):
        parent = gui.ElectrumGui.gui
        wallet = parent.wallet
        try:
            #hack.. fixme
            addrData = parent.addrData
            if addrData is None:
                raise AttributeError('dummy')
        except AttributeError:
            addrData = parent.addrData = AddressData(wallet, parent)
        addrData.refresh()


    @objc_method
    def refresh(self):
        self.updateAddressesFromWallet()
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
            #print ("ADDRESSES REFRESHED")


    @objc_method
    def showRefreshControl(self):
        if self.refreshControl is not None and not self.refreshControl.isRefreshing():
            # the below starts up the table view in the "refreshing" state..
            self.refreshControl.beginRefreshing()
            self.tableView.setContentOffset_animated_(CGPointMake(0, self.tableView.contentOffset.y-self.refreshControl.frame.size.height), True)


class AddressData:
    
    def __init__(self, wallet, gui_parent):
        self.parent = gui_parent
        self.wallet = wallet
        self.clear()
        
    def clear(self):
        # columns are: (address_text, addr_idx_text, label, balance_text, fiat_balance_text, num_tx_text, is_frozen_bool) 
        self.receiving = []
        self.used = []
        self.unspent = []
        self.change = []
        self.sections = {}
        self.lists_by_section = {}
        self.show_fx = False
        
    def refresh(self):
        self.clear()
        receiving_addresses = self.wallet.get_receiving_addresses()
        change_addresses = self.wallet.get_change_addresses()

        if self.parent.daemon.fx and self.parent.daemon.fx.get_fiat_address_config():
            fx = self.parent.daemon.fx
            self.show_fx = True
        else:
            fx = None
        which_list = self.unspent
        sequences = [0,1] if change_addresses else [0]
        for is_change in sequences:
            if len(sequences) > 1:
                which_list = self.receiving if not is_change else self.change
            else:
                which_list = self.unspent
            addr_list = change_addresses if is_change else receiving_addresses
            for n, address in enumerate(addr_list):
                num = len(self.wallet.get_address_history(address))
                is_used = self.wallet.is_used(address)
                balance = sum(self.wallet.get_addr_balance(address))
                address_text = address.to_ui_string()
                label = self.wallet.labels.get(address.to_storage_string(), '')
                balance_text = self.parent.format_amount(balance, whitespaces=True)
                is_frozen = self.wallet.is_frozen(address)
                fiat_balance = fx.value_str(balance, fx.exchange_rate()) if fx else "0"
                columns = [address_text, str(n), label, balance_text, fiat_balance, str(num), is_frozen, num, balance] # NB: num,balance needs to be last for sort below
                if is_used:
                    self.used.append(columns)
                else:
                    if balance <= 0.0 and len(sequences) < 2:
                        self.receiving.append(columns)
                    else:
                        which_list.append(columns)
        
        self.used.sort(key=lambda x: [x[-1],x[-2]], reverse=True )
        self.change.sort(key=lambda x: [x[-1],x[-2]], reverse=True )
        self.unspent.sort(key=lambda x: [x[-1],x[-2]], reverse=True )
        self.receiving.sort(key=lambda x: [x[-1],x[-2]], reverse=True )
        
                    
    def getSections(self) -> dict:
        if len(self.sections):
            return self.sections
        d = {}
        if len(self.unspent):
            d[len(d)] = _("Unspent")
        d[len(d)] = _("Receiving")
        if len(self.change):
            d[len(d)] = _("Change")
        if len(self.used):
            d[len(d)] = _("Used")
        self.sections = d
        return d

    def getListsBySection(self) -> dict:
        if len(self.lists_by_section):
            return self.lists_by_section
        d = {}
        if len(self.unspent):
            d[len(d)] = self.unspent
        d[len(d)] = self.receiving
        if len(self.change):
            d[len(d)] = self.change
        if len(self.used):
            d[len(d)] = self.used
        self.lists_by_section = d
        return d
        