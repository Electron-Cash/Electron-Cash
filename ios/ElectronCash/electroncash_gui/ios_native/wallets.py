from . import utils
from . import gui
from . import history
from . import newwallet # Do not remove -- needed to declare NewWalletVC to ObjC runtime  (used by storyboard instantiation)
from electroncash.i18n import _, language

from .uikit_bindings import *
from .custom_objc import *

# from ViewsForIB.h, WalletsStatusMode enum
StatusOffline = 0
StatusOnline = 1
StatusDownloadingHeaders = 2
StatusSynchronizing = 3


StatusColors = {
    StatusOnline : UIColor.colorWithRed_green_blue_alpha_(187.0/255.0,255.0/255.0,59.0/255.0,1.0).retain(),
    StatusOffline : UIColor.colorWithRed_green_blue_alpha_(255.0/255.0,97.0/255.0,97.0/255.0,1.0).retain(),
    StatusDownloadingHeaders : UIColor.colorWithRed_green_blue_alpha_(255.0/255.0,194.0/255.0,104.0/255.0,1.0).retain(),
    StatusSynchronizing : UIColor.colorWithRed_green_blue_alpha_(104.0/255.0,255.0/255.0,179.0/255.0,1.0).retain(),
}

VChevronImages = [
    UIImage.imageNamed_("chevron_00000").retain(),
    UIImage.imageNamed_("chevron_00001").retain(),
    UIImage.imageNamed_("chevron_00002").retain(),
    UIImage.imageNamed_("chevron_00003").retain(),
    UIImage.imageNamed_("chevron_00004").retain(),
    UIImage.imageNamed_("chevron_00005").retain(),
]

class WalletsNav(WalletsNavBase):    
    @objc_method
    def dealloc(self) -> None:
        send_super(__class__, self, 'dealloc')

class WalletsVC(WalletsVCBase):
    lineHider = objc_property()
    
    @objc_method
    def dealloc(self) -> None:
        # cleanup code here..
        gui.ElectrumGui.gui.sigHistory.disconnect(self)
        gui.ElectrumGui.gui.sigRequests.disconnect(self)
        gui.ElectrumGui.gui.sigWallets.disconnect(self)

        self.lineHider = None
        send_super(__class__, self, 'dealloc')  

    @objc_method
    def commonInit(self) -> None:
        # put additional setup code here
        self.status = StatusOffline # re-does the text/copy and colors
        self.walletAmount.text = "0"
        # Custom Segmented Control setup
        self.segControl.items = [_("Transactions"), _("Requests")]
        self.segControl.showsCount = False
        cols = [65.0/255.0, 204.0/255.0]
        self.segControl.setTitleColor_forState_(UIColor.colorWithWhite_alpha_(cols[0], 1.0),UIControlStateSelected)
        self.segControl.setTitleColor_forState_(UIColor.colorWithWhite_alpha_(cols[1], 1.0),UIControlStateNormal)
        self.segControl.font = UIFont.systemFontOfSize_weight_(16.0, UIFontWeightSemibold)
        self.segControl.autoAdjustSelectionIndicatorWidth = False
        # Can't set this property from IB, so we do it here programmatically to create the stroke around the receive button
        self.receiveBut.layer.borderColor = self.sendBut.backgroundColor.CGColor

        gui.ElectrumGui.gui.sigHistory.connect(lambda: self.refresh(), self)
        gui.ElectrumGui.gui.sigRequests.connect(lambda: self.refresh(), self)
        gui.ElectrumGui.gui.sigWallets.connect(lambda: self.refresh(), self)
    
    @objc_method
    def refresh(self) -> None:
        self.doChkTableViewCounts()
        if self.walletName: self.walletName.text = str(_Get('current'))
        if self.statusBlurb: self.statusBlurb.sizeToFit()
    
    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        self.commonInit()
        self.txsHelper.miscSetup()

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        f = self.navBar.frame
        # This line hider is a hack/fix for a weirdness in iOS where there is a white line between the top nav bar and the bottom
        # 'drawer' area.  This hopefully fixes that.
        self.lineHider = UIView.alloc().initWithFrame_(CGRectMake(0,f.size.height,f.size.width,1)).autorelease()
        self.lineHider.backgroundColor = self.blueBarTop.backgroundColor
        self.navBar.addSubview_(self.lineHider)
        self.lineHider.autoresizingMask = (1<<6)-1
        self.refresh()

    @objc_method
    def viewWillDisappear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillDisappear:', animated, argtypes=[c_bool])
        if self.lineHider:
            self.lineHider.removeFromSuperview()
            self.lineHider = None

    @objc_method
    def viewWillTransitionToSize_withTransitionCoordinator_(self, size : CGSize, coordinator : ObjCInstance) -> None:
        send_super(__class__, self, 'viewWillTransitionToSize:withTransitionCoordinator:', size, coordinator, argtypes=[CGSize,objc_id])
        if self.txsHelper and self.txsHelper.tv:
            self.txsHelper.tv.reloadData() # this implicitly redoes the central table and the number of preview transactions we see in it
        self.refresh()

    @objc_method
    def setStatus_(self, mode : int) -> None:
        send_super(__class__, self, 'setStatus:', mode, argtypes=[c_int])
        if self.viewIfLoaded is None or self.statusLabel is None:
            utils.NSLog("WARNING: WalletsVC setStatus on a WalletsVC that is not fully initialized!")
            return
        c = None
        try:
            c = StatusColors[mode]
        except:
            c = StatusColors[StatusOffline]
        self.statusLabel.backgroundColor = c
        if mode == StatusOnline:
            self.statusBlurb.text = _("All set and good to go.")
            self.statusLabel.text = _("Online")
        elif mode == StatusDownloadingHeaders:
            self.statusBlurb.text = _("Transaction history may not yet be current.")
            self.statusLabel.text = " " + _("Downloading Headers") + "   " # hack -- pad with spaces so it look right.. TODO: fix this issue
        elif mode == StatusSynchronizing:
            self.statusBlurb.text = _("Updating transaction history.")
            self.statusLabel.text = _("Synchronizing")
        else: # mode == StatusOffline        
            self.statusBlurb.text = _("Cannot send/receive new transactions.")
            self.statusLabel.text = _("Offline")
            
        self.statusBlurb.sizeToFit()
        
    @objc_method
    def setAmount_andUnits_unconf_(self, amt, units, unconf) -> None:
        #ats = NSMutableAttributedString.alloc().initWithString_(units).autorelease()
        if unconf:
            unconf = " " + unconf.strip()
            '''ats.appendAttributedString_(NSAttributedString.alloc().initWithString_attributes_(
                unconf,
                {
                    NSFontAttributeName: UIFont.systemFontOfSize_(11.0)
                }
                ).autorelease())
            '''
        else:
            unconf = ''
        self.walletAmount.text = amt
        #self.walletUnits.attributedText = ats
        self.walletUnits.text = units+unconf
        if self.modalDrawerVC:
            self.modalDrawerVC.amount.text = amt
            #self.modalDrawerVC.units.attributedText = ats
            self.modalDrawerVC.units.text = units+unconf
            

    @objc_method
    def toggleDrawer(self) -> None:
        '''
        Fancy tricky code below to create the "drawer opening" effect.
        Fades-in the WalletsDrawerVC view controller (which overlays on top of our view), while
        opening the drawer and animating the chevron. This creates the effect of the drawer opening and everything
        behind it fading darker.  It's pretty smoothe. Potential glitches include the layout constraints in the
        modal not lining up perfectly with our view's drawer stub.  But this has been tested and works on all extant
        iPhones & iPads in the simulator.
        '''
        if not self.modalDrawerVC:
            NSBundle.mainBundle.loadNibNamed_owner_options_("WalletsDrawerVC", self, None)
            vc = self.modalDrawerVC # Note: self.modalDrawerVC weak ref auto-set by Nib loader
            if not vc:
                utils.NSLog("**** Warning: toggleDrawer could not find the requisite view controller in WalletsDrawerVC.nib!")
                return
            vc.amount.text = self.walletAmount.text
            #vc.units.attributedText = self.walletUnits.attributedText
            vc.units.text = self.walletUnits.text
            vc.name.text = self.walletName.text
            semiclear = vc.view.backgroundColor.copy()
            vc.view.backgroundColor = UIColor.clearColor
            def compl() -> None:
                vc.view.backgroundColorAnimationToColor_duration_reverses_completion_(semiclear.autorelease(), 0.2, False, None)
                vc.openAnimated_(True)
            self.presentViewController_animated_completion_(vc, False, compl)
        else:
            # NB: weak ref self.modalDrawerVC will be auto-cleared by obj-c runtime after it is dismissed
            utils.call_later(0.100, self.dismissViewControllerAnimated_completion_,True, None)
            self.modalDrawerVC.closeAnimated_(True)
        
    @objc_method
    def didChangeSegment_(self, control : ObjCInstance) -> None:
        ix = self.segControl.selectedSegmentIndex
        if ix == 0:
            self.txsHelper.tv.setHidden_(False)
            self.reqstv.setHidden_(True)
        elif ix == 1:
            self.txsHelper.tv.setHidden_(True)
            self.reqstv.setHidden_(False)
            self.reqstv.reloadData()
        self.doChkTableViewCounts()

    # Detects if a tap was in the status label or on the status blurb
    @objc_method
    def gestureRecognizerShouldBegin_(self, gr : ObjCInstance) -> bool:
        s = self.statusLabel.bounds.size
        s2 = self.statusBlurb.bounds.size
        p = gr.locationInView_(self.statusLabel)
        p2 = gr.locationInView_(self.statusBlurb)
        return self.navigationController.visibleViewController.ptr.value == self.ptr.value and \
                ( (p.x >= 0 and p.y >= 0 and p.x <= s.width and p.y <= s.height) \
                  or (p2.x >= 0 and p2.y >= 0 and p2.x <= s2.width and p2.y <= s2.height) )
                  

    # pops up the network setup dialog and also does a little animation on the status label
    @objc_method
    def onTopNavTap(self) -> None:
        if self.statusLabel.hasAnimations:
            print("status label animation already active, ignoring spurious second tap....")
            return
        c1 = self.statusLabel.backgroundColor.colorWithAlphaComponent_(0.50)
        c2 = self.statusBlurb.textColor.colorWithAlphaComponent_(0.10)
        def doShowNetworkDialog() -> None:
            gui.ElectrumGui.gui.show_network_dialog()
        self.statusLabel.backgroundColorAnimationToColor_duration_reverses_completion_(c1,0.2,True,doShowNetworkDialog)
        self.statusBlurb.textColorAnimationToColor_duration_reverses_completion_(c2,0.2,True,None)
        
    @objc_method
    def onSendBut(self) -> None:
        gui.ElectrumGui.gui.show_send_modal()

    @objc_method
    def onReceiveBut(self) -> None:
        gui.ElectrumGui.gui.show_receive_modal()
        
    @objc_method
    def doChkTableViewCounts(self) -> None:
        if not self.reqstv or not self.txsHelper or not self.txsHelper.tv or not self.segControl or not self.reqstv.dataSource:
            return
        if self.segControl.selectedSegmentIndex == 0:
            # Transactions
            ntx = self.txsHelper.tableView_numberOfRowsInSection_(self.txsHelper.tv, 0)
            self.noTXsView.setHidden_(bool(ntx))
            self.noReqsView.setHidden_(True)
            self.txsHelper.tv.setHidden_(not bool(ntx))
        elif self.segControl.selectedSegmentIndex == 1:
            # Requests
            nreq = self.reqstv.dataSource.tableView_numberOfRowsInSection_(self.reqstv, 0)
            self.noTXsView.setHidden_(True)
            self.noReqsView.setHidden_(bool(nreq))
            self.reqstv.setHidden_(not bool(nreq))


class WalletsDrawerVC(WalletsDrawerVCBase):
    bluchk = objc_property()
        
    @objc_method
    def dealloc(self) -> None:
        #cleanup code here
        gui.ElectrumGui.gui.sigWallets.disconnect(self)
        self.bluchk = None
        send_super(__class__, self, 'dealloc')
     
    @objc_method 
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        self.tv.tableFooterView = self.tableFooter
        nib = UINib.nibWithNibName_bundle_("WalletsDrawerCell", None)
        self.tv.registerNib_forCellReuseIdentifier_(nib, "WalletsDrawerCell")
        gui.ElectrumGui.gui.sigWallets.connect(lambda: self.refresh(), self)
       
    @objc_method
    def refresh(self) -> None:
        self.name.text = str(_Get('current'))
        self.tv and self.tv.reloadData()
        
    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        self.ensureCurrentIsVisible()
        
    @objc_method
    def ensureCurrentIsVisible(self) -> None:
        if self.tv:
            current = _Get('current')
            wallets = _Get()
            for i,wallet in enumerate(wallets):
                if current == wallet.name:
                    self.tv.scrollToRowAtIndexPath_atScrollPosition_animated_(NSIndexPath.indexPathForRow_inSection_(i, 0), UITableViewScrollPositionMiddle, False)
                    return
        
    @objc_method
    def numberOfSectionsInTableView_(self, tableView) -> int:
        return 1

    @objc_method
    def tableView_numberOfRowsInSection_(self, tableView, section : int) -> int:
        # TODO: Implement this properly
        wl = _Get()
        return len(wl) if wl else 0

    @objc_method
    def tableView_heightForHeaderInSection_(self, tableView, section) -> float:
        return 22.0

    @objc_method
    def tableView_viewForHeaderInSection_(self, tableView, section) -> ObjCInstance:
        ret = self.tableHeader
        if ret:
            name = ret.viewWithTag_(1)
            size = ret.viewWithTag_(2)
            name.setText_withKerning_(_("Name"), utils._kern) 
            size.setText_withKerning_(_("Size:").translate({ord(i):None for i in ':'}), utils._kern)
        return ret

    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tableView, indexPath) -> ObjCInstance:
        identifier = "WalletsDrawerCell"
        cell = tableView.dequeueReusableCellWithIdentifier_(identifier)
        try:
            info = _Get()[indexPath.row]
        except:
            info = WalletsMgr.Info('Error', 0, 'INVALID')
        if cell is None:
            objs = NSBundle.mainBundle.loadNibNamed_owner_options_("WalletsDrawerCell",None,None)
            for obj in objs:
                if isinstance(obj, UITableViewCell) and obj.reuseIdentifier == identifier:
                    cell = obj
                    break
        iv = cell.viewWithTag_(1)
        name = cell.viewWithTag_(2)
        size = cell.viewWithTag_(3)
        if not self.bluchk:
            self.bluchk = iv.image
        chkd = info.name == _Get('current')
        if chkd:
            iv.image = self.bluchk
        else:
            iv.image = None
        name.text = str(info.name)
        size.text = "%2.2f KB"%(info.size/1024.0)
        return cell

    @objc_method
    def tableView_heightForRowAtIndexPath_(self, tv : ObjCInstance, indexPath : ObjCInstance) -> float:
        return 60.0

    @objc_method
    def tableView_didSelectRowAtIndexPath_(self, tv, indexPath):
        tv.deselectRowAtIndexPath_animated_(indexPath,True)
        try:
            name = _Get()[indexPath.row].name
            if name == _Get('current'): return
            gui.ElectrumGui.gui.switch_wallets(vc = self, wallet_name = name,
                                               onSuccess = lambda: utils.call_later(0.2, self.vc.toggleDrawer),
                                               onFailure = lambda x: gui.ElectrumGui.gui.show_error(message=str(x), vc = self)
                                               )
        except:
            import sys
            utils.NSLog("Got exception: %s",str(sys.exc_info()[1]))

    @objc_method
    def addWallet(self) -> None:
        if not self.tableFooter: return
        addWalletView = self.tableFooter
        if addWalletView.hasAnimations:
            print('"Add Wallet View" animation already active, ignoring spurious second tap....')
            return
        c = UIColor.colorWithRed_green_blue_alpha_(0.0,0.0,0.0,0.10)
        def doAddWallet() -> None:
            #gui.ElectrumGui.gui.show_message(message="'Add Wallet' is not yet implemented.", title="Coming Soon!")
            sb = UIStoryboard.storyboardWithName_bundle_("NewWallet", None)
            if not sb:
                utils.NSLog("ERROR: SB IS NULL")
                return
            nav = sb.instantiateViewControllerWithIdentifier_("Start_NewWallet_1")
            if nav:
                self.presentViewController_animated_completion_(nav, True, None)
            else:
                utils.NSLog("ERROR: NAV IS NULL")
        addWalletView.backgroundColorAnimationToColor_duration_reverses_completion_(c,0.2,True,doAddWallet)
     
    # overrides base
    @objc_method
    def openAnimated_(self, animated : bool) -> None:
        self.chevron.animationImages = VChevronImages
        if not self.chevron.isAnimating() and animated:
            self.chevron.animationDuration = 0.2
            self.chevron.animationRepeatCount = 1
            self.chevron.startAnimating()
        else:
            self.chevron.stopAnimating()
        send_super(__class__, self, 'openAnimated:', animated, argtypes=[c_bool])

    # overrides base
    @objc_method
    def closeAnimated_(self, animated : bool) -> None:
        self.chevron.animationImages = list(reversed(VChevronImages))
        if not self.chevron.isAnimating() and animated:
            self.chevron.animationDuration = 0.2
            self.chevron.animationRepeatCount = 1
            self.chevron.startAnimating()
        else:
            self.chevron.stopAnimating()
        send_super(__class__, self, 'closeAnimated:', animated, argtypes=[c_bool])


def _Get(key = None) -> list():
    # return a list of wallets ultimately from WalletsMgr's list_wallets() function below..
    return gui.ElectrumGui.gui.sigWallets.get(key)

''' Wallets Manager -- Misc functions to create, inspect, etc wallets all in 1 place.
    This class wasn't stricly needed but the rationale was to have all wallet management code
    in the app go through a central place for my own testing and sanity. -Calin, May 2018
'''
from typing import Any
from collections import namedtuple
import os, sys, glob

class WalletsMgr(utils.DataMgr):

    Info = namedtuple('WalletInfo', 'name size full_path')
    
    def __init__(self):
        super().__init__()
        
    def parent(self) -> object:
        # I'm paranoid about circular references.. so we return this on-demand each time
        return gui.ElectrumGui.gui
    
    def wallets_dir(self) -> str:
        p = self.parent()
        return os.path.split(p.config.get_wallet_path())[0] if p and p.config else ''
    
    def doReloadForKey(self, key : Any) -> Any:
        if key in ('current', 'basename', 'name', 'wallet_name', 'wallet', 'opened'):
            p = self.parent()
            return p.wallet.basename() if p and p.wallet else None
        return self.list_wallets()
    
    def list_wallets(self) -> list:
        ret = list()
        d = self.wallets_dir()
        if os.path.isdir(d):
            it = glob.iglob(os.path.join(self.wallets_dir(),'*'))
            for wf in it:
                if wf and wf[0] != '.':
                    st = os.stat(wf)
                    if st:
                        fn = os.path.split(wf)[1]
                        info = WalletsMgr.Info(fn, st.st_size, wf)
                        ret.append(info)
        ret.sort(key=lambda x: [x.name, x.size], reverse=False)
        return ret

    
    def check_wallet_exists(self, wallet_name : str) -> bool:
        w = os.path.split(wallet_filename)[1]
        path = self.wallets_dir()
        return os.path.exists(os.path.join(path, w))

