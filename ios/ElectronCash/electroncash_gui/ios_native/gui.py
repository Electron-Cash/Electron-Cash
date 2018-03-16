#!/usr/bin/env python3
#
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2012 thomasv@gitorious
# Copyright (C) 2018 calin.culianu@gmail.com
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

import signal
import sys
import traceback
import bz2
import base64
import time
from datetime import datetime
from decimal import Decimal
from functools import partial
try:
    from .uikit_bindings import *
except Exception as e:
    sys.exit("Error: Could not import iOS libs: %s"%str(e))
from . import utils
from . import history
from . import addresses
from . import send
from . import receive
from . import prefs
from .custom_objc import *

from electroncash.i18n import _, set_language, languages
from electroncash.plugins import run_hook
from electroncash import WalletStorage, Wallet
from electroncash.address import Address
# from electroncash.synchronizer import Synchronizer
# from electroncash.verifier import SPV
# from electroncash.util import DebugMem
from electroncash.util import UserCancelled, print_error, format_satoshis, format_satoshis_plain, PrintError, timestamp_to_datetime
import electroncash.web as web


# from electroncash.wallet import Abstract_Wallet

# a dummy hard coded wallet with a few tx's in its history for testing
# encrypted with password 'bchbch'
hardcoded_testing_wallet = bz2.decompress(base64.b64decode(b'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'))

TAG_PASSWD = 2
TAG_CASHADDR = 3
TAG_PREFS = 4
TAG_SEED = 5
TAG_NETWORK = 6

class MyTabBarController(UITabBarController):
    
    didLayout = objc_property()
    
    @objc_method
    def init(self) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self is not None: self.didLayout = False
        return self
    
    @objc_method
    def viewDidLayoutSubviews(self) -> None:
        self.didLayout = True
        send_super(__class__, self, 'viewDidLayoutSubviews')


class GuiHelper(NSObject):
    updateNeeded = objc_property()
    butsStatus = objc_property()
    butsStatusLabel = objc_property()
    butsPasswd = objc_property() # array of buttons, one per tab
    butsCashaddr = objc_property()
    butsSeed = objc_property()
    butsPrefs = objc_property()
    butsSend = objc_property()
    
    @objc_method
    def init(self):
        self = ObjCInstance(send_super(__class__, self, 'init'))
        self.updateNeeded = False
        self.butsStatus = []
        self.butsStatusLabel = []
        self.butsPasswd = []
        self.butsCashaddr = []
        self.butsSeed = []
        self.butsPrefs = []
        self.butsSend = []
        return self
    
    @objc_method
    def dealloc(self) -> None:
        self.updateNeeded = None
        self.butsStatus = None
        self.butsStatusLabel = None
        self.butsPasswd = None
        self.butsCashaddr = None
        self.butsSeed = None
        self.butsPrefs = None
        self.butsSend = None
        send_super(__class__, self, 'dealloc')
    
    @objc_method
    def onTimer_(self, ignored):
        pass
    
    @objc_method
    def doUpdateIfNeeded(self):
        if self.updateNeeded and ElectrumGui.gui is not None:
            ElectrumGui.gui.on_status_update()
            self.updateNeeded = False

    @objc_method
    def needUpdate(self):
        if self.updateNeeded: return
        self.updateNeeded = True
        self.retain()
        def inMain() -> None:
            self.doUpdateIfNeeded()
            self.autorelease()
        utils.do_in_main_thread(inMain)
        
    @objc_method
    def onToolButton_(self,but) -> None:
        print("onToolButton: called with button tag {}".format(str(but.tag)))
        if ElectrumGui.gui is not None:
            ElectrumGui.gui.on_tool_button(but)
            
    @objc_method
    def onRefreshControl_(self, refreshControl : ObjCInstance) -> None:
        if ElectrumGui.gui is not None:
            ElectrumGui.gui.refresh_all()

    @objc_method
    def bindRefreshControl_(self, refreshControl: ObjCInstance) -> None:
        if (refreshControl is not None
            and refreshControl.actionsForTarget_forControlEvent_(self, UIControlEventValueChanged) is None):
            refreshControl.addTarget_action_forControlEvents_(self,SEL('onRefreshControl:'), UIControlEventValueChanged)
            
    @objc_method
    def onModalClose_(self,but) -> None:
        if ElectrumGui.gui is not None:
            ElectrumGui.gui.on_modal_close(but)
        
    @objc_method
    def navigationController_willShowViewController_animated_(self, nav, vc, anim : bool) -> None:
        is_hidden = True if len(nav.viewControllers) and vc.ptr.value != nav.viewControllers[0].ptr.value else False
        #print("SetToolBarHidden=%s"%str(is_hidden))
        nav.setToolbarHidden_animated_(is_hidden, True)
    

# Manages the GUI. Part of the ElectronCash API so you can't rename this class easily.
class ElectrumGui(PrintError):

    gui = None

    def __init__(self, config, daemon, plugins):
        ElectrumGui.gui = self
        self.appName = 'Electron-Cash'
        self.appDomain = 'com.c3-soft.ElectronCash'
        self.set_language()

        #todo: support multiple wallets in 1 UI?
        self.config = config
        self.daemon = daemon
        self.plugins = plugins
        self.wallet = None
        self.window = None
        self.tabController = None
        self.historyNav = None
        self.historyVC = None
        self.sendVC = None
        self.sendNav = None
        self.receiveVC = None
        self.receiveNav = None
        self.addressesNav = None
        self.addressesVC = None
        self.prefsVC = None
        self.prefsNav = None
        
        self.decimal_point = config.get('decimal_point', 5)
        self.fee_unit = config.get('fee_unit', 0)
        self.num_zeros     = self.prefs_get_num_zeros()
        self.alias_info = None # TODO: IMPLEMENT alias stuff
        
        Address.show_cashaddr(self.prefs_get_use_cashaddr())

        self.history = []
        self.tx_notifications = []
        self.helper = None
        self.helperTimer = None
        self.lowMemoryToken = None
        self.downloadingNotif = None
        self.downloadingNotif_view = None
        
        self.window = UIWindow.alloc().initWithFrame_(UIScreen.mainScreen.bounds)
        NSBundle.mainBundle.loadNibNamed_owner_options_("Splash2",self.window,None)        
        self.window.makeKeyAndVisible()
        utils.NSLog("GUI instance creted, splash screen 2 presented")

    def createAndShowUI(self):
        self.helper = GuiHelper.alloc().init()
        
        self.tabController = MyTabBarController.alloc().init().autorelease()

        self.historyVC = tbl = history.HistoryTableVC.alloc().initWithStyle_(UITableViewStylePlain).autorelease()
        self.helper.bindRefreshControl_(self.historyVC.refreshControl)

        self.sendVC = snd = send.SendVC.alloc().init().autorelease()
        
        self.receiveVC = rcv = receive.ReceiveVC.alloc().init().autorelease()
        
        self.addressesVC = adr = addresses.AddressesTableVC.alloc().initWithStyle_(UITableViewStylePlain).autorelease()
        self.helper.bindRefreshControl_(self.addressesVC.refreshControl)
        
        self.historyNav = nav = UINavigationController.alloc().initWithRootViewController_(tbl).autorelease()

        self.sendNav = nav2 = UINavigationController.alloc().initWithRootViewController_(snd).autorelease()
        self.receiveNav = nav3 = UINavigationController.alloc().initWithRootViewController_(rcv).autorelease()
        self.addressesNav = nav4 = UINavigationController.alloc().initWithRootViewController_(adr).autorelease()

        self.tabController.viewControllers = [nav, nav2, nav3, nav4]
        tabitems = self.tabController.tabBar.items
        tabitems[0].image = UIImage.imageNamed_("tab_history.png").imageWithRenderingMode_(UIImageRenderingModeAlwaysOriginal)
        tabitems[1].image = UIImage.imageNamed_("tab_send.png").imageWithRenderingMode_(UIImageRenderingModeAlwaysOriginal)
        tabitems[2].image = UIImage.imageNamed_("tab_receive.png").imageWithRenderingMode_(UIImageRenderingModeAlwaysOriginal)
        tabitems[3].image = UIImage.imageNamed_("tab_addresses.png").imageWithRenderingMode_(UIImageRenderingModeAlwaysOriginal)


        self.setup_toolbar()
        
        self.prefsVC = prefs.PrefsVC.new()
        self.prefsNav = UINavigationController.alloc().initWithRootViewController_(self.prefsVC)
        self.add_navigation_bar_close_to_modal_vc(self.prefsVC)

        self.register_network_callbacks()

        tbl.refresh()
        
        self.helper.needUpdate()

        self.lowMemoryToken = NSNotificationCenter.defaultCenter.addObserverForName_object_queue_usingBlock_(
            UIApplicationDidReceiveMemoryWarningNotification,
            UIApplication.sharedApplication,
            None,
            Block(lambda: self.on_low_memory(), restype=None)
        ).retain()

        self.window.backgroundColor = UIColor.whiteColor
        self.window.rootViewController = self.tabController

        self.window.makeKeyAndVisible()                 
             
        utils.NSLog("UI Created Ok")

        return True
    
    def register_network_callbacks(self):
        # network callbacks
        if self.daemon.network:
            self.daemon.network.register_callback(self.on_history, ['on_history'])
            self.daemon.network.register_callback(self.on_quotes, ['on_quotes'])
            interests = ['updated', 'new_transaction', 'status',
                         'banner', 'verified', 'fee']
            # To avoid leaking references to "self" that prevent the
            # window from being GC-ed when closed, callbacks should be
            # methods of this class only, and specifically not be
            # partials, lambdas or methods of subobjects.  Hence...
            self.daemon.network.register_callback(self.on_network, interests)
            utils.NSLog("REGISTERED NETWORK CALLBACKS")

    def unregister_network_callbacks(self):
        if self.daemon and self.daemon.network:
            self.daemon.network.unregister_callback(self.on_history)
            self.daemon.network.unregister_callback(self.on_quotes)
            self.daemon.network.unregister_callback(self.on_network)
            utils.NSLog("UN-REGISTERED NETWORK CALLBACKS")
    
    def setup_toolbar(self):
        butsStatusLabel = []
        butsStatus = []
        butsPasswd = []
        butsSeed = []
        butsCashaddr = []
        butsPrefs = []
        for nav in self.tabController.viewControllers:
            itemsThisNav = []
            # status label
            l = UILabel.alloc().initWithFrame_(CGRectMake(0,0,UIScreen.mainScreen.bounds.size.width-100,50)).autorelease()
            l.text = "Electron Cash..."
            l.adjustsFontSizeToFitWidth = True
            l.numberOfLines=0
            l.sizeToFit()
            b = UIBarButtonItem.alloc().initWithCustomView_(l).autorelease()
            b.tag = 0

            butsStatusLabel.append(b)
            itemsThisNav.append(b)
            
            # spacer
            b = UIBarButtonItem.alloc().initWithBarButtonSystemItem_target_action_(UIBarButtonSystemItemFlexibleSpace, None, None)
            b.tag = 1
            itemsThisNav.append(b)

            # Locked/Unlocked icon
            b = UIBarButtonItem.alloc().initWithImage_style_target_action_(UIImage.imageNamed_("unlock.png").imageWithRenderingMode_(UIImageRenderingModeAlwaysOriginal),
                                                                           UIBarButtonItemStylePlain,
                                                                           self.helper,
                                                                           SEL(b'onToolButton:'))
            b.tag = TAG_PASSWD
            butsPasswd.append(b)
            itemsThisNav.append(b)

            # Cashaddr icon
            b = UIBarButtonItem.alloc().initWithImage_style_target_action_(self.cashaddr_icon(),
                                                                           UIBarButtonItemStylePlain,
                                                                           self.helper,
                                                                           SEL(b'onToolButton:'))
            b.tag = TAG_CASHADDR
            butsCashaddr.append(b)
            itemsThisNav.append(b)


            # Seed icon
            b = UIBarButtonItem.alloc().initWithImage_style_target_action_(UIImage.imageNamed_("seed.png").imageWithRenderingMode_(UIImageRenderingModeAlwaysOriginal),
                                                                           UIBarButtonItemStylePlain,
                                                                           self.helper,
                                                                           SEL(b'onToolButton:'))
            b.tag = TAG_SEED
            butsSeed.append(b)
            itemsThisNav.append(b)

            # Prefs icon
            b = UIBarButtonItem.alloc().initWithImage_style_target_action_(UIImage.imageNamed_("preferences.png").imageWithRenderingMode_(UIImageRenderingModeAlwaysOriginal),
                                                                           UIBarButtonItemStylePlain,
                                                                           self.helper,
                                                                           SEL(b'onToolButton:'))
            b.tag = TAG_PREFS
            butsPrefs.append(b)
            itemsThisNav.append(b)
            
            # status/network icon
            b = UIBarButtonItem.alloc().initWithImage_style_target_action_(UIImage.imageNamed_("status_disconnected.png").imageWithRenderingMode_(UIImageRenderingModeAlwaysOriginal),
                                                                           UIBarButtonItemStylePlain,
                                                                           self.helper,
                                                                           SEL(b'onToolButton:'))
            b.tag = TAG_NETWORK
            butsStatus.append(b)
            itemsThisNav.append(b)
            
            root = nav.viewControllers[0] # get root viewcontroller
            itemsThisNav.sort(key=lambda x: x.tag)
            root.setToolbarItems_animated_(itemsThisNav, True)
            nav.setToolbarHidden_animated_(False, True)
            # below two cause problems because of our 'persistent toolbar', so disable
            #nav.hidesBarsWhenKeyboardAppears = True
            #nav.hidesBarsWhenVerticallyCompact = True
            nav.delegate = self.helper
        self.helper.butsStatusLabel = butsStatusLabel
        self.helper.butsStatus = butsStatus
        self.helper.butsPasswd = butsPasswd
        self.helper.butsSeed = butsSeed
        self.helper.butsCashaddr = butsCashaddr
        self.helper.butsPrefs = butsPrefs
    
    def setup_downloading_notif(self):
        if self.downloadingNotif is not None: return
        self.downloadingNotif = CWStatusBarNotification.new()
        def OnTap() -> None:
            self.query_hide_downloading_notif()
            pass
        # NB: if I change the type it crashes sometimes on app startup due to bugs in this control.. perhaps? 
        self.downloadingNotif.notificationAnimationType = CWNotificationAnimationTypeOverlay
        self.downloadingNotif.notificationTappedBlock = OnTap
        if self.downloadingNotif_view is None:
            objs = NSBundle.mainBundle.loadNibNamed_owner_options_("ActivityStatusNotificationView",None,None)
            if objs is None or not len(objs):
                raise Exception("Could not load ActivityStatusNotificationView nib!")
            lbl = objs[0].viewWithTag_(2)
            if lbl is not None:
                lbl.text = _("Downloading blockchain headers...")
            activityIndicator = objs[0].viewWithTag_(1)
            if activityIndicator is not None:
                HelpfulGlue.affineScaleView_scaleX_scaleY_(activityIndicator, 0.5, 0.5)
            self.downloadingNotif_view = objs[0].retain()
    
    def __del__(self):
        utils.NSLog("GUI instance __del__")
        self.dispose()
          
    def dispose(self):
        if self.window is None:
            return
        self.stop_daemon()
        if self.lowMemoryToken is not None:
            NSNotificationCenter.defaultCenter.removeObserver_(self.lowMemoryToken.autorelease())
            self.lowMemoryToken = None
        if self.downloadingNotif is not None:
            self.dismiss_downloading_notif()
        if self.downloadingNotif_view is not None:
            self.downloadingNotif_view.autorelease()
            self.downloadingNotif_view = None
        if self.prefsVC is not None: self.prefsVC.autorelease()
        if self.prefsNav is not None: self.prefsNav.autorelease()
        self.prefsVC = None
        self.prefsNav = None
        if self.helperTimer is not None:
            self.helperTimer.invalidate()
            self.helperTimer = None
        if self.tabController is not None: 
            self.tabController.viewControllers = None
        self.historyNav = None
        self.historyVC = None
        self.sendNav = None
        self.sendVC = None
        self.receiveVC = None
        self.receiveNav = None
        self.addressesNav = None
        self.addressesVC = None
        self.window.rootViewController = None
        self.tabController = None
        self.window.release()
        self.window = None
        if self.helper is not None: self.helper.release()
        self.helper = None
    
    def on_rotated(self): # called by PythonAppDelegate after screen rotation
        #update status bar label width
        if self.helper is None or self.helper.butsStatusLabel is None: return 
        size = UIScreen.mainScreen.bounds.size
        buts = self.helper.butsStatusLabel
        for b in buts:
            f = b.customView.frame
            if size.width < size.height:
                f.size.width = size.width/2 - 30
            else:
                f.size.width = size.width / 2
            b.customView.frame = f
            #b.customView.sizeToFit()
        
        # on rotation sometimes the notif gets messed up.. so re-create it
        #if self.downloadingNotif is not None and self.is_downloading_notif_showing() and self.downloadingNotif_view is not None:
        #    self.dismiss_downloading_notif()
        #    self.show_downloading_notif()

    
    def init_network(self):
        # Show network dialog if config does not exist
        if self.daemon.network:
            if self.config.get('auto_connect') is None:
                #wizard = InstallWizard(self.config, self.app, self.plugins, None)
                #wizard.init_network(self.daemon.network)
                #wizard.terminate()
                print("NEED TO SHOW WIZARD HERE")
                pass
            
    def on_history(self, b):
        utils.NSLog("ON HISTORY (IsMainThread: %s)",str(NSThread.currentThread.isMainThread))
        assert self.historyVC is not None
        self.historyVC.needUpdate()
        self.helper.needUpdate()
        
    def on_quotes(self, event, *args):
        utils.NSLog("ON QUOTES (IsMainThread: %s)",str(NSThread.currentThread.isMainThread))        
        self.historyVC.needUpdate()
        self.addressesVC.needUpdate()
        self.helper.needUpdate()
            
    def on_network(self, event, *args):
        utils.NSLog("ON NETWORK: %s (IsMainThread: %s)",event,str(NSThread.currentThread.isMainThread))
        if not self.daemon:
            utils.NSLog("(Returning early.. daemon stopped)")
            return
        assert self.historyVC is not None
        if event == 'updated':
            self.helper.needUpdate()
        elif event == 'new_transaction':
            self.historyVC.needUpdate() #enqueue update to main thread
            self.addressesVC.needUpdate() #enqueue update to main thread
            self.tx_notifications.append(args[0])
            self.helper.needUpdate()
        elif event == 'banner':
            #todo: handle console stuff here
            pass
        elif event == 'status':
            #todo: handle status update here
            self.helper.needUpdate()
        elif event in ['verified']:
            self.historyVC.needUpdate() #enqueue update to main thread
            self.addressesVC.needUpdate()
            self.helper.needUpdate()
        elif event == 'fee':
            # todo: handle fee stuff here
            pass
        else:
            self.print_error("unexpected network message:", event, args)

    def show_downloading_notif(self, txt = None):
        if self.prefs_get_downloading_notif_hidden():
            return
        if self.downloadingNotif is None:
            self.setup_downloading_notif()

        if txt is not None and type(txt) is str:
            lbl = self.downloadingNotif_view.viewWithTag_(2)
            if lbl is not None: lbl.text = txt

        if self.is_downloading_notif_showing():
            return

        def Completion() -> None:
            #print ("Show completion")
            pass
        self.downloadingNotif_view.removeFromSuperview()
        self.downloadingNotif.displayNotificationWithView_completion_(
            self.downloadingNotif_view,
            Completion
        )
        
    def is_downloading_notif_showing(self):
        return (self.downloadingNotif.notificationIsShowing and
                not self.downloadingNotif.notificationIsDismissing)
            
    def dismiss_downloading_notif(self):
        if self.downloadingNotif is None: return
        if not self.is_downloading_notif_showing(): return
        dnf = self.downloadingNotif
        self.downloadingNotif = None
        def compl() -> None:
            #print("Dismiss completion")
            if (self.downloadingNotif_view is not None
                and dnf.customView is not None
                and self.downloadingNotif_view.isDescendantOfView_(dnf.customView)):
                self.downloadingNotif_view.removeFromSuperview()
            dnf.release()
        dnf.dismissNotificationWithCompletion_(compl)
            
    def on_status_update(self):
        utils.NSLog("ON STATUS UPDATE (IsMainThread: %s)",str(NSThread.currentThread.isMainThread))
        show_dl_pct = None
        
        if not self.wallet or not self.daemon:
            utils.NSLog("(Returning early.. wallet and/or daemon stopped)")
            return

        if self.daemon.network is None or not self.daemon.network.is_running():
            text = _("Offline")
            icon = "status_disconnected.png"

        elif self.daemon.network.is_connected():
            server_height = self.daemon.network.get_server_height()
            server_lag = self.daemon.network.get_local_height() - server_height
            # Server height can be 0 after switching to a new server
            # until we get a headers subscription request response.
            # Display the synchronizing message in that case.
            if not self.wallet.up_to_date or server_height == 0:
                text = _("Synchronizing...")
                icon = "status_waiting.png"
            elif server_lag > 1:
                text = _("Server is lagging ({} blocks)").format(server_lag)
                icon = "status_lagging.png"
            else:
                c, u, x = self.wallet.get_balance()
                text =  _("Balance" ) + ": %s "%(self.format_amount_and_units(c))
                if u:
                    text +=  " [%s unconfirmed]"%(self.format_amount(u, True).strip())
                if x:
                    text +=  " [%s unmatured]"%(self.format_amount(x, True).strip())

                # append fiat balance and price
                if self.daemon.fx.is_enabled():
                    text += self.daemon.fx.get_fiat_status_text(c + u + x,
                        self.base_unit(), self.get_decimal_point()) or ''
                if not self.daemon.network.proxy:
                    icon = "status_connected.png"
                else:
                    icon = "status_connected_proxy.png"
            
            lh, sh = self.daemon.network.get_status_value('updated')        
            '''utils.NSLog("lh=%d sh=%d is_up_to_date=%d Wallet Network is_up_to_date=%d is_connecting=%d is_connected=%d",
                        int(lh), int(sh),
                        int(self.wallet.up_to_date),
                        int(self.daemon.network.is_up_to_date()),
                        int(self.daemon.network.is_connecting()),
                        int(self.daemon.network.is_connected()))
            '''
            if lh is not None and sh is not None and lh >= 0 and sh > 0 and lh < sh:
                show_dl_pct = int((lh*100.0)/float(sh))
                
        else:
            text = _("Not connected")
            icon = "status_disconnected.png"

        #self.tray.setToolTip("%s (%s)" % (text, self.wallet.basename()))
        #self.balance_label.setText(text)
        #self.status_button.setIcon( icon )
        lbls = self.helper.butsStatusLabel
        buts = self.helper.butsStatus
        for l in lbls:
            l.customView.text = text
        img = UIImage.imageNamed_(icon).imageWithRenderingMode_(UIImageRenderingModeAlwaysOriginal)
        for b in buts:
            b.setImage_(img)
            
        self.update_lock_icon()
        self.update_buttons_on_seed()
        
        if len(self.tx_notifications):
            self.notify_transactions()
            
        if show_dl_pct is not None and self.tabController.didLayout:
            self.show_downloading_notif(_("Downloading headers {}% ...").format(show_dl_pct) if show_dl_pct > 0 else None)
        else:
            self.dismiss_downloading_notif()
            
    def notify_transactions(self):
        if not self.daemon.network or not self.daemon.network.is_connected():
            return
        self.print_error("Notifying GUI")
        if len(self.tx_notifications) > 0:
            # Combine the transactions if there are at least 2
            num_txns = len(self.tx_notifications)
            if num_txns >= 2:
                total_amount = 0
                for tx in self.tx_notifications:
                    is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(tx)
                    if v > 0:
                        total_amount += v
                self.notify(_("{} new transactions received: Total amount received in the new transactions {}")
                            .format(num_txns, self.format_amount_and_units(total_amount)))
                self.tx_notifications = []
            else:
                for tx in self.tx_notifications:
                    if tx:
                        self.tx_notifications.remove(tx)
                        is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(tx)
                        if v > 0:
                            self.notify(_("New transaction received: {}").format(self.format_amount_and_units(v)))

    def notify(self, message):
        lines = message.split(': ')
        utils.show_notification(message=':\n'.join(lines),
                                duration=10.0,
                                color=(0.0, .5, .25, 1.0), # green
                                style=CWNotificationStyleNavigationBarNotification,
                                multiline=bool(len(lines)))
        
    def query_hide_downloading_notif(self):
        vc = self.tabController if self.tabController.presentedViewController is None else self.tabController.presentedViewController
        utils.show_alert(vc = vc,
                         title = _("Hide Download Banner"),
                         message = _("Do you wish to hide the download progress banner?\n(You can re-enabled it in Settings later)"),
                         actions= [
                            [ _('Yes'), self.prefs_set_downloading_notif_hidden, True],
                            [ _('No') ],
                            ],
                         cancel = _('No')
                        )
        
        
    def update_lock_icon(self):
        img = UIImage.imageNamed_("lock.png" if self.wallet.has_password() else "unlock.png").imageWithRenderingMode_(UIImageRenderingModeAlwaysOriginal)
        buts = self.helper.butsPasswd
        for b in buts:
            b.setImage_(img)
        

    def update_buttons_on_seed(self):
        def removeBut(but,vcidx):
            nav = self.tabController.viewControllers[vcidx]
            root = nav.viewControllers[0]
            itemsThisNav = root.toolbarItems
            itemsThisNav = [x for x in itemsThisNav if x.tag != but.tag]
            root.setToolbarItems_animated_(itemsThisNav, True)
        def addBut(but,vcidx):
            nav = self.tabController.viewControllers[vcidx]
            root = nav.viewControllers[0]
            itemsThisNav = root.toolbarItems
            if but not in itemsThisNav:
                itemsThisNav.insert(but.tag,but)
                root.setToolbarItems_animated_(itemsThisNav, True)

        buts = self.helper.butsSeed
        for i,b in enumerate(buts):
            b.enabled = self.wallet.has_seed()
            if not b.isEnabled():
                removeBut(b,i)
            else:
                addBut(b,i)
        buts = self.helper.butsPasswd
        for i,b in enumerate(buts):
            b.enabled = self.wallet.can_change_password()
            if not b.isEnabled():
                removeBut(b,i)
            else:
                addBut(b,i)
        # todo -- register all send buttons here?
        buts = self.helper.butsSend
        for i,b in enumerate(buts): # todo: implement send button tracking?
            b.enabled = not self.wallet.is_watching_only()
 
    def on_tool_button(self, but : ObjCInstance) -> None:
        if but.tag == TAG_NETWORK: # status button
            print("Network status button pushed.. TODO, implement...")
            utils.show_timed_alert(self.tabController,"UNIMPLEMENTED", "Network setup dialog unimplemented -- coming soon!", 2.0)
        elif but.tag == TAG_PASSWD:
            print("Password lock button pushed.. TODO, implement...")
            utils.show_timed_alert(self.tabController,"UNIMPLEMENTED", "Password/lock dialog unimplemented -- coming soon!", 2.0)
        elif but.tag == TAG_SEED:
            print("Seed button pushed.. TODO, implement...")
            utils.show_timed_alert(self.tabController,"UNIMPLEMENTED", "Seed dialog unimplemented -- coming soon!", 2.0)
        elif but.tag == TAG_PREFS:
            print("Prefs button pushed")
            # for iOS8.0+ API which uses Blocks, but rubicon blocks seem buggy so we must do this
            self.tabController.presentViewController_animated_completion_(self.prefsNav, True, None)
        elif but.tag == TAG_CASHADDR:
            print("CashAddr button pushed.. TODO, implement fully...")
            self.toggle_cashaddr_status_bar()
        else:
            print("Unknown button pushed, tag=%d"%int(but.tag))
            
    def on_modal_close(self, but : ObjCInstance) -> None:
        title = "UNKNOWN View Controller"
        try: 
            presented = self.tabController.presentedViewController
            title = py_from_ns(presented.visibleViewController.title)
        except:
            pass
        self.tabController.dismissViewControllerAnimated_completion_(True, None)
        
    def add_navigation_bar_close_to_modal_vc(self, vc : ObjCInstance) -> ObjCInstance:
        closeButton = UIBarButtonItem.alloc().initWithBarButtonSystemItem_target_action_(UIBarButtonSystemItemStop, self.helper, SEL(b'onModalClose:')).autorelease()
        vc.navigationItem.rightBarButtonItem = closeButton
        return closeButton
        
        
    def cashaddr_icon(self):
        imgname = "addr_converter_bw.png"
        if self.prefs_get_use_cashaddr():
            imgname = "addr_converter.png"
        return UIImage.imageNamed_(imgname).imageWithRenderingMode_(UIImageRenderingModeAlwaysOriginal) 

    def update_cashaddr_icon(self):
        buts = self.helper.butsCashaddr
        img = self.cashaddr_icon()
        for b in buts:
            b.setImage_(img)

    def toggle_cashaddr_status_bar(self):
        self.toggle_cashaddr(not self.prefs_get_use_cashaddr())

    def toggle_cashaddr(self, on : bool) -> None:
        self.config.set_key('show_cashaddr', on)
        self.update_cashaddr_icon()
        Address.show_cashaddr(on)
        self.refresh_all()
                  
    def format_amount(self, x, is_diff=False, whitespaces=False):
        return format_satoshis(x, is_diff, self.num_zeros, self.decimal_point, whitespaces)

    def format_amount_and_units(self, amount, usenl=False):
        text = self.format_amount(amount) + ' '+ self.base_unit()
        x = self.daemon.fx.format_amount_and_units(amount)
        if text and x:
            text += "\n" if usenl else ''
            text += ' (%s)'%x
        return text

    def format_fee_rate(self, fee_rate):
        if self.fee_unit == 0:
            return '{:.2f} sats/byte'.format(fee_rate/1000)
        else:
            return self.format_amount(fee_rate) + ' ' + self.base_unit() + '/kB'

    def base_unit(self):
        assert self.decimal_point in [2, 5, 8]
        if self.decimal_point == 2:
            return 'bits'
        if self.decimal_point == 5:
            return 'mBCH'
        if self.decimal_point == 8:
            return 'BCH'
        raise Exception('Unknown base unit')

    def get_decimal_point(self):
        return self.decimal_point
   
    def on_label_edited(self, key, newvalue):
        self.wallet.set_label(key, newvalue)
        self.wallet.storage.write()
        self.historyVC.needUpdate()
        self.addressesVC.needUpdate()


    def set_language(self):
        langs = NSLocale.preferredLanguages
        if langs:
            l = langs[0].replace('-','_')
            if not languages.get(l):
                # iOS sometimes returns a mixed language_REGION code, so try and match it to what we have 
                pre1 = l.split('_')[0]
                for k in languages.keys():
                    pre2 = k.split('_')[0]
                    if pre1 == pre2:
                        print("OS language is '%s', but we are guessing this matches our language code '%s'"%(l, k))
                        l = k
                        break
            print ("Setting language to {}".format(l))
            set_language(l)
            
    def prefs_set_downloading_notif_hidden(self, b : bool) -> None:
        was = self.prefs_get_downloading_notif_hidden()
        if b == was: return
        if b: self.dismiss_downloading_notif()
        self.config.set_key('hide_downloading_banner', bool(b))
        self.prefsVC.refresh()
        self.on_status_update()
    
    def prefs_get_downloading_notif_hidden(self) -> bool:
        return self.config.get('hide_downloading_banner', False)
        
    def prefs_get_show_fee(self) -> bool:
        return self.config.get('show_fee', True)
    
    def prefs_set_show_fee(self, b : bool) -> None:
        self.config.set_key('show_fee', bool(b))
        
    def prefs_get_max_fee_rate(self) -> float:
        return  float(format_satoshis_plain(self.config.max_fee_rate(), self.decimal_point))

    def prefs_set_max_fee_rate(self, r) -> float:
        amt = self.validate_amount(r)
        if amt is not None:
            self.config.set_key('max_fee_rate', amt)
        return self.prefs_get_max_fee_rate()
    
    def prefs_get_confirmed_only(self) -> bool:
        return bool(self.config.get('confirmed_only', False))
    
    def prefs_set_confirmed_only(self, b : bool) -> None:
        self.config.set_key('confirmed_only', bool(b))
        
    def prefs_get_use_change(self) -> tuple: # returns the setting plus a second bool that indicates whether this setting can be modified
        r1 = self.wallet.use_change
        r2 = self.config.is_modifiable('use_change')
        return r1, r2

    def prefs_set_use_change(self, x : bool) -> None:
        usechange_result = bool(x)
        if self.wallet.use_change != usechange_result:
            self.wallet.use_change = usechange_result
            self.wallet.storage.put('use_change', self.wallet.use_change)        
   
    def prefs_get_multiple_change(self) -> list:
        multiple_change = self.wallet.multiple_change
        enabled = self.wallet.use_change
        return multiple_change, enabled

    def prefs_set_multiple_change(self, x : bool) -> None:
        multiple = bool(x)
        if self.wallet.multiple_change != multiple:
            self.wallet.multiple_change = multiple
            self.wallet.storage.put('multiple_change', multiple)
    
    def prefs_get_use_cashaddr(self) -> bool:
        return bool(self.config.get('show_cashaddr', True))
    
    def prefs_set_decimal_point(self, dec: int) -> None:
        if dec in [2, 5, 8]:
            if dec == self.decimal_point:
                return
            self.decimal_point = dec
            self.config.set_key('decimal_point', self.decimal_point, True)
            self.refresh_all()
            print("Decimal point set to: %d"%dec)
        else:
            raise ValueError('Passed-in decimal point %s is not one of [2,5,8]'%str(dec))
        
    def prefs_get_num_zeros(self) -> int:
        return int(self.config.get('num_zeros', 2))
        
    def prefs_set_num_zeros(self, nz : int) -> None:
        value = int(nz)
        if self.num_zeros != value:
            self.num_zeros = value
            self.config.set_key('num_zeros', value, True)
            self.refresh_all()
            
    def view_on_block_explorer(self, item : str, which : str) -> None:
        which = which if which in ['tx', 'addr'] else None
        assert which is not None and item is not None
        url = web.BE_URL(self.config, which, item)
        if UIApplication.sharedApplication.respondsToSelector_(SEL(b'openURL:options:completionHandler:')):
            UIApplication.sharedApplication.openURL_options_completionHandler_(NSURL.URLWithString_(url),{},None)
        else:
            UIApplication.sharedApplication.openURL_(NSURL.URLWithString_(url))

    def validate_amount(self, text):
        try:
            x = Decimal(str(text))
        except:
            return None
        p = pow(10, self.decimal_point)
        return int( p * x ) if x > 0 else None
    
    def get_presented_viewcontroller(self) -> ObjCInstance:
        return self.tabController if self.tabController.presentedViewController is None else self.tabController.presentedViewController
    
    def get_current_nav_controller(self) -> ObjCInstance:
        return self.tabController.selectedViewController
    
    # can be called from any thread, always runs in main thread
    def show_error(self, message, title = _("Error"), onOk = None):
        return self.show_message(message, title, onOk)
    # can be called from any thread, always runs in main thread
    def show_message(self, message, title = _("Information"), onOk = None):
        def func() -> None:
            vc = self.get_presented_viewcontroller() 
            actions = [ [_('OK')] ]
            if onOk is not None and callable(onOk): actions[0].append(onOk)
            utils.show_alert(
                vc = vc,
                title = title,
                message = message,
                actions = actions
            )
        return utils.do_in_main_thread(func)

    def on_pr(self, request):
        #self.payment_request = request
        #if self.payment_request.verify(self.contacts):
        #    self.payment_request_ok_signal.emit()
        #else:
        #    self.payment_request_error_signal.emit()
        utils.NSLog("On PR: %s -- UNIMPLEMENTED.. IMPLEMENT ME!",str(request))
    
    def sign_payment_request(self, addr):
        ''' No-op for now -- needs to be IMPLEMENTED -- requires the alias functionality '''
        assert isinstance(addr, Address)
        alias = self.config.get('alias')
        alias_privkey = None
        if alias and self.alias_info:
            alias_addr, alias_name, validated = self.alias_info
            if alias_addr:
                if self.wallet.is_mine(alias_addr):
                    msg = _('This payment request will be signed.') + '\n' + _('Please enter your password')
                    password = self.password_dialog(msg)
                    if password:
                        try:
                            self.wallet.sign_payment_request(addr, alias, alias_addr, password)
                        except Exception as e:
                            self.show_error(str(e))
                            return
                    else:
                        return
                else:
                    return

      
    def show_send_tab(self):
        vcs = self.tabController.viewControllers
        for i,vc in enumerate(vcs):
            if vc.ptr.value == self.sendVC.ptr.value:
                if self.tabController.selectedIndex != i: self.tabController.selectedIndex = i
                return

    def pay_to_URI(self, URI, errFunc : callable = None):
        utils.NSLog("PayTo URI: %s", str(URI))
        if not URI:
            return
        try:
            out = web.parse_URI(URI, self.on_pr)
        except Exception as e:
            if not callable(errFunc):
                self.show_error(_('Invalid bitcoincash URI:') + '\n' + str(e))
            else:
                errFunc()
            return
        self.show_send_tab()
        r = out.get('r')
        sig = out.get('sig')
        name = out.get('name')
        if r or (name and sig):
            #self.prepare_for_payment_request()
            print("TODO: prepare_for_payment_request")
            return
        address = out.get('address')
        amount = out.get('amount')
        label = out.get('label')
        message = out.get('message')
        # use label as description (not BIP21 compliant)
        self.sendVC.onPayTo_message_amount_(address,message,amount)
    
    def refresh_all(self):
        self.refresh_components('*')
        
    def refresh_components(self, *args) -> None:
        if not args: args = ['*']
        components = set(map(lambda x: str(x).strip().lower(),args))
        al = {'*','all','world','everything'}
        if components & {'helper', *al}:
            self.helper.needUpdate()
        if components & {'history', *al}:
            self.historyVC.needUpdate()
        if components & {'address', 'addresses', *al}:
            self.addressesVC.needUpdate()
        if components & {'prefs', 'preferences', 'settings', *al}:
            self.prefsVC.refresh()
        if components & {'receive', 'paymentrequests', 'pr', *al}:
            self.receiveVC.refresh()
                

    def on_new_daemon(self):
        self.daemon.gui = self
        self.open_last_wallet()
        self.register_network_callbacks()
        self.refresh_all()
        
    def on_low_memory(self) -> None:
        utils.NSLog("GUI: Low memory")
        if self.downloadingNotif_view is not None and self.downloadingNotif is None:
            self.downloadingNotif_view.release()
            self.downloadingNotif_view = None
            utils.NSLog("Released cached 'downloading notification banner view' due to low memory")
        
    def stop_daemon(self):
        if not self.daemon_is_running(): return
        self.unregister_network_callbacks()
        self.daemon.stop_wallet(self.wallet.storage.path)
        self.daemon.stop()
        self.wallet = None
        self.daemon = None
        
    def start_daemon(self):
        if self.daemon_is_running(): return
        import electroncash.daemon as ed
        fd, server = ed.get_fd_or_server(self.config)
        self.daemon = ed.Daemon(self.config, fd, True)
        self.daemon.start()
        self.on_new_daemon()

    def daemon_is_running(self) -> bool:
        return self.daemon is not None and self.daemon.is_running()

    def open_last_wallet(self):
        self.config.open_last_wallet()
        path = self.config.get_wallet_path()


        # hard code some stuff for testing
        self.daemon.network.auto_connect = True
        self.config.set_key('auto_connect', self.daemon.network.auto_connect, True)
        print("WALLET PATH: %s"%path)
        #print ("NETWORK: %s"%str(self.daemon.network))
        w = self.do_wallet_stuff(path, self.config.get('url'))
        assert w
        # TODO: put this stuff in the UI
        self.wallet = w

    @staticmethod
    def prompt_password(prmpt, dummy=0):
        print("prompt_password(%s,%s) thread=%s mainThread?=%s"%(prmpt,str(dummy),NSThread.currentThread.description,str(NSThread.currentThread.isMainThread)))
        return "bchbch"
    
    def password_dialog(self, msg) -> str:
        print("PASSWORD_DIALOG UNIMPLEMTNED. TODO: IMPLEMENT ME!!")
        return ElectrumGui.prompt_password(msg)

    def generate_wallet(self, path):
        with open(path, "wb") as fdesc:
            fdesc.write(hardcoded_testing_wallet)
            fdesc.close()
            print("Generated hard-coded wallet -- wrote %d bytes"%len(hardcoded_testing_wallet))
        storage = WalletStorage(path, manual_upgrades=True)
        if not storage.file_exists():
            return
        if storage.is_encrypted():
            password = ElectrumGui.prompt_password("EnterPasswd",0)
            if not password:
                return
            storage.decrypt(password)
        if storage.requires_split():
            return
        if storage.requires_upgrade():
            return
        if storage.get_action():
            return
        wallet = Wallet(storage)
        return wallet

    def do_wallet_stuff(self, path, uri):
        try:
            wallet = self.daemon.load_wallet(path, ElectrumGui.prompt_password("PassPrompt1"))
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            return
        if not wallet:
            storage = WalletStorage(path, manual_upgrades=True)
            try:
                wallet = self.generate_wallet(path)
            except Exception as e:
                print_error('[do_wallet_stuff] Exception caught', e)
            if not wallet:
                print("NO WALLET!!!")
                return
            wallet.start_threads(self.daemon.network)
            self.daemon.add_wallet(wallet)
        #print("WALLET=%s synchronizer=%s"%(str(wallet),str(wallet.synchronizer)))
        return wallet

    def sign_tx_with_password(self, tx, callback, password):
        '''Sign the transaction in a separate thread.  When done, calls
        the callback with a success code of True or False.
        '''
        # call hook to see if plugin needs gui interaction
        run_hook('sign_tx', self, tx)

        def on_error(exc_info):
            if not isinstance(exc_info[1], UserCancelled):
                traceback.print_exception(*exc_info)
                self.show_error(str(exc_info[1]))
        def on_signed(result):
            callback(True)
        def on_failed(exc_info):
            on_error(exc_info)
            callback(False)

        if False:#self.tx_external_keypairs:
            task = partial(Transaction.sign, tx, self.tx_external_keypairs)
        else:
            task = partial(self.wallet.sign_transaction, tx, password)
        utils.WaitingDialog(self.tabController, _('Signing transaction...'), task,
                            on_signed, on_failed)

    def broadcast_transaction(self, tx, tx_desc):
        def broadcast_thread(): # non-GUI thread
            #pr = self.payment_request
            #if pr and pr.has_expired():
            #    self.payment_request = None
            #    return False, _("Payment request has expired")
            status, msg =  self.daemon.network.broadcast(tx)
            #if pr and status is True:
            #    self.invoices.set_paid(pr, tx.txid())
            #    self.invoices.save()
            #    self.payment_request = None
            #    refund_address = self.wallet.get_receiving_addresses()[0]
            #    ack_status, ack_msg = pr.send_ack(str(tx), refund_address)
            #    if ack_status:
            #        msg = ack_msg
            return status, msg

        # Capture current TL window; override might be removed on return
        parent = self#.top_level_window()

        def broadcast_done(result):
            # GUI thread
            if result:
                status, msg = result
                if status:
                    if tx_desc is not None and tx.is_complete():
                        self.wallet.set_label(tx.txid(), tx_desc)
                    parent.show_message(_('Payment sent.') + '\n' + msg)
                    #self.invoice_list.update()
                    self.sendVC.clear()
                else:
                    parent.show_error(msg)
        def on_error(exc_info):
            if not isinstance(exc_info[1], UserCancelled):
                traceback.print_exception(*exc_info)
                self.show_error(str(exc_info[1]))

        utils.WaitingDialog(self.tabController, _('Broadcasting transaction...'),
                            broadcast_thread, broadcast_done, on_error)


    # this method is called by Electron Cash libs to start the GUI
    def main(self):
        import hashlib
        print("HashLib algorithms available: " + str(hashlib.algorithms_available))
        import platform
        print ("Platform %s uname: %s"%(platform.platform(),platform.uname()))
        print ("Bundle Identifier %s"% utils.bundle_identifier)

        try:
            self.init_network()
        except:
            traceback.print_exc(file=sys.stdout)
            return
        
        self.open_last_wallet()
        
        self.createAndShowUI()
