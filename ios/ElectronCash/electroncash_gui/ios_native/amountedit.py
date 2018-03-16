from electroncash.i18n import _
from .custom_objc import *
from .uikit_bindings import *
from . import utils
from . import gui

from decimal import Decimal
from electroncash.util import format_satoshis_plain, format_satoshis

def parent():
    return gui.ElectrumGui.gui

def config():
    return parent().config

# can use utils.register_callback() for this object.
# callbacks:
#   'textChanged' == func(amountEdit : BTCAmountEdit) -> None
#   'shortcut'    == func() -> None
#   'frozen'      == func() -> None
#   'edited'      == func(amountEdit : BTCAmountEdit) -> None

class BTCAmountEdit(UITextField):
    #frozen = pyqtSignal()
    #shortcut = pyqtSignal()
    isInt = objc_property()
    isShortcut = objc_property()
    modified = objc_property()

    @objc_method
    def init(self) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self is not None:
            self.commonInit()
        return self

    @objc_method
    def initWithCoder_(self, coder : ObjCInstance) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'initWithCoder:', coder.ptr, argtypes=[c_void_p]))
        if self is not None:
            self.commonInit()
        return self

    @objc_method
    def dealloc(self) -> None:
        # cleanup code here...
        self.isInt = None
        self.isShortcut = None
        self.modified = None
        utils.remove_all_callbacks(self)
        send_super(__class__, self, 'dealloc')

    @objc_method
    def baseUnit(self) -> ObjCInstance:
        return ns_from_py(parent().base_unit())

    @objc_method
    def decimalPoint(self) -> int:
        return parent().get_decimal_point()

    @objc_method
    def commonInit(self):
        # This seems sufficient for hundred-BTC amounts with 8 decimals
        #self.setFixedWidth(140)
        #self.base_unit = base_unit
        #self.textChanged.connect(self.numbify)
        self.addTarget_action_forControlEvents_(self, SEL(b'numbify'), UIControlEventEditingDidEnd)
        self.addTarget_action_forControlEvents_(self, SEL(b'edited'), UIControlEventEditingChanged)        
        self.isInt = False
        self.isShortcut = False
        self.modified = False
        #self.help_palette = QPalette()

    @objc_method
    def setFrozen_(self, b : bool) -> None:
        #self.setReadOnly(b)
        self.userInteractionEnabled = not b
        #self.setFrame(not b)
        self.alpha = 1.0 if b else 0.3
        utils.get_callback(self, 'frozen')()
        #self.frozen.emit()
        
    @objc_method
    def isFrozen(self) -> bool:
        return not self.userInteractionEnabled

    @objc_method
    def numbify(self):
        text = str(self.text).strip()
        #if text == '!':
        #    #self.shortcut.emit()
        #    utils.get_callback(self, 'shortcut')()
        #    return
        #pos = self.cursorPosition()
        chars = '0123456789'
        if not self.isInt: chars +='.'
        s = ''.join([i for i in text if i in chars])
        if not self.isInt:
            if '.' in s:
                p = s.find('.')
                s = s.replace('.','')
                s = s[:p] + '.' + s[p:p+self.decimalPoint()]
        self.text = s
        utils.get_callback(self, 'textChanged')(self)
        # setText sets Modified to False.  Instead we want to remember
        # if updates were because of user modification.
        #self.setModified(self.hasFocus())
        #self.setCursorPosition(pos)

    @objc_method
    def formatPlain_(self, amount : int) -> ObjCInstance:
        return ns_from_py(format_satoshis_plain(amount, self.decimalPoint()))
        #return ns_from_py(format_satoshis(amount, False, parent().num_zeros, self.decimalPoint()))
        
    @objc_method
    def isModified(self) -> bool:
        return self.modified

    @objc_method
    def edited(self) -> None:
        self.modified = True
        utils.get_callback(self, 'edited')(self)

    @objc_method
    def getAmount(self) -> ObjCInstance:
        try:
            x = Decimal(str(self.text))
        except:
            return None
        p = pow(10, self.decimalPoint())
        return ns_from_py( int( p * x ) ) if x > 0 else None

    @objc_method
    def setAmount_(self, amount : ObjCInstance) -> None:
        self.modified = False
        if amount is None:
            self.text = ""  # Text(" ") # Space forces repaint in case units changed
        else:
            self.text = self.formatPlain_(amount) 
        self.numbify()

class FiatAmountEdit(BTCAmountEdit):
    
    @objc_method
    def baseUnit(self) -> ObjCInstance:
        return ns_from_py(parent().daemon.fx.get_currency() if parent().daemon.fx.is_enabled() else "USD")
    
    @objc_method
    def decimalPoint(self) -> int:
        return 2  # fiat always has precision of 2

    @objc_method
    def formatPlain_(self, amount : int) -> ObjCInstance:
        return ns_from_py(format_satoshis(amount, False, 2, self.decimalPoint()))

class BTCkBEdit(BTCAmountEdit):
    @objc_method
    def baseUnit(self) -> ObjCInstance:
        bu = ObjCInstance(send_super(__class__, self, 'baseUnit'))
        return ns_from_py(py_from_ns(bu) + '/kB')
