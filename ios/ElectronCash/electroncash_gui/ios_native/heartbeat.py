import sys
import time

try:
    from .uikit_bindings import *
except Exception as e:
    sys.exit("Error: Could not import iOS libs: %s"%str(e))


singleton = None

# This class implements a callback "tick" function invoked by the objective c
# CFRunLoop for this app.  This is necessary so the Python interpreter ends up executing
# its threads. Otherwise control exits the interpreter and never returns to it.
# It's a horrible hack but I can't otherwise figure out how to give the jsonrpc server
# timeslices and/or a chance to run.  If you can figure it out, let me know!
# -Calin
class HeartBeat(NSObject):
    funcs = objc_property()
    tickTimer = objc_property()

    @objc_method
    def init(self):
        self = ObjCInstance(send_super(__class__, self, 'init'))
        self.funcs = NSMutableArray.alloc().init().autorelease()
        self.tickTimer = None
        #print("Heartbeat: initted super ok!")
        return self

    @objc_method
    def dealloc(self) -> None:
        self.stop()
        self.funcs = None
        send_super(__class__, self, 'dealloc')

    @objc_method
    def tick_(self, t : ObjCInstance) -> None:
        if not NSThread.isMainThread:
            print("WARNING: HeartBeat Timer Tick is not in the process's main thread! FIXME!")
        en = self.funcs.objectEnumerator()
        inv = en.nextObject()
        while inv:
            inv.invoke()
            inv = en.nextObject()
        time.sleep(0.001) # give other python "threads" a chance to run..

    @objc_method
    def addCallback(self, target, selNameStr):
        inv = NSInvocation.invocationWithMethodSignature_(NSMethodSignature.signatureWithObjCTypes_(b'v@:'))
        inv.target = target
        inv.selector = SEL(selNameStr)
        self.funcs.addObject_(inv)


    @objc_method
    def removeCallback(self, target, selNameStr):
        en = self.funcs.objectEnumerator()
        inv = en.nextObject()
        while inv:
            if inv.selector.name == SEL(selNameStr).name and inv.target == target:
                break
            inv = en.nextObject()
        if inv:
            self.funcs.removeObjectIdenticalTo_(inv)

    @objc_method
    def start(self):
        
        def OnTimer(t : objc_id) -> None:
            self.tick_(ObjCInstance(t))
        
        self.stop()
        self.tickTimer = NSTimer.timerWithTimeInterval_repeats_block_(0.030, True, OnTimer)
        NSRunLoop.mainRunLoop().addTimer_forMode_(self.tickTimer, NSDefaultRunLoopMode)

    @objc_method
    def stop(self):
        try:
            if self.tickTimer is not None:
                self.tickTimer.invalidate()
                self.tickTimer = None
        except:
            pass

def Start():
    global singleton
    if singleton is None:
        singleton = HeartBeat.alloc().init()
        singleton.start()

def Stop():
    global singleton
    if singleton is not None:
        singleton.stop()
        singleton.autorelease()
        singleton = None
        
def IsRunning() -> bool:
    global singleton
    return bool(singleton is not None)
        
def Add(target, selNameStr):
    if singleton is None:
        Start()
    singleton.addCallback(target, selNameStr)

def Remove(target, selNameStr):
    if singleton is not None:
        singleton.removeCallback(target, selNameStr)
