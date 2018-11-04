from ..address import *

def testOpCodeValues():
    assert OpCodes.lookup.get("OP_CHECKDATASIG") == 0xba
    assert OpCodes.lookup.get("OP_CHECKDATASIGVERIFY") == 0xbb
