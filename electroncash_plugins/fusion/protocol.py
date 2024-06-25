#!/usr/bin/env python3
#
# Electron Cash - a lightweight Bitcoin Cash client
# CashFusion - an advanced coin anonymizer
#
# Copyright (C) 2020 Mark B. Lundeberg
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
"""
Magic parameters for the protocol that need to be followed uniformly by
participants either for functionality or for privacy reasons. Unlike
flexible server params these do need to be fixed and implicitly shared.

Any time the values are changed, the version should be bumped to avoid
having loss of function, or theoretical privacy loss.
"""

from . import pedersen

# this class doesn't get instantiated, it's just a bag of values.
class Protocol:
    VERSION = b'alpha13'
    PEDERSEN = pedersen.PedersenSetup(b'\x02CashFusion gives us fungibility.')

    # 4-byte 'lokad' identifier at start of OP_RETURN
    FUSE_ID = b'FUZ\x00'

    # The server only enforces dust limits, but clients should not make outputs
    # smaller than this.
    MIN_OUTPUT = 10000

    # Covert connection timescales
    # don't let connection attempts take longer than this, since they need to be finished early enough that a spare can be tried.
    COVERT_CONNECT_TIMEOUT = 15.0
    # What timespan to make connections over
    COVERT_CONNECT_WINDOW = 15.0
    # likewise for submitted data (which is quite small), we don't want it going too late.
    COVERT_SUBMIT_TIMEOUT = 3.0
    # What timespan to make covert submissions over.
    COVERT_SUBMIT_WINDOW = 5.0

    COVERT_CONNECT_SPARES = 6 # how many spare connections to make

    MAX_CLOCK_DISCREPANCY = 5.0 # how much the server's time is allowed to differ from client

    ### Critical timeline ###
    # (For early phases in a round)
    # For client privacy, it is critical that covert submissions happen within
    # very specific windows so that they know the server is not able to pull
    # off a strong timing partition.

    # Parameters for the 'warmup period' during which clients attempt Tor connections.
    # It is long since Tor circuits can take a while to establish.
    WARMUP_TIME = 30. # time interval between fusionbegin and first startround message.
    WARMUP_SLOP = 3.  # allowed discrepancy in warmup interval, and in clock sync.

    # T_* are client times measured from receipt of startround message.
    # TS_* are server times measured from send of startround message.

    # The server expects all commitments by this time, so it can start uploading them.
    TS_EXPECTING_COMMITMENTS = +3.0

    # when to start submitting covert components; the BlindSigResponses must have been received by this time.
    T_START_COMPS = +5.0
    # submission nominally stops at +10.0, but could be lagged if timeout and spares need to be used.

    # the server will reject all components received after this time.
    TS_EXPECTING_COVERT_COMPONENTS = +15.0

    # At this point the server needs to generate the tx template and calculate
    # all sighashes in order to prepare for receiving signatures, and then send
    # ShareCovertComponents (a large message, may need time for clients to download).

    # when to start submitting signatures; the ShareCovertComponents must be received by this time.
    T_START_SIGS = +20.0
    # submission nominally stops at +25.0, but could be lagged if timeout and spares need to be used.

    # the server will reject all signatures received after this time.
    TS_EXPECTING_COVERT_SIGNATURES = +30.0

    # At this point the server assembles the tx and tries to broadcast it.
    # It then informs clients of success or fail.

    # After submitting sigs, clients expect to hear back a result by this time.
    T_EXPECTING_CONCLUSION = 35.0

    # When to start closing covert connections if .stop() is called. It is
    # likely the server has already closed, but client needs to do this just
    # in case.
    T_START_CLOSE = +45.0 # before conclusion
    T_START_CLOSE_BLAME = +80.0 # after conclusion, during blame phase.

    ### (End critical timeline) ###


    # For non-critical messages like during blame phase, just regular relative timeouts are needed.
    # Note that when clients send a result and expect a 'gathered' response from server, they wait
    # twice this long to allow for other slow clients.
    STANDARD_TIMEOUT = 3.
    # How much extra time to allow for a peer to check blames (this may involve querying blockchain).
    BLAME_VERIFY_TIME = 5.

    
    
    ###---------------
    fusion_beta = True
    ###---------------
    ### New 2024 Fusion Version Proposal.
    
    ### Development Version.  Set fusion_beta = True to activate.
    
    ### This can eventually be activated in mainline based on a timestamp condition so that there is
    ### plenty of time to roll out new client and server versions of the software.
    
    ### Note: This is an intentionally slower version of fusion to allow slow clients and TOR connections.
    ### The trade-off is slightly longer waiting under the optimal conditions while producing less failures overall.
    ### A total of 35 seconds is added to the entire timeline.
    
    ### What we are changing and why:
    ###
    # COVERT_CONNECT_TIMEOUT increased from 15 to 30 seconds to give more time to set up TOR connections.
    # COVERT_CONNECT_WINDOW remains at 15 seconds.  Keeping the window the same but increasing time allowance is desirable.
    # COVERT_SUBMIT_TIMEOUT increased from 3 seconds to 8 seconds in case TOR transmission is slow.
    # COVERT_SUBMIT_WINDOW remains at 5 seconds.  Keeping the window the same but increasing time allowance is desirable.
    # WARMUP_TIME increased from 30 seconds to 60 seconds to allow total connection setup more time including retries.
    # (note the ratio of COVERT_CONNECT_TIMEOUT to WARMUP_TIME remains at 1:2)
    # 
    # Timeline vars:
    #
    # TS_EXPECTING_COMMITMENTS increased from 3 seconds to 10 seconds. 3 seconds seemed way too short to send the commitments.
    # T_START_COMPS set to 20, thus allowing minimum of 10 seconds (instead of 2) to receive blind signature responses 
    # TS_EXPECTING_COVERT_COMPONENTS set to 40, thus allowing 20 seconds (rather than 10) for server to receive components.
    # T_START_SIGS set to 50, thus allowing 10 seconds (rather than 5) to receive components from server
    # TS_EXPECTING_COVERT_SIGNATURES set to 70, thus allowing 20 seconds (rather than 10) for server to get all signatures.
    # T_EXPECTING_CONCLUSION set to 80, thus allowing 10 seconds (rather than 5) for the server to respond after getting all signatures.
    # T_START_CLOSE and T_START_CLOSE changed to 90 and 115 respectively, but delta is unchanged; they still allow the same 10 seconds + 25 seconds.
    # ---end critical timeline
    # STANDARD_TIMEOUT doubled from 3 seconds to 6 seconds
    # BLAME_VERIFY_TIME doubled from 5 seconds to 10 seconds
    
    
    if (fusion_beta):
        VERSION = b'beta14'
        PEDERSEN = pedersen.PedersenSetup(b'\x02CashFusion gives us fungibility.')
     
        # 4-byte 'lokad' identifier at start of OP_RETURN
        FUSE_ID = b'FUZ\x00'

        # The server only enforces dust limits, but clients should not make outputs
        # smaller than this.
        MIN_OUTPUT = 10000

        # Covert connection timescales
        # don't let connection attempts take longer than this, since they need to be finished early enough that a spare can be tried.
        COVERT_CONNECT_TIMEOUT = 30.0
        # What timespan to make connections over
        COVERT_CONNECT_WINDOW = 15.0
        # likewise for submitted data (which is quite small), we don't want it going too late.
        COVERT_SUBMIT_TIMEOUT = 8.0
        # What timespan to make covert submissions over.
        COVERT_SUBMIT_WINDOW = 5.0

        COVERT_CONNECT_SPARES = 6 # how many spare connections to make

        MAX_CLOCK_DISCREPANCY = 5.0 # how much the server's time is allowed to differ from client

        ### Critical timeline ###
        # (For early phases in a round)
        # For client privacy, it is critical that covert submissions happen within
        # very specific windows so that they know the server is not able to pull
        # off a strong timing partition.

        # Parameters for the 'warmup period' during which clients attempt Tor connections.
        # It is long since Tor circuits can take a while to establish.
        WARMUP_TIME = 60. # time interval between fusionbegin and first startround message.
        WARMUP_SLOP = 3.  # allowed discrepancy in warmup interval, and in clock sync.

        # T_* are client times measured from receipt of startround message.
        # TS_* are server times measured from send of startround message.

        # The server expects all commitments by this time, so it can start uploading them.
        TS_EXPECTING_COMMITMENTS = +10.0

        # when to start submitting covert components; the BlindSigResponses must have been received by this time.
        T_START_COMPS = +20.0
        # submission nominally stops at +25.0, but could be lagged if timeout and spares need to be used.

        # the server will reject all components received after this time.
        TS_EXPECTING_COVERT_COMPONENTS = +40.0

        # At this point the server needs to generate the tx template and calculate
        # all sighashes in order to prepare for receiving signatures, and then send
        # ShareCovertComponents (a large message, may need time for clients to download).

        # when to start submitting signatures; the ShareCovertComponents must be received by this time.
        T_START_SIGS = +50.0
        # submission nominally stops at +55.0, but could be lagged if timeout and spares need to be used.

        # the server will reject all signatures received after this time.
        TS_EXPECTING_COVERT_SIGNATURES = +70.0

        # At this point the server assembles the tx and tries to broadcast it.
        # It then informs clients of success or fail.

        # After submitting sigs, clients expect to hear back a result by this time.
        T_EXPECTING_CONCLUSION = 80.0

        # When to start closing covert connections if .stop() is called. It is
        # likely the server has already closed, but client needs to do this just
        # in case.
        T_START_CLOSE = +90.0 # before conclusion
        T_START_CLOSE_BLAME = +115.0 # after conclusion, during blame phase.

        ### (End critical timeline) ###


        # For non-critical messages like during blame phase, just regular relative timeouts are needed.
        # Note that when clients send a result and expect a 'gathered' response from server, they wait
        # twice this long to allow for other slow clients.
        STANDARD_TIMEOUT = 6.
        # How much extra time to allow for a peer to check blames (this may involve querying blockchain).
        BLAME_VERIFY_TIME = 10.

del pedersen
