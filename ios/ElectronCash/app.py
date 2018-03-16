#!/usr/bin/env python3
import sys, os
from electroncash import daemon
from electroncash.util import set_verbosity
from electroncash_gui.ios_native import ElectrumGui
from electroncash_gui.ios_native.utils import get_user_dir, call_later
from electroncash.networks import NetworkConstants
from electroncash.simple_config import SimpleConfig
from electroncash_gui.ios_native.uikit_bindings import *

def main():
    print("HomeDir from ObjC = '%s'"%get_user_dir())

    script_dir = os.path.dirname(os.path.realpath(__file__))
    is_bundle = getattr(sys, 'frozen', False)
    print("script_dir = '%s'\nis_bunde = %s"%(script_dir, str(is_bundle)))

    # config is an object passed to the various constructors (wallet, interface, gui)
    config_options = {
            'verbose': True,
            'cmd': 'gui',
            'gui': 'ios_native',
    }

    config_options['cwd'] = os.getcwd()

    set_verbosity(config_options.get('verbose'))

    if config_options.get('testnet'):
        NetworkConstants.set_testnet()

    for k,v in config_options.items():
        print("config[%s] = %s"%(str(k),str(v)))

    config = SimpleConfig(config_options,read_user_dir_function=get_user_dir)

    fd, server = daemon.get_fd_or_server(config)
    if fd is not None:
        plugins = None
        d = daemon.Daemon(config, fd, True)
        gui = ElectrumGui(config, d, plugins)
        d.gui = gui
        def later() -> None:
            d.start()
            #d.init_gui(config, plugins)
            gui.main()
        call_later(0.1,later)
    else:
        result = server.gui(config_options)

    return "Bitcoin Cash FTW!"
