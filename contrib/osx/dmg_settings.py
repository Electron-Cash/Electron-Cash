#!/usr/bin/env python3

import os.path

PACKAGE = defines.get('PACKAGE', 'NO-PACKAGE')

background = 'contrib/osx/background.png'
volume_name = PACKAGE
application = 'dist/{}.app'.format(PACKAGE)

symlinks = {
    'Applications': '/Applications',
}

icon = './electron.icns'

files = [
    application,
]

icon_locations = {
    '{}.app'.format(PACKAGE) :       (0, 140),
    'Applications'           :     (230, 135),
}

window_rect = ((400, 250), (450, 300))
