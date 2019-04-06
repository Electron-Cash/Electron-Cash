#!/usr/bin/env python3

import os.path

PACKAGE = defines.get('PACKAGE', 'NO-PACKAGE')

background = 'contrib/osx/background.png'
volume_name = f'{PACKAGE}'
application = f'dist/{PACKAGE}.app'

symlinks = {
    'Applications': '/Applications',
}

icon = './electron.icns'

files = [
    application,
]

icon_locations = {
    f'{PACKAGE}.app':   (0, 140),
    'Applications':     (230, 135),
}

window_rect = ((400, 250), (450, 300))
