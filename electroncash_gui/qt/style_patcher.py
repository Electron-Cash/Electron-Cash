"""
This is used to patch the QApplication style sheet.
It reads the current stylesheet, appends our modifications and sets the new stylesheet.
"""

from PyQt5 import QtWidgets
from electroncash.util import print_error
import sys

OLD_QDARKSTYLE_PATCH = '''
QWidget:disabled {
    color: hsl(0, 0, 50%);
}
QPushButton:disabled {
    border-color: hsl(0, 0, 50%);
    color: hsl(0, 0, 50%);
}
'''

CUSTOM_PATCH_FOR_DARK_THEME = '''
/* PayToEdit text was being clipped */
QAbstractScrollArea {
    padding: 0px;
}
/* In History tab, labels while edited were being clipped (Windows) */
QAbstractItemView QLineEdit {
    padding: 0px;
    show-decoration-selected: 1;
}
/* Checked item in dropdowns have way too much height...
   see #6281 and https://github.com/ColinDuquesnoy/QDarkStyleSheet/issues/200
   */
QComboBox::item:checked {
    font-weight: bold;
    max-height: 30px;
}
'''

CUSTOM_PATCH_FOR_DEFAULT_THEME_MACOS = '''
/* On macOS, main window status bar icons have ugly frame (see #6300) */
StatusBarButton {
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 4px;
    margin: 0px;
    padding: 2px;
}
StatusBarButton:checked {
  background-color: transparent;
  border: 1px solid #1464A0;
}
StatusBarButton:checked:disabled {
  border: 1px solid #14506E;
}
StatusBarButton:pressed {
  margin: 1px;
  background-color: transparent;
  border: 1px solid #1464A0;
}
StatusBarButton:disabled {
  border: none;
}
StatusBarButton:hover {
  border: 1px solid #148CD2;
}
'''

def patch(use_dark_theme: bool = False, darkstyle_ver: tuple = None):
    custom_patch = ""
    if darkstyle_ver is None or darkstyle_ver < (2,6,8):
        # only apply this patch to qdarkstyle < 2.6.8.
        # 2.6.8 and above seem to not need it.
        custom_patch = OLD_QDARKSTYLE_PATCH
        print_error("[style_patcher] qdarkstyle < 2.6.8 detected; stylesheet patch #1 applied")
    else:
        # This patch is for qdarkstyle >= 2.6.8.
        if use_dark_theme:
            custom_patch = CUSTOM_PATCH_FOR_DARK_THEME
        else:  # default theme (typically light)
            if sys.platform == 'darwin':
                custom_patch = CUSTOM_PATCH_FOR_DEFAULT_THEME_MACOS
        print_error("[style_patcher] qdarkstyle >= 2.6.8 detected; stylesheet patch #2 applied")
    
    app = QtWidgets.QApplication.instance()
    style_sheet = app.styleSheet() + custom_patch
    app.setStyleSheet(style_sheet)