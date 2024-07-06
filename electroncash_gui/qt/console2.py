"""
Electron Cash iPython Integration
Copyright (C) 2024 Calin Culianu <calin.culianu@gmail.com>
License: MIT

Requires: ipython, qtconsole
python3 -m pip install ipython qtconsole --user
"""
from qtconsole.rich_jupyter_widget import RichJupyterWidget
from qtconsole.inprocess import QtInProcessKernelManager
from PyQt5.QtCore import pyqtSignal, Qt


class ConsoleWidget(RichJupyterWidget):
    """
    A much more feature-rich drop-in replacement for the old Electron Cash Console widget.
    """
    closed = pyqtSignal()

    def __init__(self, customBanner=None, *args, **kwargs):
        super(ConsoleWidget, self).__init__(*args, **kwargs)

        if customBanner is not None:
            self.banner = customBanner

        self.font_size = 6
        self.kernel_manager = QtInProcessKernelManager()
        self.kernel_manager.start_kernel(show_banner=False)
        self.kernel_manager.kernel.gui = 'qt'
        self.kernel_client = self._kernel_manager.client()
        self.kernel_client.start_channels()

        self.exit_requested.connect(self._slot_exit_requested)

    def _slot_exit_requested(self):
        self.print_text("Unsupported, use the GUI to exit the app.")

    def push_vars(self, vars: dict):
        """
        Given a dictionary containing name / value pairs, push those variables
        to the Jupyter console widget
        """
        self.kernel_manager.kernel.shell.push(vars)

    def clear(self):
        """
        Clears the terminal
        """
        self._control.clear()

        # self.kernel_manager

    def print_text(self, text, before_prompt=True):
        """
        Prints some plain text to the console
        """
        self._append_plain_text(text, before_prompt=before_prompt)

    def execute_command(self, command):
        """
        Execute a command in the frame of the console widget
        """
        self._execute(command, False)

    def closeEvent(self, e):
        super().closeEvent(e)
        if e.isAccepted():
            self.closed.emit()

    """ --- Compat --- """

    def updateNamespace(self, vars: dict):
        """Provided for compatibility with the legacy Console widget"""
        self.push_vars(vars)

    def set_json(self, b: bool):
        """Unused, provided for compatibility with the legacy Console widget"""
        pass

    def showMessage(self, msg: str):
        """Provided for compatibility with the legacy Console widget"""
        self.banner = msg
        self.print_text(msg, before_prompt=True)

    def set_history(self, hist):
        """Provided for compatibility with the legacy Console widget"""
        self._set_history(hist)


widgets = []


def start(globals_to_add):
    """ Pass globals() to this function to start a new console window """
    import weakref
    window = globals_to_add.get('window')
    wallet = globals_to_add.get('wallet')
    if not window or not wallet:
        raise RuntimeError('This function requires globals containing a \'window\' and a \'wallet\' instance')
    globals_to_add = globals_to_add.copy()
    if 'help' in globals_to_add:
        globals_to_add['help_ec'] = globals_to_add['help']
        globals_to_add.pop('help', None)  # delete help so that the ipython help doesn't get clobbered
    widget = ConsoleWidget()
    widget.push_vars(globals_to_add)
    widgets.append(widget)
    widget.show()
    weak_widget = weakref.ref(widget)

    def rm():
        slf = weak_widget()
        if slf:
            try:
                widgets.remove(slf)
            except ValueError:
                pass
            slf.deleteLater()

    widget.closed.connect(rm, Qt.QueuedConnection)
