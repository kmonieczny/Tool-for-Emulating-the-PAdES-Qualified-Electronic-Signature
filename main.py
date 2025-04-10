import sys
from PyQt5.QtWidgets import QApplication
from main_app.gui.gui import PAdESApp

def main():
    app = QApplication(sys.argv)
    window = PAdESApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main() 