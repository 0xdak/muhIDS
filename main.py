from ast import main
from PyQt5.QtWidgets import QMainWindow, QTableWidget, QApplication, QPushButton
from PyQt5 import uic, QtWidgets, QtCore
from scapy.all import conf, sniff, wrpcap, ETH_P_ALL

from sys import argv
import sys
import time


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        uic.loadUi("mainwindow.ui", self)

        self.tableWidget = self.findChild(QTableWidget, "tableWidget") 
        self.pushButton  = self.findChild(QPushButton, "pushButton")
        
        
        self.pushButton.clicked.connect(self.pushButtonClicked)

        self.row = 0

        self.sniffer = Sniffer()
        self.sniffer.new_signal.connect(self.fill_tableWidget)
        self.sniffer.start()
        
        self.show()

    # paket analiz edildikten sonra çağırılacak
    @QtCore.pyqtSlot(str, str, str, str)
    def fill_tableWidget(self, src_ip, src_port, dest_ip, dest_port):
        self.tableWidget.setRowCount(self.row+1)
        self.tableWidget.setItem(self.row, 0, QtWidgets.QTableWidgetItem(src_ip))
        self.tableWidget.setItem(self.row, 1, QtWidgets.QTableWidgetItem(src_port))
        self.tableWidget.setItem(self.row, 2, QtWidgets.QTableWidgetItem(dest_ip))
        self.tableWidget.setItem(self.row, 3, QtWidgets.QTableWidgetItem(dest_port))
        self.row += 1

    def pushButtonClicked(self):
        for i in range(100000):
            self.fill_tableWidget(str(i), i, i, i)

    def closeEvent(self, event):
        print('closing')



class Sniffer(QtCore.QThread):
    new_signal = QtCore.pyqtSignal(str, str, str, str)

    def run(self):
        i = 0
        while True:
            time.sleep(.01)
            self.new_signal.emit(str(i), str(i), str(i), str(i))
            i += 1

        
app = QApplication(argv)
UIWindow = MainWindow()
try:
    sys.exit(app.exec_())
except:
    print("exiting")