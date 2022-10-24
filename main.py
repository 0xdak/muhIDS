from ast import main
from PyQt5.QtWidgets import QMainWindow, QTableWidget, QApplication, QPushButton, QLineEdit
from PyQt5 import uic, QtWidgets, QtCore
from scapy.all import conf, sniff, wrpcap, ETH_P_ALL

from multiprocessing import Process, Event, Queue

from sys import argv
import sys
from time import sleep, time


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        uic.loadUi("mainwindow.ui", self)
        

        self.tableWidget = self.findChild(QTableWidget, "tableWidget") 
        self.txtInterface = self.findChild(QLineEdit, "txtInterface") 
        self.startButton  = self.findChild(QPushButton, "pushButton")
        
        self.INTERFACE = "wlan0"
        
        self.startButton.clicked.connect(self.startButtonClicked)

        self.row = 0

        self.QUEUE = Queue()
        self.TIMESTAMP = str(time()).split('.')[0]
        
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

    def startButtonClicked(self):
        self.INTERFACE = self.txtInterface.text()
        self.SNIFFER = Sniffer(self.INTERFACE, self.QUEUE, self.TIMESTAMP)
        self.SNIFFER.new_signal.connect(self.fill_tableWidget)
        self.SNIFFER.start()

    def closeEvent(self, event):
        print('[*] stopping muhIDS')
        # LOG_FILE.close()
        # ANALYZER.join()
        sleep(.1)
        self.SNIFFER.join()
        print('[*] bye')



class Sniffer(QtCore.QThread):
    def __init__(self, interface, queue, name):
        super(Sniffer, self).__init__()
        self.daemon = True
        self.socket = None
        self.interface = interface
        self.stop = Event()
        self.que = queue
        self.log_name = name
        
    new_signal = QtCore.pyqtSignal(str, str, str, str)

    def run(self):
        # p = Process(target=job_function, args=(self.queue, self.job_input))
        # p.start()
        i = 0
        self.socket = conf.L2listen(type=ETH_P_ALL, iface=self.interface)
        packets = sniff(opened_socket=self.socket,
                        prn=self.analyze_packet,
                        stop_filter=self.stop_sniffering)



            # time.sleep(.01)
            # self.new_signal.emit(str(i), str(i), str(i), str(i))
            # i += 1
    
    def analyze_packet(self, packet):
        self.que.put(bytes(packet))

    def stop_sniffering(self, _):
        return self.stop.is_set()

    def join(self, timeout=None):
        self.stop.set()
        super().join(timeout)

        
app = QApplication(argv)
UIWindow = MainWindow()
try:
    sys.exit(app.exec_())
except:
    print("exiting")