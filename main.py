from ast import main
import re
from PyQt5.QtWidgets import QMainWindow, QTableWidget, QApplication, QPushButton, QLineEdit
from PyQt5 import uic, QtWidgets, QtCore, QtGui
from scapy.all import conf, sniff, wrpcap, ETH_P_ALL, Ether
import scapy.all as scapy
from multiprocessing import Process, Event, Queue
from scapy.layers import http
from sys import argv
import sys
from time import sleep, time

from signature import Signature
from importer import RULES, REGEX_SQL, REGEX_XSS


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
    @QtCore.pyqtSlot(str, str, str, str, str, bool, str)
    def fill_tableWidget(self, src_ip, src_port, dest_ip, dest_port, rule_id, blocked, payload):
        self.tableWidget.setRowCount(self.row+1)
        self.tableWidget.setItem(self.row, 0, QtWidgets.QTableWidgetItem(str(self.row+1)))
        self.tableWidget.setItem(self.row, 1, QtWidgets.QTableWidgetItem(rule_id))
        self.tableWidget.setItem(self.row, 2, QtWidgets.QTableWidgetItem(src_ip))
        self.tableWidget.setItem(self.row, 3, QtWidgets.QTableWidgetItem(src_port))
        self.tableWidget.setItem(self.row, 4, QtWidgets.QTableWidgetItem(dest_ip))
        self.tableWidget.setItem(self.row, 5, QtWidgets.QTableWidgetItem(dest_port))
        self.tableWidget.setItem(self.row, 6, QtWidgets.QTableWidgetItem(payload))
        if (blocked):
            self.tableWidget.item(self.row, 0).setBackground(QtGui.QColor(255,0,0))
            self.tableWidget.item(self.row, 1).setBackground(QtGui.QColor(255,0,0))
            self.tableWidget.item(self.row, 2).setBackground(QtGui.QColor(255,0,0))
            self.tableWidget.item(self.row, 3).setBackground(QtGui.QColor(255,0,0))
            self.tableWidget.item(self.row, 4).setBackground(QtGui.QColor(255,0,0))
            self.tableWidget.item(self.row, 5).setBackground(QtGui.QColor(255,0,0))
            self.tableWidget.item(self.row, 6).setBackground(QtGui.QColor(255,0,0))
            self.tableWidget.scrollToBottom()
        self.row += 1

    def startButtonClicked(self):
        self.INTERFACE = self.txtInterface.text()
        self.SNIFFER = Sniffer(self.INTERFACE, self.QUEUE, self.TIMESTAMP)
        self.SNIFFER.start()

        self.ANALYZER = Analyzer(self.QUEUE)
        self.ANALYZER.new_signal.connect(self.fill_tableWidget)
        self.ANALYZER.start()


    def closeEvent(self, event):
        print('[*] stopping muhIDS')
        self.ANALYZER.join()
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
        

    def run(self):
        # p = Process(target=job_function, args=(self.queue, self.job_input))
        # p.start()
        i = 0
        self.socket = conf.L2listen(type=ETH_P_ALL,iface=self.interface)
        packets = sniff(opened_socket=self.socket,
                        prn=self.analyze_packet,
                        stop_filter=self.stop_sniffering)



            # sleep(.01)
            # self.new_signal.emit(str(i), str(i), str(i), str(i))
            # i += 1
    
    def analyze_packet(self, packet):
        self.que.put(bytes(packet))

    def stop_sniffering(self, _):
        return self.stop.is_set()

    def join(self, timeout=None):
        self.stop.set()
        super().join(timeout)

def arpcheck(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        packet.show()
        try:
            ipadd = packet[scapy.ARP].psrc
            
            p = Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(pdst=ipadd)
            result = scapy.srp(p, timeout=3, verbose=False)[0]
            real_mac = result[0][1].hwsrc

            response_mac = packet[scapy.ARP].hwsrc
                    # if they're different, definitely there is an attack
            if real_mac != response_mac:
                print(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
                return True
        except IndexError:
            return False
        return False
        arp_request = scapy.ARP(pdst=ipadd)
        br = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_br = br / arp_request
        list_1 = scapy.srp(arp_req_br, timeout=5,
                       verbose=False)[0]
        try:
            print(list_1)
            print("bakıyoruz list_1")
            originalmac = list_1[0][1].hwsrc
            print(originalmac, " - ", responsemac)
            # responsemac will get response of the MAC
            responsemac = packet[scapy.ARP].hwsrc
            if originalmac != responsemac:
                print("[*] ALERT!!! You are under attack, ARP table is being poisoned.!")
            # print(packet.show())
            return True
        except:
            print("hata verdi list_1")
            return False

def get_httppayload(packet):
    http_payload = b""
    payload = bytes(packet[scapy.TCP].payload)
    http_header_exists = False
    try:
        http_header = payload[payload.index(b"HTTP/"):payload.index(b"\r\n\r\n")+2]
        if http_header:
            http_header_exists = True
    except:
        pass
    if not http_header_exists and http_payload:
        http_payload += payload
    elif http_header_exists and http_payload:
        http_header_raw = http_payload[:http_payload.index(b"\r\n\r\n")+2]
        http_header_parsed = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header_raw.decode("utf8")))
        if "Content-Type" in http_header_parsed.keys():
            if "image" in http_header_parsed["Content-Type"]:
                image_payload = http_payload[http_payload.index(b"\r\n\r\n")+4:]
                if image_payload:
                    scapy.extract_payload(http_header_parsed, image_payload, scapy.output_path)
        http_payload = payload
    elif http_header_exists and not http_payload:
        http_payload = payload,

    return http_payload

class Analyzer(QtCore.QThread):
    def __init__(self, task_queue):
        super(Analyzer, self).__init__()
        self.daemon = True
        self.stop = Event()
        self.task_queue = task_queue
        self.with_packer_num = False

    new_signal = QtCore.pyqtSignal(str, str, str, str, str, bool, str)

    def is_dead(self):
        return self.stop.is_set()

    def is_intrusion(self, packet, index):
        summary = packet.summary()
        payload = str(bytes(packet.payload))
        try:
            packet_signature = Signature(packet)
        except ValueError as err: # ARP olabilir.
            print(f"[@] {err} {summary}")
            if arpcheck(packet):
                self.new_signal.emit(packet[scapy.ARP].psrc,"ARP",packet[scapy.ARP].pdst,
                   "ARP", "", True, payload) 
           
        else:
            for offset, rule in enumerate(RULES):
                # INTERACTIVE 1 : SIGNATURE-BASED
                if packet_signature == rule:
                    msg = f"{RULES[offset].__repr__()} ~> {summary}"
                    print(f"[!!] {msg}")
                    #TODO RULES[offset].__repr__().split()[1] değişecek, !! tehlikeli index out of range hatası verebilir
                    self.new_signal.emit(packet_signature.src_ip,packet_signature.src_port,packet_signature.dst_ip,
                    packet_signature.dst_port, RULES[offset].__repr__().split()[1], True, payload) 
                    return True
                # print("PROTOMUZ: ", packet_signature.proto)
                # print(packet)

                # INTERACTIVE 2 : ARP POISINING
                if arpcheck(packet):
                    self.new_signal.emit(packet_signature.src_ip,packet_signature.src_port,packet_signature.dst_ip,
                    packet_signature.dst_port, "ARP Poisoning", True, payload)


                http_payload = b""
                # INTERACTIVE 3 : SQL INJECTION
                if packet_signature.src_port == "80" or packet_signature.src_port == "443" or packet_signature.dst_port == "80" or packet_signature.dst_port == "443" : 

                    try:
                        http_payload = get_httppayload(packet)
                    except:
                        http_payload = ""

                    matches = re.search(REGEX_SQL, str(http_payload), re.IGNORECASE)
                

                    if matches is not None:
                        print(matches)
                        if packet.haslayer(http.HTTPRequest) and packet[http.HTTPRequest].Method!=b'GET':
                            self.new_signal.emit(packet_signature.src_ip,packet_signature.src_port,
                            packet_signature.dst_ip,packet_signature.dst_port, "SQL Injection",  True, str(http_payload))  
                            return True
                    
                    self.new_signal.emit(packet_signature.src_ip,packet_signature.src_port,
                    packet_signature.dst_ip,packet_signature.dst_port, "",  False, str(http_payload))  
                
                # INTERACTIVE 4 : XSS
                if packet_signature.src_port == "80" or packet_signature.src_port == "443" or packet_signature.dst_port == "80" or packet_signature.dst_port == "443" : 

                    try:
                        http_payload = get_httppayload(packet)
                    except:
                        http_payload = ""
                    matches = re.search(REGEX_XSS, str(http_payload), re.IGNORECASE)

                    if packet.haslayer(http.HTTPRequest) and packet[http.HTTPRequest].Method!=b'GET':
                        if matches is not None:
                            print(matches)
                            self.new_signal.emit(packet_signature.src_ip,packet_signature.src_port,
                            packet_signature.dst_ip,packet_signature.dst_port, "XSS",  True, str(http_payload)) 
                    # print(matches)

                    self.new_signal.emit(packet_signature.src_ip,packet_signature.src_port,
                    packet_signature.dst_ip,packet_signature.dst_port, "",  False, str(http_payload)) 


            print(f"[=] {summary}")
            # payload = str(bytes(packet[scapy.TCP].payload).decode('UTF8','replace'))
            self.new_signal.emit(packet_signature.src_ip,packet_signature.src_port,
            packet_signature.dst_ip,packet_signature.dst_port, "",  False, payload)  
            return False

    def run(self):
        index = 1
        while not self.is_dead():
            print(self.task_queue.get())
            self.is_intrusion(Ether(self.task_queue.get()), index)
            index += 1

    def join(self, timeout=None):
        self.stop.set()
        super().join(timeout)
        
app = QApplication(argv)
UIWindow = MainWindow()
try:
    sys.exit(app.exec_())
except:
    print("exiting")