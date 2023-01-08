from ast import main
import re
import subprocess
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

import urllib.parse

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
        scapy.load_layer("http")

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
    try:
        packet.show()

        ipadd = packet[scapy.ARP].psrc
        src_mac = packet[scapy.ARP].hwsrc
        
        cmd = "arp -n | grep "+ src_mac +" | awk '{print $1,$3}'"
        result = subprocess.check_output(cmd, shell=True)
        result = result.decode('utf-8')
        maca_ait_ipler = result.split('\n')
        sadece_ipler = []

        for i in maca_ait_ipler:
            sadece_ipler.append(i.split(' ')[0])

        if sadece_ipler == ['']:
            return False
        print("Kaynak MAC: ", src_mac)
        print("Kaynak MAC'e ait IP'ler: ", sadece_ipler)
        print("olduğu söylenilen ip: ", ipadd)

        # print("kaynak ip: ", ipadd)
        # print("olması gereken mac: ",real_mac)
        # print("kaynağın mac'i: ", response_mac)

        if ipadd not in sadece_ipler:
            print(f"[!] You are under attack,")
            return True
        
        print("-------------------------------------------")
    except IndexError:
        return False
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
            if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
                if arpcheck(packet):
                    payload = packet[scapy.ARP].hwsrc + " " +packet[scapy.ARP].psrc + " olduğunu söylüyor."
                    self.new_signal.emit(packet[scapy.ARP].psrc,"ARP",packet[scapy.ARP].pdst,
                    "ARP", "ARP Poisoning", True, payload) 
                    return True
                else:
                    self.new_signal.emit(packet[scapy.ARP].psrc,"ARP",packet[scapy.ARP].pdst,
                    "ARP", "", False, "hwsrc: " + packet[scapy.ARP].hwsrc + "| hwdst: " + packet[scapy.ARP].hwdst) 
           
        else:
            for offset, rule in enumerate(RULES):

                if packet_signature.src_port == "443" or packet_signature.dst_port == "443" : 
                    return True

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
                # if arpcheck(packet):
                #     self.new_signal.emit(packet_signature.src_ip,packet_signature.src_port,packet_signature.dst_ip,
                #     packet_signature.dst_port, "ARP Poisoning", True, payload)
                #     return True


                http_payload = b""
                # INTERACTIVE 3 : SQL INJECTION
                if packet_signature.src_port == "80" or packet_signature.src_port == "443" or packet_signature.dst_port == "80" or packet_signature.dst_port == "443" : 
                    print(packet.show)
                    content = ""
                    try:

                        http_payload = get_httppayload(packet)
                        content = str(http_payload[0]).split('\\r\\n\\r\\n')[-1]
                        content = urllib.parse.unquote(content)
                        http_payload = http_payload[0].decode("utf8")
                    except Exception as e:
                        http_payload = e

                    matches = re.search(REGEX_SQL, content, re.IGNORECASE)
                
                    if matches is not None:
                        print(matches)
                        if packet.haslayer(http.HTTPRequest) and packet[http.HTTPRequest].Method!=b'GET':
                            self.new_signal.emit(packet_signature.src_ip,packet_signature.src_port,
                            packet_signature.dst_ip,packet_signature.dst_port, "SQL Injection",  True, content)  
                            return True
                
                # INTERACTIVE 4 : XSS
                if packet_signature.src_port == "80" or packet_signature.src_port == "443" or packet_signature.dst_port == "80" or packet_signature.dst_port == "443" : 

                    content = ""
                    try:
                        http_payload = get_httppayload(packet)
                        content = str(http_payload[0]).split('\\r\\n\\r\\n')[-1]
                        content = urllib.parse.unquote(content)
                        http_payload = http_payload[0].decode("utf8")
                    except Exception as e:
                        http_payload = e

                    matches = re.search(REGEX_XSS, content, re.IGNORECASE)
                    
                    if packet.haslayer(http.HTTPRequest) and packet[http.HTTPRequest].Method!=b'GET':
                        if matches is not None:
                            self.new_signal.emit(packet_signature.src_ip,packet_signature.src_port,
                            packet_signature.dst_ip,packet_signature.dst_port, "XSS",  True, content) 
                            return True


            # print(f"[=] {summary}")
            # payload = str(bytes(packet[scapy.TCP].payload).decode('UTF8','replace'))
            self.new_signal.emit(packet_signature.src_ip,packet_signature.src_port,
            packet_signature.dst_ip,packet_signature.dst_port, "",  False, payload)  
            return False

    def run(self):
        index = 1
        while not self.is_dead():
            # print(self.task_queue.get())
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