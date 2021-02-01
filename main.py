from telnetlib import IP
from scapy.all import *
from threading import Thread, Event
from time import sleep

class Sniffer(Thread):
    def  _init_(self, interface=None):
        super()._init_()

        self.interface = interface
        self.stop_sniffer = Event()

    def run(self):
        sniff(iface=self.interface, filter="ip", prn=self.print_packet, stop_filter=self.should_stop_sniffer)

    def join(self, timeout=None):
        self.stop_sniffer.set()
        super().join(timeout)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def print_packet(self, packet):
        ip_layer = packet.getlayer(IP)
        print("[!] New Packet: {src} -> {dst} , len = {len}".format(src=ip_layer.src, dst=ip_layer.dst,len=ip_layer.len))

sniffer = Sniffer()

print("[*] Start sniffing...")
sniffer.start()

try:
    while True:
        sleep(100)
except KeyboardInterrupt:
    print("[*] Stop sniffing")
    sniffer.join()