from telnetlib import IP
from tkinter.ttk import Style
from scapy.all import *
from threading import Thread, Event
from time import sleep
import tkinter as tk
import time

from neo.src import client

API_KEY = 'YourAPIkey'

class Sniffer(Thread):
    oldTime= time.time() # start the timer
    def __init__(self, interface=None):
        super().__init__()
        self.interface = interface  # this rules the interface of the sniffer
        self.stop_sniffer = Event()
        self.oldTime=time.time()

    # this commands runs in background and initiate the scanning of the ip addresses
    def run(self):
        sniff(iface=self.interface, filter="ip", prn=self.print_packet, stop_filter=self.should_stop_sniffer)

    # stop command for the sniffer
    def join(self, timeout=None):
        self.stop_sniffer.set()
        super().join(timeout)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    # this command contact with the api and send the suspicious ip to check.
    def print_packet(self, packet):
        ip_layer = packet.getlayer(IP)  # separate the ip layer from the packet
        dest = (ip_layer.dst)  # take the destination ip from the ip layer

        if dest in ipDictonary:  # check if ip is already scanned
            ipDictonary[dest] += float(ip_layer.len) # sum the total length of the packet transferred to the the specific ip
        else:
            ipDictonary[dest] = float(ip_layer.len)
        #  print(self.oldTime)
        #dest = "http://coronavirusstatus.space/index.php"
        #ipDictonary[dest]=1100000
        if (ipDictonary[dest] > 1000000 and dest not in ipInScanning): #  check if ip address gets more than 10mb per time of unit and not scanned already
            ipInScanning[dest] = 'true'
            print(ipDictonary[dest])

            # write the suspicious ip to a file for the api
            f = open("urls_to_scan.txt", 'w')
            #  f.write('http://coronavirusstatus.space/index.php')
            f.write(dest)
            f.close()
            client.main() # initiate the api
            #sleep(5)
        newTime= time.time()
        subTime = newTime-self.oldTime  # time elapsed
        if(subTime>30):
            self.cleanRecords() # if more than 30 seconds passed and not received 10mb reset length dictionary

        print(
            "[!] New Packet: {src} -> {dst} , len = {len}".format(src=ip_layer.src, dst=ip_layer.dst, len=ip_layer.len))

    def cleanRecords(self) :
        ipDictonary.clear()
        print("Records Cleaned")
        sleep(5)
        self.oldTime=time.time() # reset the timer




ipDictonary = {}  # this dicitonary will save ip adresses and their total length of packets
ipInScanning = {}  # this dicitonary will save ip's that already scanned

sniffer = Sniffer()  # create sniffer

# gui panel
Freq = 2500
Dur = 150
top = tk.Tk()
top.title('Maleware Traffic Detect')
top.geometry('300x100')  # Size 200, 200


def start():
    print("[*] Start sniffing...")
    sniffer.start()
    top.destroy()
    try:
        while True:
            sleep(100)
    except KeyboardInterrupt:
        print("[*] Stop sniffing")
        sniffer.join()
        for key in ipDictonary:
            print("len = {}\n".format(str(ipDictonary[key])))


startButton = tk.Button(top, height=2, width=20, text="Start",
                        command=start)
startButton.pack(pady=30)
top.mainloop()
