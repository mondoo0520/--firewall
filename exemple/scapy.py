from scapy.all import *

def packet_capture(packet):
    print(f"packey: {packet.summary()}")

sniff(prn=packet_capture)