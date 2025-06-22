from scapy.all import load_layer, sniff
from scapy.layers.tls.handshake import TLSClientHello

load_layer("TLS")

def extract_sni(packet):
    if packet.haslayer(TLSClientHello):
        client_hello = packet[TLSClientHello]
        for ext in getattr(client_hello, "ext", []):
            if hasattr(ext, "ervernames"):
                for servername in ext.servernames:
                    print("SNI도메인", servername.servername.decode())

sniff("tcp port 443", prn=extract_sni)
