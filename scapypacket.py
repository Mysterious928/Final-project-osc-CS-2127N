from scapy.all import *

ip_packet = IP(dst="192.168.1.2")
tcp_packet = TCP(dport=80,flags="S")
packet = ip_packet / tcp_packet / Raw(load="32456789k0l3456789shsadb")

send(packet)

