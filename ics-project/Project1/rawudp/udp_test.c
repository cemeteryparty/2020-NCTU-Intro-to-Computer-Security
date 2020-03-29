// ----rawudp.c------
// Must be run by root lol! Just datagram, no payload/data
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h> //inet_addr
#include <netinet/udp.h>

#define PCKT_LEN 8192// The packet length

typedef struct iphdr iph;
typedef struct udphdr udph;// 8 bytes

     

// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
// The checksum field is the 16 bit one's complement of the one's
// complement sum of all 16 bit words in the header.  
// For purposes of computing the checksum, the value of the checksum field is zero.
unsigned short csum(unsigned short *buf, int nwords){
    unsigned long sum = 0,i;
    for(i = 0;i < nwords;i++)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}//it seems that kernal will recalculate it again

// Source IP, source port, target IP, target port from the command line arguments
int main(int argc, char *argv[]){
    int sd;
    // No data/payload just datagram
    char buffer[PCKT_LEN];

    // Our own headers' structures
    iph *ip = (iph *) buffer; //
    udph *udp = (udph *)(buffer + sizeof(iph));

    // Source and destination addresses: IP and port
    struct sockaddr_in sin,din;
    int one = 1;

    const int *val = &one;
    memset(buffer, 0, PCKT_LEN);

    if(argc != 5){
        printf("- Invalid parameters!!!\n");
        printf("- Usage %s <source hostname/IP> <source port> <target hostname/IP> <target port>\n", argv[0]);
        exit(-1);
    }

    // Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if(sd == -1){
        printf("socket() error\n");
        exit(-1);// If something wrong just exit
    }
    else
        printf("socket() - Using SOCK_RAW socket and UDP protocol is OK.\n");

     

    // The source is redundant, may be used later if needed

    // The address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    // Port numbers
    sin.sin_port = htons(atoi(argv[2]));
    din.sin_port = htons(atoi(argv[4]));

    // IP addresses

    sin.sin_addr.s_addr = inet_addr(argv[1]);
    din.sin_addr.s_addr = inet_addr(argv[3]);

    // Fabricate the IP header or we can use the
    // standard header structures but assign our own values.
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 16; //Low delay, dns.c:0
    ip->tot_len = sizeof(iph) + sizeof(udph);
    ip->id = htons(54321); //htonl(getpid());
    ip->ttl = 64; // hops
    ip->protocol = 17; // UDP ,dns.c:IPPROTO_UDP 
    ip->saddr = inet_addr(argv[1]);// Source IP address, can use spoofed address here!!!
    ip->daddr = inet_addr(argv[3]);// The destination IP address
    // Calculate the checksum for integrity, kernal will revise
    ip->check = csum((unsigned short *)buffer, ip->tot_len);
    //printf("0x%04hx\n",ip->check);

    // Fabricate the UDP header.
    udp->source = htons(atoi(argv[2]));// Source port number
    udp->dest = htons(atoi(argv[4]));// Destination port number
    udp->len = htons(sizeof(udph));
    udp->check = 0;

    
    //ip->check = csum((unsigned short *)buffer, sizeof(iph) + sizeof(udph));
    
    //ip->check = csum((unsigned short *)buffer,sizeof(iph) / sizeof(unsigned short));
    //ip->check = csum((unsigned short *)buffer,sizeof(iph) / sizeof(unsigned short));

    // Inform the kernel do not fill up the packet structure. we will build our own...

    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1){
        printf("setsockopt() error\n");
        exit(-1);
    }
    else
        printf("setsockopt() is OK.\n");

     
    // Send loop, send for every 2 second for 100 count

    printf("Trying...\n");

    printf("Using raw socket and UDP protocol\n");

    printf("Using Source IP: %s port: %u, Target IP: %s port: %u.\n", argv[1], atoi(argv[2]), argv[3], atoi(argv[4]));


    int count;
    for(count = 0;count < 20;count++){
        if(sendto(sd,buffer,ip->tot_len,0,(struct sockaddr *)&din,sizeof(din)) < 0){
            printf("sendto() error\n");
            exit(-1);
        }
        else{
            printf("Count #%d - sendto() is OK.\n",count + 1);
            sleep(2);
        }
    }

    close(sd);

    return 0;
}