/*************************************************************************
    > File Name: MySimpleSniffer.c
    > Author: yanghuan
    > Mail: yanghuancoder@163.com 
    > Created Time: Fri 28 Apr 2017 09:28:16 AM DST
 ************************************************************************/

#include<stdio.h>
#include<unistd.h>
#include<pcap.h>
#include<time.h>
#include<stdlib.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<netdb.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<ctype.h>

//only sniffer the packet from 80 port
#define FILTER_PORT 80

const char *dump_log = "grep_packet.log";
const char *analysis_log = "grep_packet_analy.log";

void filterPacket(pcap_t *device);	//filter the packet by port
void dealData(u_char *usearg, 
		const struct pcap_pkthdr *pkthdr, const u_char *packet); //deal Data function
void analysisData(const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char *argv[]){
	char errBuffer[PCAP_ERRBUF_SIZE], *dev;
	
	if(argc < 2){
		//look up the dev 
		dev = pcap_lookupdev(errBuffer);
		if(dev == NULL){
			//just exam, when it work, should note it
			fprintf(stdout, "fail to look up dev: %s\n", errBuffer);
			exit(0);
		}
		/**
		 * open network interface
		 * grep max packet length is 65535
		 * don't open the promiscuous mode
		 * wait 1000ms, if above, just not grep data
		 */
		pcap_t *device = pcap_open_live(dev, 65535, 0, 1000, errBuffer);
		
		if(device == NULL){
			fprintf(stdout, "fail to open live: %s\n", errBuffer);
			exit(1);
		}

		//set filter rules
		filterPacket(device);

		/**
		 * pass user_id to identify
		 * -1 is grep data util do not hava data
		 *  dealData is to deal the data
		 *  if wait data above 1000ms, will return back
		 */
		int user_id = 1;
		pcap_dispatch(device, -1, dealData, (u_char *)&user_id);

		pcap_close(device);
	}else{
		//use user into to sniffer
		//asume it is the IP like 192.168.10.1
		struct in_addr *IP = NULL;
		if(isdigit(argv[1])){
			inet_aton(argv[1], IP);	
		}else{
			struct hostent *dns = gethostbyname(argv[1]);
			if(dns == NULL){
				fprintf(stdout, "there is no host like: %s\n",argv[1]);
				exit(0);
			}
			IP = (struct in_addr *) &dns->h_addr_list[0];
		}

	}
}

void dealData(u_char *usearg, const struct pcap_pkthdr *pkthdr, const u_char *packet){
	int fd;
	fd = open(dump_log, O_CREAT|O_WRONLY|O_APPEND);

	if(fd == -1){
		printf("can not open the file\n");
		exit(2);
	}
	//write into the log
	write(fd, packet, pkthdr->len + 1);
	write(fd, "\n", 2);
	clost(fd);

	//analysis the data
	analysisData(pkthdr, packet);
}

void analysisData(const struct pcap_pkthdr *pkthdr, const u_char *packet){
	//open in write append,create mode
	int fd = open(analysis_log, O_CREAT|O_WRONLY|O_APPEND);
	if(fd == -1){
		printf("can not open the file\n");
		exit(2);
	}
	
	//TODO add the deal data logic and 
	//then write into the log file
	for(int i = 0; i < pkthdr->len; ++i){
	}
}

void filterPacket(pcap_t *device){
	char *filter_rule = "dst port 80";
	struct bpf_program filter;
	/**
	 * filter save the compiled rule
	 * 1 is need to optimize the rule
	 * 0 is the network mask
	 */
	pcap_compile(device, &filter, filter_rule, 1, 0);
	//appli the rule
	pcap_setfilter(device, &filter);
}
