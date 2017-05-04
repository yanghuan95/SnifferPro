/*************************************************************************
    > File Name: MySimpleSniffer.c
    > Author: yanghuan
    > Mail: yanghuancoder@163.com 
    > Created Time: Fri 28 Apr 2017 09:28:16 AM DST
 ************************************************************************/

#include<stdio.h>
#include<string.h>
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
#include<netinet/if_ether.h>
#include<ctype.h>
#include<linux/ip.h>
#include<linux/tcp.h>

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
		pcap_t *device = pcap_open_live(dev, 65535, 1, 0, errBuffer);
		
		if(device == NULL){
			fprintf(stdout, "fail to open live: %s\n", errBuffer);
			exit(1);
		}


		//set filter rules
//		filterPacket(device);

		/**
		 * pass user_id to identify
		 * -1 is grep data util do not hava data
		 *  dealData is to deal the data
		 *  if wait data above 1000ms, will return back
		 */
		int user_id = 1;
		printf("now, loop\n");
		pcap_loop(device, -1, dealData, (u_char *)&user_id);

		pcap_close(device);
	}

	return 0;
}

void dealData(u_char *usearg, const struct pcap_pkthdr *pkthdr, const u_char *packet){

	printf("get packet\n");
	FILE *fd;
	fd = fopen(dump_log, "a+");

	if(fd == NULL){
		printf("can not open the file\n");
		exit(2);
	}
	
	fprintf(fd, "-----------------------\n");
	//write into the log
	fprintf(fd, "grep time is :%s\n", 
			ctime((const time_t *)&pkthdr->ts.tv_sec));
	fprintf(fd, "packet length is %d\n", pkthdr->len);
	fprintf(fd, "packet is :\n%s\n", packet);
	fprintf(fd, "-----------------------\n");

	fclose(fd);


	//analysis the data
	analysisData(pkthdr, packet);
}

void analysisData(const struct pcap_pkthdr *pkthdr, const u_char *packet){
	printf("deal packet\n");	
	//open in write append,create mode
	FILE *fd = fopen(analysis_log, "a+");
	if(fd == NULL){
		printf("can not open the file\n");
		exit(2);
	}
	
	//TODO add the deal data logic and 
	//then write into the log file
	fprintf(fd, "*************************\n");
	fprintf(fd, "grep packet length is %d\n", pkthdr->len);
	fprintf(fd, "received at : %s\n", 
			ctime((const time_t*)&pkthdr->ts.tv_sec));

	struct ether_header *eptr;
	u_char *ptr;
	eptr = (struct ether_header *)packet;
	//save src and dest mac address
	ptr = (u_char *)(eptr->ether_shost);
	fprintf(fd, "src mac address is %02x:%02x:%02x:%02x:%02x:%02x\n",
			 *(ptr), *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5));

	ptr = (u_char *)eptr->ether_dhost;
	fprintf(fd, "dest mac address is %02x:%02x:%02x:%02x:%02x:%02x\n",
			 *(ptr), *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5));

	if(ntohs(eptr->ether_type) == ETHERTYPE_IP){
		fprintf(fd, "ethernet type %x is IP packet\n",
				ntohs(eptr->ether_type));
	}else if(ntohs(eptr->ether_type) == ETHERTYPE_ARP){
		fprintf(fd, "ethernet type %x is ARP packet\n",
				ntohs(eptr->ether_type));
	}else{
		fprintf(fd, "type %x not a IP\n", ntohs(eptr->ether_type));
		return;
	}
	
	fprintf(fd, "-----------------------\n");

	//get ip packet 
	fprintf(fd, "decode the ip packet\n");
	struct iphdr *ip = (struct iphdr*) (packet + sizeof(struct ether_header));
	fprintf(fd, "the IP packet length is: %d\n", ip->tot_len);
	fprintf(fd, "the IP protocol is %d\n", ip->protocol);
	struct in_addr address;
	address.s_addr = ip->saddr;
	fprintf(fd, "src ip : %s\n", inet_ntoa(address));
	address.s_addr = ip->daddr;
	fprintf(fd, "dest ip : %s\n", inet_ntoa(address));

	fprintf(fd, "-----------------------\n");

	//get tcp packet
	fprintf(fd, "decode the tcp packet\n");
	struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header)
					+ sizeof(struct iphdr));
	fprintf(fd, "src port : %d\n", tcp->source);
	fprintf(fd, "dest port : %d\n", tcp->dest);
	fprintf(fd, "seq of packet is %d\n", tcp->seq);
	fprintf(fd, "seq of packet is %d\n", tcp->seq);
	fprintf(fd, "-----------------------\n");

	//get the data
	fprintf(fd, "data :\n");
	u_char *data = (u_char *)(struct tcphdr *)(packet + sizeof(struct ether_header)
					+ sizeof(struct iphdr) + sizeof(struct tcphdr));

	int i = 0;
	do{
		fprintf(fd, "%02x ", data[i]);
		++i;
		if(i % 16 == 0)
			fprintf(fd, "\n");
	}while(i < strlen(data));

	fprintf(fd, "\n");

	fclose(fd);
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
