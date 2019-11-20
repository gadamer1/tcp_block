#include <stdio.h>
#include <iostream>
#include <string>
#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>


using namespace std;

uint16_t ip_checksum(u_char *buf, uint8_t len);
uint16_t tcp_checksum(u_char *buf, uint8_t len);


struct packet{
	//ethernet header
	uint8_t dest_mac[6];
	uint8_t src_mac[6];
	uint16_t type;



	//ip header
	uint8_t header_length:4;
	uint8_t version:4;
	uint8_t service_field;
	uint16_t total_length;
	uint16_t identification;
	uint16_t flag;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t ip_checksum;
	uint32_t src_address;
	uint32_t dest_address;


	// tcp_header

	uint16_t src_port;
	uint16_t dest_port;
	uint32_t sequence_number;
	uint32_t acknowledgement_number;
	uint8_t res1:4;
	uint8_t tcp_header_length:4;


	uint8_t fin:1;
	uint8_t syn:1;
	uint8_t rst:1;
	uint8_t psh:1;
	uint8_t ack:1;
	uint8_t urg:1;
	uint8_t res2:4;
	
	uint16_t tcp_checksum;
	uint16_t urgent_pointer;
};

struct packet* data;


int send_rst_packet(pcap_t *fp,int size,int len,int type){ // 0 is forward 1 is backward

	struct packet* rst_packet = data;
	if(type ==0){
		rst_packet->sequence_number+=len;
	}else {rst_packet->acknowledgement_number+=len;}
	rst_packet->rst=1;
	rst_packet->fin =0;
	rst_packet->syn=0;
	rst_packet->ack=0;
	
	// calculate IP checksum
    rst_packet->ip_checksum=htons(ip_checksum((u_char*)(rst_packet+14),rst_packet->header_length*4));
	
    // calculate TCP checksum
    rst_packet->tcp_checksum = tcp_checksum((u_char *)(rst_packet+rst_packet->header_length*4+14), (int)rst_packet->tcp_header_length);
	

	if(pcap_sendpacket(fp,(const u_char*)rst_packet,size) !=0){
		fprintf(stderr,"\nError sending the packet: \n");
		return -1;
	}
	printf("\nsend rst packet successfully!\n");
	return 0;
}

uint16_t ip_checksum(u_char *buf, uint8_t len){
    uint32_t sum=0;
    for(int i=0;i<len;i++){
        sum+=buf[i];
    }
    uint16_t res=(sum>>16)+(sum&0xffff);
    return ~res;
}


unsigned short tcp_checksum(u_char *buf, uint8_t len)
{
    uint32_t sum = 0;

    while(len--)
        sum += *buf++;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

int send_fin_packet(pcap_t *fp,int size){

	struct packet* rst_packet = data;

	rst_packet->fin|=0x1;


	if(pcap_sendpacket(fp,(const u_char*)rst_packet,size) !=0){
		fprintf(stderr,"\nError sending the packet: \n");
		return -1;
	}
	printf("\nsend fin packet successfully!\n");
}



void usage(){
	printf("usage: tcp_block <interface> <host>\n");
	printf("example: tcp_block ens33 test.gilgil.net");
}


int main(int argc,char *argv[]){

	if(argc !=3){
		usage();
	}

	char* dev= argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(handle ==NULL){
		fprintf(stderr,"couldn't open device %s: %s\n",dev,errbuf);
		return -1;
	}	
	
	while(true){

		printf("sniff..\n");
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		
		if( res==0) continue;
		if(res==-1||res==2) break;
		
		/* sniff packet*/
		data = (struct packet*)packet;
		if(ntohs(data->type) !=0x0800){
			printf("%02x", data->type);
			printf("packet is not IPV4\n");
			continue;
		}
		if(data->protocol !=0x06){
			printf("packet is not tcp\n");
			continue;
		}

		int ip_header_length = (int)data->header_length*(int)data->version;	
		packet +=14+ip_header_length + (int)data->tcp_header_length*4;
		
		int tcp_payload_size = ntohs((int)data->total_length) - (int)ip_header_length- (int)data->tcp_header_length;
		int size =(int)ip_header_length + (int)data->tcp_header_length;
		string s((char*)packet,tcp_payload_size);
		cout <<s<< endl;
		
		/*fire wall*/
		if(s.find(argv[2])>0){ // ex) test.gilgil.net
			if(data->dest_port!=0x0050){
			/*1. rst packet*/
				printf("send rst packet\n");
				if(send_rst_packet(handle,size,tcp_payload_size,0)==-1) continue;
			}else{
				/*backward rst packet*/
				printf("backward rst packet\n");
				if(send_rst_packet(handle,size,tcp_payload_size,1)==-1) continue;
			}
			if(data->dest_port != 0x0050){
			/*2. fin packet*/
				printf("send fin packet\n");
				if(send_fin_packet(handle,size)==-1) continue;
			}else{
				/*backward fin packet*/
				printf("backward fin packet\n");
				if(send_fin_packet(handle,size)==-1) continue;
			}
		}
	}
}
