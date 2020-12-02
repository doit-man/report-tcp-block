#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#define ETHER_SIZE 14
#define IP_SIZE 20
#define TCP_SIZE 20


char * target;

struct TcpPacket {
	struct libnet_ethernet_hdr ether_;
        struct libnet_ipv4_hdr ip_;
        struct libnet_tcp_hdr tcp_;
        char* data_;
};



void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

int GetMacAddress(char *ifname, uint8_t *mac_addr)
{
	struct ifreq ifr;
	int sockfd, ret;
	sockfd = socket(AF_INET, SOCK_DGRAM,0);
	if(sockfd<0){
		printf("Fail to get interface MAC address\n");
		return -1;
	}
	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
	ret = ioctl(sockfd,SIOCGIFHWADDR,&ifr);
	if (ret < 0){
		printf("Fail to get interface MAC address\n");
		return -1;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data,6);
	
	close(sockfd);
	return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }
	
    char* dev = argv[1];
    target = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    uint8_t my_mac_addr[6];
    GetMacAddress(argv[1],my_mac_addr);
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
	struct libnet_ethernet_hdr* ether;
	struct libnet_ipv4_hdr* ip;
	struct libnet_tcp_hdr* tcp;
	char* data;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

	ether = (struct libnet_ethernet_hdr*)packet;
        ip = (struct libnet_ipv4_hdr*) (packet+ETHER_SIZE);
        tcp = (struct libnet_tcp_hdr*) (packet + ETHER_SIZE+IP_SIZE);
        data = (char*) (packet + ETHER_SIZE+IP_SIZE+TCP_SIZE);
	if(ntohs(ether->ether_type)!= 0x0800) continue;
	if(ip->ip_p != 6)continue;
	//print_info(ether,ip,tcp,data);
	char* pattern = strstr(data,argv[2]);
	if(pattern == NULL) continue;
	TcpPacket FdPacket;
	TcpPacket BkPacket;	
	FdPacket.ether_.ether_dhost[0]= ether->ether_dhost[0];
        FdPacket.ether_.ether_dhost[1]= ether->ether_dhost[1];
        FdPacket.ether_.ether_dhost[2]= ether->ether_dhost[2];
        FdPacket.ether_.ether_dhost[3]= ether->ether_dhost[3];
        FdPacket.ether_.ether_dhost[4]= ether->ether_dhost[4];
        FdPacket.ether_.ether_dhost[5]= ether->ether_dhost[5];
        FdPacket.ether_.ether_shost[0]= my_mac_addr[0];
        FdPacket.ether_.ether_shost[1]= my_mac_addr[1];
        FdPacket.ether_.ether_shost[2]= my_mac_addr[2];
        FdPacket.ether_.ether_shost[3]= my_mac_addr[3];
        FdPacket.ether_.ether_shost[4]= my_mac_addr[4];
        FdPacket.ether_.ether_shost[5]= my_mac_addr[5];
	FdPacket.ether_.ether_type = htons(0x0800);
	FdPacket.ip_ = *ip;
	FdPacket.ip_.ip_sum = 0;
	FdPacket.ip_.ip_len= htons(sizeof(FdPacket.ip_) + sizeof(FdPacket.tcp_));
	FdPacket.tcp_ = *tcp;
	FdPacket.tcp_.th_seq += htons(FdPacket.ip_.ip_len - FdPacket.ip_.ip_hl - (FdPacket.tcp_.th_off*4));
	FdPacket.tcp_.th_flags = 0x04;
	FdPacket.tcp_.th_sum = 0;
	TcpPacket * Fd = &FdPacket;
	unsigned short * Fd_ip_ = (unsigned short *)(Fd+ETHER_SIZE);
	for(int i = 0; i< (sizeof(FdPacket.ip_)/2);i++)
	{
		FdPacket.ip_.ip_sum += (uint16_t)Fd_ip_[i];
	}
	FdPacket.ip_.ip_sum = (FdPacket.ip_.ip_sum &0xffff)+(FdPacket.ip_.ip_sum>>16);
	FdPacket.ip_.ip_sum = (FdPacket.ip_.ip_sum &0xffff)+(FdPacket.ip_.ip_sum>>16);
	
	
	Fd_ip_ = (unsigned short*)(Fd+ETHER_SIZE +IP_SIZE);
	
	for(int i = 0; i< (sizeof(FdPacket.tcp_)/2);i++)
        {
                FdPacket.tcp_.th_sum += (uint16_t)Fd_ip_[i];
		FdPacket.tcp_.th_sum = (FdPacket.tcp_.th_sum &0xffff)+(FdPacket.tcp_.th_sum>>16);
        }



	BkPacket.ether_.ether_dhost[0]= ether->ether_shost[0];
	BkPacket.ether_.ether_dhost[1]= ether->ether_shost[1];
	BkPacket.ether_.ether_dhost[2]= ether->ether_shost[2];
	BkPacket.ether_.ether_dhost[3]= ether->ether_shost[3];
	BkPacket.ether_.ether_dhost[4]= ether->ether_shost[4];
	BkPacket.ether_.ether_dhost[5]= ether->ether_shost[5];
        BkPacket.ether_.ether_shost[0]= my_mac_addr[0];
	BkPacket.ether_.ether_shost[1]= my_mac_addr[1];
	BkPacket.ether_.ether_shost[2]= my_mac_addr[2];
	BkPacket.ether_.ether_shost[3]= my_mac_addr[3];
	BkPacket.ether_.ether_shost[4]= my_mac_addr[4];
	BkPacket.ether_.ether_shost[5]= my_mac_addr[5];
        BkPacket.ether_.ether_type = htons(0x0800);
	BkPacket.ip_ = *ip;
	BkPacket.ip_.ip_len= sizeof(BkPacket.ip_) + sizeof(BkPacket.tcp_)+10;
	BkPacket.ip_.ip_ttl = 128;
	BkPacket.ip_.ip_src = ip->ip_dst;
	BkPacket.ip_.ip_dst = ip->ip_src;
	BkPacket.ip_.ip_sum = 0;
	BkPacket.tcp_ = *tcp;
	BkPacket.tcp_.th_dport = tcp->th_sport;
	BkPacket.tcp_.th_sport = tcp->th_dport;
	BkPacket.tcp_.th_ack = FdPacket.tcp_.th_seq;
	BkPacket.tcp_.th_seq = tcp->th_ack;
	BkPacket.tcp_.th_flags = 0x01;
	BkPacket.data_ = "Blocked!!!";
	BkPacket.tcp_.th_sum = 0;	
	
	TcpPacket * Bk = &BkPacket;
        unsigned short * Bk_ip_ = (unsigned short *)(Bk+ETHER_SIZE);
        for(int i = 0; i< (sizeof(BkPacket.ip_)/2);i++)
        {
                BkPacket.ip_.ip_sum += (uint16_t)Bk_ip_[i];
        }
        BkPacket.ip_.ip_sum = (BkPacket.ip_.ip_sum &0xffff)+(BkPacket.ip_.ip_sum>>16);
        BkPacket.ip_.ip_sum = (BkPacket.ip_.ip_sum &0xffff)+(BkPacket.ip_.ip_sum>>16);

        
        Bk_ip_ = (unsigned short*)(Bk+ETHER_SIZE +IP_SIZE);

        for(int i = 0; i< ((sizeof(BkPacket.tcp_)+10)/2);i++)
        {
                BkPacket.tcp_.th_sum += (uint16_t)Bk_ip_[i];
		BkPacket.tcp_.th_sum = (BkPacket.tcp_.th_sum &0xffff)+(BkPacket.tcp_.th_sum>>16);
        }



	//printf("find!!\n\n");
	int res1= pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&FdPacket),sizeof(FdPacket));
	int res2= pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&BkPacket),sizeof(BkPacket));
	//printf("%d %d\n",res1,res2);
    }    

    pcap_close(handle);
}
