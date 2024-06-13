#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <fstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <cstring>
#include <arpa/inet.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

void usage() {
    printf("syntax: tcp-block <interface> <pattern>\n");
    printf("sample: tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

bool get_s_mac(const char* dev, char* mac) {
    std::ifstream mac_file("/sys/class/net/" + std::string(dev) + "/address");
    if (!mac_file.is_open()) {
        return false;
    }
    mac_file >> mac;
    return true;
}

uint16_t checksum(uint16_t* ptr, int len) {
    uint32_t sum = 0;
    uint16_t odd = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1) {
        *(uint8_t *)(&odd) = (*(uint8_t *)ptr);
        sum += odd;
    }

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

void dump(char* packet) {
    EthHdr* eth = (EthHdr*)packet;
    IpHdr* ip = (IpHdr*)(packet + sizeof(EthHdr));
    TcpHdr* tcp = (TcpHdr*)(packet + sizeof(EthHdr) + ip->header_len());
    const char* payload = (const char*)(packet + sizeof(EthHdr) + ip->header_len() + tcp->header_len());

    printf("Ethernet Header\n");
    printf("  |- Destination MAC : %s\n", eth->dmac_.operator std::string().c_str());
    printf("  |- Source MAC      : %s\n", eth->smac_.operator std::string().c_str());
    printf("  |- Protocol        : %u\n", eth->type());

    printf("IP Header\n");
    printf("  |- IP Version      : %u\n", ip->ip_v);
    printf("  |- IP Header Length: %u DWORDS or %u Bytes\n", ip->header_len(), ip->header_len());
    printf("  |- Type Of Service  : %u\n", ip->dscp_and_ecn);
    printf("  |- IP Total Length   : %u Bytes(Size of Packet)\n", ntohs(ip->total_length));
    printf("  |- Identification    : %u\n", ntohs(ip->identification));
    printf("  |- TTL      : %u\n", ip->ttl);
    printf("  |- Protocol : %u\n", ip->protocol);
    printf("  |- Checksum : %u\n", ntohs(ip->checksum));
    printf("  |- Source IP        : %s\n", ip->sip().operator std::string().c_str());
    printf("  |- Destination IP   : %s\n", ip->dip().operator std::string().c_str());

    printf("TCP Header\n");
    printf("  |- Source Port      : %u\n", ntohs(tcp->sport_));
    printf("  |- Destination Port : %u\n", ntohs(tcp->dport_));
    printf("  |- Sequence Number    : %u\n", ntohl(tcp->seq_));
    printf("  |- Acknowledge Number : %u\n", ntohl(tcp->ack_));
    printf("  |- Header Length      : %u DWORDS or %u BYTES\n", tcp->hlen_ >> 4, tcp->header_len());
    printf("  |- Urgent Flag          : %u\n", tcp->flags_ & TcpHdr::URG >> 5);
    printf("  |- Acknowledgement Flag : %u\n", tcp->flags_ & TcpHdr::ACK >> 4);
    printf("  |- Push Flag            : %u\n", tcp->flags_ & TcpHdr::PSH >> 3);
    printf("  |- Reset Flag           : %u\n", tcp->flags_ & TcpHdr::RST >> 2);
    printf("  |- Synchronise Flag     : %u\n", tcp->flags_ & TcpHdr::SYN >> 1);
    printf("  |- Finish Flag          : %u\n", tcp->flags_ & TcpHdr::FIN >> 0);
    printf("  |- Window         : %u\n", ntohs(tcp->win_));
    printf("  |- Checksum       : %u\n", ntohs(tcp->sum_));
    printf("  |- Urgent Pointer : %u\n", ntohs(tcp->urp_));
    printf("  |- Payload        : %ld\n", strlen(payload));
    printf("    %s\n", payload);
}

void send_packet(pcap_t* handle, const char* dev, EthHdr* eth, IpHdr* ip, TcpHdr* tcp, const char* payload, int recv_len, bool is_forward) {
    char mac[18];
    int eth_len = sizeof(EthHdr);
    int ip_len = ip->header_len();
    int tcp_len = tcp->header_len();
    int payload_len = strlen(payload);

    printf("\n\npayload_len: %d\n", payload_len);
    
    int base_packet_len = eth_len + ip_len + tcp_len + payload_len;

    while (!get_s_mac(dev, mac)) {
        printf("Failed to get source MAC address\n");
    }

    EthHdr new_eth;
    IpHdr new_ip;
    TcpHdr new_tcp;

    // Construct Ethernet header
    memcpy(&new_eth, eth, eth_len);
    if (!is_forward) {
        new_eth.dmac_ = eth->smac_;
    }
    new_eth.smac_ = Mac(mac);
    // if (!is_forward) {
    //     new_eth.dmac_ = eth->dmac_;
    //     new_eth.smac_ = eth->smac_;
    // } else {
    //     new_eth.dmac_ = eth->dmac_;
    //     new_eth.smac_ = eth->smac_;
    // }

    // Construct IP header
    memcpy(&new_ip, ip, ip_len);
    if (!is_forward) {
        new_ip.sip_ = ip->dip_;
        new_ip.dip_ = ip->sip_;
        new_ip.ttl = 128;
    }
    new_ip.checksum = 0;

    printf("new_ip.total_length: %d\n", ntohs(new_ip.total_length));
    printf("%d %d %d\n", ip_len, tcp_len, payload_len);

    // Construct TCP header
    memcpy(&new_tcp, tcp, sizeof(TcpHdr));
    if (is_forward) {
        new_tcp.flags_ = TcpHdr::RST | TcpHdr::ACK;
        new_tcp.seq_ = htonl(ntohl(tcp->seq_) + recv_len);
    } else {
        new_tcp.sport_ = tcp->dport_;
        new_tcp.dport_ = tcp->sport_;
        new_tcp.flags_ = TcpHdr::FIN | TcpHdr::ACK | TcpHdr::PSH;
        new_tcp.seq_ = tcp->ack_;
        new_tcp.ack_ = htonl(ntohl(tcp->seq_) + recv_len);
    };
    new_tcp.hlen_ = (sizeof(TcpHdr) / 4) << 4;
    new_tcp.win_ = 0;
    new_tcp.urp_ = 0;
    new_tcp.sum_ = 0;

    // update tcp length
    tcp_len = new_tcp.header_len();
    base_packet_len = eth_len + ip_len + tcp_len + payload_len;
    new_ip.total_length = htons(ip_len + tcp_len + payload_len);

    pseudo_header psh;
    psh.source_address = new_ip.sip_;
    psh.dest_address = new_ip.dip_;
    psh.placeholder = 0;
    psh.protocol = IpHdr::TCP;
    psh.tcp_length = htons(tcp_len + payload_len);

    char *buffer = (char *)malloc(sizeof(pseudo_header) + tcp_len + payload_len);
    memcpy(buffer, &psh, sizeof(pseudo_header));
    memcpy(buffer + sizeof(pseudo_header), &new_tcp, tcp_len);
    memcpy(buffer + sizeof(pseudo_header) + tcp_len, payload, payload_len);

    new_tcp.sum_ = checksum((uint16_t*)buffer, sizeof(buffer));
    new_ip.checksum = checksum((uint16_t*)&new_ip, ip_len);

    char *packet = (char *)malloc(base_packet_len);
    memcpy(packet, &new_eth, eth_len);
    memcpy(packet + eth_len, &new_ip, ip_len);
    memcpy(packet + eth_len + ip_len, &new_tcp, tcp_len);
    memcpy(packet + eth_len + ip_len + tcp_len, payload, payload_len);

    dump(packet);

    if (!is_forward) {
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd < 0) {
            fprintf(stderr, "socket return %d error=%s\n", sockfd, strerror(errno));
            return;
        }

        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = new_tcp.sport();
        sin.sin_addr.s_addr = new_ip.sip();

        if (sendto(sockfd, (unsigned char*)(packet + eth_len), ntohs(new_ip.total_length), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
            perror("sendto failed");
        }
        
        close(sockfd);
    } else {
        if (pcap_sendpacket(handle, (const u_char*)packet, base_packet_len) != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", -1, pcap_geterr(handle));
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    const char* dev = argv[1];
    const char* pattern = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthHdr* eth = (EthHdr*)packet;
        if (eth->type() != EthHdr::Ip4) continue;

        IpHdr* ip = (IpHdr*)(packet + sizeof(EthHdr));
        if (ip->protocol != IpHdr::TCP) continue;

        TcpHdr* tcp = (TcpHdr*)(packet + sizeof(EthHdr) + sizeof(IpHdr));
        int eth_len = sizeof(EthHdr);
        int ip_len = ip->header_len();
        int tcp_len = tcp->header_len();
        int payload_len = ntohs(ip->total_length) - ip_len - tcp_len;
        const char* payload = (const char*)(packet + eth_len + ip_len + tcp_len);
        const char *new_payload = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n ";

        if (strncmp(payload, "GET", 3) != 0) continue;
        for (int i = 0; i < 50; i++) {
            if (strncmp(payload + i, pattern, strlen(pattern)) == 0) {
                printf("Block! %s\n", pattern);

                printf("payload_len: %d\n", payload_len);

                send_packet(handle, dev, eth, ip, tcp, "", payload_len, true);
                send_packet(handle, dev, eth, ip, tcp, new_payload, payload_len, false);

                break;
            }
        }
    }

    pcap_close(handle);
    return 0;
}
