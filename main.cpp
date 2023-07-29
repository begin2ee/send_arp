#include <cstdio>
#include <pcap.h>
#include <string>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp eth0 192.168.0.1 192.168.0.2\n");
}

Mac getMyMacAddress(const char* dev) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        exit(1);
    }

    close(sock);
    return Mac(ifr.ifr_hwaddr.sa_data);
}

Mac sendArpRequest(const char* dev, Ip target_ip) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return Mac("00:00:00:00:00:00");
    }

    Mac my_mac = getMyMacAddress(dev);
    Mac unknown_mac("00:00:00:00:00:00");

    EthArpPacket packet;

    // Set Ethernet header
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // Broadcast MAC address
    packet.eth_.smac_ = my_mac; // My MAC address

    // Set ARP header
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac; // My MAC address
    packet.arp_.sip_ = htonl(Ip("0.0.0.0")); // Unknown IP address
    packet.arp_.tmac_ = unknown_mac; // Unknown MAC address
    packet.arp_.tip_ = htonl(target_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthArpPacket* arp_packet = (EthArpPacket*)packet;
        if (arp_packet->eth_.type() != EthHdr::Arp) continue;
        if (arp_packet->arp_.op() != htons(ArpHdr::Reply)) continue;
        if (arp_packet->arp_.sip() == htonl(target_ip)) {
            pcap_close(handle);
            return arp_packet->arp_.smac();
        }
    }

    pcap_close(handle);
    return Mac("00:00:00:00:00:00"); // MAC 주소를 받지 못한 경우
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    Ip sender_ip = Ip(argv[2]);
    Ip target_ip = Ip(argv[3]);

    Mac sender_mac = sendArpRequest(dev, sender_ip);
    Mac target_mac = sendArpRequest(dev, target_ip);

    if (sender_mac == Mac("00:00:00:00:00:00") || target_mac == Mac("00:00:00:00:00:00")) {
        printf("Failed to get MAC address.\n");
        return -1;
    }

    printf("Sender IP: %s, Sender MAC: %s\n", std::string(sender_ip).c_str(), std::string(sender_mac).c_str());
    printf("Target IP: %s, Target MAC: %s\n", std::string(target_ip).c_str(), std::string(target_mac).c_str());

    return 0;
}

