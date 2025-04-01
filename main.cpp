#include <iostream>
#include <pcap.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <cstring>
#include <limits>
#include <netdb.h>

#ifdef __APPLE__
#define MACOS
#endif

void print_device_info(const char* dev) {
    struct ifaddrs* ifap;
    struct sockaddr_in* addr;

    if (getifaddrs(&ifap) == 0) {
        for (struct ifaddrs* ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_INET) {
                addr = (struct sockaddr_in*)ifa->ifa_addr;
                if (strcmp(ifa->ifa_name, dev) == 0) {
                    std::cout << "Device: " << ifa->ifa_name << std::endl;
                    std::cout << "IP Address: " << inet_ntoa(addr->sin_addr) << std::endl;
                }
            }
        }
        freeifaddrs(ifap);
    } else {
        std::cerr << "Failed to get IP address." << std::endl;
    }
}

void print_hex(const unsigned char* data, size_t len) {
    std::cout << "Packet Data (Hex):\n";
    
    // Define how many bytes to print (e.g., 64 bytes)
    size_t max_bytes_to_print = 64;
    size_t bytes_to_print = std::min(len, max_bytes_to_print);

    for (size_t i = 0; i < bytes_to_print; ++i) {
        printf("%02x ", data[i]);
        if (i % 16 == 15) {
            std::cout << std::endl;
        }
    }
    
    // If the packet is longer than the specified number of bytes, indicate truncation
    if (len > max_bytes_to_print) {
        std::cout << "\n... (more bytes not displayed)" << std::endl;
    }
    
    std::cout << std::endl;
}


void print_ascii(const unsigned char* data, size_t len) {
    std::cout << "Packet Data (ASCII):\n";
    for (size_t i = 0; i < len; ++i) {
        char c = data[i];
        // Only print printable characters (space, letters, digits, symbols)
        if (isprint(c)) {
            std::cout << c;
        } else if (i == len - 1) {
            // Optionally, show a newline at the end of the printable part
            std::cout << std::endl;
        }
    }
    std::cout << std::endl;
}


std::string resolve_ip_to_hostname(const struct in_addr& ip) {
    struct hostent* host = gethostbyaddr(&ip, sizeof(ip), AF_INET);
    return host ? host->h_name : "Unknown Host";
}

void parse_http(const unsigned char* data, size_t len) {
    std::string packet_str((const char*)data, len);
    size_t pos = packet_str.find("GET ");
    if (pos != std::string::npos) {
        size_t end_pos = packet_str.find(" HTTP/1.1", pos);
        if (end_pos != std::string::npos) {
            std::string website = packet_str.substr(pos + 4, end_pos - pos - 4);
            std::cout << "Accessed Website (HTTP GET Request): " << website << std::endl;
        }
    }
}

void parse_dns(const unsigned char* data, size_t len) {
    if (len > 42) {  // Minimum size for DNS packet
        std::string domain_name((const char*)data + 12, len - 12);
        std::cout << "DNS Query for Domain: " << domain_name << std::endl;
    }
}

void packet_handler(unsigned char* user_data, const struct pcap_pkthdr* pkthdr, const unsigned char* packet_data) {
    std::cout << "********** Packet Data Captured **********" << std::endl;
    std::cout << "Captured Packet Length: " << pkthdr->len << " bytes." << std::endl;

#ifdef MACOS
    if (pkthdr->len >= sizeof(struct ip)) {
        struct ip* ip_header = (struct ip*)packet_data;
        std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << " (" << resolve_ip_to_hostname(ip_header->ip_src) << ")" << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << " (" << resolve_ip_to_hostname(ip_header->ip_dst) << ")" << std::endl;

        if (ip_header->ip_p == IPPROTO_TCP && pkthdr->len >= (sizeof(struct ip) + sizeof(struct tcphdr))) {
            struct tcphdr* tcp_header = (struct tcphdr*)(packet_data + ip_header->ip_hl * 4); // Skip IP header
            std::cout << "Source Port: " << ntohs(tcp_header->th_sport) << std::endl;
            std::cout << "Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;

            // Check for HTTP or DNS traffic
            if (ntohs(tcp_header->th_dport) == 80 || ntohs(tcp_header->th_sport) == 80) {
                parse_http(packet_data + sizeof(struct ip) + sizeof(struct tcphdr), pkthdr->len - sizeof(struct ip) - sizeof(struct tcphdr));
            }
        }
    }
#else
    int data_link_type = pcap_datalink(nullptr);
    if (data_link_type == DLT_EN10MB) {
        if (pkthdr->len >= sizeof(struct ether_header)) {
            struct ether_header* eth_header = (struct ether_header*)packet_data;
            std::cout << "Source MAC: ";
            for (int i = 0; i < 6; ++i) {
                printf("%02x", eth_header->ether_shost[i]);
                if (i < 5) {
                    std::cout << ":";
                }
            }
            std::cout << std::endl;
            std::cout << "Destination MAC: ";
            for (int i = 0; i < 6; ++i) {
                printf("%02x", eth_header->ether_dhost[i]);
                if (i < 5) {
                    std::cout << ":";
                }
            }
            std::cout << std::endl;
        }
    }
    
    if (pkthdr->len >= sizeof(struct ip)) {
        struct ip* ip_header = (struct ip*)(packet_data + sizeof(struct ether_header)); // Skip Ethernet header
        std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << " (" << resolve_ip_to_hostname(ip_header->ip_src) << ")" << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << " (" << resolve_ip_to_hostname(ip_header->ip_dst) << ")" << std::endl;

        if (ip_header->ip_p == IPPROTO_TCP && pkthdr->len >= (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr))) {
            struct tcphdr* tcp_header = (struct tcphdr*)(packet_data + sizeof(struct ether_header) + ip_header->ip_hl * 4); // Skip IP header
            std::cout << "Source Port: " << ntohs(tcp_header->th_sport) << std::endl;
            std::cout << "Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;

            // Check for HTTP or DNS traffic
            if (ntohs(tcp_header->th_dport) == 80 || ntohs(tcp_header->th_sport) == 80) {
                parse_http(packet_data + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr), pkthdr->len - sizeof(struct ether_header) - sizeof(struct ip) - sizeof(struct tcphdr));
            }
            else if (ip_header->ip_p == IPPROTO_UDP) {
                parse_dns(packet_data + sizeof(struct ether_header) + sizeof(struct ip), pkthdr->len - sizeof(struct ether_header) - sizeof(struct ip));
            }
        }
    }
#endif

    print_hex(packet_data, pkthdr->len);
    print_ascii(packet_data, pkthdr->len);

    std::cout << "--------------------Packet End---------------------" << std::endl;
}

int main(int argc, char* argv[]) {
    char* dev;

    if (argc >= 2) {
        dev = argv[1];
        print_device_info(dev);
    } else {
        std::cout << "No device name provided." << std::endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding network devices: " << errbuf << std::endl;
        return 1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << dev << ": " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, nullptr);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
