//
// Created by sinat on 3/9/2024.
//

#ifndef SETICMP_H
#define SETICMP_H
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <iostream>
#include <stdexcept>
#include <pcap.h>
#include <ws2tcpip.h>

/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    _snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]),"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

#ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
#else
    sockaddrlen = sizeof(struct sockaddr_storage);
#endif


    if(getnameinfo(sockaddr,
                   sockaddrlen,
                   address,
                   addrlen,
                   NULL,
                   0,
                   NI_NUMERICHOST) != 0) address = NULL;

    return address;
}
class covert_handler{
public:
    explicit covert_handler(std::string& ip) : ip(ip)
    {
        ipaddr = inet_addr(ip.c_str());
        if (ipaddr == INADDR_NONE) {
            throw std::runtime_error("Invalid IP address");
        }
        hIcmpFile = IcmpCreateFile();
        if (hIcmpFile == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Failed to create ICMP file handle");
        }
    }
    void send_message(const char* message){
        size_t chunk_size = 32;
        size_t message_size = strlen(message);
        for (size_t offset = 0; offset < message_size; offset += chunk_size) {
            char SendData[32] = {0};
            size_t bytes_to_copy = std::min(chunk_size, message_size - offset);
            memcpy(SendData, message + offset, bytes_to_copy);

            ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
            ReplyBuffer = (VOID *) malloc(ReplySize);
            if (ReplyBuffer == nullptr) {
                throw std::runtime_error("Failed to allocate memory for reply buffer");
            }
            dwRetVal = IcmpSendEcho(hIcmpFile,
                                    ipaddr,
                                    SendData,
                                    sizeof(SendData),
                                    nullptr,
                                    ReplyBuffer,
                                    ReplySize,
                                    1000);

            if (dwRetVal != 0) {
                auto pEchoReply = (PICMP_ECHO_REPLY) ReplyBuffer;
                struct in_addr ReplyAddr{};
                ReplyAddr.S_un.S_addr = pEchoReply->Address;
                std::cout << "Reply from\n" << inet_ntoa(ReplyAddr) << '\n'
                          << "is : " << std::string((char *) (pEchoReply->Data), bytes_to_copy) << '\n';
            } else {
                throw std::runtime_error(&"Failed to send ICMP message "[GetLastError()]);
            }
        }
    }
    void receive_message()
    {
        pcap_addr_t *a;
        char ip6str[128];
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *alldevs;
        pcap_if_t *dev;
        pcap_t *handle;
        // Find all available network interfaces
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            throw std::runtime_error("Error finding devices: " + std::string(errbuf));
        }
        int i = 1;
        // Iterate over the list of network interfaces
        for (dev = alldevs; dev != NULL; dev = dev->next) {
            std::cout << "Number: " << i << '\n';
            std::cout << "Interface: " << dev->name << '\n';
            std::cout << "Description: " << dev->description << '\n';
            for(a=dev->addresses;a;a=a->next) {
                printf("\tAddress Family: #%d\n",a->addr->sa_family);

                switch(a->addr->sa_family)
                {
                    case AF_INET:
                        printf("\tAddress Family Name: AF_INET\n");
                        if (a->addr)
                            printf("\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
                        if (a->netmask)
                            printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
                        if (a->broadaddr)
                            printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
                        if (a->dstaddr)
                            printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
                        break;

                    case AF_INET6:
                        printf("\tAddress Family Name: AF_INET6\n");
                        if (a->addr)
                            printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
                        break;

                    default:
                        printf("\tAddress Family Name: Unknown\n");
                        break;
                }
            }
            printf("\n");
            i++;
        }
        int num;
        std::cin >> num;
        for (dev=alldevs,i=0; i<num-1 ;dev=dev->next,i++);
        std::cout<<num;

        handle = pcap_open_live(dev->name,65536,1,1000,errbuf);
        if (handle == nullptr)
        {
            pcap_freealldevs(alldevs);
            throw std::runtime_error("Unable to open the adapter " + std::string(dev->name));
        }
        pcap_freealldevs(alldevs);
        pcap_loop(handle, 0, packet_handler, NULL);
    }
    ~covert_handler(){
        IcmpCloseHandle(hIcmpFile);
        if (ReplyBuffer != nullptr) {
            free(ReplyBuffer);
        }
    }

private:
    std::string ip;
    HANDLE hIcmpFile;
    DWORD dwRetVal = 0;
    unsigned long ipaddr;
    LPVOID ReplyBuffer = nullptr;
    DWORD ReplySize = 0;
    static void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
    {
        std::cout << "recieved packet" << '\n';
    }
};
#endif //SETICMP_H
