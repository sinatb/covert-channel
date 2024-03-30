//
// Created by sinat on 3/9/2024.
//

#ifndef SETICMP_H
#define SETICMP_H
#include "utils.h"
/* From tcptraceroute, convert a numeric IP address to a string */
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
            print_if_ip(dev->addresses);
            i++;
        }
        int num;
        std::cin >> num;
        for (dev=alldevs,i=0; i<num-1 ;dev=dev->next,i++);

        std::cout << "Opening device " << dev->name << '\n';

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
