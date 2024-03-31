//
// Created by sinat on 3/9/2024.
//

#ifndef SETICMP_H
#define SETICMP_H
#include "utils.h"
class covert_handler{
public:

    explicit covert_handler( string& ip) : ip(ip)
    {
        ipaddr = inet_addr(ip.c_str());
        if (ipaddr == INADDR_NONE) {
            throw runtime_error("Invalid IP address");
        }
        hIcmpFile = IcmpCreateFile();
        if (hIcmpFile == INVALID_HANDLE_VALUE) {
            throw runtime_error("Failed to create ICMP file handle");
        }
        set_pcap_if();
        thread receiver_thread(&covert_handler::receive_message,this);
        receiver_thread.detach();
    }
    void send_message(const char* message){
        size_t chunk_size = 32;
        size_t message_size = strlen(message);
        for (size_t offset = 0; offset < message_size; offset += chunk_size) {
            char SendData[32] = {0};
            size_t bytes_to_copy =  min(chunk_size, message_size - offset);
            memcpy(SendData, message + offset, bytes_to_copy);

            ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
            ReplyBuffer = (VOID *) malloc(ReplySize);
            if (ReplyBuffer == nullptr) {
                throw runtime_error("Failed to allocate memory for reply buffer");
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
                cout << "Reply from\n" << inet_ntoa(ReplyAddr) << '\n'
                        << "is : " <<  string((char *) (pEchoReply->Data), bytes_to_copy) << '\n';
            } else {
                throw runtime_error(&"Failed to send ICMP message "[GetLastError()]);
            }
        }
    }
    static void print_stats()
    {
        for(const auto& p_if : covert_handler::pkt_inf)
        {
            cout << p_if;
        }
    }
    static void print_data()
    {
        for (const auto& p_ms : covert_handler::pkt_msg)
        {
            cout << p_ms;
        }
    }
    ~covert_handler(){
        IcmpCloseHandle(hIcmpFile);
        if (ReplyBuffer != nullptr) {
            free(ReplyBuffer);
        }
        pcap_close(handle);
    }

private:
    std::string ip;
    HANDLE hIcmpFile;
    DWORD dwRetVal = 0;
    unsigned long ipaddr;
    LPVOID ReplyBuffer = nullptr;
    DWORD ReplySize = 0;
    pcap_t *handle;
    pcap_if_t * alldevs;
    pcap_if_t * dev;
    inline static vector<string> pkt_inf {};
    inline static vector<string> pkt_msg{};

    void set_pcap_if()
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        // Find all available network interfaces
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            throw runtime_error("Error finding devices: " +  string(errbuf));
        }
        int i = 1;
        // Iterate over the list of network interfaces
        for (dev = alldevs; dev != nullptr; dev = dev->next) {
            cout << "Number: " << i << '\n';
            cout << "Interface: " << dev->name << '\n';
            cout << "Description: " << dev->description << '\n';
            print_if_ip(dev->addresses);
            i++;
        }
        int num;
        cin >> num;
        for (dev=alldevs,i=0; i<num-1 ;dev=dev->next,i++);
        cout << "Opening device " << dev->name << '\n';
        handle = pcap_open_live(dev->name,65536,1,1000,errbuf);
        if (handle == nullptr)
        {
            pcap_freealldevs(alldevs);
            throw runtime_error("Unable to open the adapter " +  string(dev->name));
        }
        pcap_freealldevs(alldevs);
        // Compile the filter expression
        u_long netmask=((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
        if (dev->addresses == nullptr)
            netmask = PCAP_NETMASK_UNKNOWN;
        struct bpf_program fp{};
        if (pcap_compile(handle, &fp, "icmp", 0, netmask) == -1) {
            throw runtime_error("Error compiling filter: " +  string(pcap_geterr(handle)));
        }
        // Set the filter
        if (pcap_setfilter(handle, &fp) == -1) {
            throw runtime_error("Error setting filter: " +  string(pcap_geterr(handle)));
        }
    }
    void receive_message()
    {
        pcap_loop(handle, 0,packet_handler, nullptr);
    }
    static void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
    {
       u_char type = pkt_data[34];
       u_char code = pkt_data[35];
       string info = "Source Ip : " + to_string((int) pkt_data[26]) + "." +
                               to_string((int) pkt_data[27]) + "." +
                               to_string((int) pkt_data[28]) + "." +
                               to_string((int) pkt_data[29]) + " " +
                               "Type : " + to_string((int)(type)) + " " +
                               "Code : " + to_string((int)(code)) + " " +
                               '\n';
       pkt_inf.push_back(info);
       string data;
       int payload_length = header->len - 14 - 20 - 8;
       if (payload_length > 0) {
            for (int i = 42; i < header->len; ++i)
            {
                data+=(char) pkt_data[i];
            }
            data += '\n';
       }
       pkt_msg.push_back(data);
    }

};

#endif //SETICMP_H
