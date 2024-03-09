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
    covert_handler(std::string& ip) : ip(ip)
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
    char* send_covert_message(){
        char* ret;
        ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
        ReplyBuffer = (VOID*) malloc(ReplySize);
        if (ReplyBuffer == NULL) {
            throw std::runtime_error("Failed to allocate memory for reply buffer");
        }
        dwRetVal = IcmpSendEcho(hIcmpFile,
                                ipaddr,
                                SendData,
                                sizeof(SendData),
                                NULL,
                                ReplyBuffer,
                                ReplySize,
                                1000);
        if (dwRetVal != 0) {
            PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
            struct in_addr ReplyAddr;
            ReplyAddr.S_un.S_addr = pEchoReply->Address;
            std::cout <<"\tSent icmp message to %s\n" << ip << '\n';
            if (dwRetVal > 1) {
                std::cout << "\tReceived %ld icmp message responses\n" << dwRetVal <<'\n';
                std::cout << "\tInformation from the first response:\n" << '\n';
            }
            else {
                std::cout <<"\tReceived %ld icmp message response\n" << dwRetVal << '\n';
                std::cout <<"\tInformation from this response:\n" << '\n';
            }
            std::cout <<"\t  Received from %s\n" << inet_ntoa( ReplyAddr ) << '\n';
            std::cout <<"\t  Status = %ld\n" << pEchoReply->Status << '\n';
            std::cout <<"\t  Roundtrip time = %ld milliseconds\n" << pEchoReply->RoundTripTime <<'\n';
        }
        else {
            throw std::runtime_error(&"Failed to send ICMP message " [ GetLastError()]);
        }
        free(ReplyBuffer);
        return ret;
    }
private:
    std::string ip;
    HANDLE hIcmpFile;
    DWORD dwRetVal = 0;
    unsigned long ipaddr;
    LPVOID ReplyBuffer = NULL;
    DWORD ReplySize = 0;
    char SendData[32];
};
#endif //SETICMP_H
