//
// Created by sinat on 3/30/2024.
//

#ifndef UTILS_H
#define UTILS_H
#include <thread>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <winsock.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <pcap.h>

using namespace std;

#define IPTOSBUFFERS    12
#define PCAP_NETMASK_UNKNOWN 0xFFFFFFFF

char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    _snprintf_s(output[which],
                sizeof(output[which]),
                sizeof(output[which]),
                "%d.%d.%d.%d",p[0], p[1], p[2], p[3]);
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
                   nullptr,
                   0,
                   NI_NUMERICHOST) != 0) address = nullptr;

    return address;
}
void print_if_ip(pcap_addr* addresses){
    pcap_addr_t *a;
    char ip6str[128];
    for(a=addresses;a;a=a->next) {
        cout<< "Address Family: " << a->addr->sa_family << '\n';
        switch(a->addr->sa_family)
        {
            case AF_INET:
                printf("\tAddress Family Name: AF_INET\n");
                if (a->addr)
                    printf("\tAddress: %s\n",
                           iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
                if (a->netmask)
                    printf("\tNetmask: %s\n",
                           iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
                if (a->broadaddr)
                    printf("\tBroadcast Address: %s\n",
                           iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
                if (a->dstaddr)
                    printf("\tDestination Address: %s\n",
                           iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
                break;

            case AF_INET6:
                printf("\tAddress Family Name: AF_INET6\n");
                if (a->addr)
                    printf("\tAddress: %s\n",
                           ip6tos(a->addr, ip6str, sizeof(ip6str)));
                break;

            default:
                printf("\tAddress Family Name: Unknown\n");
                break;
        }
    }
    cout << '\n';
}
#endif //UTILS_H
