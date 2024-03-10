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
#include <thread>
#include <stack>
#include <mutex>
#include <condition_variable>
#include <atomic>

class covert_handler{
public:
    explicit covert_handler(std::string& ip) : ip(ip), shouldRun(true)
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
        queue_condition.notify_all();
        shouldRun = false;
        if (ReplyBuffer != nullptr) {
            free(ReplyBuffer);
        }
        if (handler_thread.joinable()) {
            handler_thread.join();
        }
    }
    void start(){
        handler_thread = std::thread(&covert_handler::covert_message_handler,this);
        handler_thread.detach();
    }
    void add_message(std::string& message)
    {
        {
            std::unique_lock<std::mutex> lock(queueSaftey);
            queue.push(message.c_str());
        }
        queue_condition.notify_one();
    }
    bool should_run(){
        return shouldRun.load();
    }
private:
    std::string ip;
    std::stack<const char*> queue;
    std::mutex queueSaftey;
    std::condition_variable queue_condition;
    std::atomic<bool> shouldRun;
    std::thread handler_thread;
    HANDLE hIcmpFile;
    DWORD dwRetVal = 0;
    unsigned long ipaddr;
    LPVOID ReplyBuffer = nullptr;
    DWORD ReplySize = 0;
    void covert_message_handler()
    {
        while (true)
        {

            size_t chunk_size = 32;
            const char* message = nullptr;
            {
                std::unique_lock<std::mutex> lock(queueSaftey);
                queue_condition.wait(lock, [this] { return !queue.empty(); });
                if (!queue.empty()) {
                    message = queue.top();
                    queue.pop();
                }
            }
            if (message != nullptr) // sender mode
            {
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
            }else{ //listener mode

            }
        }
    }
};
#endif //SETICMP_H
