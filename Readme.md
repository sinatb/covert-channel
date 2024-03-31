# Covert Channel

The following project is an implementation of ICMP based covert channel in c++ language.

## How it works

At the start of the program, The user has to provide the IP address of the other device running the program. And also 
the interface which the requests are sent from.
The program has 4 main commands.
- `stats`
- `data`
- `send`
- `exit`

The `send <MSG>` command, sends the `<MSG>` to the specified IP. This Message is hidden in the data part of the ICMP
packet. By default, this part of the header is used for storing error information. When using the `ping` command in 
windows or linux the value of this field is a constant string.

The `stats` command returns a list of all the Messages sent to and received from the specified IP.

The `data` command returns the messages received from the specified IP.

## Implementation

The main component of this program is the `covert_handler` class. The constructor of this class receives the IP address 
of the other host and creates an ICMP handle and a pcap handle.

The ICMP handle is used to send the echo requests via 
`IcmpSendEcho` implemented in `icmpapi.h`, A windows specific header with some ICMP functionality.
The sending algorithm is pretty straight forward. The Message is broken into 32 byte parts. After that each part is sent
inside the data part of a request.

For receiving the pcap handle is created over the interface specified by the user. A
bpf filter is set to call the handler only when the received packet is of ICMP type and the src IP is equal to the IP 
specified at the start of the program. The handler stores the data and status of each packet received. The Type, Code,
source IP and payload data is extracted with regard to the ipv4 Packet structure.

The packet structure is :
```c++
Ethernet Header (14 bytes)
IPv4 Header (20 bytes)
ICMP Header (8 bytes)
ICMP Payload (variable size)
```
so the bytes 26-29 are the source IP, bytes 34 and 35 are the Type and code and from byte 42 (14+20+8) to the end is the
received data.

The main function in the receiving part is `pcap_loop`. This function is a blocking function, and therefore it is run on
a different thread from the main thread. This function receives the packets and calls the handler on the packets passing
the filter.

The `utils.h` file stores some useful functions from pcap documentation for printing the network interfaces and their ip
addresses.

## Further work

- Adding support for ipv6
- Adding data Encryption
- Adding Reliability to the channel
