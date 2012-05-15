/*
 Arp ping utility.
 Usage: arping -d [device name] -c [number] -t (timeout in milliseconds) host
 Will also scan an entire range, used as: arping 10.10.1.0/24.
*/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <errno.h>
#include <net/if_dl.h>

#include "send.h" // functions for sending arp packets.

// structs and typedefs

typedef struct ethhead {
    char dest[6];
    char source[6];
    char protocol[2];
} ether;

typedef struct arppacket {
    char hardwareType[2]; // always going to be 0x0001
    char protocalType[2]; // always going to be 0x0800
    char six; // hardware address length. Always going to be six
    char four; // ipv4 address length. Always going to be four.
    char oper[2]; // either 1 or 2.
    char sha[6];
    char spa[4];
    char tha[6];
    char tpa[4];
} arp;

// functions not main.

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int usage(char *programName);

int main(int argc, char *argv[])
{
    char *dev = NULL, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp; // filter.
    bpf_u_int32 mask;
    bpf_u_int32 net; // no need to worry about ipv6 compatibility.
                     // ipv6 doesn't use arp!
    // unfortunately, we need to do other hacks to get this info.
    int eger, target, sockfd, sendPacketNo = 1, timeout = 200; // send 1 packet, 200 ms timeout.
    while ((eger = getopt(argc, argv, "c:d:ht:")) != -1) {
        switch (eger) {
            case 'c':
                sendPacketNo = (int)strtol(optarg, NULL, 10);
                break;
            case 'd':
                dev = optarg;
                break;
            case 't':
                timeout = (int)strtol(optarg, NULL, 10);
                break;
            case 'h':
            case '?':
            default:
                return usage(argv[0]);
        }
    }
    argc -= optind;
    argv += optind;

    if (argc == 0) {
        return usage(argv[0]);
    }

    inet_pton(AF_INET, argv[0], (void *)&target);

    if (dev == NULL)
        if ((dev = pcap_lookupdev(errbuf)) == NULL) {
            fprintf(stderr, "Can't find default device. Retry with -d <device>\n");
            return 2;
        }
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Could not get netmask for device %s. Error: %s\n", dev, errbuf);
        return 3;
    }
    if ((handle = pcap_open_live(dev, BUFSIZ, -1, timeout * sendPacketNo, errbuf)) == NULL) {
        fprintf(stderr, "Couldn't open device %s. Error: %s\n", dev, errbuf);
        return 4;
    }
    if (pcap_compile(handle, &fp, "arp", 0, net) == -1) { // We are filtering for arp.
        fprintf(stderr, "Couldn't parse filter. You should not ever see this.\n");
        return 5;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter. You should not ever see this.\n");
        return 5;
    }

    memcpy(&sockfd, handle, sizeof(int));
    // this is all we need from the pcap_t in order to send packets.

    for (eger = 0; eger < sendPacketNo; eger++) {
        sendPackets(sockfd, getAddresses(dev), target);
        int count = pcap_dispatch(handle, -1, callback, (unsigned char *)&target);
        if (count == -1) {
            fprintf(stderr, "Error reading packets.\n");
        }
    }
    pcap_close(handle);
    return 0;
}

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /*
    int ip = (int)*args; // args is just a pointer to an int.
    ether *eth = calloc(1, sizeof(ether));
    memcpy(eth, packet, 14);
    memcpy(arpPacket, (packet+14), 26);
    */
    int i;
    for (i = 0; i < 40; i++) {
        printf("%02x", packet[i]);
    }
    printf("\n");
}

int usage(char *programName)
{
    printf("Usage: %s -c packet_count -d device -t timeout target\nPacket_count is number of packets to send out.\ndevice is the device to use (for example, eth0).\ntimeout is time to wait before considering host to be down.\nTarget is an ipv4 address (e.g. 10.0.0.3).\n", programName);
    return -1;
}
