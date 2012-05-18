#include "send.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <errno.h>

#include <assert.h>

void assemblePacket(unsigned char *packet, unsigned char *sha, unsigned char *spa, unsigned char *tha, unsigned char *tpa);
addresses *getAddresses(char *dev);

void sendPackets(int sockfd, addresses *ourAddresses, int targetIP)
{
    // target is in host byte order.
    // We need to convert it to network byte order.
    unsigned char sha[6], spa[4], tha[6], tpa[4];
    int targetNetwork = targetIP;
    for (int i = 0; i < 6; i++) {
        tha[i] = 0xff;
        sha[i] = ourAddresses->mac[i];
    }
    for (int i = 0; i < 4; i++) {
        spa[i] = ourAddresses->ip[i];
        tpa[i] = (targetNetwork >> (i*8)) & 0xFF;
    }
    //memcpy(sha, ourAddresses->mac, 6);
    //memcpy(spa, ourAddresses->ip, 4);
    unsigned char *packet = (unsigned char *)malloc(42);
    assemblePacket(packet, sha, spa, tha, tpa);
    if (write(sockfd, packet, 42) == -1) {
        fprintf(stderr, "Error writing to socket: errno: %d, %s\n", errno, strerror(errno));
        assert(0 == 1);
    }
    sync();
    free(packet);
}

int getIPAddress(char *dev)
{
    unsigned int ret;
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    int success = 0;
    // retrieve the current interfaces - returns 0 on success
    success = getifaddrs(&interfaces);
    if (success == 0) {
        // Loop through linked list of interfaces
        temp_addr = interfaces;
        while(temp_addr != NULL) {
            if(temp_addr->ifa_addr->sa_family == AF_INET) {
                if (strncmp(temp_addr->ifa_name, dev, strlen(temp_addr->ifa_name)) == 0) {
                    char *address = inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr);
                    if (inet_pton(AF_INET, address, (void *)&ret) != 1) {
                        fprintf(stderr, "ERROR GETTING OUR OWN IP ADDRESS. ABORTING.\n");
                        assert(1 == 0);
                    }
                }
            }
            temp_addr = temp_addr->ifa_next;
        }
    }
    // Free memory
    freeifaddrs(interfaces);
    return ret;
}

addresses *getAddresses(char *dev)
{
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf)) {
        fprintf(stderr, "Error getting device names, %s\n", errbuf);
        return NULL;
    }

    int ip;
    struct sockaddr_dl *link;
    addresses *ret = (addresses *)calloc(1, sizeof(addresses));
    device = alldevs;
    pcap_addr_t list, *a;
    while (device != NULL) {
        if (strncmp(device->name, dev, strlen(device->name)) == 0) {
            // found the device we're looking for.
            list = device->addresses[0];
            for (a = device->addresses; a != NULL; a = a->next) {
                if (a->addr->sa_family == AF_LINK && a->addr->sa_data != NULL) {
                    link = (struct sockaddr_dl*)a->addr->sa_data;
                    unsigned char mac[link->sdl_alen];
                    caddr_t macaddr = LLADDR(link);
                    memcpy(mac, LLADDR(link), link->sdl_alen);
                    if (link->sdl_alen == 6) {
                        for (int i = 0; i < 6; i++)
                            ret->mac[i] = mac[i];
                        //sprintf((char *)ret->mac, "%02x%02x%02x%02x%02x%02x",(unsigned char)mac[0], (unsigned char)mac[1], (unsigned char)mac[2], (unsigned char)mac[3], (unsigned char)mac[4], (unsigned char)mac[5]);
                    } else if (link->sdl_alen > 6) {
                        for (int i = 0; i < 6; i++)
                            ret->mac[i] = mac[i+1];
                        //sprintf((char *)ret->mac, "%02x%02x%02x%02x%02x%02x",(unsigned char)mac[1], (unsigned char)mac[2], (unsigned char)mac[3], (unsigned char)mac[4], (unsigned char)mac[5], (unsigned char)mac[6]);
                    }
                    list = a[0];
                    /*
                    ip = htonl((int)list.addr);
                    for (int i = 0; i < 4; i++)
                        ret->ip[i] = (ip >> i) & 0xFF;
                    */
                    break;
                }
            }
            break;
        }
        device = device->next;
    }
    int ipAddress = getIPAddress(dev);
    for (int i = 0; i < 4; i++) {
        ret->ip[i] = (ipAddress >> (i*8)) & 0xFF;
    }
    return ret;
}

void assemblePacket(unsigned char *packet, unsigned char *sha, unsigned char *spa, unsigned char *tha, unsigned char *tpa)
{
    // hey, this ain't working.
    memcpy((packet), tha, 6);
    memcpy((packet+6), tha, 6);
    // set stuff to 12 and 13...
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x00;
    packet[15] = 0x01; // ethernet layer
    packet[16] = 0x08;
    packet[17] = 0x00; // arp protocol
    packet[18] = 0x06; // mac length
    packet[19] = 0x04; // ipv4 length
    packet[20] = 0x00;
    packet[21] = 0x01; // arp request
    memcpy((packet+22), sha, 6);
    memcpy((packet+28), spa, 4);
    memcpy((packet+32), tha, 6);
    memcpy((packet+38), tpa, 4);
    fprintf(stderr, "DEBUG: packet is:\n\t");
    for (int i = 0; i < 42; i++) {
        if (i == 0 || i == 32)
            fprintf(stderr, " tha:");
        if (i == 6 || i == 22)
            fprintf(stderr, " sha:");
        if (i == 12)
            fprintf(stderr, " eth:");
        if (i == 14)
            fprintf(stderr, " arp:");
        if (i == 28)
            fprintf(stderr, " spa:");
        if (i == 38)
            fprintf(stderr, " tpa:");
        fprintf(stderr, "%02x:", packet[i]);
    }
    fprintf(stderr, "\n");
}
