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
#include <errno.h>

void assemblePacket(unsigned char *packet, unsigned char *sha, unsigned char *spa, unsigned char *tha, unsigned char *tpa);
addresses *getAddresses(char *dev);

void sendPackets(int sockfd, addresses *ourAddresses, int targetIP)
{
    // target is in host byte order.
    // We need to convert it to network byte order.
    unsigned char sha[6], spa[4], tha[6], tpa[4];
    int targetNetwork = htonl(targetIP);
    for (int i = 0; i < 6; i++) {
        tha[i] = 0xff;
        sha[i] = ourAddresses->mac[i];
    }
    for (int i = 0; i < 4; i++) {
        spa[i] = ourAddresses->ip[i];
    }
    //memcpy(sha, ourAddresses->mac, 6);
    //memcpy(spa, ourAddresses->ip, 4);
    memcpy(tpa, &targetNetwork, 4);
    unsigned char *packet = (unsigned char *)calloc(1, 40);
    assemblePacket(packet, sha, spa, tha, tpa);
    write(sockfd, packet, 40);
    sync();
    free(packet);
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
                    ip = htonl((int)list.addr);
                    for (int i = 0; i < 4; i++)
                        ret->ip[i] = (ip >> i) & 0xFF;
                    break;
                }
            }
            break;
        }
        device = device->next;
    }
    return ret;
}

void assemblePacket(unsigned char *packet, unsigned char *sha, unsigned char *spa, unsigned char *tha, unsigned char *tpa)
{
    // hey, this ain't working.
    memcpy(packet, tha, 6);
    memcpy((packet+6), tha, 6);
    packet[12] = 0x00;
    packet[13] = 0x01; // ethernet layer
    packet[14] = 0x08;
    packet[15] = 0x00; // arp protocol
    packet[16] = 0x06; // mac length
    packet[17] = 0x04; // ipv4 length
    packet[18] = 0x00;
    packet[19] = 0x01; // arp request
    memcpy((packet+20), sha, 6);
    memcpy((packet+26), spa, 4);
    memcpy((packet+30), tha, 6);
    memcpy((packet+36), tpa, 4);
    fprintf(stderr, "DEBUG: packet is:\n\t");
    for (int i = 0; i < 40; i++) {
        if (i == 0 || i == 6)
            fprintf(stderr, " tha:");
        if (i == 12)
            fprintf(stderr, " arp:");
        if (i == 20)
            fprintf(stderr, " sha:");
        if (i == 26)
            fprintf(stderr, " spa:");
        if (i == 30)
            fprintf(stderr, " tha:");
        if (i == 36)
            fprintf(stderr, " tpa:");
        fprintf(stderr, "%02x:", packet[i]);
    }
    fprintf(stderr, "\n");
}
