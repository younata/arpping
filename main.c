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

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int usage(void);
void sendPackets(int sockfd, char *ourMacAddress, int ourIPAddr, int targetIP);
char *getMacAddress(char *dev);

int main(int argc, char *argv[])
{
    char *dev = NULL, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp; // filter.
    bpf_u_int32 mask;
    bpf_u_int32 net; // no need to worry about ipv6 compatibility.
                     // ipv6 doesn't use arp!
    int eger, target, sockfd, sendPacketNo = 1, timeout = 200; // send 1 packet, 200 ms timeout.
    while ((eger = getopt(argc, argv, "c:d:t:")) != -1) {
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
            case '?':
            default:
                return usage();
        }
    }
    argc -= optind;
    argv += optind;

    //inet_pton(AF_INET, argv[0], (void *)&target);

    if (dev == NULL)
        if ((dev = pcap_lookupdev(errbuf)) == NULL) {
            fprintf(stderr, "Can't find default device. Retry with -d <device>\n");
            return 2;
        }
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Could not get netmask for device %s. Error: %s\n", dev, errbuf);
        return 3;
    }
    printf("net: %08x mask: %08x\n", net, mask);
    return 0;
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
        sendPackets(sockfd, getMacAddress(dev), net, target);
        int count = pcap_dispatch(handle, -1, callback, NULL);
        if (count == -1) {
            fprintf(stderr, "Error reading packets.\n");
        }
    }
    pcap_close(handle);
    return 0;
}

int usage(void)
{
    printf("Usage: Write me.\n");
    return -1;
}
