#ifndef SENDARP_
#define SENDARP_

// structs and typedefs

struct addresses_s {
    unsigned char ip[4];
    unsigned char mac[6];
} addresses_s;
typedef struct addresses_s addresses;

// functions

void sendPackets(int sockfd, addresses *ourAddresses, int targetIP);
addresses *getAddresses(char *dev);

#endif
