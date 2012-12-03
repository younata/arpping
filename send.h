#ifndef SENDARP_
#define SENDARP_

//#define DEBUG 0

// structs and typedefs

typedef struct STaddresses {
    unsigned char ip[4];
    unsigned char mac[6];
} addresses;

// functions

void sendPackets(int sockfd, addresses *ourAddresses, int targetIP);
addresses *getAddresses(char *dev);

#endif
