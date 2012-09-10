#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <yajl/yajl_parse.h> 
#include <yajl/yajl_gen.h> 

#include "include/spoof_packet.h"

#define EXIT_OK 0
#define EXIT_UNKNOWN_ERR -1
#define BASE_TEST_PACKET_BYTES 10

#ifndef DEBUG
#	define DEBUG 0
#endif

#define debug_print(fmt, ...) \
	do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while(0)

struct spoof_packet* createTestPacket(char* msg);

int main(int argc, char** argv) {
	int ifIdx;
	int sd = socket(AF_PACKET, SOCK_RAW, ETHERTYPE_IP);
	debug_print("decriptor is %d\n", sd);

	char* target = "eth2";
	//createTestPacket("hello, yes, this is dog");
	struct ifreq ifioctl;
	memcpy(&ifioctl.ifr_name, target, strlen(target)+1);
	debug_print("getting index for %s\n", ifioctl.ifr_name);
	ioctl(sd, SIOCGIFINDEX, &ifioctl);

	ifIdx = ifioctl.ifr_ifindex;
	debug_print("interface index is %d\n", ifIdx);
	
	debug_print("obtaining hwaddress...%s\n", "");
	ioctl(sd, SIOCGIFHWADDR, &ifioctl);
	debug_print("hwaddress is %s", "");
	if (DEBUG) {
		for (int i = 0; i < 6; i++) {
			fprintf(stderr, "%s%02x", (i == 0? "" : ":"), 
				ifioctl.ifr_hwaddr.sa_data[i] & 0xff); 
		}
		debug_print("%s\n", "");
	}
	struct spoof_packet* packet = createTestPacket("Hello, this is dog");
	
	return EXIT_OK;
}

/**
 * Creates a simple test packet which embeds a
 * message inside a ping packet 
 */
struct spoof_packet* createTestPacket(char* msg) {
	//void* buffer = malloc(BASE_TEST_PACKET_BYTES + strlen(msg) * 
	//	sizeof(char));
	struct spoof_packet* poof = malloc(sizeof(struct spoof_packet));
	return poof;
}
