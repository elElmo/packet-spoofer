#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <yajl/yajl_parse.h> 
#include <yajl/yajl_gen.h> 

#include "spoof_packet.h"
#include "spoof_defs.h"

#define EXIT_OK 0
#define EXIT_UNKNOWN_ERR -1
#define BASE_TEST_PACKET_BYTES 10

#ifndef DEBUG
#	define DEBUG 0
#endif

#define debug_print(fmt, ...) \
	do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while(0)

struct spoof_packet* createTestPacket(char* msg, const struct sockaddr* src,
	const struct sockaddr* dst);
unsigned short calculateCrc(unsigned short* blob, const int numBytes);

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
	struct spoof_packet* packet = createTestPacket(
		"Hello, this is dog",
		&ifioctl.ifr_hwaddr,
		&ifioctl.ifr_hwaddr
	);
	struct sockaddr_ll dllAddr;
    dllAddr.sll_family = AF_PACKET;
    dllAddr.sll_protocol = 0;
    dllAddr.sll_ifindex = ifIdx;
    dllAddr.sll_hatype = 0;
    dllAddr.sll_pkttype = 0;
    dllAddr.sll_halen = 6;
    memset(dllAddr.sll_addr, 0, 8);        // zeroes out hwaddr
	const struct sockaddr *saPtr;
	size_t saLen;
	saPtr = (struct sockaddr*)&dllAddr;
	saLen = sizeof(dllAddr);
	debug_print("%c\n", packet->buffer[0]);

	int code = sendto(sd, packet->buffer, packet->length, 0, saPtr, saLen);
	debug_print("message be le sent: %d\n", code);
	return EXIT_OK;
}

/**
 * Creates a simple test packet which embeds a
 * message inside a ping packet 
 */
struct spoof_packet* createTestPacket(char* msg, const struct sockaddr* src, 
	const struct sockaddr* dst) {
	//void* buffer = malloc(BASE_TEST_PACKET_BYTES + strlen(msg) * 
	//	sizeof(char));
	struct spoof_packet* poof = malloc(sizeof(struct spoof_packet));
	// construct ethernet frame header
	struct ethhdr ether;
	memcpy(ether.h_dest, dst->sa_data, ETH_ALEN);
	memcpy(ether.h_source, src->sa_data, ETH_ALEN);
	ether.h_proto = htons(ETH_P_IP);
	// construct ip packet header
	struct iphdr ip;
	ip.version = 0x04;
	ip.ihl = 0x05;
	ip.tos = 0x00;
	ip.tot_len = htons(
		sizeof(struct iphdr) + sizeof(struct icmphdr) + strlen(msg) + 1
	);
	//ip.id = random();
	ip.id = 0x00;
	ip.frag_off = 0x00;
	ip.ttl = 0xff;
	ip.protocol = IPPROTO_ICMP;
	ip.check = 0x00;
	ip.saddr = inet_addr("192.0.0.1");
	ip.daddr = inet_addr("10.0.2.1");
	ip.check = 0x00;
	ip.check = calculateCrc((unsigned short*)&ip, sizeof(struct iphdr));
	// construct icmp content
	struct icmphdr icmp;
	icmp.type = ICMP_ECHO;
	icmp.code = 0x00;
	icmp.checksum = 0x00;
	icmp.un.echo.id = 0x00;
	icmp.un.echo.sequence = 0x00;

	poof->length = 
		sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) +
		strlen(msg) + 1;
	char* buffer = malloc(poof->length);
	poof->buffer = buffer;
	memcpy(buffer, &ether, sizeof(struct ethhdr));
	buffer += sizeof(struct ethhdr);
	memcpy(buffer, &ip, sizeof(struct iphdr));
	buffer += sizeof(struct iphdr);
	char* icmpPtr = buffer;
	memcpy(buffer, &icmp, sizeof(struct icmphdr));
	buffer += sizeof(struct icmphdr);
	memcpy(buffer, msg, strlen(msg));
	icmp.checksum = calculateCrc((unsigned short*)icmpPtr, sizeof(struct icmphdr) +
		strlen(msg) + 1	
	);
	memcpy(icmpPtr, &icmp, sizeof(struct icmphdr));

	return poof;
}

unsigned short calculateCrc(unsigned short* blob, const int numBytes) {
	unsigned int checksum = 0;
	for (int i = 0; i < (numBytes / 2); i++) {
		checksum += *blob++;
	}
	if (numBytes & 0x01) {
		checksum += *((char*)blob);
	}
	// one's compliment
	checksum = (checksum >> 16) + (checksum & 0xffff);
	// bit carry
	checksum += (checksum >> 16);
	debug_print("checksum: %x\n", ~checksum);
	return ~checksum;
}
