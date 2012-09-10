#ifndef _SPOOF_DEFS_H_
#define _SPOOF_DEFGS_H_
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/ip.h>

#define IP_PACKET_MIN_SIZE sizeof(ethhdr) + sizeof(iphdr)

#endif
