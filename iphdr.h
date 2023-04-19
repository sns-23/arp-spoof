#pragma once

#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    uint8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
    uint8_t ip_tos;       /* type of service */
    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;
    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
    uint16_t ip_sum;         /* checksum */
    Ip ip_src, ip_dst; /* source and dest address */

	Ip dip() { return ip_dst; }
	Ip sip() { return ip_src; }
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)
