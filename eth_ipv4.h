#ifndef ETH_IPV4_H
#define ETH_IPV4_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct Ipv4Info
{
    uint8_t dscp;         /* IPv4 DSCP field value */
    uint8_t protocol;     /* IPv4 protocol field value */
    bool optionsPresent;  /* Are IPv4 options present in the packet? */
}
Ipv4Info;

/*
 * Parses a raw Ethernet frame (starting at the destination MAC address,
 * without preamble/SFD and FCS being required) that may carry any number
 * of VLAN tags (802.1Q, 802.1ad, legacy 0x9100/0x9200/0x9300 QinQ).
 *
 * Returns true if the frame carries a well-formed IPv4 header and fills
 * *info. Returns false otherwise and leaves *info untouched.
 */
bool ethIpv4Parse (const void* buffer, size_t bufLen, Ipv4Info* info);

#endif /* ETH_IPV4_H */
