#include "eth_ipv4.h"

/*
 * Ethernet frame as passed in `buffer` (no preamble/SFD, FCS optional):
 *
 *   0                 6                 12          14
 *  +-----------------+-----------------+-----------+--------------------
 *  |  Destination    |  Source MAC     | EtherType |  Payload ...
 *  |  MAC (6 B)      |  (6 B)          |  (2 B)    |
 *  +-----------------+-----------------+-----------+--------------------
 *
 * With any number of VLAN tags (4 B each) inserted before the EtherType:
 *
 *  +--------+--------+------+-----+------+-----+     +-----------+---------
 *  | Dst MAC| Src MAC| TPID | TCI | TPID | TCI | ... | EtherType | Payload
 *  |  6 B   |  6 B   | 2 B  | 2 B | 2 B  | 2 B |     |  0x0800   | (IPv4 payload)
 *  +--------+--------+------+-----+------+-----+     +-----------+---------
 *                    |<-VLAN tag->|<-VLAN tag->|
 *
 *  TPID (Tag Protocol Identifier): 0x8100 (802.1Q), 0x88A8 (802.1ad), 0x9100/0x9200/0x9300 (legacy QinQ)
 *  TCI (Tag Control Information):  PCP (3 bits) | DEI (1 bit) | VLAN ID (12 bits)
 *
 * IPv4 header (fields marked * are extracted into Ipv4Info):
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-------+-------+-----------+---+-------------------------------+
 *  |Version|  IHL  |   DSCP*   |ECN|         Total Length          |
 *  +-------+-------+-----------+---+-----+-------------------------+
 *  |         Identification        |Flags|     Fragment Offset     |
 *  +---------------+---------------+-----+-------------------------+
 *  |      TTL      |   Protocol*   |        Header Checksum        |
 *  +---------------+---------------+-------------------------------+
 *  |                       Source Address                          |
 *  +---------------------------------------------------------------+
 *  |                    Destination Address                        |
 *  +---------------------------------------------------------------+
 *  |              Options* (present if IHL > 5) ...                |
 *  +---------------------------------------------------------------+
 */

#define ETH_MAC_LEN             6u
#define ETH_TYPE_LEN            2u
#define ETH_HDR_LEN             (2u * ETH_MAC_LEN + ETH_TYPE_LEN)  /* 14 */
#define VLAN_TAG_LEN            4u                                 /* TPID + TCI */

#define ETHERTYPE_IPV4          0x0800u
#define IPV4_MIN_HDR_LEN        20u
#define IPV4_MIN_IHL            5u /* min packet header length; 5 words = 20 bytes */

/* Tag Protocol Identifiers that mark a VLAN tag in the EtherType position. */
typedef enum VlanTpid
{
    VLAN_TPID_8021Q  = 0x8100,   /* 802.1Q customer tag (C-tag) */
    VLAN_TPID_8021AD = 0x88A8,   /* 802.1ad service tag (S-tag) */
    VLAN_TPID_QINQ1  = 0x9100,   /* legacy, pre-802.1ad QinQ */
    VLAN_TPID_QINQ2  = 0x9200,
    VLAN_TPID_QINQ3  = 0x9300
}
VlanTpid;

static uint16_t readBe16 (const uint8_t* p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static bool isVlanTpid (uint16_t etherType)
{
    switch (etherType)
    {
        case VLAN_TPID_8021Q:
        case VLAN_TPID_8021AD:
        case VLAN_TPID_QINQ1:
        case VLAN_TPID_QINQ2:
        case VLAN_TPID_QINQ3:
            return true;
        default:
            return false;
    }
}

bool ethIpv4Parse (const void* buffer, size_t bufLen, Ipv4Info* info)
{
    if (buffer == NULL || info == NULL || bufLen < ETH_HDR_LEN)
    {
        return false;
    }

    const uint8_t* packet = (const uint8_t*)buffer;

    /* Offset of the current EtherType/TPID field. */
    size_t offset = 2u * ETH_MAC_LEN;
    uint16_t etherType = readBe16(&packet[offset]);

    /* Skip any number of VLAN tags. Each tag is TPID(2) + TCI(2) and is
     * followed by the next EtherType/TPID. The loop is bounded by bufLen,
     * since every iteration advances offset by 4 bytes.
     * Invariant: offset + ETH_TYPE_LEN <= bufLen, so bufLen - offset
     * never underflows. */
    while (isVlanTpid(etherType))
    {
        /* packet is malformed if it doesn't fit a vlan tag and ethtype */
        if (bufLen - offset < VLAN_TAG_LEN + ETH_TYPE_LEN)
        {
            return false;
        }
        offset += VLAN_TAG_LEN;
        etherType = readBe16(&packet[offset]);
    }

    if (etherType != ETHERTYPE_IPV4)
    {
        return false;
    }

    offset += ETH_TYPE_LEN;   /* start of the IPv4 header */

    if (bufLen - offset < IPV4_MIN_HDR_LEN)
    {
        return false;
    }

    const uint8_t* ip_packet = &packet[offset];
    uint8_t version = (uint8_t)(ip_packet[0] >> 4); // ipv4 (0x45) or ipv6 (0x60)
    uint8_t ihl = (uint8_t)(ip_packet[0] & 0x0fu); // least significant half of 1st byte
    size_t hdrLen = (size_t)ihl * 4u; // hdrLen is in words
    uint8_t dscp = (uint8_t)(ip_packet[1] >> 2);          /* upper 6 bits of TOS/DS */
    uint16_t totalLen = readBe16(&ip_packet[2]);
    uint8_t protocol = ip_packet[9];
    bool optionsPresent = (ihl > IPV4_MIN_IHL); // if header len is more than minimum, options are appended at the end

    if (version != 4u || ihl < IPV4_MIN_IHL)
    {
        return false;
    }

    /* The whole header (including options) must be inside the buffer and
     * the IPv4 total length must at least cover the header. */
    if (bufLen - offset < hdrLen || totalLen < hdrLen)
    {
        return false;
    }

    info->dscp = dscp;
    info->protocol = protocol;
    info->optionsPresent = optionsPresent;

    return true;
}
