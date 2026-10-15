/*
 * Unit tests for ethIpv4Parse(), using the Unity test framework
 * (vendor/unity). Build and run with `make test`.
 */
#include <stdio.h>
#include <string.h>

#include "unity.h"
#include "eth_ipv4.h"

void setUp (void) {}
void tearDown (void) {}

/* ------------------------------------------------------------------------ */
/* Frame builder                                                            */
/* ------------------------------------------------------------------------ */

#define ETHERTYPE_IPV4   0x0800
#define ETHERTYPE_IPV6   0x86DD
#define TPID_8021Q       0x8100
#define TPID_8021AD      0x88A8
#define TPID_QINQ_9100   0x9100
#define TPID_QINQ_9200   0x9200
#define TPID_QINQ_9300   0x9300

#define ETH_HDR_LEN      14      /* dst MAC + src MAC + EtherType */

#define IPPROTO_ICMP_    1
#define IPPROTO_TCP_     6
#define IPPROTO_UDP_     17

#define MAX_FRAME        2048

typedef struct Frame
{
    uint8_t data[MAX_FRAME];
    size_t len;
}
Frame;

static void put8 (Frame* f, uint8_t v)
{
    f->data[f->len++] = v;
}

static void put16 (Frame* f, uint16_t v)
{
    put8(f, (uint8_t)(v >> 8));
    put8(f, (uint8_t)(v & 0xFF));
}

/* Destination + source MAC. */
static void putMacs (Frame* f)
{
    static const uint8_t dst[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    static const uint8_t src[6] = { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB };
    memcpy(&f->data[f->len], dst, 6); f->len += 6;
    memcpy(&f->data[f->len], src, 6); f->len += 6;
}

/* VLAN tag: TPID + TCI (PCP=3, DEI=0, VID=vid). */
static void putVlan (Frame* f, uint16_t tpid, uint16_t vid)
{
    put16(f, tpid);
    put16(f, (uint16_t)((3u << 13) | (vid & 0x0FFF)));
}

/*
 * IPv4 header with the given version/IHL, TOS byte and protocol, followed by
 * (ihl-5)*4 bytes of options and `payloadLen` bytes of payload.
 */
static void putIpv4Ex (Frame* f, uint8_t version, uint8_t ihl, uint8_t tos,
                       uint8_t protocol, size_t payloadLen)
{
    size_t hdrLen = (size_t)ihl * 4u;
    put8(f, (uint8_t)((version << 4) | (ihl & 0x0F)));
    put8(f, tos);
    put16(f, (uint16_t)(hdrLen + payloadLen));     /* total length */
    put16(f, 0x1234);                              /* identification */
    put16(f, 0x4000);                              /* flags: DF */
    put8(f, 64);                                   /* TTL */
    put8(f, protocol);
    put16(f, 0x0000);                              /* checksum (not checked) */
    put8(f, 192); put8(f, 168); put8(f, 1); put8(f, 1);   /* src */
    put8(f, 192); put8(f, 168); put8(f, 1); put8(f, 2);   /* dst */
    for (size_t i = 20; i < hdrLen; i++)
    {
        put8(f, 0x01);                             /* NOP options */
    }
    for (size_t i = 0; i < payloadLen; i++)
    {
        put8(f, (uint8_t)i);
    }
}

static void putIpv4 (Frame* f, uint8_t ihl, uint8_t tos, uint8_t protocol)
{
    putIpv4Ex(f, 4, ihl, tos, protocol, 8);
}

/* Builds: MACs | nTags VLAN tags (with the given TPIDs) | etherType. */
static void startFrame (Frame* f, const uint16_t* tpids, size_t nTags,
                        uint16_t etherType)
{
    f->len = 0;
    putMacs(f);
    for (size_t i = 0; i < nTags; i++)
    {
        putVlan(f, tpids[i], (uint16_t)(100 + i));
    }
    put16(f, etherType);
}

/* Sentinel used to verify that info stays untouched on failure. */
static const Ipv4Info SENTINEL = { 0xAB, 0xCD, true };

static void assertInfoIsSentinel (const Ipv4Info* info, const char* msg)
{
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(SENTINEL.dscp, info->dscp, msg);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(SENTINEL.protocol, info->protocol, msg);
    TEST_ASSERT_EQUAL_MESSAGE(SENTINEL.optionsPresent, info->optionsPresent, msg);
}

/* Expect failure and untouched output. `msg` identifies the case on failure. */
static void expectRejectMsg (const void* buf, size_t len, const char* msg)
{
    Ipv4Info info = SENTINEL;
    TEST_ASSERT_FALSE_MESSAGE(ethIpv4Parse(buf, len, &info), msg);
    assertInfoIsSentinel(&info, msg);
}

static void expectReject (const void* buf, size_t len)
{
    expectRejectMsg(buf, len, NULL);
}

/* Untagged, valid IPv4/UDP frame used as the base for input-validation tests. */
static void buildValidFrame (Frame* f)
{
    startFrame(f, NULL, 0, ETHERTYPE_IPV4);
    putIpv4(f, 5, 0xB8 /* DSCP 46 */, IPPROTO_UDP_);
}

/* ------------------------------------------------------------------------ */
/* Input validation                                                         */
/* ------------------------------------------------------------------------ */

void test_empty_buffer (void)
{
    Frame f;
    buildValidFrame(&f);
    expectReject(f.data, 0);
}

void test_null_buffer (void)
{
    Frame f;
    buildValidFrame(&f);
    expectRejectMsg(NULL, f.len, "NULL with real length");
    expectRejectMsg(NULL, 0, "NULL with zero length");
}

void test_null_info (void)
{
    Frame f;
    buildValidFrame(&f);
    TEST_ASSERT_FALSE(ethIpv4Parse(f.data, f.len, NULL));
}

/* ------------------------------------------------------------------------ */
/* EtherType                                                                */
/* ------------------------------------------------------------------------ */

void test_ethertype_ipv6 (void)
{
    /* EtherType 0x86DD followed by a minimal IPv6 header (version 6). */
    Frame f;
    startFrame(&f, NULL, 0, ETHERTYPE_IPV6);
    put8(&f, 0x60);
    for (int i = 1; i < 40; i++)
    {
        put8(&f, 0x00);
    }
    expectReject(f.data, f.len);
}

/* ------------------------------------------------------------------------ */
/* VLAN tags                                                                */
/* ------------------------------------------------------------------------ */

void test_vlan_tag_truncated_3_bytes (void)
{
    /* MACs (12) + only 3 of the 4 VLAN tag bytes. */
    static const uint16_t tags[] = { TPID_8021Q };
    Frame f;
    startFrame(&f, tags, 1, ETHERTYPE_IPV4);
    putIpv4(&f, 5, 0, IPPROTO_UDP_);

    expectReject(f.data, 12 + 3);
}

void test_all_vlan_tpids (void)
{
    static const uint16_t tpids[] = { TPID_8021Q, TPID_8021AD, TPID_QINQ_9100,
                                      TPID_QINQ_9200, TPID_QINQ_9300 };
    const size_t count = sizeof tpids / sizeof tpids[0];

    /* Each TPID on its own. */
    for (size_t i = 0; i < count; i++)
    {
        Frame f;
        startFrame(&f, &tpids[i], 1, ETHERTYPE_IPV4);
        putIpv4(&f, 5, 0xB8 /* DSCP 46 */, IPPROTO_TCP_);

        char msg[32];
        snprintf(msg, sizeof msg, "tpid=0x%04X", tpids[i]);
        Ipv4Info info = SENTINEL;
        TEST_ASSERT_TRUE_MESSAGE(ethIpv4Parse(f.data, f.len, &info), msg);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(46, info.dscp, msg);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(IPPROTO_TCP_, info.protocol, msg);
    }

    /* All of them stacked in one frame. */
    Frame f;
    startFrame(&f, tpids, count, ETHERTYPE_IPV4);
    putIpv4(&f, 5, 0xB8, IPPROTO_TCP_);

    Ipv4Info info = SENTINEL;
    TEST_ASSERT_TRUE(ethIpv4Parse(f.data, f.len, &info));
    TEST_ASSERT_EQUAL_UINT8(46, info.dscp);
    TEST_ASSERT_EQUAL_UINT8(IPPROTO_TCP_, info.protocol);
}

void test_vlan_stack_truncated_at_every_byte (void)
{
    /* Two tags: MACs (12) + tag (4) + tag (4) + EtherType (2) = 22 bytes
     * before the IPv4 header. Cutting the frame anywhere in there, including
     * right after a complete tag, must be rejected. */
    static const uint16_t tags[] = { TPID_8021AD, TPID_8021Q };
    Frame f;
    startFrame(&f, tags, 2, ETHERTYPE_IPV4);
    putIpv4(&f, 5, 0, IPPROTO_UDP_);

    for (size_t len = ETH_HDR_LEN; len < 22; len++)
    {
        char msg[32];
        snprintf(msg, sizeof msg, "len=%zu", len);
        expectRejectMsg(f.data, len, msg);
    }
}

/* ------------------------------------------------------------------------ */
/* IPv4 header                                                              */
/* ------------------------------------------------------------------------ */

void test_no_payload_after_ethertype (void)
{
    /* Ethernet header with EtherType IPv4, but the frame ends there. */
    Frame f;
    startFrame(&f, NULL, 0, ETHERTYPE_IPV4);
    TEST_ASSERT_EQUAL_size_t(ETH_HDR_LEN, f.len);

    expectReject(f.data, f.len);
}

void test_ipv4_header_truncated_15_bytes (void)
{
    /* Only 15 of the 20 mandatory IPv4 header bytes are present. */
    Frame f;
    buildValidFrame(&f);
    expectReject(f.data, ETH_HDR_LEN + 15);
}

void test_ihl_less_than_min (void)
{
    for (uint8_t ihl = 0; ihl < 5; ihl++)
    {
        Frame f;
        startFrame(&f, NULL, 0, ETHERTYPE_IPV4);
        putIpv4Ex(&f, 4, ihl, 0, IPPROTO_UDP_, 40);

        char msg[32];
        snprintf(msg, sizeof msg, "ihl=%u", ihl);
        expectRejectMsg(f.data, f.len, msg);
    }
}

void test_wrong_ip_version (void)
{
    /* EtherType says IPv4, but the version nibble in the IP header does not. */
    static const uint8_t versions[] = { 0, 5, 6, 15 };
    for (size_t i = 0; i < sizeof versions; i++)
    {
        Frame f;
        startFrame(&f, NULL, 0, ETHERTYPE_IPV4);
        putIpv4Ex(&f, versions[i], 5, 0, IPPROTO_UDP_, 8);

        char msg[32];
        snprintf(msg, sizeof msg, "version=%u", versions[i]);
        expectRejectMsg(f.data, f.len, msg);
    }
}

void test_total_length_smaller_than_header (void)
{
    /* IHL 6 = 24-byte header, but Total Length claims only 20 bytes. */
    Frame f;
    startFrame(&f, NULL, 0, ETHERTYPE_IPV4);
    size_t ipStart = f.len;
    putIpv4(&f, 6, 0, IPPROTO_UDP_);
    f.data[ipStart + 2] = 0x00;
    f.data[ipStart + 3] = 20;

    expectReject(f.data, f.len);
}

void test_ipv4_options_truncated (void)
{
    /* IHL 8 = 32-byte header (12 bytes of options). The 20-byte minimum is
     * present, but the buffer ends inside the options. */
    Frame f;
    startFrame(&f, NULL, 0, ETHERTYPE_IPV4);
    size_t ipStart = f.len;
    putIpv4(&f, 8, 0, IPPROTO_UDP_);

    for (size_t len = ipStart + 20; len < ipStart + 32; len++)
    {
        char msg[32];
        snprintf(msg, sizeof msg, "len=%zu", len);
        expectRejectMsg(f.data, len, msg);
    }

    /* Exactly the full header is enough. */
    Ipv4Info info = SENTINEL;
    TEST_ASSERT_TRUE(ethIpv4Parse(f.data, ipStart + 32, &info));
    TEST_ASSERT_TRUE(info.optionsPresent);
}

/* ------------------------------------------------------------------------ */
/* Parsed fields                                                            */
/* ------------------------------------------------------------------------ */

void test_parses_dscp (void)
{
    /* Every DSCP value, with both ECN bits set: they must not leak into DSCP. */
    for (unsigned dscp = 0; dscp < 64; dscp++)
    {
        Frame f;
        startFrame(&f, NULL, 0, ETHERTYPE_IPV4);
        putIpv4(&f, 5, (uint8_t)((dscp << 2) | 0x03), IPPROTO_UDP_);

        char msg[32];
        snprintf(msg, sizeof msg, "dscp=%u", dscp);
        Ipv4Info info = SENTINEL;
        TEST_ASSERT_TRUE_MESSAGE(ethIpv4Parse(f.data, f.len, &info), msg);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(dscp, info.dscp, msg);
    }
}

void test_parses_protocol (void)
{
    static const uint8_t protos[] = { IPPROTO_ICMP_, IPPROTO_TCP_, IPPROTO_UDP_, 255 };
    for (size_t i = 0; i < sizeof protos; i++)
    {
        Frame f;
        startFrame(&f, NULL, 0, ETHERTYPE_IPV4);
        putIpv4(&f, 5, 0, protos[i]);

        char msg[32];
        snprintf(msg, sizeof msg, "protocol=%u", protos[i]);
        Ipv4Info info = SENTINEL;
        TEST_ASSERT_TRUE_MESSAGE(ethIpv4Parse(f.data, f.len, &info), msg);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(protos[i], info.protocol, msg);
    }
}

void test_parses_options_absent (void)
{
    /* IHL 5: 20-byte header, no options. */
    Frame f;
    startFrame(&f, NULL, 0, ETHERTYPE_IPV4);
    putIpv4(&f, 5, 0, IPPROTO_UDP_);

    Ipv4Info info = SENTINEL;    /* sentinel has optionsPresent = true */
    TEST_ASSERT_TRUE(ethIpv4Parse(f.data, f.len, &info));
    TEST_ASSERT_FALSE(info.optionsPresent);
}

void test_parses_options_present (void)
{
    /* IHL 6 (smallest with options) and 15 (largest). */
    static const uint8_t ihls[] = { 6, 15 };
    for (size_t i = 0; i < sizeof ihls; i++)
    {
        Frame f;
        startFrame(&f, NULL, 0, ETHERTYPE_IPV4);
        putIpv4(&f, ihls[i], 0, IPPROTO_UDP_);

        char msg[32];
        snprintf(msg, sizeof msg, "ihl=%u", ihls[i]);
        Ipv4Info info = { 0, 0, false };
        TEST_ASSERT_TRUE_MESSAGE(ethIpv4Parse(f.data, f.len, &info), msg);
        TEST_ASSERT_TRUE_MESSAGE(info.optionsPresent, msg);
    }
}

/* ------------------------------------------------------------------------ */
/* Raw frame                                                                */
/* ------------------------------------------------------------------------ */

void test_raw_byte_frame (void)
{
    /* Complete frame written out byte by byte, as it appears on the wire:
     * 802.1Q VID 10, IPv4/TCP SYN, DSCP AF41 (34), no options. */
    static const uint8_t frame[] = {
        0x00, 0x1b, 0x21, 0x3a, 0x4f, 0x10,   /* dst MAC */
        0x00, 0x0c, 0x29, 0x6d, 0x1e, 0x22,   /* src MAC */
        0x81, 0x00, 0x60, 0x0a,               /* 802.1Q, PCP 3, VID 10 */
        0x08, 0x00,                           /* EtherType IPv4 */
        0x45, 0x88, 0x00, 0x28,               /* v4, IHL 5, TOS 0x88, len 40 */
        0x1c, 0x46, 0x40, 0x00,               /* id, flags DF */
        0x40, 0x06, 0x00, 0x00,               /* TTL 64, proto TCP, checksum */
        0x0a, 0x00, 0x00, 0x01,               /* src 10.0.0.1 */
        0x0a, 0x00, 0x00, 0x02,               /* dst 10.0.0.2 */
        0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,   /* TCP 1234 -> 80 */
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,   /* SYN */
        0x00, 0x00, 0x00, 0x00,
    };

    Ipv4Info info = SENTINEL;
    TEST_ASSERT_TRUE(ethIpv4Parse(frame, sizeof frame, &info));
    TEST_ASSERT_EQUAL_UINT8(34, info.dscp);
    TEST_ASSERT_EQUAL_UINT8(IPPROTO_TCP_, info.protocol);
    TEST_ASSERT_FALSE(info.optionsPresent);
}

/* ------------------------------------------------------------------------ */

int main (void)
{
    UNITY_BEGIN();

    RUN_TEST(test_empty_buffer);
    RUN_TEST(test_null_buffer);
    RUN_TEST(test_null_info);

    RUN_TEST(test_ethertype_ipv6);

    RUN_TEST(test_vlan_tag_truncated_3_bytes);
    RUN_TEST(test_all_vlan_tpids);
    RUN_TEST(test_vlan_stack_truncated_at_every_byte);

    RUN_TEST(test_no_payload_after_ethertype);
    RUN_TEST(test_ipv4_header_truncated_15_bytes);
    RUN_TEST(test_ihl_less_than_min);
    RUN_TEST(test_wrong_ip_version);
    RUN_TEST(test_total_length_smaller_than_header);
    RUN_TEST(test_ipv4_options_truncated);

    RUN_TEST(test_parses_dscp);
    RUN_TEST(test_parses_protocol);
    RUN_TEST(test_parses_options_absent);
    RUN_TEST(test_parses_options_present);

    RUN_TEST(test_raw_byte_frame);

    return UNITY_END();
}
