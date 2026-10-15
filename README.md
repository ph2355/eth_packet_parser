# Ethernet IPv4 parser

```c
bool ethIpv4Parse (const void* buffer, size_t bufLen, Ipv4Info* info);
```

Parses a raw Ethernet frame with any number of VLAN tags (`0x8100`, `0x88A8`,
`0x9100`/`0x9200`/`0x9300`). Returns `true` for a well-formed IPv4 packet and
fills `info` with DSCP, protocol and whether options are present. Otherwise it
returns `false` and leaves `info` unchanged. The IPv4 checksum is not verified.

## Build and test

Requires a C99 compiler and `make`.

| Command | What it does |
|---|---|
| `make test` | Build and run the unit tests |
| `make sanitize` | Run the tests with AddressSanitizer and UBSan |
| `make clean` | Remove build output |

## Tests

The tests in `test_eth_ipv4.c` use [Unity](https://github.com/ThrowTheSwitch/Unity)
v2.6.0, bundled in `vendor/unity/`. They cover invalid input, non-IPv4 frames,
all VLAN TPIDs and truncated VLAN stacks, malformed IPv4 headers, and parsing
of each `Ipv4Info` field.
