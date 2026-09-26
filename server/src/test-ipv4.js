const { parseIPv4 } = require("./parsers/ipv4");

// Create a fake IPv4 packet
const ipPacket = Buffer.from([
    // Byte 0
    // Version = 4
    // IHL = 5
    0x45,

    // Byte 1
    // DSCP/ECN
    0x00,

    // Bytes 2-3
    // Total Length = 60 bytes
    0x00, 0x3c,

    // Bytes 4-5
    // Identification
    0x12, 0x34,

    // Bytes 6-7
    // Flags + Fragment Offset
    0x40, 0x00,

    // Byte 8
    // TTL = 64
    0x40,

    // Byte 9
    // Protocol = TCP
    0x06,

    // Bytes 10-11
    // Checksum
    0xab, 0xcd,

    // Bytes 12-15
    // Source IP = 192.168.1.10
    0xc0, 0xa8, 0x01, 0x0a,

    // Bytes 16-19
    // Destination IP = 142.250.72.14
    0x8e, 0xfa, 0x48, 0x0e,

    // Bytes 20+
    // Fake payload
    0x01, 0x02, 0x03, 0x04
]);

const result = parseIPv4(ipPacket);

console.log(result);