const { decodePacket } = require("./packet");


const packet = Buffer.from([

    // =================================
    // Ethernet Header - 14 bytes
    // =================================

    // Destination MAC
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,

    // Source MAC
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,

    // EtherType = IPv4
    0x08, 0x00,


    // =================================
    // IPv4 Header - 20 bytes
    // =================================

    // Version 4 + IHL 5
    0x45,

    // DSCP
    0x00,

    // Total Length = 40
    0x00, 0x28,

    // Identification
    0x12, 0x34,

    // Flags + Fragment Offset
    0x40, 0x00,

    // TTL
    0x40,

    // Protocol = TCP
    0x06,

    // Checksum
    0x00, 0x00,

    // Source IP = 192.168.1.10
    0xC0, 0xA8, 0x01, 0x0A,

    // Destination IP = 192.168.1.20
    0xC0, 0xA8, 0x01, 0x14,


    // =================================
    // TCP Header - 20 bytes
    // =================================

    // Source port = 50000
    0xC3, 0x50,

    // Destination port = 443
    0x01, 0xBB,

    // Sequence number
    0x00, 0x00, 0x00, 0x01,

    // Acknowledgement number
    0x00, 0x00, 0x00, 0x00,

    // Data offset = 5
    0x50,

    // SYN flag
    0x02,

    // Window size
    0x72, 0x10,

    // Checksum
    0x00, 0x00,

    // Urgent pointer
    0x00, 0x00
]);


const result = decodePacket(packet);


console.dir(result, {
    depth: null
});