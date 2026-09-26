const { parseTCP } = require("./parsers/tcp");

const tcpPacket = Buffer.from([
    // Source port = 52341
    0xCC, 0x75,

    // Destination port = 443
    0x01, 0xBB,

    // Sequence number
    0x00, 0x00, 0x00, 0x01,

    // Acknowledgement number
    0x00, 0x00, 0x00, 0x00,

    // Data Offset = 5
    0x50,

    // Flags = SYN
    0x02,

    // Window size
    0x72, 0x10,

    // Checksum
    0x00, 0x00,

    // Urgent pointer
    0x00, 0x00
]);

const result = parseTCP(tcpPacket);

console.log(result);