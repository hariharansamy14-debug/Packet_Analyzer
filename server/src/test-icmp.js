const { parseICMP } = require("./parsers/icmp");


const icmpPacket = Buffer.from([

    // Type = 8
    // Echo Request
    0x08,

    // Code = 0
    0x00,

    // Checksum
    0x12, 0x34,

    // Identifier
    0x00, 0x01,

    // Sequence number
    0x00, 0x01,

    // Payload
    0xDE, 0xAD,
    0xBE, 0xEF
]);


const result = parseICMP(icmpPacket);


console.dir(result, {
    depth: null
});