const {parseEthernet} = require('./parsers/ethernet.js')

const frame = Buffer.from([

     // Destination MAC
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,

    // Source MAC
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,

    // EtherType = IPv4
    0x08, 0x00


]);

const result = parseEthernet(frame);
console.log(result);
