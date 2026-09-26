const { parseEthernet } = require("./parsers/ethernet");
const { parseIPv4 } = require("./parsers/ipv4");
const { parseTCP } = require("./parsers/tcp");
const { parseUDP } = require("./parsers/udp");
const { parseICMP } = require("./parsers/icmp");

function decodePacket(buffer) {

    // --------------------------------
    // Layer 2: Ethernet
    // --------------------------------

    const ethernet = parseEthernet(buffer);


    let network = null;
    let transport = null;


    // --------------------------------
    // Layer 3
    // --------------------------------

    if (ethernet.etherType === 0x0800) {

        // IPv4 packet
        network = parseIPv4(ethernet.payload);


        // --------------------------------
        // Layer 4
        // --------------------------------

if (network.fragmentOffset !== 0) {

    // Noninitial fragments do not begin with a transport header.
    transport = null;

} else if (network.protocolNumber === 6) {

    // TCP
    transport = parseTCP(network.payload);

} else if (network.protocolNumber === 17) {

    // UDP
    transport = parseUDP(network.payload);

} else if (network.protocolNumber === 1) {

    // ICMP
    transport = parseICMP(network.payload);
}
    }


    return {
        ethernet,
        network,
        transport
    };
}


module.exports = {
    decodePacket
};