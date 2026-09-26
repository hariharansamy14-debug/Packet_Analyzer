const assert = require("node:assert/strict");
const test = require("node:test");
const { parseEthernet } = require("./parsers/ethernet");
const { parseICMP } = require("./parsers/icmp");
const { parseIPv4 } = require("./parsers/ipv4");
const { parseTCP } = require("./parsers/tcp");
const { parseUDP } = require("./parsers/udp");
const { decodePacket } = require("./packet");

function makeIPv4Packet({ flagsAndOffset = 0, payload = Buffer.alloc(0), protocol = 6 } = {}) {
    const header = Buffer.alloc(20);
    header[0] = 0x45;
    header.writeUInt16BE(header.length + payload.length, 2);
    header.writeUInt16BE(flagsAndOffset, 6);
    header[8] = 64;
    header[9] = protocol;
    return Buffer.concat([header, payload]);
}

test("Ethernet rejects non-buffer and truncated input", () => {
    assert.throws(() => parseEthernet("not a buffer"), TypeError);
    assert.throws(() => parseEthernet(Buffer.alloc(13)), /at least 14 bytes/);
});

test("IPv4 parses DSCP and ECN and accepts capture-truncated payload", () => {
    const packet = makeIPv4Packet({ payload: Buffer.from([1, 2]) });
    packet[1] = 0x2b;
    packet.writeUInt16BE(60, 2);
    const result = parseIPv4(packet);
    assert.equal(result.dscp, 10);
    assert.equal(result.ecn, 3);
    assert.deepEqual(result.payload, Buffer.from([1, 2]));
});

test("IPv4 rejects invalid versions, header lengths, and total lengths", () => {
    const wrongVersion = makeIPv4Packet();
    wrongVersion[0] = 0x65;
    assert.throws(() => parseIPv4(wrongVersion), /Unsupported IP version/);

    const shortHeader = makeIPv4Packet();
    shortHeader[0] = 0x44;
    assert.throws(() => parseIPv4(shortHeader), /at least 20 bytes/);

    const truncatedOptions = makeIPv4Packet();
    truncatedOptions[0] = 0x46;
    assert.throws(() => parseIPv4(truncatedOptions), /header is truncated/);

    const shortTotalLength = makeIPv4Packet();
    shortTotalLength.writeUInt16BE(19, 2);
    assert.throws(() => parseIPv4(shortTotalLength), /smaller than its header/);
});

test("TCP rejects invalid or truncated data offsets", () => {
    const shortOffset = Buffer.alloc(20);
    shortOffset[12] = 0x40;
    assert.throws(() => parseTCP(shortOffset), /at least 20 bytes/);

    const truncatedOptions = Buffer.alloc(20);
    truncatedOptions[12] = 0x60;
    assert.throws(() => parseTCP(truncatedOptions), /header is truncated/);
});

test("UDP validates its length and excludes trailing frame bytes", () => {
    const packet = Buffer.from([0, 1, 0, 2, 0, 10, 0, 0, 0xaa, 0xbb, 0xcc]);
    assert.deepEqual(parseUDP(packet).payload, Buffer.from([0xaa, 0xbb]));

    packet.writeUInt16BE(7, 4);
    assert.throws(() => parseUDP(packet), /at least 8 bytes/);
});

test("ICMP rejects non-buffer and truncated input", () => {
    assert.throws(() => parseICMP(null), TypeError);
    assert.throws(() => parseICMP(Buffer.alloc(7)), /at least 8 bytes/);
});

test("decoder does not parse a transport header from a noninitial fragment", () => {
    const ethernet = Buffer.alloc(14);
    ethernet.writeUInt16BE(0x0800, 12);
    const ip = makeIPv4Packet({ flagsAndOffset: 1, payload: Buffer.alloc(20) });
    const result = decodePacket(Buffer.concat([ethernet, ip]));
    assert.equal(result.network.fragmentOffset, 1);
    assert.equal(result.transport, null);
});