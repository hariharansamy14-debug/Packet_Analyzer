const assert = require("node:assert/strict");
const test = require("node:test");
const { parsePcapGlobalHeader } = require("./parsers/pcap");

test("PCAP parses its global header fields", () => {
    const header = Buffer.from([
        0xd4, 0xc3, 0xb2, 0xa1,
        0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00
    ]);
    const result = parsePcapGlobalHeader(header);

    assert.equal(result.byteOrder, "little-endian");
    assert.equal(result.timestampResolution, "microseconds");
    assert.equal(result.versionMajor, 2);
    assert.equal(result.versionMinor, 4);
    assert.equal(result.snaplen, 4096);
    assert.equal(result.network, 1);
});

test("PCAP rejects non-buffer and truncated headers", () => {
    assert.throws(() => parsePcapGlobalHeader("not a buffer"), TypeError);
    assert.throws(() => parsePcapGlobalHeader(Buffer.alloc(23)), /requires 24 bytes/);
});