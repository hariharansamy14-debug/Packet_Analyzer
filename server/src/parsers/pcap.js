function parsePcapGlobalHeader(buffer) {

    if (!Buffer.isBuffer(buffer)) {
        throw new TypeError("Expected a Buffer");
    }

    if (buffer.length < 24) {
        throw new Error("PCAP global header requires 24 bytes");
    }

    const magic = buffer.subarray(0, 4).toString("hex");
    const formats = {
        "d4c3b2a1": { byteOrder: "little-endian", timestampResolution: "microseconds" },
        "a1b2c3d4": { byteOrder: "big-endian", timestampResolution: "microseconds" },
        "4d3cb2a1": { byteOrder: "little-endian", timestampResolution: "nanoseconds" },
        "a1b23c4d": { byteOrder: "big-endian", timestampResolution: "nanoseconds" }
    };
    const format = formats[magic];
    if (!format) {
        throw new Error("Unsupported PCAP magic number");
    }

    const readUInt16 = format.byteOrder === "little-endian"
        ? buffer.readUInt16LE.bind(buffer)
        : buffer.readUInt16BE.bind(buffer);
    const readUInt32 = format.byteOrder === "little-endian"
        ? buffer.readUInt32LE.bind(buffer)
        : buffer.readUInt32BE.bind(buffer);
    const readInt32 = format.byteOrder === "little-endian"
        ? buffer.readInt32LE.bind(buffer)
        : buffer.readInt32BE.bind(buffer);

    return {
        ...format,
        versionMajor: readUInt16(4),
        versionMinor: readUInt16(6),
        thiszone: readInt32(8),
        sigfigs: readUInt32(12),
        snaplen: readUInt32(16),
        network: readUInt32(20)
    };
}

module.exports = { parsePcapGlobalHeader };