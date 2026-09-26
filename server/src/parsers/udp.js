function parseUDP(buffer) {
    if (!Buffer.isBuffer(buffer)) {
        throw new TypeError("Expected a Buffer");
    }

    // UDP header is always 8 bytes
    if (buffer.length < 8) {
        throw new Error("UDP header must be at least 8 bytes");
    }


    // Bytes 0-1
    const sourcePort = buffer.readUInt16BE(0);


    // Bytes 2-3
    const destinationPort = buffer.readUInt16BE(2);


    // Bytes 4-5
    const length = buffer.readUInt16BE(4);
    if (length < 8) {
        throw new Error("UDP length must be at least 8 bytes");
    }


    // Bytes 6-7
    const checksum = buffer.readUInt16BE(6);


    // UDP payload
    const payload = buffer.subarray(8, length);


    return {
        sourcePort,
        destinationPort,
        length,
        checksum,
        payload
    };
}


module.exports = {
    parseUDP
};