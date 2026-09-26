function getTCPFlags(flagsByte) {

    return {
        cwr: (flagsByte & 0x80) !== 0,
        ece: (flagsByte & 0x40) !== 0,
        urg: (flagsByte & 0x20) !== 0,
        ack: (flagsByte & 0x10) !== 0,
        psh: (flagsByte & 0x08) !== 0,
        rst: (flagsByte & 0x04) !== 0,
        syn: (flagsByte & 0x02) !== 0,
        fin: (flagsByte & 0x01) !== 0
    };
}


function parseTCP(buffer) {
    if (!Buffer.isBuffer(buffer)) {
        throw new TypeError("Expected a Buffer");
    }

    // Minimum TCP header = 20 bytes
    if (buffer.length < 20) {
        throw new Error("TCP header must be at least 20 bytes");
    }


    // Source port
    const sourcePort = buffer.readUInt16BE(0);


    // Destination port
    const destinationPort = buffer.readUInt16BE(2);


    // Sequence number
    const sequenceNumber = buffer.readUInt32BE(4);


    // Acknowledgement number
    const acknowledgementNumber = buffer.readUInt32BE(8);


    // Byte 12
    const dataOffsetByte = buffer.readUInt8(12);

    // Upper 4 bits = Data Offset
    const dataOffset = dataOffsetByte >> 4;

    // TCP header length is measured in 32-bit words
    const headerLength = dataOffset * 4;
    if (dataOffset < 5) {
        throw new Error("TCP header length must be at least 20 bytes");
    }
    if (headerLength > buffer.length) {
        throw new Error("TCP header is truncated");
    }


    // Byte 13 = TCP flags
    const flagsByte = buffer.readUInt8(13);

    const flags = getTCPFlags(flagsByte);


    // Window size
    const windowSize = buffer.readUInt16BE(14);


    // Checksum
    const checksum = buffer.readUInt16BE(16);


    // Urgent pointer
    const urgentPointer = buffer.readUInt16BE(18);


    // Everything after TCP header
    const payload = buffer.subarray(headerLength);


    return {
        sourcePort,
        destinationPort,

        sequenceNumber,
        acknowledgementNumber,

        dataOffset,
        headerLength,

        flags,

        windowSize,

        checksum,

        urgentPointer,

        payload
    };
}


module.exports = {
    parseTCP
};